pub mod config;
pub mod docker;
pub mod host;
pub mod protocol;
pub mod pve;
pub mod queue;
pub mod service;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
pub use config::Config;
use config::{Kind, RemoteConfig};
use host::HostCollector;
use protocol::{Ack, ConfigResponse, Envelope, Transport, CONFIG_PATH, SAMPLES_PATH};
use queue::Store;
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "InfraScope telemetry client; never accepts secrets on the command line"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a new TOML template without overwriting an existing file.
    InitConfig {
        #[arg(long)]
        output: PathBuf,
    },
    /// Collect and print a real snapshot; no enrollment, upload or state writes.
    Sample {
        #[arg(long)]
        config: PathBuf,
    },
    /// Enroll using INFRASCOPE_ENROLLMENT_TOKEN from the process environment.
    Enroll {
        #[arg(long)]
        config: PathBuf,
    },
    /// Poll configuration, collect once, persist and upload the backlog.
    Once {
        #[arg(long)]
        config: PathBuf,
    },
    /// Continuously collect; Ctrl+C exits after the current bounded operation.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Enter Windows SCM dispatch. Use only from an installed Windows service.
    RunService {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        service_name: Option<String>,
    },
    /// Print local enrollment and queue status without credentials.
    Status {
        #[arg(long)]
        config: PathBuf,
    },
}

pub fn cli(kind: Kind) -> Result<()> {
    match Args::parse().command {
        Command::InitConfig { output } => {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .context("create configuration (existing files are never overwritten)")?;
            file.write_all(Config::example(kind).as_bytes())?;
            file.sync_all()?;
            println!("Configuration created. Set server_url, CA, a private per-collector state_dir and any collector options before enrollment.");
        }
        Command::Sample { config } => {
            let config = Config::load(&config)?;
            let metrics = collect(kind, &config, &mut HostCollector::default())?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"schemaVersion":1,"observedAt":chrono::Utc::now().to_rfc3339(),"kind":kind,"metrics":metrics,"uploaded":false})
                )?
            );
        }
        Command::Enroll { config } => {
            let config = Config::load(&config)?;
            let mut store = Store::open(&config, kind)?;
            enroll(&config, &mut store, kind)?;
            println!(
                "{}",
                serde_json::json!({"enrolled":true,"agentId":store.state.agent_id,"assetId":store.state.asset_id,"kind":kind})
            );
        }
        Command::Once { config } => {
            let config = Config::load(&config)?;
            let mut store = Store::open(&config, kind)?;
            require_enrolled(&store)?;
            let transport = Transport::new(&config)?;
            cycle(
                &config,
                kind,
                &mut store,
                &transport,
                &mut HostCollector::default(),
                &mut 0,
                &AtomicBool::new(false),
            )?;
        }
        Command::Run { config } => {
            let stop = Arc::new(AtomicBool::new(false));
            let signal = Arc::clone(&stop);
            ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))
                .context("install stop signal handler")?;
            run(kind, config, stop)?;
        }
        Command::RunService {
            config,
            service_name,
        } => service::run(kind, config, service_name)?,
        Command::Status { config } => {
            let config = Config::load(&config)?;
            let store = Store::open(&config, kind)?;
            println!(
                "{}",
                serde_json::json!({"enrolled":store.state.agent_id.is_some(),"agentId":store.state.agent_id,"assetId":store.state.asset_id,
                "kind":kind,"sequence":store.state.sequence.to_string(),"pendingBatches":store.pending()?.len(),"config":store.state.remote_config})
            );
        }
    }
    Ok(())
}

fn enroll(config: &Config, store: &mut Store, kind: Kind) -> Result<()> {
    if store.state.agent_id.is_some() {
        bail!("already enrolled; refusing to overwrite identity or migrate unacknowledged samples");
    }
    let token = std::env::var("INFRASCOPE_ENROLLMENT_TOKEN").context("set INFRASCOPE_ENROLLMENT_TOKEN in this process environment; never pass tokens on the command line")?;
    let result = Transport::new(config)?.enroll(&token, &store.key, kind)?;
    store.state.agent_id = Some(result.agent_id);
    store.state.asset_id = Some(result.asset_id);
    store.state.remote_config = Some(result.config);
    store.save()?;
    Ok(())
}

fn require_enrolled(store: &Store) -> Result<()> {
    if store.state.agent_id.is_none()
        || store.state.asset_id.is_none()
        || store.state.remote_config.is_none()
    {
        bail!("not enrolled; first run enroll with INFRASCOPE_ENROLLMENT_TOKEN set");
    }
    Ok(())
}

fn collect(kind: Kind, config: &Config, host: &mut HostCollector) -> Result<serde_json::Value> {
    match kind {
        Kind::Host => Ok(host.collect()),
        Kind::Docker => docker::collect(config),
        Kind::Pve => pve::collect(config),
    }
}

fn apply_remote(store: &mut Store, remote: RemoteConfig, kind: Kind) -> Result<()> {
    remote.validate(kind)?;
    if let Some(previous) = &store.state.remote_config {
        if remote.version < previous.version {
            bail!("remote configuration rollback refused");
        }
        if remote.version == previous.version
            && serde_json::to_vec(previous)? != serde_json::to_vec(&remote)?
        {
            bail!("remote configuration changed without a version increase");
        }
    }
    store.state.remote_config = Some(remote);
    store.save()
}

fn flush(store: &Store, transport: &Transport, stop: &AtomicBool) -> Result<usize> {
    let agent_id = store.state.agent_id.as_deref().context("not enrolled")?;
    let mut sent = 0;
    let deadline = Instant::now() + Duration::from_secs(30);
    // A wall-clock deadline keeps configuration polling responsive after an outage.
    for path in store.pending()?.into_iter().take(100) {
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            break;
        }
        let (bytes, envelope) = store.read(&path)?;
        let ack: Ack = transport.signed_with_timeout(
            SAMPLES_PATH,
            agent_id,
            &store.key,
            &bytes,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        store.acknowledge(&path, &envelope, &ack)?;
        sent += 1;
    }
    Ok(sent)
}

fn cycle(
    config: &Config,
    kind: Kind,
    store: &mut Store,
    transport: &Transport,
    host: &mut HostCollector,
    dropped: &mut u64,
    stop: &AtomicBool,
) -> Result<()> {
    let version = store
        .state
        .remote_config
        .as_ref()
        .context("not enrolled")?
        .version;
    let config_request = serde_json::to_vec(&serde_json::json!({"appliedVersion":version}))?;
    let response: Result<ConfigResponse> = transport.signed(
        CONFIG_PATH,
        store.state.agent_id.as_deref().context("not enrolled")?,
        &store.key,
        &config_request,
    );
    match response {
        Ok(response) => apply_remote(store, response.config, kind)?,
        Err(error) => eprintln!(
            "configuration poll failed; retaining last validated configuration: {error:#}"
        ),
    }
    let remote = store.state.remote_config.clone().context("not enrolled")?;
    let mut collection_error = None;
    if remote.enabled && !stop.load(Ordering::SeqCst) {
        let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (metrics, health) = match collect(kind, config, host) {
            Ok(value) => {
                let status = if value
                    .get("status")
                    .and_then(|status| status.as_str())
                    .is_some_and(|status| status != "ok")
                {
                    "partial"
                } else {
                    "ok"
                };
                if status == "partial" {
                    collection_error = Some(anyhow::anyhow!("collector returned partial inventory; inspect metrics errors and truncation"));
                }
                (
                    value,
                    serde_json::json!({"status":status,"droppedSamplesSinceStart":dropped.to_string()}),
                )
            }
            Err(error) => {
                eprintln!("collection failed: {error:#}");
                collection_error = Some(error);
                (
                    serde_json::json!({}),
                    serde_json::json!({"status":"error","code":"collection_failed","droppedSamplesSinceStart":dropped.to_string()}),
                )
            }
        };
        let sequence = store.reserve_sequence()?;
        let envelope = Envelope {
            schema_version: 1,
            batch_id: uuid::Uuid::new_v4().to_string(),
            agent_id: store.state.agent_id.clone().context("not enrolled")?,
            asset_id: store.state.asset_id.clone().context("not enrolled")?,
            sequence: sequence.to_string(),
            observed_at,
            config_version: remote.version,
            kind,
            metrics,
            health,
        };
        if let Err(error) = store.enqueue(&envelope) {
            *dropped = dropped.saturating_add(1);
            eprintln!("sample not persisted; droppedSamplesSinceStart={dropped}: {error:#}");
            let _ = flush(store, transport, stop);
            return Err(error);
        }
    }
    let sent = flush(store, transport, stop)?;
    println!(
        "{}",
        serde_json::json!({"agentId":store.state.agent_id,"kind":kind,"enabled":remote.enabled,"configVersion":remote.version,
        "acknowledgedBatches":sent,"pendingBatches":store.pending()?.len(),"droppedSamplesSinceStart":dropped.to_string()})
    );
    if let Some(error) = collection_error {
        return Err(
            error.context("collector error reported to server; no successful sample claimed")
        );
    }
    Ok(())
}

pub fn run(kind: Kind, config_path: PathBuf, stop: Arc<AtomicBool>) -> Result<()> {
    let config = Config::load(&config_path)?;
    let mut store = Store::open(&config, kind)?;
    require_enrolled(&store)?;
    let transport = Transport::new(&config)?;
    let mut host = HostCollector::default();
    let mut dropped = 0;
    while !stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        if let Err(error) = cycle(
            &config,
            kind,
            &mut store,
            &transport,
            &mut host,
            &mut dropped,
            &stop,
        ) {
            eprintln!("collection/upload cycle incomplete: {error:#}");
        }
        let interval = store
            .state
            .remote_config
            .as_ref()
            .map_or(config.interval_seconds, |config| config.interval_seconds);
        let wait = Duration::from_secs(interval).saturating_sub(started.elapsed());
        let until = Instant::now() + wait;
        while !stop.load(Ordering::SeqCst) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    eprintln!("stopped; unacknowledged samples remain on disk");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_version_cannot_rollback_or_mutate() {
        let temp = tempfile::tempdir().unwrap();
        let mut c = Config::default();
        c.state_dir = temp.path().into();
        let mut store = Store::open(&c, Kind::Host).unwrap();
        let remote = RemoteConfig {
            version: 2,
            interval_seconds: 5,
            enabled: true,
            collectors: vec![Kind::Host],
        };
        apply_remote(&mut store, remote.clone(), Kind::Host).unwrap();
        let mut bad = remote.clone();
        bad.version = 1;
        assert!(apply_remote(&mut store, bad, Kind::Host).is_err());
        let mut bad = remote.clone();
        bad.enabled = false;
        assert!(apply_remote(&mut store, bad, Kind::Host).is_err());
        let mut next = remote;
        next.version = 3;
        next.enabled = false;
        apply_remote(&mut store, next, Kind::Host).unwrap();
    }
}
