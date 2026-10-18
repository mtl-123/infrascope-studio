use crate::Config;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use url::{Host, Url};

const MAX_RESPONSE: u64 = 2 * 1024 * 1024;
const MAX_PAYLOAD: usize = 900 * 1024;
const COLLECTION_BUDGET: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DockerConfig {
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_limit")]
    pub max_containers: usize,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub client_identity_file: Option<PathBuf>,
}

fn default_endpoint() -> String {
    if cfg!(windows) {
        "npipe:////./pipe/docker_engine".into()
    } else {
        "unix:///var/run/docker.sock".into()
    }
}
fn default_timeout() -> u64 {
    5
}
fn default_limit() -> usize {
    100
}

impl DockerConfig {
    pub fn validate(&self) -> Result<()> {
        if !(1..=30).contains(&self.timeout_seconds) {
            bail!("docker.timeout_seconds must be between 1 and 30");
        }
        if !(1..=1000).contains(&self.max_containers) {
            bail!("docker.max_containers must be between 1 and 1000");
        }
        if let Some(version) = &self.api_version {
            let parts: Vec<_> = version.split('.').collect();
            if parts.len() != 2
                || parts
                    .iter()
                    .any(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
            {
                bail!("docker.api_version must have the form 1.45, without a v prefix");
            }
        }
        if let Some(path) = self.endpoint.strip_prefix("unix://") {
            if !path.starts_with('/') || path.len() < 2 || path.contains('\0') {
                bail!("docker unix socket must be an absolute path");
            }
            return Ok(());
        }
        if self.endpoint.starts_with("npipe:") {
            bail!("Docker named pipes are not supported by this build; configure a verified HTTPS Docker API endpoint or run the collector beside Docker on Linux using its unix socket");
        }
        validate_network_endpoint(&self.endpoint)?;
        Ok(())
    }
}

fn validate_network_endpoint(endpoint: &str) -> Result<Url> {
    let url = Url::parse(endpoint).map_err(|_| anyhow!("invalid docker endpoint URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!(
            "docker endpoint must be an origin URL without credentials, path, query, or fragment"
        );
    }
    let literal_loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.scheme() != "https" && !(url.scheme() == "http" && literal_loopback) {
        bail!("docker endpoint requires HTTPS; plaintext HTTP is allowed only for an explicitly configured literal loopback IP");
    }
    if url.host().is_none() {
        bail!("docker endpoint requires a host");
    }
    Ok(url)
}

fn client(config: &DockerConfig) -> Result<(Client, String)> {
    config.validate()?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(config.timeout_seconds))
        .timeout(Duration::from_secs(config.timeout_seconds));
    let base = if let Some(socket) = config.endpoint.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            builder = builder.unix_socket(socket);
            "http://localhost".to_owned()
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            bail!("Unix Docker sockets require the Linux collector; use a verified HTTPS Docker API endpoint on Windows");
        }
    } else {
        config.endpoint.trim_end_matches('/').to_owned()
    };
    if let Some(path) = &config.ca_file {
        let bytes = std::fs::read(path).context("cannot read Docker CA file")?;
        let cert = reqwest::Certificate::from_pem(&bytes).context("invalid Docker CA PEM")?;
        builder = builder.add_root_certificate(cert);
    }
    if let Some(path) = &config.client_identity_file {
        let bytes = std::fs::read(path).context("cannot read Docker client identity file")?;
        let identity = reqwest::Identity::from_pem(&bytes)
            .context("invalid Docker client certificate/private key PEM")?;
        builder = builder.identity(identity);
    }
    Ok((
        builder
            .build()
            .context("cannot initialize Docker HTTP client")?,
        base,
    ))
}

fn get_json(client: &Client, url: &str, deadline: Instant, timeout: u64) -> Result<Value> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("Docker collection exceeded its 60-second budget");
    }
    let response = client
        .get(url)
        .timeout(remaining.min(Duration::from_secs(timeout)))
        .send()
        .map_err(|_| {
            anyhow!("Docker read request failed (connection, timeout, or TLS verification)")
        })?;
    if !response.status().is_success() {
        bail!(
            "Docker read request returned HTTP {}",
            response.status().as_u16()
        );
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .context("cannot read Docker response")?;
    if bytes.len() as u64 > MAX_RESPONSE {
        bail!("Docker response exceeds 2 MiB limit");
    }
    serde_json::from_slice(&bytes).context("Docker returned invalid JSON")
}

pub fn collect(config: &Config) -> Result<Value> {
    let config = config
        .docker
        .as_ref()
        .context("Docker collector is not configured")?;
    let (client, base) = client(config)?;
    let deadline = Instant::now() + COLLECTION_BUDGET;
    let version = get_json(
        &client,
        &format!("{base}/version"),
        deadline,
        config.timeout_seconds,
    )?;
    let api_prefix = config
        .api_version
        .as_ref()
        .map(|v| format!("/v{v}"))
        .unwrap_or_default();
    let list = get_json(
        &client,
        &format!("{base}{api_prefix}/containers/json?all=true&size=false"),
        deadline,
        config.timeout_seconds,
    )?;
    let inventory = list
        .as_array()
        .context("Docker container inventory was not an array")?;
    let mut containers = Vec::new();
    let mut errors = Vec::new();
    for container in inventory.iter().take(config.max_containers) {
        let id = match container.get("Id").and_then(Value::as_str) {
            Some(id) if valid_container_id(id) => id,
            _ => {
                if errors.len() < 100 {
                    errors.push(json!({"source":"inventory", "error":"invalid or absent Docker container ID"}));
                }
                continue;
            }
        };
        let mut item = inventory_item(container)?;
        if container.get("State").and_then(Value::as_str) != Some("running") {
            item["metrics"] = Value::Null;
            item["metrics_status"] = json!("not_running");
        } else {
            match get_json(
                &client,
                &format!("{base}{api_prefix}/containers/{id}/stats?stream=false"),
                deadline,
                config.timeout_seconds,
            )
            .and_then(|stats| parse_stats(&stats))
            {
                Ok(metrics) => {
                    item["metrics"] = metrics;
                    item["metrics_status"] = json!("collected");
                }
                Err(err) => {
                    item["metrics"] = Value::Null;
                    item["metrics_status"] = json!("error");
                    if errors.len() < 100 {
                        errors.push(
                            json!({"container_id":id, "source":"stats", "error":err.to_string()}),
                        );
                    }
                }
            }
        }
        containers.push(item);
    }
    let truncated = inventory.len() > config.max_containers;
    let mut payload = json!({
        "collector":"docker", "source":"docker_engine_api", "status":if errors.is_empty() && !truncated {"ok"} else {"partial"},
        "engine_version":version.get("Version"), "api_version":version.get("ApiVersion"),
        "engine_os":version.get("Os"), "containers_total":inventory.len(), "containers":containers,
        "truncated":truncated, "errors":errors, "diagnostics_limit":100,
        "semantics": {"cpu_percent":"Docker CPU delta divided by system delta times online CPUs; may exceed 100 for multicore", "network_bytes":"cumulative counters, not rates", "block_io_bytes":"cumulative counters, not rates", "memory_working_set_bytes":"usage minus total_inactive_file or inactive_file; null when unavailable", "guest_os_metrics":"not collected; use a host agent inside each guest for OS-level metrics"}
    });
    bound_payload(&mut payload)?;
    Ok(payload)
}

fn bound_payload(payload: &mut Value) -> Result<()> {
    while serde_json::to_vec(payload)?.len() > MAX_PAYLOAD {
        let items = payload["containers"]
            .as_array_mut()
            .context("missing Docker result containers")?;
        if items.is_empty() {
            bail!("Docker diagnostic payload exceeds transport size limit");
        }
        items.truncate(items.len() / 2);
        payload["truncated"] = json!(true);
        payload["status"] = json!("partial");
        payload["truncation_reason"] = json!("transport_payload_limit");
    }
    Ok(())
}

fn valid_container_id(id: &str) -> bool {
    (12..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn inventory_item(value: &Value) -> Result<Value> {
    let id = value
        .get("Id")
        .and_then(Value::as_str)
        .context("missing container ID")?;
    let labels = value.get("Labels").and_then(Value::as_object);
    let label = |key: &str| labels.and_then(|ls| ls.get(key)).and_then(Value::as_str);
    let names: Vec<&str> = value
        .get("Names")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|s| s.trim_start_matches('/'))
        .collect();
    Ok(json!({
        "id":id, "names":names, "image":value.get("Image"), "image_id":value.get("ImageID"),
        "state":value.get("State"), "status":value.get("Status"), "created_unix":value.get("Created"),
        "compose":{"project":label("com.docker.compose.project"), "service":label("com.docker.compose.service"), "container_number":label("com.docker.compose.container-number")},
        "swarm":{"service_id":label("com.docker.swarm.service.id"), "service_name":label("com.docker.swarm.service.name")}
    }))
}

fn counter(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_u64)
        .map(|n| json!(n.to_string()))
        .unwrap_or(Value::Null)
}

fn parse_stats(stats: &Value) -> Result<Value> {
    if !stats.is_object() || stats.get("cpu_stats").is_none() && stats.get("memory_stats").is_none()
    {
        bail!("Docker stats response lacks CPU and memory statistics");
    }
    let current = stats
        .pointer("/cpu_stats/cpu_usage/total_usage")
        .and_then(Value::as_u64);
    let previous = stats
        .pointer("/precpu_stats/cpu_usage/total_usage")
        .and_then(Value::as_u64);
    let system = stats
        .pointer("/cpu_stats/system_cpu_usage")
        .and_then(Value::as_u64);
    let previous_system = stats
        .pointer("/precpu_stats/system_cpu_usage")
        .and_then(Value::as_u64);
    let cpus = stats
        .pointer("/cpu_stats/online_cpus")
        .and_then(Value::as_u64)
        .or_else(|| {
            stats
                .pointer("/cpu_stats/cpu_usage/percpu_usage")
                .and_then(Value::as_array)
                .map(|a| a.len() as u64)
        });
    let cpu_percent = match (current, previous, system, previous_system, cpus) {
        (Some(c), Some(p), Some(s), Some(ps), Some(n)) if c >= p && s > ps && ps > 0 && n > 0 => {
            Some((c - p) as f64 / (s - ps) as f64 * n as f64 * 100.0)
        }
        _ => None,
    };
    let usage = stats.pointer("/memory_stats/usage").and_then(Value::as_u64);
    let limit = stats.pointer("/memory_stats/limit").and_then(Value::as_u64);
    let inactive = stats
        .pointer("/memory_stats/stats/total_inactive_file")
        .and_then(Value::as_u64)
        .or_else(|| {
            stats
                .pointer("/memory_stats/stats/inactive_file")
                .and_then(Value::as_u64)
        });
    let working_set = usage.zip(inactive).and_then(|(u, c)| u.checked_sub(c));
    let memory_percent = usage
        .zip(limit)
        .filter(|(_, l)| *l > 0)
        .map(|(u, l)| u as f64 / l as f64 * 100.0);
    let mut networks = Map::new();
    if let Some(items) = stats.get("networks").and_then(Value::as_object) {
        for (name, network) in items {
            networks.insert(name.clone(), json!({"rx_bytes":counter(network.get("rx_bytes")), "tx_bytes":counter(network.get("tx_bytes")), "rx_packets":counter(network.get("rx_packets")), "tx_packets":counter(network.get("tx_packets")), "rx_errors":counter(network.get("rx_errors")), "tx_errors":counter(network.get("tx_errors")), "rx_dropped":counter(network.get("rx_dropped")), "tx_dropped":counter(network.get("tx_dropped"))}));
        }
    }
    let io = stats
        .pointer("/blkio_stats/io_service_bytes_recursive")
        .and_then(Value::as_array);
    let sum_op = |operation: &str| -> Option<String> {
        let entries = io?;
        let mut total = 0_u64;
        let mut found = false;
        for entry in entries {
            if entry
                .get("op")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case(operation))
            {
                total = total.checked_add(entry.get("value")?.as_u64()?)?;
                found = true;
            }
        }
        found.then(|| total.to_string())
    };
    Ok(json!({
        "sample_time":stats.get("read"), "previous_sample_time":stats.get("preread"),
        "cpu_percent":cpu_percent, "cpu_total_usage_ns":counter(stats.pointer("/cpu_stats/cpu_usage/total_usage")), "online_cpus":cpus,
        "memory_usage_bytes":usage.map(|n|n.to_string()), "memory_limit_bytes":limit.map(|n|n.to_string()),
        "memory_working_set_bytes":working_set.map(|n|n.to_string()), "memory_usage_percent":memory_percent,
        "memory_inactive_file_bytes":inactive.map(|n|n.to_string()), "memory_cache_bytes":counter(stats.pointer("/memory_stats/stats/cache")),
        "pids_current":stats.pointer("/pids_stats/current"), "networks":networks,
        "block_io_read_bytes":sum_op("Read"), "block_io_write_bytes":sum_op("Write")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    fn fixture_server(
        responses: Vec<(u16, String)>,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut paths = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 16384);
                }
                let request = String::from_utf8(request).unwrap();
                paths.push(request.lines().next().unwrap().to_owned());
                let header = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLocation: http://127.0.0.1:1/do-not-follow\r\n\r\n", body.len());
                stream.write_all(header.as_bytes()).unwrap();
                let _ = stream.write_all(body.as_bytes());
            }
            paths
        });
        (endpoint, handle)
    }

    #[test]
    fn docker_network_requires_tls_or_literal_loopback() {
        for endpoint in [
            "https://docker.internal:2376",
            "http://127.0.0.1:2375",
            "http://[::1]:2375",
        ] {
            assert!(validate_network_endpoint(endpoint).is_ok(), "{endpoint}");
        }
        for endpoint in [
            "http://localhost:2375",
            "http://192.168.1.5:2375",
            "https://u:p@docker/",
            "https://docker/path",
            "https://docker/?x=y",
            "file:///tmp/docker",
        ] {
            assert!(validate_network_endpoint(endpoint).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn docker_cgroup_v1_v2_and_zero_limit_are_not_fabricated() {
        let v1 = parse_stats(&json!({"memory_stats":{"usage":1000,"limit":2000,"stats":{"total_inactive_file":100}},"cpu_stats":{},"precpu_stats":{}})).unwrap();
        assert_eq!(v1["memory_working_set_bytes"], "900");
        assert_eq!(v1["memory_usage_percent"], 50.0);
        assert!(v1["cpu_percent"].is_null());
        let v2 = parse_stats(
            &json!({"memory_stats":{"usage":1000,"limit":0,"stats":{"inactive_file":200}}}),
        )
        .unwrap();
        assert_eq!(v2["memory_working_set_bytes"], "800");
        assert!(v2["memory_usage_percent"].is_null());
        let missing = parse_stats(&json!({"memory_stats":{"usage":1000}})).unwrap();
        assert!(missing["memory_working_set_bytes"].is_null());
        let inconsistent =
            parse_stats(&json!({"memory_stats":{"usage":1000,"stats":{"inactive_file":2000}}}))
                .unwrap();
        assert!(inconsistent["memory_working_set_bytes"].is_null());
    }

    #[test]
    fn docker_cpu_uses_deltas_and_keeps_multicore_percentage() {
        let parsed = parse_stats(&json!({"cpu_stats":{"cpu_usage":{"total_usage":300},"system_cpu_usage":2000,"online_cpus":8},"precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000}})).unwrap();
        assert_eq!(parsed["cpu_percent"], 160.0);
        let reset = parse_stats(&json!({"cpu_stats":{"cpu_usage":{"total_usage":30},"system_cpu_usage":2000,"online_cpus":8},"precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000}})).unwrap();
        assert!(reset["cpu_percent"].is_null());
    }

    #[test]
    fn docker_counters_keep_u64_precision_and_missing_is_null() {
        let parsed = parse_stats(&json!({"memory_stats":{},"networks":{"eth0":{"rx_bytes":18446744073709551615_u64}},"blkio_stats":{"io_service_bytes_recursive":[{"op":"Read","value":10},{"op":"Read","value":20}]}})).unwrap();
        assert_eq!(
            parsed["networks"]["eth0"]["rx_bytes"],
            "18446744073709551615"
        );
        assert!(parsed["networks"]["eth0"]["tx_bytes"].is_null());
        assert_eq!(parsed["block_io_read_bytes"], "30");
        assert!(parsed["block_io_write_bytes"].is_null());
    }

    #[test]
    fn docker_group_names_do_not_replace_container_identity() {
        let a = inventory_item(&json!({"Id":"aaaaaaaaaaaa","Names":["/web"],"Labels":{"com.docker.compose.project":"one","com.docker.compose.service":"web","secret.password":"do-not-export"}})).unwrap();
        let b = inventory_item(&json!({"Id":"bbbbbbbbbbbb","Names":["/web"],"Labels":{"com.docker.compose.project":"two","com.docker.compose.service":"web"}})).unwrap();
        assert_ne!(a["id"], b["id"]);
        assert_ne!(a["compose"]["project"], b["compose"]["project"]);
        assert!(!a.to_string().contains("do-not-export"));
    }

    #[test]
    fn docker_rejects_malformed_stats_and_ids() {
        assert!(parse_stats(&json!({"message":"permission denied"})).is_err());
        assert!(!valid_container_id("../containers/evil"));
        assert!(!valid_container_id("not-an-id"));
        assert!(valid_container_id("0123456789abcdef"));
    }

    #[test]
    fn docker_large_inventory_is_explicitly_partial_not_unuploadable() {
        let mut payload = json!({"containers":[{"id":"aaaaaaaaaaaa","names":["x".repeat(MAX_PAYLOAD)]}],"truncated":false,"status":"ok"});
        bound_payload(&mut payload).unwrap();
        assert_eq!(payload["truncated"], true);
        assert_eq!(payload["status"], "partial");
        assert!(serde_json::to_vec(&payload).unwrap().len() <= MAX_PAYLOAD);
    }

    #[test]
    fn docker_fixture_read_only_partial_failure_retains_other_inventory() {
        let list = json!([
            {"Id":"aaaaaaaaaaaa", "Names":["/running"], "State":"running"},
            {"Id":"bbbbbbbbbbbb", "Names":["/stopped"], "State":"exited"}
        ])
        .to_string();
        let (endpoint, handle) = fixture_server(vec![
            (200, json!({"Version":"fixture"}).to_string()),
            (200, list),
            (500, "sensitive error body is not exported".into()),
        ]);
        let mut config = Config::default();
        config.docker = Some(serde_json::from_value(json!({"endpoint":endpoint})).unwrap());
        let result = collect(&config).unwrap();
        assert_eq!(result["status"], "partial");
        assert_eq!(result["containers_total"], 2);
        assert_eq!(result["containers"][0]["metrics_status"], "error");
        assert_eq!(result["containers"][1]["metrics_status"], "not_running");
        assert!(result["containers"][0]["metrics"].is_null());
        assert!(!result.to_string().contains("sensitive error body"));
        assert_eq!(
            handle.join().unwrap(),
            vec![
                "GET /version HTTP/1.1",
                "GET /containers/json?all=true&size=false HTTP/1.1",
                "GET /containers/aaaaaaaaaaaa/stats?stream=false HTTP/1.1"
            ]
        );
    }

    #[test]
    fn docker_fixture_redirect_and_oversized_response_are_rejected() {
        for (status, body) in [
            (302, "{}".to_owned()),
            (200, " ".repeat(MAX_RESPONSE as usize + 1)),
        ] {
            let (endpoint, handle) = fixture_server(vec![(status, body)]);
            let config: DockerConfig =
                serde_json::from_value(json!({"endpoint":endpoint})).unwrap();
            let (client, base) = client(&config).unwrap();
            assert!(get_json(
                &client,
                &format!("{base}/version"),
                Instant::now() + COLLECTION_BUDGET,
                config.timeout_seconds
            )
            .is_err());
            assert_eq!(handle.join().unwrap().len(), 1);
        }
    }
}
