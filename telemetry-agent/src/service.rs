use crate::config::Kind;
use anyhow::Result;
use std::path::PathBuf;

#[cfg(not(windows))]
pub fn run(_: Kind, _: PathBuf, _: Option<String>) -> Result<()> {
    anyhow::bail!(
        "run-service is Windows-only; on Linux use the provided systemd unit with the run command"
    )
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        ffi::OsString,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, OnceLock,
        },
        time::Duration,
    };
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    static SETTINGS: OnceLock<(Kind, PathBuf, String)> = OnceLock::new();
    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch(kind: Kind, config: PathBuf, name: Option<String>) -> Result<()> {
        let name = name.unwrap_or_else(|| format!("InfraScope-{}", kind.as_str()));
        let config = std::fs::canonicalize(config)?;
        SETTINGS
            .set((kind, config, name.clone()))
            .map_err(|_| anyhow::anyhow!("service is already initialized"))?;
        service_dispatcher::start(name, ffi_service_main)?;
        Ok(())
    }

    fn service_main(_: Vec<OsString>) {
        if let Err(error) = execute() {
            eprintln!("Windows service failed: {error:#}");
        }
    }

    fn execute() -> Result<()> {
        let (kind, config, name) = SETTINGS
            .get()
            .ok_or_else(|| anyhow::anyhow!("missing service settings"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&stop);
        let status = service_control_handler::register(name, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                signal.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        let result = crate::run(*kind, config.clone(), stop);
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        result
    }
}

#[cfg(windows)]
pub fn run(kind: Kind, config: PathBuf, name: Option<String>) -> Result<()> {
    windows::dispatch(kind, config, name)
}
