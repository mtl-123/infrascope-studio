use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Host,
    Docker,
    Pve,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Docker => "docker",
            Self::Pve => "pve",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server_url: String,
    pub state_dir: PathBuf,
    pub allow_insecure_loopback: bool,
    pub ca_cert: Option<PathBuf>,
    pub interval_seconds: u64,
    pub request_timeout_seconds: u64,
    pub max_queue_bytes: u64,
    pub max_queue_files: usize,
    pub docker: Option<crate::docker::DockerConfig>,
    pub pve: Option<crate::pve::PveConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: "https://127.0.0.1:18443".into(),
            state_dir: PathBuf::from("./agent-state"),
            allow_insecure_loopback: false,
            ca_cert: None,
            interval_seconds: 5,
            request_timeout_seconds: 15,
            max_queue_bytes: 64 * 1024 * 1024,
            max_queue_files: 10000,
            docker: None,
            pve: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).context("read configuration")?;
        if text.len() > 64 * 1024 {
            bail!("configuration exceeds 64 KiB");
        }
        let mut config: Self = toml::from_str(&text).context("parse configuration")?;
        let base = path.parent().unwrap_or(Path::new("."));
        if config.state_dir.is_relative() {
            config.state_dir = base.join(&config.state_dir);
        }
        if let Some(cert) = config.ca_cert.as_mut() {
            if cert.is_relative() {
                *cert = base.join(&*cert);
            }
        }
        if let Some(docker) = config.docker.as_mut() {
            for path in [&mut docker.ca_file, &mut docker.client_identity_file]
                .into_iter()
                .flatten()
            {
                if path.is_relative() {
                    *path = base.join(&*path);
                }
            }
        }
        if let Some(pve) = config.pve.as_mut() {
            if let Some(path) = pve.ca_file.as_mut() {
                if path.is_relative() {
                    *path = base.join(&*path);
                }
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let url = Url::parse(&self.server_url).context("invalid server_url")?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            bail!("server_url must be an origin without credentials, path, query or fragment");
        }
        let literal_loopback = match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            _ => false,
        };
        if url.scheme() != "https"
            && !(url.scheme() == "http" && self.allow_insecure_loopback && literal_loopback)
        {
            bail!("HTTPS required; development HTTP requires explicit allow_insecure_loopback and a literal loopback IP");
        }
        if !(1..=3600).contains(&self.interval_seconds) {
            bail!("interval_seconds must be 1..3600");
        }
        if !(1..=120).contains(&self.request_timeout_seconds) {
            bail!("request_timeout_seconds must be 1..120");
        }
        if !(1024..=1024 * 1024 * 1024).contains(&self.max_queue_bytes) {
            bail!("max_queue_bytes must be 1024..1073741824");
        }
        if !(1..=100000).contains(&self.max_queue_files) {
            bail!("max_queue_files must be 1..100000");
        }
        if self.state_dir.as_os_str().is_empty() {
            bail!("state_dir is required");
        }
        if let Some(docker) = &self.docker {
            docker.validate()?;
        }
        if let Some(pve) = &self.pve {
            pve.validate()?;
        }
        Ok(())
    }

    pub fn example(kind: Kind) -> String {
        let mut text = concat!(
            "# InfraScope telemetry 0.1.0. No secrets belong in this file.\n",
            "server_url = \"https://127.0.0.1:18443\"\n",
            "state_dir = \"./agent-state\"\n",
            "# ca_cert = \"./infrascope-ca.pem\"\n",
            "allow_insecure_loopback = false\n",
            "interval_seconds = 5\nrequest_timeout_seconds = 15\n",
            "max_queue_bytes = 67108864\nmax_queue_files = 10000\n",
        )
        .to_string();
        match kind {
            Kind::Host => (),
            Kind::Docker => text.push_str("\n[docker]\nendpoint = \"unix:///var/run/docker.sock\"\ntimeout_seconds = 10\nmax_containers = 100\n# ca_file = \"./docker-ca.pem\"\n# client_identity_file = \"./docker-client-cert-and-key.pem\"\n"),
            Kind::Pve => text.push_str("\n[pve]\nbase_url = \"https://pve.example.invalid:8006\"\ntoken_env = \"INFRASCOPE_PVE_TOKEN\"\n# Token value: PVEAPIToken=user@realm!tokenid=secret\n# ca_file = \"./pve-ca.pem\"\nnode_filter = []\ntimeout_seconds = 10\nmax_guests = 100\n"),
        }
        text.replace("./agent-state", &format!("./{}-state", kind.as_str()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteConfig {
    pub version: u64,
    pub interval_seconds: u64,
    pub enabled: bool,
    pub collectors: Vec<Kind>,
}

impl RemoteConfig {
    pub fn validate(&self, kind: Kind) -> Result<()> {
        if self.version == 0 || self.version > i64::MAX as u64 {
            bail!("invalid remote configuration version");
        }
        if !(1..=3600).contains(&self.interval_seconds) {
            bail!("invalid remote collection interval");
        }
        if self.collectors != vec![kind] {
            bail!("remote collector kind mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn templates_use_distinct_collector_state_directories() {
        for kind in [Kind::Host, Kind::Docker, Kind::Pve] {
            let c: Config = toml::from_str(&Config::example(kind)).unwrap();
            assert_eq!(
                c.state_dir,
                PathBuf::from(format!("./{}-state", kind.as_str()))
            );
        }
    }
    #[test]
    fn only_explicit_literal_loopback_allows_http() {
        let mut c = Config::default();
        c.server_url = "http://127.0.0.1:18080".into();
        assert!(c.validate().is_err());
        c.allow_insecure_loopback = true;
        assert!(c.validate().is_ok());
        for url in [
            "http://localhost",
            "http://192.168.1.2",
            "ftp://127.0.0.1",
            "https://user:pass@example.com",
            "https://example.com/api",
            "https://example.com?token=x",
        ] {
            c.server_url = url.into();
            assert!(c.validate().is_err(), "{url}");
        }
        c.server_url = "http://[::1]:18080".into();
        assert!(c.validate().is_ok());
    }
    #[test]
    fn remote_config_cannot_change_kind_or_run_commands() {
        let mut c = RemoteConfig {
            version: 1,
            interval_seconds: 5,
            enabled: true,
            collectors: vec![Kind::Host],
        };
        assert!(c.validate(Kind::Host).is_ok());
        c.interval_seconds = 0;
        assert!(c.validate(Kind::Host).is_err());
        c.interval_seconds = 5;
        assert!(c.validate(Kind::Pve).is_err());
        assert!(serde_json::from_str::<RemoteConfig>(r#"{"version":1,"intervalSeconds":5,"enabled":true,"collectors":["host"],"command":"rm"}"#).is_err());
    }
}
