use crate::config::{Config, Kind, RemoteConfig};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, time::Duration};

pub const ENROLL_PATH: &str = "/api/v1/agents/enroll";
pub const CONFIG_PATH: &str = "/api/v1/agent/config";
pub const SAMPLES_PATH: &str = "/api/v1/agent/samples";
pub const MAX_BODY: usize = 1024 * 1024;

pub fn canonical(method: &str, path: &str, time: &str, nonce: &str, body: &[u8]) -> String {
    format!(
        "{method}\n{path}\n{time}\n{nonce}\n{}",
        hex::encode(Sha256::digest(body))
    )
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub schema_version: u32,
    pub batch_id: String,
    pub agent_id: String,
    pub asset_id: String,
    pub sequence: String,
    pub observed_at: String,
    pub config_version: u64,
    pub kind: Kind,
    pub metrics: serde_json::Value,
    pub health: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub agent_id: String,
    pub asset_id: String,
    pub config: RemoteConfig,
}

#[derive(Debug, Deserialize)]
pub struct ConfigResponse {
    pub config: RemoteConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ack {
    pub accepted: bool,
    pub batch_id: String,
    pub duplicate: bool,
}

pub struct Transport {
    client: Client,
    origin: String,
    timeout: Duration,
}

impl Transport {
    pub fn new(config: &Config) -> Result<Self> {
        config.validate()?;
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .connect_timeout(Duration::from_secs(config.request_timeout_seconds.min(10)))
            .user_agent(concat!("InfraScopeAgent/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = &config.ca_cert {
            let pem = std::fs::read(path).context("read server CA certificate")?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("parse server CA certificate")?,
            );
        }
        Ok(Self {
            client: builder.build().context("build HTTPS transport")?,
            origin: config.server_url.trim_end_matches('/').into(),
            timeout: Duration::from_secs(config.request_timeout_seconds),
        })
    }

    fn response<T: serde::de::DeserializeOwned>(
        response: reqwest::blocking::Response,
    ) -> Result<T> {
        let status = response.status();
        if !status.is_success() {
            bail!(
                "server returned HTTP {}; response body omitted to protect secrets",
                status.as_u16()
            );
        }
        let mut bytes = Vec::new();
        response
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)
            .context("read bounded server response")?;
        if bytes.len() > MAX_BODY {
            bail!("server response exceeds 1 MiB");
        }
        serde_json::from_slice(&bytes).context("invalid server response")
    }

    pub fn enroll(&self, token: &str, key: &SigningKey, kind: Kind) -> Result<Enrollment> {
        if token.is_empty() || token.len() > 4096 {
            bail!("enrollment token must contain 1..4096 characters");
        }
        let body = serde_json::json!({
            "token": token,
            "publicKey": STANDARD.encode(key.verifying_key().as_bytes()),
            "hostname": sysinfo::System::host_name().unwrap_or_else(|| "unknown".into()),
            "os": std::env::consts::OS,
            "version": env!("CARGO_PKG_VERSION"),
            "kind": kind,
        });
        let response = self
            .client
            .post(format!("{}{}", self.origin, ENROLL_PATH))
            .json(&body)
            .send()
            .context("enrollment request failed")?;
        let result: Enrollment = Self::response(response)?;
        if result.agent_id.is_empty()
            || result.asset_id.is_empty()
            || result.agent_id.len() > 128
            || result.asset_id.len() > 128
        {
            bail!("invalid enrollment identifiers");
        }
        result.config.validate(kind)?;
        Ok(result)
    }

    pub fn signed<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        agent_id: &str,
        key: &SigningKey,
        body: &[u8],
    ) -> Result<T> {
        self.signed_with_timeout(path, agent_id, key, body, self.timeout)
    }

    pub fn signed_with_timeout<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        agent_id: &str,
        key: &SigningKey,
        body: &[u8],
        remaining: Duration,
    ) -> Result<T> {
        if ![CONFIG_PATH, SAMPLES_PATH].contains(&path) {
            bail!("unsupported signed endpoint");
        }
        if body.len() > MAX_BODY {
            bail!("sample exceeds 1 MiB");
        }
        let time = chrono::Utc::now().timestamp().to_string();
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let signature = key.sign(canonical("POST", path, &time, &nonce, body).as_bytes());
        let response = self
            .client
            .post(format!("{}{path}", self.origin))
            .timeout(self.timeout.min(remaining))
            .header("Content-Type", "application/json")
            .header("X-Agent-Id", agent_id)
            .header("X-Agent-Time", time)
            .header("X-Agent-Nonce", nonce)
            .header("X-Agent-Signature", STANDARD.encode(signature.to_bytes()))
            .body(body.to_vec())
            .send()
            .context("signed request failed")?;
        Self::response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    #[test]
    fn canonical_signature_binds_path_nonce_and_exact_body() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let body = b"{\"sequence\":\"9007199254740993\"}";
        let message = canonical("POST", SAMPLES_PATH, "100", "nonce", body);
        let sig = key.sign(message.as_bytes());
        assert!(key.verifying_key().verify(message.as_bytes(), &sig).is_ok());
        for altered in [
            canonical("POST", CONFIG_PATH, "100", "nonce", body),
            canonical("POST", SAMPLES_PATH, "100", "other", body),
            canonical("POST", SAMPLES_PATH, "100", "nonce", b"{}"),
        ] {
            assert!(key
                .verifying_key()
                .verify(altered.as_bytes(), &sig)
                .is_err());
        }
        assert_eq!(
            canonical("POST", "/x", "1", "n", b""),
            "POST\n/x\n1\nn\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
