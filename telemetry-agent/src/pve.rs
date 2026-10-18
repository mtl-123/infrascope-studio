use crate::Config;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use url::Url;

const MAX_RESPONSE: u64 = 2 * 1024 * 1024;
const MAX_PAYLOAD: usize = 900 * 1024;
const COLLECTION_BUDGET: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PveConfig {
    pub base_url: String,
    pub token_env: String,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub node_filter: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_limit")]
    pub max_guests: usize,
}

fn default_timeout() -> u64 {
    5
}
fn default_limit() -> usize {
    100
}

impl PveConfig {
    pub fn validate(&self) -> Result<()> {
        validated_base(&self.base_url)?;
        if self.token_env.is_empty()
            || !self
                .token_env
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            bail!("pve.token_env must name an environment variable, not contain a token");
        }
        if !(1..=30).contains(&self.timeout_seconds) {
            bail!("pve.timeout_seconds must be between 1 and 30");
        }
        if !(1..=1000).contains(&self.max_guests) {
            bail!("pve.max_guests must be between 1 and 1000");
        }
        if self.node_filter.len() > 1000 || self.node_filter.iter().any(|node| !valid_node(node)) {
            bail!("pve.node_filter contains an invalid node name or too many nodes");
        }
        Ok(())
    }
}

fn validated_base(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| anyhow!("invalid PVE base URL"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("PVE base_url must be an HTTPS origin such as https://pve.example:8006 without credentials or a path");
    }
    Ok(url)
}

fn token_header(value: &str) -> Result<HeaderValue> {
    let token = value
        .strip_prefix("PVEAPIToken=")
        .context("PVE token must use PVEAPIToken=user@realm!tokenid=secret format")?;
    let (identity, secret) = token
        .split_once('=')
        .context("invalid PVE API token format")?;
    if !identity.contains('@')
        || !identity.contains('!')
        || secret.is_empty()
        || value.len() > 8192
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        bail!("invalid PVE API token format");
    }
    let mut header =
        HeaderValue::from_str(value).map_err(|_| anyhow!("invalid PVE API token header"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn client(config: &PveConfig) -> Result<Client> {
    config.validate()?;
    let secret = std::env::var(&config.token_env)
        .map_err(|_| anyhow!("PVE token environment variable is missing or not Unicode"))?;
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, token_header(&secret)?);
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(config.timeout_seconds))
        .timeout(Duration::from_secs(config.timeout_seconds));
    if let Some(path) = &config.ca_file {
        let bytes = std::fs::read(path).context("cannot read PVE CA file")?;
        let cert = reqwest::Certificate::from_pem(&bytes).context("invalid PVE CA PEM")?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .context("cannot initialize PVE HTTPS client")
}

fn get_data(client: &Client, url: &str, deadline: Instant, timeout: u64) -> Result<Value> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("PVE collection exceeded its 60-second budget");
    }
    let response = client
        .get(url)
        .timeout(remaining.min(Duration::from_secs(timeout)))
        .send()
        .map_err(|_| {
            anyhow!("PVE read request failed (connection, timeout, or TLS verification)")
        })?;
    if !response.status().is_success() {
        bail!(
            "PVE read request returned HTTP {}",
            response.status().as_u16()
        );
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .context("cannot read PVE response")?;
    if bytes.len() as u64 > MAX_RESPONSE {
        bail!("PVE response exceeds 2 MiB limit");
    }
    let value: Value = serde_json::from_slice(&bytes).context("PVE returned invalid JSON")?;
    unwrap_data(value)
}

fn unwrap_data(value: Value) -> Result<Value> {
    let data = value
        .get("data")
        .context("PVE response lacks data envelope")?;
    if data.is_null() {
        bail!("PVE response data is null");
    }
    Ok(data.clone())
}

fn valid_node(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= 253
        && node
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        && node != "."
        && node != ".."
}

fn guest_identity(item: &Value) -> Result<(&str, &str, u64)> {
    let node = item
        .get("node")
        .and_then(Value::as_str)
        .context("PVE guest is missing its node")?;
    if !valid_node(node) {
        bail!("PVE guest contains an invalid node");
    }
    let kind = item
        .get("type")
        .and_then(Value::as_str)
        .context("PVE guest is missing its type")?;
    if !matches!(kind, "qemu" | "lxc") {
        bail!("unsupported PVE guest type");
    }
    let vmid = item
        .get("vmid")
        .and_then(Value::as_u64)
        .context("PVE guest is missing a numeric vmid")?;
    if vmid == 0 || vmid > u32::MAX as u64 {
        bail!("PVE guest vmid is out of range");
    }
    Ok((node, kind, vmid))
}

fn as_counter(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_u64)
        .map(|n| json!(n.to_string()))
        .unwrap_or(Value::Null)
}

fn metrics(item: &Value) -> Result<Value> {
    if !item.is_object() {
        bail!("PVE status was not an object");
    }
    if item
        .get("status")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("PVE status response is missing its status field");
    }
    let cpu = item
        .get("cpu")
        .and_then(Value::as_f64)
        .filter(|n| n.is_finite() && *n >= 0.0);
    Ok(json!({
        "status":item.get("status"), "cpu_fraction":cpu, "cpu_percent":cpu.map(|n|n*100.0),
        "cpus":item.get("cpus").or_else(|| item.get("maxcpu")),
        "memory_used_bytes":as_counter(item.get("mem")), "memory_total_bytes":as_counter(item.get("maxmem")),
        "disk_used_bytes":as_counter(item.get("disk")), "disk_total_bytes":as_counter(item.get("maxdisk")),
        "network_in_bytes":as_counter(item.get("netin")), "network_out_bytes":as_counter(item.get("netout")),
        "disk_read_bytes":as_counter(item.get("diskread")), "disk_write_bytes":as_counter(item.get("diskwrite")),
        "uptime_seconds":as_counter(item.get("uptime")), "qmp_status":item.get("qmpstatus"),
        "pid":item.get("pid")
    }))
}

pub fn collect(config: &Config) -> Result<Value> {
    let config = config
        .pve
        .as_ref()
        .context("PVE collector is not configured")?;
    let client = client(config)?;
    let base = config.base_url.trim_end_matches('/');
    let deadline = Instant::now() + COLLECTION_BUDGET;
    let inventory = get_data(
        &client,
        &format!("{base}/api2/json/cluster/resources?type=vm"),
        deadline,
        config.timeout_seconds,
    )?;
    let inventory = inventory
        .as_array()
        .context("PVE guest inventory was not an array")?;
    let mut errors = Vec::new();
    let node_inventory = match get_data(
        &client,
        &format!("{base}/api2/json/nodes"),
        deadline,
        config.timeout_seconds,
    ) {
        Ok(value) if value.is_array() => value,
        Ok(_) => {
            errors.push(json!({"source":"nodes","error":"PVE node inventory was not an array"}));
            json!([])
        }
        Err(err) => {
            errors.push(json!({"source":"nodes","error":err.to_string()}));
            json!([])
        }
    };
    let selected_node =
        |node: &str| config.node_filter.is_empty() || config.node_filter.iter().any(|n| n == node);
    let mut nodes = Vec::new();
    for node in node_inventory.as_array().unwrap() {
        let name = match node
            .get("node")
            .and_then(Value::as_str)
            .filter(|n| valid_node(n))
        {
            Some(name) => name,
            None => {
                if errors.len() < 100 {
                    errors
                        .push(json!({"source":"nodes", "error":"invalid or absent PVE node name"}));
                }
                continue;
            }
        };
        if !selected_node(name) {
            continue;
        }
        nodes.push(json!({"node":name, "status":node.get("status"), "metrics":metrics(node)?, "source":"pve_node_inventory"}));
    }
    let mut guests = Vec::new();
    let mut selected_total = 0_usize;
    for item in inventory {
        let (node, kind, vmid) = match guest_identity(item) {
            Ok(identity) => identity,
            Err(err) => {
                if errors.len() < 100 {
                    errors.push(json!({"source":"inventory","error":err.to_string()}));
                }
                continue;
            }
        };
        if !selected_node(node) {
            continue;
        }
        selected_total += 1;
        if guests.len() >= config.max_guests {
            continue;
        }
        let id = format!("{node}/{kind}/{vmid}");
        let mut guest = json!({
            "id":id, "node":node, "type":kind, "vmid":vmid,
            "name":item.get("name"), "status":item.get("status"), "template":item.get("template"),
            "pool":item.get("pool"), "tags":item.get("tags"), "source":"pve_hypervisor_api", "guest_os_metrics":false
        });
        match get_data(
            &client,
            &format!("{base}/api2/json/nodes/{node}/{kind}/{vmid}/status/current"),
            deadline,
            config.timeout_seconds,
        )
        .and_then(|data| metrics(&data))
        {
            Ok(value) => {
                guest["metrics"] = value;
                guest["metrics_status"] = json!("collected");
            }
            Err(err) => {
                guest["metrics"] = Value::Null;
                guest["metrics_status"] = json!("error");
                if errors.len() < 100 {
                    errors.push(
                        json!({"guest_id":id,"source":"status/current","error":err.to_string()}),
                    );
                }
            }
        }
        guests.push(guest);
    }
    let truncated = selected_total > config.max_guests;
    let mut payload = json!({
        "collector":"pve", "source":"proxmox_ve_api", "status":if errors.is_empty() && !truncated {"ok"} else {"partial"},
        "nodes":nodes, "guests":guests, "guests_total":inventory.len(), "guests_selected":selected_total,
        "truncated":truncated, "errors":errors, "diagnostics_limit":100,
        "semantics":{"cpu_fraction":"PVE-reported CPU fraction; cpu_percent is fraction times 100", "network_bytes":"cumulative counters, not rates", "disk_io_bytes":"cumulative counters, not rates", "guest_os_metrics":"hypervisor observations only; install the host agent inside each VM/LXC for guest OS disks, processes, and interfaces", "identity":"collector/cluster binding plus node/type/vmid; display names are not identity", "permissions":"PVE API tokens must be granted read-only audit privileges; restricted inventory may omit guests"}
    });
    bound_payload(&mut payload)?;
    Ok(payload)
}

fn bound_payload(payload: &mut Value) -> Result<()> {
    while serde_json::to_vec(payload)?.len() > MAX_PAYLOAD {
        let guests = payload["guests"]
            .as_array_mut()
            .context("missing PVE result guests")?;
        if guests.is_empty() {
            let nodes = payload["nodes"]
                .as_array_mut()
                .context("missing PVE result nodes")?;
            if nodes.is_empty() {
                bail!("PVE diagnostic payload exceeds transport size limit");
            }
            nodes.truncate(nodes.len() / 2);
        } else {
            guests.truncate(guests.len() / 2);
        }
        payload["truncated"] = json!(true);
        payload["status"] = json!("partial");
        payload["truncation_reason"] = json!("transport_payload_limit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pve_rejects_plaintext_and_credential_urls() {
        assert!(validated_base("https://pve.example:8006").is_ok());
        for url in [
            "http://127.0.0.1:8006",
            "https://u:p@pve.example:8006",
            "https://pve.example:8006/api2",
            "https://pve.example/?token=x",
        ] {
            assert!(validated_base(url).is_err());
        }
    }

    #[test]
    fn pve_tokens_are_headers_not_urls_and_debug_is_redacted() {
        let header = token_header("PVEAPIToken=agent@pve!metrics=secret-value").unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("secret-value"));
        for invalid in [
            "secret",
            "PVEAPIToken=agent@pve!metrics=",
            "PVEAPIToken=agent@pve!metrics=secret\r\nX-Evil: true",
        ] {
            assert!(token_header(invalid).is_err());
        }
    }

    #[test]
    fn pve_vm_lxc_and_nodes_have_distinct_identities() {
        let identities: Vec<String> = [
            json!({"node":"pve-a","type":"qemu","vmid":100,"name":"shared"}),
            json!({"node":"pve-a","type":"lxc","vmid":100,"name":"shared"}),
            json!({"node":"pve-b","type":"qemu","vmid":100,"name":"shared"}),
        ]
        .iter()
        .map(|v| {
            let (node, kind, id) = guest_identity(v).unwrap();
            format!("{node}/{kind}/{id}")
        })
        .collect();
        assert_ne!(identities[0], identities[1]);
        assert_ne!(identities[0], identities[2]);
        for value in [
            json!({"node":"../evil","type":"qemu","vmid":100}),
            json!({"node":"pve","type":"qemu","vmid":"100/../"}),
            json!({"node":"pve","type":"evil","vmid":100}),
        ] {
            assert!(guest_identity(&value).is_err());
        }
    }

    #[test]
    fn pve_real_envelope_shapes_and_unknown_metrics() {
        let data = unwrap_data(json!({"data":{"status":"running","cpu":0.125,"maxcpu":4,"mem":123456,"maxmem":1073741824,"netin":9007199254740993_u64}})).unwrap();
        let parsed = metrics(&data).unwrap();
        assert_eq!(parsed["cpu_percent"], 12.5);
        assert_eq!(parsed["network_in_bytes"], "9007199254740993");
        assert!(parsed["network_out_bytes"].is_null());
        let stopped = metrics(&json!({"status":"stopped"})).unwrap();
        assert!(stopped["cpu_percent"].is_null());
        assert!(stopped["memory_used_bytes"].is_null());
        assert!(unwrap_data(json!({"errors":{"permission":"denied"}})).is_err());
        assert!(unwrap_data(json!({"data":null})).is_err());
        assert!(metrics(&json!([])).is_err());
        assert!(metrics(&json!({})).is_err());
    }

    #[test]
    fn pve_large_inventory_is_explicitly_partial_not_unuploadable() {
        let mut payload = json!({"nodes":[],"guests":[{"id":"pve/qemu/100","name":"x".repeat(MAX_PAYLOAD)}],"truncated":false,"status":"ok"});
        bound_payload(&mut payload).unwrap();
        assert_eq!(payload["truncated"], true);
        assert_eq!(payload["status"], "partial");
        assert!(serde_json::to_vec(&payload).unwrap().len() <= MAX_PAYLOAD);
    }
}
