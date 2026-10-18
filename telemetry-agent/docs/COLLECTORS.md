# Docker and Proxmox VE collectors

The dedicated `infrascope-docker-collector` and `infrascope-pve-collector`
binaries use the same enrollment, signed upload, local queue, and server
configuration protocol as `infrascope-agent`. Give each collector a separate
state directory and enrollment. Never share an identity directory between
collectors or machines. Server-side configuration can disable collection or
change intervals, but cannot supply arbitrary endpoints or execute commands.

## Deployment model

- Install `infrascope-agent` inside each Windows/Linux machine or VM for guest
  OS CPU, memory, interface counters, and filesystem capacity.
- Run the Docker collector beside Docker on Linux using a Unix socket, or use
  an explicitly configured TLS-protected Docker API endpoint. Windows builds
  support verified HTTPS Docker endpoints, not Windows named pipes in this
  version. Do not expose an unauthenticated Docker API on a network.
- Run the PVE collector on a management machine that can reach the cluster's
  HTTPS API. No installation or command execution inside a VM is required for
  hypervisor observations. QEMU VMs and LXC containers remain separate types.
- PVE hypervisor observations do not replace the guest OS agent. In particular,
  PVE `disk`/`maxdisk` are API-reported figures, not a claim about free space in
  every guest filesystem. VM lifecycle operations are not implemented.

## Docker local configuration

Generate the complete configuration using the binary's `init-config` command,
then configure this section:

```toml
[docker]
endpoint = "unix:///var/run/docker.sock"
# api_version = "1.45"
timeout_seconds = 5
max_containers = 100
```

Linux socket read access is powerful: Docker's API can control the host even
though this collector only issues GET requests. Prefer a read-only API proxy
that only allows `/version`, `/containers/json`, and container `/stats`.
Adding an account to the Docker group grants broader privileges than this
collector itself needs; do not do it casually.

For a Docker TLS endpoint on either supported OS:

```toml
[docker]
endpoint = "https://docker.example.internal:2376"
ca_file = "./docker-ca.pem"
client_identity_file = "./docker-client-identity.pem"
timeout_seconds = 5
max_containers = 100
```

The identity PEM combines the client certificate and private key; secure its
filesystem permissions. File paths are resolved relative to the configuration.
Plain HTTP is accepted only when the operator explicitly configures a literal
loopback IP (`127.0.0.1` or `::1`). There is no TLS verification bypass. Proxy
environment variables and redirects are disabled for collector requests.

Only selected grouping labels are exported: Compose project, service and
container number; Swarm service ID and name. Arbitrary labels, environment
variables, inspect output, and embedded application secrets are not exported.

Docker metrics:

- `cpu_percent` is the Engine's current-versus-previous CPU delta, divided by
  the system delta and multiplied by online CPUs and 100. It may exceed 100 on
  multicore hosts. `sample_time` and `previous_sample_time` define the actual
  window. Missing/reset baselines yield null, not an invented rate.
- Memory usage and limit are raw bytes. Working set subtracts
  `total_inactive_file` (cgroup v1) or `inactive_file` (cgroup v2). It is null if
  unavailable or inconsistent. A zero memory limit has no computed percentage.
- Network and block I/O are cumulative counters, not instantaneous throughput.
  64-bit byte/counter values use decimal strings to avoid JavaScript rounding.
- Stopped containers remain in inventory with `metrics_status=not_running` and
  null metrics. A failed stats request sets that container's status to `error`
  and the collection to `partial`; other inventory remains available.

## PVE local configuration

```toml
[pve]
base_url = "https://pve.example.internal:8006"
token_env = "INFRASCOPE_PVE_TOKEN"
ca_file = "./pve-ca.pem"
node_filter = []
timeout_seconds = 5
max_guests = 100
```

Place a token of this shape in the collector process environment, not in the
TOML file, command arguments, URL, or chat:

```text
PVEAPIToken=metrics@pve!collector=<secret>
```

Give the token the least read-only audit privileges required for the intended
nodes and guests (typically PVEAuditor scoped to the relevant paths). Both the
user and a privilege-separated token must have the required permissions. The
collector cannot prove whether a successful inventory omits guests invisible
to that token. Confirm expected inventory against the PVE management interface.

The collector sends only:

```text
GET /api2/json/cluster/resources?type=vm
GET /api2/json/nodes
GET /api2/json/nodes/{node}/qemu/{vmid}/status/current
GET /api2/json/nodes/{node}/lxc/{vmid}/status/current
```

The token is a sensitive Authorization header, not logged. HTTPS certificate
and hostname verification are mandatory. Configure the PVE CA, not an insecure
mode. Redirects and HTTP proxies are disabled, and all requests stay on the
configured origin. Node and VM identifiers are validated before path use.

PVE metrics include API-reported CPU fraction and percentage, allocated CPUs,
memory, disk, cumulative network/disk-I/O counters, uptime, and status. Missing
metrics remain null. Guest identity includes node, type, and numeric VM ID;
display names are not unique identifiers. The agent/asset enrollment binds
this identity to its particular cluster. Migrating a VM to another node changes
this version's node-qualified identity; reconciliation is not implemented.

## Limits and verification boundaries

Each collector has a 60-second collection budget, 1-30-second request timeout,
2 MiB API response limit, and 1-1000 configured inventory limit. Serialized
metrics are capped below the transport's 1 MiB limit: oversized inventories
are reduced with `truncated=true`, `status=partial`, and an explicit reason.
At most 100 detailed errors are returned. Large inventories should use narrower
node scope or multiple independently enrolled collectors; this is not a claim
of complete inventory collection after a truncation warning.

The sample command prints real observations without uploading or enrolling.
The Docker API fixtures in Rust tests verify parsing, counters, request safety,
partial failures, and size limits; they are not live Docker acceptance. PVE
fixtures similarly do not verify real cluster authentication or VM/LXC data.

On 2026-10-18, a compiled Linux collector read the local WSL Docker Engine
29.1.3: seven containers were returned, six running containers supplied real
stats, and one stopped container retained null metrics. Evidence is in the
development workspace's `.local-dev/telemetry-evidence/docker-readonly-sample.json`.
That sample did not upload data. PVE real-cluster access, Windows Docker TLS,
and production continuous collection remain unverified until tested with the
operator's actual targets and credentials.
