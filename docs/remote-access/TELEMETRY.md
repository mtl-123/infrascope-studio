# Telemetry Agent Protocol v1

This is the implemented agent ingestion boundary, not acceptance of every
monitoring requirement. Host, Docker and PVE use the same signed transport but
have separate, immutable enrollment kinds. A PVE collector reads hypervisor/API
measurements; install a host agent inside a guest when guest OS measurements are
required. A recent authenticated report is not proof that every measurement was
available, nor that every virtual machine is reachable.

## Transport and identity

- Production agent endpoints require native HTTPS on the Go server. HTTP is
  accepted only with explicit `REMOTE_LOOPBACK_TEST=true` and loopback peer/origin.
  `X-Forwarded-*` cannot bypass this check. Configure the real CA on the client;
  there is no protocol flag to disable certificate validation.
- Web administration uses the existing login cookie, CSRF token and asset
  management boundary. An asset manager can enroll/manage only their own assets;
  an administrator is still confined to their workspace.
- Each agent is permanently bound to one asset, workspace, collector kind and
  raw Ed25519 public key. Enrollment requires an enabled, non-archived asset with
  recorded responsibility. Agent revocation cannot be undone by sending samples
  or reusing an enrollment token.
- Enrollment bearer tokens are returned once by the administrative endpoint and
  stored as SHA-256 hashes, never in audit details. Keep tokens out of URLs,
  shell history and shared logs. The server stores no agent private key.
- Local Docker endpoints and PVE API credentials are client deployment settings,
  not remotely supplied commands. Runtime server configuration contains only
  enabled state, collection interval, version and the enrolled collector kind.

## Administrative API

All JSON endpoints use `Content-Type: application/json`. Authenticated modifying
requests additionally require `Origin` matching `REMOTE_PUBLIC_ORIGIN` and the
session `X-CSRF-Token`.

### Create an enrollment

`POST /api/v1/agents/enrollments`

```json
{"assetId":"existing-asset-id","kind":"host","expiresInSeconds":600}
```

Kinds are `host`, `docker`, or `pve`. Lifetime defaults to 600 seconds and must be
60..3600 seconds. Successful response is HTTP 201:

```json
{"id":"enrollment-id","token":"returned-only-here","expiresAt":"2026-10-18T10:10:00Z"}
```

There is no automatic asset creation, responsibility assignment, remote-access
grant, host-key approval or network allowlist expansion.

### Inspect agents

`GET /api/v1/agents?assetId=existing-asset-id&offset=0`

Returns at most 100 rows, filtered by management scope. Each row contains `id`,
`assetId`, `kind`, `hostname`, `os`, `agentVersion`, `desiredVersion`,
`appliedVersion`, `intervalSeconds`, `enabled`, `revoked`, `createdAt`, `lastSeen`
and `revokedAt`. It never returns enrollment tokens or public/private key fields.

### Change runtime configuration

`PATCH /api/v1/agents/{id}/config`

```json
{"version":1,"intervalSeconds":10,"enabled":true,"collectors":["host"]}
```

`version` is the current desired version, not the desired replacement. A
successful response returns the new configuration with version incremented. The
interval is 1..3600 seconds and `collectors` must contain exactly the enrollment
kind. Stale version, wrong kind and revoked identity return HTTP 409. Disabled
collection denies new samples but still permits configuration polling so the
client can receive a later enable instruction. Desired and client-applied
versions are tracked separately; saving a configuration is not proof of delivery.

### Revoke an identity

`POST /api/v1/agents/{id}/revoke`

```json
{"confirm":true}
```

Returns `{"revoked":true}` after the transaction commits. Subsequent agent
configuration and sample requests fail with HTTP 403. Revocation serializes with
ingestion on the agent row: a sample cannot commit after an already committed
revocation using a stale authentication result. History is retained.

## Agent enrollment

`POST /api/v1/agents/enroll` does not use a browser session. It requires HTTPS and
the enrollment bearer token:

```json
{
  "token":"token-from-administrator",
  "publicKey":"base64-of-32-raw-ed25519-public-key-bytes",
  "hostname":"host-01",
  "os":"linux",
  "version":"0.1.0",
  "kind":"host"
}
```

First use returns HTTP 201:

```json
{
  "agentId":"generated-agent-id",
  "assetId":"existing-asset-id",
  "config":{"version":1,"intervalSeconds":5,"enabled":true,"collectors":["host"]},
  "serverTime":"2026-10-18T10:00:00Z"
}
```

One token creates at most one identity. If the first HTTPS response is lost,
retrying the same unexpired token with the same public key and kind returns HTTP
200 with that same identity and its current configuration. It never replaces a
public key or creates a second identity. Expired tokens, wrong keys/kinds,
revocation, disabled asset or loss of issuing administrator's authority fail.
Persist the private key before making the first enrollment request. When the
token expires before recovery, request a new token rather than inventing an ID.

## Signed requests

Both signed endpoints require these headers:

```text
X-Agent-Id: enrolled-agent-id
X-Agent-Time: Unix timestamp in whole seconds
X-Agent-Nonce: random unique string, 20..100 bytes
X-Agent-Signature: standard Base64 Ed25519 signature
```

Sign the UTF-8 bytes of this exact canonical string, with no final newline:

```text
METHOD\nESCAPED_URL_PATH\nTIME\nNONCE\nLOWERCASE_SHA256_HEX_OF_EXACT_BODY_BYTES
```

For example the method is `POST` and path is `/api/v1/agent/samples`, with no
query string. The server accepts at most 30 seconds of clock difference. Sync
system clocks; `serverTime` in replies does not silently change the local clock.
Bodies must be uncompressed JSON and at most 1 MiB. Sign the exact bytes sent,
not a reserialized object. Successfully accepted nonces are persisted for one
minute. Each retry needs a fresh nonce/signature while retaining the exact sample
body. Altering a committed batch's serialized content is an integrity conflict.

### Poll configuration

`POST /api/v1/agent/config`

```json
{"appliedVersion":1}
```

Response is HTTP 200:

```json
{
  "config":{"version":2,"intervalSeconds":10,"enabled":true,"collectors":["host"]},
  "serverTime":"2026-10-18T10:01:00Z"
}
```

`appliedVersion` may be zero before applying an initial configuration. It cannot
exceed the current desired version. Clients must validate/apply the received
configuration before acknowledging its version.

### Submit a sample

`POST /api/v1/agent/samples`

```json
{
  "schemaVersion":1,
  "batchId":"3c1ae2f8-6792-4de1-b347-66916015dc7a",
  "agentId":"enrolled-agent-id",
  "assetId":"existing-asset-id",
  "sequence":"1",
  "observedAt":"2026-10-18T10:00:00.123Z",
  "configVersion":1,
  "kind":"host",
  "metrics":{"cpu":{"usagePercent":19.25}},
  "health":{"status":"ok"}
}
```

- `batchId` must be a UUID. `sequence` is a canonical positive uint64 decimal
  string, not a floating-point JSON number. It is unique within an agent;
  out-of-order delivery is allowed to support a durable local queue.
- `observedAt` is the collection time in RFC3339, at most 30 days old and at most
  5 minutes in the future. `receivedAt` is assigned separately by PostgreSQL.
- Scope, kind and schema version are validated. `configVersion` must be positive
  and no higher than the current desired configuration version.
- `metrics` and `health` are objects; missing measurements may be null or omitted,
  not synthetic zeroes. JSON nesting is capped at 16, arrays at 1000 elements and
  aggregate object traversal at 20000 values, within the whole-body 1 MiB limit.
- The server stores JSONB data without executing source strings or metric names.
  This v1 boundary does not implement typed time-series aggregation, arbitrary
  commands, automatic discovery promotion, or a complete cardinality policy.

Only after the database transaction commits does the server return HTTP 200:

```json
{"accepted":true,"batchId":"3c1ae2f8-6792-4de1-b347-66916015dc7a","duplicate":false}
```

An exact retry returns `duplicate:true`. A reused batch with different bytes or a
sequence reused under another batch returns HTTP 409. A DB failure returns HTTP
500 with no success ACK; the sample and nonce transaction rolls back together.
Do not remove a queued sample without a matching durable ACK.

## Read actual telemetry

`GET /api/v1/assets/{id}/telemetry?limit=50&offset=0`

The existing asset visibility rules apply, including group/organization/grant
revocation and workspace boundaries. A visible asset is not automatically
manageable, and a metadata viewer receives no remote account secrets.

Optional `since` and `until` are RFC3339 timestamps, with a positive range no
longer than 31 days. Default is the previous hour, with the admitted future clock
skew. `limit` is 1..100. Results include `hasMore` and `nextOffset`; use a fixed
time range when paginating changing data.

```json
{
  "assetId":"existing-asset-id",
  "agents":[],
  "samples":[],
  "dataState":"empty",
  "observedAt":null,
  "hasMore":false,
  "nextOffset":0,
  "retentionDays":30,
  "statusMeaning":"fresh means recent authenticated sample, not host power, reachability or successful collection"
}
```

Sample rows return the submitted envelope plus `receivedAt`, without signature,
nonce or internal payload hash. `dataState` describes latest known data across
the asset, independently of the selected historical page. `fresh` means an
enabled, non-revoked agent and enabled asset have a latest sample younger than
`max(30 seconds, 3 * configured interval)`. `stale` retains history, including
disabled/revoked sources. `empty` means no stored sample; no metric values are
fabricated. Inspect each sample's `health` to distinguish partial collection from
healthy measurement.

## Operational limits and test evidence

- Enrollment is limited to 60 requests per minute per issuing user; public
  enrollment attempts to 60 per peer IP; signed requests to 240 per agent. Use
  bounded backoff for HTTP 429/5xx rather than a tight loop.
- Replay rows are expired during the next request by that agent. Sample cleanup
  deletes rows received more than 30 days ago during successful ingestion by the
  same agent. **There is no background/global retention worker yet**: inactive
  agents can retain old rows. `retentionDays` is this implemented cleanup target,
  not a complete configurable storage lifecycle guarantee.
- Migration `008_telemetry_agents.sql` adds enrollment, agent, nonce and sample
  tables to the existing PostgreSQL schema. Apply via the normal migration
  command; do not point test scripts at the user's live database.
- `telemetry_test.go` exercises real isolated PostgreSQL transactions, replay,
  scope, enroll concurrency/recovery, exact ACK retry, uint64 precision, DB
  failure rollback, optimistic config updates, revoke, pagination and stale/empty
  states. Go protocol fixtures are not live Windows/Linux/Docker/PVE acceptance.
- Runtime integration with actual compiled clients and external-device coverage
  must be reported separately. Unavailable physical/test targets remain
  incomplete, even if serialization, API or build tests pass.
