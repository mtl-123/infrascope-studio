package access

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const telemetryBodyLimit = 1 << 20

var telemetryBatchPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type agentRuntimeConfig struct {
	Version         int64    `json:"version"`
	IntervalSeconds int      `json:"intervalSeconds"`
	Enabled         bool     `json:"enabled"`
	Collectors      []string `json:"collectors"`
}

type telemetryAgent struct {
	ID, Workspace, Asset, Kind string
	Config                     agentRuntimeConfig
}

type telemetrySample struct {
	SchemaVersion int             `json:"schemaVersion"`
	BatchID       string          `json:"batchId"`
	AgentID       string          `json:"agentId"`
	AssetID       string          `json:"assetId"`
	Sequence      string          `json:"sequence"`
	ObservedAt    time.Time       `json:"observedAt"`
	ConfigVersion int64           `json:"configVersion"`
	Kind          string          `json:"kind"`
	Metrics       json.RawMessage `json:"metrics"`
	Health        json.RawMessage `json:"health"`
}

func (a *App) telemetryTransport(r *http.Request) error {
	if !a.Config.Enabled || a.leaseLost.Load() {
		return fail(503, "agent_unavailable", "Telemetry service is unavailable")
	}
	origin, err := url.Parse(a.Config.Origin)
	if err == nil && origin.Scheme == "https" && r.TLS != nil {
		return nil
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && a.Config.LoopbackTest && loopback(host) && origin != nil && loopback(origin.Hostname()) {
		return nil
	}
	return fail(403, "agent_tls_required", "Agents require HTTPS; forwarded headers are not trusted")
}

func (a *App) agentEnrollments(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := a.telemetryTransport(r); err != nil {
		return err
	}
	var in struct {
		AssetID          string `json:"assetId"`
		Kind             string `json:"kind"`
		ExpiresInSeconds int    `json:"expiresInSeconds"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if !contains([]string{"host", "docker", "pve"}, in.Kind) {
		return fail(400, "agent_kind", "Collector kind must be host, docker or pve")
	}
	if in.ExpiresInSeconds == 0 {
		in.ExpiresInSeconds = 600
	}
	if in.ExpiresInSeconds < 60 || in.ExpiresInSeconds > 3600 {
		return fail(400, "agent_expiry", "Enrollment lifetime must be 60 to 3600 seconds")
	}
	if err := a.manageAsset(r.Context(), u, in.AssetID); err != nil {
		return err
	}
	if !a.rate("agent-enrollment:"+u.ID, 60, time.Minute) {
		return fail(429, "agent_rate", "Too many enrollment requests")
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = telemetryAssetReady(ctx, tx, u.Workspace, in.AssetID); err != nil {
		return err
	}
	id, token := ID(), ID()+ID()
	expires := time.Now().UTC().Add(time.Duration(in.ExpiresInSeconds) * time.Second)
	_, err = tx.Exec(ctx, `INSERT INTO ra_agent_enrollments(id,workspace,asset_id,kind,token_hash,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, u.Workspace, in.AssetID, in.Kind, digest(token), u.ID, expires)
	if err == nil {
		err = a.audit(context.WithValue(ctx, txContextKey{}, tx), u, "agent.enrollment.create", id, "success", "", map[string]any{"assetId": in.AssetID, "kind": in.Kind, "expiresAt": expires})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	jsonOut(w, 201, map[string]any{"id": id, "token": token, "expiresAt": expires})
	return nil
}

func telemetryAssetReady(ctx context.Context, tx pgx.Tx, workspace, asset string) error {
	var usable, owned bool
	err := tx.QueryRow(ctx, `SELECT enabled AND NOT archived,NOT ownership_legacy AND EXISTS(SELECT 1 FROM ra_asset_responsibility_refs rr WHERE rr.workspace=a.workspace AND rr.asset_id=a.id) FROM ra_assets a WHERE workspace=$1 AND id=$2 FOR SHARE OF a`, workspace, asset).Scan(&usable, &owned)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!usable || !owned) {
		return fail(403, "agent_asset_disabled", "Asset must be enabled and have assigned responsibility before enrollment or ingestion")
	}
	return err
}

func (a *App) agentEnroll(w http.ResponseWriter, r *http.Request) {
	if err := a.enrollTelemetry(w, r); err != nil {
		errorOut(w, err)
	}
}

func (a *App) enrollTelemetry(w http.ResponseWriter, r *http.Request) error {
	if err := a.telemetryTransport(r); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !a.rate("agent-enroll-ip:"+host, 60, time.Minute) {
		return fail(429, "agent_rate", "Too many enrollment attempts")
	}
	var in struct {
		Token     string `json:"token"`
		PublicKey string `json:"publicKey"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		Version   string `json:"version"`
		Kind      string `json:"kind"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(in.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || !bounded(in.Token, 100) || !bounded(in.Hostname, 255) || !bounded(in.OS, 80) || !bounded(in.Version, 80) || !contains([]string{"host", "docker", "pve"}, in.Kind) {
		return fail(400, "agent_identity", "Invalid agent identity, raw Ed25519 public key or collector kind")
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var enrollment, workspace, asset, creator string
	err = tx.QueryRow(ctx, `UPDATE ra_agent_enrollments e SET consumed_at=now() WHERE token_hash=$1 AND kind=$2 AND consumed_at IS NULL AND expires_at>now()
 AND EXISTS(SELECT 1 FROM ra_users u JOIN ra_assets a ON a.workspace=u.workspace AND a.id=e.asset_id WHERE u.workspace=e.workspace AND u.id=e.created_by AND u.enabled AND (u.role='admin' OR (u.role='asset_manager' AND a.created_by=u.id)))
 RETURNING id,workspace,asset_id,created_by`, digest(in.Token), in.Kind).Scan(&enrollment, &workspace, &asset, &creator)
	if errors.Is(err, pgx.ErrNoRows) {
		// A lost HTTPS response must not strand an identity. The one-use token can
		// recover only its already-created identity, never bind a different key.
		var id string
		config := agentRuntimeConfig{Collectors: []string{in.Kind}}
		err = tx.QueryRow(ctx, `SELECT ag.id,e.workspace,e.asset_id,ag.config_version,ag.interval_seconds,ag.enabled
 FROM ra_agent_enrollments e JOIN ra_agents ag ON ag.enrollment_id=e.id
 WHERE e.token_hash=$1 AND e.kind=$2 AND ag.kind=$2 AND ag.public_key=$3 AND e.expires_at>now() AND e.consumed_at IS NOT NULL AND NOT ag.revoked
 AND EXISTS(SELECT 1 FROM ra_users u JOIN ra_assets a ON a.workspace=u.workspace AND a.id=e.asset_id WHERE u.workspace=e.workspace AND u.id=e.created_by AND u.enabled AND (u.role='admin' OR (u.role='asset_manager' AND a.created_by=u.id)))
 FOR UPDATE OF ag`, digest(in.Token), in.Kind, pub).Scan(&id, &workspace, &asset, &config.Version, &config.IntervalSeconds, &config.Enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return fail(410, "agent_enrollment_expired", "Enrollment is expired, used by another key, revoked or no longer authorized")
		}
		if err != nil {
			return err
		}
		if err = telemetryAssetReady(ctx, tx, workspace, asset); err != nil {
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		jsonOut(w, 200, map[string]any{"agentId": id, "assetId": asset, "config": config, "serverTime": time.Now().UTC()})
		return nil
	}
	if err != nil {
		return err
	}
	if err = telemetryAssetReady(ctx, tx, workspace, asset); err != nil {
		return err
	}
	id := ID()
	_, err = tx.Exec(ctx, `INSERT INTO ra_agents(id,workspace,asset_id,enrollment_id,kind,public_key,hostname,os,agent_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, workspace, asset, enrollment, in.Kind, pub, in.Hostname, in.OS, in.Version)
	if err == nil {
		err = a.audit(context.WithValue(ctx, txContextKey{}, tx), &User{ID: creator, Workspace: workspace}, "agent.enroll", id, "success", "", map[string]string{"assetId": asset, "kind": in.Kind})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	jsonOut(w, 201, map[string]any{"agentId": id, "assetId": asset, "config": agentRuntimeConfig{Version: 1, IntervalSeconds: 5, Enabled: true, Collectors: []string{in.Kind}}, "serverTime": time.Now().UTC()})
	return nil
}

func (a *App) authenticateAgent(r *http.Request, tx pgx.Tx) (telemetryAgent, []byte, error) {
	var agent telemetryAgent
	id, ts, nonce, signature := r.Header.Get("X-Agent-Id"), r.Header.Get("X-Agent-Time"), r.Header.Get("X-Agent-Nonce"), r.Header.Get("X-Agent-Signature")
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(timestamp, 0)) > 30*time.Second || time.Until(time.Unix(timestamp, 0)) > 30*time.Second || len(nonce) < 20 || !bounded(nonce, 100) || !bounded(id, 120) {
		return agent, nil, fail(403, "agent_auth", "Invalid agent identity, timestamp or nonce")
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" {
		return agent, nil, fail(400, "agent_encoding", "Signed requests require uncompressed JSON and no query string")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, telemetryBodyLimit+1))
	if err != nil || len(body) > telemetryBodyLimit {
		return agent, nil, fail(413, "body_limit", "Agent request exceeds 1 MiB")
	}
	var pub []byte
	agent.ID = id
	// Serialize requests with revocation and config changes; no sample can commit
	// after a previously committed revocation using a stale authentication result.
	err = tx.QueryRow(r.Context(), `SELECT workspace,asset_id,kind,public_key,config_version,interval_seconds,enabled FROM ra_agents WHERE id=$1 AND NOT revoked FOR UPDATE`, id).Scan(&agent.Workspace, &agent.Asset, &agent.Kind, &pub, &agent.Config.Version, &agent.Config.IntervalSeconds, &agent.Config.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return agent, nil, fail(403, "agent_revoked", "Agent is unknown or revoked")
	}
	if err != nil {
		return agent, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	hash := sha256.Sum256(body)
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(hash[:])
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(canonical), sig) {
		return agent, nil, fail(403, "agent_signature", "Agent signature verification failed")
	}
	if !a.rate("agent-signed:"+id, 240, time.Minute) {
		return agent, nil, fail(429, "agent_rate", "Agent request limit exceeded; retry with backoff")
	}
	if err = telemetryAssetReady(r.Context(), tx, agent.Workspace, agent.Asset); err != nil {
		return agent, nil, err
	}
	_, err = tx.Exec(r.Context(), `DELETE FROM ra_agent_nonces WHERE agent_id=$1 AND expires_at<now()`, id)
	if err != nil {
		return agent, nil, err
	}
	result, err := tx.Exec(r.Context(), `INSERT INTO ra_agent_nonces(agent_id,nonce_hash,expires_at) VALUES($1,$2,now()+interval '1 minute') ON CONFLICT DO NOTHING`, id, digest(nonce))
	if err != nil {
		return agent, nil, err
	}
	if result.RowsAffected() != 1 {
		return agent, nil, fail(409, "agent_replay", "Agent request nonce has already been accepted")
	}
	agent.Config.Collectors = []string{agent.Kind}
	return agent, body, nil
}

func (a *App) agentSignedRoute(w http.ResponseWriter, r *http.Request) {
	if err := a.handleAgentSigned(w, r); err != nil {
		errorOut(w, err)
	}
}

func (a *App) handleAgentSigned(w http.ResponseWriter, r *http.Request) error {
	if err := a.telemetryTransport(r); err != nil {
		return err
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	agent, body, err := a.authenticateAgent(r, tx)
	if err != nil {
		return err
	}
	var result any
	switch r.URL.Path {
	case "/api/v1/agent/config":
		var in struct {
			AppliedVersion int64 `json:"appliedVersion"`
		}
		if strictJSON(body, &in) != nil || in.AppliedVersion < 0 || in.AppliedVersion > agent.Config.Version {
			return fail(400, "agent_config_version", "Applied version must be a known configuration version")
		}
		_, err = tx.Exec(ctx, `UPDATE ra_agents SET applied_version=GREATEST(applied_version,$2),last_seen=now() WHERE id=$1`, agent.ID, in.AppliedVersion)
		result = map[string]any{"config": agent.Config, "serverTime": time.Now().UTC()}
	case "/api/v1/agent/samples":
		result, err = a.saveAgentSample(ctx, tx, agent, body)
	default:
		return fail(404, "agent_operation", "Unknown agent operation")
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	// Durable commit is the acknowledgement boundary, including duplicate retries.
	jsonOut(w, 200, result)
	return nil
}

func telemetryObject(raw json.RawMessage) bool {
	var obj map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &obj) != nil || obj == nil {
		return false
	}
	var visit func(any, int) bool
	count := 0
	visit = func(value any, depth int) bool {
		count++
		if depth > 16 || count > 20000 {
			return false
		}
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				if len(key) > 200 || !visit(item, depth+1) {
					return false
				}
			}
		case []any:
			if len(v) > 1000 {
				return false
			}
			for _, item := range v {
				if !visit(item, depth+1) {
					return false
				}
			}
		}
		return true
	}
	return visit(obj, 0)
}

func (a *App) saveAgentSample(ctx context.Context, tx pgx.Tx, agent telemetryAgent, body []byte) (any, error) {
	var in telemetrySample
	if strictJSON(body, &in) != nil || in.SchemaVersion != 1 || !telemetryBatchPattern.MatchString(in.BatchID) || in.AgentID != agent.ID || in.AssetID != agent.Asset || in.Kind != agent.Kind || in.ConfigVersion < 1 || in.ConfigVersion > agent.Config.Version || !telemetryObject(in.Metrics) || !telemetryObject(in.Health) {
		return nil, fail(400, "agent_sample", "Invalid schema, scope, config version or metrics object")
	}
	sequence, err := strconv.ParseUint(in.Sequence, 10, 64)
	if err != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != in.Sequence {
		return nil, fail(400, "agent_sequence", "Sequence must be a canonical positive uint64 decimal string")
	}
	if time.Until(in.ObservedAt) > 5*time.Minute || time.Since(in.ObservedAt) > 30*24*time.Hour {
		return nil, fail(400, "agent_observed_at", "Samples must be within the last 30 days, with at most 5 minutes future skew")
	}
	if !agent.Config.Enabled {
		return nil, fail(403, "agent_paused", "Collection is disabled by current configuration")
	}
	payloadHash := digest(string(body))
	var previousHash string
	err = tx.QueryRow(ctx, `SELECT payload_hash FROM ra_agent_samples WHERE agent_id=$1 AND batch_id=$2`, agent.ID, in.BatchID).Scan(&previousHash)
	duplicate := err == nil
	if duplicate && previousHash != payloadHash {
		return nil, fail(409, "agent_batch_conflict", "Batch ID was already committed with different content")
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if !duplicate {
		result, insertErr := tx.Exec(ctx, `INSERT INTO ra_agent_samples(workspace,asset_id,agent_id,batch_id,sequence,observed_at,config_version,kind,payload_hash,metrics,health) VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,$10,$11) ON CONFLICT(agent_id,sequence) DO NOTHING`, agent.Workspace, agent.Asset, agent.ID, in.BatchID, in.Sequence, in.ObservedAt, in.ConfigVersion, in.Kind, payloadHash, []byte(in.Metrics), []byte(in.Health))
		if insertErr != nil {
			return nil, insertErr
		}
		if result.RowsAffected() != 1 {
			return nil, fail(409, "agent_sequence_conflict", "Sequence was already committed under another batch ID")
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE ra_agents SET applied_version=GREATEST(applied_version,$2),last_seen=now() WHERE id=$1`, agent.ID, in.ConfigVersion); err != nil {
		return nil, err
	}
	// Bounded retention is real database behavior, not a UI-only time filter.
	if _, err = tx.Exec(ctx, `DELETE FROM ra_agent_samples WHERE agent_id=$1 AND received_at<now()-interval '30 days'`, agent.ID); err != nil {
		return nil, err
	}
	return map[string]any{"accepted": true, "batchId": in.BatchID, "duplicate": duplicate}, nil
}

const telemetryAgentsSelect = `SELECT id,asset_id AS "assetId",kind,hostname,os,agent_version AS "agentVersion",config_version AS "desiredVersion",applied_version AS "appliedVersion",interval_seconds AS "intervalSeconds",enabled,revoked,created_at AS "createdAt",last_seen AS "lastSeen",revoked_at AS "revokedAt" FROM ra_agents`

func (a *App) agents(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.manage"); err != nil {
		return err
	}
	asset := r.URL.Query().Get("assetId")
	if asset != "" {
		if err := a.manageAsset(r.Context(), u, asset); err != nil {
			return err
		}
	}
	offset, err := pageOffset(r.URL.Query().Get("offset"))
	if err != nil {
		return err
	}
	rows, err := a.list(r.Context(), telemetryAgentsSelect+` WHERE workspace=$1 AND ($2='' OR asset_id=$2) AND ($3='admin' OR EXISTS(SELECT 1 FROM ra_assets a WHERE a.workspace=ra_agents.workspace AND a.id=ra_agents.asset_id AND a.created_by=$4)) ORDER BY created_at DESC,id LIMIT 100 OFFSET $5`, u.Workspace, asset, u.Role, u.ID, offset)
	if err != nil {
		return err
	}
	jsonOut(w, 200, rows)
	return nil
}

func (a *App) agentManagedAsset(r *http.Request, u *User) (string, error) {
	if err := require(u, "asset.manage"); err != nil {
		return "", err
	}
	var asset string
	err := a.store(r.Context()).QueryRow(r.Context(), `SELECT asset_id FROM ra_agents WHERE workspace=$1 AND id=$2`, u.Workspace, r.PathValue("id")).Scan(&asset)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fail(404, "agent_not_found", "Agent not found")
	}
	if err != nil {
		return "", err
	}
	return asset, a.manageAsset(r.Context(), u, asset)
}

func (a *App) agentConfig(w http.ResponseWriter, r *http.Request, u *User) error {
	if _, err := a.agentManagedAsset(r, u); err != nil {
		return err
	}
	var in agentRuntimeConfig
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if in.Version < 1 || in.IntervalSeconds < 1 || in.IntervalSeconds > 3600 || len(in.Collectors) != 1 {
		return fail(400, "agent_config", "Configuration requires current version, interval 1..3600 and the enrolled collector kind")
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `UPDATE ra_agents SET config_version=config_version+1,interval_seconds=$4,enabled=$5 WHERE workspace=$1 AND id=$2 AND config_version=$3 AND kind=$6 AND NOT revoked RETURNING config_version`, u.Workspace, r.PathValue("id"), in.Version, in.IntervalSeconds, in.Enabled, in.Collectors[0]).Scan(&in.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(409, "agent_config_conflict", "Configuration changed, collector kind differs or agent was revoked")
	}
	if err == nil {
		err = a.audit(context.WithValue(ctx, txContextKey{}, tx), u, "agent.config", r.PathValue("id"), "success", "", in)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	jsonOut(w, 200, in)
	return nil
}

func (a *App) revokeAgent(w http.ResponseWriter, r *http.Request, u *User) error {
	if _, err := a.agentManagedAsset(r, u); err != nil {
		return err
	}
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if !in.Confirm {
		return fail(400, "agent_confirm", "Explicit revocation confirmation is required")
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE ra_agents SET revoked=true,revoked_at=COALESCE(revoked_at,now()) WHERE workspace=$1 AND id=$2`, u.Workspace, r.PathValue("id"))
	if err == nil {
		err = a.audit(context.WithValue(ctx, txContextKey{}, tx), u, "agent.revoke", r.PathValue("id"), "success", "", map[string]bool{"revoked": true})
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	jsonOut(w, 200, map[string]bool{"revoked": true})
	return nil
}

func (a *App) assetTelemetry(w http.ResponseWriter, r *http.Request, u *User) error {
	if err := require(u, "asset.view"); err != nil {
		return err
	}
	asset := r.PathValue("id")
	var visible bool
	if err := a.store(r.Context()).QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM ra_assets a WHERE `+assetVisibilitySQL+` AND a.id=$4)`, u.Workspace, u.Role, u.ID, asset).Scan(&visible); err != nil {
		return err
	}
	if !visible {
		return fail(404, "asset_not_found", "Asset does not exist or is outside your scope")
	}
	limit := 50
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return fail(400, "telemetry_limit", "Sample limit must be 1 to 100")
		}
	}
	offset, err := pageOffset(r.URL.Query().Get("offset"))
	if err != nil {
		return err
	}
	until, since := time.Now().UTC().Add(5*time.Minute), time.Now().UTC().Add(-time.Hour)
	for _, item := range []struct {
		key string
		dst *time.Time
	}{{"since", &since}, {"until", &until}} {
		if raw := r.URL.Query().Get(item.key); raw != "" {
			*item.dst, err = time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return fail(400, "telemetry_range", "Sample times must use RFC3339")
			}
		}
	}
	if !until.After(since) || until.Sub(since) > 31*24*time.Hour {
		return fail(400, "telemetry_range", "Sample time range must be positive and at most 31 days")
	}
	agents, err := a.list(r.Context(), telemetryAgentsSelect+` WHERE workspace=$1 AND asset_id=$2 ORDER BY created_at DESC,id LIMIT 100`, u.Workspace, asset)
	if err != nil {
		return err
	}
	samples, err := a.list(r.Context(), `SELECT 1 AS "schemaVersion",batch_id::text AS "batchId",agent_id AS "agentId",asset_id AS "assetId",sequence::text,observed_at AS "observedAt",received_at AS "receivedAt",config_version AS "configVersion",kind,metrics,health FROM ra_agent_samples WHERE workspace=$1 AND asset_id=$2 AND observed_at>=$3 AND observed_at<=$4 ORDER BY observed_at DESC,agent_id,batch_id LIMIT $5 OFFSET $6`, u.Workspace, asset, since, until, limit+1, offset)
	if err != nil {
		return err
	}
	hasMore := len(samples) > limit
	if hasMore {
		samples = samples[:limit]
	}
	state := "empty"
	var observedAt any
	var observed time.Time
	var active bool
	var interval int
	err = a.store(r.Context()).QueryRow(r.Context(), `SELECT s.observed_at,a.enabled AND NOT a.revoked AND asset.enabled AND NOT asset.archived, a.interval_seconds FROM ra_agent_samples s JOIN ra_agents a ON a.id=s.agent_id JOIN ra_assets asset ON asset.workspace=s.workspace AND asset.id=s.asset_id WHERE s.workspace=$1 AND s.asset_id=$2 ORDER BY s.observed_at DESC,s.received_at DESC LIMIT 1`, u.Workspace, asset).Scan(&observed, &active, &interval)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		observedAt, state = observed, "stale"
		if active && time.Since(observed) < time.Duration(max(30, 3*interval))*time.Second && time.Until(observed) <= 5*time.Minute {
			state = "fresh"
		}
	}
	jsonOut(w, 200, map[string]any{"assetId": asset, "agents": agents, "samples": samples, "dataState": state, "observedAt": observedAt, "hasMore": hasMore, "nextOffset": offset + len(samples), "retentionDays": 30, "statusMeaning": "fresh means recent authenticated sample, not host power, reachability or successful collection"})
	return nil
}
