package access

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func telemetryRequest(t *testing.T, h *harness, user testUser, method, path string, in any, want int) map[string]any {
	t.Helper()
	request, err := http.NewRequest(method, h.server.URL+path, bytes.NewReader(marshal(in)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", h.server.URL)
	request.Header.Set("X-CSRF-Token", user.csrf)
	client := user.client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s %s want %d got %d: %s", method, path, want, response.StatusCode, raw)
	}
	var out map[string]any
	if len(raw) > 0 && raw[0] == '[' {
		var rows []any
		err = json.Unmarshal(raw, &rows)
		out = map[string]any{"items": rows}
	} else {
		err = json.Unmarshal(raw, &out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func telemetryToken(t *testing.T, h *harness, kind string) string {
	t.Helper()
	return telemetryRequest(t, h, h.admin, "POST", "/api/v1/agents/enrollments", map[string]any{"assetId": h.asset, "kind": kind}, 201)["token"].(string)
}

func telemetryEnrolled(t *testing.T, h *harness, kind string) (string, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result := telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", map[string]any{"token": telemetryToken(t, h, kind), "publicKey": base64.StdEncoding.EncodeToString(public), "hostname": "real-agent-test", "os": "linux", "version": "0.1.0", "kind": kind}, 201)
	return result["agentId"].(string), private
}

func telemetrySignedRequest(t *testing.T, h *harness, agent string, key ed25519.PrivateKey, path string, body []byte, nonce string, timestamp int64) *http.Request {
	t.Helper()
	request, err := http.NewRequest("POST", h.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	ts := strconv.FormatInt(timestamp, 10)
	hash := sha256.Sum256(body)
	canonical := "POST\n" + path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(hash[:])
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Agent-Id", agent)
	request.Header.Set("X-Agent-Time", ts)
	request.Header.Set("X-Agent-Nonce", nonce)
	request.Header.Set("X-Agent-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(canonical))))
	return request
}

func telemetrySend(t *testing.T, request *http.Request, want int) map[string]any {
	t.Helper()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s want %d got %d: %s", request.URL.Path, want, response.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func telemetrySigned(t *testing.T, h *harness, agent string, key ed25519.PrivateKey, path string, in any, want int) map[string]any {
	t.Helper()
	return telemetrySend(t, telemetrySignedRequest(t, h, agent, key, path, marshal(in), ID(), time.Now().Unix()), want)
}

func telemetryTestSample(agent, asset string) telemetrySample {
	return telemetrySample{SchemaVersion: 1, BatchID: "3c1ae2f8-6792-4de1-b347-66916015dc7a", AgentID: agent, AssetID: asset, Sequence: "1", ObservedAt: time.Now().UTC(), ConfigVersion: 1, Kind: "host", Metrics: json.RawMessage(`{"cpu":{"usagePercent":19.25},"memory":{"totalBytes":8388608}}`), Health: json.RawMessage(`{"status":"ok"}`)}
}

func TestIntegrationTelemetryEnrollmentAtomicAndScopes(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	token := telemetryToken(t, h, "host")
	in := map[string]any{"token": token, "publicKey": base64.StdEncoding.EncodeToString(public), "hostname": "test-host", "os": "linux", "version": "0.1.0", "kind": "host"}
	invalid := map[string]any{}
	for k, v := range in {
		invalid[k] = v
	}
	invalid["publicKey"] = base64.StdEncoding.EncodeToString(public[:31])
	telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", invalid, 400)
	invalid["publicKey"], invalid["kind"] = in["publicKey"], "docker"
	telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", invalid, 410)
	var tokenHash string
	if err := h.a.DB.QueryRow(context.Background(), `SELECT token_hash FROM ra_agent_enrollments WHERE workspace=$1`, h.a.Config.Workspace).Scan(&tokenHash); err != nil || tokenHash == token || tokenHash != digest(token) {
		t.Fatalf("token hash storage: %q %v", tokenHash, err)
	}
	// The same enrollment token cannot create two agents under concurrency.
	statuses := make(chan int, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			request, _ := http.NewRequest("POST", h.server.URL+"/api/v1/agents/enroll", bytes.NewReader(marshal(in)))
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				statuses <- 0
				return
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	workers.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[201] != 1 || counts[200] != 1 {
		t.Fatalf("single-use enrollment concurrency: %v", counts)
	}
	recovered := telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", in, 200)
	var agents int
	if err := h.a.DB.QueryRow(context.Background(), `SELECT count(*) FROM ra_agents WHERE workspace=$1`, h.a.Config.Workspace).Scan(&agents); err != nil || agents != 1 {
		t.Fatalf("lost-response recovery created a second identity: %d %v", agents, err)
	}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	invalid["kind"], invalid["publicKey"] = "host", base64.StdEncoding.EncodeToString(otherPublic)
	telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", invalid, 410)
	telemetryRequest(t, h, h.admin, "POST", "/api/v1/agents/"+recovered["agentId"].(string)+"/revoke", map[string]bool{"confirm": true}, 200)
	telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", in, 410)
	operator := h.user("telemetry-no-management", "operator")
	telemetryRequest(t, h, operator, "POST", "/api/v1/agents/enrollments", map[string]any{"assetId": h.asset, "kind": "host"}, 403)
	manager := h.user("telemetry-foreign-manager", "asset_manager")
	telemetryRequest(t, h, manager, "POST", "/api/v1/agents/enrollments", map[string]any{"assetId": h.asset, "kind": "host"}, 403)
	token = telemetryToken(t, h, "host")
	selfAccessTestExec(t, h, `UPDATE ra_agent_enrollments SET expires_at=now()-interval '1 second' WHERE token_hash=$1`, digest(token))
	in["token"] = token
	telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", in, 410)
	token = telemetryToken(t, h, "host")
	selfAccessTestExec(t, h, `UPDATE ra_assets SET enabled=false WHERE id=$1`, h.asset)
	in["token"] = token
	telemetryRequest(t, h, testUser{}, "POST", "/api/v1/agents/enroll", in, 403)
	selfAccessTestExec(t, h, `UPDATE ra_assets SET enabled=true,ownership_legacy=true WHERE id=$1`, h.asset)
	telemetryRequest(t, h, h.admin, "POST", "/api/v1/agents/enrollments", map[string]any{"assetId": h.asset, "kind": "host"}, 403)
	selfAccessTestExec(t, h, `UPDATE ra_assets SET ownership_legacy=false WHERE id=$1`, h.asset)
	h.a.Config.LoopbackTest = false
	telemetryRequest(t, h, h.admin, "POST", "/api/v1/agents/enrollments", map[string]any{"assetId": h.asset, "kind": "host"}, 403)
}

func TestIntegrationTelemetrySignatureReplayAndScope(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	agent, key := telemetryEnrolled(t, h, "host")
	sample := telemetryTestSample(agent, h.asset)
	body, nonce, timestamp := marshal(sample), ID(), time.Now().Unix()
	request := telemetrySignedRequest(t, h, agent, key, "/api/v1/agent/samples", body, nonce, timestamp)
	request.Header.Set("X-Agent-Signature", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	telemetrySend(t, request, 403)
	telemetrySend(t, telemetrySignedRequest(t, h, agent, key, "/api/v1/agent/samples", body, nonce, timestamp), 200)
	if result := telemetrySend(t, telemetrySignedRequest(t, h, agent, key, "/api/v1/agent/samples", body, nonce, timestamp), 409); result["code"] != "agent_replay" {
		t.Fatal(result)
	}
	telemetrySend(t, telemetrySignedRequest(t, h, agent, key, "/api/v1/agent/samples", body, ID(), timestamp-60), 403)
	sample.AssetID = ID()
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 400)
	sample.AssetID, sample.Kind = h.asset, "docker"
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 400)
	sample.Kind, sample.Sequence = "host", "18446744073709551616"
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 400)
	sample.Sequence, sample.ObservedAt = "2", time.Now().Add(-31*24*time.Hour)
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 400)
	request = telemetrySignedRequest(t, h, agent, key, "/api/v1/agent/samples", []byte(strings.Repeat("x", telemetryBodyLimit+1)), ID(), time.Now().Unix())
	telemetrySend(t, request, 413)
}

func TestIntegrationTelemetryDurableAckDedupAndDBFailure(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	agent, key := telemetryEnrolled(t, h, "host")
	sample := telemetryTestSample(agent, h.asset)
	if result := telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 200); result["accepted"] != true || result["duplicate"] != false {
		t.Fatal(result)
	}
	if result := telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 200); result["duplicate"] != true {
		t.Fatal(result)
	}
	changed := sample
	changed.Metrics = json.RawMessage(`{"cpu":{"usagePercent":99}}`)
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", changed, 409)
	changed = sample
	changed.BatchID = "3c1ae2f8-6792-4de1-b347-66916015dc7b"
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", changed, 409)
	changed.Sequence = "18446744073709551615"
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", changed, 200)
	var sequence string
	if err := h.a.DB.QueryRow(context.Background(), `SELECT sequence::text FROM ra_agent_samples WHERE agent_id=$1 AND batch_id=$2`, agent, changed.BatchID).Scan(&sequence); err != nil || sequence != changed.Sequence {
		t.Fatalf("uint64 storage truncated: %s %v", sequence, err)
	}
	// Force the DB write to fail after signature verification. It must neither
	// acknowledge nor retain a nonce that would prevent a recoverable retry.
	constraint := fmt.Sprintf("telemetry_failure_%x", time.Now().UnixNano())
	selfAccessTestExec(t, h, `ALTER TABLE ra_agent_samples ADD CONSTRAINT `+constraint+` CHECK (workspace <> '`+h.a.Config.Workspace+`') NOT VALID`)
	t.Cleanup(func() {
		h.a.DB.Exec(context.Background(), `ALTER TABLE ra_agent_samples DROP CONSTRAINT IF EXISTS `+constraint)
	})
	changed.Sequence, changed.BatchID = "3", "3c1ae2f8-6792-4de1-b347-66916015dc7c"
	body, nonce, timestamp := marshal(changed), ID(), time.Now().Unix()
	result := telemetrySend(t, telemetrySignedRequest(t, h, agent, key, "/api/v1/agent/samples", body, nonce, timestamp), 500)
	if result["accepted"] != nil {
		t.Fatalf("DB failure acknowledged: %v", result)
	}
	var count int
	if err := h.a.DB.QueryRow(context.Background(), `SELECT count(*) FROM ra_agent_samples WHERE agent_id=$1`, agent).Scan(&count); err != nil || count != 2 {
		t.Fatalf("partial commit: %d %v", count, err)
	}
	selfAccessTestExec(t, h, `ALTER TABLE ra_agent_samples DROP CONSTRAINT `+constraint)
	telemetrySend(t, telemetrySignedRequest(t, h, agent, key, "/api/v1/agent/samples", body, nonce, timestamp), 200)
	var metric []byte
	if err := h.a.DB.QueryRow(context.Background(), `SELECT metrics FROM ra_agent_samples WHERE agent_id=$1 AND batch_id=$2`, agent, sample.BatchID).Scan(&metric); err != nil || !bytes.Contains(metric, []byte("19.25")) {
		t.Fatalf("committed metric mismatch: %s %v", metric, err)
	}
}

func TestIntegrationTelemetryConfigAndImmediateRevoke(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	agent, key := telemetryEnrolled(t, h, "host")
	configPath := "/api/v1/agents/" + agent + "/config"
	config := agentRuntimeConfig{Version: 1, IntervalSeconds: 10, Enabled: true, Collectors: []string{"host"}}
	telemetryRequest(t, h, h.admin, "PATCH", configPath, config, 200)
	telemetryRequest(t, h, h.admin, "PATCH", configPath, config, 409)
	config.Version, config.Collectors = 2, []string{"docker"}
	telemetryRequest(t, h, h.admin, "PATCH", configPath, config, 409)
	result := telemetrySigned(t, h, agent, key, "/api/v1/agent/config", map[string]any{"appliedVersion": 1}, 200)
	delivered := result["config"].(map[string]any)
	if delivered["version"] != float64(2) || delivered["intervalSeconds"] != float64(10) {
		t.Fatalf("config was not delivered: %v", result)
	}
	var desired, applied int
	if err := h.a.DB.QueryRow(context.Background(), `SELECT config_version,applied_version FROM ra_agents WHERE id=$1`, agent).Scan(&desired, &applied); err != nil || desired != 2 || applied != 1 {
		t.Fatalf("desired != applied boundary: %d %d %v", desired, applied, err)
	}
	config.Collectors, config.Enabled = []string{"host"}, false
	telemetryRequest(t, h, h.admin, "PATCH", configPath, config, 200)
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", telemetryTestSample(agent, h.asset), 403)
	result = telemetrySigned(t, h, agent, key, "/api/v1/agent/config", map[string]any{"appliedVersion": 2}, 200)
	delivered = result["config"].(map[string]any)
	if delivered["enabled"] != false || delivered["version"] != float64(3) {
		t.Fatalf("paused agent could not receive config: %v", result)
	}
	telemetryRequest(t, h, h.admin, "POST", "/api/v1/agents/"+agent+"/revoke", map[string]bool{"confirm": false}, 400)
	telemetryRequest(t, h, h.admin, "POST", "/api/v1/agents/"+agent+"/revoke", map[string]bool{"confirm": true}, 200)
	telemetrySigned(t, h, agent, key, "/api/v1/agent/config", map[string]any{"appliedVersion": 2}, 403)
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", telemetryTestSample(agent, h.asset), 403)
}

func TestIntegrationTelemetryQueryVisibilityFreshnessAndPagination(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	path := "/api/v1/assets/" + h.asset + "/telemetry"
	result := telemetryRequest(t, h, h.admin, "GET", path, nil, 200)
	if result["dataState"] != "empty" || len(result["samples"].([]any)) != 0 || result["observedAt"] != nil {
		t.Fatalf("empty data fabricated measurements: %v", result)
	}
	otherWorkspace := newHarness(t)
	telemetryRequest(t, otherWorkspace, otherWorkspace.admin, "GET", path, nil, 404)
	telemetryRequest(t, otherWorkspace, otherWorkspace.admin, "POST", "/api/v1/agents/enrollments", map[string]any{"assetId": h.asset, "kind": "host"}, 404)
	reader := h.user("telemetry-reader", "operator")
	telemetryRequest(t, h, reader, "GET", path, nil, 404)
	grant := h.grant(reader, true)
	telemetryRequest(t, h, reader, "GET", path, nil, 200)
	agent, key := telemetryEnrolled(t, h, "host")
	sample := telemetryTestSample(agent, h.asset)
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 200)
	sample.Sequence, sample.BatchID = "2", "3c1ae2f8-6792-4de1-b347-66916015dc7b"
	telemetrySigned(t, h, agent, key, "/api/v1/agent/samples", sample, 200)
	result = telemetryRequest(t, h, reader, "GET", path+"?limit=1", nil, 200)
	if result["dataState"] != "fresh" || len(result["samples"].([]any)) != 1 || result["hasMore"] != true {
		t.Fatalf("pagination or freshness: %v", result)
	}
	encoded := string(marshal(result))
	for _, forbidden := range []string{"public_key", "publicKey", "token_hash", "tokenHash"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("agent metadata exposed %s", forbidden)
		}
	}
	result = telemetryRequest(t, h, reader, "GET", path+"?limit=1&offset=1", nil, 200)
	if result["hasMore"] != false || len(result["samples"].([]any)) != 1 {
		t.Fatal(result)
	}
	selfAccessTestExec(t, h, `UPDATE ra_assets SET enabled=false WHERE id=$1`, h.asset)
	if result = telemetryRequest(t, h, reader, "GET", path, nil, 200); result["dataState"] != "stale" || result["observedAt"] == nil {
		t.Fatalf("disabled asset history erased or presented fresh: %v", result)
	}
	selfAccessTestExec(t, h, `UPDATE ra_assets SET enabled=true WHERE id=$1`, h.asset)
	selfAccessTestExec(t, h, `UPDATE ra_agent_samples SET observed_at=now()-interval '5 minutes' WHERE agent_id=$1`, agent)
	if result = telemetryRequest(t, h, reader, "GET", path, nil, 200); result["dataState"] != "stale" {
		t.Fatalf("old sample shown fresh: %v", result)
	}
	h.request(h.admin, "DELETE", "/grants/"+grant, nil, 200)
	telemetryRequest(t, h, reader, "GET", path, nil, 404)
	telemetryRequest(t, h, reader, "GET", "/api/v1/agents?assetId="+h.asset, nil, 403)
	telemetryRequest(t, h, h.admin, "GET", path+"?limit=101", nil, 400)
	telemetryRequest(t, h, h.admin, "GET", path+"?since=2020-01-01T00:00:00Z", nil, 400)
}

func TestTelemetryPayloadStructuralLimits(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `"value"`, strings.Repeat(`{"x":`, 18) + `{}` + strings.Repeat(`}`, 18), `{"x":[` + strings.Repeat("0,", 1000) + `0]}`} {
		if telemetryObject(json.RawMessage(raw)) {
			t.Fatalf("unsafe structure accepted: %.100s", raw)
		}
	}
	if !telemetryObject(json.RawMessage(`{"host":{"cpu":null},"unavailable":["cpu"]}`)) {
		t.Fatal("valid missing measurement rejected")
	}
}
