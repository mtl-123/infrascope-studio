package access

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
)

func pairLauncherTestDevice(h *harness, u testUser) (string, string, ed25519.PrivateKey) {
	h.t.Helper()
	p := h.request(u, "POST", "/connectors/pairing-challenges", map[string]any{}, 201)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		h.t.Fatal(err)
	}
	sid := digest("launcher-protocol-fixture-not-a-Windows-device")
	proof := ed25519.Sign(key, []byte("pair\n"+p["challenge"].(string)+"\n"+h.server.URL+"\n"+sid))
	paired := h.request(testUser{}, "POST", "/connector/pair", map[string]any{
		"challenge": p["challenge"], "publicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		"name": "Launcher protocol fixture (not a Windows device)", "windowsUserHash": sid,
		"version": "test", "signature": base64.StdEncoding.EncodeToString(proof), "origin": h.server.URL,
	}, 201)
	id, binding := paired["connectorId"].(string), paired["browserBindingId"].(string)
	h.device(id, key, "poll", map[string]any{"capabilities": map[string]any{}, "windowsUserHash": sid}, 200, "")
	return id, binding, key
}

func TestIntegrationLauncherCatalogScopeAndBinding(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	ctx := context.Background()
	adminDevice, adminBinding, adminKey := pairLauncherTestDevice(h, h.admin)
	adminCatalog := h.device(adminDevice, adminKey, "catalog", map[string]any{"browserBindingId": adminBinding}, 200, "")
	if len(adminCatalog["items"].([]any)) != 0 {
		t.Fatal("admin role must not bypass remote account grants")
	}
	u := h.user("launcher-catalog", "operator")
	grant := h.grant(u, false)
	id, binding, key := pairLauncherTestDevice(h, u)
	// More than one result page of earlier, unauthorized accounts must not hide the granted one.
	_, err := h.a.DB.Exec(ctx, `INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,created_by)
		SELECT $1 || n::text,$2,$3,'A ungranted ' || n::text,'ungranted','password','["ssh","sftp","rdp"]',$4
		FROM generate_series(1,210) n`, ID(), h.a.Config.Workspace, h.asset, h.admin.id)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"browserBindingId": binding}
	catalog := h.device(id, key, "catalog", body, 200, "")
	items := catalog["items"].([]any)
	if len(items) != 3 || catalog["truncated"] != false || catalog["userId"] != u.id {
		t.Fatalf("expected all three granted protocols, got %v", catalog)
	}
	for _, raw := range items {
		item := raw.(map[string]any)
		if len(item) != 9 || item["assetId"] != h.asset || item["accountId"] != h.account || item["host"] != h.host || launcherAction(item["protocol"].(string)) == "" {
			t.Fatalf("unexpected catalog metadata: %v", item)
		}
	}
	encoded := string(marshal(catalog))
	for _, secretField := range []string{"password", "privateKey", "ciphertext", "nonce", "csrf", "login_id_hash", "remote-test-secret"} {
		if strings.Contains(encoded, secretField) {
			t.Fatalf("catalog exposed forbidden field %s", secretField)
		}
	}
	for _, query := range []string{"%", "_", "A ungranted"} {
		result := h.device(id, key, "catalog", map[string]any{"browserBindingId": binding, "query": query}, 200, "")
		if len(result["items"].([]any)) != 0 {
			t.Fatalf("query must be literal and scoped: %q", query)
		}
	}
	result := h.device(id, key, "catalog", map[string]any{"browserBindingId": binding, "query": "  INTEGRATION  "}, 200, "")
	if len(result["items"].([]any)) != 3 {
		t.Fatal("case-insensitive bounded search failed")
	}
	for _, query := range []string{"ssh", "  LINUX   ssh  TESTER ", "ssh\tIntegration\n127.0.0.1"} {
		result = h.device(id, key, "catalog", map[string]any{"browserBindingId": binding, "query": query}, 200, "")
		if len(result["items"].([]any)) != 1 || result["items"].([]any)[0].(map[string]any)["protocol"] != "ssh" {
			t.Fatalf("protocol and unordered multiword search failed: %q: %v", query, result)
		}
	}
	for _, query := range []string{"linux windows", "ssh rdp", "tester no-such-word"} {
		result = h.device(id, key, "catalog", map[string]any{"browserBindingId": binding, "query": query}, 200, "")
		if len(result["items"].([]any)) != 0 {
			t.Fatalf("every search term must match the same authorized entry: %q", query)
		}
	}
	if _, err = h.a.DB.Exec(ctx, "UPDATE ra_accounts SET enabled=false WHERE id=$1", h.account); err != nil {
		t.Fatal(err)
	}
	result = h.device(id, key, "catalog", body, 200, "")
	if len(result["items"].([]any)) != 0 {
		t.Fatal("disabled accounts must disappear")
	}
	if _, err = h.a.DB.Exec(ctx, "UPDATE ra_accounts SET enabled=true WHERE id=$1", h.account); err != nil {
		t.Fatal(err)
	}
	h.request(h.admin, "DELETE", "/grants/"+grant, nil, 200)
	result = h.device(id, key, "catalog", body, 200, "")
	if len(result["items"].([]any)) != 0 {
		t.Fatal("revocation must remove catalog entries immediately")
	}
	for _, tc := range []struct{ change, restore string }{
		{"UPDATE ra_browser_bindings SET revoked=true WHERE id=$1", "UPDATE ra_browser_bindings SET revoked=false WHERE id=$1"},
		{"UPDATE ra_browser_bindings SET expires_at=now()-interval '1 minute' WHERE id=$1", "UPDATE ra_browser_bindings SET expires_at=now()+interval '1 hour' WHERE id=$1"},
		{"UPDATE ra_login_sessions SET expires_at=now()-interval '1 minute' WHERE id_hash=(SELECT login_id_hash FROM ra_browser_bindings WHERE id=$1)", "UPDATE ra_login_sessions SET expires_at=now()+interval '1 hour' WHERE id_hash=(SELECT login_id_hash FROM ra_browser_bindings WHERE id=$1)"},
		{"UPDATE ra_login_sessions SET auth_version=auth_version+1 WHERE id_hash=(SELECT login_id_hash FROM ra_browser_bindings WHERE id=$1)", "UPDATE ra_login_sessions SET auth_version=auth_version-1 WHERE id_hash=(SELECT login_id_hash FROM ra_browser_bindings WHERE id=$1)"},
	} {
		if _, err = h.a.DB.Exec(ctx, tc.change, binding); err != nil {
			t.Fatal(err)
		}
		h.device(id, key, "catalog", body, 401, "")
		if _, err = h.a.DB.Exec(ctx, tc.restore, binding); err != nil {
			t.Fatal(err)
		}
	}
	h.request(u, "POST", "/auth/logout", map[string]any{}, 200)
	h.device(id, key, "catalog", body, 401, "")
}

func TestIntegrationLauncherQuickLaunchDeviceBinding(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	u := h.user("launcher-rdp", "operator")
	h.grant(u, false)
	d1, b1, k1 := pairLauncherTestDevice(h, u)
	secondBrowser := h.login("launcher-rdp", "changed-test-123", 200)
	d2, b2, k2 := pairLauncherTestDevice(h, secondBrowser)
	input := map[string]any{"browserBindingId": b1, "assetId": h.asset, "accountId": h.account, "protocol": "rdp", "confirmed": true, "idempotencyKey": ID()}
	first := h.device(d1, k1, "quick-launch", input, 201, "")
	firstID := first["id"].(string)
	if first["state"] != "queued" {
		t.Fatal("quick launch must queue, not claim desktop authentication")
	}
	retry := h.device(d1, k1, "quick-launch", input, 200, "")
	if retry["id"] != firstID {
		t.Fatal("same-device retry duplicated task")
	}
	h.device(d2, k2, "quick-launch", input, 401, "")
	input["browserBindingId"] = b2
	h.device(d1, k1, "quick-launch", input, 401, "")
	second := h.device(d2, k2, "quick-launch", input, 201, "")
	if second["id"] == firstID {
		t.Fatal("same idempotency key crossed devices or browser bindings")
	}
	ctx := context.Background()
	var device, binding, login string
	var raw []byte
	err := h.a.DB.QueryRow(ctx, "SELECT connector_id,binding_id,login_id_hash,options FROM ra_rdp_launches WHERE id=$1", firstID).Scan(&device, &binding, &login, &raw)
	if err != nil {
		t.Fatal(err)
	}
	var opts RDPOptions
	if json.Unmarshal(raw, &opts) != nil || device != d1 || binding != b1 || opts.Clipboard || opts.Drives || !opts.Fullscreen || opts.DriveMode != "all" {
		t.Fatal("RDP quick launch must bind current device/browser and disable redirections")
	}
	var expectedLogin string
	if err = h.a.DB.QueryRow(ctx, "SELECT login_id_hash FROM ra_browser_bindings WHERE id=$1", b1).Scan(&expectedLogin); err != nil || login != expectedLogin {
		t.Fatal("launch did not preserve the exact paired login")
	}
	h.device(d2, k2, "redeem", map[string]any{"launchId": firstID, "locallyConfirmed": true}, 404, "")
	h.device(d1, k1, "redeem", map[string]any{"launchId": firstID, "locallyConfirmed": true}, 200, "")
	input["browserBindingId"] = b1
	var lastQueued string
	for i := 0; i < 11; i++ {
		input["idempotencyKey"] = ID()
		queued := h.device(d1, k1, "quick-launch", input, 201, "")
		lastQueued = queued["id"].(string)
	}
	poll := map[string]any{"capabilities": map[string]any{}, "windowsUserHash": digest("launcher-protocol-fixture-not-a-Windows-device")}
	queued := h.device(d1, k1, "poll", poll, 200, "")["launches"].([]any)
	if len(queued) != 10 {
		t.Fatal("normal poll should preserve its ten-task limit")
	}
	for _, raw := range queued {
		if raw.(map[string]any)["id"] == lastQueued {
			t.Fatal("eleventh task must be outside the default poll page")
		}
	}
	poll["launchId"] = lastQueued
	queued = h.device(d1, k1, "poll", poll, 200, "")["launches"].([]any)
	if len(queued) != 1 || queued[0].(map[string]any)["id"] != lastQueued {
		t.Fatal("exact launch poll must find the selected task beyond the first page")
	}
	if len(h.device(d2, k2, "poll", poll, 200, "")["launches"].([]any)) != 0 {
		t.Fatal("exact launch poll must not expose another connector's task")
	}
	poll["launchId"] = strings.Repeat("x", 101)
	h.device(d1, k1, "poll", poll, 400, "")
	for _, proto := range []string{"ssh", "sftp"} {
		input["protocol"], input["browserBindingId"] = proto, b1
		result := h.device(d1, k1, "quick-launch", input, 200, "")
		target, err := url.Parse(result["url"].(string))
		if err != nil || target.Scheme+"://"+target.Host != h.server.URL || target.Path != "/remote-workspace.html" || target.Fragment != "" || target.User != nil || len(target.Query()) != 4 || target.Query().Get("assetId") != h.asset || target.Query().Get("accountId") != h.account || target.Query().Get("protocol") != proto || target.Query().Get("userId") != u.id || result["state"] != "open_browser" {
			t.Fatalf("unexpected browser intent: %v", result)
		}
	}
	var count int
	if err = h.a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_remote_sessions WHERE workspace=$1", h.a.Config.Workspace).Scan(&count); err != nil || count != 0 {
		t.Fatal("browser intent must not bypass browser authentication and create a session")
	}
	h.request(u, "POST", "/auth/logout", map[string]any{}, 200)
	h.device(d1, k1, "quick-launch", input, 401, "")
	input["browserBindingId"] = b2
	h.device(d2, k2, "quick-launch", input, 200, "")
}

func TestIntegrationLauncherValidationAndRevocation(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	u := h.user("launcher-validation", "operator")
	grant := h.grant(u, false)
	id, binding, key := pairLauncherTestDevice(h, u)
	catalog := map[string]any{"browserBindingId": binding}
	nonce := ID()
	h.device(id, key, "catalog", catalog, 200, nonce)
	h.device(id, key, "catalog", catalog, 409, nonce)
	h.device(id, key, "catalog", map[string]any{}, 400, "")
	h.device(id, key, "catalog", map[string]any{"browserBindingId": binding, "query": strings.Repeat("x", 201)}, 400, "")
	h.device(id, key, "catalog", map[string]any{"browserBindingId": binding, "userId": h.admin.id}, 400, "")
	input := map[string]any{"browserBindingId": binding, "assetId": h.asset, "accountId": h.account, "protocol": "ssh", "confirmed": true, "idempotencyKey": ID()}
	for _, tc := range []struct {
		field string
		value any
		want  int
	}{
		{"confirmed", false, 403}, {"protocol", "vnc", 400}, {"accountId", "", 400}, {"accountId", ID(), 404},
		{"assetId", ID(), 403}, {"browserBindingId", ID(), 401}, {"idempotencyKey", "", 400},
		{"connectorId", ID(), 400}, {"host", "other-target", 400},
	} {
		bad := map[string]any{}
		for k, v := range input {
			bad[k] = v
		}
		bad[tc.field] = tc.value
		h.device(id, key, "quick-launch", bad, tc.want, "")
	}
	ctx := context.Background()
	if _, err := h.a.DB.Exec(ctx, "DELETE FROM ra_endpoints WHERE asset_id=$1 AND protocol='ssh'", h.asset); err != nil {
		t.Fatal(err)
	}
	h.device(id, key, "quick-launch", input, 404, "")
	remaining := h.device(id, key, "catalog", catalog, 200, "")
	if len(remaining["items"].([]any)) != 2 {
		t.Fatal("catalog must exclude missing real endpoints")
	}
	input["protocol"] = "sftp"
	h.request(h.admin, "DELETE", "/grants/"+grant, nil, 200)
	h.device(id, key, "quick-launch", input, 403, "")
	h.request(u, "POST", "/connectors/"+id+"/revoke", map[string]any{}, 200)
	h.device(id, key, "catalog", catalog, 403, "")
	h.device(id, key, "quick-launch", input, 403, "")
}

func TestIntegrationLauncherCatalogGroupsAndTruncation(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	u := h.user("launcher-groups", "operator")
	id, binding, key := pairLauncherTestDevice(h, u)
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := h.a.DB.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	group, useGrant, actionGrant := ID(), ID(), ID()
	exec("INSERT INTO ra_groups(id,workspace,name) VALUES($1,$2,'Launcher group')", group, h.a.Config.Workspace)
	exec("INSERT INTO ra_group_members(workspace,group_id,user_id) VALUES($1,$2,$3)", h.a.Config.Workspace, group, u.id)
	for _, grant := range []struct{ id, action string }{{useGrant, "remoteAccount.use"}, {actionGrant, "ssh.connect"}} {
		exec(`INSERT INTO ra_grants(id,workspace,group_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,granted_by)
			VALUES($1,$2,$3,$4,$5,$6,'["ssh"]','{}',now()-interval '1 minute',now()+interval '1 hour',$7)`,
			grant.id, h.a.Config.Workspace, group, h.asset, h.account, marshal([]string{grant.action}), h.admin.id)
	}
	body := map[string]any{"browserBindingId": binding}
	result := h.device(id, key, "catalog", body, 200, "")
	if len(result["items"].([]any)) != 0 {
		t.Fatal("launcher and browser catalog must both reject split action grants")
	}
	launch := map[string]any{"browserBindingId": binding, "assetId": h.asset, "accountId": h.account, "protocol": "ssh", "confirmed": true, "idempotencyKey": ID()}
	h.device(id, key, "quick-launch", launch, 403, "")
	exec("UPDATE ra_grants SET actions='[\"remoteAccount.use\",\"ssh.connect\"]' WHERE id=$1", actionGrant)
	result = h.device(id, key, "catalog", body, 200, "")
	if len(result["items"].([]any)) != 1 || result["items"].([]any)[0].(map[string]any)["protocol"] != "ssh" {
		t.Fatal("complete group grant must authorize only its matching protocol")
	}
	exec("UPDATE ra_grants SET protocols='[\"sftp\"]' WHERE id=$1", actionGrant)
	result = h.device(id, key, "catalog", body, 200, "")
	if len(result["items"].([]any)) != 0 {
		t.Fatal("actions from different protocols must not combine")
	}
	exec("UPDATE ra_grants SET protocols='[\"ssh\"]' WHERE id=$1", actionGrant)
	exec("DELETE FROM ra_group_members WHERE group_id=$1 AND user_id=$2", group, u.id)
	result = h.device(id, key, "catalog", body, 200, "")
	if len(result["items"].([]any)) != 0 {
		t.Fatal("group removal must immediately remove catalog permissions")
	}
	exec("INSERT INTO ra_group_members(workspace,group_id,user_id) VALUES($1,$2,$3)", h.a.Config.Workspace, group, u.id)
	prefix := ID()
	exec(`INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,created_by)
		SELECT $1 || n::text,$2,$3,'Catalog row ' || n::text,'tester','password','["ssh"]',$4
		FROM generate_series(1,205) n`, prefix, h.a.Config.Workspace, h.asset, h.admin.id)
	exec(`INSERT INTO ra_grants(id,workspace,group_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,granted_by)
		SELECT 'grant-' || id,workspace,$1,asset_id,id,'["remoteAccount.use","ssh.connect"]','["ssh"]','{}',now()-interval '1 minute',now()+interval '1 hour',$2
		FROM ra_accounts WHERE workspace=$3 AND left(id,length($4))=$4`, group, h.admin.id, h.a.Config.Workspace, prefix)
	exec("UPDATE ra_accounts SET name='zz final account' WHERE id=$1", prefix+"205")
	result = h.device(id, key, "catalog", body, 200, "")
	if len(result["items"].([]any)) != 200 || result["truncated"] != true {
		t.Fatal("large catalogs must explicitly report their 200-result limit")
	}
	result = h.device(id, key, "catalog", map[string]any{"browserBindingId": binding, "query": "zz final account"}, 200, "")
	if len(result["items"].([]any)) != 1 || result["truncated"] != false || result["items"].([]any)[0].(map[string]any)["accountId"] != prefix+"205" {
		t.Fatal("search must apply before the result limit")
	}
}
