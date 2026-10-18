package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func onboardingInput(t *testing.T, h *harness) serverOnboardingInput {
	t.Helper()
	person := h.request(h.admin, "POST", "/people", map[string]any{"displayName": "Onboarding owner", "contactType": "internal", "enabled": true}, 200)
	return serverOnboardingInput{
		IdempotencyKey: ID(), Confirm: true, Name: "New Linux target", OSFamily: "linux", Host: "192.0.2.19",
		SSHPort: 2202, SFTPPort: 2203, Protocols: []string{"ssh", "sftp"}, Username: "tester", AuthType: "password",
		Secret: Secret{Password: "onboarding-test-secret"}, ClaimantID: person["id"].(string), ReadRoots: []string{"/home/tester"}, ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
}

func onboardingRequest(t *testing.T, h *harness, u testUser, in serverOnboardingInput, status int) map[string]any {
	t.Helper()
	req, err := http.NewRequest("POST", h.server.URL+"/api/v1/servers/onboard", bytes.NewReader(marshal(in)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", h.server.URL)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", u.csrf)
	resp, err := u.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("onboard status got %d want %d: %s", resp.StatusCode, status, raw)
	}
	if in.Secret.Password != "" && bytes.Contains(raw, []byte(in.Secret.Password)) || bytes.Contains(raw, []byte("privateKey")) || bytes.Contains(raw, []byte("ciphertext")) {
		t.Fatal("response exposed credential material")
	}
	var out map[string]any
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func onboardingCounts(t *testing.T, h *harness, assets, permits int) {
	t.Helper()
	for _, table := range []string{"ra_assets", "ra_accounts", "ra_grants", "ra_secrets", "ra_server_onboarding_requests"} {
		var count int
		if err := h.a.DB.QueryRow(context.Background(), "SELECT count(*) FROM "+table+" WHERE workspace=$1", h.a.Config.Workspace).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != assets {
			t.Fatalf("%s count got %d want %d", table, count, assets)
		}
	}
	var count int
	if err := h.a.DB.QueryRow(context.Background(), "SELECT count(*) FROM ra_asset_egress WHERE workspace=$1", h.a.Config.Workspace).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != permits {
		t.Fatalf("permit count got %d want %d", count, permits)
	}
}

func TestIntegrationServerOnboardingAtomicRolesAndCSRF(t *testing.T) {
	h := newHarness(t)
	in := onboardingInput(t, h)
	for _, role := range []string{"asset_manager", "operator", "auditor"} {
		u := h.user("onboarding-"+role, role)
		if out := onboardingRequest(t, h, u, in, 403); out["code"] != "onboarding_denied" {
			t.Fatalf("role boundary: %v", out)
		}
	}
	for _, csrf := range []string{"", "wrong-token"} {
		u := h.admin
		u.csrf = csrf
		if out := onboardingRequest(t, h, u, in, 403); out["code"] != "csrf" {
			t.Fatalf("CSRF boundary: %v", out)
		}
	}
	selfAccessTestExec(t, h, "UPDATE ra_login_sessions SET reauth_at=now()-interval '6 minutes' WHERE user_id=$1", h.admin.id)
	if out := onboardingRequest(t, h, h.admin, in, 403); out["code"] != "reauth_required" {
		t.Fatalf("recent auth boundary: %v", out)
	}
	h.request(h.admin, "POST", "/auth/reauth", map[string]string{"password": "test-password-123"}, 200)
	bad := in
	bad.ClaimantID = ID()
	if out := onboardingRequest(t, h, h.admin, bad, 400); out["code"] != "ownership_person" {
		t.Fatalf("foreign or missing claimant accepted: %v", out)
	}
	org := h.request(h.admin, "POST", "/organizations", p2OrganizationInput("Disabled onboarding organization", ""), 200)["id"].(string)
	selfAccessTestExec(t, h, "UPDATE ra_organizations SET enabled=false WHERE id=$1", org)
	bad = in
	bad.OrganizationID = &org
	if out := onboardingRequest(t, h, h.admin, bad, 400); out["code"] != "asset_organization_disabled" {
		t.Fatalf("disabled org accepted: %v", out)
	}
	onboardingCounts(t, h, 0, 0)
	// Force failure after asset, encrypted credential, and grant inserts. The
	// workspace-specific constraint cannot reject another test's rows.
	constraint := "onboarding_rollback_" + fmt.Sprintf("%x", time.Now().UnixNano())
	selfAccessTestExec(t, h, "ALTER TABLE ra_asset_egress ADD CONSTRAINT "+constraint+" CHECK (workspace <> '"+h.a.Config.Workspace+"') NOT VALID")
	t.Cleanup(func() {
		h.a.DB.Exec(context.Background(), "ALTER TABLE ra_asset_egress DROP CONSTRAINT IF EXISTS "+constraint)
	})
	onboardingRequest(t, h, h.admin, in, 500)
	onboardingCounts(t, h, 0, 0)
	var history, refs, endpoints, audits int
	if err := h.a.DB.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM ra_asset_ownership_history WHERE workspace=$1),
		(SELECT count(*) FROM ra_asset_responsibility_refs WHERE workspace=$1),
		(SELECT count(*) FROM ra_endpoints WHERE workspace=$1),
		(SELECT count(*) FROM ra_audit_events WHERE workspace=$1 AND action IN ('asset.save','server.onboard'))`, h.a.Config.Workspace).Scan(&history, &refs, &endpoints, &audits); err != nil {
		t.Fatal(err)
	}
	if history+refs+endpoints+audits != 0 {
		t.Fatalf("partial asset write escaped rollback: %d/%d/%d/%d", history, refs, endpoints, audits)
	}
	selfAccessTestExec(t, h, "ALTER TABLE ra_asset_egress DROP CONSTRAINT "+constraint)
	onboardingRequest(t, h, h.admin, in, 200)
	onboardingCounts(t, h, 1, 2)
}

func TestIntegrationServerOnboardingExactPermitAndIdempotency(t *testing.T) {
	h := newHarness(t)
	in := onboardingInput(t, h)
	originalAllowed := append([]netip.Prefix{}, h.a.Config.Allowed...)
	first := onboardingRequest(t, h, h.admin, in, 200)
	if first["created"] != true || first["next"] != "verify_host_key" || len(first) != 5 {
		t.Fatalf("unexpected first response: %v", first)
	}
	retry := onboardingRequest(t, h, h.admin, in, 200)
	if retry["assetId"] != first["assetId"] || retry["accountId"] != first["accountId"] || retry["grantId"] != first["grantId"] || retry["created"] != false {
		t.Fatalf("non-idempotent retry: %v", retry)
	}
	changed := in
	changed.Secret.Password = "another-password"
	if out := onboardingRequest(t, h, h.admin, changed, 409); out["code"] != "idempotency_conflict" {
		t.Fatalf("credential change accepted under existing key: %v", out)
	}
	ctx := context.Background()
	asset := first["assetId"].(string)
	u := &User{ID: h.admin.id, Workspace: h.a.Config.Workspace, Role: "admin"}
	x, err := h.a.account(ctx, u, first["accountId"].(string))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"ssh", "sftp"} {
		ep, err := h.a.endpoint(ctx, u, asset, protocol)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.a.target(ctx, ep); err != nil {
			t.Fatalf("exact selected target rejected: %v", err)
		}
		for _, mutation := range []func(*Endpoint){
			func(e *Endpoint) { e.Port++ },
			func(e *Endpoint) { e.Host = "192.0.2.20" },
			func(e *Endpoint) { e.Protocol = "rdp" },
			func(e *Endpoint) { e.ID = ID() },
		} {
			modified := ep
			mutation(&modified)
			if _, err = h.a.target(ctx, modified); err == nil {
				t.Fatalf("permit broadened beyond exact endpoint: %+v", modified)
			}
		}
	}
	if !reflect.DeepEqual(originalAllowed, h.a.Config.Allowed) {
		t.Fatal("onboarding expanded global allowed networks")
	}
	for _, denied := range []struct{ protocol, action string }{{"sftp", "sftp.upload"}, {"sftp", "sftp.delete"}, {"rdp", "rdp.launch"}, {"rdp", "rdp.clipboard"}, {"ssh", "credential.temporary"}} {
		if _, err := h.a.policy(ctx, u, x, denied.protocol, denied.action); err == nil {
			t.Fatalf("unrequested permission granted: %s", denied.action)
		}
	}
	var ciphertext, nonce, audit []byte
	var version int64
	var trusted int
	var storedHash, hashVersion, subject string
	if err = h.a.DB.QueryRow(ctx, `SELECT s.ciphertext,s.nonce,s.version,
		(SELECT count(*) FROM ra_host_keys WHERE workspace=$1),
		(SELECT request_hash FROM ra_server_onboarding_requests WHERE workspace=$1),
		(SELECT hash_key_version FROM ra_server_onboarding_requests WHERE workspace=$1),
		(SELECT user_id FROM ra_grants WHERE workspace=$1),
		(SELECT jsonb_agg(details) FROM ra_audit_events WHERE workspace=$1)
		FROM ra_secrets s WHERE s.workspace=$1`, u.Workspace).Scan(&ciphertext, &nonce, &version, &trusted, &storedHash, &hashVersion, &subject, &audit); err != nil {
		t.Fatal(err)
	}
	var secret Secret
	if err = unseal(h.a.Config.Keys[hashVersion], nonce, ciphertext, u.Workspace+":"+x.ID+":"+formatInt(version), &secret); err != nil {
		t.Fatal(err)
	}
	canonical := in
	if _, _, err = h.a.validateServerOnboarding(&canonical); err != nil {
		t.Fatal(err)
	}
	if secret.Password != in.Secret.Password || bytes.Contains(ciphertext, []byte(in.Secret.Password)) || bytes.Contains(audit, []byte(in.Secret.Password)) || trusted != 0 || subject != u.ID || storedHash != serverOnboardingHash(h.a.Config.Keys[hashVersion], u.Workspace, u.ID, canonical) {
		t.Fatal("credential encryption, audit redaction, keyed retry hash, own-only grant, or host-key boundary failed")
	}
	h.request(h.admin, "DELETE", "/grants/"+first["grantId"].(string), nil, 200)
	onboardingRequest(t, h, h.admin, in, 200)
	if _, err = h.a.policy(ctx, u, x, "ssh", "ssh.connect"); err == nil {
		t.Fatal("replay restored revoked access")
	}
	h.a.Config.ActiveKey = "rotated"
	h.a.Config.Keys["rotated"] = bytes.Repeat([]byte{7}, 32)
	onboardingRequest(t, h, h.admin, in, 200)
	delete(h.a.Config.Keys, hashVersion)
	if out := onboardingRequest(t, h, h.admin, in, 409); out["code"] != "idempotency_conflict" {
		t.Fatalf("missing original retry key silently recreated server: %v", out)
	}
	onboardingCounts(t, h, 1, 2)
	// A later endpoint edit must not make its old one-time confirmation reusable.
	current := h.request(h.admin, "GET", "/assets/"+asset, nil, 200)
	originalEndpoints := make([]map[string]any, 0, 2)
	for _, raw := range current["endpoints"].([]any) {
		ep := raw.(map[string]any)
		originalEndpoints = append(originalEndpoints, map[string]any{
			"protocol": ep["protocol"], "host": ep["host"], "port": ep["port"], "gatewayId": ep["gatewayId"],
		})
	}
	changedEndpoints := make([]map[string]any, 0, len(originalEndpoints))
	for _, original := range originalEndpoints {
		changedEndpoints = append(changedEndpoints, map[string]any{
			"protocol": original["protocol"], "host": "192.0.2.21", "port": original["port"].(float64) + 10, "gatewayId": original["gatewayId"],
		})
	}
	edit := map[string]any{"name": in.Name, "kind": "physical", "osFamily": "linux", "enabled": true, "tags": []string{}, "metadata": map[string]string{}, "version": current["version"], "endpoints": changedEndpoints}
	h.request(h.admin, "PATCH", "/assets/"+asset, edit, 200)
	onboardingCounts(t, h, 1, 0)
	current = h.request(h.admin, "GET", "/assets/"+asset, nil, 200)
	edit["version"], edit["endpoints"] = current["version"], originalEndpoints
	h.request(h.admin, "PATCH", "/assets/"+asset, edit, 200)
	onboardingCounts(t, h, 1, 0)
	for _, protocol := range []string{"ssh", "sftp"} {
		ep, err := h.a.endpoint(ctx, u, asset, protocol)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.a.target(ctx, ep); err == nil {
			t.Fatalf("restoring original %s endpoint revived its old egress confirmation", protocol)
		}
	}
}

func TestIntegrationServerOnboardingRDPAndValidation(t *testing.T) {
	h := newHarness(t)
	in := onboardingInput(t, h)
	for _, mutate := range []func(*serverOnboardingInput){
		func(x *serverOnboardingInput) { x.Confirm = false },
		func(x *serverOnboardingInput) { x.IdempotencyKey = "" },
		func(x *serverOnboardingInput) { x.Host = "example.com" },
		func(x *serverOnboardingInput) { x.Host = "169.254.169.254" },
		func(x *serverOnboardingInput) { x.Host = "0.0.0.0" },
		func(x *serverOnboardingInput) { x.Host = "255.255.255.255" },
		func(x *serverOnboardingInput) { x.Host = "ff02::1" },
		func(x *serverOnboardingInput) { x.Protocols = []string{"ssh", "ssh"} },
		func(x *serverOnboardingInput) { x.SSHPort = -1 },
		func(x *serverOnboardingInput) {
			x.AuthType = "private_key"
			x.Secret = Secret{PrivateKey: "invalid-key"}
		},
		func(x *serverOnboardingInput) { x.ReadRoots = nil },
		func(x *serverOnboardingInput) { x.ReadRoots = []string{"/home/../etc"} },
		func(x *serverOnboardingInput) { x.WriteRoots = []string{"/etc"} },
		func(x *serverOnboardingInput) { x.AllowFileWrite = true },
		func(x *serverOnboardingInput) { x.AllowDrives = true },
		func(x *serverOnboardingInput) { x.ExpiresAt = time.Now().Add(31 * 24 * time.Hour) },
		func(x *serverOnboardingInput) { x.Secret = Secret{Password: "", PrivateKey: ""} },
	} {
		bad := in
		bad.Protocols = append([]string{}, in.Protocols...)
		mutate(&bad)
		onboardingRequest(t, h, h.admin, bad, 400)
	}
	onboardingCounts(t, h, 0, 0)
	in.Protocols, in.ReadRoots, in.OSFamily = []string{"rdp"}, nil, "windows"
	bad := in
	bad.Secret.Password = strings.Repeat("a", 1281)
	onboardingRequest(t, h, h.admin, bad, 400)
	first := onboardingRequest(t, h, h.admin, in, 200)
	if first["next"] != "select_connector" {
		t.Fatalf("RDP should continue connector selection, not fake a session: %v", first)
	}
	onboardingCounts(t, h, 1, 1)
	in.IdempotencyKey, in.AuthType, in.Secret, in.AllowInteractive = ID(), "interactive", Secret{}, true
	interactive := onboardingRequest(t, h, h.admin, in, 200)
	var secrets, launched int
	if err := h.a.DB.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM ra_secrets WHERE account_id=$1),
		(SELECT count(*) FROM ra_rdp_launches WHERE workspace=$2)`, interactive["accountId"], h.a.Config.Workspace).Scan(&secrets, &launched); err != nil {
		t.Fatal(err)
	}
	if secrets != 0 || launched != 0 {
		t.Fatal("interactive credential persisted or RDP launch invented")
	}
}

func TestServerOnboardingKeyedDigestAndLocalBoundary(t *testing.T) {
	a := &App{Config: Config{GatewayID: "gateway-test"}}
	in := serverOnboardingInput{Confirm: true, IdempotencyKey: "test", Name: "Linux", OSFamily: "linux", Host: "192.0.2.19", Protocols: []string{"ssh"}, Username: "tester", AuthType: "password", Secret: Secret{Password: "secret"}, ClaimantID: "owner"}
	key := bytes.Repeat([]byte{1}, 32)
	if serverOnboardingHash(key, "workspace", "user", in) == serverOnboardingHash(bytes.Repeat([]byte{2}, 32), "workspace", "user", in) || serverOnboardingHash(key, "workspace", "user", in) == serverOnboardingHash(key, "workspace", "other-user", in) {
		t.Fatal("onboarding hash is not bound to secret key and principal")
	}
	for _, host := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "224.0.0.1", "::", "fe80::1%eth0"} {
		in.Host = host
		if _, _, err := a.validateServerOnboarding(&in); err == nil {
			t.Fatalf("prohibited target accepted: %s", host)
		}
	}
}
