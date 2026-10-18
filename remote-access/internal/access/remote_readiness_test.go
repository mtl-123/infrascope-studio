package access

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestRemoteReadinessRejectsGatewayInterfaceAddresses(t *testing.T) {
	app := &App{Config: Config{GatewayID: "local", Allowed: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}}}
	interfaces := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	for _, host := range []string{"192.0.2.10", "2001:db8::10", "::ffff:192.0.2.10"} {
		state, reason := app.readinessGatewayWithInterfaces(Endpoint{Host: host, Gateway: "local"}, interfaces)
		if state != "needs_gateway_policy" || !strings.Contains(reason, "自身地址") {
			t.Fatalf("allowed CIDR bypassed local interface denial for %s: %s %s", host, state, reason)
		}
	}
	endpoint := Endpoint{Host: "192.0.2.11", Gateway: "local"}
	if state, reason := app.readinessGatewayWithInterfaces(endpoint, interfaces); state != "" {
		t.Fatalf("other allowed host incorrectly blocked: %s %s", state, reason)
	}
	if state, reason := app.readinessGatewayWithInterfaces(endpoint, func() ([]net.Addr, error) {
		return nil, errors.New("interface enumeration failed")
	}); state != "needs_gateway_policy" || !strings.Contains(reason, "无法枚举") {
		t.Fatalf("interface enumeration failure must not imply readiness: %s %s", state, reason)
	}
	app.Config.LoopbackTest = true
	endpoint.Host = "192.0.2.10"
	if state, reason := app.readinessGatewayWithInterfaces(endpoint, func() ([]net.Addr, error) {
		t.Fatal("explicit loopback test mode should not enumerate interfaces")
		return nil, nil
	}); state != "" {
		t.Fatalf("explicit loopback test exception was lost: %s %s", state, reason)
	}
}

func readReadiness(h *harness, user testUser, asset string) remoteAssetReadiness {
	h.t.Helper()
	raw, _ := p2ScopeRaw(h, user, http.MethodGet, "/api/v1/assets/"+asset+"/remote-readiness", nil, http.StatusOK)
	var out remoteAssetReadiness
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatal(err)
	}
	if strings.Contains(string(raw), "remote-test-secret") || strings.Contains(string(raw), "ciphertext") || strings.Contains(string(raw), "privateKey") {
		h.t.Fatal("readiness exposed secret material")
	}
	if len(out.Protocols) != 3 {
		h.t.Fatalf("expected all protocol prerequisites, got %#v", out)
	}
	return out
}

func readinessProtocol(t *testing.T, out remoteAssetReadiness, protocol, state string) remoteProtocolReadiness {
	t.Helper()
	for _, got := range out.Protocols {
		if got.Protocol == protocol {
			if got.State != state {
				t.Fatalf("%s readiness: want %s, got %#v", protocol, state, got)
			}
			return got
		}
	}
	t.Fatalf("missing %s", protocol)
	return remoteProtocolReadiness{}
}

func readinessCounts(h *harness) map[string]int {
	h.t.Helper()
	out := map[string]int{}
	for _, table := range []string{"ra_grants", "ra_accounts", "ra_secrets", "ra_host_keys", "ra_remote_sessions", "ra_transfers", "ra_rdp_launches", "ra_audit_events", "ra_connectors", "ra_browser_bindings"} {
		var count int
		if err := h.a.DB.QueryRow(context.Background(), "SELECT count(*) FROM "+table+" WHERE workspace=$1", h.a.Config.Workspace).Scan(&count); err != nil {
			h.t.Fatal(err)
		}
		out[table] = count
	}
	return out
}

func TestIntegrationRemoteReadinessAdminDoesNotGrantOrConnect(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	before := readinessCounts(h)
	out := readReadiness(h, h.admin, h.asset)
	if out.AssetID != h.asset || out.AssetName != "Integration target" || out.OSFamily != "linux" || !out.CanManage || !out.CanGrantSelf || out.ConnectorReady {
		t.Fatalf("incorrect asset metadata: %#v", out)
	}
	for _, proto := range []string{"ssh", "sftp", "rdp"} {
		p := readinessProtocol(t, out, proto, "needs_grant")
		if p.Endpoint == nil || p.Endpoint.Host != h.host || len(p.Accounts) != 1 || p.Accounts[0].Authorized || len(p.Accounts[0].Actions) != 0 || !p.Accounts[0].CredentialConfigured {
			t.Fatalf("management became remote permission: %#v", p)
		}
	}
	if after := readinessCounts(h); !reflect.DeepEqual(before, after) {
		t.Fatalf("readiness wrote remote data: before=%v after=%v", before, after)
	}
	ctx := context.Background()
	if _, err := h.a.DB.Exec(ctx, "DELETE FROM ra_secrets WHERE account_id=$1", h.account); err != nil {
		t.Fatal(err)
	}
	readinessProtocol(t, readReadiness(h, h.admin, h.asset), "ssh", "needs_credential")
	if _, err := h.a.DB.Exec(ctx, "UPDATE ra_accounts SET enabled=false WHERE id=$1", h.account); err != nil {
		t.Fatal(err)
	}
	readinessProtocol(t, readReadiness(h, h.admin, h.asset), "ssh", "needs_account")
	if _, err := h.a.DB.Exec(ctx, "DELETE FROM ra_endpoints WHERE asset_id=$1", h.asset); err != nil {
		t.Fatal(err)
	}
	readinessProtocol(t, readReadiness(h, h.admin, h.asset), "ssh", "needs_endpoint")
	if _, err := h.a.DB.Exec(ctx, "UPDATE ra_assets SET enabled=false WHERE id=$1", h.asset); err != nil {
		t.Fatal(err)
	}
	for _, proto := range []string{"ssh", "sftp", "rdp"} {
		readinessProtocol(t, readReadiness(h, h.admin, h.asset), proto, "asset_disabled")
	}
	p2ScopeRaw(h, testUser{}, "GET", "/api/v1/assets/"+h.asset+"/remote-readiness", nil, 401)
}

func TestIntegrationRemoteReadinessVisibilityDoesNotLeakAccounts(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	operator := h.user("readiness-reader", "operator")
	manager := h.user("readiness-manager", "asset_manager")
	auditor := h.user("readiness-auditor", "auditor")
	p2ScopeRaw(h, operator, "GET", "/api/v1/assets/"+h.asset+"/remote-readiness", nil, 404)
	h.request(h.admin, "POST", "/asset-groups", p2ScopeInput("Readiness metadata only", []string{h.asset}, []string{operator.id, manager.id, auditor.id}, []string{}), 200)
	for _, user := range []testUser{operator, manager, auditor} {
		out := readReadiness(h, user, h.asset)
		if out.CanManage || out.CanGrantSelf {
			t.Fatal("metadata visibility granted management or self authorization")
		}
		for _, proto := range []string{"ssh", "sftp", "rdp"} {
			if p := readinessProtocol(t, out, proto, "needs_account"); len(p.Accounts) != 0 {
				t.Fatalf("metadata visibility exposed account metadata: %#v", p.Accounts)
			}
		}
	}
	h.grant(auditor, true)
	if out := readReadiness(h, auditor, h.asset); len(out.Protocols[0].Accounts) != 0 || out.ConnectorReady {
		t.Fatal("auditor obtained remote capabilities")
	}
	grant := h.grant(operator, true)
	p := readinessProtocol(t, readReadiness(h, operator, h.asset), "ssh", "needs_host_key")
	if len(p.Accounts) != 1 || !p.Accounts[0].Authorized || !contains(p.Accounts[0].Actions, "ssh.connect") {
		t.Fatal("valid user grant not reflected")
	}
	if _, err := h.a.DB.Exec(context.Background(), "UPDATE ra_grants SET actions=actions-'ssh.connect' WHERE id=$1", grant); err != nil {
		t.Fatal(err)
	}
	out := readReadiness(h, operator, h.asset)
	if p = readinessProtocol(t, out, "ssh", "needs_account"); len(p.Accounts) != 0 {
		t.Fatal("account metadata leaked for unauthorized protocol")
	}
	readinessProtocol(t, out, "sftp", "needs_host_key")
	h.request(h.admin, "DELETE", "/grants/"+grant, nil, 200)
	if p = readinessProtocol(t, readReadiness(h, operator, h.asset), "ssh", "needs_account"); len(p.Accounts) != 0 {
		t.Fatal("revoked grant still exposed account")
	}
	h.grant(operator, true)
	if _, err := h.a.DB.Exec(context.Background(), "UPDATE ra_accounts SET enabled=false WHERE id=$1", h.account); err != nil {
		t.Fatal(err)
	}
	if p = readinessProtocol(t, readReadiness(h, operator, h.asset), "ssh", "needs_account"); len(p.Accounts) != 0 {
		t.Fatal("disabled account exposed to scope reader")
	}
	if _, err := h.a.DB.Exec(context.Background(), "UPDATE ra_assets SET created_by=$1 WHERE id=$2", manager.id, h.asset); err != nil {
		t.Fatal(err)
	}
	out = readReadiness(h, manager, h.asset)
	if !out.CanManage || out.CanGrantSelf || len(out.Protocols[0].Accounts) != 1 || out.Protocols[0].Accounts[0].Authorized {
		t.Fatalf("creator management incorrectly grants self-use: %#v", out)
	}
	foreign := newHarness(t)
	foreign.setupAsset()
	p2ScopeRaw(h, h.admin, "GET", "/api/v1/assets/"+foreign.asset+"/remote-readiness", nil, 404)
}

func TestIntegrationRemoteReadinessHostTrustGatewayAndBrowserBinding(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	u := h.user("readiness-operator", "operator")
	grant := h.grant(u, true)
	readinessProtocol(t, readReadiness(h, u, h.asset), "ssh", "needs_host_key")
	// The existing fixture is a real local protocol server, not an external host.
	h.trust()
	before := readinessCounts(h)
	out := readReadiness(h, u, h.asset)
	readinessProtocol(t, out, "ssh", "ready_to_attempt")
	readinessProtocol(t, out, "sftp", "ready_to_attempt")
	if p := readinessProtocol(t, out, "rdp", "needs_connector"); !strings.Contains(p.Reason, "HTTP") {
		t.Fatal("HTTP platform must explain its controlled connector prerequisite")
	}
	if after := readinessCounts(h); !reflect.DeepEqual(before, after) {
		t.Fatalf("readiness connected or wrote state: before=%v after=%v", before, after)
	}
	// Perform actual SFTP separately; readiness alone does not prove authentication.
	h.request(u, "GET", "/sftp/entries?accountId="+h.account+"&path="+url.QueryEscape(h.root), nil, 200)
	if _, err := h.a.DB.Exec(context.Background(), `UPDATE ra_grants SET limits=jsonb_set(limits,'{readRoots}','[]') WHERE id=$1`, grant); err != nil {
		t.Fatal(err)
	}
	readinessProtocol(t, readReadiness(h, u, h.asset), "sftp", "needs_grant")
	if _, err := h.a.DB.Exec(context.Background(), `UPDATE ra_grants SET limits=jsonb_set(limits,'{readRoots}',$1::jsonb) WHERE id=$2`, marshal([]string{h.root}), grant); err != nil {
		t.Fatal(err)
	}
	allowed := h.a.Config.Allowed
	h.a.Config.Allowed = nil
	out = readReadiness(h, u, h.asset)
	readinessProtocol(t, out, "ssh", "needs_gateway_policy")
	readinessProtocol(t, out, "rdp", "needs_connector")
	h.a.Config.Allowed = allowed
	ctx := context.Background()
	updateEndpoint := func(host, gateway string) {
		t.Helper()
		if _, err := h.a.DB.Exec(ctx, "UPDATE ra_endpoints SET host=$1,gateway_id=$2 WHERE asset_id=$3 AND protocol='ssh'", host, gateway, h.asset); err != nil {
			t.Fatal(err)
		}
	}
	updateEndpoint("192.0.2.10", h.a.Config.GatewayID)
	readinessProtocol(t, readReadiness(h, u, h.asset), "ssh", "needs_gateway_policy")
	updateEndpoint("does-not-resolve.invalid", h.a.Config.GatewayID)
	// A guaranteed unresolvable DNS name still yields only an attempt, proving no DNS probe.
	readinessProtocol(t, readReadiness(h, u, h.asset), "ssh", "ready_to_attempt")
	updateEndpoint(h.host, "unconfigured-peer")
	readinessProtocol(t, readReadiness(h, u, h.asset), "ssh", "needs_gateway_policy")
	h.a.Config.Peers = map[string]string{"unconfigured-peer": "https://example.invalid"}
	readinessProtocol(t, readReadiness(h, u, h.asset), "ssh", "ready_to_attempt")
	updateEndpoint(h.host, h.a.Config.GatewayID)

	serverURL, _ := url.Parse(h.server.URL)
	loginHash := ""
	for _, cookie := range u.client.Jar.Cookies(serverURL) {
		if cookie.Name == "infra_session" {
			loginHash = digest(cookie.Value)
		}
	}
	if loginHash == "" {
		t.Fatal("test session cookie missing")
	}
	// Metadata fixture only: no real HTTPS server, Windows device or RDP session.
	h.a.Config.Origin = "https://platform.example.invalid"
	connector, binding := ID(), ID()
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_connectors(id,workspace,user_id,name,public_key,windows_user_hash,approved_origin,version,last_seen,capabilities)
 VALUES($1,$2,$3,'Readiness metadata fixture',$4,'not-a-real-Windows-device',$5,'1.0.0',now(),'{"ok":true,"mstsc":true,"rdpsign":true,"credentialApi":true,"signing":{"ok":true,"configured":true}}')`, connector, h.a.Config.Workspace, u.id, []byte("fixture-only"), h.a.Config.Origin); err != nil {
		t.Fatal(err)
	}
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_browser_bindings(id,workspace,user_id,connector_id,login_id_hash,expires_at) VALUES($1,$2,$3,$4,'wrong-browser',now()+interval '1 hour')`, binding, h.a.Config.Workspace, u.id, connector); err != nil {
		t.Fatal(err)
	}
	readinessProtocol(t, readReadiness(h, u, h.asset), "rdp", "needs_connector")
	if _, err := h.a.DB.Exec(ctx, "UPDATE ra_browser_bindings SET login_id_hash=$1 WHERE id=$2", loginHash, binding); err != nil {
		t.Fatal(err)
	}
	h.a.Config.Allowed = nil
	before = readinessCounts(h)
	out = readReadiness(h, u, h.asset)
	if !out.ConnectorReady {
		t.Fatal("online connector for own login was not recognized")
	}
	readinessProtocol(t, out, "rdp", "ready_to_attempt")
	readinessProtocol(t, out, "ssh", "needs_gateway_policy")
	if after := readinessCounts(h); !reflect.DeepEqual(before, after) {
		t.Fatal("readiness should not choose a device or queue an RDP task")
	}
	for _, capabilities := range []string{
		`{}`,
		`null`,
		`{"mstsc":true}`,
		`{"ok":true,"credentialApi":true,"mstsc":true,"rdpsign":true}`,
		`{"ok":true,"credentialApi":true,"mstsc":true,"rdpsign":true,"signing":true}`,
		`{"ok":true,"credentialApi":true,"mstsc":true,"rdpsign":true,"signing":null}`,
	} {
		if _, err := h.a.DB.Exec(ctx, "UPDATE ra_connectors SET capabilities=$1::jsonb,last_seen=now() WHERE id=$2", capabilities, connector); err != nil {
			t.Fatal(err)
		}
		out = readReadiness(h, u, h.asset)
		if out.ConnectorReady {
			t.Fatalf("missing or malformed capability evidence reported ready: %s", capabilities)
		}
		readinessProtocol(t, out, "rdp", "needs_connector")
	}
	if _, err := h.a.DB.Exec(ctx, `UPDATE ra_connectors SET capabilities='{"ok":true,"credentialApi":true,"mstsc":true,"rdpsign":true,"signing":{"ok":true,"configured":true}}' WHERE id=$1`, connector); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{
		"last_seen=now()-interval '21 seconds'",
		"last_seen=now(),revoked=true",
		"revoked=false,capabilities='{\"mstsc\":false}'",
		"capabilities='{\"signing\":{\"ok\":true,\"configured\":false}}'",
	} {
		if _, err := h.a.DB.Exec(ctx, "UPDATE ra_connectors SET "+change+" WHERE id=$1", connector); err != nil {
			t.Fatal(err)
		}
		out = readReadiness(h, u, h.asset)
		if out.ConnectorReady {
			t.Fatalf("unavailable connector reported ready after %s", change)
		}
		readinessProtocol(t, out, "rdp", "needs_connector")
	}
}
