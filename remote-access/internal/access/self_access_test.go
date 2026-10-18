package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func selfAccessTestInput() selfAccessInput {
	return selfAccessInput{Confirm: true, Protocols: []string{"ssh", "sftp", "rdp"}, ExpiresAt: time.Now().Add(time.Hour).UTC(), ReadRoots: []string{"/home/tester"}, IdempotencyKey: ID()}
}

func selfAccessTestExec(t *testing.T, h *harness, sql string, args ...any) {
	t.Helper()
	if _, err := h.a.DB.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func selfAccessTestCounts(t *testing.T, h *harness, grants, requests, audits int) {
	t.Helper()
	var gotGrants, gotRequests, gotAudits int
	err := h.a.DB.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM ra_grants WHERE workspace=$1),
		(SELECT count(*) FROM ra_self_access_requests WHERE workspace=$1),
		(SELECT count(*) FROM ra_audit_events WHERE workspace=$1 AND action='grant.self')`, h.a.Config.Workspace).Scan(&gotGrants, &gotRequests, &gotAudits)
	if err != nil {
		t.Fatal(err)
	}
	if gotGrants != grants || gotRequests != requests || gotAudits != audits {
		t.Fatalf("self access state: grants/requests/audits got %d/%d/%d want %d/%d/%d", gotGrants, gotRequests, gotAudits, grants, requests, audits)
	}
}

func TestIntegrationSelfAccessExplicitScopeAndValidation(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	ctx := context.Background()
	url := "/accounts/" + h.account + "/grant-self"
	selfAccessTestCounts(t, h, 0, 0, 0)
	if got := h.request(h.admin, "GET", "/my/access", nil, 200); len(got["items"].([]any)) != 0 {
		t.Fatalf("creating asset/account implicitly granted access: %v", got)
	}
	var secretBefore []byte
	var versionBefore int64
	if err := h.a.DB.QueryRow(ctx, "SELECT ciphertext,version FROM ra_secrets WHERE account_id=$1", h.account).Scan(&secretBefore, &versionBefore); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*selfAccessInput)
		code string
	}{
		{"confirmation", func(in *selfAccessInput) { in.Confirm = false }, "self_grant_confirmation"},
		{"missing-key", func(in *selfAccessInput) { in.IdempotencyKey = "" }, "self_grant_confirmation"},
		{"padded-key", func(in *selfAccessInput) { in.IdempotencyKey = " padded " }, "self_grant_confirmation"},
		{"duplicate-protocol", func(in *selfAccessInput) { in.Protocols = []string{"ssh", "ssh"} }, "self_grant_protocol"},
		{"unknown-protocol", func(in *selfAccessInput) { in.Protocols = []string{"telnet"} }, "self_grant_protocol"},
		{"empty-read-roots", func(in *selfAccessInput) { in.ReadRoots = nil }, "self_grant_roots"},
		{"relative-root", func(in *selfAccessInput) { in.ReadRoots = []string{"home/tester"} }, "self_grant_roots"},
		{"unclean-root", func(in *selfAccessInput) { in.ReadRoots = []string{"/home/../etc"} }, "self_grant_roots"},
		{"write-root-without-confirmation", func(in *selfAccessInput) { in.WriteRoots = []string{"/home/tester"} }, "self_grant_roots"},
		{"write-without-root", func(in *selfAccessInput) { in.AllowFileWrite = true }, "self_grant_roots"},
		{"roots-without-sftp", func(in *selfAccessInput) { in.Protocols = []string{"ssh"} }, "self_grant_options"},
		{"rdp-options-without-rdp", func(in *selfAccessInput) { in.Protocols = []string{"sftp"}; in.AllowDrives = true }, "self_grant_options"},
		{"expired", func(in *selfAccessInput) { in.ExpiresAt = time.Now().Add(-time.Minute) }, "self_grant_expiry"},
		{"too-long", func(in *selfAccessInput) { in.ExpiresAt = time.Now().Add(31 * 24 * time.Hour) }, "self_grant_expiry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := selfAccessTestInput()
			tc.edit(&in)
			out := h.request(h.admin, "POST", url, in, 400)
			if out["code"] != tc.code {
				t.Fatalf("wrong error: %v", out)
			}
			selfAccessTestCounts(t, h, 0, 0, 0)
		})
	}
	h.request(h.admin, "POST", "/accounts/"+ID()+"/grant-self", selfAccessTestInput(), 404)
	foreignWorkspace, foreignUser, foreignAsset, foreignAccount := ID(), ID(), ID(), ID()
	selfAccessTestExec(t, h, `INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) SELECT $1,$2,'foreign-self-access','Foreign',password_hash,'admin' FROM ra_users WHERE id=$3`, foreignUser, foreignWorkspace, h.admin.id)
	selfAccessTestExec(t, h, `INSERT INTO ra_assets(id,workspace,name,kind,os_family,created_by) VALUES($1,$2,'Foreign','virtual','linux',$3)`, foreignAsset, foreignWorkspace, foreignUser)
	selfAccessTestExec(t, h, `INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,created_by) VALUES($1,$2,$3,'Foreign account','tester','password','["ssh"]',$4)`, foreignAccount, foreignWorkspace, foreignAsset, foreignUser)
	h.request(h.admin, "POST", "/accounts/"+foreignAccount+"/grant-self", selfAccessTestInput(), 404)
	for _, tc := range []struct{ table, id, code string }{
		{"ra_assets", h.asset, "asset_disabled"},
		{"ra_accounts", h.account, "account_disabled"},
	} {
		for _, column := range []string{"enabled", "archived"} {
			selfAccessTestExec(t, h, "UPDATE "+tc.table+" SET "+column+"=$1 WHERE id=$2", column == "archived", tc.id)
			out := h.request(h.admin, "POST", url, selfAccessTestInput(), 403)
			if out["code"] != tc.code {
				t.Fatalf("disabled/archived resource returned %v", out)
			}
			selfAccessTestExec(t, h, "UPDATE "+tc.table+" SET "+column+"=$1 WHERE id=$2", column == "enabled", tc.id)
		}
	}
	selfAccessTestExec(t, h, "UPDATE ra_accounts SET protocols='[\"ssh\"]' WHERE id=$1", h.account)
	if out := h.request(h.admin, "POST", url, selfAccessTestInput(), 400); out["code"] != "self_grant_protocol" {
		t.Fatalf("account protocol restriction ignored: %v", out)
	}
	selfAccessTestExec(t, h, "UPDATE ra_accounts SET protocols='[\"ssh\",\"sftp\",\"rdp\"]' WHERE id=$1", h.account)
	selfAccessTestExec(t, h, "UPDATE ra_accounts SET auth_type='interactive' WHERE id=$1", h.account)
	interactive := selfAccessTestInput()
	interactive.Protocols, interactive.ReadRoots = []string{"rdp"}, nil
	if out := h.request(h.admin, "POST", url, interactive, 400); out["code"] != "interactive_confirmation" {
		t.Fatalf("interactive auth silently allowed: %v", out)
	}
	selfAccessTestExec(t, h, "UPDATE ra_accounts SET auth_type='password' WHERE id=$1", h.account)
	selfAccessTestExec(t, h, "DELETE FROM ra_endpoints WHERE asset_id=$1 AND protocol='rdp'", h.asset)
	if out := h.request(h.admin, "POST", url, selfAccessTestInput(), 400); out["code"] != "endpoint_unavailable" {
		t.Fatalf("missing endpoint silently allowed: %v", out)
	}
	selfAccessTestExec(t, h, `INSERT INTO ra_endpoints(id,workspace,asset_id,protocol,host,port,gateway_id) VALUES($1,$2,$3,'rdp',$4,$5,$6)`, ID(), h.a.Config.Workspace, h.asset, h.host, h.port, h.a.Config.GatewayID)
	selfAccessTestCounts(t, h, 0, 0, 0)
	in := selfAccessTestInput()
	out := h.request(h.admin, "POST", url, in, 200)
	if out["created"] != true {
		t.Fatalf("first explicit request not created: %v", out)
	}
	var owner, grantedBy string
	var rawActions, rawProtocols, rawLimits []byte
	if err := h.a.DB.QueryRow(ctx, "SELECT user_id,granted_by,actions,protocols,limits FROM ra_grants WHERE id=$1", out["id"]).Scan(&owner, &grantedBy, &rawActions, &rawProtocols, &rawLimits); err != nil {
		t.Fatal(err)
	}
	var actions, protocols []string
	var limits Limits
	for _, pair := range []struct {
		raw   []byte
		value any
	}{{rawActions, &actions}, {rawProtocols, &protocols}, {rawLimits, &limits}} {
		if err := json.Unmarshal(pair.raw, pair.value); err != nil {
			t.Fatal(err)
		}
	}
	wantActions := []string{"asset.view", "remoteAccount.view", "remoteAccount.use", "rdp.launch", "sftp.list", "sftp.download", "ssh.connect", "ssh.resume", "ssh.close"}
	if owner != h.admin.id || grantedBy != h.admin.id || !reflect.DeepEqual(actions, wantActions) || !reflect.DeepEqual(protocols, []string{"rdp", "sftp", "ssh"}) {
		t.Fatalf("unexpected grant subject/actions/protocols: %s %s %v %v", owner, grantedBy, actions, protocols)
	}
	if !reflect.DeepEqual(limits.ReadRoots, in.ReadRoots) || len(limits.WriteRoots) != 0 || limits.AllowOverwrite || limits.AllowInteractive || limits.MaxConcurrent != 3 {
		t.Fatalf("default grant broadened file/interactive rights: %+v", limits)
	}
	x, err := h.a.account(ctx, &User{ID: h.admin.id, Workspace: h.a.Config.Workspace}, h.account)
	if err != nil {
		t.Fatal(err)
	}
	u := &User{ID: h.admin.id, Workspace: h.a.Config.Workspace, Role: "admin"}
	for _, allowed := range []struct{ protocol, action string }{{"ssh", "ssh.connect"}, {"sftp", "sftp.list"}, {"sftp", "sftp.download"}, {"rdp", "rdp.launch"}} {
		if _, err := h.a.policy(ctx, u, x, allowed.protocol, allowed.action); err != nil {
			t.Fatalf("explicit permission unavailable: %s: %v", allowed.action, err)
		}
	}
	for _, denied := range []struct{ protocol, action string }{{"sftp", "sftp.upload"}, {"sftp", "sftp.delete"}, {"rdp", "rdp.clipboard"}, {"rdp", "rdp.driveRedirect"}, {"ssh", "credential.temporary"}} {
		if _, err := h.a.policy(ctx, u, x, denied.protocol, denied.action); err == nil {
			t.Fatalf("unrequested permission allowed: %s", denied.action)
		}
	}
	var secretAfter []byte
	var versionAfter int64
	var trustedKeys int
	if err := h.a.DB.QueryRow(ctx, "SELECT ciphertext,version,(SELECT count(*) FROM ra_host_keys WHERE workspace=$2) FROM ra_secrets WHERE account_id=$1", h.account, h.a.Config.Workspace).Scan(&secretAfter, &versionAfter, &trustedKeys); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secretBefore, secretAfter) || versionBefore != versionAfter || trustedKeys != 0 {
		t.Fatal("self grant changed secret or implicitly trusted a host key")
	}
	selfAccessTestCounts(t, h, 1, 1, 1)
}

func TestIntegrationSelfAccessRoleReauthAndCSRFBoundaries(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	url := "/accounts/" + h.account + "/grant-self"
	for _, role := range []string{"asset_manager", "operator", "auditor"} {
		u := h.user("self-access-"+role, role)
		out := h.request(u, "POST", url, selfAccessTestInput(), 403)
		if out["code"] != "self_grant_denied" {
			t.Fatalf("role %s: wrong rejection: %v", role, out)
		}
	}
	for _, token := range []string{"", "incorrect-csrf"} {
		u := h.admin
		u.csrf = token
		if out := h.request(u, "POST", url, selfAccessTestInput(), 403); out["code"] != "csrf" {
			t.Fatalf("CSRF not enforced before mutation: %v", out)
		}
	}
	selfAccessTestExec(t, h, "UPDATE ra_login_sessions SET reauth_at=now()-interval '6 minutes' WHERE user_id=$1", h.admin.id)
	if out := h.request(h.admin, "POST", url, selfAccessTestInput(), 403); out["code"] != "reauth_required" {
		t.Fatalf("old authentication silently accepted: %v", out)
	}
	selfAccessTestCounts(t, h, 0, 0, 0)
	h.request(h.admin, "POST", "/auth/reauth", map[string]string{"password": "test-password-123"}, 200)
	h.request(h.admin, "POST", url, selfAccessTestInput(), 200)
	selfAccessTestCounts(t, h, 1, 1, 1)
}

func TestIntegrationSelfAccessIdempotencyAndConcurrentRetry(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	url := "/accounts/" + h.account + "/grant-self"
	in := selfAccessTestInput()
	first := h.request(h.admin, "POST", url, in, 200)
	retry := h.request(h.admin, "POST", url, in, 200)
	if retry["id"] != first["id"] || retry["created"] != false {
		t.Fatalf("retry created another grant: first=%v retry=%v", first, retry)
	}
	changed := in
	changed.ReadRoots = []string{"/different-root"}
	if out := h.request(h.admin, "POST", url, changed, 409); out["code"] != "idempotency_conflict" {
		t.Fatalf("same key accepted another request: %v", out)
	}
	if out := h.request(h.admin, "POST", "/accounts/"+ID()+"/grant-self", in, 409); out["code"] != "idempotency_conflict" {
		t.Fatalf("same key accepted another account: %v", out)
	}
	h.request(h.admin, "DELETE", "/grants/"+first["id"].(string), nil, 200)
	retry = h.request(h.admin, "POST", url, in, 200)
	var revoked bool
	if err := h.a.DB.QueryRow(context.Background(), "SELECT revoked FROM ra_grants WHERE id=$1", first["id"]).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked || retry["created"] != false || retry["id"] != first["id"] {
		t.Fatalf("retry restored revoked access: %v revoked=%v", retry, revoked)
	}
	selfAccessTestCounts(t, h, 1, 1, 1)
	in.IdempotencyKey = ID()
	payload := marshal(in)
	type result struct {
		id      string
		created bool
		err     error
	}
	results := make(chan result, 6)
	start := make(chan struct{})
	for i := 0; i < cap(results); i++ {
		go func() {
			<-start
			r, err := http.NewRequest("POST", h.server.URL+"/api/remote-access"+url, bytes.NewReader(payload))
			if err != nil {
				results <- result{err: err}
				return
			}
			r.Header.Set("Origin", h.server.URL)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", h.admin.csrf)
			res, err := h.admin.client.Do(r)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer res.Body.Close()
			raw, err := io.ReadAll(res.Body)
			if err != nil {
				results <- result{err: err}
				return
			}
			if res.StatusCode != 200 {
				results <- result{err: fmt.Errorf("concurrent grant status %d: %s", res.StatusCode, raw)}
				return
			}
			var out struct {
				ID      string `json:"id"`
				Created bool   `json:"created"`
			}
			if err = json.Unmarshal(raw, &out); err != nil {
				results <- result{err: err}
				return
			}
			results <- result{id: out.ID, created: out.Created}
		}()
	}
	close(start)
	created, id := 0, ""
	for i := 0; i < cap(results); i++ {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.id == "" || id != "" && id != got.id {
			t.Fatalf("concurrent retry returned inconsistent IDs: %q %q", id, got.id)
		}
		id = got.id
		if got.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent retries created %d grants, want 1", created)
	}
	selfAccessTestCounts(t, h, 2, 2, 2)
}
