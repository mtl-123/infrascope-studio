package access

import (
	"context"
	"testing"
)

func TestAssetCSVFormulaAndControlPrefixes(t *testing.T) {
	for _, prefix := range []string{"", " ", "\t", "\r", "\n", "\u00a0", "\u2003", "\u202f", "\ufeff", "\u200b", " \ufeff\u200b\u00a0"} {
		for _, formula := range []string{"=1+1", "+SUM(1,2)", "-1+1", "@SUM(1,2)"} {
			input := prefix + formula
			if got := csvSafe(input); got != "'"+input {
				t.Errorf("formula prefix %q: got %q, want %q", input, got, "'"+input)
			}
		}
	}
	for _, input := range []string{"tab\tseparated", "line\nbreak", "carriage\rreturn", "\tplain text"} {
		if got := csvSafe(input); got != "'"+input {
			t.Errorf("control characters %q: got %q, want %q", input, got, "'"+input)
		}
	}
	for _, test := range []struct {
		input any
		want  string
	}{
		{"", ""}, {"ordinary asset", "ordinary asset"}, {"asset-01", "asset-01"},
		{"name@example.com", "name@example.com"}, {"comma,name", "comma,name"},
		{"\u00a0ordinary asset", "\u00a0ordinary asset"}, {true, "true"}, {42, "42"},
	} {
		if got := csvSafe(test.input); got != test.want {
			t.Errorf("safe cell %#v: got %q, want %q", test.input, got, test.want)
		}
	}
}

func TestIntegrationUnifiedAssetAliasBoundaries(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	ctx := context.Background()
	before := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	input := p2AssetInput("Must not be persisted", before["ownership"].(map[string]any))
	input["version"] = before["version"]
	var assetsBefore, savesBefore int
	if err := h.a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_assets WHERE workspace=$1", h.a.Config.Workspace).Scan(&assetsBefore); err != nil {
		t.Fatal(err)
	}
	if err := h.a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_audit_events WHERE workspace=$1 AND action='asset.save'", h.a.Config.Workspace).Scan(&savesBefore); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "incorrect-csrf"} {
		invalid := h.admin
		invalid.csrf = token
		for _, request := range []struct{ method, path string }{
			{"POST", "/api/v1/assets"}, {"PATCH", "/api/v1/assets/" + h.asset},
		} {
			out := p2ScopeJSON(h, invalid, request.method, request.path, input, 403)
			if out["code"] != "csrf" {
				t.Fatalf("alias did not reject invalid CSRF before mutation: %v", out)
			}
		}
	}
	var assetsAfter, savesAfter int
	if err := h.a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_assets WHERE workspace=$1", h.a.Config.Workspace).Scan(&assetsAfter); err != nil {
		t.Fatal(err)
	}
	if err := h.a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_audit_events WHERE workspace=$1 AND action='asset.save'", h.a.Config.Workspace).Scan(&savesAfter); err != nil {
		t.Fatal(err)
	}
	if assetsAfter != assetsBefore || savesAfter != savesBefore {
		t.Fatalf("CSRF rejection mutated state: assets %d -> %d, saves %d -> %d", assetsBefore, assetsAfter, savesBefore, savesAfter)
	}
	p2EqualJSON(t, p2ScopeJSON(h, h.admin, "GET", "/api/v1/assets/"+h.asset, nil, 200), before)

	foreignWorkspace, foreignUser, foreignAsset := ID(), ID(), ID()
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) SELECT $1,$2,'foreign-boundary','Foreign boundary',password_hash,'admin' FROM ra_users WHERE id=$3`, foreignUser, foreignWorkspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_assets(id,workspace,name,kind,os_family,created_by) VALUES($1,$2,'Foreign boundary asset','physical','other',$3)`, foreignAsset, foreignWorkspace, foreignUser); err != nil {
		t.Fatal(err)
	}
	reader := h.user("alias-boundary-reader", "operator")
	h.grant(reader, true)
	for _, u := range []testUser{h.admin, reader} {
		for _, base := range []string{"/api/v1/assets", "/api/remote-access/assets"} {
			p2ScopeJSON(h, u, "GET", base+"/"+foreignAsset, nil, 404)
			p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, u, "GET", base+"?ids="+foreignAsset, nil, 200)))
			p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, u, "GET", base+"?ids="+foreignAsset+","+h.asset, nil, 200)), h.asset)
		}
		_, rows := p2ScopeCSV(h, u, "?ids="+foreignAsset)
		if len(rows) != 0 {
			t.Fatalf("foreign workspace asset leaked through CSV: %v", rows)
		}
		_, rows = p2ScopeCSV(h, u, "?ids="+foreignAsset+","+h.asset)
		if len(rows) != 1 || rows[0]["id"] != h.asset {
			t.Fatalf("mixed workspace export must retain only the authorized asset: %v", rows)
		}
	}

	// Archiving the account must invalidate its metadata grant without relying on revocation.
	account := map[string]any{"name": "test-os-account", "username": "tester", "authType": "password", "protocols": []string{"ssh", "sftp", "rdp"}, "enabled": true, "archived": true}
	h.request(h.admin, "PATCH", "/accounts/"+h.account, account, 200)
	var activeGrant bool
	if err := h.a.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ra_grants WHERE workspace=$1 AND account_id=$2 AND NOT revoked AND starts_at<=now() AND expires_at>now())", h.a.Config.Workspace, h.account).Scan(&activeGrant); err != nil {
		t.Fatal(err)
	}
	if !activeGrant {
		t.Fatal("archived-account test requires an otherwise valid, unrevoked grant")
	}
	for _, base := range []string{"/api/v1/assets", "/api/remote-access/assets"} {
		p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, reader, "GET", base, nil, 200)))
		p2ScopeJSON(h, reader, "GET", base+"/"+h.asset, nil, 404)
	}
	_, rows := p2ScopeCSV(h, reader, "")
	if len(rows) != 0 {
		t.Fatalf("archived account retained asset visibility in export: %v", rows)
	}
	account["archived"] = false
	h.request(h.admin, "PATCH", "/accounts/"+h.account, account, 200)
	p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, reader, "GET", "/api/v1/assets", nil, 200)), h.asset)
}
