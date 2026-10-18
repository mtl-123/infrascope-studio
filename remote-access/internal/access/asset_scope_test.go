package access

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

func p2ScopeInput(name string, assets, users, groups []string) map[string]any {
	return map[string]any{
		"name": name, "description": "Read-only inventory scope", "enabled": true,
		"startsAt": time.Now().Add(-time.Hour), "expiresAt": time.Now().Add(time.Hour),
		"assetIds": assets, "userIds": users, "groupIds": groups,
	}
}

func p2ScopeGroup(h *harness, id string) map[string]any {
	h.t.Helper()
	for _, raw := range p2Items(h.t, h.request(h.admin, "GET", "/asset-groups", nil, 200)) {
		row := raw.(map[string]any)
		if row["id"] == id {
			return row
		}
	}
	h.t.Fatalf("asset group %s missing", id)
	return nil
}

func p2ScopeRaw(h *harness, u testUser, method, path string, body any, status int) ([]byte, http.Header) {
	h.t.Helper()
	var input io.Reader
	if body != nil {
		input = bytes.NewReader(marshal(body))
	}
	r, err := http.NewRequest(method, h.server.URL+path, input)
	if err != nil {
		h.t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", h.server.URL)
	r.Header.Set("X-CSRF-Token", u.csrf)
	client := u.client
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	if res.StatusCode != status {
		h.t.Fatalf("%s %s: want %d, got %d: %s", method, path, status, res.StatusCode, raw)
	}
	return raw, res.Header
}

func p2ScopeJSON(h *harness, u testUser, method, path string, body any, status int) map[string]any {
	h.t.Helper()
	raw, _ := p2ScopeRaw(h, u, method, path, body, status)
	var out map[string]any
	if len(raw) > 0 && raw[0] == '[' {
		var items []any
		if err := json.Unmarshal(raw, &items); err != nil {
			h.t.Fatal(err)
		}
		return map[string]any{"items": items}
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatal(err, string(raw))
	}
	return out
}

func p2ScopeIDs(t *testing.T, rows []any, want ...string) {
	t.Helper()
	got := make([]string, 0, len(rows))
	for _, raw := range rows {
		got = append(got, raw.(map[string]any)["id"].(string))
	}
	sort.Strings(got)
	wantCopy := append([]string{}, want...)
	sort.Strings(wantCopy)
	if strings.Join(got, ",") != strings.Join(wantCopy, ",") {
		t.Fatalf("visible IDs: got %v, want %v", got, wantCopy)
	}
}

func p2ScopeCSV(h *harness, u testUser, query string) ([]string, []map[string]string) {
	h.t.Helper()
	raw, headers := p2ScopeRaw(h, u, "GET", "/api/v1/assets/export"+query, nil, 200)
	if !strings.Contains(headers.Get("Content-Type"), "text/csv") {
		h.t.Fatalf("export must be CSV: %v", headers)
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\ufeff"))).ReadAll()
	if err != nil || len(rows) == 0 {
		h.t.Fatalf("invalid CSV: %v %s", err, raw)
	}
	out := make([]map[string]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		if len(row) != len(rows[0]) {
			h.t.Fatalf("CSV field count mismatch: %v", row)
		}
		item := map[string]string{}
		for i, key := range rows[0] {
			item[key] = row[i]
		}
		out = append(out, item)
	}
	return rows[0], out
}

func TestIntegrationAssetScopesReadOnlyAndRemoteGrant(t *testing.T) {
	h := newHarness(t)
	operator := h.user("scope-reader", "operator")
	manager := h.user("scope-manager", "asset_manager")
	auditor := h.user("scope-auditor", "auditor")
	h.setupAsset()
	ctx := context.Background()
	// Directory responsibility and a login identity remain separate even if their IDs coincide.
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_people(id,workspace,display_name,department,email,contact_type,source,enabled,created_by) VALUES($1,$2,'Scope reader','Operations','','internal','manual',true,$3)`, operator.id, h.a.Config.Workspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	ownerAsset := h.request(h.admin, "POST", "/assets", p2AssetInput("Responsibility is not authorization", p2Ownership("assigned", operator.id)), 200)["id"].(string)
	p2ScopeIDs(t, p2Items(t, h.request(operator, "GET", "/assets", nil, 200)))
	p2ScopeIDs(t, p2Items(t, h.request(auditor, "GET", "/assets", nil, 200)))
	h.request(operator, "GET", "/assets/"+ownerAsset, nil, 404)
	input := p2ScopeInput("Inventory readers", []string{h.asset, ownerAsset}, []string{operator.id, manager.id, auditor.id}, []string{})
	group := h.request(h.admin, "POST", "/asset-groups", input, 200)["id"].(string)
	for _, u := range []testUser{operator, manager, auditor} {
		p2ScopeIDs(t, p2Items(t, h.request(u, "GET", "/assets", nil, 200)), h.asset, ownerAsset)
		if got := h.request(u, "GET", "/assets/"+h.asset, nil, 200); got["canManage"] != false {
			t.Fatalf("read-only scope exposed management capability: %v", got)
		}
		h.request(u, "GET", "/asset-groups", nil, 403)
		h.request(u, "POST", "/asset-groups", input, 403)
		h.request(u, "PATCH", "/asset-groups/"+group, input, 403)
		edit := p2AssetInput("Unauthorized edit", p2Ownership("assigned", operator.id))
		edit["version"] = 1
		h.request(u, "PATCH", "/assets/"+h.asset, edit, 403)
		h.request(u, "GET", "/assets/"+h.asset+"/ownership-history", nil, 403)
		p2ScopeIDs(t, p2Items(t, h.request(u, "GET", "/assets/"+h.asset+"/accounts", nil, 200)))
		h.request(u, "GET", "/accounts/"+h.account, nil, 404)
		account := map[string]any{"name": "forged", "username": "forged", "authType": "password", "protocols": []string{"ssh"}, "enabled": true}
		h.request(u, "POST", "/assets/"+h.asset+"/accounts", account, 403)
		h.request(u, "PATCH", "/accounts/"+h.account, account, 403)
		h.request(u, "POST", "/accounts/"+h.account+"/credential", map[string]any{"action": "clear"}, 403)
		h.request(u, "POST", "/people", p2PersonInput("Unauthorized person"), 403)
		h.request(u, "PATCH", "/people/"+operator.id, map[string]any{"displayName": "changed", "version": 1}, 403)
		h.request(u, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 100, "rows": 30}, 403)
		h.request(u, "GET", "/sftp/entries?accountId="+h.account, nil, 403)
		h.request(u, "POST", "/rdp/launches", map[string]any{"assetId": h.asset, "accountId": h.account, "idempotencyKey": ID()}, 403)
		p2ScopeIDs(t, p2Items(t, h.request(u, "GET", "/my/access", nil, 200)))
	}
	h.request(operator, "GET", "/people", nil, 403)
	h.request(operator, "POST", "/assets", p2AssetInput("Forbidden create", p2Ownership("assigned", operator.id)), 403)
	owned := h.request(manager, "POST", "/assets", p2AssetInput("Manager's own inventory", p2Ownership("assigned", operator.id)), 200)["id"].(string)
	if got := h.request(manager, "GET", "/assets/"+owned, nil, 200); got["canManage"] != true {
		t.Fatalf("creator management was lost: %v", got)
	}
	if got := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200); got["canManage"] != true {
		t.Fatalf("admin management was lost: %v", got)
	}
	h.trust()
	grant := h.grant(operator, true)
	auditorGrant := h.grant(auditor, true)
	h.request(auditor, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 100, "rows": 30}, 403)
	h.request(auditor, "GET", "/sftp/entries?accountId="+h.account, nil, 403)
	h.request(auditor, "POST", "/rdp/launches", map[string]any{"assetId": h.asset, "accountId": h.account, "idempotencyKey": ID()}, 403)
	h.request(h.admin, "DELETE", "/grants/"+auditorGrant, nil, 200)
	input["enabled"], input["version"] = false, 1
	h.request(h.admin, "PATCH", "/asset-groups/"+group, input, 200)
	// The independently issued remote grant survives scope revocation, including real loopback I/O.
	p2ScopeIDs(t, p2Items(t, h.request(operator, "GET", "/assets", nil, 200)), h.asset)
	h.request(operator, "GET", "/accounts/"+h.account, nil, 200)
	h.request(operator, "GET", "/sftp/entries?accountId="+h.account+"&path="+url.QueryEscape(h.root), nil, 200)
	session := h.request(operator, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 100, "rows": 30}, 201)["id"].(string)
	h.request(operator, "DELETE", "/ssh/sessions/"+session, nil, 200)
	if _, err := h.a.DB.Exec(ctx, `UPDATE ra_grants SET actions=actions-'asset.view' WHERE id=$1`, grant); err != nil {
		t.Fatal(err)
	}
	h.request(operator, "GET", "/assets/"+h.asset, nil, 404)
	if _, err := h.a.DB.Exec(ctx, `UPDATE ra_grants SET actions=actions || '["asset.view"]'::jsonb WHERE id=$1`, grant); err != nil {
		t.Fatal(err)
	}
	h.request(operator, "GET", "/assets/"+h.asset, nil, 200)
	if _, err := h.a.DB.Exec(ctx, `UPDATE ra_accounts SET enabled=false WHERE id=$1`, h.account); err != nil {
		t.Fatal(err)
	}
	h.request(operator, "GET", "/assets/"+h.asset, nil, 404)
	if _, err := h.a.DB.Exec(ctx, `UPDATE ra_accounts SET enabled=true WHERE id=$1`, h.account); err != nil {
		t.Fatal(err)
	}
	h.request(h.admin, "DELETE", "/grants/"+grant, nil, 200)
	h.request(operator, "GET", "/assets/"+h.asset, nil, 404)
	h.request(operator, "GET", "/sftp/entries?accountId="+h.account, nil, 403)
}

func TestIntegrationAssetScopeValidationAndImmediateRevocation(t *testing.T) {
	h := newHarness(t)
	a, b := h.user("scope-a", "operator"), h.user("scope-b", "operator")
	person := p2CreatePerson(h, "Scope owner")
	asset := h.request(h.admin, "POST", "/assets", p2AssetInput("Scoped asset", p2Ownership("assigned", person)), 200)["id"].(string)
	userGroup := h.request(h.admin, "POST", "/groups", map[string]any{"name": "Reader team", "members": []string{b.id}}, 200)["id"].(string)
	input := p2ScopeInput("Team scope", []string{asset}, []string{a.id}, []string{userGroup})
	id := h.request(h.admin, "POST", "/asset-groups", input, 200)["id"].(string)
	row := p2ScopeGroup(h, id)
	for key, want := range map[string][]string{"asset_ids": {asset}, "user_ids": {a.id}, "group_ids": {userGroup}} {
		p2EqualJSON(t, row[key], want)
	}
	if row["version"] != float64(1) || row["enabled"] != true || row["description"] != input["description"] {
		t.Fatalf("scope did not round-trip: %v", row)
	}
	for _, u := range []testUser{a, b} {
		h.request(u, "GET", "/assets/"+asset, nil, 200)
	}
	ctx := context.Background()
	foreignWorkspace, foreignUser, foreignAsset, foreignGroup := ID(), ID(), ID(), ID()
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) SELECT $1,$2,'foreign','Foreign',password_hash,'admin' FROM ra_users WHERE id=$3`, foreignUser, foreignWorkspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_assets(id,workspace,name,kind,os_family,created_by) VALUES($1,$2,'Foreign asset','physical','other',$3)`, foreignAsset, foreignWorkspace, foreignUser); err != nil {
		t.Fatal(err)
	}
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_groups(id,workspace,name) VALUES($1,$2,'Foreign team')`, foreignGroup, foreignWorkspace); err != nil {
		t.Fatal(err)
	}
	foreignScope := ID()
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_asset_groups(id,workspace,name,starts_at,expires_at,created_by) VALUES($1,$2,'Foreign scope',now()-interval '1 hour',now()+interval '1 hour',$3)`, foreignScope, foreignWorkspace, foreignUser); err != nil {
		t.Fatal(err)
	}
	p2ScopeIDs(t, p2Items(t, h.request(h.admin, "GET", "/asset-groups", nil, 200)), id)
	input["version"] = 1
	h.request(h.admin, "PATCH", "/asset-groups/"+foreignScope, input, 404)
	delete(input, "version")
	for field, foreign := range map[string]string{"assetIds": foreignAsset, "userIds": foreignUser, "groupIds": foreignGroup} {
		valid := input[field]
		for _, invalid := range []string{foreign, ID()} {
			input[field] = []string{invalid}
			h.request(h.admin, "POST", "/asset-groups", input, 400)
			input["version"], input["name"] = 1, "Must not partially replace"
			h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 400)
			p2EqualJSON(t, p2ScopeGroup(h, id), row)
			delete(input, "version")
			input["name"] = "Team scope"
		}
		input[field] = valid
	}
	for _, mutation := range []map[string]any{
		{"name": " "}, {"name": strings.Repeat("x", 181)}, {"description": strings.Repeat("x", 2001)},
		{"startsAt": time.Time{}}, {"expiresAt": time.Time{}}, {"startsAt": time.Now().Add(2 * time.Hour)},
		{"unexpected": true}, {"assetIds": make([]string, 501)}, {"userIds": make([]string, 101)}, {"groupIds": make([]string, 101)},
	} {
		invalid := p2ScopeInput("Invalid scope", []string{asset}, []string{a.id}, []string{})
		for key, value := range mutation {
			invalid[key] = value
		}
		h.request(h.admin, "POST", "/asset-groups", invalid, 400)
	}
	h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 400)
	input["version"], input["description"] = 1, "Updated scope"
	h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 200)
	input["name"] = "Stale scope"
	h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 409)
	if got := p2ScopeGroup(h, id); got["name"] != "Team scope" || got["description"] != "Updated scope" || got["version"] != float64(2) {
		t.Fatalf("stale scope overwrite: %v", got)
	}
	input["name"] = "Team scope"
	h.request(h.admin, "PATCH", "/asset-groups/"+ID(), input, 404)
	h.request(h.admin, "PATCH", "/groups/"+userGroup, map[string]any{"name": "Reader team", "members": []string{}}, 200)
	h.request(b, "GET", "/assets/"+asset, nil, 404)
	h.request(a, "GET", "/assets/"+asset, nil, 200)
	input["version"], input["userIds"] = 2, []string{}
	h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 200)
	h.request(a, "GET", "/assets/"+asset, nil, 404)
	h.request(h.admin, "PATCH", "/groups/"+userGroup, map[string]any{"name": "Reader team", "members": []string{b.id}}, 200)
	h.request(b, "GET", "/assets/"+asset, nil, 200)
	for i, window := range [][2]time.Time{
		{time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)},
		{time.Now().Add(-2 * time.Hour), time.Now().Add(-time.Hour)},
		{time.Now().Add(-time.Hour), time.Now().Add(time.Hour)},
	} {
		input["version"], input["startsAt"], input["expiresAt"] = 3+i, window[0], window[1]
		h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 200)
		want := 404
		if i == 2 {
			want = 200
		}
		h.request(b, "GET", "/assets/"+asset, nil, want)
	}
	input["version"], input["enabled"] = 6, false
	h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 200)
	h.request(b, "GET", "/assets/"+asset, nil, 404)
	input["version"], input["enabled"], input["assetIds"] = 7, true, []string{}
	h.request(h.admin, "PATCH", "/asset-groups/"+id, input, 200)
	p2ScopeIDs(t, p2Items(t, h.request(b, "GET", "/assets", nil, 200)))
	p2EqualJSON(t, p2ScopeGroup(h, id)["asset_ids"], []string{})
}

func TestIntegrationUnifiedAssetsFiltersAndSafeExport(t *testing.T) {
	h := newHarness(t)
	u := h.user("inventory-reader", "operator")
	personInput := p2PersonInput("Inventory owner")
	personInput["email"] = "private-owner@example.com"
	person := h.request(h.admin, "POST", "/people", personInput, 200)["id"].(string)
	otherPerson := p2CreatePerson(h, "Other owner")
	input := p2AssetInput(`=HYPERLINK("https://invalid.example","inventory")`, p2Ownership("assigned", person))
	input["category"], input["environment"], input["site"], input["business"] = "nas", "+SUM(1,1)", "@site", "-business"
	first := p2ScopeJSON(h, h.admin, "POST", "/api/v1/assets", input, 200)["id"].(string)
	secondInput := p2AssetInput("Inventory second", p2Ownership("assigned", otherPerson))
	secondInput["environment"] = "staging"
	second := h.request(h.admin, "POST", "/assets", secondInput, 200)["id"].(string)
	hidden := h.request(h.admin, "POST", "/assets", p2AssetInput("Hidden inventory", p2Ownership("assigned", person)), 200)["id"].(string)
	groupInput := p2ScopeInput("Inventory scope", []string{first, second}, []string{u.id}, []string{})
	group := h.request(h.admin, "POST", "/asset-groups", groupInput, 200)["id"].(string)
	otherGroup := h.request(h.admin, "POST", "/asset-groups", p2ScopeInput("Hidden scope", []string{hidden}, []string{}, []string{}), 200)["id"].(string)
	p2EqualJSON(t, p2ScopeJSON(h, u, "GET", "/api/v1/assets/"+first, nil, 200), h.request(u, "GET", "/assets/"+first, nil, 200))
	input["version"], input["description"] = 1, "Updated through unified inventory API"
	p2ScopeJSON(h, h.admin, "PATCH", "/api/v1/assets/"+first, input, 200)
	if got := h.request(h.admin, "GET", "/assets/"+first, nil, 200); got["version"] != float64(2) || got["description"] != input["description"] {
		t.Fatalf("alias did not update the original asset: %v", got)
	}
	p2ScopeJSON(h, h.admin, "PATCH", "/api/v1/assets/"+first, input, 409)
	for _, test := range []struct {
		query string
		ids   []string
	}{
		{"", []string{first, second}}, {"q=HYPERLINK", []string{first}}, {"category=nas", []string{first}},
		{"environment=" + url.QueryEscape("+SUM(1,1)"), []string{first}}, {"site=" + url.QueryEscape("@site"), []string{first}},
		{"business=" + url.QueryEscape("-business"), []string{first}}, {"ownerId=" + person, []string{first}},
		{"groupId=" + group, []string{first, second}}, {"groupId=" + otherGroup, []string{}},
		{"ids=" + first + "," + hidden, []string{first}}, {"ids=" + hidden, []string{}},
		{"category=nas&environment=staging", []string{}}, {"q=private-owner%40example.com", []string{}},
		{"ownerId=" + otherPerson + "&environment=staging&groupId=" + group, []string{second}},
	} {
		path := "/api/v1/assets?" + test.query
		alias := p2ScopeJSON(h, u, "GET", path, nil, 200)
		p2ScopeIDs(t, p2Items(t, alias), test.ids...)
		p2EqualJSON(t, alias, h.request(u, "GET", "/assets?"+test.query, nil, 200))
		_, exported := p2ScopeCSV(h, u, "?"+test.query)
		items := make([]any, 0, len(exported))
		for _, row := range exported {
			items = append(items, map[string]any{"id": row["id"]})
		}
		// Random URL-safe IDs may start with '-'; exports protect these cells too.
		expectedCSV := make([]string, len(test.ids))
		for i, id := range test.ids {
			expectedCSV[i] = csvSafe(id)
		}
		p2ScopeIDs(t, items, expectedCSV...)
	}
	for _, query := range []string{"offset=1", "offset=1000000", "ids=" + second, "q=does-not-match"} {
		p2ScopeJSON(h, u, "GET", "/api/v1/assets/"+hidden+"?"+query, nil, 404)
	}
	// Collection pagination must never turn an authorized item GET into a false 404.
	p2ScopeJSON(h, u, "GET", "/api/v1/assets/"+first+"?offset=1", nil, 200)
	for _, query := range []string{"offset=-1", "offset=bad", "offset=1000001", "q=" + strings.Repeat("q", 201), "ids=" + strings.TrimSuffix(strings.Repeat(first+",", 101), ",")} {
		p2ScopeJSON(h, u, "GET", "/api/v1/assets?"+query, nil, 400)
		h.request(u, "GET", "/assets?"+query, nil, 400)
	}
	headers, rows := p2ScopeCSV(h, u, "?ids="+first)
	p2EqualJSON(t, headers, []string{"id", "name", "category", "kind", "os_family", "environment", "site", "business", "enabled", "archived"})
	if len(rows) != 1 {
		t.Fatalf("expected one exported asset: %v", rows)
	}
	for _, field := range []string{"name", "environment", "site", "business"} {
		if rows[0][field] != "'"+input[field].(string) {
			t.Fatalf("CSV formula prefix not protected for %s: %q", field, rows[0][field])
		}
	}
	if bytes.Contains(marshal(rows), []byte("private-owner@example.com")) || bytes.Contains(marshal(rows), []byte("password")) {
		t.Fatalf("export leaked contact or credentials: %v", rows)
	}
	p2ScopeRaw(h, testUser{}, "GET", "/api/v1/assets/export", nil, 401)
	groupInput["version"], groupInput["enabled"] = 1, false
	h.request(h.admin, "PATCH", "/asset-groups/"+group, groupInput, 200)
	_, rows = p2ScopeCSV(h, u, "")
	if len(rows) != 0 {
		t.Fatalf("export retained revoked scope: %v", rows)
	}
}

func TestIntegrationAssetScopePaginationAndExportLimit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	prefix := ID()
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_assets(id,workspace,name,kind,os_family,created_by,category,environment) SELECT $1||n::text,$2,'Bulk inventory '||lpad(n::text,4,'0'),'physical','other',$3,'server',CASE WHEN n<=1000 THEN 'exportable' ELSE 'overflow' END FROM generate_series(1,1001) AS n`, prefix, h.a.Config.Workspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	firstIDs := []string{}
	for offset := 0; offset <= 1000; offset += 100 {
		rows := p2Items(t, p2ScopeJSON(h, h.admin, "GET", fmt.Sprintf("/api/v1/assets?offset=%d", offset), nil, 200))
		want := 100
		if offset == 1000 {
			want = 1
		}
		if len(rows) != want {
			t.Fatalf("asset page at %d: got %d, want %d", offset, len(rows), want)
		}
		for _, raw := range rows {
			id := raw.(map[string]any)["id"].(string)
			if offset == 0 {
				firstIDs = append(firstIDs, id)
			}
			if seen[id] {
				t.Fatalf("asset repeated across pages: %s", id)
			}
			seen[id] = true
		}
	}
	p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, h.admin, "GET", "/api/v1/assets?ids="+strings.Join(firstIDs, ","), nil, 200)), firstIDs...)
	for _, query := range []string{"", "?offset=1000"} {
		out := p2ScopeJSON(h, h.admin, "GET", "/api/v1/assets/export"+query, nil, 422)
		if !bytes.Contains(marshal(out), []byte("export_limit")) {
			t.Fatalf("oversized export lacks explicit error: %v", out)
		}
	}
	_, exported := p2ScopeCSV(h, h.admin, "?environment=exportable&offset=999")
	if len(exported) != 1000 {
		t.Fatalf("export must include all matching rows, not just the page: %d", len(exported))
	}
	for i := 0; i < 101; i++ {
		h.request(h.admin, "POST", "/asset-groups", p2ScopeInput(fmt.Sprintf("Paged group %03d", i), []string{}, []string{}, []string{}), 200)
	}
	first := p2Items(t, h.request(h.admin, "GET", "/asset-groups", nil, 200))
	next := p2Items(t, h.request(h.admin, "GET", "/asset-groups?offset=100", nil, 200))
	if len(first) != 100 || len(next) != 1 {
		t.Fatalf("asset groups must page 100 records: first=%d next=%d", len(first), len(next))
	}
	seen = map[string]bool{}
	for _, raw := range append(first, next...) {
		id := raw.(map[string]any)["id"].(string)
		if seen[id] {
			t.Fatalf("asset group repeated across pages: %s", id)
		}
		seen[id] = true
	}
	for _, query := range []string{"offset=-1", "offset=wrong", "offset=1000001"} {
		h.request(h.admin, "GET", "/asset-groups?"+query, nil, 400)
	}
}
