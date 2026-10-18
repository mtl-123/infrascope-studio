package access

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
)

func p2PersonInput(name string) map[string]any {
	return map[string]any{"displayName": name, "department": "Operations", "email": "", "contactType": "internal", "enabled": true}
}

func p2CreatePerson(h *harness, name string) string {
	h.t.Helper()
	return h.request(h.admin, "POST", "/people", p2PersonInput(name), 200)["id"].(string)
}

func p2Items(t *testing.T, response map[string]any) []any {
	t.Helper()
	items, ok := response["items"].([]any)
	if !ok {
		t.Fatalf("expected a JSON list, got %v", response)
	}
	return items
}

func p2Person(h *harness, id string) map[string]any {
	h.t.Helper()
	items := p2Items(h.t, h.request(h.admin, "GET", "/people?ids="+url.QueryEscape(id), nil, 200))
	if len(items) != 1 {
		h.t.Fatalf("expected one person for %s, got %v", id, items)
	}
	return items[0].(map[string]any)
}

func p2Ownership(state, id string) map[string]any {
	v := map[string]any{"state": state, "userId": "", "claimantId": "", "operationsId": "", "businessId": "", "notificationIds": []string{}, "backupIds": []string{}}
	if state == "pending" {
		v["claimantId"] = id
	} else {
		v["userId"] = id
	}
	return v
}

func p2AssetInput(name string, ownership map[string]any) map[string]any {
	v := map[string]any{
		"name": name, "kind": "physical", "osFamily": "other", "groupName": "P2-tests",
		"tags": []string{}, "metadata": map[string]string{}, "enabled": true, "archived": false,
		"category": "server", "environment": "production", "site": "Room A", "business": "Inventory",
		"endpoints": []map[string]any{},
	}
	if ownership != nil {
		v["ownership"] = ownership
	}
	return v
}

func p2EqualJSON(t *testing.T, got, want any) {
	t.Helper()
	if !bytes.Equal(marshal(got), marshal(want)) {
		t.Fatalf("JSON differs: got %s, want %s", marshal(got), marshal(want))
	}
}

func p2History(h *harness, asset string, count int) []any {
	h.t.Helper()
	items := p2Items(h.t, h.request(h.admin, "GET", "/assets/"+asset+"/ownership-history", nil, 200))
	if len(items) != count {
		h.t.Fatalf("expected %d ownership revisions, got %v", count, items)
	}
	for i, raw := range items {
		row := raw.(map[string]any)
		if row["changed_by"] != h.admin.id || row["changed_at"] == nil || row["changed_at"] == "" {
			h.t.Fatalf("missing ownership change provenance: %v", row)
		}
		if i > 0 && items[i-1].(map[string]any)["revision"].(float64) <= row["revision"].(float64) {
			h.t.Fatalf("ownership revisions are not descending: %v", items)
		}
	}
	return items
}

func TestIntegrationManualPeopleDirectory(t *testing.T) {
	h := newHarness(t)
	first := p2CreatePerson(h, "Same name")
	secondInput := p2PersonInput("Same name")
	secondInput["contactType"] = "external"
	secondInput["department"] = "Supplier"
	secondInput["email"] = "supplier@example.com"
	second := h.request(h.admin, "POST", "/people", secondInput, 200)["id"].(string)
	if first == second {
		t.Fatal("people with the same display name must retain separate identities")
	}
	person := p2Person(h, first)
	if person["display_name"] != "Same name" || person["department"] != "Operations" || person["email"] != "" || person["contact_type"] != "internal" || person["source"] != "manual" || person["enabled"] != true || person["version"] != float64(1) {
		t.Fatalf("manual person was not persisted truthfully: %v", person)
	}
	if person["email_configured"] == true {
		t.Fatalf("person without an email must not appear email-configured: %v", person)
	}
	if got := p2Person(h, second); got["source"] != "manual" || got["email"] != "supplier@example.com" || got["contact_type"] != "external" {
		t.Fatalf("external person lost its source or contact fields: %v", got)
	}
	for _, query := range []string{"Same name", "Supplier"} {
		items := p2Items(t, h.request(h.admin, "GET", "/people?q="+url.QueryEscape(query), nil, 200))
		want := 1
		if query == "Same name" {
			want = 2
		}
		if len(items) != want {
			t.Fatalf("search %q: expected %d people, got %v", query, want, items)
		}
	}
	if items := p2Items(t, h.request(h.admin, "GET", "/people?q=supplier%40example.com", nil, 200)); len(items) != 0 {
		t.Fatalf("directory search must not match private email fields: %v", items)
	}
	if items := p2Items(t, h.request(h.admin, "GET", "/people?ids="+first+","+second, nil, 200)); len(items) != 2 {
		t.Fatalf("ID hydration lost people with the same name: %v", items)
	}
	if items := p2Items(t, h.request(h.admin, "GET", "/people?offset=1", nil, 200)); len(items) != 1 {
		t.Fatalf("offset did not paginate the people directory: %v", items)
	}
	for _, query := range []string{"offset=-1", "offset=wrong", "offset=1000001", "q=" + strings.Repeat("x", 201), "ids=" + strings.TrimSuffix(strings.Repeat(first+",", 21), ",")} {
		h.request(h.admin, "GET", "/people?"+query, nil, 400)
	}
	for _, mutation := range []map[string]any{
		{"displayName": " "}, {"email": "not-an-address"}, {"email": "Display Name <person@example.com>"},
		{"contactType": "robot"}, {"source": "wecom"}, {"unexpected": true},
	} {
		input := p2PersonInput("Invalid person")
		for key, value := range mutation {
			input[key] = value
		}
		h.request(h.admin, "POST", "/people", input, 400)
	}
	edit := p2PersonInput("Renamed person")
	h.request(h.admin, "PATCH", "/people/"+first, edit, 400)
	edit["version"] = 1
	h.request(h.admin, "PATCH", "/people/"+first, edit, 200)
	edit["displayName"] = "Stale editor"
	h.request(h.admin, "PATCH", "/people/"+first, edit, 409)
	person = p2Person(h, first)
	if person["display_name"] != "Renamed person" || person["version"] != float64(2) {
		t.Fatalf("stale person edit changed persisted data: %v", person)
	}
	if _, err := h.a.DB.Exec(context.Background(), `INSERT INTO ra_people(id,workspace,display_name,department,email,contact_type,source,enabled,created_by) SELECT $1||n::text,$2,'Bulk person '||n::text,'Pagination','','internal','manual',true,$3 FROM generate_series(1,101) AS n`, ID(), h.a.Config.Workspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	page := p2Items(t, h.request(h.admin, "GET", "/people", nil, 200))
	next := p2Items(t, h.request(h.admin, "GET", "/people?offset=100", nil, 200))
	if len(page) != 100 || len(next) != 3 {
		t.Fatalf("directory must page 100 records: first=%d next=%d", len(page), len(next))
	}
	seen := map[string]bool{}
	for _, raw := range append(page, next...) {
		id := raw.(map[string]any)["id"].(string)
		if seen[id] {
			t.Fatalf("person %s repeated across directory pages", id)
		}
		seen[id] = true
	}
}

func TestIntegrationPeopleAndOwnershipScopes(t *testing.T) {
	h := newHarness(t)
	manager := h.user("p2-manager", "asset_manager")
	operator := h.user("p2-operator", "operator")
	auditor := h.user("p2-auditor", "auditor")
	input := p2PersonInput("Private contact")
	input["email"] = "private@example.com"
	person := h.request(h.admin, "POST", "/people", input, 200)["id"].(string)
	items := p2Items(t, h.request(manager, "GET", "/people?ids="+person, nil, 200))
	if len(items) != 1 || items[0].(map[string]any)["email"] != "" || items[0].(map[string]any)["email_configured"] != true {
		t.Fatalf("asset manager directory must redact email but expose configuration state: %v", items)
	}
	if got := p2Items(t, h.request(manager, "GET", "/people?q=private%40example.com", nil, 200)); len(got) != 0 {
		t.Fatalf("asset manager could infer private email through search: %v", got)
	}
	input["version"] = 1
	h.request(manager, "POST", "/people", input, 403)
	h.request(manager, "PATCH", "/people/"+person, input, 403)
	for _, user := range []testUser{operator, auditor} {
		h.request(user, "GET", "/people", nil, 403)
		h.request(user, "GET", "/people?ids="+person, nil, 403)
		h.request(user, "POST", "/people", input, 403)
		h.request(user, "PATCH", "/people/"+person, input, 403)
	}

	ctx := context.Background()
	foreignWorkspace, foreignUser, foreignPerson := ID(), ID(), ID()
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) SELECT $1,$2,'foreign-admin','Foreign admin',password_hash,'admin' FROM ra_users WHERE id=$3`, foreignUser, foreignWorkspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_people(id,workspace,display_name,department,email,contact_type,source,enabled,created_by) VALUES($1,$2,'Foreign contact','Other','foreign@example.com','internal','manual',true,$3)`, foreignPerson, foreignWorkspace, foreignUser); err != nil {
		t.Fatal(err)
	}
	if got := p2Items(t, h.request(h.admin, "GET", "/people?ids="+foreignPerson, nil, 200)); len(got) != 0 {
		t.Fatalf("people lookup leaked a different workspace: %v", got)
	}
	h.request(h.admin, "PATCH", "/people/"+foreignPerson, input, 404)
	for _, field := range []string{"userId", "operationsId", "businessId", "notificationIds", "backupIds", "claimantId"} {
		ownership := p2Ownership("assigned", person)
		if field == "claimantId" {
			ownership = p2Ownership("pending", foreignPerson)
		} else if strings.HasSuffix(field, "Ids") {
			ownership[field] = []string{foreignPerson}
		} else {
			ownership[field] = foreignPerson
		}
		h.request(h.admin, "POST", "/assets", p2AssetInput("Cross-workspace "+field, ownership), 400)
	}
	adminAsset := h.request(h.admin, "POST", "/assets", p2AssetInput("Admin asset", p2Ownership("assigned", person)), 200)["id"].(string)
	managerAsset := h.request(manager, "POST", "/assets", p2AssetInput("Manager asset", p2Ownership("assigned", person)), 200)["id"].(string)
	h.request(manager, "GET", "/assets/"+managerAsset+"/ownership-history", nil, 200)
	h.request(manager, "GET", "/assets/"+adminAsset+"/ownership-history", nil, 403)
	for _, user := range []testUser{operator, auditor} {
		h.request(user, "GET", "/assets/"+adminAsset+"/ownership-history", nil, 403)
	}
	h.request(h.admin, "GET", "/assets/"+ID()+"/ownership-history", nil, 404)
	edit := p2AssetInput("Unauthorized change", p2Ownership("assigned", person))
	edit["version"] = 1
	h.request(manager, "PATCH", "/assets/"+adminAsset, edit, 403)
	p2History(h, adminAsset, 1)
}

func TestIntegrationMonitoringOnlyAssetsAndOwnershipValidation(t *testing.T) {
	h := newHarness(t)
	owner := p2CreatePerson(h, "Asset owner")
	ops := p2CreatePerson(h, "Operations contact")
	business := p2CreatePerson(h, "Business contact")
	ownership := p2Ownership("assigned", owner)
	ownership["operationsId"], ownership["businessId"] = ops, business
	notifications := []string{ops, business}
	sort.Strings(notifications)
	ownership["notificationIds"], ownership["backupIds"] = notifications, []string{business}
	for _, category := range []string{"server", "nas", "pve", "switch", "printer", "scanner", "other"} {
		input := p2AssetInput("Monitoring-only "+category, ownership)
		input["category"] = category
		asset := h.request(h.admin, "POST", "/assets", input, 200)["id"].(string)
		got := h.request(h.admin, "GET", "/assets/"+asset, nil, 200)
		if got["category"] != category || got["environment"] != "production" || got["site"] != "Room A" || got["business"] != "Inventory" || got["ownershipLegacy"] != false || got["kind"] != "physical" {
			t.Fatalf("monitoring asset metadata did not round-trip: %v", got)
		}
		if endpoints, ok := got["endpoints"].([]any); !ok || len(endpoints) != 0 {
			t.Fatalf("monitoring-only asset acquired an endpoint: %v", got)
		}
		p2EqualJSON(t, got["ownership"], ownership)
	}
	input := p2AssetInput("Default server category", p2Ownership("pending", owner))
	delete(input, "category")
	input["kind"] = "virtual"
	asset := h.request(h.admin, "POST", "/assets", input, 200)["id"].(string)
	got := h.request(h.admin, "GET", "/assets/"+asset, nil, 200)
	if got["category"] != "server" || got["kind"] != "virtual" {
		t.Fatalf("default category changed the existing kind contract: %v", got)
	}
	p2EqualJSON(t, got["ownership"], p2Ownership("pending", owner))

	invalid := []map[string]any{nil, {}, p2Ownership("assigned", ""), p2Ownership("pending", ""), p2Ownership("unknown", owner), p2Ownership("assigned", ID()), p2Ownership("assigned", h.admin.id)}
	both := p2Ownership("assigned", owner)
	both["claimantId"] = ops
	invalid = append(invalid, both)
	both = p2Ownership("pending", owner)
	both["userId"] = ops
	invalid = append(invalid, both)
	unknown := p2Ownership("assigned", owner)
	unknown["pretendVerified"] = true
	invalid = append(invalid, unknown)
	for _, field := range []string{"operationsId", "businessId", "notificationIds", "backupIds"} {
		bad := p2Ownership("assigned", owner)
		if strings.HasSuffix(field, "Ids") {
			bad[field] = []string{ID()}
		} else {
			bad[field] = ID()
		}
		invalid = append(invalid, bad)
	}
	for i, bad := range invalid {
		h.request(h.admin, "POST", "/assets", p2AssetInput(fmt.Sprintf("Invalid ownership %d", i), bad), 400)
	}
	for field, value := range map[string]any{"ownership": nil, "category": "firewall", "kind": "container"} {
		bad := p2AssetInput("Invalid asset", p2Ownership("assigned", owner))
		bad[field] = value
		h.request(h.admin, "POST", "/assets", bad, 400)
	}
	var endpoints, grants, sessions, transfers, launches int
	if err := h.a.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM ra_endpoints WHERE workspace=$1),(SELECT count(*) FROM ra_grants WHERE workspace=$1),(SELECT count(*) FROM ra_remote_sessions WHERE workspace=$1),(SELECT count(*) FROM ra_transfers WHERE workspace=$1),(SELECT count(*) FROM ra_rdp_launches WHERE workspace=$1)`, h.a.Config.Workspace).Scan(&endpoints, &grants, &sessions, &transfers, &launches); err != nil {
		t.Fatal(err)
	}
	if endpoints != 0 || grants != 0 || sessions != 0 || transfers != 0 || launches != 0 {
		t.Fatalf("monitoring metadata created remote access: endpoints=%d grants=%d sessions=%d transfers=%d launches=%d", endpoints, grants, sessions, transfers, launches)
	}
}

func TestIntegrationOwnershipHistoryAndLegacyUpgrade(t *testing.T) {
	h := newHarness(t)
	first, second := p2CreatePerson(h, "First owner"), p2CreatePerson(h, "Second owner")
	personEdit := p2PersonInput("First owner")
	personEdit["email"], personEdit["version"] = "historical-owner@example.com", 1
	h.request(h.admin, "PATCH", "/people/"+first, personEdit, 200)
	initial := p2Ownership("assigned", first)
	asset := h.request(h.admin, "POST", "/assets", p2AssetInput("History target", initial), 200)["id"].(string)
	history := p2History(h, asset, 1)
	if history[0].(map[string]any)["revision"] != float64(1) {
		t.Fatalf("first ownership revision must be 1: %v", history)
	}
	p2EqualJSON(t, history[0].(map[string]any)["ownership"], initial)
	snapshot, ok := history[0].(map[string]any)["people_snapshot"].([]any)
	if !ok || len(snapshot) != 1 {
		t.Fatalf("ownership history must preserve the contact identity snapshot: %v", history)
	}
	p2EqualJSON(t, snapshot[0], map[string]any{"id": first, "displayName": "First owner", "department": "Operations", "contactType": "internal"})
	if bytes.Contains(marshal(history), []byte("email")) {
		t.Fatalf("ownership history leaked email fields: %s", marshal(history))
	}
	personEdit["displayName"], personEdit["department"], personEdit["version"] = "Renamed owner", "New department", 2
	h.request(h.admin, "PATCH", "/people/"+first, personEdit, 200)
	p2EqualJSON(t, p2History(h, asset, 1), history)
	for version := 1; version <= 2; version++ {
		edit := p2AssetInput("Ordinary asset edit", nil)
		edit["version"] = version
		if version == 2 {
			edit["ownership"] = initial
		}
		h.request(h.admin, "PATCH", "/assets/"+asset, edit, 200)
		p2History(h, asset, 1)
	}
	replacement := p2Ownership("assigned", second)
	edit := p2AssetInput("Changed owner", replacement)
	edit["version"] = 3
	h.request(h.admin, "PATCH", "/assets/"+asset, edit, 200)
	history = p2History(h, asset, 2)
	p2EqualJSON(t, history[0].(map[string]any)["ownership"], replacement)
	p2EqualJSON(t, history[1].(map[string]any)["ownership"], initial)
	edit["ownership"] = initial
	h.request(h.admin, "PATCH", "/assets/"+asset, edit, 409)
	edit["version"] = 4
	edit["endpoints"] = []map[string]any{{"protocol": "ssh", "host": "bad host", "port": 22, "gatewayId": h.a.Config.GatewayID}}
	h.request(h.admin, "PATCH", "/assets/"+asset, edit, 400)
	p2EqualJSON(t, p2History(h, asset, 2), history)
	got := h.request(h.admin, "GET", "/assets/"+asset, nil, 200)
	if got["version"] != float64(4) {
		t.Fatalf("rejected edit advanced asset version: %v", got)
	}
	p2EqualJSON(t, got["ownership"], replacement)

	legacy := ID()
	if _, err := h.a.DB.Exec(context.Background(), `INSERT INTO ra_assets(id,workspace,name,kind,os_family,created_by) VALUES($1,$2,'Legacy inventory','physical','other',$3)`, legacy, h.a.Config.Workspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	got = h.request(h.admin, "GET", "/assets/"+legacy, nil, 200)
	if got["ownershipLegacy"] != true {
		t.Fatalf("legacy asset falsely claimed an established owner: %v", got)
	}
	edit = p2AssetInput("Legacy inventory", nil)
	edit["version"] = 1
	h.request(h.admin, "PATCH", "/assets/"+legacy, edit, 400)
	p2History(h, legacy, 0)
	edit["ownership"] = p2Ownership("pending", first)
	h.request(h.admin, "PATCH", "/assets/"+legacy, edit, 200)
	got = h.request(h.admin, "GET", "/assets/"+legacy, nil, 200)
	if got["ownershipLegacy"] != false || got["version"] != float64(2) {
		t.Fatalf("legacy remediation was not persisted: %v", got)
	}
	p2EqualJSON(t, got["ownership"], edit["ownership"])
	p2History(h, legacy, 1)
}

func TestIntegrationDisabledPeopleDoNotGrantRemoteAccess(t *testing.T) {
	h := newHarness(t)
	operator := h.user("p2-owner-operator", "operator")
	owner := p2CreatePerson(h, "p2-owner-operator")
	replacement := p2CreatePerson(h, "Replacement owner")
	h.setupAsset()
	edit := assetEdit(h, 1, "Owned target")
	edit["ownership"] = p2Ownership("assigned", owner)
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	if owner == operator.id {
		t.Fatal("person directory identity must not be a platform login identity")
	}
	if items := p2Items(t, h.request(operator, "GET", "/my/access", nil, 200)); len(items) != 0 {
		t.Fatalf("ownership unexpectedly supplied remote access: %v", items)
	}
	h.request(operator, "GET", "/assets/"+h.asset, nil, 404)
	h.request(operator, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 80, "rows": 24}, 403)
	h.request(operator, "GET", "/sftp/entries?accountId="+h.account, nil, 403)
	h.request(operator, "POST", "/rdp/launches", map[string]any{"assetId": h.asset, "accountId": h.account, "idempotencyKey": ID()}, 403)

	personEdit := p2PersonInput("p2-owner-operator")
	personEdit["enabled"], personEdit["version"] = false, 1
	h.request(h.admin, "PATCH", "/people/"+owner, personEdit, 200)
	if got := p2Person(h, owner); got["enabled"] != false || got["version"] != float64(2) {
		t.Fatalf("disabling a referenced person did not preserve the identity: %v", got)
	}
	before := p2History(h, h.asset, 2)
	edit["version"] = 2
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 400)
	p2EqualJSON(t, p2History(h, h.asset, 2), before)
	got := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	if got["version"] != float64(2) {
		t.Fatalf("invalid disabled-person rebinding advanced the asset version: %v", got)
	}
	p2EqualJSON(t, got["ownership"], p2Ownership("assigned", owner))
	delete(edit, "ownership")
	edit["name"] = "Metadata-only edit with retired contact"
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	p2EqualJSON(t, p2History(h, h.asset, 2), before)
	edit["version"], edit["ownership"] = 3, p2Ownership("assigned", replacement)
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	p2History(h, h.asset, 3)
	for _, field := range []string{"userId", "claimantId", "operationsId", "businessId", "notificationIds", "backupIds"} {
		ownership := p2Ownership("assigned", replacement)
		if field == "claimantId" {
			ownership = p2Ownership("pending", owner)
		} else if strings.HasSuffix(field, "Ids") {
			ownership[field] = []string{owner}
		} else {
			ownership[field] = owner
		}
		h.request(h.admin, "POST", "/assets", p2AssetInput("Disabled "+field, ownership), 400)
	}

	h.grant(operator, false)
	if items := p2Items(t, h.request(operator, "GET", "/my/access", nil, 200)); len(items) != 1 {
		t.Fatalf("explicit grant did not expose the account: %v", items)
	}
	delete(edit, "ownership")
	edit["version"], edit["archived"] = 4, true
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	if items := p2Items(t, h.request(operator, "GET", "/my/access", nil, 200)); len(items) != 0 {
		t.Fatalf("archiving an asset retained remote access: %v", items)
	}
	h.request(operator, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 80, "rows": 24}, 403)
	edit["version"], edit["archived"] = 5, false
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	if items := p2Items(t, h.request(operator, "GET", "/my/access", nil, 200)); len(items) != 0 {
		t.Fatalf("unarchiving implicitly restored revoked grants: %v", items)
	}
	p2History(h, h.asset, 3)
}
