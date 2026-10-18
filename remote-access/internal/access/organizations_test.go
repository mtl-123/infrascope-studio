package access

import (
	"context"
	"testing"
)

func p2OrganizationInput(name, parent string, members ...string) map[string]any {
	return map[string]any{"name": name, "description": "Direct metadata scope; hierarchy does not inherit", "parentId": parent, "memberIds": members, "enabled": true}
}

func p2OrganizationRow(h *harness, id string) map[string]any {
	h.t.Helper()
	for _, raw := range p2Items(h.t, h.request(h.admin, "GET", "/organizations", nil, 200)) {
		row := raw.(map[string]any)
		if row["id"] == id {
			return row
		}
	}
	h.t.Fatalf("organization %s missing", id)
	return nil
}

func TestIntegrationOrganizationsMetadataOnlyAndRevocation(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	reader, manager, auditor := h.user("org-reader", "operator"), h.user("org-manager", "asset_manager"), h.user("org-auditor", "auditor")
	input := p2OrganizationInput("Operations", "", reader.id, manager.id, auditor.id)
	org := h.request(h.admin, "POST", "/organizations", input, 200)["id"].(string)
	asset := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	edit := p2AssetInput("Organization inventory", asset["ownership"].(map[string]any))
	edit["version"], edit["organizationId"] = asset["version"], org
	// Keep real loopback endpoints/account usable for the independent-grant check.
	edit["endpoints"] = asset["endpoints"]
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	for _, user := range []testUser{reader, manager, auditor} {
		p2ScopeIDs(t, p2Items(t, h.request(user, "GET", "/assets", nil, 200)), h.asset)
		row := h.request(user, "GET", "/assets/"+h.asset, nil, 200)
		if row["canManage"] != false || row["organization_id"] != org {
			t.Fatalf("organization scope must be metadata-only: %v", row)
		}
		h.request(user, "GET", "/organizations", nil, 403)
		h.request(user, "POST", "/organizations", input, 403)
		h.request(user, "PATCH", "/organizations/"+org, input, 403)
		h.request(user, "PATCH", "/assets/"+h.asset, edit, 403)
		h.request(user, "GET", "/assets/"+h.asset+"/ownership-history", nil, 403)
		p2ScopeIDs(t, p2Items(t, h.request(user, "GET", "/assets/"+h.asset+"/accounts", nil, 200)))
		h.request(user, "GET", "/accounts/"+h.account, nil, 404)
		h.request(user, "POST", "/ssh/sessions", map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 100, "rows": 30}, 403)
		h.request(user, "GET", "/sftp/entries?accountId="+h.account, nil, 403)
		h.request(user, "POST", "/rdp/launches", map[string]any{"assetId": h.asset, "accountId": h.account, "idempotencyKey": ID()}, 403)
		_, exported := p2ScopeCSV(h, user, "")
		if len(exported) != 1 || exported[0]["id"] != h.asset {
			t.Fatalf("organization CSV scope mismatch: %v", exported)
		}
	}
	h.request(reader, "GET", "/organizations/options", nil, 403)
	h.request(auditor, "GET", "/organizations/options", nil, 403)
	options := p2Items(t, h.request(manager, "GET", "/organizations/options", nil, 200))
	p2ScopeIDs(t, options, org)
	if len(options[0].(map[string]any)) != 3 {
		t.Fatalf("options must contain only id/name/enabled, not organization members: %v", options)
	}
	groupInput := p2ScopeInput("Independent metadata grant", []string{h.asset}, []string{auditor.id}, nil)
	group := h.request(h.admin, "POST", "/asset-groups", groupInput, 200)["id"].(string)
	grant := h.grant(reader, true)
	input["version"], input["memberIds"] = 1, []string{}
	h.request(h.admin, "PATCH", "/organizations/"+org, input, 200)
	p2ScopeIDs(t, p2Items(t, h.request(manager, "GET", "/assets", nil, 200)))
	p2ScopeIDs(t, p2Items(t, h.request(manager, "GET", "/organizations/options", nil, 200)))
	// Removing organization membership must not revoke separately issued scopes.
	h.request(reader, "GET", "/assets/"+h.asset, nil, 200)
	h.request(reader, "GET", "/accounts/"+h.account, nil, 200)
	h.request(auditor, "GET", "/assets/"+h.asset, nil, 200)
	h.request(h.admin, "DELETE", "/grants/"+grant, nil, 200)
	groupInput["version"], groupInput["enabled"] = 1, false
	h.request(h.admin, "PATCH", "/asset-groups/"+group, groupInput, 200)
	for _, user := range []testUser{reader, auditor} {
		h.request(user, "GET", "/assets/"+h.asset, nil, 404)
		_, exported := p2ScopeCSV(h, user, "")
		if len(exported) != 0 {
			t.Fatalf("revoked organization retained CSV visibility: %v", exported)
		}
	}
}

func TestIntegrationOrganizationsHierarchyAndValidation(t *testing.T) {
	h := newHarness(t)
	reader := h.user("parent-reader", "operator")
	person := p2CreatePerson(h, "Hierarchy owner")
	parentInput := p2OrganizationInput("Parent", "", reader.id)
	parent := h.request(h.admin, "POST", "/organizations", parentInput, 200)["id"].(string)
	childInput := p2OrganizationInput("Child", parent)
	child := h.request(h.admin, "POST", "/organizations", childInput, 200)["id"].(string)
	root := h.request(h.admin, "POST", "/organizations", p2OrganizationInput("Other root", ""), 200)["id"].(string)
	assetInput := p2AssetInput("Child inventory", p2Ownership("assigned", person))
	assetInput["organizationId"] = child
	asset := h.request(h.admin, "POST", "/assets", assetInput, 200)["id"].(string)
	h.request(reader, "GET", "/assets/"+asset, nil, 404)
	if got := p2OrganizationRow(h, child); got["parent_id"] != parent || got["version"] != float64(1) {
		t.Fatalf("hierarchy did not round trip: %v", got)
	}
	parentInput["parentId"], parentInput["version"] = child, 1
	if got := h.request(h.admin, "PATCH", "/organizations/"+parent, parentInput, 400); got["code"] != "organization_cycle" {
		t.Fatalf("ancestor cycle must be rejected: %v", got)
	}
	parentInput["parentId"] = parent
	h.request(h.admin, "PATCH", "/organizations/"+parent, parentInput, 400)
	if got := p2OrganizationRow(h, parent); got["version"] != float64(1) || got["parent_id"] != "" {
		t.Fatalf("failed cycle changed organization: %v", got)
	}
	childInput["version"], childInput["parentId"], childInput["memberIds"] = 1, root, []string{reader.id}
	h.request(h.admin, "PATCH", "/organizations/"+child, childInput, 200)
	h.request(reader, "GET", "/assets/"+asset, nil, 200)
	rootInput := p2OrganizationInput("Other root", "")
	rootInput["version"], rootInput["enabled"] = 1, false
	h.request(h.admin, "PATCH", "/organizations/"+root, rootInput, 200)
	// Disabled ancestors do not silently revoke direct child membership.
	h.request(reader, "GET", "/assets/"+asset, nil, 200)
	childInput["version"] = 2
	delete(childInput, "parentId")
	h.request(h.admin, "PATCH", "/organizations/"+child, childInput, 200)
	if got := p2OrganizationRow(h, child); got["parent_id"] != root {
		t.Fatalf("omitted parent must preserve reparenting: %v", got)
	}
	childInput["version"], childInput["enabled"] = 3, false
	h.request(h.admin, "PATCH", "/organizations/"+child, childInput, 200)
	h.request(reader, "GET", "/assets/"+asset, nil, 404)
	before := p2OrganizationRow(h, child)
	h.request(h.admin, "PATCH", "/organizations/"+child, childInput, 409)
	p2EqualJSON(t, p2OrganizationRow(h, child), before)
	childInput["version"] = 0
	h.request(h.admin, "PATCH", "/organizations/"+child, childInput, 400)
	h.request(h.admin, "POST", "/organizations", p2OrganizationInput("Parent", ""), 409)
	h.request(h.admin, "POST", "/organizations", p2OrganizationInput("Contact is not a login", "", person), 400)
	h.request(h.admin, "POST", "/organizations", p2OrganizationInput("Duplicate members", "", reader.id, reader.id), 400)
	many := make([]string, 501)
	for i := range many {
		many[i] = ID()
	}
	h.request(h.admin, "POST", "/organizations", p2OrganizationInput("Too many members", "", many...), 400)
	h.request(h.admin, "GET", "/organizations?offset=-1", nil, 400)
	h.request(h.admin, "GET", "/organizations/options?offset=invalid", nil, 400)
	p2ScopeIDs(t, p2Items(t, h.request(h.admin, "GET", "/organizations?offset=3", nil, 200)))
	childInput["version"], childInput["enabled"], childInput["parentId"] = 4, true, ""
	h.request(h.admin, "PATCH", "/organizations/"+child, childInput, 200)
	if got := p2OrganizationRow(h, child); got["parent_id"] != "" {
		t.Fatalf("explicit empty parent did not detach child: %v", got)
	}
}

func TestIntegrationOrganizationsWorkspaceAndAssignmentRollback(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	manager := h.user("organization-owner", "asset_manager")
	person := p2CreatePerson(h, "Assignment owner")
	input := p2OrganizationInput("Manager organization", "", manager.id)
	org := h.request(h.admin, "POST", "/organizations", input, 200)["id"].(string)
	other := h.request(h.admin, "POST", "/organizations", p2OrganizationInput("Unrelated organization", ""), 200)["id"].(string)
	foreignWorkspace, foreignUser, foreignOrg := ID(), ID(), ID()
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) SELECT $1,$2,'foreign-org','Foreign organization admin',password_hash,'admin' FROM ra_users WHERE id=$3`, foreignUser, foreignWorkspace, h.admin.id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.a.DB.Exec(ctx, `INSERT INTO ra_organizations(id,workspace,name,created_by) VALUES($1,$2,'Foreign organization',$3)`, foreignOrg, foreignWorkspace, foreignUser); err != nil {
		t.Fatal(err)
	}
	before := p2OrganizationRow(h, org)
	for _, bad := range []map[string]any{
		p2OrganizationInput("Forged member", "", foreignUser),
		p2OrganizationInput("Forged parent", foreignOrg, manager.id),
	} {
		bad["version"] = 1
		h.request(h.admin, "PATCH", "/organizations/"+org, bad, 400)
		p2EqualJSON(t, p2OrganizationRow(h, org), before)
	}
	foreignInput := p2OrganizationInput("Foreign mutation", "", h.admin.id)
	foreignInput["version"] = 1
	h.request(h.admin, "PATCH", "/organizations/"+foreignOrg, foreignInput, 404)
	p2ScopeIDs(t, p2Items(t, h.request(h.admin, "GET", "/organizations", nil, 200)), org, other)
	p2ScopeIDs(t, p2Items(t, h.request(manager, "GET", "/organizations/options", nil, 200)), org)
	assetInput := p2AssetInput("Manager owned asset", p2Ownership("assigned", person))
	assetInput["organizationId"] = org
	asset := h.request(manager, "POST", "/assets", assetInput, 200)["id"].(string)
	assetBefore := h.request(manager, "GET", "/assets/"+asset, nil, 200)
	assetInput["version"], assetInput["organizationId"], assetInput["name"] = assetBefore["version"], other, "Must roll back"
	h.request(manager, "PATCH", "/assets/"+asset, assetInput, 403)
	p2EqualJSON(t, h.request(manager, "GET", "/assets/"+asset, nil, 200), assetBefore)
	assetInput["organizationId"] = foreignOrg
	h.request(h.admin, "PATCH", "/assets/"+asset, assetInput, 400)
	p2EqualJSON(t, h.request(manager, "GET", "/assets/"+asset, nil, 200), assetBefore)
	// The composite FK also protects scope from accidental raw SQL assignments.
	if _, err := h.a.DB.Exec(ctx, `UPDATE ra_assets SET organization_id=$1 WHERE workspace=$2 AND id=$3`, foreignOrg, h.a.Config.Workspace, asset); err == nil {
		t.Fatal("cross-workspace asset organization bypassed the database constraint")
	}
	input["version"], input["memberIds"], input["enabled"] = 1, []string{}, false
	h.request(h.admin, "PATCH", "/organizations/"+org, input, 200)
	assetInput["organizationId"] = org
	h.request(manager, "PATCH", "/assets/"+asset, assetInput, 400)
	h.request(h.admin, "POST", "/assets", assetInput, 400)
	// Creator management remains independent, and omitted assignments preserve
	// disabled organizations without blocking unrelated asset maintenance.
	delete(assetInput, "organizationId")
	assetInput["name"] = "Retained disabled organization"
	h.request(manager, "PATCH", "/assets/"+asset, assetInput, 200)
	updated := h.request(manager, "GET", "/assets/"+asset, nil, 200)
	if updated["organization_id"] != org || updated["canManage"] != true {
		t.Fatalf("unrelated asset edit lost assignment or creator scope: %v", updated)
	}
	assetInput["version"], assetInput["organizationId"] = updated["version"], ""
	h.request(manager, "PATCH", "/assets/"+asset, assetInput, 200)
	if got := h.request(manager, "GET", "/assets/"+asset, nil, 200); got["organization_id"] != "" && got["organization_id"] != nil {
		t.Fatalf("explicit empty organization did not clear assignment: %v", got)
	}
	var auditCount int
	if err := h.a.DB.QueryRow(ctx, `SELECT count(*) FROM ra_audit_events WHERE workspace=$1 AND action='organization.save'`, h.a.Config.Workspace).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("failed organization writes must not leave audit successes: %d %v", auditCount, err)
	}
}
