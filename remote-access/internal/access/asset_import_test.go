package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func p2ImportPreview(h *harness, u testUser, claimant, csv string) map[string]any {
	h.t.Helper()
	return p2ScopeJSON(h, u, "POST", "/api/v1/asset-imports/preview", map[string]any{"csv": csv, "claimantId": claimant}, 200)
}

func p2ImportRows(t *testing.T, job map[string]any, states ...string) []map[string]any {
	t.Helper()
	raw, ok := job["rows"].([]any)
	if !ok || len(raw) != len(states) {
		t.Fatalf("expected %d import rows, got %v", len(states), job)
	}
	rows := make([]map[string]any, len(raw))
	for i, item := range raw {
		row, ok := item.(map[string]any)
		if !ok || row["rowNumber"] != float64(i+1) || row["state"] != states[i] {
			t.Fatalf("row %d: want state %s and stable data-row number, got %v", i+1, states[i], item)
		}
		rows[i] = row
	}
	return rows
}

func p2ImportConfirm(h *harness, u testUser, job string, numbers ...int) map[string]any {
	h.t.Helper()
	return p2ScopeJSON(h, u, "POST", "/api/v1/asset-imports/"+job+"/confirm", map[string]any{"confirm": true, "rowNumbers": numbers}, 200)
}

func p2ImportAssetCount(h *harness, want int) {
	h.t.Helper()
	var count int
	if err := h.a.DB.QueryRow(context.Background(), "SELECT count(*) FROM ra_assets WHERE workspace=$1", h.a.Config.Workspace).Scan(&count); err != nil {
		h.t.Fatal(err)
	}
	if count != want {
		h.t.Fatalf("workspace asset count: got %d, want %d", count, want)
	}
}

func TestIntegrationAssetImportPreviewValidation(t *testing.T) {
	h := newHarness(t)
	person := p2CreatePerson(h, "\u5f20\u4e09")
	input := p2AssetInput("Existing inventory", p2Ownership("pending", person))
	input["inventoryId"] = "existing-01"
	h.request(h.admin, "POST", "/assets", input, 200)
	job := p2ImportPreview(h, h.admin, person, "inventoryId,name,category,kind,osFamily,site\nexisting-01,Existing,server,physical,linux,Room A\nfresh-01,\u4e2d\u6587\u8bbe\u5907,nas,virtual,linux,\u673a\u623f\n fresh-01 ,Repeated,nas,physical,other,Room B\nbad-01,Bad category,router,physical,linux,Room C\nbad-02,,server,physical,linux,Room D\n")
	rows := p2ImportRows(t, job, "duplicate", "ready", "duplicate", "invalid", "invalid")
	if job["source"] != "csv" || job["state"] != "preview" || job["counts"] == nil || job["expiresAt"] == nil {
		t.Fatalf("preview must expose truthful source, state, counts and expiry: %v", job)
	}
	if rows[1]["inventoryId"] != "fresh-01" || rows[1]["name"] != "\u4e2d\u6587\u8bbe\u5907" {
		t.Fatalf("CSV identity/name did not round-trip: %v", rows[1])
	}
	for _, n := range []int{0, 2, 3, 4} {
		if rows[n]["message"] == "" || rows[n]["message"] == nil {
			t.Fatalf("rejected row needs an actionable diagnostic: %v", rows[n])
		}
	}
	p2ImportAssetCount(h, 1)
	for _, csv := range []string{
		"name\nMissing identity\n", "inventoryId\nMissing name\n", "inventoryId,name\nx,\"unterminated\n",
		"inventoryId,name\nx," + strings.Repeat("x", 512<<10),
		"inventoryId,name\n" + strings.Repeat("x,Too many\n", 201),
	} {
		p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/preview", map[string]any{"csv": csv, "claimantId": person}, 400)
	}
	for _, claimant := range []string{"", ID()} {
		p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/preview", map[string]any{"csv": "inventoryId,name\nx,Valid\n", "claimantId": claimant}, 400)
	}
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/preview", map[string]any{"csv": "inventoryId,name\nx,Valid\n", "claimantId": person, "autoConfirm": true}, 400)
	path := "/api/v1/asset-imports/" + job["id"].(string) + "/confirm"
	for _, selection := range [][]int{{}, {0}, {6}, {4}, {1}} {
		p2ScopeJSON(h, h.admin, "POST", path, map[string]any{"confirm": true, "rowNumbers": selection}, 400)
	}
	p2ImportAssetCount(h, 1)
}

func TestIntegrationAssetImportConfirmationScopesAndProvenance(t *testing.T) {
	h := newHarness(t)
	manager := h.user("import-manager", "asset_manager")
	other := h.user("import-other-manager", "asset_manager")
	reader := h.user("import-reader", "operator")
	person := p2CreatePerson(h, "Import claimant")
	job := p2ImportPreview(h, manager, person, "inventoryId,name,category,kind,osFamily,environment,site,business,description\nimport-01,Imported NAS,nas,virtual,linux,production,Room A,Storage,Recorded by operator\n")
	id := job["id"].(string)
	p2ScopeJSON(h, reader, "POST", "/api/v1/asset-imports/preview", map[string]any{"csv": "inventoryId,name\nreader,Forbidden\n", "claimantId": person}, 403)
	p2ScopeJSON(h, other, "GET", "/api/v1/asset-imports/"+id, nil, 404)
	p2ScopeJSON(h, other, "POST", "/api/v1/asset-imports/"+id+"/confirm", map[string]any{"confirm": true, "rowNumbers": []int{1}}, 404)
	p2ScopeJSON(h, other, "POST", "/api/v1/asset-imports/"+id+"/cancel", map[string]any{"confirm": true}, 404)
	p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, other, "GET", "/api/v1/asset-imports", nil, 200)))
	p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, manager, "GET", "/api/v1/asset-imports", nil, 200)), id)
	p2ScopeJSON(h, h.admin, "GET", "/api/v1/asset-imports/"+id, nil, 200)
	missingCSRF := manager
	missingCSRF.csrf = ""
	p2ScopeJSON(h, missingCSRF, "POST", "/api/v1/asset-imports/"+id+"/confirm", map[string]any{"confirm": true, "rowNumbers": []int{1}}, 403)
	p2ScopeJSON(h, manager, "POST", "/api/v1/asset-imports/"+id+"/confirm", map[string]any{"confirm": false, "rowNumbers": []int{1}}, 400)
	p2ImportAssetCount(h, 0)
	confirmed := p2ImportConfirm(h, manager, id, 1)
	rows := p2ImportRows(t, confirmed, "created")
	assetID, ok := rows[0]["assetId"].(string)
	if !ok || assetID == "" {
		t.Fatalf("created row lacks its persistent asset identity: %v", rows[0])
	}
	asset := h.request(manager, "GET", "/assets/"+assetID, nil, 200)
	for key, want := range map[string]any{"inventory_id": "import-01", "name": "Imported NAS", "category": "nas", "kind": "virtual", "os_family": "linux", "environment": "production", "site": "Room A", "business": "Storage", "description": "Recorded by operator", "canManage": true, "ownershipLegacy": false} {
		if asset[key] != want {
			t.Fatalf("imported asset field %s: got %v, want %v", key, asset[key], want)
		}
	}
	p2EqualJSON(t, asset["ownership"], p2Ownership("pending", person))
	p2EqualJSON(t, asset["endpoints"], []any{})
	var source, sourceJob, creator string
	var observed time.Time
	if err := h.a.DB.QueryRow(context.Background(), `SELECT o.source_kind,o.source_job_id,o.observed_at,a.created_by FROM ra_asset_origins o JOIN ra_assets a ON a.id=o.asset_id AND a.workspace=o.workspace WHERE o.workspace=$1 AND o.asset_id=$2`, h.a.Config.Workspace, assetID).Scan(&source, &sourceJob, &observed, &creator); err != nil {
		t.Fatal(err)
	}
	if source != "csv" || sourceJob != id || observed.IsZero() || creator != manager.id {
		t.Fatalf("import provenance mismatch: source=%s job=%s observed=%s creator=%s", source, sourceJob, observed, creator)
	}
	replayed := p2ImportRows(t, p2ImportConfirm(h, manager, id, 1), "created")
	if replayed[0]["assetId"] != assetID {
		t.Fatal("confirmation replay changed the asset identity")
	}
	p2ImportAssetCount(h, 1)
	var revisions int
	if err := h.a.DB.QueryRow(context.Background(), "SELECT count(*) FROM ra_asset_ownership_history WHERE asset_id=$1", assetID).Scan(&revisions); err != nil || revisions != 1 {
		t.Fatalf("idempotent replay wrote extra ownership history: count=%d error=%v", revisions, err)
	}
	p2ScopeJSON(h, manager, "POST", "/api/v1/asset-imports/"+id+"/cancel", map[string]any{"confirm": true}, 409)
	h.request(reader, "GET", "/assets/"+assetID, nil, 404)
}

func TestIntegrationAssetImportConcurrentIdentityAndPartialCommit(t *testing.T) {
	h := newHarness(t)
	person := p2CreatePerson(h, "Concurrent claimant")
	jobs := []map[string]any{
		p2ImportPreview(h, h.admin, person, "inventoryId,name\nconcurrent-shared,Shared A\nconcurrent-a,Only A\n"),
		p2ImportPreview(h, h.admin, person, "inventoryId,name\nconcurrent-shared,Shared B\nconcurrent-b,Only B\n"),
	}
	type outcome struct {
		job map[string]any
		err error
	}
	results := make(chan outcome, len(jobs))
	start := make(chan struct{})
	for _, job := range jobs {
		go func(id string) {
			<-start
			request, err := http.NewRequest("POST", h.server.URL+"/api/v1/asset-imports/"+id+"/confirm", bytes.NewReader(marshal(map[string]any{"confirm": true, "rowNumbers": []int{1, 2}})))
			if err != nil {
				results <- outcome{err: err}
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", h.server.URL)
			request.Header.Set("X-CSRF-Token", h.admin.csrf)
			response, err := h.admin.client.Do(request)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			if response.StatusCode != 200 {
				results <- outcome{err: fmt.Errorf("confirm status %d: %s", response.StatusCode, raw)}
				return
			}
			var out map[string]any
			err = json.Unmarshal(raw, &out)
			results <- outcome{job: out, err: err}
		}(job["id"].(string))
	}
	close(start)
	created, duplicates := 0, 0
	for range jobs {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		raw, ok := result.job["rows"].([]any)
		if !ok || len(raw) != 2 {
			t.Fatalf("concurrent confirmation lost rows: %v", result.job)
		}
		first := raw[0].(map[string]any)
		switch first["state"] {
		case "created":
			created++
		case "duplicate":
			duplicates++
		default:
			t.Fatalf("shared identity must create exactly once or report duplicate: %v", result.job)
		}
		if row := raw[1].(map[string]any); row["state"] != "created" || row["assetId"] == nil || row["assetId"] == "" {
			t.Fatalf("duplicate must not roll back an unrelated valid row: %v", row)
		}
	}
	if created != 1 || duplicates != 1 {
		t.Fatalf("concurrent inventory identity was not serialized: created=%d duplicates=%d", created, duplicates)
	}
	p2ImportAssetCount(h, 3)
	var uniqueInventory, origins int
	if err := h.a.DB.QueryRow(context.Background(), "SELECT count(DISTINCT inventory_id) FROM ra_assets WHERE workspace=$1", h.a.Config.Workspace).Scan(&uniqueInventory); err != nil {
		t.Fatal(err)
	}
	if err := h.a.DB.QueryRow(context.Background(), "SELECT count(*) FROM ra_asset_origins WHERE workspace=$1", h.a.Config.Workspace).Scan(&origins); err != nil {
		t.Fatal(err)
	}
	if uniqueInventory != 3 || origins != 3 {
		t.Fatalf("assets and source records diverged: uniqueInventory=%d origins=%d", uniqueInventory, origins)
	}
	for _, job := range jobs {
		p2ImportConfirm(h, h.admin, job["id"].(string), 2)
	}
	p2ImportAssetCount(h, 3)
}

func TestIntegrationAssetImportClaimantRevalidationAndRetry(t *testing.T) {
	h := newHarness(t)
	person := p2CreatePerson(h, "Claimant before confirmation")
	job := p2ImportPreview(h, h.admin, person, "inventoryId,name\nclaimant-01,Requires active claimant\n")
	id := job["id"].(string)
	edit := p2PersonInput("Claimant before confirmation")
	edit["enabled"], edit["version"] = false, 1
	h.request(h.admin, "PATCH", "/people/"+person, edit, 200)
	failed := p2ImportRows(t, p2ImportConfirm(h, h.admin, id, 1), "failed")
	if failed[0]["message"] == nil || failed[0]["message"] == "" {
		t.Fatal("disabled claimant needs an explicit row failure")
	}
	p2ImportAssetCount(h, 0)
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/preview", map[string]any{"csv": "inventoryId,name\nclaimant-02,Disabled\n", "claimantId": person}, 400)
	edit["enabled"], edit["version"] = true, 2
	h.request(h.admin, "PATCH", "/people/"+person, edit, 200)
	rows := p2ImportRows(t, p2ImportConfirm(h, h.admin, id, 1), "created")
	asset := h.request(h.admin, "GET", "/assets/"+rows[0]["assetId"].(string), nil, 200)
	p2EqualJSON(t, asset["ownership"], p2Ownership("pending", person))
	p2ImportAssetCount(h, 1)
}

func TestIntegrationAssetImportExpiryCancellationAndWorkspace(t *testing.T) {
	h := newHarness(t)
	person := p2CreatePerson(h, "Lifecycle claimant")
	job := p2ImportPreview(h, h.admin, person, "inventoryId,name\nlife-01,Selected\nlife-02,Not selected\n")
	id := job["id"].(string)
	partial := p2ImportRows(t, p2ImportConfirm(h, h.admin, id, 1), "created", "ready")
	assetID := partial[0]["assetId"].(string)
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/"+id+"/cancel", map[string]any{"confirm": false}, 400)
	cancelled := p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/"+id+"/cancel", map[string]any{"confirm": true}, 200)
	if cancelled["state"] != "cancelled" {
		t.Fatalf("cancellation must be persisted: %v", cancelled)
	}
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/"+id+"/confirm", map[string]any{"confirm": true, "rowNumbers": []int{2}}, 409)
	h.request(h.admin, "GET", "/assets/"+assetID, nil, 200)
	p2ImportAssetCount(h, 1)
	expiring := p2ImportPreview(h, h.admin, person, "inventoryId,name\nexpire-01,Expired preview\n")
	expiringID := expiring["id"].(string)
	if _, err := h.a.DB.Exec(context.Background(), "UPDATE ra_asset_import_jobs SET expires_at=now()-interval '1 second' WHERE workspace=$1 AND id=$2", h.a.Config.Workspace, expiringID); err != nil {
		t.Fatal(err)
	}
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/"+expiringID+"/confirm", map[string]any{"confirm": true, "rowNumbers": []int{1}}, 410)
	p2ImportAssetCount(h, 1)
	foreign := newHarness(t)
	foreignPerson := p2CreatePerson(foreign, "Foreign claimant")
	foreignJob := p2ImportPreview(foreign, foreign.admin, foreignPerson, "inventoryId,name\nforeign-01,Foreign asset\n")
	foreignID := foreignJob["id"].(string)
	p2ScopeJSON(h, h.admin, "GET", "/api/v1/asset-imports/"+foreignID, nil, 404)
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/"+foreignID+"/confirm", map[string]any{"confirm": true, "rowNumbers": []int{1}}, 404)
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/"+foreignID+"/cancel", map[string]any{"confirm": true}, 404)
	p2ScopeJSON(h, h.admin, "POST", "/api/v1/asset-imports/preview", map[string]any{"csv": "inventoryId,name\nx,Wrong workspace\n", "claimantId": foreignPerson}, 400)
	p2ScopeIDs(t, p2Items(t, p2ScopeJSON(h, h.admin, "GET", "/api/v1/asset-imports", nil, 200)), id, expiringID)
	p2ImportAssetCount(foreign, 0)
}

func TestIntegrationLocalDiscoveryObservesHostBeforeConfirmation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatal("local discovery acceptance requires the real Linux/WSL execution host")
	}
	h := newHarness(t)
	person := p2CreatePerson(h, "Local host claimant")
	reader := h.user("discovery-reader", "operator")
	path := "/api/v1/discovery/local-preview"
	p2ScopeJSON(h, reader, "POST", path, map[string]any{"claimantId": person}, 403)
	for _, forbidden := range []string{"host", "url", "command"} {
		p2ScopeJSON(h, h.admin, "POST", path, map[string]any{"claimantId": person, forbidden: "arbitrary-target"}, 400)
	}
	// Discovery currently has evidence for WSL classification only. Other Linux
	// hosts must reject without creating inventory, rather than guess a kind.
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(kernel)), "microsoft") {
		response := p2ScopeJSON(h, h.admin, "POST", path, map[string]any{"claimantId": person}, 501)
		if response["code"] != "discovery_classification_unverified" {
			t.Fatalf("wrong discovery rejection: %v", response)
		}
		p2ImportAssetCount(h, 0)
		return
	}
	started := time.Now().Add(-time.Second)
	job := p2ScopeJSON(h, h.admin, "POST", path, map[string]any{"claimantId": person}, 200)
	rows := p2ImportRows(t, job, "ready")
	if job["source"] != "local_discovery" || job["state"] != "preview" {
		t.Fatalf("local discovery source/state is not truthful: %v", job)
	}
	facts, ok := job["facts"].(map[string]any)
	if !ok {
		t.Fatalf("discovery must expose observed facts, not just a fabricated inventory row: %v", job)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if facts["hostname"] != hostname {
		t.Fatalf("discovery did not read this host: got %v, actual %s", facts["hostname"], hostname)
	}
	for _, field := range []string{"interfaces", "mounts"} {
		observations, ok := facts[field].([]any)
		if !ok || len(observations) == 0 {
			t.Fatalf("Linux host discovery missing observed %s: %v", field, facts)
		}
	}
	stamp, ok := facts["observedAt"].(string)
	observed, err := time.Parse(time.RFC3339Nano, stamp)
	if !ok || err != nil || observed.Before(started) || observed.After(time.Now().Add(time.Second)) {
		t.Fatalf("discovery timestamp must belong to this execution: value=%v error=%v", facts["observedAt"], err)
	}
	p2ImportAssetCount(h, 0)
	id := job["id"].(string)
	created := p2ImportRows(t, p2ImportConfirm(h, h.admin, id, 1), "created")
	assetID := created[0]["assetId"].(string)
	asset := h.request(h.admin, "GET", "/assets/"+assetID, nil, 200)
	if asset["inventory_id"] != rows[0]["inventoryId"] {
		t.Fatalf("confirmation lost the discovered identity: %v", asset)
	}
	p2EqualJSON(t, asset["ownership"], p2Ownership("pending", person))
	p2EqualJSON(t, asset["endpoints"], []any{})
	var source, sourceJob string
	var stored []byte
	var storedObserved time.Time
	if err := h.a.DB.QueryRow(context.Background(), "SELECT source_kind,source_job_id,facts,observed_at FROM ra_asset_origins WHERE workspace=$1 AND asset_id=$2", h.a.Config.Workspace, assetID).Scan(&source, &sourceJob, &stored, &storedObserved); err != nil {
		t.Fatal(err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(stored, &persisted); err != nil {
		t.Fatal(err)
	}
	if source != "local_discovery" || sourceJob != id {
		t.Fatalf("discovered asset provenance was not retained: source=%s job=%s", source, sourceJob)
	}
	p2EqualJSON(t, persisted, facts)
	if difference := storedObserved.Sub(observed); difference > time.Microsecond || difference < -time.Microsecond {
		t.Fatalf("provenance time is not the actual observation time: got %v observed %v", storedObserved, observed)
	}
	p2ImportAssetCount(h, 1)
	duplicate := p2ScopeJSON(h, h.admin, "POST", path, map[string]any{"claimantId": person}, 200)
	p2ImportRows(t, duplicate, "duplicate")
	p2ImportAssetCount(h, 1)
}
