package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

func assetEdit(h *harness, version int64, name string) map[string]any {
	return map[string]any{
		"version": version, "name": name, "kind": "virtual", "osFamily": "linux",
		"groupName": "isolated-tests", "tags": []string{}, "metadata": map[string]string{}, "enabled": true,
		"endpoints": []map[string]any{{"protocol": "ssh", "host": h.host, "port": h.port, "gatewayId": h.a.Config.GatewayID}},
	}
}

func TestIntegrationAssetVersionConflict(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	before := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	version := int64(before["version"].(float64))
	h.request(h.admin, "PATCH", "/assets/"+h.asset, assetEdit(h, version, "First editor"), 200)
	conflict := h.request(h.admin, "PATCH", "/assets/"+h.asset, assetEdit(h, version, "Stale editor"), 409)
	if conflict["code"] != "asset_version_conflict" {
		t.Fatalf("unexpected conflict response: %v", conflict)
	}
	after := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	if after["name"] != "First editor" || int64(after["version"].(float64)) != version+1 {
		t.Fatal("stale edit changed the stored asset", after)
	}
	missing := assetEdit(h, 0, "Missing version")
	delete(missing, "version")
	h.request(h.admin, "PATCH", "/assets/"+h.asset, missing, 400)
	h.request(h.admin, "PATCH", "/assets/"+h.asset, assetEdit(h, version+1, "Refreshed editor"), 200)
	var count int
	if err := h.a.DB.QueryRow(context.Background(), "SELECT count(*) FROM ra_audit_events WHERE workspace=$1 AND object_id=$2 AND action='asset.save'", h.a.Config.Workspace, h.asset).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("only creation and two accepted edits should be audited as saved; got %d", count)
	}
}

func TestIntegrationConcurrentAssetVersion(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	var wg sync.WaitGroup
	results := make(chan int, 2)
	errors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := json.Marshal(assetEdit(h, 1, "Concurrent editor"))
			if err != nil {
				errors <- err
				return
			}
			request, err := http.NewRequest("PATCH", h.server.URL+"/api/remote-access/assets/"+h.asset, bytes.NewReader(body))
			if err != nil {
				errors <- err
				return
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", h.server.URL)
			request.Header.Set("X-CSRF-Token", h.admin.csrf)
			response, err := h.admin.client.Do(request)
			if err != nil {
				errors <- err
				return
			}
			defer response.Body.Close()
			results <- response.StatusCode
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	statusCounts := map[int]int{}
	for status := range results {
		statusCounts[status]++
	}
	if statusCounts[200] != 1 || statusCounts[409] != 1 {
		t.Fatalf("expected one accepted edit and one conflict, got %v", statusCounts)
	}
	after := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	if after["version"].(float64) != 2 || after["name"] != "Concurrent editor" {
		t.Fatalf("unexpected concurrent edit result: %v", after)
	}
}
