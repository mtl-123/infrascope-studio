package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationAssetImportReversedConcurrentRows(t *testing.T) {
	h := newHarness(t)
	person := p2CreatePerson(h, "Reverse-order claimant")
	jobs := []map[string]any{
		p2ImportPreview(h, h.admin, person, "inventoryId,name\nreverse-a,Asset A\nreverse-b,Asset B\n"),
		p2ImportPreview(h, h.admin, person, "inventoryId,name\nreverse-b,Asset B\nreverse-a,Asset A\n"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	gate, err := pgx.Connect(ctx, h.a.Config.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close(context.Background())
	var gateKey int32
	if err = gate.QueryRow(ctx, "SELECT hashtext($1) & 2147483647", h.a.Config.Workspace).Scan(&gateKey); err != nil {
		t.Fatal(err)
	}
	function := pgx.Identifier{"p2_import_gate_" + digest(h.a.Config.Workspace)[:16]}.Sanitize()
	trigger := pgx.Identifier{"p2_import_gate_" + digest(h.a.Config.Workspace)[:16]}.Sanitize()
	// A database gate holds the first unique insertion of each transaction. With
	// opposite input ordering both acquire different identities before advancing;
	// stable server-side ordering instead leaves the second waiting on the first.
	definition := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock_shared(%d,43210); RETURN NEW; END $$;
CREATE TRIGGER %s AFTER INSERT ON ra_assets FOR EACH ROW WHEN (NEW.workspace='%s') EXECUTE FUNCTION %s()`, function, gateKey, trigger, h.a.Config.Workspace, function)
	if _, err = gate.Exec(ctx, definition); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := h.a.DB.Exec(cleanupCtx, "DROP TRIGGER IF EXISTS "+trigger+" ON ra_assets; DROP FUNCTION IF EXISTS "+function+"()"); err != nil {
			t.Errorf("remove isolated import gate: %v", err)
		}
	})
	if _, err = gate.Exec(ctx, "SELECT pg_advisory_lock($1,43210)", gateKey); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		status int
		raw    []byte
		err    error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	for _, job := range jobs {
		go func(id string) {
			<-start
			request, err := http.NewRequestWithContext(ctx, "POST", h.server.URL+"/api/v1/asset-imports/"+id+"/confirm", bytes.NewReader(marshal(map[string]any{"confirm": true, "rowNumbers": []int{1, 2}})))
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
			results <- outcome{status: response.StatusCode, raw: raw, err: err}
		}(job["id"].(string))
	}
	close(start)
	waiters := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err = gate.QueryRow(ctx, "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=$1::oid AND objid=43210 AND NOT granted", gateKey).Scan(&waiters); err != nil {
			break
		}
		if waiters == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, unlockErr := gate.Exec(ctx, "SELECT pg_advisory_unlock($1,43210)", gateKey)
	// Drain both goroutines even when one fails so no request outlives its fixture.
	responses := []outcome{<-results, <-results}
	if err != nil || unlockErr != nil || waiters == 0 {
		t.Fatalf("database gate did not exercise concurrent inserts: waiters=%d query=%v unlock=%v", waiters, err, unlockErr)
	}
	created, duplicates := 0, 0
	for _, result := range responses {
		if result.err != nil || result.status != 200 {
			t.Fatalf("reverse-order jobs must not deadlock or roll back: status=%d error=%v response=%s", result.status, result.err, result.raw)
		}
		var job map[string]any
		if err := json.Unmarshal(result.raw, &job); err != nil {
			t.Fatal(err)
		}
		rows, ok := job["rows"].([]any)
		if !ok || len(rows) != 2 {
			t.Fatalf("confirmation lost original rows: %v", job)
		}
		for index, raw := range rows {
			row := raw.(map[string]any)
			if row["rowNumber"] != float64(index+1) {
				t.Fatalf("lock ordering changed displayed CSV row numbers: %v", rows)
			}
			switch row["state"] {
			case "created":
				created++
			case "duplicate":
				duplicates++
			default:
				t.Fatalf("unexpected concurrent confirmation outcome: %v", row)
			}
		}
	}
	if created != 2 || duplicates != 2 {
		t.Fatalf("reverse-order jobs must create each identity exactly once: created=%d duplicates=%d", created, duplicates)
	}
	p2ImportAssetCount(h, 2)
}

func TestIntegrationAssetImportPreservesClaimantDatabaseErrors(t *testing.T) {
	h := newHarness(t)
	person := p2CreatePerson(h, "Locked claimant")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	blocker, err := h.a.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err = blocker.Exec(ctx, "SELECT id FROM ra_people WHERE workspace=$1 AND id=$2 FOR UPDATE", h.a.Config.Workspace, person); err != nil {
		t.Fatal(err)
	}
	tx, err := h.a.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout='80ms'"); err != nil {
		t.Fatal(err)
	}
	in := AssetInput{Name: "Do not misreport database failure", Kind: "physical", OS: "linux", Inventory: "claimant-lock-error", Enabled: true, Tags: []string{}, Metadata: map[string]string{}, Endpoints: []Endpoint{}, Ownership: &Ownership{State: "pending", ClaimantID: person, NotificationIDs: []string{}, BackupIDs: []string{}}}
	u := &User{ID: h.admin.id, Workspace: h.a.Config.Workspace, Role: "admin"}
	_, err = h.a.saveAsset(ctx, tx, u, "", in)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("real database lock error must propagate, not become a claimant-validation 400: got %T %v", err, err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	p2ImportAssetCount(h, 0)
}
