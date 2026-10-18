package access

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"infrascope/remote-access/migrations"
)

func TestIntegrationPeopleAssetsMigration(t *testing.T) {
	databaseURL := os.Getenv("INFRA_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("INFRA_TEST_DATABASE_URL not provided; migration test requires isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = "pg_catalog"
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })

	// A private search_path exercises a real 001 database without touching shared tables.
	schema := "p2_migration_" + strings.ToLower(ID())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("clean up test schema %s: %v", schema, err)
		}
	})
	isolatedConfig := config.Copy()
	isolatedConfig.RuntimeParams["search_path"] = quotedSchema
	db, err := pgx.ConnectConfig(ctx, isolatedConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var currentSchema string
	if err = db.QueryRow(ctx, "SELECT current_schema()").Scan(&currentSchema); err != nil || currentSchema != schema {
		t.Fatalf("unexpected migration schema %q: %v", currentSchema, err)
	}
	applyMigration := func(sql string) {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, sql); err != nil {
			t.Fatal("apply migration:", err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal("prepare migration fixture:", err)
		}
	}
	snapshot := func(query string) string {
		t.Helper()
		var result string
		if err := db.QueryRow(ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(saved) ORDER BY to_jsonb(saved)::text),'[]'::jsonb)::text FROM ("+query+") saved").Scan(&result); err != nil {
			t.Fatal("snapshot migration data:", err)
		}
		return result
	}
	applyMigration(migrations.BaseSQL)
	workspace, userID, assetID, accountID, grantID, endpointID := ID(), ID(), ID(), ID(), ID(), ID()
	hash, err := PasswordHash("migration-platform-password")
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	secret := Secret{Password: "migration-remote-password"}
	aad := workspace + ":" + accountID + ":7"
	ciphertext, nonce, err := seal(key, aad, secret)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role,auth_version) VALUES($1,$2,'legacy-admin','Legacy Admin',$3,'admin',7)`, userID, workspace, hash)
	exec(`INSERT INTO ra_login_sessions(id_hash,workspace,user_id,auth_version,csrf,expires_at) VALUES($1,$2,$3,7,$4,now()+interval '1 hour')`, digest(ID()), workspace, userID, ID())
	exec(`INSERT INTO ra_assets(id,workspace,name,kind,os_family,group_name,tags,description,metadata,version,inventory_id,created_by) VALUES($1,$2,'Legacy asset','virtual','linux','legacy-group','["legacy"]','Keep existing asset','{"provider":"legacy"}',12,'legacy-inventory',$3)`, assetID, workspace, userID)
	exec(`INSERT INTO ra_endpoints(id,workspace,asset_id,protocol,host,port,gateway_id,version) VALUES($1,$2,$3,'ssh','192.0.2.10',2222,'legacy-gateway',3)`, endpointID, workspace, assetID)
	exec(`INSERT INTO ra_host_keys(workspace,endpoint_id,algorithm,fingerprint,approved_by) VALUES($1,$2,'ssh-ed25519','SHA256:legacy-test-fingerprint',$3)`, workspace, endpointID, userID)
	exec(`INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,credential_version,version,created_by) VALUES($1,$2,$3,'Legacy account','legacy-user','password','["ssh"]',7,9,$4)`, accountID, workspace, assetID, userID)
	exec(`INSERT INTO ra_secrets(workspace,account_id,ciphertext,nonce,key_version,version,updated_by) VALUES($1,$2,$3,$4,'legacy-key',7,$5)`, workspace, accountID, ciphertext, nonce, userID)
	exec(`INSERT INTO ra_grants(id,workspace,user_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,version,granted_by) VALUES($1,$2,$3,$4,$5,'["remoteAccount.use","ssh.connect"]','["ssh"]',$6,now()-interval '1 hour',now()+interval '1 day',5,$3)`, grantID, workspace, userID, assetID, accountID, marshal(Limits{MaxFileBytes: 1024, MaxTotalBytes: 4096, MaxFiles: 10, MaxDepth: 4, MaxConcurrent: 1}))

	queries := map[string]string{
		"users":          "SELECT * FROM ra_users",
		"login_sessions": "SELECT * FROM ra_login_sessions",
		"assets":         "SELECT id,workspace,name,kind,os_family,group_name,tags,description,metadata,enabled,archived,version,inventory_id,created_by,created_at,updated_at FROM ra_assets",
		"endpoints":      "SELECT * FROM ra_endpoints",
		"host_keys":      "SELECT * FROM ra_host_keys",
		"accounts":       "SELECT * FROM ra_accounts",
		"secrets":        "SELECT * FROM ra_secrets",
		"grants":         "SELECT * FROM ra_grants",
	}
	before := map[string]string{}
	for name, query := range queries {
		before[name] = snapshot(query)
	}
	for attempt := 0; attempt < 2; attempt++ {
		applyMigration(migrations.PeopleAssetsSQL)
		for name, query := range queries {
			if got := snapshot(query); got != before[name] {
				t.Fatalf("002 execution %d changed existing %s rows", attempt+1, name)
			}
		}
		var legacy bool
		var category, environment, site, business string
		var ownershipJSON []byte
		if err = db.QueryRow(ctx, `SELECT category,environment,site,business,ownership,ownership_legacy FROM ra_assets WHERE id=$1`, assetID).Scan(&category, &environment, &site, &business, &ownershipJSON, &legacy); err != nil {
			t.Fatal(err)
		}
		var ownership Ownership
		if err = json.Unmarshal(ownershipJSON, &ownership); err != nil {
			t.Fatal(err)
		}
		if !legacy || category != "server" || environment != "" || site != "" || business != "" || ownership.State != "pending" || len(ownership.ids()) != 0 {
			t.Fatalf("legacy asset must retain an explicit incomplete responsibility state: legacy=%v category=%q ownership=%s", legacy, category, ownershipJSON)
		}
		if snapshot("SELECT * FROM ra_people") != "[]" || snapshot("SELECT * FROM ra_asset_ownership_history") != "[]" || snapshot("SELECT * FROM ra_asset_responsibility_refs") != "[]" {
			t.Fatal("migration fabricated people or assigned responsibility")
		}
	}
	var storedCiphertext, storedNonce []byte
	if err = db.QueryRow(ctx, "SELECT ciphertext,nonce FROM ra_secrets WHERE account_id=$1", accountID).Scan(&storedCiphertext, &storedNonce); err != nil {
		t.Fatal(err)
	}
	var restored Secret
	if err = unseal(key, storedNonce, storedCiphertext, aad, &restored); err != nil || restored != secret {
		t.Fatal("migration damaged encrypted credential recovery:", err)
	}
	var versions []int32
	if err = db.QueryRow(ctx, "SELECT array_agg(version ORDER BY version) FROM ra_schema_versions").Scan(&versions); err != nil || len(versions) != 2 || versions[0] != 1 || versions[1] != 2 {
		t.Fatalf("unexpected schema versions %v: %v", versions, err)
	}

	personID := ID()
	ownership := Ownership{State: "assigned", UserID: personID, OperationsID: personID, BusinessID: personID, NotificationIDs: []string{personID}, BackupIDs: []string{}}
	peopleSnapshot := marshal([]map[string]any{{"id": personID, "displayName": "Assigned person", "department": "Operations", "source": "manual"}})
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO ra_people(id,workspace,display_name,department,email,contact_type,created_by) VALUES($1,$2,'Assigned person','Operations','assigned@example.test','internal',$3)`, personID, workspace, userID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE ra_assets SET category='nas',environment='staging',site='migration-lab',business='storage',ownership=$1,ownership_legacy=false,version=version+1,updated_at=now() WHERE id=$2`, marshal(ownership), assetID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_asset_responsibility_refs(workspace,asset_id,person_id) VALUES($1,$2,$3)`, workspace, assetID, personID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_asset_ownership_history(workspace,asset_id,revision,ownership,people_snapshot,changed_by) VALUES($1,$2,13,$3,$4,$5)`, workspace, assetID, marshal(ownership), peopleSnapshot, userID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	queries["assets"] = "SELECT * FROM ra_assets"
	queries["people"] = "SELECT * FROM ra_people"
	queries["ownership_history"] = "SELECT * FROM ra_asset_ownership_history"
	queries["responsibility_refs"] = "SELECT * FROM ra_asset_responsibility_refs"
	queries["schema_versions"] = "SELECT * FROM ra_schema_versions"
	for name, query := range queries {
		before[name] = snapshot(query)
	}
	for attempt := 0; attempt < 2; attempt++ {
		applyMigration(migrations.PeopleAssetsSQL)
		for name, query := range queries {
			if got := snapshot(query); got != before[name] {
				t.Fatalf("repeated 002 execution %d changed completed %s rows", attempt+1, name)
			}
		}
	}
}
