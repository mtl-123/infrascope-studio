package access

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"infrascope/remote-access/migrations"
)

func TestIntegrationAssetScopesMigration(t *testing.T) {
	databaseURL := os.Getenv("INFRA_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("INFRA_TEST_DATABASE_URL not provided; migration test requires isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	// Only this randomly named test schema may be created or dropped.
	schema := "p2_scope_migration_" + strings.ToLower(ID())
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
	apply := func(sql string) {
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
	snapshot := func(table string) string {
		t.Helper()
		var result string
		query := "SELECT COALESCE(jsonb_agg(to_jsonb(saved) ORDER BY to_jsonb(saved)::text),'[]'::jsonb)::text FROM " + pgx.Identifier{table}.Sanitize() + " saved"
		if err := db.QueryRow(ctx, query).Scan(&result); err != nil {
			t.Fatal("snapshot migration table:", err)
		}
		return result
	}
	apply(migrations.BaseSQL)
	apply(migrations.PeopleAssetsSQL)
	workspace, user, person, asset, account, endpoint, grant, userGroup := ID(), ID(), ID(), ID(), ID(), ID(), ID(), ID()
	foreignWorkspace, foreignUser, foreignAsset, foreignUserGroup := ID(), ID(), ID(), ID()
	// Authentication is not exercised here: preserve an opaque legacy hash byte-for-byte.
	exec(`INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role,auth_version) VALUES($1,$2,'p2-admin','P2 Admin','unchanged-legacy-password-hash','admin',4),($3,$4,'foreign-admin','Foreign Admin','foreign-password-hash','admin',2)`, user, workspace, foreignUser, foreignWorkspace)
	exec(`INSERT INTO ra_login_sessions(id_hash,workspace,user_id,auth_version,csrf,expires_at) VALUES($1,$2,$3,4,'unchanged-csrf',now()+interval '1 hour')`, digest(ID()), workspace, user)
	exec(`INSERT INTO ra_groups(id,workspace,name) VALUES($1,$2,'Existing operators'),($3,$4,'Foreign operators')`, userGroup, workspace, foreignUserGroup, foreignWorkspace)
	exec(`INSERT INTO ra_group_members(workspace,group_id,user_id) VALUES($1,$2,$3)`, workspace, userGroup, user)
	exec(`INSERT INTO ra_people(id,workspace,display_name,department,email,contact_type,source,enabled,version,created_by) VALUES($1,$2,'Existing responsible person','Operations','owner@example.test','internal','manual',true,3,$3)`, person, workspace, user)
	ownership := Ownership{State: "assigned", UserID: person, OperationsID: person, BusinessID: person, NotificationIDs: []string{person}, BackupIDs: []string{}}
	exec(`INSERT INTO ra_assets(id,workspace,name,kind,os_family,group_name,tags,description,metadata,version,inventory_id,created_by,category,environment,site,business,ownership,ownership_legacy) VALUES($1,$2,'P2 assigned asset','virtual','linux','Existing operators','["preserve"]','Existing inventory','{"provider":"existing"}',17,'p2-existing-inventory',$3,'nas','production','Room A','Storage',$4,false)`, asset, workspace, user, marshal(ownership))
	exec(`INSERT INTO ra_assets(id,workspace,name,kind,os_family,created_by) VALUES($1,$2,'Foreign legacy asset','physical','other',$3)`, foreignAsset, foreignWorkspace, foreignUser)
	exec(`INSERT INTO ra_asset_responsibility_refs(workspace,asset_id,person_id) VALUES($1,$2,$3)`, workspace, asset, person)
	exec(`INSERT INTO ra_asset_ownership_history(workspace,asset_id,revision,ownership,people_snapshot,changed_by) VALUES($1,$2,17,$3,$4,$5)`, workspace, asset, marshal(ownership), marshal([]map[string]string{{"id": person, "displayName": "Existing responsible person", "department": "Operations", "contactType": "internal"}}), user)
	exec(`INSERT INTO ra_endpoints(id,workspace,asset_id,protocol,host,port,gateway_id,version) VALUES($1,$2,$3,'ssh','192.0.2.20',2222,'existing-gateway',5)`, endpoint, workspace, asset)
	exec(`INSERT INTO ra_host_keys(workspace,endpoint_id,algorithm,fingerprint,approved_by) VALUES($1,$2,'ssh-ed25519','SHA256:existing-migration-key',$3)`, workspace, endpoint, user)
	exec(`INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,credential_version,version,created_by) VALUES($1,$2,$3,'Existing OS account','existing-user','password','["ssh","sftp"]',6,8,$4)`, account, workspace, asset, user)
	key := bytes.Repeat([]byte{9}, 32)
	secret := Secret{Password: "preserved-encrypted-remote-password"}
	aad := workspace + ":" + account + ":6"
	ciphertext, nonce, err := seal(key, aad, secret)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO ra_secrets(workspace,account_id,ciphertext,nonce,key_version,version,updated_by) VALUES($1,$2,$3,$4,'existing-key',6,$5)`, workspace, account, ciphertext, nonce, user)
	exec(`INSERT INTO ra_grants(id,workspace,group_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,version,granted_by) VALUES($1,$2,$3,$4,$5,'["asset.view","remoteAccount.use","ssh.connect"]','["ssh"]',$6,now()-interval '1 hour',now()+interval '1 day',7,$7)`, grant, workspace, userGroup, asset, account, marshal(Limits{MaxFileBytes: 1024, MaxTotalBytes: 4096, MaxFiles: 10, MaxDepth: 4, MaxConcurrent: 1}), user)
	exec(`INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'asset.save',$3,'success','{"preserve":true}')`, workspace, user, asset)
	oldTables := []string{"ra_users", "ra_login_sessions", "ra_groups", "ra_group_members", "ra_people", "ra_assets", "ra_asset_responsibility_refs", "ra_asset_ownership_history", "ra_endpoints", "ra_host_keys", "ra_accounts", "ra_secrets", "ra_grants", "ra_audit_events"}
	before := map[string]string{}
	for _, table := range oldTables {
		before[table] = snapshot(table)
	}
	scopeTables := []string{"ra_asset_groups", "ra_asset_group_assets", "ra_asset_group_users", "ra_asset_group_subject_groups"}
	for attempt := 1; attempt <= 2; attempt++ {
		apply(migrations.AssetScopesSQL)
		for _, table := range oldTables {
			if snapshot(table) != before[table] {
				t.Fatalf("003 execution %d changed existing table %s", attempt, table)
			}
		}
		for _, table := range scopeTables {
			if got := snapshot(table); got != "[]" {
				t.Fatalf("003 fabricated inventory scope in %s: %s", table, got)
			}
		}
	}
	localScope, foreignScope := ID(), ID()
	exec(`INSERT INTO ra_asset_groups(id,workspace,name,description,enabled,starts_at,expires_at,version,created_by) VALUES($1,$2,'Explicit existing scope','Keep explicit bindings',true,now()-interval '1 hour',now()+interval '1 day',9,$3),($4,$5,'Foreign explicit scope','Foreign bindings',true,now()-interval '1 hour',now()+interval '1 day',2,$6)`, localScope, workspace, user, foreignScope, foreignWorkspace, foreignUser)
	exec(`INSERT INTO ra_asset_group_assets(workspace,asset_group_id,asset_id) VALUES($1,$2,$3),($4,$5,$6)`, workspace, localScope, asset, foreignWorkspace, foreignScope, foreignAsset)
	exec(`INSERT INTO ra_asset_group_users(workspace,asset_group_id,user_id) VALUES($1,$2,$3),($4,$5,$6)`, workspace, localScope, user, foreignWorkspace, foreignScope, foreignUser)
	exec(`INSERT INTO ra_asset_group_subject_groups(workspace,asset_group_id,group_id) VALUES($1,$2,$3),($4,$5,$6)`, workspace, localScope, userGroup, foreignWorkspace, foreignScope, foreignUserGroup)
	for _, table := range append(scopeTables, "ra_schema_versions") {
		before[table] = snapshot(table)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		apply(migrations.AssetScopesSQL)
		for table, want := range before {
			if got := snapshot(table); got != want {
				t.Fatalf("repeated 003 execution %d changed populated table %s", attempt, table)
			}
		}
	}
	for _, invalid := range []struct {
		label string
		sql   string
		args  []any
	}{
		{"scope creator", `INSERT INTO ra_asset_groups(id,workspace,name,starts_at,expires_at,created_by) VALUES($1,$2,'Forged creator',now(),now()+interval '1 hour',$3)`, []any{ID(), workspace, foreignUser}},
		{"asset target", `INSERT INTO ra_asset_group_assets(workspace,asset_group_id,asset_id) VALUES($1,$2,$3)`, []any{workspace, localScope, foreignAsset}},
		{"asset parent", `INSERT INTO ra_asset_group_assets(workspace,asset_group_id,asset_id) VALUES($1,$2,$3)`, []any{workspace, foreignScope, asset}},
		{"user target", `INSERT INTO ra_asset_group_users(workspace,asset_group_id,user_id) VALUES($1,$2,$3)`, []any{workspace, localScope, foreignUser}},
		{"user parent", `INSERT INTO ra_asset_group_users(workspace,asset_group_id,user_id) VALUES($1,$2,$3)`, []any{workspace, foreignScope, user}},
		{"group target", `INSERT INTO ra_asset_group_subject_groups(workspace,asset_group_id,group_id) VALUES($1,$2,$3)`, []any{workspace, localScope, foreignUserGroup}},
		{"group parent", `INSERT INTO ra_asset_group_subject_groups(workspace,asset_group_id,group_id) VALUES($1,$2,$3)`, []any{workspace, foreignScope, userGroup}},
	} {
		_, err := db.Exec(ctx, invalid.sql, invalid.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("%s cross-workspace reference must fail its composite FK, got %v", invalid.label, err)
		}
	}
	for table, want := range before {
		if snapshot(table) != want {
			t.Fatalf("rejected cross-workspace writes changed table %s", table)
		}
	}
	var restoredCiphertext, restoredNonce []byte
	if err = db.QueryRow(ctx, `SELECT ciphertext,nonce FROM ra_secrets WHERE account_id=$1`, account).Scan(&restoredCiphertext, &restoredNonce); err != nil {
		t.Fatal(err)
	}
	var restored Secret
	if err = unseal(key, restoredNonce, restoredCiphertext, aad, &restored); err != nil || restored != secret {
		t.Fatal("003 damaged encrypted credential recovery:", err)
	}
	var versions []int32
	if err = db.QueryRow(ctx, "SELECT array_agg(version ORDER BY version) FROM ra_schema_versions").Scan(&versions); err != nil || len(versions) != 3 || versions[0] != 1 || versions[1] != 2 || versions[2] != 3 {
		t.Fatalf("unexpected schema versions %v: %v", versions, err)
	}
}
