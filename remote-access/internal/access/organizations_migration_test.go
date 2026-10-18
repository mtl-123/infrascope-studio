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

func TestIntegrationOrganizationsImportsMigration(t *testing.T) {
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
	schema := "p2_org_import_migration_" + strings.ToLower(ID())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("clean up isolated schema %s: %v", schema, err)
		}
	})
	isolated := config.Copy()
	isolated.RuntimeParams["search_path"] = quotedSchema
	db, err := pgx.ConnectConfig(ctx, isolated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	var actualSchema string
	if err = db.QueryRow(ctx, "SELECT current_schema()").Scan(&actualSchema); err != nil || actualSchema != schema {
		t.Fatalf("migration schema mismatch: %q %v", actualSchema, err)
	}
	apply := func(source string) {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, source); err != nil {
			t.Fatal("apply migration:", err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal("migration fixture:", err)
		}
	}
	snapshot := func(table string, ignoreOrganization bool) string {
		t.Helper()
		value := "to_jsonb(saved)"
		if table == "ra_assets" && ignoreOrganization {
			value = "(to_jsonb(saved)-'organization_id')"
		}
		var result string
		if err := db.QueryRow(ctx, "SELECT COALESCE(jsonb_agg("+value+" ORDER BY "+value+"::text),'[]'::jsonb)::text FROM "+pgx.Identifier{table}.Sanitize()+" saved").Scan(&result); err != nil {
			t.Fatal("migration snapshot:", err)
		}
		return result
	}
	apply(migrations.BaseSQL)
	apply(migrations.PeopleAssetsSQL)
	apply(migrations.AssetScopesSQL)
	workspace, user, reader, person, asset, account, grant, scope := ID(), ID(), ID(), ID(), ID(), ID(), ID(), ID()
	foreignWorkspace, foreignUser, foreignPerson, foreignAsset := ID(), ID(), ID(), ID()
	exec(`INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) VALUES($1,$2,'migration-admin','Migration admin','opaque-hash','admin'),($3,$2,'migration-reader','Migration reader','opaque-reader-hash','operator'),($4,$5,'foreign-admin','Foreign admin','opaque-foreign-hash','admin')`, user, workspace, reader, foreignUser, foreignWorkspace)
	exec(`INSERT INTO ra_people(id,workspace,display_name,contact_type,created_by) VALUES($1,$2,'Existing owner','internal',$3),($4,$5,'Foreign owner','internal',$6)`, person, workspace, user, foreignPerson, foreignWorkspace, foreignUser)
	ownership := Ownership{State: "pending", ClaimantID: person, NotificationIDs: []string{}, BackupIDs: []string{}}
	exec(`INSERT INTO ra_assets(id,workspace,name,kind,os_family,inventory_id,version,created_by,ownership,ownership_legacy) VALUES($1,$2,'Existing asset','virtual','linux','existing-import-key',7,$3,$4,false),($5,$6,'Foreign asset','physical','other','foreign-import-key',3,$7,'{}',true)`, asset, workspace, user, marshal(ownership), foreignAsset, foreignWorkspace, foreignUser)
	exec(`INSERT INTO ra_asset_responsibility_refs(workspace,asset_id,person_id) VALUES($1,$2,$3)`, workspace, asset, person)
	exec(`INSERT INTO ra_asset_ownership_history(workspace,asset_id,revision,ownership,changed_by) VALUES($1,$2,7,$3,$4)`, workspace, asset, marshal(ownership), user)
	exec(`INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,credential_version,created_by) VALUES($1,$2,$3,'Existing account','existing-user','password','["ssh"]',2,$4)`, account, workspace, asset, user)
	key, secret := bytes.Repeat([]byte{11}, 32), Secret{Password: "migration-encrypted-secret"}
	aad := workspace + ":" + account + ":2"
	ciphertext, nonce, err := seal(key, aad, secret)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO ra_secrets(workspace,account_id,ciphertext,nonce,key_version,version,updated_by) VALUES($1,$2,$3,$4,'migration-key',2,$5)`, workspace, account, ciphertext, nonce, user)
	exec(`INSERT INTO ra_grants(id,workspace,user_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,granted_by) VALUES($1,$2,$3,$4,$5,'["asset.view","ssh.connect"]','["ssh"]','{}',now()-interval '1 hour',now()+interval '1 day',$6)`, grant, workspace, reader, asset, account, user)
	exec(`INSERT INTO ra_asset_groups(id,workspace,name,starts_at,expires_at,created_by) VALUES($1,$2,'Existing independent scope',now()-interval '1 hour',now()+interval '1 day',$3)`, scope, workspace, user)
	exec(`INSERT INTO ra_asset_group_assets(workspace,asset_group_id,asset_id) VALUES($1,$2,$3)`, workspace, scope, asset)
	exec(`INSERT INTO ra_asset_group_users(workspace,asset_group_id,user_id) VALUES($1,$2,$3)`, workspace, scope, reader)
	exec(`INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result) VALUES($1,$2,'migration.fixture',$3,'success')`, workspace, user, asset)
	oldTables := []string{"ra_users", "ra_people", "ra_assets", "ra_asset_responsibility_refs", "ra_asset_ownership_history", "ra_accounts", "ra_secrets", "ra_grants", "ra_asset_groups", "ra_asset_group_assets", "ra_asset_group_users", "ra_audit_events"}
	before := map[string]string{}
	for _, table := range oldTables {
		before[table] = snapshot(table, true)
	}
	newTables := []string{"ra_organizations", "ra_organization_members", "ra_asset_import_jobs", "ra_asset_origins"}
	for attempt := 1; attempt <= 2; attempt++ {
		apply(migrations.OrganizationsSQL)
		apply(migrations.AssetImportsSQL)
		for table, want := range before {
			if got := snapshot(table, true); got != want {
				t.Fatalf("004/005 upgrade %d changed existing %s: %s", attempt, table, got)
			}
		}
		for _, table := range newTables {
			if got := snapshot(table, false); got != "[]" {
				t.Fatalf("004/005 fabricated data in %s: %s", table, got)
			}
		}
		var assigned int
		if err = db.QueryRow(ctx, "SELECT count(*) FROM ra_assets WHERE organization_id IS NOT NULL").Scan(&assigned); err != nil || assigned != 0 {
			t.Fatalf("upgrade silently assigned organizations: %d %v", assigned, err)
		}
	}
	parent, child, foreignOrg, job, foreignJob, discovery := ID(), ID(), ID(), ID(), ID(), ID()
	exec(`INSERT INTO ra_organizations(id,workspace,name,created_by) VALUES($1,$2,'Explicit parent',$3),($4,$5,'Foreign organization',$6)`, parent, workspace, user, foreignOrg, foreignWorkspace, foreignUser)
	exec(`INSERT INTO ra_organizations(id,workspace,name,parent_id,enabled,version,created_by) VALUES($1,$2,'Explicit child',$3,false,4,$4)`, child, workspace, parent, user)
	exec(`INSERT INTO ra_organization_members(workspace,organization_id,user_id) VALUES($1,$2,$3)`, workspace, child, reader)
	exec(`UPDATE ra_assets SET organization_id=$1 WHERE workspace=$2 AND id=$3`, child, workspace, asset)
	exec(`INSERT INTO ra_asset_import_jobs(id,workspace,created_by,source_kind,state,rows,claimant_id,organization_id,expires_at) VALUES($1,$2,$3,'csv','confirmed','[{"rowNumber":1,"state":"created"}]',$4,$5,now()+interval '1 hour'),($6,$7,$8,'csv','preview','[]',$9,$10,now()+interval '1 hour'),($11,$2,$3,'local_discovery','preview','[]',$4,NULL,now()+interval '1 hour')`, job, workspace, user, person, child, foreignJob, foreignWorkspace, foreignUser, foreignPerson, foreignOrg, discovery)
	exec(`INSERT INTO ra_asset_origins(workspace,asset_id,source_kind,source_job_id,observed_at,facts) VALUES($1,$2,'csv',$3,now(),'{"source":"uploaded_csv","automaticDiscovery":false}')`, workspace, asset, job)
	allTables := append(append([]string{}, oldTables...), newTables...)
	allTables = append(allTables, "ra_schema_versions")
	for _, table := range allTables {
		before[table] = snapshot(table, false)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		apply(migrations.OrganizationsSQL)
		apply(migrations.AssetImportsSQL)
		for table, want := range before {
			if got := snapshot(table, false); got != want {
				t.Fatalf("004/005 rerun %d changed populated %s", attempt, table)
			}
		}
	}
	for _, invalid := range []struct {
		label, sql, code string
		args             []any
	}{
		{"organization creator", `INSERT INTO ra_organizations(id,workspace,name,created_by) VALUES($1,$2,'Forged creator',$3)`, "23503", []any{ID(), workspace, foreignUser}},
		{"organization parent", `UPDATE ra_organizations SET parent_id=$1 WHERE id=$2`, "23503", []any{foreignOrg, child}},
		{"organization self parent", `UPDATE ra_organizations SET parent_id=id WHERE id=$1`, "23514", []any{child}},
		{"organization member user", `INSERT INTO ra_organization_members(workspace,organization_id,user_id) VALUES($1,$2,$3)`, "23503", []any{workspace, child, foreignUser}},
		{"organization member scope", `INSERT INTO ra_organization_members(workspace,organization_id,user_id) VALUES($1,$2,$3)`, "23503", []any{workspace, foreignOrg, user}},
		{"asset organization", `UPDATE ra_assets SET organization_id=$1 WHERE id=$2`, "23503", []any{foreignOrg, asset}},
		{"job creator", `UPDATE ra_asset_import_jobs SET created_by=$1 WHERE id=$2`, "23503", []any{foreignUser, job}},
		{"job claimant", `UPDATE ra_asset_import_jobs SET claimant_id=$1 WHERE id=$2`, "23503", []any{foreignPerson, job}},
		{"job organization", `UPDATE ra_asset_import_jobs SET organization_id=$1 WHERE id=$2`, "23503", []any{foreignOrg, job}},
		{"job source", `UPDATE ra_asset_import_jobs SET source_kind='pretend_remote_scan' WHERE id=$1`, "23514", []any{job}},
		{"origin asset", `INSERT INTO ra_asset_origins(workspace,asset_id,source_kind,source_job_id,observed_at) VALUES($1,$2,'csv',$3,now())`, "23503", []any{workspace, foreignAsset, job}},
		{"origin job", `UPDATE ra_asset_origins SET source_job_id=$1 WHERE asset_id=$2`, "23503", []any{foreignJob, asset}},
		{"origin source", `UPDATE ra_asset_origins SET source_kind='pretend_remote_scan' WHERE asset_id=$1`, "23514", []any{asset}},
	} {
		_, err := db.Exec(ctx, invalid.sql, invalid.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != invalid.code {
			t.Fatalf("%s must reject with %s, got %v", invalid.label, invalid.code, err)
		}
	}
	for table, want := range before {
		if snapshot(table, false) != want {
			t.Fatalf("rejected migration-constraint writes changed %s", table)
		}
	}
	var restoredCiphertext, restoredNonce []byte
	if err = db.QueryRow(ctx, `SELECT ciphertext,nonce FROM ra_secrets WHERE account_id=$1`, account).Scan(&restoredCiphertext, &restoredNonce); err != nil {
		t.Fatal(err)
	}
	var restored Secret
	if err = unseal(key, restoredNonce, restoredCiphertext, aad, &restored); err != nil || restored != secret {
		t.Fatal("004/005 changed credential recovery:", err)
	}
	var versions []int32
	if err = db.QueryRow(ctx, "SELECT array_agg(version ORDER BY version) FROM ra_schema_versions").Scan(&versions); err != nil || len(versions) != 5 {
		t.Fatalf("unexpected schema versions: %v %v", versions, err)
	}
	for index, version := range versions {
		if version != int32(index+1) {
			t.Fatalf("unexpected schema version ordering: %v", versions)
		}
	}
}
