CREATE TABLE IF NOT EXISTS ra_asset_import_jobs (
 id text PRIMARY KEY, workspace text NOT NULL, created_by text NOT NULL,
 source_kind text NOT NULL CHECK(source_kind IN ('csv','local_discovery')),
 state text NOT NULL CHECK(state IN ('preview','partial','confirmed','cancelled')),
 rows jsonb NOT NULL, facts jsonb NOT NULL DEFAULT '{}', claimant_id text NOT NULL, organization_id text,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(workspace,id), FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id),
 FOREIGN KEY(workspace,claimant_id) REFERENCES ra_people(workspace,id),
 FOREIGN KEY(workspace,organization_id) REFERENCES ra_organizations(workspace,id)
);
CREATE INDEX IF NOT EXISTS ra_asset_import_owner ON ra_asset_import_jobs(workspace,created_by,created_at DESC);
CREATE TABLE IF NOT EXISTS ra_asset_origins (
 workspace text NOT NULL, asset_id text PRIMARY KEY, source_kind text NOT NULL CHECK(source_kind IN ('csv','local_discovery')),
 source_job_id text NOT NULL, observed_at timestamptz NOT NULL, facts jsonb NOT NULL DEFAULT '{}',
 FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id),
 FOREIGN KEY(workspace,source_job_id) REFERENCES ra_asset_import_jobs(workspace,id)
);
INSERT INTO ra_schema_versions(version) VALUES(5) ON CONFLICT DO NOTHING;
