CREATE TABLE IF NOT EXISTS ra_asset_groups (
 id text PRIMARY KEY, workspace text NOT NULL, name text NOT NULL, description text NOT NULL DEFAULT '',
 enabled boolean NOT NULL DEFAULT true, starts_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 version bigint NOT NULL DEFAULT 1, created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(expires_at>starts_at), UNIQUE(workspace,id), UNIQUE(workspace,name),
 FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id)
);
CREATE TABLE IF NOT EXISTS ra_asset_group_assets (
 workspace text NOT NULL, asset_group_id text NOT NULL, asset_id text NOT NULL,
 PRIMARY KEY(asset_group_id,asset_id),
 FOREIGN KEY(workspace,asset_group_id) REFERENCES ra_asset_groups(workspace,id),
 FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id)
);
CREATE INDEX IF NOT EXISTS ra_asset_group_asset_scope ON ra_asset_group_assets(workspace,asset_id,asset_group_id);
CREATE TABLE IF NOT EXISTS ra_asset_group_users (
 workspace text NOT NULL, asset_group_id text NOT NULL, user_id text NOT NULL,
 PRIMARY KEY(asset_group_id,user_id),
 FOREIGN KEY(workspace,asset_group_id) REFERENCES ra_asset_groups(workspace,id),
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id)
);
CREATE TABLE IF NOT EXISTS ra_asset_group_subject_groups (
 workspace text NOT NULL, asset_group_id text NOT NULL, group_id text NOT NULL,
 PRIMARY KEY(asset_group_id,group_id),
 FOREIGN KEY(workspace,asset_group_id) REFERENCES ra_asset_groups(workspace,id),
 FOREIGN KEY(workspace,group_id) REFERENCES ra_groups(workspace,id)
);
INSERT INTO ra_schema_versions(version) VALUES(3) ON CONFLICT DO NOTHING;
