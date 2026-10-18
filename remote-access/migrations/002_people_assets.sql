CREATE TABLE IF NOT EXISTS ra_people (
 id text PRIMARY KEY, workspace text NOT NULL, display_name text NOT NULL,
 department text NOT NULL DEFAULT '', email text NOT NULL DEFAULT '',
 contact_type text NOT NULL CHECK(contact_type IN ('internal','external')),
 source text NOT NULL DEFAULT 'manual' CHECK(source='manual'), enabled boolean NOT NULL DEFAULT true,
 version bigint NOT NULL DEFAULT 1, created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(workspace,id), FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id)
);
CREATE INDEX IF NOT EXISTS ra_people_directory ON ra_people(workspace,display_name,id);

ALTER TABLE ra_assets ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'server'
 CHECK(category IN ('server','nas','pve','switch','printer','scanner','other'));
ALTER TABLE ra_assets ADD COLUMN IF NOT EXISTS environment text NOT NULL DEFAULT '';
ALTER TABLE ra_assets ADD COLUMN IF NOT EXISTS site text NOT NULL DEFAULT '';
ALTER TABLE ra_assets ADD COLUMN IF NOT EXISTS business text NOT NULL DEFAULT '';
ALTER TABLE ra_assets ADD COLUMN IF NOT EXISTS ownership jsonb NOT NULL DEFAULT '{"state":"pending","userId":"","claimantId":"","operationsId":"","businessId":"","notificationIds":[],"backupIds":[]}';
-- Existing assets remain usable but visibly require responsibility assignment.
ALTER TABLE ra_assets ADD COLUMN IF NOT EXISTS ownership_legacy boolean NOT NULL DEFAULT true;
CREATE TABLE IF NOT EXISTS ra_asset_ownership_history (
 workspace text NOT NULL, asset_id text NOT NULL, revision bigint NOT NULL, ownership jsonb NOT NULL,
 people_snapshot jsonb NOT NULL DEFAULT '[]',
 changed_by text NOT NULL, changed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(asset_id,revision),
 FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id),
 FOREIGN KEY(workspace,changed_by) REFERENCES ra_users(workspace,id)
);
CREATE TABLE IF NOT EXISTS ra_asset_responsibility_refs (
 workspace text NOT NULL, asset_id text NOT NULL, person_id text NOT NULL,
 PRIMARY KEY(asset_id,person_id),
 FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id),
 FOREIGN KEY(workspace,person_id) REFERENCES ra_people(workspace,id)
);
INSERT INTO ra_schema_versions(version) VALUES(2) ON CONFLICT DO NOTHING;
