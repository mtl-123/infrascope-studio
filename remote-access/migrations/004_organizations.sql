CREATE TABLE IF NOT EXISTS ra_organizations (
 id text PRIMARY KEY, workspace text NOT NULL, name text NOT NULL, description text NOT NULL DEFAULT '',
 parent_id text, enabled boolean NOT NULL DEFAULT true, version bigint NOT NULL DEFAULT 1,
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(parent_id IS NULL OR parent_id<>id), UNIQUE(workspace,id), UNIQUE(workspace,name),
 FOREIGN KEY(workspace,parent_id) REFERENCES ra_organizations(workspace,id),
 FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id)
);
CREATE INDEX IF NOT EXISTS ra_organization_parent ON ra_organizations(workspace,parent_id);
CREATE TABLE IF NOT EXISTS ra_organization_members (
 workspace text NOT NULL, organization_id text NOT NULL, user_id text NOT NULL,
 PRIMARY KEY(organization_id,user_id),
 FOREIGN KEY(workspace,organization_id) REFERENCES ra_organizations(workspace,id),
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id)
);
CREATE INDEX IF NOT EXISTS ra_organization_member_scope ON ra_organization_members(workspace,user_id,organization_id);
ALTER TABLE ra_assets ADD COLUMN IF NOT EXISTS organization_id text;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ra_asset_organization_scope' AND conrelid='ra_assets'::regclass) THEN
  ALTER TABLE ra_assets ADD CONSTRAINT ra_asset_organization_scope
   FOREIGN KEY(workspace,organization_id) REFERENCES ra_organizations(workspace,id);
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS ra_asset_organization ON ra_assets(workspace,organization_id);
COMMENT ON COLUMN ra_organizations.parent_id IS 'Classification only: membership and enabled state never propagate to descendants.';
COMMENT ON TABLE ra_organization_members IS 'Direct platform-user membership grants asset metadata read only; not asset management or remote account access.';
INSERT INTO ra_schema_versions(version) VALUES(4) ON CONFLICT DO NOTHING;
