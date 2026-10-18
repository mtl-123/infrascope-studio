CREATE TABLE IF NOT EXISTS ra_asset_egress (
 workspace text NOT NULL, asset_id text NOT NULL,
 protocol text NOT NULL CHECK(protocol IN ('ssh','sftp','rdp')),
 host text NOT NULL, port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(workspace,asset_id,protocol,host,port),
 FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id),
 FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id)
);
CREATE TABLE IF NOT EXISTS ra_server_onboarding_requests (
 workspace text NOT NULL, user_id text NOT NULL, idempotency_key text NOT NULL,
 request_hash text NOT NULL, hash_key_version text NOT NULL,
 asset_id text NOT NULL, account_id text NOT NULL, grant_id text NOT NULL REFERENCES ra_grants(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(workspace,user_id,idempotency_key),
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id),
 FOREIGN KEY(workspace,asset_id,account_id) REFERENCES ra_accounts(workspace,asset_id,id)
);
INSERT INTO ra_schema_versions(version) VALUES(7) ON CONFLICT DO NOTHING;
