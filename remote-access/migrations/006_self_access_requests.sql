CREATE TABLE IF NOT EXISTS ra_self_access_requests (
 workspace text NOT NULL, user_id text NOT NULL, idempotency_key text NOT NULL,
 request_digest text NOT NULL, grant_id text NOT NULL REFERENCES ra_grants(id),
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(workspace,user_id,idempotency_key),
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id)
);
INSERT INTO ra_schema_versions(version) VALUES(6) ON CONFLICT DO NOTHING;
