CREATE TABLE IF NOT EXISTS ra_agent_enrollments (
 id text PRIMARY KEY, workspace text NOT NULL, asset_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('host','docker','pve')),
 token_hash text NOT NULL UNIQUE, created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id),
 FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id)
);
CREATE TABLE IF NOT EXISTS ra_agents (
 id text PRIMARY KEY, workspace text NOT NULL, asset_id text NOT NULL,
 enrollment_id text NOT NULL UNIQUE REFERENCES ra_agent_enrollments(id),
 kind text NOT NULL CHECK(kind IN ('host','docker','pve')),
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 hostname text NOT NULL, os text NOT NULL, agent_version text NOT NULL,
 config_version bigint NOT NULL DEFAULT 1 CHECK(config_version>0),
 applied_version bigint NOT NULL DEFAULT 0 CHECK(applied_version>=0),
 interval_seconds integer NOT NULL DEFAULT 5 CHECK(interval_seconds BETWEEN 1 AND 3600),
 enabled boolean NOT NULL DEFAULT true, revoked boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), last_seen timestamptz,
 revoked_at timestamptz,
 UNIQUE(workspace,asset_id,id), FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id)
);
CREATE INDEX IF NOT EXISTS ra_agents_asset ON ra_agents(workspace,asset_id);
CREATE TABLE IF NOT EXISTS ra_agent_nonces (
 agent_id text NOT NULL REFERENCES ra_agents(id), nonce_hash text NOT NULL,
 expires_at timestamptz NOT NULL, PRIMARY KEY(agent_id,nonce_hash)
);
CREATE INDEX IF NOT EXISTS ra_agent_nonces_expiry ON ra_agent_nonces(expires_at);
CREATE TABLE IF NOT EXISTS ra_agent_samples (
 workspace text NOT NULL, asset_id text NOT NULL, agent_id text NOT NULL,
 batch_id uuid NOT NULL, sequence numeric(20,0) NOT NULL CHECK(sequence BETWEEN 1 AND 18446744073709551615),
 observed_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 config_version bigint NOT NULL CHECK(config_version>0), kind text NOT NULL CHECK(kind IN ('host','docker','pve')),
 payload_hash text NOT NULL, metrics jsonb NOT NULL CHECK(jsonb_typeof(metrics)='object'),
 health jsonb NOT NULL CHECK(jsonb_typeof(health)='object'),
 PRIMARY KEY(agent_id,batch_id), UNIQUE(agent_id,sequence),
 FOREIGN KEY(workspace,asset_id,agent_id) REFERENCES ra_agents(workspace,asset_id,id)
);
CREATE INDEX IF NOT EXISTS ra_agent_samples_asset_time ON ra_agent_samples(workspace,asset_id,observed_at DESC,agent_id,batch_id);
CREATE INDEX IF NOT EXISTS ra_agent_samples_retention ON ra_agent_samples(agent_id,received_at);
INSERT INTO ra_schema_versions(version) VALUES(8) ON CONFLICT DO NOTHING;
