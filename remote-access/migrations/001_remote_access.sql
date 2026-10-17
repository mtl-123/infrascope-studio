CREATE TABLE IF NOT EXISTS ra_schema_versions(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS ra_users (
 id text PRIMARY KEY, workspace text NOT NULL, username text NOT NULL,
 display_name text NOT NULL, password_hash text NOT NULL, role text NOT NULL CHECK(role IN ('admin','asset_manager','operator','auditor')),
 enabled boolean NOT NULL DEFAULT true, auth_version bigint NOT NULL DEFAULT 1,
 must_change_password boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(workspace,username), UNIQUE(workspace,id)
);
CREATE TABLE IF NOT EXISTS ra_groups(id text PRIMARY KEY, workspace text NOT NULL, name text NOT NULL, UNIQUE(workspace,name),UNIQUE(workspace,id));
CREATE TABLE IF NOT EXISTS ra_group_members(workspace text NOT NULL, group_id text NOT NULL,user_id text NOT NULL,
 PRIMARY KEY(group_id,user_id),FOREIGN KEY(workspace,group_id) REFERENCES ra_groups(workspace,id),FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_login_sessions(
 id_hash text PRIMARY KEY, workspace text NOT NULL,user_id text NOT NULL,auth_version bigint NOT NULL,
 csrf text NOT NULL,expires_at timestamptz NOT NULL,reauth_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id));
CREATE INDEX IF NOT EXISTS ra_login_expiry ON ra_login_sessions(expires_at);
CREATE TABLE IF NOT EXISTS ra_assets(
 id text PRIMARY KEY,workspace text NOT NULL,name text NOT NULL,kind text NOT NULL CHECK(kind IN ('physical','virtual')),
 os_family text NOT NULL CHECK(os_family IN ('linux','windows','other')),group_name text NOT NULL DEFAULT '',
 tags jsonb NOT NULL DEFAULT '[]',description text NOT NULL DEFAULT '', metadata jsonb NOT NULL DEFAULT '{}',
 enabled boolean NOT NULL DEFAULT true,archived boolean NOT NULL DEFAULT false,version bigint NOT NULL DEFAULT 1,
 inventory_id text,created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(workspace,id),UNIQUE(workspace,inventory_id),FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_endpoints(
 id text PRIMARY KEY,workspace text NOT NULL,asset_id text NOT NULL,protocol text NOT NULL CHECK(protocol IN ('ssh','sftp','rdp')),
 host text NOT NULL,port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),gateway_id text NOT NULL,version bigint NOT NULL DEFAULT 1,
 UNIQUE(asset_id,protocol),UNIQUE(workspace,id),FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id));
CREATE TABLE IF NOT EXISTS ra_host_keys(
 workspace text NOT NULL,endpoint_id text NOT NULL,algorithm text NOT NULL,fingerprint text NOT NULL,approved_by text NOT NULL,approved_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(endpoint_id,fingerprint),FOREIGN KEY(workspace,endpoint_id) REFERENCES ra_endpoints(workspace,id),FOREIGN KEY(workspace,approved_by) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_accounts(
 id text PRIMARY KEY,workspace text NOT NULL,asset_id text NOT NULL,name text NOT NULL,username text NOT NULL,
 auth_type text NOT NULL CHECK(auth_type IN ('password','private_key','interactive')),
 protocols jsonb NOT NULL,enabled boolean NOT NULL DEFAULT true,archived boolean NOT NULL DEFAULT false,
 credential_version bigint NOT NULL DEFAULT 0,version bigint NOT NULL DEFAULT 1,
 created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(workspace,id),UNIQUE(workspace,asset_id,id),
 FOREIGN KEY(workspace,asset_id) REFERENCES ra_assets(workspace,id),FOREIGN KEY(workspace,created_by) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_secrets(
 workspace text NOT NULL,account_id text PRIMARY KEY,ciphertext bytea NOT NULL,nonce bytea NOT NULL,key_version text NOT NULL,
 version bigint NOT NULL,updated_by text NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(workspace,account_id) REFERENCES ra_accounts(workspace,id),FOREIGN KEY(workspace,updated_by) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_grants(
 id text PRIMARY KEY,workspace text NOT NULL,user_id text,group_id text,asset_id text NOT NULL,account_id text NOT NULL,
 actions jsonb NOT NULL,protocols jsonb NOT NULL,limits jsonb NOT NULL,
 starts_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false,version bigint NOT NULL DEFAULT 1,granted_by text NOT NULL,
 CHECK((user_id IS NULL) <> (group_id IS NULL)),CHECK(expires_at>starts_at),
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id),FOREIGN KEY(workspace,group_id) REFERENCES ra_groups(workspace,id),
 FOREIGN KEY(workspace,asset_id,account_id) REFERENCES ra_accounts(workspace,asset_id,id),FOREIGN KEY(workspace,granted_by) REFERENCES ra_users(workspace,id));
CREATE INDEX IF NOT EXISTS ra_grant_lookup ON ra_grants(workspace,user_id,account_id,expires_at) WHERE NOT revoked;
CREATE TABLE IF NOT EXISTS ra_remote_sessions(
 id text PRIMARY KEY,workspace text NOT NULL,user_id text NOT NULL,login_id_hash text NOT NULL,asset_id text NOT NULL,account_id text NOT NULL,
 gateway_id text NOT NULL,state text NOT NULL,credential_version bigint NOT NULL,policy_version text NOT NULL,
 lease_version bigint NOT NULL DEFAULT 0,window_id text,last_seen timestamptz NOT NULL DEFAULT now(),created_at timestamptz NOT NULL DEFAULT now(),ended_at timestamptz,reason text,
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id),FOREIGN KEY(workspace,asset_id,account_id) REFERENCES ra_accounts(workspace,asset_id,id));
CREATE TABLE IF NOT EXISTS ra_attach_tokens(token_hash text PRIMARY KEY,session_id text NOT NULL REFERENCES ra_remote_sessions(id),user_id text NOT NULL,login_id_hash text NOT NULL,window_id text NOT NULL,expires_at timestamptz NOT NULL,consumed_at timestamptz);
CREATE TABLE IF NOT EXISTS ra_transfers(
 id text PRIMARY KEY,workspace text NOT NULL,user_id text NOT NULL,login_id_hash text NOT NULL,asset_id text NOT NULL,account_id text NOT NULL,gateway_id text NOT NULL,
 direction text NOT NULL CHECK(direction IN ('upload','download')),state text NOT NULL,target_path text NOT NULL,conflict text NOT NULL,
 policy_version text NOT NULL,credential_version bigint NOT NULL,total_bytes bigint NOT NULL DEFAULT 0,done_bytes bigint NOT NULL DEFAULT 0,
 error_code text,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL,
 FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id),FOREIGN KEY(workspace,asset_id,account_id) REFERENCES ra_accounts(workspace,asset_id,id));
CREATE INDEX IF NOT EXISTS ra_transfer_owner ON ra_transfers(workspace,user_id,created_at);
CREATE TABLE IF NOT EXISTS ra_transfer_items(
 id text PRIMARY KEY,task_id text NOT NULL REFERENCES ra_transfers(id),relative_path text NOT NULL,is_directory boolean NOT NULL,
 size bigint NOT NULL CHECK(size>=0),modified_ms bigint NOT NULL DEFAULT 0,sha256 text NOT NULL DEFAULT '',offset_bytes bigint NOT NULL DEFAULT 0,
 temp_path text,final_path text,state text NOT NULL DEFAULT 'queued',retries integer NOT NULL DEFAULT 0,error_code text,
 UNIQUE(task_id,relative_path));
CREATE TABLE IF NOT EXISTS ra_transfer_chunks(item_id text NOT NULL REFERENCES ra_transfer_items(id),offset_bytes bigint NOT NULL,size integer NOT NULL,sha256 text NOT NULL,PRIMARY KEY(item_id,offset_bytes));
CREATE TABLE IF NOT EXISTS ra_connectors(
 id text PRIMARY KEY,workspace text NOT NULL,user_id text NOT NULL,name text NOT NULL,public_key bytea NOT NULL,windows_user_hash text NOT NULL,
 approved_origin text NOT NULL,version text NOT NULL,capabilities jsonb NOT NULL DEFAULT '{}',last_seen timestamptz,revoked boolean NOT NULL DEFAULT false,
 binding_version bigint NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(workspace,id),FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_pairings(id text PRIMARY KEY,challenge_hash text NOT NULL UNIQUE,workspace text NOT NULL,user_id text NOT NULL,login_id_hash text NOT NULL,expires_at timestamptz NOT NULL,consumed_at timestamptz,FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_browser_bindings(id text PRIMARY KEY,workspace text NOT NULL,user_id text NOT NULL,connector_id text NOT NULL,login_id_hash text NOT NULL,expires_at timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false,FOREIGN KEY(workspace,connector_id) REFERENCES ra_connectors(workspace,id),FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id));
CREATE TABLE IF NOT EXISTS ra_device_nonces(connector_id text NOT NULL REFERENCES ra_connectors(id),nonce_hash text NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(connector_id,nonce_hash));
CREATE TABLE IF NOT EXISTS ra_rdp_launches(
 id text PRIMARY KEY,workspace text NOT NULL,user_id text NOT NULL,login_id_hash text NOT NULL,asset_id text NOT NULL,account_id text NOT NULL,connector_id text NOT NULL,binding_id text NOT NULL REFERENCES ra_browser_bindings(id),
 credential_version bigint NOT NULL,policy_version text NOT NULL,asset_version bigint NOT NULL,connector_version bigint NOT NULL,
 options jsonb NOT NULL,ticket_hash text UNIQUE,expires_at timestamptz NOT NULL,consumed_at timestamptz,
 idempotency_key text NOT NULL,state text NOT NULL,pid integer,error_code text,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(user_id,idempotency_key),FOREIGN KEY(workspace,user_id) REFERENCES ra_users(workspace,id),FOREIGN KEY(workspace,connector_id) REFERENCES ra_connectors(workspace,id),FOREIGN KEY(workspace,asset_id,account_id) REFERENCES ra_accounts(workspace,asset_id,id));
CREATE TABLE IF NOT EXISTS ra_audit_events(
 id bigserial PRIMARY KEY,workspace text NOT NULL,actor_id text NOT NULL,action text NOT NULL,object_id text NOT NULL,result text NOT NULL,
 correlation_id text NOT NULL DEFAULT '',details jsonb NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS ra_audit_scope ON ra_audit_events(workspace,created_at DESC);
INSERT INTO ra_schema_versions(version) VALUES(1) ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION ra_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append-only'; END $$;
DROP TRIGGER IF EXISTS ra_audit_immutable ON ra_audit_events;
CREATE TRIGGER ra_audit_immutable BEFORE UPDATE OR DELETE ON ra_audit_events FOR EACH ROW EXECUTE FUNCTION ra_reject_audit_mutation();
CREATE TABLE IF NOT EXISTS ra_gateway_leases(gateway_id text PRIMARY KEY,instance_id text NOT NULL,expires_at timestamptz NOT NULL);
ALTER TABLE ra_transfers ADD COLUMN IF NOT EXISTS hidden_from_list boolean NOT NULL DEFAULT false;
ALTER TABLE ra_rdp_launches ADD COLUMN IF NOT EXISTS cleanup_state text;
