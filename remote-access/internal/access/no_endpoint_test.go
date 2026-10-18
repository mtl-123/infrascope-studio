package access

import (
	"bytes"
	"context"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestIntegrationRemovedEndpointsDenyRemoteAccess(t *testing.T) {
	h := newHarness(t)
	h.setupAsset()
	h.trust()
	operator := h.user("removed-endpoint-user", "operator")
	grant := h.grant(operator, false)
	ctx := context.Background()
	before := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	var ciphertext, nonce []byte
	var secretVersion int64
	if err := h.a.DB.QueryRow(ctx, `SELECT ciphertext,nonce,version FROM ra_secrets WHERE workspace=$1 AND account_id=$2`, h.a.Config.Workspace, h.account).Scan(&ciphertext, &nonce, &secretVersion); err != nil {
		t.Fatal(err)
	}
	var keys int
	if err := h.a.DB.QueryRow(ctx, `SELECT count(*) FROM ra_host_keys WHERE workspace=$1`, h.a.Config.Workspace).Scan(&keys); err != nil || keys != 2 {
		t.Fatalf("expected two approved host keys before removal: count=%d err=%v", keys, err)
	}
	edit := assetEdit(h, 1, "Monitoring-only after endpoint removal")
	edit["endpoints"] = []map[string]any{}
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	after := h.request(h.admin, "GET", "/assets/"+h.asset, nil, 200)
	if endpoints, ok := after["endpoints"].([]any); !ok || len(endpoints) != 0 {
		t.Fatalf("removed endpoints still appear on the asset: %v", after)
	}
	if after["version"] != float64(2) || !bytes.Equal(marshal(before["ownership"]), marshal(after["ownership"])) {
		t.Fatalf("endpoint removal did not preserve ownership and increment the asset version: %v", after)
	}
	var accounts, secrets, grants, endpoints int
	if err := h.a.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM ra_accounts WHERE workspace=$1 AND asset_id=$2 AND id=$3 AND enabled AND NOT archived),(SELECT count(*) FROM ra_secrets WHERE workspace=$1 AND account_id=$3),(SELECT count(*) FROM ra_grants WHERE workspace=$1 AND id=$4 AND NOT revoked),(SELECT count(*) FROM ra_endpoints WHERE workspace=$1 AND asset_id=$2),(SELECT count(*) FROM ra_host_keys WHERE workspace=$1)`, h.a.Config.Workspace, h.asset, h.account, grant).Scan(&accounts, &secrets, &grants, &endpoints, &keys); err != nil {
		t.Fatal(err)
	}
	if accounts != 1 || secrets != 1 || grants != 1 || endpoints != 0 || keys != 0 {
		t.Fatalf("endpoint removal changed retained data or left trust behind: accounts=%d secrets=%d grants=%d endpoints=%d keys=%d", accounts, secrets, grants, endpoints, keys)
	}
	var afterCiphertext, afterNonce []byte
	var afterSecretVersion int64
	if err := h.a.DB.QueryRow(ctx, `SELECT ciphertext,nonce,version FROM ra_secrets WHERE workspace=$1 AND account_id=$2`, h.a.Config.Workspace, h.account).Scan(&afterCiphertext, &afterNonce, &afterSecretVersion); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ciphertext, afterCiphertext) || !bytes.Equal(nonce, afterNonce) || secretVersion != afterSecretVersion {
		t.Fatal("endpoint removal unexpectedly modified the retained credential")
	}
	sshInput := map[string]any{"assetId": h.asset, "accountId": h.account, "cols": 80, "rows": 24}
	transferInput := map[string]any{"accountId": h.account, "direction": "upload", "target": h.root, "conflict": "ask"}
	for _, request := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/ssh/sessions", sshInput},
		{"GET", "/sftp/entries?accountId=" + h.account, nil},
		{"POST", "/transfers", transferInput},
		{"POST", "/rdp/launches", map[string]any{"assetId": h.asset, "accountId": h.account, "connectorId": ID(), "browserBindingId": ID(), "options": RDPOptions{DriveMode: "all"}, "idempotencyKey": ID()}},
	} {
		response := h.request(operator, request.method, request.path, request.body, 404)
		if response["code"] != "endpoint_unavailable" {
			t.Fatalf("%s %s was not refused specifically for the missing endpoint: %v", request.method, request.path, response)
		}
	}
	var sessions, transfers, launches int
	if err := h.a.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM ra_remote_sessions WHERE workspace=$1),(SELECT count(*) FROM ra_transfers WHERE workspace=$1),(SELECT count(*) FROM ra_rdp_launches WHERE workspace=$1)`, h.a.Config.Workspace).Scan(&sessions, &transfers, &launches); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || transfers != 0 || launches != 0 {
		t.Fatalf("missing endpoints created remote tasks: sessions=%d transfers=%d launches=%d", sessions, transfers, launches)
	}

	edit["version"] = 2
	edit["endpoints"] = []map[string]any{}
	for _, protocol := range []string{"ssh", "sftp"} {
		edit["endpoints"] = append(edit["endpoints"].([]map[string]any), map[string]any{"protocol": protocol, "host": h.host, "port": h.port, "gatewayId": h.a.Config.GatewayID})
	}
	h.request(h.admin, "PATCH", "/assets/"+h.asset, edit, 200)
	for _, protocol := range []string{"ssh", "sftp"} {
		probe := h.request(h.admin, "POST", "/assets/"+h.asset+"/host-key/probe", map[string]any{"protocol": protocol}, 200)
		if probe["fingerprint"] != ssh.FingerprintSHA256(h.signer.PublicKey()) || probe["trusted"] != false || probe["requiresOutOfBandVerification"] != true {
			t.Fatalf("re-added %s endpoint inherited trust: %v", protocol, probe)
		}
	}
	for _, request := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/ssh/sessions", sshInput},
		{"GET", "/sftp/entries?accountId=" + h.account, nil},
		{"POST", "/transfers", transferInput},
	} {
		response := h.request(operator, request.method, request.path, request.body, 409)
		if response["code"] != "host_key_untrusted" {
			t.Fatalf("re-added endpoint must require a fresh host-key approval: %v", response)
		}
	}
	if err := h.a.DB.QueryRow(ctx, `SELECT count(*) FROM ra_host_keys WHERE workspace=$1`, h.a.Config.Workspace).Scan(&keys); err != nil || keys != 0 {
		t.Fatalf("probing or rejected connection silently approved a host key: count=%d err=%v", keys, err)
	}
	h.trust()
	h.request(operator, "GET", "/sftp/entries?accountId="+h.account, nil, 200)
	session := h.request(operator, "POST", "/ssh/sessions", sshInput, 201)
	h.request(operator, "DELETE", "/ssh/sessions/"+session["id"].(string), nil, 200)
}
