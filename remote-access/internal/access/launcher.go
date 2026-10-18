package access

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
)

type launcherItem struct {
	AssetID     string `json:"assetId"`
	AssetName   string `json:"assetName"`
	AccountID   string `json:"accountId"`
	AccountName string `json:"accountName"`
	Username    string `json:"username"`
	OSFamily    string `json:"osFamily"`
	Protocol    string `json:"protocol"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
}

func launcherAction(protocol string) string {
	switch protocol {
	case "ssh":
		return "ssh.connect"
	case "sftp":
		return "sftp.list"
	case "rdp":
		return "rdp.launch"
	default:
		return ""
	}
}

// A device signature alone must never keep a logged-out browser's access alive.
func (a *App) launcherUser(ctx context.Context, d Device, binding string) (*User, error) {
	if !bounded(binding, 100) {
		return nil, fail(400, "browser_binding_required", "A current browser binding is required")
	}
	if a.leaseLost.Load() {
		return nil, fail(503, "gateway_lease_lost", "Gateway ownership lease has expired")
	}
	u := new(User)
	err := a.store(ctx).QueryRow(ctx, `SELECT u.id,u.workspace,u.username,u.display_name,u.role,u.enabled,u.auth_version,u.must_change_password,s.id_hash,s.csrf,s.reauth_at
		FROM ra_browser_bindings b
		JOIN ra_connectors c ON c.id=b.connector_id AND c.workspace=b.workspace AND c.user_id=b.user_id
		JOIN ra_login_sessions s ON s.id_hash=b.login_id_hash AND s.workspace=b.workspace AND s.user_id=b.user_id
		JOIN ra_users u ON u.id=s.user_id AND u.workspace=s.workspace
		WHERE b.id=$1 AND c.id=$2 AND c.workspace=$3 AND c.user_id=$4
		AND NOT b.revoked AND b.expires_at>now() AND NOT c.revoked AND c.binding_version=$5
		AND c.approved_origin=$6 AND s.expires_at>now() AND u.enabled
		AND s.auth_version=u.auth_version AND u.auth_version=$7`,
		binding, d.ID, d.User.Workspace, d.User.ID, d.Version, a.Config.Origin, d.User.Version).
		Scan(&u.ID, &u.Workspace, &u.Username, &u.Name, &u.Role, &u.Enabled, &u.Version, &u.MustChange, &u.LoginHash, &u.CSRF, &u.Reauth)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fail(401, "browser_binding_expired", "Sign in and pair this browser with this device again")
	}
	if err != nil {
		return nil, err
	}
	if u.MustChange {
		return nil, fail(403, "password_change_required", "Change your platform password before connecting")
	}
	return u, nil
}

func (a *App) launcherCatalog(w http.ResponseWriter, r *http.Request, d Device, body []byte) error {
	var in struct {
		Binding string `json:"browserBindingId"`
		Query   string `json:"query"`
	}
	if strictJSON(body, &in) != nil || len(in.Query) > 200 || strings.ContainsRune(in.Query, '\x00') {
		return fail(400, "launcher_query_invalid", "Search must be at most 200 bytes")
	}
	u, err := a.launcherUser(r.Context(), d, in.Binding)
	if err != nil {
		return err
	}
	items := []launcherItem{}
	if u.Role == "auditor" {
		jsonOut(w, 200, map[string]any{"items": items, "truncated": false, "userId": u.ID})
		return nil
	}
	// Match the browser's access catalog: one grant must contain both actions.
	rows, err := a.store(r.Context()).Query(r.Context(), `SELECT a.id,a.name,x.id,x.name,x.username,a.os_family,e.protocol,e.host,e.port
		FROM ra_accounts x JOIN ra_assets a ON a.id=x.asset_id AND a.workspace=x.workspace
		JOIN ra_endpoints e ON e.asset_id=a.id AND e.workspace=a.workspace
		WHERE x.workspace=$1 AND x.enabled AND NOT x.archived AND a.enabled AND NOT a.archived
		AND x.protocols ? e.protocol
		AND ($3='' OR NOT EXISTS(SELECT 1 FROM regexp_split_to_table(lower($3),'\s+') term
		 WHERE term<>'' AND strpos(lower(a.name || ' ' || x.name || ' ' || x.username || ' ' || e.host || ' ' || e.protocol || ' ' || a.os_family),term)=0))
		AND EXISTS(SELECT 1 FROM ra_grants g WHERE g.workspace=x.workspace AND g.account_id=x.id AND g.asset_id=a.id
		 AND NOT g.revoked AND g.starts_at<=now() AND g.expires_at>now() AND g.protocols ? e.protocol
		 AND (g.user_id=$2 OR g.group_id IN(SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$2))
		 AND g.actions ? 'remoteAccount.use'
		 AND g.actions ? CASE e.protocol WHEN 'ssh' THEN 'ssh.connect' WHEN 'sftp' THEN 'sftp.list' WHEN 'rdp' THEN 'rdp.launch' END)
		ORDER BY lower(a.name),a.id,lower(x.name),x.id,e.protocol LIMIT 201`, u.Workspace, u.ID, strings.TrimSpace(in.Query))
	if err != nil {
		return err
	}
	for rows.Next() {
		var item launcherItem
		if err = rows.Scan(&item.AssetID, &item.AssetName, &item.AccountID, &item.AccountName, &item.Username, &item.OSFamily, &item.Protocol, &item.Host, &item.Port); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// Reuse the canonical policy check; a concurrent revoke may remove results.
	allowed := make([]launcherItem, 0, len(items))
	for _, item := range items {
		x, e := a.account(r.Context(), u, item.AccountID)
		if e == nil {
			_, e = a.policy(r.Context(), u, x, item.Protocol, launcherAction(item.Protocol))
		}
		if e != nil {
			var denied *apiError
			if errors.As(e, &denied) && (denied.Status == 403 || denied.Status == 404) {
				continue
			}
			return e
		}
		allowed = append(allowed, item)
	}
	if _, err = a.launcherUser(r.Context(), d, in.Binding); err != nil {
		return err
	}
	truncated := len(items) > 200
	if len(allowed) > 200 {
		allowed = allowed[:200]
	}
	jsonOut(w, 200, map[string]any{"items": allowed, "truncated": truncated, "userId": u.ID})
	return nil
}

func (a *App) launcherQuickLaunch(w http.ResponseWriter, r *http.Request, d Device, body []byte) error {
	var in struct {
		Binding     string `json:"browserBindingId"`
		Asset       string `json:"assetId"`
		Account     string `json:"accountId"`
		Protocol    string `json:"protocol"`
		Confirmed   bool   `json:"confirmed"`
		Idempotency string `json:"idempotencyKey"`
	}
	if strictJSON(body, &in) != nil || !bounded(in.Asset, 100) || !bounded(in.Account, 100) || launcherAction(in.Protocol) == "" || !bounded(in.Idempotency, 100) {
		return fail(400, "launcher_request_invalid", "Select a saved account and a supported protocol")
	}
	if !in.Confirmed {
		return fail(403, "local_confirmation_required", "Confirm the selected connection on this computer")
	}
	u, err := a.launcherUser(r.Context(), d, in.Binding)
	if err != nil {
		return err
	}
	x, err := a.account(r.Context(), u, in.Account)
	if err != nil {
		return err
	}
	if x.Asset != in.Asset {
		return fail(403, "asset_account_mismatch", "The account does not belong to this asset")
	}
	if _, err = a.policy(r.Context(), u, x, in.Protocol, launcherAction(in.Protocol)); err != nil {
		return err
	}
	var granted bool
	err = a.store(r.Context()).QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM ra_grants g
		WHERE g.workspace=$1 AND g.account_id=$2 AND g.asset_id=$3
		AND NOT g.revoked AND g.starts_at<=now() AND g.expires_at>now() AND g.protocols ? $4
		AND (g.user_id=$5 OR g.group_id IN(SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$5))
		AND g.actions ? 'remoteAccount.use' AND g.actions ? $6)`, u.Workspace, x.ID, x.Asset, in.Protocol, u.ID, launcherAction(in.Protocol)).Scan(&granted)
	if err != nil {
		return err
	}
	if !granted {
		return fail(403, "grant_denied", "The selected connection is not available in your access catalog")
	}
	if _, err = a.endpoint(r.Context(), u, in.Asset, in.Protocol); err != nil {
		return err
	}
	if in.Protocol == "rdp" {
		// Namespace retries so another paired device or browser cannot reuse a task.
		key := "launcher:" + digest(string(marshal([]string{d.ID, in.Binding, in.Asset, in.Account, in.Protocol, in.Idempotency})))
		payload := marshal(map[string]any{
			"assetId": in.Asset, "accountId": in.Account, "connectorId": d.ID,
			"browserBindingId": in.Binding, "idempotencyKey": key,
			"options": RDPOptions{DriveMode: "all", Fullscreen: true},
		})
		req := r.Clone(r.Context())
		req.Method = http.MethodPost
		req.Header.Set("Content-Type", "application/json")
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
		return a.rdpLaunch(w, req, u)
	}
	if err = a.audit(r.Context(), u, "launcher.open", x.ID, "browser_required", "", map[string]string{"connectorId": d.ID, "protocol": in.Protocol}); err != nil {
		return err
	}
	query := url.Values{"assetId": {in.Asset}, "accountId": {in.Account}, "protocol": {in.Protocol}, "userId": {u.ID}}
	jsonOut(w, 200, map[string]string{"state": "open_browser", "url": a.Config.Origin + "/remote-workspace.html?" + query.Encode()})
	return nil
}
