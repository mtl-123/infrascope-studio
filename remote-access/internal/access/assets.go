package access

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var hostname = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
var actions = []string{"credential.temporary", "asset.view", "asset.test", "remoteAccount.view", "remoteAccount.use", "ssh.connect", "ssh.resume", "ssh.close", "sftp.list", "sftp.download", "sftp.upload", "sftp.mkdir", "sftp.rename", "sftp.delete", "rdp.launch", "rdp.clipboard", "rdp.driveRedirect"}

func validHost(h string) bool {
	return len(h) <= 255 && !strings.ContainsAny(h, " \r\n\t/\\@?#\x00") && (net.ParseIP(h) != nil || hostname.MatchString(h))
}
func (a *App) manageAsset(ctx context.Context, u *User, id string) error {
	if e := require(u, "asset.manage"); e != nil {
		return e
	}
	var creator string
	if e := a.store(ctx).QueryRow(ctx, "SELECT created_by FROM ra_assets WHERE workspace=$1 AND id=$2", u.Workspace, id).Scan(&creator); e != nil {
		return fail(404, "asset_not_found", "资产不存在")
	}
	if u.Role != "admin" && creator != u.ID {
		return fail(403, "scope_denied", "资产不在管理范围内")
	}
	return nil
}
func (a *App) assets(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	id := r.PathValue("id")
	if r.Method == "GET" {
		q := `SELECT a.id,a.name,a.kind,a.os_family,a.group_name,a.tags,a.description,a.metadata,a.enabled,a.archived,a.version,a.inventory_id,COALESCE((SELECT json_agg(json_build_object('id',e.id,'protocol',e.protocol,'host',e.host,'port',e.port,'gatewayId',e.gateway_id,'version',e.version)) FROM ra_endpoints e WHERE e.asset_id=a.id),'[]') AS endpoints FROM ra_assets a WHERE a.workspace=$1 AND ($2='' OR a.id=$2) AND ($3='admin' OR a.created_by=$4 AND $3='asset_manager' OR EXISTS(SELECT 1 FROM ra_grants g WHERE g.workspace=a.workspace AND g.asset_id=a.id AND NOT g.revoked AND g.starts_at<=now() AND g.expires_at>now() AND (g.user_id=$4 OR g.group_id IN(SELECT group_id FROM ra_group_members WHERE user_id=$4 AND workspace=$1)))) AND ($6='' OR a.name ILIKE $6 OR a.kind ILIKE $6 OR a.os_family ILIKE $6 OR a.group_name ILIKE $6 OR a.tags::text ILIKE $6) ORDER BY a.name,a.id LIMIT 100 OFFSET $5`
		offsetText := r.URL.Query().Get("offset")
		if offsetText == "" {
			offsetText = "0"
		}
		offset, parseErr := strconv.Atoi(offsetText)
		if parseErr != nil || offset < 0 || offset > 1000000 {
			return fail(400, "pagination_offset", "分页位置无效")
		}
		search := strings.TrimSpace(r.URL.Query().Get("q"))
		if len(search) > 200 {
			return fail(400, "search_length", "搜索文本过长")
		}
		if search != "" {
			search = "%" + search + "%"
		}
		v, e := a.list(ctx, q, u.Workspace, id, u.Role, u.ID, offset, search)
		if e != nil {
			return e
		}
		if id != "" {
			if len(v) == 0 {
				return fail(404, "asset_not_found", "资产不存在或无权访问")
			}
			jsonOut(w, 200, v[0])
		} else {
			jsonOut(w, 200, v)
		}
		return nil
	}
	if e := require(u, "asset.manage"); e != nil {
		return e
	}
	var in struct {
		Name        string            `json:"name"`
		Kind        string            `json:"kind"`
		OS          string            `json:"osFamily"`
		Group       string            `json:"groupName"`
		Tags        []string          `json:"tags"`
		Description string            `json:"description"`
		Metadata    map[string]string `json:"metadata"`
		Enabled     bool              `json:"enabled"`
		Archived    bool              `json:"archived"`
		Inventory   string            `json:"inventoryId"`
		Endpoints   []Endpoint        `json:"endpoints"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !bounded(in.Name, 180) || !contains([]string{"physical", "virtual"}, in.Kind) || !contains([]string{"linux", "windows", "other"}, in.OS) || len(in.Description) > 2000 || len(in.Tags) > 30 || len(in.Group) > 120 || len(in.Endpoints) < 1 || len(in.Endpoints) > 3 {
		return fail(400, "asset_invalid", "资产字段无效")
	}
	seen := map[string]bool{}
	for _, ep := range in.Endpoints {
		if !contains([]string{"ssh", "sftp", "rdp"}, ep.Protocol) || seen[ep.Protocol] || !validHost(ep.Host) || ep.Port < 1 || ep.Port > 65535 || !bounded(ep.Gateway, 120) {
			return fail(400, "endpoint_invalid", "协议端点无效或重复")
		}
		seen[ep.Protocol] = true
	}
	for _, t := range in.Tags {
		if !bounded(t, 80) {
			return fail(400, "tag_invalid", "标签无效")
		}
	}
	for k, v := range in.Metadata {
		if !contains([]string{"provider", "vmName", "instanceId", "hypervisorLabel"}, k) || len(v) > 200 {
			return fail(400, "metadata_invalid", "虚拟机元数据无效")
		}
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if id == "" {
		id = ID()
		_, e = tx.Exec(ctx, `INSERT INTO ra_assets(id,workspace,name,kind,os_family,group_name,tags,description,metadata,enabled,archived,inventory_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,''),$13)`, id, u.Workspace, in.Name, in.Kind, in.OS, in.Group, marshal(in.Tags), in.Description, marshal(in.Metadata), in.Enabled, in.Archived, in.Inventory, u.ID)
	} else {
		if e = a.manageAsset(ctx, u, id); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE ra_assets SET name=$1,kind=$2,os_family=$3,group_name=$4,tags=$5,description=$6,metadata=$7,enabled=$8,archived=$9,version=version+1,updated_at=now() WHERE workspace=$10 AND id=$11`, in.Name, in.Kind, in.OS, in.Group, marshal(in.Tags), in.Description, marshal(in.Metadata), in.Enabled, in.Archived, u.Workspace, id)
	}
	if e != nil {
		return e
	}
	for _, ep := range in.Endpoints {
		var old Endpoint
		err := tx.QueryRow(ctx, "SELECT id,host,port,gateway_id FROM ra_endpoints WHERE workspace=$1 AND asset_id=$2 AND protocol=$3", u.Workspace, id, ep.Protocol).Scan(&old.ID, &old.Host, &old.Port, &old.Gateway)
		if err != nil {
			_, e = tx.Exec(ctx, "INSERT INTO ra_endpoints(id,workspace,asset_id,protocol,host,port,gateway_id) VALUES($1,$2,$3,$4,$5,$6,$7)", ID(), u.Workspace, id, ep.Protocol, ep.Host, ep.Port, ep.Gateway)
		} else if old.Host != ep.Host || old.Port != ep.Port || old.Gateway != ep.Gateway {
			_, e = tx.Exec(ctx, "DELETE FROM ra_host_keys WHERE endpoint_id=$1", old.ID)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, "UPDATE ra_endpoints SET host=$1,port=$2,gateway_id=$3,version=version+1 WHERE id=$4", ep.Host, ep.Port, ep.Gateway, old.ID)
		}
		if e != nil {
			return e
		}
	}
	keptProtocols := []string{}
	for proto := range seen {
		keptProtocols = append(keptProtocols, proto)
	}
	if _, e = tx.Exec(ctx, "DELETE FROM ra_host_keys WHERE endpoint_id IN(SELECT id FROM ra_endpoints WHERE asset_id=$1 AND NOT(protocol=ANY($2)))", id, keptProtocols); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "DELETE FROM ra_endpoints WHERE asset_id=$1 AND NOT(protocol=ANY($2))", id, keptProtocols); e != nil {
		return e
	}
	if in.Archived || !in.Enabled {
		if _, e = tx.Exec(ctx, "UPDATE ra_grants SET revoked=true,version=version+1 WHERE workspace=$1 AND asset_id=$2", u.Workspace, id); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, "INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'asset.save',$3,'success',$4)", u.Workspace, u.ID, id, marshal(map[string]any{"archived": in.Archived})); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	a.terminateAsset(id, "asset_changed")
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}
func (a *App) accounts(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	id, asset := r.PathValue("id"), r.PathValue("asset")
	if r.Method == "GET" {
		v, e := a.list(ctx, `SELECT x.id,x.asset_id,x.name,x.username,x.auth_type,x.protocols,x.enabled,x.archived,x.credential_version,EXISTS(SELECT 1 FROM ra_secrets sec WHERE sec.account_id=x.id) AS credential_configured FROM ra_accounts x JOIN ra_assets a ON a.id=x.asset_id WHERE x.workspace=$1 AND ($2='' OR x.asset_id=$2) AND ($3='' OR x.id=$3) AND ($4='admin' OR $4='asset_manager' AND a.created_by=$5 OR EXISTS(SELECT 1 FROM ra_grants g WHERE g.account_id=x.id AND NOT g.revoked AND g.starts_at<=now() AND g.expires_at>now() AND (g.user_id=$5 OR g.group_id IN(SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$5)))) ORDER BY x.name`, u.Workspace, asset, id, u.Role, u.ID)
		if e != nil {
			return e
		}
		if id != "" {
			if len(v) == 0 {
				return fail(404, "account_not_found", "远程账号不存在或无权访问")
			}
			jsonOut(w, 200, v[0])
		} else {
			jsonOut(w, 200, v)
		}
		return nil
	}
	var in struct {
		Name      string   `json:"name"`
		Username  string   `json:"username"`
		AuthType  string   `json:"authType"`
		Protocols []string `json:"protocols"`
		Enabled   bool     `json:"enabled"`
		Archived  bool     `json:"archived"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if id != "" {
		if e := a.store(ctx).QueryRow(ctx, "SELECT asset_id FROM ra_accounts WHERE workspace=$1 AND id=$2", u.Workspace, id).Scan(&asset); e != nil {
			return fail(404, "account_not_found", "账号不存在")
		}
	}
	if e := a.manageAsset(ctx, u, asset); e != nil {
		return e
	}
	if !bounded(in.Name, 120) || len(in.Username) > 512 || strings.ContainsAny(in.Username, "\r\n\x00") || !contains([]string{"password", "private_key", "interactive"}, in.AuthType) || len(in.Protocols) < 1 || len(in.Protocols) > 3 {
		return fail(400, "account_invalid", "远程账号字段无效")
	}
	if in.AuthType != "interactive" && !bounded(in.Username, 512) {
		return fail(400, "username_required", "请输入远程用户名")
	}
	for _, p := range in.Protocols {
		if !contains([]string{"ssh", "sftp", "rdp"}, p) || in.AuthType == "interactive" && p != "rdp" || in.AuthType == "private_key" && p == "rdp" {
			return fail(400, "protocol_invalid", "认证方式与协议不兼容")
		}
	}
	if id == "" {
		id = ID()
		_, e := a.store(ctx).Exec(ctx, "INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,enabled,archived,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", id, u.Workspace, asset, in.Name, strings.TrimSpace(in.Username), in.AuthType, marshal(in.Protocols), in.Enabled, in.Archived, u.ID)
		if e != nil {
			return e
		}
	} else {
		var oldAuth string
		if e := a.store(ctx).QueryRow(ctx, "SELECT auth_type FROM ra_accounts WHERE id=$1", id).Scan(&oldAuth); e != nil {
			return e
		}
		if oldAuth != in.AuthType {
			return fail(409, "auth_type_immutable", "请创建新账号以更换认证方式，保留旧账号的审计关系")
		}
		if _, e := a.store(ctx).Exec(ctx, "UPDATE ra_accounts SET name=$1,username=$2,protocols=$3,enabled=$4,archived=$5,version=version+1 WHERE id=$6", in.Name, strings.TrimSpace(in.Username), marshal(in.Protocols), in.Enabled, in.Archived, id); e != nil {
			return e
		}
	}
	a.terminateAccount(id, "account_changed")
	if e := a.audit(ctx, u, "account.save", id, "success", "", map[string]any{}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}
func (a *App) credential(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	id := r.PathValue("id")
	if e := recent(u); e != nil {
		return e
	}
	var asset, auth string
	if e := a.store(ctx).QueryRow(ctx, "SELECT asset_id,auth_type FROM ra_accounts WHERE workspace=$1 AND id=$2", u.Workspace, id).Scan(&asset, &auth); e != nil {
		return fail(404, "account_not_found", "账号不存在")
	}
	if e := a.manageAsset(ctx, u, asset); e != nil {
		return e
	}
	var in struct {
		Action string `json:"action"`
		Secret Secret `json:"secret"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !contains([]string{"set", "clear"}, in.Action) {
		return fail(400, "credential_action", "必须明确指定 set 或 clear")
	}
	if in.Action == "set" {
		if auth == "password" && (in.Secret.Password == "" || len(in.Secret.Password) > 2048 || in.Secret.PrivateKey != "") {
			return fail(400, "credential_invalid", "密码字段无效")
		}
		if auth == "private_key" {
			if len(in.Secret.PrivateKey) > 65536 || in.Secret.Password != "" {
				return fail(400, "credential_invalid", "密钥字段无效")
			}
			var e error
			if in.Secret.Passphrase != "" {
				_, e = ssh.ParsePrivateKeyWithPassphrase([]byte(in.Secret.PrivateKey), []byte(in.Secret.Passphrase))
			} else {
				_, e = ssh.ParsePrivateKey([]byte(in.Secret.PrivateKey))
			}
			if e != nil {
				return fail(400, "private_key_invalid", "私钥格式或口令无效")
			}
		}
		if auth == "interactive" {
			return fail(400, "interactive_no_secret", "交互提示模式不保存凭据")
		}
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var v int64
	if e = tx.QueryRow(ctx, "UPDATE ra_accounts SET credential_version=credential_version+1,version=version+1 WHERE id=$1 RETURNING credential_version", id).Scan(&v); e != nil {
		return e
	}
	if in.Action == "clear" {
		_, e = tx.Exec(ctx, "DELETE FROM ra_secrets WHERE account_id=$1", id)
	} else {
		ct, n, e2 := seal(a.Config.Keys[a.Config.ActiveKey], u.Workspace+":"+id+":"+formatInt(v), in.Secret)
		if e2 != nil {
			return e2
		}
		_, e = tx.Exec(ctx, `INSERT INTO ra_secrets(workspace,account_id,ciphertext,nonce,key_version,version,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(account_id) DO UPDATE SET ciphertext=$3,nonce=$4,key_version=$5,version=$6,updated_by=$7,updated_at=now()`, u.Workspace, id, ct, n, a.Config.ActiveKey, v, u.ID)
	}
	in.Secret = Secret{}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'credential.update',$3,'success',$4)", u.Workspace, u.ID, id, marshal(map[string]any{"version": v, "operation": in.Action})); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	a.terminateAccount(id, "credential_changed")
	jsonOut(w, 200, map[string]any{"ok": true, "credentialVersion": v, "remotePasswordChanged": false})
	return nil
}
func (a *App) grants(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	if e := require(u, "grant.view"); e != nil {
		return e
	}
	if r.Method == "GET" {
		v, e := a.list(ctx, `SELECT g.id,g.user_id,g.group_id,g.asset_id,g.account_id,g.actions,g.protocols,g.limits,g.starts_at,g.expires_at,g.revoked,g.version FROM ra_grants g JOIN ra_assets a ON a.id=g.asset_id WHERE g.workspace=$1 AND ($2='admin' OR a.created_by=$3) ORDER BY g.expires_at DESC LIMIT 2000`, u.Workspace, u.Role, u.ID)
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	if e := require(u, "grant.manage"); e != nil {
		return e
	}
	id := r.PathValue("id")
	if r.Method == "DELETE" {
		var asset string
		if e := a.store(ctx).QueryRow(ctx, "SELECT asset_id FROM ra_grants WHERE workspace=$1 AND id=$2", u.Workspace, id).Scan(&asset); e != nil {
			return fail(404, "grant_not_found", "授权不存在")
		}
		if e := a.manageAsset(ctx, u, asset); e != nil {
			return e
		}
		if _, e := a.store(ctx).Exec(ctx, "UPDATE ra_grants SET revoked=true,version=version+1 WHERE id=$1", id); e != nil {
			return e
		}
		if e := a.audit(ctx, u, "grant.revoke", id, "success", "", map[string]any{}); e != nil {
			return e
		}
		jsonOut(w, 200, map[string]bool{"ok": true})
		return nil
	}
	var in struct {
		User      string    `json:"userId"`
		Group     string    `json:"groupId"`
		Asset     string    `json:"assetId"`
		Account   string    `json:"accountId"`
		Actions   []string  `json:"actions"`
		Protocols []string  `json:"protocols"`
		Limits    Limits    `json:"limits"`
		Starts    time.Time `json:"startsAt"`
		Expires   time.Time `json:"expiresAt"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := a.manageAsset(ctx, u, in.Asset); e != nil {
		return e
	}
	x, e := a.account(ctx, u, in.Account)
	if e != nil || x.Asset != in.Asset {
		return fail(400, "grant_account", "账号不属于该资产")
	}
	if (in.User == "") == (in.Group == "") || len(in.Actions) == 0 || !contains(in.Actions, "remoteAccount.use") || in.Expires.Before(in.Starts) || in.Expires.Before(time.Now()) || in.Expires.Sub(time.Now()) > 366*24*time.Hour || len(in.Protocols) == 0 {
		return fail(400, "grant_invalid", "主体、动作、协议或有效期无效")
	}
	for _, p := range in.Protocols {
		if !contains(x.Protocols, p) {
			return fail(400, "grant_protocol", "协议未在账号中启用")
		}
	}
	for _, p := range in.Actions {
		if !contains(actions, p) {
			return fail(400, "grant_action", "不支持的授权动作")
		}
	}
	l := in.Limits
	if l.MaxFileBytes < 1 || l.MaxFileBytes > 100<<30 || l.MaxTotalBytes < l.MaxFileBytes || l.MaxTotalBytes > 1<<40 || l.MaxFiles < 1 || l.MaxFiles > 100000 || l.MaxDepth < 1 || l.MaxDepth > 64 || l.MaxConcurrent < 1 || l.MaxConcurrent > 10 {
		return fail(400, "grant_limits", "必须设置有效的文件与并发限制")
	}
	for _, root := range append(append([]string{}, l.ReadRoots...), l.WriteRoots...) {
		if !validRemoteRoot(root) {
			return fail(400, "grant_root", "允许根目录必须是明确的 SFTP 绝对路径")
		}
	}
	if u.Role != "admin" {
		var delegationEnd time.Time
		if e := a.store(ctx).QueryRow(ctx, `SELECT min(expires_at) FROM ra_grants WHERE workspace=$1 AND account_id=$2 AND NOT revoked AND starts_at<=now() AND expires_at>now() AND (user_id=$3 OR group_id IN(SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$3))`, u.Workspace, x.ID, u.ID).Scan(&delegationEnd); e != nil || in.Expires.After(delegationEnd) {
			return fail(403, "delegation_expiry", "授权不能超过自身权限有效期")
		}
		for _, proto := range in.Protocols {
			for _, act := range in.Actions {
				if act == "remoteAccount.use" {
					continue
				}
				p, e := a.policy(ctx, u, x, proto, act)
				if e != nil {
					return fail(403, "delegation_denied", "不能授予自己没有的权限")
				}
				if l.MaxFiles > p.Limits.MaxFiles || l.MaxDepth > p.Limits.MaxDepth || l.MaxConcurrent > p.Limits.MaxConcurrent || l.MaxFileBytes > p.Limits.MaxFileBytes || l.MaxTotalBytes > p.Limits.MaxTotalBytes || l.AllowOverwrite && !p.Limits.AllowOverwrite || l.AllowInteractive && !p.Limits.AllowInteractive {
					return fail(403, "delegation_limit", "资源限制超过可委派范围")
				}
				for _, rr := range l.ReadRoots {
					if !withinAny(rr, p.Limits.ReadRoots) {
						return fail(403, "delegation_root", "读取范围超过可委派目录")
					}
				}
				for _, rr := range l.WriteRoots {
					if !withinAny(rr, p.Limits.WriteRoots) {
						return fail(403, "delegation_root", "写入范围超过可委派目录")
					}
				}
			}
		}
	}
	if id == "" {
		id = ID()
		_, e = a.store(ctx).Exec(ctx, `INSERT INTO ra_grants(id,workspace,user_id,group_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,granted_by) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12)`, id, u.Workspace, in.User, in.Group, in.Asset, in.Account, marshal(in.Actions), marshal(in.Protocols), marshal(l), in.Starts, in.Expires, u.ID)
	} else {
		var asset string
		if e = a.store(ctx).QueryRow(ctx, "SELECT asset_id FROM ra_grants WHERE workspace=$1 AND id=$2", u.Workspace, id).Scan(&asset); e != nil {
			return fail(404, "grant_not_found", "授权不存在")
		}
		if e = a.manageAsset(ctx, u, asset); e != nil {
			return e
		}
		_, e = a.store(ctx).Exec(ctx, `UPDATE ra_grants SET user_id=NULLIF($1,''),group_id=NULLIF($2,''),asset_id=$3,account_id=$4,actions=$5,protocols=$6,limits=$7,starts_at=$8,expires_at=$9,revoked=false,version=version+1 WHERE workspace=$10 AND id=$11`, in.User, in.Group, in.Asset, in.Account, marshal(in.Actions), marshal(in.Protocols), marshal(l), in.Starts, in.Expires, u.Workspace, id)
	}
	if e != nil {
		return fail(400, "grant_reference", "授权对象无效或不属于当前组织")
	}
	if e = a.audit(ctx, u, "grant.save", id, "success", "", map[string]any{"accountId": in.Account}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}
func (a *App) myAccess(w http.ResponseWriter, r *http.Request, u *User) error {
	if u.Role == "auditor" {
		jsonOut(w, 200, []any{})
		return nil
	}
	v, e := a.list(r.Context(), `SELECT a.id AS asset_id,a.name AS asset_name,a.os_family,x.id AS account_id,x.name AS account_name,x.username,x.protocols,COALESCE(json_agg(json_build_object('id',g.id,'actions',g.actions,'protocols',g.protocols,'limits',g.limits,'expiresAt',g.expires_at)), '[]') AS grants FROM ra_assets a JOIN ra_accounts x ON x.asset_id=a.id JOIN ra_grants g ON g.account_id=x.id WHERE a.workspace=$1 AND x.enabled AND NOT x.archived AND a.enabled AND NOT a.archived AND NOT g.revoked AND g.starts_at<=now() AND g.expires_at>now() AND (g.user_id=$2 OR g.group_id IN(SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$2)) GROUP BY a.id,x.id ORDER BY a.name,x.name`, u.Workspace, u.ID)
	if e != nil {
		return e
	}
	jsonOut(w, 200, v)
	return nil
}
func (a *App) auditList(w http.ResponseWriter, r *http.Request, u *User) error {
	if e := require(u, "audit.read"); e != nil {
		return e
	}
	v, e := a.list(r.Context(), "SELECT id,actor_id,action,object_id,result,correlation_id,details,created_at FROM ra_audit_events WHERE workspace=$1 ORDER BY id DESC LIMIT 500", u.Workspace)
	if e != nil {
		return e
	}
	jsonOut(w, 200, v)
	return nil
}
func parseJSON[T any](b []byte) (T, error) { var v T; e := json.Unmarshal(b, &v); return v, e }
