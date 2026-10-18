package access

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type selfAccessInput struct {
	Confirm          bool      `json:"confirm"`
	Protocols        []string  `json:"protocols"`
	ExpiresAt        time.Time `json:"expiresAt"`
	ReadRoots        []string  `json:"readRoots"`
	WriteRoots       []string  `json:"writeRoots"`
	AllowFileWrite   bool      `json:"allowFileWrite"`
	AllowClipboard   bool      `json:"allowClipboard"`
	AllowDrives      bool      `json:"allowDrives"`
	AllowInteractive bool      `json:"allowInteractive"`
	IdempotencyKey   string    `json:"idempotencyKey"`
}

func (a *App) grantSelf(w http.ResponseWriter, r *http.Request, u *User) error {
	if u.Role != "admin" {
		return fail(403, "self_grant_denied", "只有平台管理员可明确授权本人使用账号；其他用户请由有权管理员分配")
	}
	if err := recent(u); err != nil {
		return err
	}
	var in selfAccessInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if !in.Confirm || !bounded(in.IdempotencyKey, 120) || strings.TrimSpace(in.IdempotencyKey) != in.IdempotencyKey || len(in.Protocols) < 1 || len(in.Protocols) > 3 {
		return fail(400, "self_grant_confirmation", "请明确确认本人授权并选择协议，提供有效幂等键")
	}
	sort.Strings(in.Protocols)
	for i, p := range in.Protocols {
		if !contains([]string{"ssh", "sftp", "rdp"}, p) || i > 0 && in.Protocols[i-1] == p {
			return fail(400, "self_grant_protocol", "协议无效或重复")
		}
	}
	for _, roots := range [][]string{in.ReadRoots, in.WriteRoots} {
		if len(roots) > 10 {
			return fail(400, "self_grant_roots", "每种文件根目录最多 10 项")
		}
		for _, root := range roots {
			if !validRemoteRoot(root) || len(root) > 2048 {
				return fail(400, "self_grant_roots", "SFTP 需明确有效的绝对根目录，不使用空值表示全部")
			}
		}
	}
	if contains(in.Protocols, "sftp") && len(in.ReadRoots) == 0 {
		return fail(400, "self_grant_roots", "启用文件管理须明确可读根目录")
	}
	if !contains(in.Protocols, "sftp") && (len(in.ReadRoots) > 0 || len(in.WriteRoots) > 0 || in.AllowFileWrite) {
		return fail(400, "self_grant_options", "未选择 SFTP，不能配置文件权限")
	}
	if in.AllowFileWrite && len(in.WriteRoots) == 0 || !in.AllowFileWrite && len(in.WriteRoots) > 0 {
		return fail(400, "self_grant_roots", "文件写权限与明确可写目录必须同时设置")
	}
	if !contains(in.Protocols, "rdp") && (in.AllowClipboard || in.AllowDrives || in.AllowInteractive) {
		return fail(400, "self_grant_options", "未选择 RDP，不能启用本机资源重定向或交互凭据")
	}
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize retries for this user/request; the same key can never create a second grant.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('self-access:'||$1||':'||$2||':'||$3,0))`, u.Workspace, u.ID, in.IdempotencyKey); err != nil {
		return err
	}
	requestHash := digest(r.PathValue("id") + ":" + string(marshal(in)))
	var priorHash, priorGrant string
	err = tx.QueryRow(ctx, "SELECT request_digest,grant_id FROM ra_self_access_requests WHERE workspace=$1 AND user_id=$2 AND idempotency_key=$3", u.Workspace, u.ID, in.IdempotencyKey).Scan(&priorHash, &priorGrant)
	if err == nil {
		if priorHash != requestHash {
			return fail(409, "idempotency_conflict", "此请求标识已用于不同授权；请刷新核对")
		}
		jsonOut(w, 200, map[string]any{"id": priorGrant, "created": false, "message": "已处理该请求；不重复授权，不恢复已撤销权限"})
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !in.ExpiresAt.After(time.Now()) || in.ExpiresAt.After(time.Now().Add(30*24*time.Hour)) {
		return fail(400, "self_grant_expiry", "本人快捷授权须在未来生效并于 30 天内到期")
	}
	var asset string
	if err = tx.QueryRow(ctx, "SELECT asset_id FROM ra_accounts WHERE workspace=$1 AND id=$2", u.Workspace, r.PathValue("id")).Scan(&asset); errors.Is(err, pgx.ErrNoRows) {
		return fail(404, "account_not_found", "账号不存在")
	} else if err != nil {
		return err
	}
	var enabled bool
	if err = tx.QueryRow(ctx, "SELECT enabled AND NOT archived FROM ra_assets WHERE workspace=$1 AND id=$2 FOR SHARE", u.Workspace, asset).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return fail(403, "asset_disabled", "资产已停用或归档")
	}
	var rawProtocols []byte
	var authType string
	if err = tx.QueryRow(ctx, "SELECT protocols,auth_type,enabled AND NOT archived FROM ra_accounts WHERE workspace=$1 AND id=$2 AND asset_id=$3 FOR SHARE", u.Workspace, r.PathValue("id"), asset).Scan(&rawProtocols, &authType, &enabled); err != nil {
		return err
	}
	if !enabled {
		return fail(403, "account_disabled", "远程账号已停用或归档")
	}
	accountProtocols, err := parseJSON[[]string](rawProtocols)
	if err != nil {
		return err
	}
	acts := []string{"asset.view", "remoteAccount.view", "remoteAccount.use"}
	for _, p := range in.Protocols {
		if !contains(accountProtocols, p) {
			return fail(400, "self_grant_protocol", "账号未启用所选协议")
		}
		var endpoint string
		if err = tx.QueryRow(ctx, "SELECT id FROM ra_endpoints WHERE workspace=$1 AND asset_id=$2 AND protocol=$3 FOR SHARE", u.Workspace, asset, p).Scan(&endpoint); errors.Is(err, pgx.ErrNoRows) {
			return fail(400, "endpoint_unavailable", "请先为服务器配置所选协议的真实地址与端口")
		} else if err != nil {
			return err
		}
		switch p {
		case "ssh":
			acts = append(acts, "ssh.connect", "ssh.resume", "ssh.close")
		case "sftp":
			acts = append(acts, "sftp.list", "sftp.download")
			if in.AllowFileWrite {
				acts = append(acts, "sftp.upload", "sftp.mkdir", "sftp.rename", "sftp.delete")
			}
		case "rdp":
			acts = append(acts, "rdp.launch")
			if in.AllowClipboard {
				acts = append(acts, "rdp.clipboard")
			}
			if in.AllowDrives {
				acts = append(acts, "rdp.driveRedirect")
			}
		}
	}
	if authType == "interactive" && !in.AllowInteractive {
		return fail(400, "interactive_confirmation", "交互式 RDP 账号需要明确允许 Windows 凭据提示")
	}
	limits := Limits{ReadRoots: in.ReadRoots, WriteRoots: in.WriteRoots, MaxFileBytes: 1 << 30, MaxTotalBytes: 10 << 30, MaxFiles: 10000, MaxDepth: 32, MaxConcurrent: 3, AllowOverwrite: false, AllowInteractive: in.AllowInteractive}
	id := ID()
	if _, err = tx.Exec(ctx, `INSERT INTO ra_grants(id,workspace,user_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,granted_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),$9,$3)`, id, u.Workspace, u.ID, asset, r.PathValue("id"), marshal(acts), marshal(in.Protocols), marshal(limits), in.ExpiresAt); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_self_access_requests(workspace,user_id,idempotency_key,request_digest,grant_id) VALUES($1,$2,$3,$4,$5)`, u.Workspace, u.ID, in.IdempotencyKey, requestHash, id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'grant.self',$3,'success',$4)`, u.Workspace, u.ID, id, marshal(map[string]any{"assetId": asset, "accountId": r.PathValue("id"), "protocols": in.Protocols, "actions": acts, "expiresAt": in.ExpiresAt, "explicitConfirmation": true})); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	jsonOut(w, 200, map[string]any{"id": id, "created": true, "message": "已明确授权本人；仍需真实网络、主机信任与目标认证验证"})
	return nil
}
