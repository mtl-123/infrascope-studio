package access

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var drivePattern = regexp.MustCompile(`^[A-Za-z]:\\?$`)

type RDPOptions struct {
	Clipboard  bool   `json:"redirectClipboard"`
	Drives     bool   `json:"redirectDrives"`
	DriveMode  string `json:"driveMode"`
	DriveList  string `json:"driveList"`
	Fullscreen bool   `json:"fullscreen"`
	Multi      bool   `json:"multiMonitor"`
}

func normalizeDrives(s string) (string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' }) {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !drivePattern.MatchString(v) {
			return "", fail(400, "invalid_drive_list", "盘符格式无效")
		}
		v = strings.ToUpper(v[:1]) + ":\\"
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	if len(out) == 0 {
		return "", fail(400, "invalid_drive_list", "请至少填写一个本地盘符")
	}
	return strings.Join(out, ";"), nil
}
func validateOptions(o RDPOptions, p Policy) (RDPOptions, error) {
	if o.Clipboard && !contains(p.Actions, "rdp.clipboard") {
		return o, fail(403, "clipboard_denied", "当前授权禁止剪贴板重定向")
	}
	if o.Drives && !contains(p.Actions, "rdp.driveRedirect") {
		return o, fail(403, "drive_redirect_denied", "当前授权禁止磁盘映射")
	}
	if o.DriveMode != "all" && o.DriveMode != "custom" {
		return o, fail(400, "drive_mode", "磁盘范围无效")
	}
	if len(o.DriveList) > 256 {
		return o, fail(400, "drive_list", "盘符列表过长")
	}
	if o.Drives && o.DriveMode == "custom" {
		v, e := normalizeDrives(o.DriveList)
		if e != nil {
			return o, e
		}
		o.DriveList = v
	}
	return o, nil
}
func (a *App) connectors(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	if r.Method == "GET" {
		v, e := a.list(ctx, `SELECT c.id,c.name,c.version,c.capabilities,c.last_seen,c.revoked,c.approved_origin,COALESCE((SELECT json_agg(json_build_object('id',b.id,'expiresAt',b.expires_at)) FROM ra_browser_bindings b WHERE b.connector_id=c.id AND b.login_id_hash=$3 AND NOT b.revoked AND b.expires_at>now()),'[]') AS browser_bindings FROM ra_connectors c WHERE c.workspace=$1 AND c.user_id=$2 ORDER BY c.created_at`, u.Workspace, u.ID, u.LoginHash)
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	if e := require(u, "connector.revoke"); e != nil {
		return e
	}
	if e := recent(u); e != nil {
		return e
	}
	id := r.PathValue("id")
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	res, e := tx.Exec(ctx, "UPDATE ra_connectors SET revoked=true,binding_version=binding_version+1 WHERE workspace=$1 AND user_id=$2 AND id=$3", u.Workspace, u.ID, id)
	if e != nil {
		return e
	}
	if res.RowsAffected() != 1 {
		return fail(404, "connector_not_found", "连接器不存在")
	}
	if _, e = tx.Exec(ctx, "UPDATE ra_browser_bindings SET revoked=true WHERE connector_id=$1", id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE ra_rdp_launches SET state='revoked' WHERE connector_id=$1 AND consumed_at IS NULL", id); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	if e = a.audit(ctx, u, "connector.revoke", id, "success", "", map[string]any{}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) pairChallenge(w http.ResponseWriter, r *http.Request, u *User) error {
	if e := require(u, "connector.pair"); e != nil {
		return e
	}
	if e := recent(u); e != nil {
		return e
	}
	if !a.rate("pair:"+u.ID, 5, 10*time.Minute) {
		return fail(429, "pair_throttled", "配对请求过多")
	}
	token, id := ID(), ID()
	_, e := a.DB.Exec(r.Context(), "INSERT INTO ra_pairings(id,challenge_hash,workspace,user_id,login_id_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6)", id, digest(token), u.Workspace, u.ID, u.LoginHash, time.Now().Add(2*time.Minute))
	if e != nil {
		return e
	}
	jsonOut(w, 201, map[string]any{"id": id, "challenge": token, "expiresIn": 120, "platform": a.Config.Origin, "instruction": "仅在自己 Windows 电脑的连接器页面输入该挑战，并确认设备名称"})
	return nil
}
func (a *App) pairDevice(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Enabled {
		errorOut(w, fail(503, "module_disabled", "模块未启用"))
		return
	}
	var in struct {
		Challenge       string `json:"challenge"`
		PublicKey       string `json:"publicKey"`
		Name            string `json:"name"`
		WindowsUserHash string `json:"windowsUserHash"`
		Version         string `json:"version"`
		Signature       string `json:"signature"`
		Origin          string `json:"origin"`
	}
	if e := decode(w, r, &in); e != nil {
		errorOut(w, e)
		return
	}
	if !bounded(in.Name, 120) || !bounded(in.Version, 30) || !shaPattern.MatchString(in.WindowsUserHash) || in.Origin != a.Config.Origin {
		errorOut(w, fail(400, "device_invalid", "设备身份或批准的平台地址无效"))
		return
	}
	block, _ := pem.Decode([]byte(in.PublicKey))
	if block == nil {
		errorOut(w, fail(400, "public_key_invalid", "设备公钥无效"))
		return
	}
	key, e := x509.ParsePKIXPublicKey(block.Bytes)
	pub, ok := key.(ed25519.PublicKey)
	sig, e2 := base64.StdEncoding.DecodeString(in.Signature)
	if e != nil || !ok || e2 != nil || !ed25519.Verify(pub, []byte("pair\n"+in.Challenge+"\n"+in.Origin+"\n"+in.WindowsUserHash), sig) {
		errorOut(w, fail(403, "device_proof_failed", "设备私钥证明失败"))
		return
	}
	ctx := r.Context()
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		errorOut(w, e)
		return
	}
	defer tx.Rollback(ctx)
	var workspace, user, login string
	e = tx.QueryRow(ctx, `UPDATE ra_pairings p SET consumed_at=now() WHERE challenge_hash=$1 AND consumed_at IS NULL AND expires_at>now() AND EXISTS(SELECT 1 FROM ra_login_sessions s JOIN ra_users u ON u.id=s.user_id WHERE s.id_hash=p.login_id_hash AND s.expires_at>now() AND u.enabled AND s.auth_version=u.auth_version) RETURNING workspace,user_id,login_id_hash`, digest(in.Challenge)).Scan(&workspace, &user, &login)
	if e != nil {
		errorOut(w, fail(410, "pairing_expired", "配对挑战已失效或被使用"))
		return
	}
	id, binding := ID(), ID()
	_, e = tx.Exec(ctx, "INSERT INTO ra_connectors(id,workspace,user_id,name,public_key,windows_user_hash,approved_origin,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", id, workspace, user, in.Name, block.Bytes, in.WindowsUserHash, in.Origin, in.Version)
	if e == nil {
		_, e = tx.Exec(ctx, "INSERT INTO ra_browser_bindings(id,workspace,user_id,connector_id,login_id_hash,expires_at) SELECT $1,$2,$3,$4,$5,expires_at FROM ra_login_sessions WHERE id_hash=$5", binding, workspace, user, id, login)
	}
	if e == nil {
		_, e = tx.Exec(ctx, "INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'connector.pair',$3,'success',$4)", workspace, user, id, marshal(map[string]string{"deviceName": in.Name}))
	}
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		errorOut(w, e)
		return
	}
	jsonOut(w, 201, map[string]any{"connectorId": id, "browserBindingId": binding, "userId": user, "workspace": workspace, "platform": in.Origin})
}

type Device struct {
	ID              string
	User            User
	Version         int64
	WindowsUserHash string
}

func (a *App) deviceAuth(r *http.Request) (Device, []byte, error) {
	var d Device
	id, ts, nonce, signature := r.Header.Get("X-Connector-Id"), r.Header.Get("X-Connector-Time"), r.Header.Get("X-Connector-Nonce"), r.Header.Get("X-Connector-Signature")
	t, e := strconv.ParseInt(ts, 10, 64)
	if e != nil || time.Since(time.Unix(t, 0)) > 30*time.Second || time.Until(time.Unix(t, 0)) > 30*time.Second || len(nonce) < 20 || len(nonce) > 100 {
		return d, nil, fail(403, "device_auth_failed", "设备请求时间或 nonce 无效")
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || len(body) > 65536 {
		return d, nil, fail(413, "body_limit", "设备请求超过上限")
	}
	var pub []byte
	d.ID = id
	e = a.DB.QueryRow(r.Context(), `SELECT c.public_key,c.workspace,c.user_id,c.binding_version,c.windows_user_hash,u.auth_version,u.role FROM ra_connectors c JOIN ra_users u ON u.id=c.user_id AND u.workspace=c.workspace WHERE c.id=$1 AND NOT c.revoked AND u.enabled`, id).Scan(&pub, &d.User.Workspace, &d.User.ID, &d.Version, &d.WindowsUserHash, &d.User.Version, &d.User.Role)
	if e != nil {
		if !errors.Is(e, pgx.ErrNoRows) {
			return d, nil, e
		}
		return d, nil, fail(403, "device_revoked", "设备未配对或已撤销")
	}
	key, e := x509.ParsePKIXPublicKey(pub)
	pk, ok := key.(ed25519.PublicKey)
	sig, e2 := base64.StdEncoding.DecodeString(signature)
	hash := sha256.Sum256(body)
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(hash[:])
	if e != nil || !ok || e2 != nil || !ed25519.Verify(pk, []byte(canonical), sig) {
		return d, nil, fail(403, "device_signature", "设备签名无效")
	}
	nonceResult, e := a.DB.Exec(r.Context(), "INSERT INTO ra_device_nonces(connector_id,nonce_hash,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", id, digest(nonce), time.Now().Add(time.Minute))
	if e != nil || nonceResult.RowsAffected() != 1 {
		return d, nil, fail(409, "device_replay", "设备请求重复或未能登记防重放记录")
	}
	return d, body, nil
}
func (a *App) deviceRoute(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Enabled {
		errorOut(w, fail(503, "module_disabled", "模块未启用"))
		return
	}
	d, body, e := a.deviceAuth(r)
	if e != nil {
		errorOut(w, e)
		return
	}
	ctx := r.Context()
	switch pathName := r.PathValue("operation"); pathName {
	case "poll":
		var in struct {
			Capabilities    map[string]any `json:"capabilities"`
			WindowsUserHash string         `json:"windowsUserHash"`
		}
		if strictJSON(body, &in) != nil || in.WindowsUserHash != d.WindowsUserHash {
			errorOut(w, fail(403, "windows_user_mismatch", "Windows 交互用户不匹配"))
			return
		}
		if len(marshal(in.Capabilities)) > 8192 {
			errorOut(w, fail(413, "capabilities_limit", "能力信息过大"))
			return
		}
		_, e = a.store(ctx).Exec(ctx, "UPDATE ra_connectors SET last_seen=now(),capabilities=$1 WHERE id=$2", marshal(in.Capabilities), d.ID)
		if e != nil {
			errorOut(w, e)
			return
		}
		launches, e := a.list(ctx, `SELECT l.id,l.asset_id,l.account_id,l.options,l.expires_at,a.name AS asset_name,x.name AS account_name,x.username,e.host,e.port FROM ra_rdp_launches l JOIN ra_assets a ON a.id=l.asset_id JOIN ra_accounts x ON x.id=l.account_id JOIN ra_endpoints e ON e.asset_id=l.asset_id AND e.protocol='rdp' WHERE l.connector_id=$1 AND l.state='queued' AND l.expires_at>now() AND l.consumed_at IS NULL ORDER BY l.created_at LIMIT 10`, d.ID)
		if e != nil {
			errorOut(w, e)
			return
		}
		jsonOut(w, 200, map[string]any{"launches": launches})
	case "redeem":
		var in struct {
			Launch    string `json:"launchId"`
			Confirmed bool   `json:"locallyConfirmed"`
		}
		if strictJSON(body, &in) != nil || !in.Confirmed {
			errorOut(w, fail(403, "local_confirmation_required", "需要目标电脑用户确认"))
			return
		}
		payload, e := a.redeem(ctx, d, in.Launch)
		if e != nil {
			errorOut(w, e)
			return
		}
		jsonOut(w, 200, payload)
	case "event":
		var in struct {
			Launch string `json:"launchId"`
			State  string `json:"state"`
			PID    int    `json:"pid"`
			Code   string `json:"code"`
		}
		if strictJSON(body, &in) != nil || !contains([]string{"received", "signing_setup_required", "started", "failed", "cleanup_completed", "cleanup_failed"}, in.State) || len(in.Code) > 100 || in.PID < 0 {
			errorOut(w, fail(400, "device_event", "启动反馈无效"))
			return
		}
		res, e := a.store(ctx).Exec(ctx, `UPDATE ra_rdp_launches SET state=CASE WHEN $1 IN('cleanup_completed','cleanup_failed') THEN state ELSE $1 END,cleanup_state=CASE WHEN $1 IN('cleanup_completed','cleanup_failed') THEN $1 ELSE cleanup_state END,pid=COALESCE(NULLIF($2,0),pid),error_code=COALESCE(NULLIF($3,''),error_code) WHERE id=$4 AND connector_id=$5 AND consumed_at IS NOT NULL AND (state IN('redeemed','received') OR $1 IN('cleanup_completed','cleanup_failed') OR state=$1)`, in.State, in.PID, in.Code, in.Launch, d.ID)
		if e != nil || res.RowsAffected() != 1 {
			errorOut(w, fail(404, "launch_not_found", "启动任务不存在或尚未兑换"))
			return
		}
		_ = a.audit(ctx, &d.User, "rdp."+in.State, d.ID, in.State, in.Launch, map[string]any{"pid": in.PID, "code": in.Code})
		jsonOut(w, 200, map[string]bool{"ok": true})
	default:
		errorOut(w, fail(404, "device_operation", "设备操作不存在"))
	}
}
func (a *App) rdpLaunch(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	if r.Method == "GET" {
		v, e := a.list(ctx, "SELECT id,asset_id,account_id,connector_id,state,cleanup_state,pid,error_code,created_at,expires_at FROM ra_rdp_launches WHERE workspace=$1 AND user_id=$2 AND ($3='' OR id=$3) ORDER BY created_at DESC LIMIT 100", u.Workspace, u.ID, r.PathValue("id"))
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	var in struct {
		Asset       string     `json:"assetId"`
		Account     string     `json:"accountId"`
		Connector   string     `json:"connectorId"`
		Binding     string     `json:"browserBindingId"`
		Options     RDPOptions `json:"options"`
		Idempotency string     `json:"idempotencyKey"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !bounded(in.Idempotency, 100) {
		return fail(400, "idempotency_key", "必须提供幂等键")
	}
	x, e := a.account(ctx, u, in.Account)
	if e != nil {
		return e
	}
	if x.Asset != in.Asset {
		return fail(403, "asset_account_mismatch", "账号不属于该资产")
	}
	p, e := a.policy(ctx, u, x, "rdp", "rdp.launch")
	if e != nil {
		return e
	}
	if x.AuthType == "interactive" && !p.Limits.AllowInteractive {
		return fail(403, "interactive_denied", "不允许在 mstsc 中改用交互凭据")
	}
	opts, e := validateOptions(in.Options, p)
	if e != nil {
		return e
	}
	ep, e := a.endpoint(ctx, u, x.Asset, "rdp")
	if e != nil {
		return e
	}
	_ = ep
	var cv, av int64
	e = a.store(ctx).QueryRow(ctx, `SELECT c.binding_version,a.version FROM ra_connectors c JOIN ra_browser_bindings b ON b.connector_id=c.id JOIN ra_assets a ON a.id=$1 WHERE c.id=$2 AND c.user_id=$3 AND c.workspace=$4 AND NOT c.revoked AND c.last_seen>now()-interval '20 seconds' AND b.id=$5 AND b.login_id_hash=$6 AND NOT b.revoked AND b.expires_at>now()`, in.Asset, in.Connector, u.ID, u.Workspace, in.Binding, u.LoginHash).Scan(&cv, &av)
	if e != nil {
		return fail(409, "connector_binding_unavailable", "请选择当前浏览器已配对且在线的 Windows 设备")
	}
	var old string
	e = a.store(ctx).QueryRow(ctx, "SELECT id FROM ra_rdp_launches WHERE user_id=$1 AND idempotency_key=$2", u.ID, in.Idempotency).Scan(&old)
	if e == nil {
		jsonOut(w, 200, map[string]string{"id": old})
		return nil
	}
	id := ID()
	_, e = a.store(ctx).Exec(ctx, `INSERT INTO ra_rdp_launches(id,workspace,user_id,login_id_hash,asset_id,account_id,connector_id,binding_id,credential_version,policy_version,asset_version,connector_version,options,expires_at,idempotency_key,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'queued')`, id, u.Workspace, u.ID, u.LoginHash, in.Asset, in.Account, in.Connector, in.Binding, x.CredentialVersion, p.Version, av, cv, marshal(opts), time.Now().Add(60*time.Second), in.Idempotency)
	if e != nil {
		return fail(409, "launch_conflict", "启动请求重复或无法创建")
	}
	if e = a.audit(ctx, u, "rdp.issue", x.ID, "queued", id, map[string]string{"connectorId": in.Connector}); e != nil {
		return e
	}
	jsonOut(w, 201, map[string]string{"id": id, "state": "queued"})
	return nil
}
func (a *App) redeem(ctx context.Context, d Device, id string) (map[string]any, error) {
	tx, e := a.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	ctx = context.WithValue(ctx, txContextKey{}, tx)
	var account, asset, policy, login, binding string
	var cred, cv, av int64
	var optsJSON []byte
	var expires time.Time
	var state string
	e = tx.QueryRow(ctx, "SELECT account_id,asset_id,policy_version,login_id_hash,binding_id,credential_version,connector_version,asset_version,options,expires_at,state FROM ra_rdp_launches WHERE id=$1 AND connector_id=$2 AND user_id=$3 AND workspace=$4 FOR UPDATE", id, d.ID, d.User.ID, d.User.Workspace).Scan(&account, &asset, &policy, &login, &binding, &cred, &cv, &av, &optsJSON, &expires, &state)
	if e != nil {
		return nil, fail(404, "launch_not_found", "启动任务不存在")
	}
	if state != "queued" || time.Now().After(expires) {
		return nil, fail(410, "launch_expired_or_consumed", "启动任务已过期、撤销或消费")
	}
	u := d.User
	u.LoginHash = login
	if e = a.validLogin(ctx, &u); e != nil {
		return nil, e
	}
	var currentAV int64
	var currentCV int64
	if e = tx.QueryRow(ctx, "SELECT binding_version FROM ra_connectors WHERE id=$1 AND NOT revoked FOR SHARE", d.ID).Scan(&currentCV); e != nil || currentCV != cv {
		return nil, fail(410, "connector_revoked", "设备授权已变化")
	}
	var validBinding bool
	e = tx.QueryRow(ctx, `SELECT a.version,EXISTS(SELECT 1 FROM ra_browser_bindings WHERE id=$2 AND connector_id=$3 AND login_id_hash=$4 AND NOT revoked AND expires_at>now()) FROM ra_assets a WHERE a.workspace=$5 AND a.id=$1 AND a.enabled AND NOT a.archived`, asset, binding, d.ID, login, u.Workspace).Scan(&currentAV, &validBinding)
	if e != nil || currentAV != av || !validBinding || cv != d.Version {
		return nil, fail(410, "binding_changed", "资产或设备绑定已变化")
	}
	x, e := a.account(ctx, &u, account)
	if e != nil {
		return nil, e
	}
	if x.CredentialVersion != cred {
		return nil, fail(410, "credential_changed", "凭据版本已变化")
	}
	p, e := a.policy(ctx, &u, x, "rdp", "rdp.launch")
	if e != nil {
		return nil, e
	}
	if p.Version != policy {
		return nil, fail(410, "policy_changed", "授权策略已变化")
	}
	if x.AuthType == "interactive" && !p.Limits.AllowInteractive {
		return nil, fail(403, "interactive_denied", "交互式凭据未授权")
	}
	var opts RDPOptions
	if json.Unmarshal(optsJSON, &opts) != nil {
		return nil, errors.New("invalid saved options")
	}
	opts, e = validateOptions(opts, p)
	if e != nil {
		return nil, e
	}
	ep, e := a.endpoint(ctx, &u, asset, "rdp")
	if e != nil {
		return nil, e
	}
	sec, e := a.secret(ctx, &u, x)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "UPDATE ra_rdp_launches SET consumed_at=now(),state='redeemed' WHERE id=$1", id); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,correlation_id) VALUES($1,$2,'rdp.consume',$3,'redeemed',$4)", u.Workspace, u.ID, x.ID, id); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, fail(409, "redemption_conflict", "任务并发兑换冲突，请查询任务状态")
	}
	return map[string]any{"launchId": id, "connectorId": d.ID, "windowsUserHash": d.WindowsUserHash, "address": ep.Host, "port": ep.Port, "username": x.Username, "password": sec.Password, "options": opts, "permittedActions": p.Actions, "interactiveAllowed": p.Limits.AllowInteractive, "expiresAt": expires}, nil
}
