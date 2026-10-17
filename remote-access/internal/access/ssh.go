package access

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

func formatInt(v int64) string { return strconv.FormatInt(v, 10) }

type Output struct {
	Type     string `json:"type"`
	Sequence uint64 `json:"sequence"`
	Data     string `json:"data"`
}
type SSHSession struct {
	mu                           sync.Mutex
	app                          *App
	ID                           string
	User                         User
	Account                      Account
	Policy                       string
	Endpoint                     Endpoint
	client                       *ssh.Client
	shell                        *ssh.Session
	input                        io.WriteCloser
	state, reason                string
	created, lastInput, detached time.Time
	sequence                     uint64
	output                       []Output
	bufferBytes                  int
	wire                         *websocket.Conn
	lease                        int64
	window                       string
	lastInputSeq                 uint64
	closed                       chan struct{}
	once                         sync.Once
}

func (s *SSHSession) Write(b []byte) (int, error) {
	originalLength := len(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "closed" || s.state == "failed" {
		return 0, io.ErrClosedPipe
	}
	for len(b) > 0 {
		n := min(len(b), 32768)
		s.sequence++
		out := Output{"output", s.sequence, base64.StdEncoding.EncodeToString(b[:n])}
		s.output = append(s.output, out)
		s.bufferBytes += len(out.Data)
		if s.bufferBytes > 1<<20 {
			go s.terminate("output_buffer_exceeded")
			return 0, errors.New("terminal replay buffer limit")
		}
		if s.wire != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			e := s.wire.Write(ctx, websocket.MessageText, marshal(out))
			cancel()
			if e != nil {
				s.wire.CloseNow()
				s.wire = nil
				s.detached = time.Now()
			}
		}
		b = b[n:]
	}
	return originalLength, nil
}
func (s *SSHSession) terminate(reason string) {
	s.once.Do(func() {
		s.mu.Lock()
		s.state = "closed"
		s.reason = reason
		if s.wire != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = s.wire.Write(ctx, websocket.MessageText, marshal(map[string]any{"type": "status", "state": "closed", "reason": reason}))
			cancel()
			s.wire.CloseNow()
		}
		if s.shell != nil {
			_ = s.shell.Close()
		}
		if s.client != nil {
			_ = s.client.Close()
		}
		s.mu.Unlock()
		close(s.closed)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = s.app.DB.Exec(ctx, "UPDATE ra_remote_sessions SET state='closed',ended_at=now(),reason=$1 WHERE id=$2", reason, s.ID)
		_ = s.app.audit(ctx, &s.User, "ssh.end", s.Account.ID, "closed", s.ID, map[string]string{"reason": reason})
	})
}
func (a *App) terminateLogin(id, why string) {
	a.mu.Lock()
	var list []*SSHSession
	for _, s := range a.sessions {
		if s.User.LoginHash == id {
			list = append(list, s)
		}
	}
	a.mu.Unlock()
	for _, s := range list {
		s.terminate(why)
	}
}
func (a *App) terminateUser(id, why string) {
	a.mu.Lock()
	var list []*SSHSession
	for _, s := range a.sessions {
		if s.User.ID == id {
			list = append(list, s)
		}
	}
	a.mu.Unlock()
	for _, s := range list {
		s.terminate(why)
	}
}
func (a *App) terminateAccount(id, why string) {
	a.mu.Lock()
	var list []*SSHSession
	for _, s := range a.sessions {
		if s.Account.ID == id {
			list = append(list, s)
		}
	}
	a.mu.Unlock()
	for _, s := range list {
		s.terminate(why)
	}
}
func (a *App) terminateAsset(id, why string) {
	a.mu.Lock()
	var list []*SSHSession
	for _, s := range a.sessions {
		if s.Account.Asset == id {
			list = append(list, s)
		}
	}
	a.mu.Unlock()
	for _, s := range list {
		s.terminate(why)
	}
}
func (a *App) validLogin(ctx context.Context, u *User) error {
	var valid bool
	e := a.store(ctx).QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ra_login_sessions s JOIN ra_users u ON u.id=s.user_id WHERE s.id_hash=$1 AND s.user_id=$2 AND s.workspace=$3 AND s.expires_at>now() AND u.enabled AND u.auth_version=s.auth_version)`, u.LoginHash, u.ID, u.Workspace).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return fail(401, "session_expired", "登录已失效")
	}
	return nil
}

type temporarySecretKey struct{}

func (a *App) dialSSH(ctx context.Context, u *User, account Account, ep Endpoint) (*ssh.Client, error) {
	target, e := a.target(ctx, ep)
	if e != nil {
		return nil, e
	}
	sec, temporary := ctx.Value(temporarySecretKey{}).(Secret)
	if !temporary {
		sec, e = a.secret(ctx, u, account)
		if e != nil {
			return nil, e
		}
	}
	var methods []ssh.AuthMethod
	if account.AuthType == "password" {
		methods = []ssh.AuthMethod{ssh.Password(sec.Password)}
	} else if account.AuthType == "private_key" {
		var signer ssh.Signer
		if sec.Passphrase != "" {
			signer, e = ssh.ParsePrivateKeyWithPassphrase([]byte(sec.PrivateKey), []byte(sec.Passphrase))
		} else {
			signer, e = ssh.ParsePrivateKey([]byte(sec.PrivateKey))
		}
		if e != nil {
			return nil, fail(409, "private_key_invalid", "私钥或口令无效")
		}
		methods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		return nil, fail(400, "auth_not_supported", "SSH 不支持交互式 RDP 凭据模式")
	}
	sec = Secret{}
	var trustErr error
	config := &ssh.ClientConfig{User: account.Username, Auth: methods, Timeout: 10 * time.Second, HostKeyCallback: func(host string, addr net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		var trusted bool
		e := a.store(ctx).QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM ra_host_keys WHERE workspace=$1 AND endpoint_id=$2 AND fingerprint=$3 AND algorithm=$4)", u.Workspace, ep.ID, fp, key.Type()).Scan(&trusted)
		if e != nil || !trusted {
			trustErr = fail(409, "host_key_untrusted", "SSH 主机密钥未知或发生变化，需要管理员核实")
			return trustErr
		}
		return nil
	}}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, e := d.DialContext(ctx, "tcp", target)
	if e != nil {
		return nil, fail(502, "target_unreachable", "SSH 目标不可达或连接超时")
	}
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	c, ch, req, e := ssh.NewClientConn(conn, net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)), config)
	if e != nil {
		conn.Close()
		if trustErr != nil {
			return nil, trustErr
		}
		if strings.Contains(e.Error(), "unable to authenticate") {
			return nil, fail(401, "remote_auth_failed", "远程账号认证失败")
		}
		return nil, fail(502, "ssh_handshake_failed", "SSH 协商失败")
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, ch, req), nil
}
func (a *App) hostKeys(w http.ResponseWriter, r *http.Request, u *User) error {
	ctx := r.Context()
	asset := r.PathValue("id")
	if e := a.manageAsset(ctx, u, asset); e != nil {
		return e
	}
	var in struct {
		Protocol    string `json:"protocol"`
		Fingerprint string `json:"fingerprint"`
		Algorithm   string `json:"algorithm"`
		Confirm     bool   `json:"confirm"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !contains([]string{"ssh", "sftp"}, in.Protocol) {
		return fail(400, "protocol_invalid", "请选择 SSH 或 SFTP")
	}
	ep, e := a.endpoint(ctx, u, asset, in.Protocol)
	if e != nil {
		return e
	}
	if strings.HasSuffix(r.URL.Path, "/approve") {
		if e = recent(u); e != nil {
			return e
		}
		if !in.Confirm || !strings.HasPrefix(in.Fingerprint, "SHA256:") || len(in.Fingerprint) != 50 || !bounded(in.Algorithm, 80) {
			return fail(400, "confirmation_required", "请通过可信渠道核对后明确确认指纹")
		}
		keyDigest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(in.Fingerprint, "SHA256:"))
		if err != nil || len(keyDigest) != 32 {
			return fail(400, "fingerprint_invalid", "指纹格式无效")
		}
		tx, err := a.DB.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "DELETE FROM ra_host_keys WHERE workspace=$1 AND endpoint_id=$2 AND algorithm=$3", u.Workspace, ep.ID, in.Algorithm); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO ra_host_keys(workspace,endpoint_id,algorithm,fingerprint,approved_by) VALUES($1,$2,$3,$4,$5)", u.Workspace, ep.ID, in.Algorithm, in.Fingerprint, u.ID); err != nil {
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		if e = a.audit(ctx, u, "host_key.approve", ep.ID, "success", "", map[string]string{"fingerprint": in.Fingerprint, "algorithm": in.Algorithm}); e != nil {
			return e
		}
		jsonOut(w, 200, map[string]bool{"ok": true})
		return nil
	}
	if !a.rate("probe:"+u.ID, 10, time.Minute) {
		return fail(429, "probe_throttled", "探测过于频繁")
	}
	target, e := a.target(ctx, ep)
	if e != nil {
		return e
	}
	conn, e := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", target)
	if e != nil {
		return fail(502, "target_unreachable", "目标不可达")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	fp, algo := "", ""
	_, _, _, _ = ssh.NewClientConn(conn, target, &ssh.ClientConfig{User: "host-key-probe", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp = ssh.FingerprintSHA256(key)
		algo = key.Type()
		return errors.New("read-only host key probe completed")
	}})
	if fp == "" {
		return fail(502, "host_key_probe_failed", "未取得主机密钥；未进行登录")
	}
	jsonOut(w, 200, map[string]any{"fingerprint": fp, "algorithm": algo, "trusted": false, "endpointId": ep.ID, "requiresOutOfBandVerification": true})
	return nil
}
func (a *App) newSSH(w http.ResponseWriter, r *http.Request, u *User) error {
	var in struct {
		Asset     string  `json:"assetId"`
		Account   string  `json:"accountId"`
		Temporary *Secret `json:"temporaryCredential"`
		Cols      int     `json:"cols"`
		Rows      int     `json:"rows"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if in.Cols < 10 || in.Cols > 500 || in.Rows < 2 || in.Rows > 300 {
		return fail(400, "terminal_size", "终端尺寸无效")
	}
	ctx := r.Context()
	x, e := a.account(ctx, u, in.Account)
	if e != nil {
		return e
	}
	if x.Asset != in.Asset {
		return fail(403, "asset_account_mismatch", "账号不属于该资产")
	}
	p, e := a.policy(ctx, u, x, "ssh", "ssh.connect")
	if e != nil {
		return e
	}
	if in.Temporary != nil {
		if !a.Config.AllowTemporarySSH || !contains(p.Actions, "credential.temporary") {
			return fail(403, "temporary_credential_denied", "临时凭据未获明确授权")
		}
		if e = recent(u); e != nil {
			return e
		}
		if len(in.Temporary.Password) > 2048 || len(in.Temporary.PrivateKey) > 65536 || len(in.Temporary.Passphrase) > 2048 {
			return fail(400, "credential_invalid", "临时凭据超出限制")
		}
		ctx = context.WithValue(ctx, temporarySecretKey{}, *in.Temporary)
		in.Temporary = nil
	}
	ep, e := a.endpoint(ctx, u, in.Asset, "ssh")
	if e != nil {
		return e
	}
	if ep.Gateway != a.Config.GatewayID {
		return gatewayError(ep.Gateway)
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT id FROM ra_users WHERE id=$1 FOR UPDATE", u.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "infrascope-ssh-quota:"+a.Config.GatewayID); e != nil {
		return e
	}
	var global, perAccount int
	if e = tx.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE account_id=$2) FROM ra_remote_sessions WHERE gateway_id=$1 AND state NOT IN('closed','failed')", a.Config.GatewayID, x.ID).Scan(&global, &perAccount); e != nil {
		return e
	}
	if global >= a.Config.MaxSSH || perAccount >= 32 {
		return fail(429, "gateway_session_quota", "网关或账号会话配额已满")
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM ra_remote_sessions WHERE user_id=$1 AND state NOT IN('closed','failed')", u.ID).Scan(&n); e != nil {
		return e
	}
	if n >= a.Config.MaxSessions {
		return fail(429, "session_quota", "SSH 会话数量达到上限")
	}
	id := ID()
	_, e = tx.Exec(ctx, "INSERT INTO ra_remote_sessions(id,workspace,user_id,login_id_hash,asset_id,account_id,gateway_id,state,credential_version,policy_version) VALUES($1,$2,$3,$4,$5,$6,$7,'connecting',$8,$9)", id, u.Workspace, u.ID, u.LoginHash, x.Asset, x.ID, a.Config.GatewayID, x.CredentialVersion, p.Version)
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	client, e := a.dialSSH(ctx, u, x, ep)
	if e != nil {
		_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_remote_sessions SET state='failed',ended_at=now(),reason='connect_failed' WHERE id=$1", id)
		_ = a.audit(ctx, u, "ssh.connect", x.ID, "failed", id, map[string]any{})
		return e
	}
	ready := false
	defer func() {
		if !ready {
			_, _ = a.DB.Exec(context.Background(), "UPDATE ra_remote_sessions SET state='failed',ended_at=now(),reason='connect_failed' WHERE id=$1 AND state='connecting'", id)
		}
	}()
	shell, e := client.NewSession()
	if e != nil {
		client.Close()
		return fail(502, "ssh_channel_failed", "无法创建 SSH 通道")
	}
	s := &SSHSession{app: a, ID: id, User: *u, Account: x, Policy: p.Version, Endpoint: ep, client: client, shell: shell, state: "ready", created: time.Now(), lastInput: time.Now(), detached: time.Now(), closed: make(chan struct{})}
	input, e := shell.StdinPipe()
	if e != nil {
		client.Close()
		return e
	}
	s.input = input
	shell.Stdout = s
	shell.Stderr = s
	if e = shell.RequestPty("xterm-256color", in.Rows, in.Cols, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); e == nil {
		e = shell.Shell()
	}
	if e != nil {
		s.terminate("pty_failed")
		return fail(502, "pty_failed", "目标未允许交互式 PTY")
	}
	a.mu.Lock()
	a.sessions[id] = s
	a.mu.Unlock()
	if _, e = a.store(ctx).Exec(ctx, "UPDATE ra_remote_sessions SET state='ready' WHERE id=$1", id); e != nil {
		s.terminate("storage_failed")
		return e
	}
	if e = a.audit(ctx, u, "ssh.start", x.ID, "success", id, map[string]any{"gateway": a.Config.GatewayID}); e != nil {
		s.terminate("audit_failed")
		return e
	}
	ready = true
	go func() { _ = shell.Wait(); s.terminate("remote_exit") }()
	jsonOut(w, 201, map[string]any{"id": id, "state": "ready", "gatewayId": a.Config.GatewayID})
	return nil
}
func (a *App) ownedSession(ctx context.Context, u *User, id string) (*SSHSession, error) {
	var owner, gateway, state string
	e := a.store(ctx).QueryRow(ctx, "SELECT user_id,gateway_id,state FROM ra_remote_sessions WHERE workspace=$1 AND id=$2", u.Workspace, id).Scan(&owner, &gateway, &state)
	if e != nil || owner != u.ID {
		return nil, fail(404, "session_not_found", "会话不存在或无权访问")
	}
	if gateway != a.Config.GatewayID {
		return nil, gatewayError(gateway)
	}
	a.mu.Lock()
	s := a.sessions[id]
	a.mu.Unlock()
	if s == nil {
		return nil, fail(410, "session_gone", "原 SSH 会话已结束或网关已重启，请新建连接")
	}
	if e = a.validLogin(ctx, u); e != nil {
		return nil, e
	}
	x, e := a.account(ctx, u, s.Account.ID)
	if e != nil {
		return nil, e
	}
	if x.CredentialVersion != s.Account.CredentialVersion {
		return nil, fail(410, "credential_changed", "凭据版本已变更")
	}
	if _, e = a.policy(ctx, u, x, "ssh", "ssh.resume"); e != nil {
		return nil, e
	}
	return s, nil
}
func (a *App) sessionInfo(w http.ResponseWriter, r *http.Request, u *User) error {
	if r.Method == "GET" && r.PathValue("id") == "" {
		v, e := a.list(r.Context(), "SELECT id,asset_id,account_id,gateway_id,state,created_at,ended_at,reason FROM ra_remote_sessions WHERE workspace=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 200", u.Workspace, u.ID)
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	s, e := a.ownedSession(r.Context(), u, r.PathValue("id"))
	if e != nil {
		return e
	}
	if r.Method == "DELETE" {
		if _, e = a.policy(r.Context(), u, s.Account, "ssh", "ssh.close"); e != nil {
			return e
		}
		s.terminate("user_closed")
	}
	s.mu.Lock()
	v := map[string]any{"id": s.ID, "state": s.state, "reason": s.reason, "sequence": s.sequence, "windowId": s.window, "gatewayId": a.Config.GatewayID, "accountId": s.Account.ID, "assetId": s.Account.Asset}
	s.mu.Unlock()
	jsonOut(w, 200, v)
	return nil
}
func (a *App) attachAuthorization(w http.ResponseWriter, r *http.Request, u *User) error {
	s, e := a.ownedSession(r.Context(), u, r.PathValue("id"))
	if e != nil {
		return e
	}
	var in struct {
		Window string `json:"windowId"`
	}
	if e = decode(w, r, &in); e != nil {
		return e
	}
	if !bounded(in.Window, 100) {
		return fail(400, "window_id", "窗口标识无效")
	}
	token := ID()
	_, e = a.DB.Exec(r.Context(), "INSERT INTO ra_attach_tokens(token_hash,session_id,user_id,login_id_hash,window_id,expires_at) VALUES($1,$2,$3,$4,$5,$6)", digest(token), s.ID, u.ID, u.LoginHash, in.Window, time.Now().Add(30*time.Second))
	if e != nil {
		return e
	}
	jsonOut(w, 200, map[string]any{"authorization": token, "expiresIn": 30})
	return nil
}
func (a *App) stream(w http.ResponseWriter, r *http.Request, u *User) error {
	if !a.origin(r) {
		return fail(403, "origin", "WebSocket 来源无效")
	}
	s, e := a.ownedSession(r.Context(), u, r.PathValue("id"))
	if e != nil {
		return e
	}
	ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{strings.TrimPrefix(strings.TrimPrefix(a.Config.Origin, "https://"), "http://")}, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return nil
	}
	defer ws.CloseNow()
	ws.SetReadLimit(65536)
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	_, body, e := ws.Read(ctx)
	cancel()
	if e != nil {
		return nil
	}
	var first struct {
		Type          string `json:"type"`
		Authorization string `json:"authorization"`
		LastSequence  uint64 `json:"lastSequence"`
	}
	if strictJSON(body, &first) != nil || first.Type != "attach" {
		return nil
	}
	var window string
	e = a.DB.QueryRow(r.Context(), "UPDATE ra_attach_tokens SET consumed_at=now() WHERE token_hash=$1 AND session_id=$2 AND user_id=$3 AND login_id_hash=$4 AND expires_at>now() AND consumed_at IS NULL RETURNING window_id", digest(first.Authorization), s.ID, u.ID, u.LoginHash).Scan(&window)
	if e != nil {
		return nil
	}
	s.mu.Lock()
	if s.state != "ready" {
		s.mu.Unlock()
		return nil
	}
	if first.LastSequence > s.sequence || first.LastSequence < s.sequence && (len(s.output) == 0 || first.LastSequence+1 < s.output[0].Sequence) {
		s.mu.Unlock()
		_ = ws.Write(r.Context(), websocket.MessageText, marshal(map[string]any{"type": "error", "code": "replay_gap", "message": "回放范围已失效，请创建新连接"}))
		return nil
	}
	s.lease++
	lease := s.lease
	s.window = window
	s.lastInputSeq = 0
	if s.wire != nil {
		s.wire.CloseNow()
	}
	s.wire = ws
	s.detached = time.Time{}
	_ = ws.Write(r.Context(), websocket.MessageText, marshal(map[string]any{"type": "status", "state": "ready", "lease": lease}))
	for _, out := range s.output {
		if out.Sequence > first.LastSequence {
			c, cc := context.WithTimeout(r.Context(), 5*time.Second)
			e = ws.Write(c, websocket.MessageText, marshal(out))
			cc()
			if e != nil {
				break
			}
		}
	}
	s.mu.Unlock()
	_, _ = a.DB.Exec(r.Context(), "UPDATE ra_remote_sessions SET lease_version=$1,window_id=$2,last_seen=now() WHERE id=$3", lease, window, s.ID)
	defer func() {
		s.mu.Lock()
		if s.lease == lease {
			s.wire = nil
			s.detached = time.Now()
		}
		s.mu.Unlock()
	}()
	for {
		_, b, e := ws.Read(r.Context())
		if e != nil {
			return nil
		}
		var m struct {
			Type     string `json:"type"`
			Sequence uint64 `json:"sequence"`
			Lease    int64  `json:"lease"`
			Data     string `json:"data"`
			Cols     int    `json:"cols"`
			Rows     int    `json:"rows"`
		}
		if strictJSON(b, &m) != nil {
			return nil
		}
		s.mu.Lock()
		if s.lease != lease || m.Lease != lease || s.state != "ready" {
			s.mu.Unlock()
			return nil
		}
		switch m.Type {
		case "input":
			if m.Sequence != s.lastInputSeq+1 || len(m.Data) > 32768 {
				s.mu.Unlock()
				return nil
			}
			s.lastInputSeq = m.Sequence
			s.lastInput = time.Now()
			timer := time.AfterFunc(5*time.Second, func() { s.client.Close() })
			_, e = s.input.Write([]byte(m.Data))
			timer.Stop()
			s.mu.Unlock()
			if e != nil {
				return nil
			}
		case "resize":
			if m.Rows < 2 || m.Rows > 300 || m.Cols < 10 || m.Cols > 500 {
				s.mu.Unlock()
				return nil
			}
			s.mu.Unlock()
			if e = s.shell.WindowChange(m.Rows, m.Cols); e != nil {
				return nil
			}
		case "ack":
			if m.Sequence > s.sequence {
				s.mu.Unlock()
				return nil
			}
			for len(s.output) > 0 && s.output[0].Sequence <= m.Sequence {
				s.bufferBytes -= len(s.output[0].Data)
				s.output = s.output[1:]
			}
			s.mu.Unlock()
		case "heartbeat":
			s.mu.Unlock()
		case "close":
			s.mu.Unlock()
			if _, e = a.policy(r.Context(), u, s.Account, "ssh", "ssh.close"); e != nil {
				return nil
			}
			s.terminate("user_closed")
			return nil
		default:
			s.mu.Unlock()
			return nil
		}
	}
}
func (a *App) StartBackground(ctx context.Context) error {
	ctx, a.cancel = context.WithCancel(ctx)
	result, e := a.DB.Exec(ctx, "INSERT INTO ra_gateway_leases(gateway_id,instance_id,expires_at) VALUES($1,$2,now()+interval '30 seconds') ON CONFLICT(gateway_id) DO UPDATE SET instance_id=EXCLUDED.instance_id,expires_at=EXCLUDED.expires_at WHERE ra_gateway_leases.expires_at<now()", a.Config.GatewayID, a.instanceID)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return errors.New("gateway ID is already owned by another live instance")
	}
	go a.maintainGatewayLease(ctx)
	if _, e := a.store(ctx).Exec(ctx, "UPDATE ra_remote_sessions SET state='closed',ended_at=now(),reason='gateway_restart' WHERE gateway_id=$1 AND state NOT IN('closed','failed')", a.Config.GatewayID); e != nil {
		return e
	}
	_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='paused',error_code='gateway_restart' WHERE gateway_id=$1 AND direction='upload' AND state IN('running','queued','scanning')", a.Config.GatewayID)
	_, _ = a.store(ctx).Exec(ctx, "UPDATE ra_transfers SET state='failed',error_code='gateway_restart' WHERE gateway_id=$1 AND direction='download' AND state IN('running','queued','scanning')", a.Config.GatewayID)
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				a.retryCleanup(ctx)
			}
		}
	}()
	go func() {
		tick := time.NewTicker(time.Duration(a.Config.RevokePoll) * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				a.mu.Lock()
				list := make([]*SSHSession, 0, len(a.sessions))
				for _, s := range a.sessions {
					list = append(list, s)
				}
				a.mu.Unlock()
				for _, s := range list {
					s.mu.Lock()
					state := s.state
					idle := time.Since(s.lastInput) > time.Duration(a.Config.Idle)*time.Second
					old := time.Since(s.created) > time.Duration(a.Config.MaxDuration)*time.Second
					detached := !s.detached.IsZero() && time.Since(s.detached) > time.Duration(a.Config.Grace)*time.Second
					s.mu.Unlock()
					if state == "closed" {
						a.mu.Lock()
						delete(a.sessions, s.ID)
						a.mu.Unlock()
						continue
					}
					if idle || old || detached {
						s.terminate("session_timeout")
						continue
					}
					checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
					if e := a.validLogin(checkCtx, &s.User); e != nil {
						checkCancel()
						s.terminate("login_revoked")
						continue
					}
					account, e := a.account(checkCtx, &s.User, s.Account.ID)
					if e != nil || account.CredentialVersion != s.Account.CredentialVersion {
						checkCancel()
						s.terminate("account_revoked")
						continue
					}
					if p, e := a.policy(checkCtx, &s.User, account, "ssh", "ssh.connect"); e != nil || p.Version != s.Policy {
						s.terminate("authorization_changed")
					}
					checkCancel()
				}
				a.cleanup(ctx)
			}
		}
	}()
	return nil
}
