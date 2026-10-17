package access

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
	"log"
)

type Config struct {
	AllowTemporarySSH                                                             bool
	Peers                                                                         map[string]string
	MaxSFTP, MaxSSH                                                               int
	Bandwidth                                                                     int64
	Enabled, LoopbackTest                                                         bool
	Listen, Origin, StaticDir, Workspace, GatewayID, DatabaseURL, ActiveKey       string
	Keys                                                                          map[string][]byte
	Allowed                                                                       []netip.Prefix
	SessionHours, MaxSessions, MaxTransfers, Idle, MaxDuration, Grace, RevokePoll int
}

func LoadConfig() (Config, error) {
	c := Config{AllowTemporarySSH: os.Getenv("REMOTE_ALLOW_TEMPORARY_SSH_CREDENTIALS") == "true", MaxSFTP: numenv("REMOTE_MAX_SFTP_CHANNELS", 32), MaxSSH: numenv("REMOTE_MAX_SSH_GATEWAY", 128), Bandwidth: int64(numenv("REMOTE_BANDWIDTH_BYTES_PER_USER", 16777216)), Enabled: os.Getenv("REMOTE_ENABLED") == "true", LoopbackTest: os.Getenv("REMOTE_LOOPBACK_TEST") == "true", Listen: env("REMOTE_LISTEN", "127.0.0.1:8080"), Origin: env("REMOTE_PUBLIC_ORIGIN", ""), StaticDir: env("REMOTE_STATIC_DIR", "../dist"), Workspace: env("REMOTE_WORKSPACE", "default"), GatewayID: env("REMOTE_GATEWAY_ID", "gateway-1"), DatabaseURL: os.Getenv("DATABASE_URL"), ActiveKey: env("REMOTE_ACTIVE_KEY_VERSION", "key-1"), Keys: map[string][]byte{}, SessionHours: numenv("REMOTE_SESSION_HOURS", 8), MaxSessions: numenv("REMOTE_MAX_SESSIONS_PER_USER", 8), MaxTransfers: numenv("REMOTE_MAX_TRANSFERS_PER_USER", 3), Idle: numenv("REMOTE_SSH_IDLE_SECONDS", 1800), MaxDuration: numenv("REMOTE_SSH_MAX_SECONDS", 28800), Grace: numenv("REMOTE_SSH_REATTACH_SECONDS", 60), RevokePoll: numenv("REMOTE_REVOKE_POLL_SECONDS", 5)}
	if !c.Enabled && (len(os.Args) == 1 || os.Args[1] == "serve") {
		return c, nil
	}
	u, e := url.Parse(c.Origin)
	if e != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return c, errors.New("REMOTE_PUBLIC_ORIGIN must be an exact HTTPS origin")
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return c, e
	}
	if u.Scheme != "https" && !(c.LoopbackTest && u.Scheme == "http" && loopback(host) && loopback(u.Hostname())) {
		return c, errors.New("HTTPS is mandatory outside loopback tests")
	}
	if c.DatabaseURL == "" {
		return c, errors.New("DATABASE_URL required")
	}
	var keys map[string]string
	if e = json.Unmarshal([]byte(env("REMOTE_SECRET_KEYS", "{}")), &keys); e != nil {
		return c, errors.New("invalid keyring")
	}
	for k, v := range keys {
		b, e := base64.StdEncoding.DecodeString(v)
		if e != nil || len(b) != 32 {
			return c, errors.New("AES key must contain 32 bytes")
		}
		c.Keys[k] = b
	}
	if len(c.Keys[c.ActiveKey]) != 32 {
		return c, errors.New("active secret key is missing")
	}
	for _, v := range strings.Split(os.Getenv("REMOTE_ALLOWED_CIDRS"), ",") {
		if strings.TrimSpace(v) == "" {
			continue
		}
		p, e := netip.ParsePrefix(strings.TrimSpace(v))
		if e != nil {
			return c, e
		}
		c.Allowed = append(c.Allowed, p)
	}
	c.Peers = map[string]string{}
	if e = json.Unmarshal([]byte(env("REMOTE_GATEWAY_PEERS", "{}")), &c.Peers); e != nil {
		return c, errors.New("invalid gateway route table")
	}
	for id, raw := range c.Peers {
		v, err := url.Parse(raw)
		if !bounded(id, 120) || strings.ContainsAny(id, "/\\") || err != nil || v.Scheme != "https" || v.Host == "" || v.User != nil || v.RawQuery != "" || v.Fragment != "" || v.Path != "" {
			return c, errors.New("gateway peers require exact trusted HTTPS origins")
		}
	}
	if c.RevokePoll < 1 || c.RevokePoll > 10 {
		return c, errors.New("revocation poll must be between 1 and 10 seconds")
	}
	return c, nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func numenv(k string, d int) int {
	v, e := strconv.Atoi(os.Getenv(k))
	if e != nil || v < 1 {
		return d
	}
	return v
}
func loopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip, e := netip.ParseAddr(h)
	return e == nil && ip.IsLoopback()
}
func ID() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func PasswordHash(p string) (string, error) {
	if len(p) < 12 || len(p) > 1024 {
		return "", fail(400, "password_policy", "平台密码需为 12–1024 字节")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	h := argon2.IDKey([]byte(p), salt, 3, 65536, 2, 32)
	return "$argon2id$v=19$m=65536,t=3,p=2$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(h), nil
}
func passwordOK(encoded, p string) bool {
	if len(p) > 1024 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[3] != "m=65536,t=3,p=2" {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[4])
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(parts[5])
	if e != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(p), salt, 3, 65536, 2, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func seal(key []byte, aad string, v any) ([]byte, []byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, nil, e
	}
	data, e := json.Marshal(v)
	if e != nil {
		return nil, nil, e
	}
	defer zero(data)
	return g.Seal(nil, n, data, []byte(aad)), n, nil
}
func unseal(key, nonce, ct []byte, aad string, v any) error {
	b, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return e
	}
	if len(nonce) != g.NonceSize() {
		return errors.New("invalid nonce")
	}
	data, e := g.Open(nil, nonce, ct, []byte(aad))
	if e != nil {
		return e
	}
	defer zero(data)
	return json.Unmarshal(data, v)
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type apiError struct {
	Status        int
	Code, Message string
	Gateway       string
}

func (e *apiError) Error() string   { return e.Message }
func fail(s int, c, m string) error { return &apiError{Status: s, Code: c, Message: m} }
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func errorOut(w http.ResponseWriter, e error) {
	var a *apiError
	if errors.As(e, &a) {
		jsonOut(w, a.Status, map[string]any{"error": a.Message, "code": a.Code, "gatewayId": a.Gateway})
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(e, &pgErr) {
		log.Printf("remote-access SQL failure: code=%s message=%s table=%s", pgErr.Code, pgErr.Message, pgErr.TableName)
	} else {
		log.Printf("remote-access internal failure type=%T", e)
	}
	jsonOut(w, 500, map[string]any{"error": "服务端操作失败；请用请求时间联系管理员", "code": "internal_error"})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return fail(415, "content_type", "需要 application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		var too *http.MaxBytesError
		if errors.As(e, &too) {
			return fail(413, "body_limit", "请求超过上限")
		}
		return fail(400, "invalid_json", "JSON 类型、字段或内容无效")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return fail(400, "invalid_json", "请求只能包含一个 JSON 对象")
	}
	return nil
}
func marshal(v any) []byte { b, _ := json.Marshal(v); return b }
func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
func bounded(s string, n int) bool {
	return strings.TrimSpace(s) != "" && len(s) <= n && !strings.ContainsAny(s, "\x00\r\n")
}

type User struct {
	ID         string    `json:"id"`
	Workspace  string    `json:"workspace"`
	Username   string    `json:"username"`
	Name       string    `json:"displayName"`
	Role       string    `json:"role"`
	Enabled    bool      `json:"enabled"`
	Version    int64     `json:"-"`
	MustChange bool      `json:"mustChangePassword"`
	LoginHash  string    `json:"-"`
	CSRF       string    `json:"-"`
	Reauth     time.Time `json:"-"`
}

var rolePerms = map[string][]string{
	"admin":         {"user.manage", "group.manage", "asset.view", "asset.manage", "asset.test", "remoteAccount.view", "remoteAccount.manage", "grant.view", "grant.manage", "session.viewAll", "session.terminate", "audit.read", "connector.pair", "connector.revoke"},
	"asset_manager": {"asset.view", "asset.manage", "asset.test", "remoteAccount.view", "remoteAccount.manage", "grant.view", "grant.manage", "connector.pair", "connector.revoke"},
	"operator":      {"asset.view", "remoteAccount.view", "connector.pair", "connector.revoke"},
	"auditor":       {"audit.read"},
}

func has(u *User, p string) bool { return contains(rolePerms[u.Role], p) }
func require(u *User, p string) error {
	if !has(u, p) {
		return fail(403, "permission_denied", "没有此操作权限")
	}
	return nil
}

type Limits struct {
	ReadRoots        []string `json:"readRoots"`
	WriteRoots       []string `json:"writeRoots"`
	MaxFileBytes     int64    `json:"maxFileBytes"`
	MaxTotalBytes    int64    `json:"maxTotalBytes"`
	MaxFiles         int      `json:"maxFiles"`
	MaxDepth         int      `json:"maxDepth"`
	MaxConcurrent    int      `json:"maxConcurrent"`
	AllowOverwrite   bool     `json:"allowOverwrite"`
	AllowInteractive bool     `json:"allowInteractive"`
}
type Policy struct {
	Actions, Protocols []string
	Limits             Limits
	Version            string
}
type Endpoint struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Gateway  string `json:"gatewayId"`
	Version  int64  `json:"version"`
}
type Account struct {
	ID                string   `json:"id"`
	Asset             string   `json:"assetId"`
	Name              string   `json:"name"`
	Username          string   `json:"username"`
	AuthType          string   `json:"authType"`
	Protocols         []string `json:"protocols"`
	Enabled           bool     `json:"enabled"`
	Archived          bool     `json:"archived"`
	CredentialVersion int64    `json:"credentialVersion"`
	Version           int64    `json:"version"`
}
type Secret struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type App struct {
	instanceID    string
	leaseLost     atomic.Bool
	Config        Config
	DB            *pgxpool.Pool
	mu            sync.Mutex
	sessions      map[string]*SSHSession
	transferLocks map[string]*sync.Mutex
	attempts      map[string][]time.Time
	fileSlots     map[string]int
	bandwidthNext map[string]time.Time
	dummyHash     string
	cancel        context.CancelFunc
}

func New(ctx context.Context, c Config) (*App, error) {
	if c.MaxSFTP < 1 {
		c.MaxSFTP = 32
	}
	if c.MaxSSH < 1 {
		c.MaxSSH = 128
	}
	if c.Bandwidth < 65536 {
		c.Bandwidth = 16777216
	}
	pool, e := pgxpool.New(ctx, c.DatabaseURL)
	if e != nil {
		return nil, e
	}
	if e = pool.Ping(ctx); e != nil {
		pool.Close()
		return nil, e
	}
	dummy, _ := PasswordHash(ID())
	a := &App{instanceID: ID(), fileSlots: map[string]int{}, bandwidthNext: map[string]time.Time{}, Config: c, DB: pool, sessions: map[string]*SSHSession{}, transferLocks: map[string]*sync.Mutex{}, attempts: map[string][]time.Time{}, dummyHash: dummy}
	return a, nil
}
func (a *App) Close() {
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Lock()
	for _, s := range a.sessions {
		s.terminate("gateway_shutdown")
	}
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = a.DB.Exec(ctx, "UPDATE ra_gateway_leases SET expires_at=now() WHERE gateway_id=$1 AND instance_id=$2", a.Config.GatewayID, a.instanceID)
	a.DB.Close()
}
func (a *App) audit(ctx context.Context, u *User, action, object, result, corr string, details any) error {
	_, e := a.store(ctx).Exec(ctx, "INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,correlation_id,details) VALUES($1,$2,$3,$4,$5,$6,$7)", u.Workspace, u.ID, action, object, result, corr, marshal(details))
	return e
}
func (a *App) list(ctx context.Context, q string, args ...any) ([]map[string]any, error) {
	rows, e := a.store(ctx).Query(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	names := rows.FieldDescriptions()
	for rows.Next() {
		vs, e := rows.Values()
		if e != nil {
			return nil, e
		}
		m := map[string]any{}
		for i, n := range names {
			m[n.Name] = vs[i]
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (a *App) sessionUser(ctx context.Context, r *http.Request) (*User, error) {
	c, e := r.Cookie("infra_session")
	if e != nil {
		return nil, fail(401, "not_authenticated", "请先登录")
	}
	u := new(User)
	h := digest(c.Value)
	e = a.store(ctx).QueryRow(ctx, `SELECT u.id,u.workspace,u.username,u.display_name,u.role,u.enabled,u.auth_version,u.must_change_password,s.csrf,s.reauth_at FROM ra_login_sessions s JOIN ra_users u ON u.id=s.user_id AND u.workspace=s.workspace WHERE s.id_hash=$1 AND s.expires_at>now() AND u.enabled AND s.auth_version=u.auth_version`, h).Scan(&u.ID, &u.Workspace, &u.Username, &u.Name, &u.Role, &u.Enabled, &u.Version, &u.MustChange, &u.CSRF, &u.Reauth)
	if e != nil {
		return nil, fail(401, "session_expired", "登录已失效")
	}
	u.LoginHash = h
	return u, nil
}
func (a *App) origin(r *http.Request) bool { return r.Header.Get("Origin") == a.Config.Origin }
func (a *App) guard(fn func(http.ResponseWriter, *http.Request, *User) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.leaseLost.Load() {
			errorOut(w, fail(503, "gateway_lease_lost", "网关所有权租约已失效"))
			return
		}
		if !a.Config.Enabled {
			errorOut(w, fail(503, "module_disabled", "远程接入模块未启用"))
			return
		}
		u, e := a.sessionUser(r.Context(), r)
		if e == nil && r.Method != "GET" && r.Method != "HEAD" && (!a.origin(r) || !equal(r.Header.Get("X-CSRF-Token"), u.CSRF)) {
			e = fail(403, "csrf", "请求来源或 CSRF 校验失败")
		}
		if e == nil && u.MustChange && r.URL.Path != "/api/remote-access/auth/password" && r.URL.Path != "/api/remote-access/auth/me" && r.URL.Path != "/api/remote-access/auth/logout" {
			e = fail(403, "password_change_required", "请先设置自己的密码")
		}
		if e == nil {
			e = fn(w, r, u)
		}
		if e != nil {
			errorOut(w, e)
		}
	}
}
func (a *App) rate(key string, n int, window time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	old := a.attempts[key]
	kept := old[:0]
	for _, t := range old {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= n {
		return false
	}
	a.attempts[key] = append(kept, now)
	if len(a.attempts) > 20000 {
		for k, v := range a.attempts {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > time.Hour {
				delete(a.attempts, k)
			}
		}
	}
	return true
}
func (a *App) target(ctx context.Context, ep Endpoint) (string, error) {
	if ep.Gateway != a.Config.GatewayID {
		return "", gatewayError(ep.Gateway)
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", ep.Host)
	if e != nil || len(ips) == 0 {
		return "", fail(502, "dns_failure", "目标名称解析失败")
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return "", fail(403, "egress_denied", "目标地址被网关策略阻止")
		}
		allowed := false
		for _, p := range a.Config.Allowed {
			if p.Contains(ip) {
				allowed = true
			}
		}
		if !allowed {
			return "", fail(403, "egress_denied", "目标不在明确允许的网段中")
		}
		if !a.Config.LoopbackTest {
			addrs, _ := net.InterfaceAddrs()
			for _, addr := range addrs {
				if local, _, err := net.ParseCIDR(addr.String()); err == nil && local.String() == ip.String() {
					return "", fail(403, "egress_denied", "禁止访问网关自身地址")
				}
			}
		}
		if ip.IsLoopback() && !a.Config.LoopbackTest {
			return "", fail(403, "egress_denied", "禁止访问网关回环地址")
		}
	}
	// Pin the resolved address; the SSH library must not repeat DNS resolution.
	return net.JoinHostPort(ips[0].Unmap().String(), strconv.Itoa(ep.Port)), nil
}
func (a *App) endpoint(ctx context.Context, u *User, asset, protocol string) (Endpoint, error) {
	var ep Endpoint
	e := a.store(ctx).QueryRow(ctx, `SELECT e.id,e.protocol,e.host,e.port,e.gateway_id,e.version FROM ra_endpoints e JOIN ra_assets a ON a.id=e.asset_id AND a.workspace=e.workspace WHERE e.workspace=$1 AND e.asset_id=$2 AND e.protocol=$3 AND a.enabled AND NOT a.archived`, u.Workspace, asset, protocol).Scan(&ep.ID, &ep.Protocol, &ep.Host, &ep.Port, &ep.Gateway, &ep.Version)
	if e != nil {
		return ep, fail(404, "endpoint_unavailable", "资产未启用该协议")
	}
	return ep, nil
}
func (a *App) account(ctx context.Context, u *User, id string) (Account, error) {
	var x Account
	var p []byte
	e := a.store(ctx).QueryRow(ctx, `SELECT id,asset_id,name,username,auth_type,protocols,enabled,archived,credential_version,version FROM ra_accounts WHERE workspace=$1 AND id=$2`, u.Workspace, id).Scan(&x.ID, &x.Asset, &x.Name, &x.Username, &x.AuthType, &p, &x.Enabled, &x.Archived, &x.CredentialVersion, &x.Version)
	if e != nil {
		return x, fail(404, "account_not_found", "远程账号不可用")
	}
	if e = json.Unmarshal(p, &x.Protocols); e != nil {
		return x, e
	}
	if !x.Enabled || x.Archived {
		return x, fail(403, "account_disabled", "远程账号已停用")
	}
	return x, nil
}
func (a *App) secret(ctx context.Context, u *User, account Account) (Secret, error) {
	var s Secret
	if account.AuthType == "interactive" {
		return s, nil
	}
	var ct, nonce []byte
	var key string
	var version int64
	e := a.store(ctx).QueryRow(ctx, "SELECT ciphertext,nonce,key_version,version FROM ra_secrets WHERE workspace=$1 AND account_id=$2", u.Workspace, account.ID).Scan(&ct, &nonce, &key, &version)
	if e != nil || version != account.CredentialVersion {
		return s, fail(409, "credential_unavailable", "凭据缺失或版本已变更")
	}
	e = unseal(a.Config.Keys[key], nonce, ct, u.Workspace+":"+account.ID+":"+strconv.FormatInt(version, 10), &s)
	if e != nil {
		return s, fail(503, "key_unavailable", "凭据密钥不可用")
	}
	return s, nil
}
func (a *App) policy(ctx context.Context, u *User, account Account, protocol, action string) (Policy, error) {
	if u.Role == "auditor" {
		return Policy{}, fail(403, "read_only_role", "审计员不能连接主机或读取文件内容")
	}
	p := Policy{Limits: Limits{MaxFileBytes: 1 << 30, MaxTotalBytes: 10 << 30, MaxFiles: 10000, MaxDepth: 32, MaxConcurrent: 3}}
	if !contains(account.Protocols, protocol) {
		return p, fail(403, "protocol_denied", "账号未启用此协议")
	}
	var usable bool
	var assetVersion int64
	if e := a.store(ctx).QueryRow(ctx, "SELECT enabled AND NOT archived,version FROM ra_assets WHERE workspace=$1 AND id=$2", u.Workspace, account.Asset).Scan(&usable, &assetVersion); e != nil || !usable {
		return p, fail(403, "asset_disabled", "资产已停用")
	}
	rows, e := a.store(ctx).Query(ctx, `SELECT id,version,actions,protocols,limits FROM ra_grants WHERE workspace=$1 AND account_id=$2 AND asset_id=$3 AND NOT revoked AND starts_at<=now() AND expires_at>now() AND (user_id=$4 OR group_id IN (SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$4)) ORDER BY id`, u.Workspace, account.ID, account.Asset, u.ID)
	if e != nil {
		return p, e
	}
	defer rows.Close()
	versions := []string{fmt.Sprintf("account:%d:asset:%d", account.Version, assetVersion)}
	for rows.Next() {
		var id string
		var v int64
		var acts, protos, lim []byte
		if e = rows.Scan(&id, &v, &acts, &protos, &lim); e != nil {
			return p, e
		}
		var as, ps []string
		var l Limits
		if json.Unmarshal(acts, &as) != nil || json.Unmarshal(protos, &ps) != nil || json.Unmarshal(lim, &l) != nil {
			continue
		}
		if !contains(ps, protocol) {
			continue
		}
		versions = append(versions, fmt.Sprintf("%s:%d", id, v))
		p.Actions = append(p.Actions, as...)
		p.Protocols = append(p.Protocols, ps...)
		if contains(as, action) {
			p.Limits.ReadRoots = append(p.Limits.ReadRoots, l.ReadRoots...)
			p.Limits.WriteRoots = append(p.Limits.WriteRoots, l.WriteRoots...)
			p.Limits.MaxFileBytes = min(p.Limits.MaxFileBytes, l.MaxFileBytes)
			p.Limits.MaxTotalBytes = min(p.Limits.MaxTotalBytes, l.MaxTotalBytes)
			p.Limits.MaxFiles = min(p.Limits.MaxFiles, l.MaxFiles)
			p.Limits.MaxDepth = min(p.Limits.MaxDepth, l.MaxDepth)
			p.Limits.MaxConcurrent = min(p.Limits.MaxConcurrent, l.MaxConcurrent)
			p.Limits.AllowOverwrite = p.Limits.AllowOverwrite || l.AllowOverwrite
			p.Limits.AllowInteractive = p.Limits.AllowInteractive || l.AllowInteractive
		}
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	if !contains(p.Actions, "remoteAccount.use") || !contains(p.Actions, action) {
		return p, fail(403, "grant_denied", "没有有效的账号与操作授权")
	}
	p.Version = digest(strings.Join(versions, "|"))
	return p, nil
}
func (a *App) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/") {
		http.NotFound(w, r)
		return
	}
	if p == "/" {
		p = "/index.html"
	}
	base, e := filepath.Abs(a.Config.StaticDir)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(base, filepath.Clean("/"+p))
	rel, e := filepath.Rel(base, path)
	if e != nil || strings.HasPrefix(rel, "..") || strings.Contains(p, "\x00") {
		http.Error(w, "Forbidden", 403)
		return
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	resolvedRel, e := filepath.Rel(base, resolved)
	if e != nil || strings.HasPrefix(resolvedRel, "..") {
		http.Error(w, "Forbidden", 403)
		return
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "display-capture=(self)")
	http.ServeFile(w, r, path)
}

func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
