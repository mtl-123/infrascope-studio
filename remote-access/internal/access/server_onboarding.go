package access

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"
)

type serverOnboardingInput struct {
	IdempotencyKey   string    `json:"idempotencyKey"`
	Confirm          bool      `json:"confirm"`
	Name             string    `json:"name"`
	OSFamily         string    `json:"osFamily"`
	Host             string    `json:"host"`
	SSHPort          int       `json:"sshPort"`
	SFTPPort         int       `json:"sftpPort"`
	RDPPort          int       `json:"rdpPort"`
	Protocols        []string  `json:"protocols"`
	Username         string    `json:"username"`
	AuthType         string    `json:"authType"`
	Secret           Secret    `json:"secret"`
	ClaimantID       string    `json:"claimantId"`
	OrganizationID   *string   `json:"organizationId"`
	ReadRoots        []string  `json:"readRoots"`
	WriteRoots       []string  `json:"writeRoots"`
	AllowFileWrite   bool      `json:"allowFileWrite"`
	AllowClipboard   bool      `json:"allowClipboard"`
	AllowDrives      bool      `json:"allowDrives"`
	AllowInteractive bool      `json:"allowInteractive"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

func (a *App) validateServerOnboarding(in *serverOnboardingInput) ([]Endpoint, []string, error) {
	if !in.Confirm || !bounded(in.IdempotencyKey, 120) || strings.TrimSpace(in.IdempotencyKey) != in.IdempotencyKey {
		return nil, nil, fail(400, "onboarding_confirmation", "请明确确认创建服务器、保存凭据、仅授权本人并放行该 IP 和所选端口")
	}
	in.Name, in.Username = strings.TrimSpace(in.Name), strings.TrimSpace(in.Username)
	if !bounded(in.Name, 180) || !contains([]string{"linux", "windows"}, in.OSFamily) || !bounded(in.ClaimantID, 120) {
		return nil, nil, fail(400, "onboarding_invalid", "请填写服务器名称、系统类型并明确选择有效责任人")
	}
	ip, err := netip.ParseAddr(in.Host)
	if err != nil || ip.Zone() != "" {
		return nil, nil, fail(400, "onboarding_ip", "快捷添加需填写明确的 IPv4 或 IPv6 地址；域名请使用资产高级配置")
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip == netip.MustParseAddr("255.255.255.255") {
		return nil, nil, fail(400, "onboarding_ip", "不能放行未指定、组播、广播或链路本地目标地址")
	}
	if !a.Config.LoopbackTest {
		if ip.IsLoopback() {
			return nil, nil, fail(400, "onboarding_ip", "不能连接网关回环地址")
		}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return nil, nil, err
		}
		for _, local := range addrs {
			if prefix, err := netip.ParsePrefix(local.String()); err == nil && prefix.Addr().Unmap() == ip {
				return nil, nil, fail(400, "onboarding_ip", "不能连接网关自身地址")
			}
		}
	}
	in.Host = ip.String()
	if len(in.Protocols) < 1 || len(in.Protocols) > 3 {
		return nil, nil, fail(400, "onboarding_protocol", "请选择 SSH、SFTP 或 RDP")
	}
	sort.Strings(in.Protocols)
	for i, protocol := range in.Protocols {
		if !contains([]string{"ssh", "sftp", "rdp"}, protocol) || i > 0 && in.Protocols[i-1] == protocol {
			return nil, nil, fail(400, "onboarding_protocol", "协议无效或重复")
		}
	}
	if !contains([]string{"password", "private_key", "interactive"}, in.AuthType) || !optionalText(in.Username, 512) || in.AuthType != "interactive" && !bounded(in.Username, 512) {
		return nil, nil, fail(400, "onboarding_account", "请输入有效远程用户名及认证方式")
	}
	switch in.AuthType {
	case "password":
		if len(in.Secret.Password) < 1 || len(in.Secret.Password) > 2048 || strings.ContainsRune(in.Secret.Password, '\x00') || in.Secret.PrivateKey != "" || in.Secret.Passphrase != "" {
			return nil, nil, fail(400, "credential_invalid", "请填写有效密码；密码模式不能同时提交私钥或私钥口令")
		}
		if contains(in.Protocols, "rdp") && len(utf16.Encode([]rune(in.Secret.Password)))*2 > 2560 {
			return nil, nil, fail(400, "credential_invalid", "RDP 密码超过 Windows 凭据存储的 2560 字节 UTF-16 限制")
		}
	case "private_key":
		if contains(in.Protocols, "rdp") || len(in.Secret.PrivateKey) > 65536 || len(in.Secret.Passphrase) > 2048 || in.Secret.Password != "" {
			return nil, nil, fail(400, "credential_invalid", "私钥仅支持 SSH/SFTP，且不能同时提交密码")
		}
		if in.Secret.Passphrase != "" {
			_, err = ssh.ParsePrivateKeyWithPassphrase([]byte(in.Secret.PrivateKey), []byte(in.Secret.Passphrase))
		} else {
			_, err = ssh.ParsePrivateKey([]byte(in.Secret.PrivateKey))
		}
		if err != nil {
			return nil, nil, fail(400, "private_key_invalid", "私钥格式或口令无效")
		}
	case "interactive":
		if len(in.Protocols) != 1 || in.Protocols[0] != "rdp" || !in.AllowInteractive || in.Secret != (Secret{}) {
			return nil, nil, fail(400, "interactive_confirmation", "交互模式仅支持 RDP，须明确允许 Windows 凭据提示且不提交任何凭据")
		}
	}
	for _, roots := range [][]string{in.ReadRoots, in.WriteRoots} {
		if len(roots) > 10 {
			return nil, nil, fail(400, "onboarding_roots", "每种文件目录最多 10 项")
		}
		for _, root := range roots {
			if len(root) > 2048 || !validRemoteRoot(root) {
				return nil, nil, fail(400, "onboarding_roots", "SFTP 需要明确的有效绝对目录")
			}
		}
	}
	if contains(in.Protocols, "sftp") && len(in.ReadRoots) == 0 || in.AllowFileWrite && len(in.WriteRoots) == 0 || !in.AllowFileWrite && len(in.WriteRoots) > 0 {
		return nil, nil, fail(400, "onboarding_roots", "请选择 SFTP 可读目录；文件写入必须明确确认并填写可写目录")
	}
	if !contains(in.Protocols, "sftp") && (len(in.ReadRoots) > 0 || len(in.WriteRoots) > 0 || in.AllowFileWrite) || !contains(in.Protocols, "rdp") && (in.AllowClipboard || in.AllowDrives || in.AllowInteractive) {
		return nil, nil, fail(400, "onboarding_options", "权限选项与所选协议不一致")
	}
	if in.SSHPort == 0 {
		in.SSHPort = 22
	}
	if in.SFTPPort == 0 {
		in.SFTPPort = in.SSHPort
	}
	if in.RDPPort == 0 {
		in.RDPPort = 3389
	}
	endpoints := make([]Endpoint, 0, len(in.Protocols))
	actions := []string{"asset.view", "remoteAccount.view", "remoteAccount.use"}
	for _, protocol := range in.Protocols {
		port := map[string]int{"ssh": in.SSHPort, "sftp": in.SFTPPort, "rdp": in.RDPPort}[protocol]
		if port < 1 || port > 65535 {
			return nil, nil, fail(400, "onboarding_port", "所选协议端口必须介于 1 和 65535 之间")
		}
		endpoints = append(endpoints, Endpoint{Protocol: protocol, Host: in.Host, Port: port, Gateway: a.Config.GatewayID})
		switch protocol {
		case "ssh":
			actions = append(actions, "ssh.connect", "ssh.resume", "ssh.close")
		case "sftp":
			actions = append(actions, "sftp.list", "sftp.download")
			if in.AllowFileWrite {
				actions = append(actions, "sftp.upload", "sftp.mkdir", "sftp.rename", "sftp.delete")
			}
		case "rdp":
			actions = append(actions, "rdp.launch")
			if in.AllowClipboard {
				actions = append(actions, "rdp.clipboard")
			}
			if in.AllowDrives {
				actions = append(actions, "rdp.driveRedirect")
			}
		}
	}
	return endpoints, actions, nil
}

func serverOnboardingHash(key []byte, workspace, user string, in serverOnboardingInput) string {
	// A plain password-bearing digest would permit offline password guessing.
	h := hmac.New(sha256.New, key)
	h.Write([]byte("infrascope.server-onboarding.v1\x00" + workspace + "\x00" + user + "\x00"))
	h.Write(marshal(in))
	return hex.EncodeToString(h.Sum(nil))
}

func (a *App) onboardServer(w http.ResponseWriter, r *http.Request, u *User) error {
	if u.Role != "admin" {
		return fail(403, "onboarding_denied", "快捷添加并授权本人仅限平台管理员")
	}
	if err := recent(u); err != nil {
		return err
	}
	var in serverOnboardingInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	defer func() { in.Secret = Secret{} }()
	endpoints, actions, err := a.validateServerOnboarding(&in)
	if err != nil {
		return err
	}
	key := a.Config.Keys[a.Config.ActiveKey]
	if len(key) != 32 {
		return fail(503, "credential_key_unavailable", "凭据加密密钥不可用；未创建服务器")
	}
	requestHash := serverOnboardingHash(key, u.Workspace, u.ID, in)
	ctx := r.Context()
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('server-onboarding:'||$1||':'||$2||':'||$3,0))`, u.Workspace, u.ID, in.IdempotencyKey); err != nil {
		return err
	}
	next := "verify_host_key"
	if !contains(in.Protocols, "ssh") && !contains(in.Protocols, "sftp") {
		next = "select_connector"
	}
	var asset, account, grant, priorHash, hashKeyVersion string
	err = tx.QueryRow(ctx, `SELECT request_hash,hash_key_version,asset_id,account_id,grant_id FROM ra_server_onboarding_requests WHERE workspace=$1 AND user_id=$2 AND idempotency_key=$3`, u.Workspace, u.ID, in.IdempotencyKey).Scan(&priorHash, &hashKeyVersion, &asset, &account, &grant)
	if err == nil {
		priorKey := a.Config.Keys[hashKeyVersion]
		if len(priorKey) != 32 || !hmac.Equal([]byte(priorHash), []byte(serverOnboardingHash(priorKey, u.Workspace, u.ID, in))) {
			return fail(409, "idempotency_conflict", "此请求已用于不同参数，或原加密密钥已移除；请核对现有服务器，不要重复创建")
		}
		jsonOut(w, 200, map[string]any{"assetId": asset, "accountId": account, "grantId": grant, "created": false, "next": next})
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if !in.ExpiresAt.After(time.Now()) || in.ExpiresAt.After(time.Now().Add(30*24*time.Hour)) {
		return fail(400, "onboarding_expiry", "本人授权须在未来到期且最长不超过 30 天")
	}
	asset, err = a.saveAsset(ctx, tx, u, "", AssetInput{
		Name: in.Name, Kind: "physical", OS: in.OSFamily, Enabled: true,
		OrganizationID: in.OrganizationID, Ownership: &Ownership{State: "pending", ClaimantID: in.ClaimantID},
		Tags: []string{}, Metadata: map[string]string{}, Endpoints: endpoints,
	})
	if err != nil {
		return err
	}
	account, grant = ID(), ID()
	credentialVersion := int64(0)
	if in.AuthType != "interactive" {
		credentialVersion = 1
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_accounts(id,workspace,asset_id,name,username,auth_type,protocols,credential_version,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, account, u.Workspace, asset, "Server account", in.Username, in.AuthType, marshal(in.Protocols), credentialVersion, u.ID); err != nil {
		return err
	}
	if credentialVersion != 0 {
		ct, nonce, err := seal(key, u.Workspace+":"+account+":1", in.Secret)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ra_secrets(workspace,account_id,ciphertext,nonce,key_version,version,updated_by) VALUES($1,$2,$3,$4,$5,1,$6)`, u.Workspace, account, ct, nonce, a.Config.ActiveKey, u.ID); err != nil {
			return err
		}
	}
	in.Secret = Secret{}
	limits := Limits{ReadRoots: in.ReadRoots, WriteRoots: in.WriteRoots, MaxFileBytes: 1 << 30, MaxTotalBytes: 10 << 30, MaxFiles: 10000, MaxDepth: 32, MaxConcurrent: 3, AllowInteractive: in.AllowInteractive}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_grants(id,workspace,user_id,asset_id,account_id,actions,protocols,limits,starts_at,expires_at,granted_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),$9,$3)`, grant, u.Workspace, u.ID, asset, account, marshal(actions), marshal(in.Protocols), marshal(limits), in.ExpiresAt); err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		if _, err = tx.Exec(ctx, `INSERT INTO ra_asset_egress(workspace,asset_id,protocol,host,port,created_by) VALUES($1,$2,$3,$4,$5,$6)`, u.Workspace, asset, endpoint.Protocol, endpoint.Host, endpoint.Port, u.ID); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_server_onboarding_requests(workspace,user_id,idempotency_key,request_hash,hash_key_version,asset_id,account_id,grant_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, u.Workspace, u.ID, in.IdempotencyKey, requestHash, a.Config.ActiveKey, asset, account, grant); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ra_audit_events(workspace,actor_id,action,object_id,result,details) VALUES($1,$2,'server.onboard',$3,'success',$4)`, u.Workspace, u.ID, asset, marshal(map[string]any{"accountId": account, "grantId": grant, "protocols": in.Protocols, "host": in.Host, "endpoints": endpoints, "expiresAt": in.ExpiresAt, "explicitConfirmation": true, "networkScope": "exact-asset-protocol-ip-port", "connectionVerified": false})); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	jsonOut(w, 200, map[string]any{"assetId": asset, "accountId": account, "grantId": grant, "created": true, "next": next})
	return nil
}
