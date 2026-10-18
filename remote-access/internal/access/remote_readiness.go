package access

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

type remoteAccountReadiness struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Username             string   `json:"username"`
	AuthType             string   `json:"authType"`
	CredentialConfigured bool     `json:"credentialConfigured"`
	Authorized           bool     `json:"authorized"`
	State                string   `json:"state"`
	Reason               string   `json:"reason"`
	Actions              []string `json:"actions"`
}

type remoteProtocolReadiness struct {
	Protocol string                   `json:"protocol"`
	Endpoint *Endpoint                `json:"endpoint"`
	State    string                   `json:"state"`
	Reason   string                   `json:"reason"`
	Accounts []remoteAccountReadiness `json:"accounts"`
}

type remoteAssetReadiness struct {
	AssetID        string                    `json:"assetId"`
	AssetName      string                    `json:"assetName"`
	OSFamily       string                    `json:"osFamily"`
	CanManage      bool                      `json:"canManage"`
	CanGrantSelf   bool                      `json:"canGrantSelf"`
	Protocols      []remoteProtocolReadiness `json:"protocols"`
	ConnectorReady bool                      `json:"connectorReady"`
}

type readinessAccount struct {
	Account
	credentialConfigured bool
	credentialKey        string
}

// This is a metadata preflight, not a network probe, credential check or grant.
// Real connection handlers must recheck every permission and connection policy.
func (a *App) remoteReadiness(w http.ResponseWriter, r *http.Request, u *User) error {
	assets, err := a.queryAssets(r, u, 1, false)
	if err != nil {
		return err
	}
	if len(assets) == 0 || r.PathValue("id") == "" {
		return fail(404, "asset_not_found", "资产不存在或无权访问")
	}
	asset := assets[0]
	out := remoteAssetReadiness{AssetID: r.PathValue("id"), Protocols: []remoteProtocolReadiness{}, CanGrantSelf: u.Role == "admin"}
	out.AssetName, _ = asset["name"].(string)
	out.OSFamily, _ = asset["os_family"].(string)
	out.CanManage, _ = asset["canManage"].(bool)
	enabled, _ := asset["enabled"].(bool)
	archived, _ := asset["archived"].(bool)
	var endpoints []Endpoint
	if err = json.Unmarshal(marshal(asset["endpoints"]), &endpoints); err != nil {
		return err
	}
	accounts, err := a.readinessAccounts(r.Context(), u, out.AssetID, out.CanManage)
	if err != nil {
		return err
	}
	out.ConnectorReady, err = a.readinessConnector(r.Context(), u)
	if err != nil {
		return err
	}
	for _, protocol := range []string{"ssh", "sftp", "rdp"} {
		p := remoteProtocolReadiness{Protocol: protocol, Accounts: []remoteAccountReadiness{}}
		for i := range endpoints {
			if endpoints[i].Protocol == protocol {
				p.Endpoint = &endpoints[i]
				break
			}
		}
		baseState, baseReason := "", ""
		switch {
		case !enabled || archived:
			baseState, baseReason = "asset_disabled", "资产已停用或归档，不能远程接入"
		case p.Endpoint == nil:
			baseState, baseReason = "needs_endpoint", "请先配置此协议的服务器地址与端口"
		}
		trusted := false
		if p.Endpoint != nil && protocol != "rdp" {
			err = a.store(r.Context()).QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM ra_host_keys WHERE workspace=$1 AND endpoint_id=$2)`, u.Workspace, p.Endpoint.ID).Scan(&trusted)
			if err != nil {
				return err
			}
		}
		for _, account := range accounts {
			if !contains(account.Protocols, protocol) {
				continue
			}
			entry, err := a.readinessForAccount(r.Context(), u, account, p.Endpoint, protocol, baseState, baseReason, trusted, out.ConnectorReady)
			if err != nil {
				return err
			}
			if !out.CanManage && !entry.Authorized {
				continue
			}
			p.Accounts = append(p.Accounts, entry)
		}
		p.State, p.Reason = baseState, baseReason
		if p.State == "" {
			p.State, p.Reason = "needs_account", "没有可用的此协议远程账号；管理资产并不自动授予远程权限"
			for _, account := range p.Accounts {
				if readinessRank(account.State) > readinessRank(p.State) {
					p.State, p.Reason = account.State, account.Reason
				}
			}
		}
		out.Protocols = append(out.Protocols, p)
	}
	jsonOut(w, http.StatusOK, out)
	return nil
}

func (a *App) readinessAccounts(ctx context.Context, u *User, asset string, canManage bool) ([]readinessAccount, error) {
	rows, err := a.store(ctx).Query(ctx, `SELECT x.id,x.asset_id,x.name,x.username,x.auth_type,x.protocols,x.enabled,x.archived,x.credential_version,x.version,
 EXISTS(SELECT 1 FROM ra_secrets s WHERE s.workspace=x.workspace AND s.account_id=x.id AND s.version=x.credential_version),
 COALESCE((SELECT s.key_version FROM ra_secrets s WHERE s.workspace=x.workspace AND s.account_id=x.id AND s.version=x.credential_version),'')
 FROM ra_accounts x WHERE x.workspace=$1 AND x.asset_id=$2 AND ($3 OR ($5<>'auditor' AND x.enabled AND NOT x.archived AND EXISTS(
 SELECT 1 FROM ra_grants g WHERE g.workspace=x.workspace AND g.asset_id=x.asset_id AND g.account_id=x.id
 AND NOT g.revoked AND g.starts_at<=now() AND g.expires_at>now() AND g.actions ? 'remoteAccount.use'
 AND (g.user_id=$4 OR g.group_id IN(SELECT group_id FROM ra_group_members WHERE workspace=$1 AND user_id=$4)))))
 ORDER BY x.name,x.id`, u.Workspace, asset, canManage, u.ID, u.Role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := []readinessAccount{}
	for rows.Next() {
		var account readinessAccount
		var protocols []byte
		if err = rows.Scan(&account.ID, &account.Asset, &account.Name, &account.Username, &account.AuthType, &protocols, &account.Enabled, &account.Archived, &account.CredentialVersion, &account.Version, &account.credentialConfigured, &account.credentialKey); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(protocols, &account.Protocols); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (a *App) readinessForAccount(ctx context.Context, u *User, account readinessAccount, endpoint *Endpoint, protocol, baseState, baseReason string, trusted, connector bool) (remoteAccountReadiness, error) {
	out := remoteAccountReadiness{ID: account.ID, Name: account.Name, Username: account.Username, AuthType: account.AuthType, CredentialConfigured: account.credentialConfigured, Actions: []string{}}
	action := map[string]string{"ssh": "ssh.connect", "sftp": "sftp.list", "rdp": "rdp.launch"}[protocol]
	policy, err := a.policy(ctx, u, account.Account, protocol, action)
	if err != nil {
		var denied *apiError
		if !errors.As(err, &denied) {
			return out, err
		}
	}
	out.Authorized = err == nil && account.Enabled && !account.Archived
	if out.Authorized {
		for _, action := range policy.Actions {
			if !contains(out.Actions, action) {
				out.Actions = append(out.Actions, action)
			}
		}
	}
	gatewayState, gatewayReason := "", ""
	if endpoint != nil && protocol != "rdp" {
		exact, permitErr := a.exactEndpointPermit(ctx, *endpoint)
		if permitErr != nil {
			return out, permitErr
		}
		if exact {
			// The permit narrows one endpoint; retain all reserved/self-address checks.
			config := a.Config
			ip, parseErr := netip.ParseAddr(endpoint.Host)
			if parseErr != nil {
				return out, parseErr
			}
			config.Allowed = []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}
			checker := &App{Config: config}
			gatewayState, gatewayReason = checker.readinessGateway(*endpoint)
		} else {
			gatewayState, gatewayReason = a.readinessGateway(*endpoint)
		}
	}
	switch {
	case baseState != "":
		out.State, out.Reason = baseState, baseReason
	case !account.Enabled || account.Archived:
		out.State, out.Reason = "needs_account", "此远程账号已停用或归档"
	case account.AuthType != "interactive" && !account.credentialConfigured:
		out.State, out.Reason = "needs_credential", "请为远程账号单独保存服务器密码或私钥；平台登录密码不能代替远程凭据"
	case account.AuthType != "interactive" && len(a.Config.Keys[account.credentialKey]) != 32:
		out.State, out.Reason = "needs_credential", "已保存凭据所需的解密密钥不可用，请联系管理员"
	case !out.Authorized:
		out.State, out.Reason = "needs_grant", "当前登录用户没有此账号与协议的有效操作授权；不会自动授权"
	case account.AuthType == "interactive" && !policy.Limits.AllowInteractive:
		out.State, out.Reason = "needs_grant", "交互式 RDP 账号还需要明确授权允许交互凭据"
	case protocol == "sftp" && len(policy.Limits.ReadRoots) == 0:
		out.State, out.Reason = "needs_grant", "此 SFTP 授权未配置可读取的绝对根目录，请由管理员明确目录范围"
	case gatewayState != "":
		out.State, out.Reason = gatewayState, gatewayReason
	case protocol != "rdp" && !trusted:
		out.State, out.Reason = "needs_host_key", "请先核对并确认服务器主机指纹；本检查不会自动信任指纹"
	case protocol == "rdp" && !connector:
		out.State, out.Reason = "needs_connector", "请在自己 Windows 电脑配对当前浏览器的在线连接器并配置签名；不会替你选择设备或启动远程桌面"
		if origin, err := url.Parse(a.Config.Origin); err != nil || origin.Scheme != "https" {
			out.Reason = "本地开发 HTTP 尚不支持受控连接器配对；需配置受信任 HTTPS 平台，再在本人 Windows 电脑配对当前浏览器"
		}
	default:
		out.State, out.Reason = "ready_to_attempt", "配置允许发起尝试；尚未拨号、校验远程密码或证明连接成功"
		if protocol == "rdp" {
			out.Reason = "请选择已绑定的 Windows 设备后发起尝试；尚未启动 mstsc 或验证远程登录"
		} else if _, err := netip.ParseAddr(endpoint.Host); err != nil {
			out.Reason += "；DNS 解析与所有解析地址的网段校验将在实际连接时执行"
		} else if endpoint.Gateway != a.Config.GatewayID {
			out.Reason += "；所属网关的可达性与出站策略将在实际连接时校验"
		}
	}
	return out, nil
}

func readinessRank(state string) int {
	return map[string]int{"asset_disabled": 0, "needs_endpoint": 1, "needs_account": 2, "needs_credential": 3, "needs_grant": 4, "needs_gateway_policy": 5, "needs_host_key": 6, "needs_connector": 7, "ready_to_attempt": 8}[state]
}

func (a *App) readinessGateway(endpoint Endpoint) (string, string) {
	return a.readinessGatewayWithInterfaces(endpoint, net.InterfaceAddrs)
}

func (a *App) readinessGatewayWithInterfaces(endpoint Endpoint, interfaces func() ([]net.Addr, error)) (string, string) {
	if endpoint.Gateway != a.Config.GatewayID {
		if a.Config.Peers[endpoint.Gateway] == "" {
			return "needs_gateway_policy", "所属网关未配置可信路由，不能发起连接"
		}
		return "", ""
	}
	if len(a.Config.Allowed) == 0 {
		return "needs_gateway_policy", "网关尚未明确允许任何目标网段，请由管理员配置目标网段；不会自动放开所有地址"
	}
	ip, err := netip.ParseAddr(endpoint.Host)
	if err != nil {
		// Do not resolve hostnames here. Actual dialing resolves and validates all IPs.
		return "", ""
	}
	ip = ip.Unmap()
	if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() && !a.Config.LoopbackTest {
		return "needs_gateway_policy", "该目标地址被网关出站策略禁止"
	}
	for _, prefix := range a.Config.Allowed {
		if prefix.Contains(ip) {
			if !a.Config.LoopbackTest {
				addrs, err := interfaces()
				if err != nil {
					return "needs_gateway_policy", "无法枚举网关本机接口，尚不能确认目标是否被自身地址策略禁止"
				}
				for _, addr := range addrs {
					if local, _, err := net.ParseCIDR(addr.String()); err == nil && local.String() == ip.String() {
						return "needs_gateway_policy", "禁止连接网关自身地址，请使用其他服务器地址"
					}
				}
			}
			return "", ""
		}
	}
	return "needs_gateway_policy", "目标 IP 不在明确允许的网段中，请联系管理员核对出站策略"
}

func (a *App) readinessConnector(ctx context.Context, u *User) (bool, error) {
	if !has(u, "connector.pair") || u.LoginHash == "" {
		return false, nil
	}
	if origin, err := url.Parse(a.Config.Origin); err != nil || origin.Scheme != "https" {
		return false, nil
	}
	rows, err := a.store(ctx).Query(ctx, `SELECT c.version,c.capabilities FROM ra_connectors c WHERE c.workspace=$1 AND c.user_id=$2
 AND NOT c.revoked AND c.approved_origin=$4 AND c.last_seen>now()-interval '20 seconds'
 AND EXISTS(SELECT 1 FROM ra_browser_bindings b WHERE b.workspace=c.workspace AND b.user_id=c.user_id AND b.connector_id=c.id
 AND b.login_id_hash=$3 AND NOT b.revoked AND b.expires_at>now())`, u.Workspace, u.ID, u.LoginHash, a.Config.Origin)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	ready := false
	for rows.Next() {
		var version string
		var raw []byte
		if err = rows.Scan(&version, &raw); err != nil {
			return false, err
		}
		var capabilities map[string]any
		if err = json.Unmarshal(raw, &capabilities); err != nil {
			return false, err
		}
		valid := strings.TrimSpace(version) != ""
		for _, key := range []string{"ok", "credentialApi", "mstsc", "rdpsign"} {
			if capabilities[key] != true {
				valid = false
			}
		}
		signing, signingReported := capabilities["signing"].(map[string]any)
		valid = valid && signingReported && signing["ok"] == true && signing["configured"] == true
		ready = ready || valid
	}
	return ready, rows.Err()
}
