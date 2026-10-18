package access

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pkg/sftp"
)

type txContextKey struct{}
type queryRunner interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (a *App) store(ctx context.Context) queryRunner {
	if tx, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok {
		return tx
	}
	return a.DB
}
func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	p := "/api/remote-access"
	m.HandleFunc("POST "+p+"/auth/login", a.login)
	m.HandleFunc("GET "+p+"/auth/me", a.guard(a.me))
	m.HandleFunc("POST "+p+"/auth/logout", a.guard(a.logout))
	m.HandleFunc("POST "+p+"/auth/reauth", a.guard(a.reauth))
	m.HandleFunc("POST "+p+"/auth/password", a.guard(a.password))
	m.HandleFunc("GET "+p+"/users", a.guard(a.users))
	m.HandleFunc("POST "+p+"/users", a.guard(a.users))
	m.HandleFunc("PATCH "+p+"/users/{id}", a.guard(a.users))
	m.HandleFunc("GET "+p+"/people", a.guard(a.people))
	m.HandleFunc("POST "+p+"/people", a.guard(a.people))
	m.HandleFunc("PATCH "+p+"/people/{id}", a.guard(a.people))
	m.HandleFunc("GET "+p+"/groups", a.guard(a.groups))
	m.HandleFunc("POST "+p+"/groups", a.guard(a.groups))
	m.HandleFunc("PATCH "+p+"/groups/{id}", a.guard(a.groups))
	m.HandleFunc("GET "+p+"/assets", a.guard(a.assets))
	m.HandleFunc("POST "+p+"/assets", a.guard(a.assets))
	m.HandleFunc("GET "+p+"/assets/{id}", a.guard(a.assets))
	m.HandleFunc("PATCH "+p+"/assets/{id}", a.guard(a.assets))
	m.HandleFunc("GET "+p+"/assets/{id}/ownership-history", a.guard(a.ownershipHistory))
	m.HandleFunc("GET "+p+"/asset-groups", a.guard(a.assetGroups))
	m.HandleFunc("POST "+p+"/asset-groups", a.guard(a.assetGroups))
	m.HandleFunc("PATCH "+p+"/asset-groups/{id}", a.guard(a.assetGroups))
	m.HandleFunc("GET /api/v1/assets", a.guard(a.assets))
	m.HandleFunc("POST /api/v1/assets", a.guard(a.assets))
	m.HandleFunc("GET /api/v1/assets/export", a.guard(a.exportAssets))
	m.HandleFunc("GET /api/v1/assets/{id}", a.guard(a.assets))
	m.HandleFunc("PATCH /api/v1/assets/{id}", a.guard(a.assets))
	m.HandleFunc("GET /api/v1/assets/{id}/remote-readiness", a.guard(a.remoteReadiness))
	m.HandleFunc("POST "+p+"/accounts/{id}/grant-self", a.guard(a.grantSelf))
	m.HandleFunc("POST /api/v1/servers/onboard", a.guard(a.onboardServer))
	m.HandleFunc("GET "+p+"/organizations", a.guard(a.organizations))
	m.HandleFunc("POST "+p+"/organizations", a.guard(a.organizations))
	m.HandleFunc("PATCH "+p+"/organizations/{id}", a.guard(a.organizations))
	m.HandleFunc("GET "+p+"/organizations/options", a.guard(a.organizationOptions))
	m.HandleFunc("GET /api/v1/asset-imports", a.guard(a.importJobs))
	m.HandleFunc("GET /api/v1/asset-imports/{id}", a.guard(a.importJobs))
	m.HandleFunc("POST /api/v1/asset-imports/preview", a.guard(a.previewImport))
	m.HandleFunc("POST /api/v1/asset-imports/{id}/confirm", a.guard(a.confirmImport))
	m.HandleFunc("POST /api/v1/asset-imports/{id}/cancel", a.guard(a.cancelImport))
	m.HandleFunc("POST /api/v1/discovery/local-preview", a.guard(a.previewLocalDiscovery))
	m.HandleFunc("POST /api/v1/agents/enrollments", a.guard(a.agentEnrollments))
	m.HandleFunc("POST /api/v1/agents/enroll", a.agentEnroll)
	m.HandleFunc("POST /api/v1/agent/config", a.agentSignedRoute)
	m.HandleFunc("POST /api/v1/agent/samples", a.agentSignedRoute)
	m.HandleFunc("GET /api/v1/agents", a.guard(a.agents))
	m.HandleFunc("PATCH /api/v1/agents/{id}/config", a.guard(a.agentConfig))
	m.HandleFunc("POST /api/v1/agents/{id}/revoke", a.guard(a.revokeAgent))
	m.HandleFunc("GET /api/v1/assets/{id}/telemetry", a.guard(a.assetTelemetry))
	m.HandleFunc("POST "+p+"/assets/{id}/host-key/probe", a.guard(a.hostKeys))
	m.HandleFunc("POST "+p+"/assets/{id}/host-key/approve", a.guard(a.hostKeys))
	m.HandleFunc("POST "+p+"/assets/{id}/test", a.guard(a.testEndpoint))
	m.HandleFunc("GET "+p+"/assets/{asset}/accounts", a.guard(a.accounts))
	m.HandleFunc("POST "+p+"/assets/{asset}/accounts", a.guard(a.accounts))
	m.HandleFunc("GET "+p+"/accounts/{id}", a.guard(a.accounts))
	m.HandleFunc("PATCH "+p+"/accounts/{id}", a.guard(a.accounts))
	m.HandleFunc("POST "+p+"/accounts/{id}/credential", a.guard(a.credential))
	m.HandleFunc("POST "+p+"/accounts/{id}/test", a.guard(a.testAccount))
	m.HandleFunc("GET "+p+"/grant-subjects", a.guard(a.grantSubjects))
	m.HandleFunc("GET "+p+"/grants", a.guard(a.grants))
	m.HandleFunc("POST "+p+"/grants", a.guard(a.grants))
	m.HandleFunc("PATCH "+p+"/grants/{id}", a.guard(a.grants))
	m.HandleFunc("DELETE "+p+"/grants/{id}", a.guard(a.grants))
	m.HandleFunc("GET "+p+"/my/access", a.guard(a.myAccess))
	m.HandleFunc("POST "+p+"/ssh/sessions", a.guard(a.newSSH))
	m.HandleFunc("GET "+p+"/ssh/sessions", a.guard(a.sessionInfo))
	m.HandleFunc("GET "+p+"/ssh/sessions/{id}", a.guard(a.sessionInfo))
	m.HandleFunc("DELETE "+p+"/ssh/sessions/{id}", a.guard(a.sessionInfo))
	m.HandleFunc("POST "+p+"/ssh/sessions/{id}/attach-authorizations", a.guard(a.attachAuthorization))
	m.HandleFunc("GET "+p+"/ssh/sessions/{id}/stream", a.guard(a.stream))
	m.HandleFunc("GET "+p+"/sftp/entries", a.guard(a.entries))
	m.HandleFunc("POST "+p+"/sftp/directories", a.guard(a.fileOperation))
	m.HandleFunc("POST "+p+"/sftp/rename", a.guard(a.fileOperation))
	m.HandleFunc("POST "+p+"/sftp/delete", a.guard(a.fileOperation))
	m.HandleFunc("POST "+p+"/transfers", a.guard(a.transfers))
	m.HandleFunc("GET "+p+"/transfers", a.guard(a.transfers))
	m.HandleFunc("GET "+p+"/transfers/{id}", a.guard(a.transfers))
	m.HandleFunc("POST "+p+"/transfers/{id}/items", a.guard(a.manifest))
	m.HandleFunc("PUT "+p+"/transfers/{id}/items/{item}/content", a.guard(a.upload))
	m.HandleFunc("POST "+p+"/transfers/{id}/commit", a.guard(a.commitTransfer))
	m.HandleFunc("POST "+p+"/transfers/{id}/cancel", a.guard(a.cancelTransfer))
	m.HandleFunc("GET "+p+"/transfers/{id}/content", a.guard(a.download))
	m.HandleFunc("GET "+p+"/my/connectors", a.guard(a.connectors))
	m.HandleFunc("POST "+p+"/connectors/{id}/revoke", a.guard(a.connectors))
	m.HandleFunc("POST "+p+"/connectors/pairing-challenges", a.guard(a.pairChallenge))
	m.HandleFunc("POST "+p+"/connector/pair", a.pairDevice)
	m.HandleFunc("POST "+p+"/connector/{operation}", a.deviceRoute)
	m.HandleFunc("GET "+p+"/rdp/launches", a.guard(a.rdpLaunch))
	m.HandleFunc("GET "+p+"/rdp/launches/{id}", a.guard(a.rdpLaunch))
	m.HandleFunc("POST "+p+"/rdp/launches", a.guard(a.rdpLaunch))
	m.HandleFunc("GET "+p+"/audit-events", a.guard(a.auditList))
	m.HandleFunc("GET "+p+"/admin/sessions", a.guard(a.adminSessions))
	m.HandleFunc("DELETE "+p+"/admin/sessions/{id}", a.guard(a.adminSessions))
	m.HandleFunc("POST "+p+"/transfers/{id}/hide", a.guard(a.hideTransfer))
	m.HandleFunc("POST "+p+"/transfers/{id}/control", a.guard(a.transferControl))
	m.HandleFunc("GET "+p+"/health", a.guard(a.health))
	m.HandleFunc("/gateways/{gateway}/", a.routeGateway)
	m.HandleFunc("/", a.static)
	return m
}
func (a *App) testEndpoint(w http.ResponseWriter, r *http.Request, u *User) error {
	if e := require(u, "asset.test"); e != nil {
		return e
	}
	if e := a.manageAsset(r.Context(), u, r.PathValue("id")); e != nil {
		return e
	}
	if !a.rate("endpoint-test:"+u.ID, 10, time.Minute) {
		return fail(429, "test_throttled", "测试过于频繁")
	}
	var in struct {
		Protocol string `json:"protocol"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	ep, e := a.endpoint(r.Context(), u, r.PathValue("id"), in.Protocol)
	if e != nil {
		return e
	}
	if in.Protocol == "rdp" {
		jsonOut(w, 200, map[string]any{"status": "not_tested", "reason": "RDP 必须从选定用户电脑验证；中央网关的 TCP 可达不代表用户电脑可达"})
		return nil
	}
	target, e := a.target(r.Context(), ep)
	if e != nil {
		return e
	}
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(r.Context(), "tcp", target)
	if e != nil {
		return fail(502, "tcp_unreachable", "网关到端点的 TCP 连接失败")
	}
	conn.Close()
	jsonOut(w, 200, map[string]any{"status": "tcp_reachable", "authenticated": false, "gatewayId": a.Config.GatewayID})
	return nil
}
func (a *App) testAccount(w http.ResponseWriter, r *http.Request, u *User) error {
	x, e := a.account(r.Context(), u, r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = a.manageAsset(r.Context(), u, x.Asset); e != nil {
		return e
	}
	if !a.rate("account-test:"+u.ID, 5, time.Minute) {
		return fail(429, "test_throttled", "认证测试过于频繁")
	}
	var in struct {
		Protocol string `json:"protocol"`
	}
	if e = decode(w, r, &in); e != nil {
		return e
	}
	if !contains(x.Protocols, in.Protocol) || !contains([]string{"ssh", "sftp"}, in.Protocol) {
		return fail(400, "test_protocol", "此接口只验证 SSH/SFTP 账号；RDP 通过本机连接器验证启动")
	}
	ep, e := a.endpoint(r.Context(), u, x.Asset, in.Protocol)
	if e != nil {
		return e
	}
	client, e := a.dialSSH(r.Context(), u, x, ep)
	if e != nil {
		return e
	}
	defer client.Close()
	if in.Protocol == "sftp" {
		s, e := sftp.NewClient(client)
		if e != nil {
			return fail(502, "sftp_unavailable", "SSH 认证成功，但 SFTP 子系统不可用")
		}
		s.Close()
	}
	if e = a.audit(r.Context(), u, "account.test", x.ID, "authenticated", "", map[string]string{"protocol": in.Protocol}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]any{"status": "authenticated", "protocol": in.Protocol, "shellExecuted": false})
	return nil
}
func (a *App) health(w http.ResponseWriter, r *http.Request, u *User) error {
	if !has(u, "audit.read") && !has(u, "asset.manage") {
		return fail(403, "permission_denied", "无权查看网关指标")
	}
	ctx := r.Context()
	var active, tasks, cleanup, online int
	var bytes int64
	if e := a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_remote_sessions WHERE gateway_id=$1 AND state='ready'", a.Config.GatewayID).Scan(&active); e != nil {
		return e
	}
	if e := a.DB.QueryRow(ctx, "SELECT count(*) FILTER(WHERE state IN('running','paused','scanning','queued')),COALESCE(sum(done_bytes),0)::bigint FROM ra_transfers WHERE gateway_id=$1", a.Config.GatewayID).Scan(&tasks, &bytes); e != nil {
		return e
	}
	if e := a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_transfer_items i JOIN ra_transfers t ON t.id=i.task_id WHERE t.gateway_id=$1 AND t.state IN('failed','cancelled') AND i.temp_path IS NOT NULL", a.Config.GatewayID).Scan(&cleanup); e != nil {
		return e
	}
	if e := a.DB.QueryRow(ctx, "SELECT count(*) FROM ra_connectors WHERE workspace=$1 AND NOT revoked AND last_seen>now()-interval '20 seconds'", u.Workspace).Scan(&online); e != nil {
		return e
	}
	failures, e := a.list(ctx, "SELECT reason,count(*) AS count FROM ra_remote_sessions WHERE gateway_id=$1 AND ended_at>now()-interval '24 hours' GROUP BY reason ORDER BY count(*) DESC", a.Config.GatewayID)
	if e != nil {
		return e
	}
	versions, e := a.list(ctx, "SELECT version,count(*) AS count FROM ra_connectors WHERE workspace=$1 AND NOT revoked GROUP BY version", u.Workspace)
	if e != nil {
		return e
	}
	a.mu.Lock()
	sftpChannels := a.fileSlots["gateway"]
	a.mu.Unlock()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	jsonOut(w, 200, map[string]any{"gatewayId": a.Config.GatewayID, "gatewayLeaseLost": a.leaseLost.Load(), "sshSessions": active, "sftpChannels": sftpChannels, "activeOrWaitingFileTasks": tasks, "bytesConfirmedAllRecordedTasks": bytes, "cleanupPending": cleanup, "onlineConnectors": online, "connectorVersions": versions, "sessionEndReasons24h": failures, "heapBytes": mem.Alloc, "goroutines": runtime.NumGoroutine(), "revocationPollSeconds": a.Config.RevokePoll, "userFileBandwidthBytesPerSecond": a.Config.Bandwidth, "limits": map[string]int{"gatewaySSH": a.Config.MaxSSH, "gatewaySFTP": a.Config.MaxSFTP, "userSSH": a.Config.MaxSessions, "userFileTasks": a.Config.MaxTransfers}, "localFileArchiveSpooling": false})
	return nil
}
