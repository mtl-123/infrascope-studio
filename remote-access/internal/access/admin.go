package access

import (
	"net/http"
)

func (a *App) adminSessions(w http.ResponseWriter, r *http.Request, u *User) error {
	if e := require(u, "session.viewAll"); e != nil {
		return e
	}
	if r.Method == "GET" {
		v, e := a.list(r.Context(), "SELECT id,user_id,asset_id,account_id,gateway_id,state,created_at,ended_at,reason FROM ra_remote_sessions WHERE workspace=$1 ORDER BY created_at DESC LIMIT 500", u.Workspace)
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	if e := require(u, "session.terminate"); e != nil {
		return e
	}
	var gateway string
	if e := a.DB.QueryRow(r.Context(), "SELECT gateway_id FROM ra_remote_sessions WHERE workspace=$1 AND id=$2", u.Workspace, r.PathValue("id")).Scan(&gateway); e != nil {
		return fail(404, "session_not_found", "会话不存在")
	}
	if gateway != a.Config.GatewayID {
		return fail(503, "gateway_route_required", "请请求会话所属网关")
	}
	a.mu.Lock()
	s := a.sessions[r.PathValue("id")]
	a.mu.Unlock()
	if s != nil {
		s.terminate("admin_terminated")
	}
	if e := a.audit(r.Context(), u, "session.terminate", r.PathValue("id"), "success", "", map[string]any{}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) grantSubjects(w http.ResponseWriter, r *http.Request, u *User) error {
	if e := require(u, "grant.manage"); e != nil {
		return e
	}
	users, e := a.list(r.Context(), "SELECT id,username,display_name,role FROM ra_users WHERE workspace=$1 AND enabled AND role<>'auditor' ORDER BY username LIMIT 1000", u.Workspace)
	if e != nil {
		return e
	}
	groups, e := a.list(r.Context(), "SELECT id,name FROM ra_groups WHERE workspace=$1 ORDER BY name LIMIT 1000", u.Workspace)
	if e != nil {
		return e
	}
	jsonOut(w, 200, map[string]any{"users": users, "groups": groups})
	return nil
}
func (a *App) hideTransfer(w http.ResponseWriter, r *http.Request, u *User) error {
	res, e := a.DB.Exec(r.Context(), "UPDATE ra_transfers SET hidden_from_list=true WHERE workspace=$1 AND user_id=$2 AND id=$3 AND state IN('completed','partial','failed','cancelled')", u.Workspace, u.ID, r.PathValue("id"))
	if e != nil {
		return e
	}
	if res.RowsAffected() != 1 {
		return fail(409, "task_state", "只能清除本人的已结束任务显示记录")
	}
	if e = a.audit(r.Context(), u, "transfer.hide", r.PathValue("id"), "success", "", map[string]any{"remoteFilesDeleted": false}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}
