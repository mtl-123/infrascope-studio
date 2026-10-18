package access

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

func (a *App) Bootstrap(ctx context.Context, username, name, password string) error {
	if !bounded(username, 120) || !bounded(name, 120) {
		return fail(400, "invalid_user", "用户名与显示名无效")
	}
	hash, e := PasswordHash(password)
	if e != nil {
		return e
	}
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "LOCK TABLE ra_users IN EXCLUSIVE MODE"); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM ra_users").Scan(&n); e != nil {
		return e
	}
	if n != 0 {
		return fail(409, "already_initialized", "已有用户，不能再次初始化")
	}
	_, e = tx.Exec(ctx, "INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5,'admin')", ID(), a.Config.Workspace, username, name, hash)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Enabled {
		errorOut(w, fail(503, "module_disabled", "模块未启用"))
		return
	}
	if !a.origin(r) {
		errorOut(w, fail(403, "origin", "请求来源无效"))
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if e := decode(w, r, &in); e != nil {
		errorOut(w, e)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !a.rate("login-ip:"+ip, 30, 15*time.Minute) || !a.rate("login-user:"+strings.ToLower(in.Username), 10, 15*time.Minute) {
		errorOut(w, fail(429, "login_throttled", "登录尝试过多，请稍后再试"))
		return
	}
	ctx := r.Context()
	var u User
	var hash string
	e := a.store(ctx).QueryRow(ctx, "SELECT id,workspace,username,display_name,password_hash,role,enabled,auth_version,must_change_password FROM ra_users WHERE workspace=$1 AND username=$2", a.Config.Workspace, in.Username).Scan(&u.ID, &u.Workspace, &u.Username, &u.Name, &hash, &u.Role, &u.Enabled, &u.Version, &u.MustChange)
	if e != nil {
		hash = a.dummyHash
	}
	ok := passwordOK(hash, in.Password)
	in.Password = ""
	if e != nil || !ok || !u.Enabled {
		_ = a.audit(ctx, &User{ID: "anonymous", Workspace: a.Config.Workspace}, "login", "", "denied", "", map[string]string{"reason": "invalid_credentials"})
		errorOut(w, fail(401, "invalid_credentials", "登录信息无效"))
		return
	}
	token := ID()
	csrf := ID()
	_, e = a.store(ctx).Exec(ctx, "INSERT INTO ra_login_sessions(id_hash,workspace,user_id,auth_version,csrf,expires_at) VALUES($1,$2,$3,$4,$5,$6)", digest(token), u.Workspace, u.ID, u.Version, csrf, time.Now().Add(time.Duration(a.Config.SessionHours)*time.Hour))
	if e != nil {
		errorOut(w, e)
		return
	}
	if e = a.audit(ctx, &u, "login", u.ID, "success", "", map[string]any{}); e != nil {
		errorOut(w, e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "infra_session", Value: token, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.Config.Origin, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: a.Config.SessionHours * 3600})
	jsonOut(w, 200, map[string]any{"id": u.ID, "displayName": u.Name, "role": u.Role, "mustChangePassword": u.MustChange, "csrf": csrf})
}
func (a *App) me(w http.ResponseWriter, r *http.Request, u *User) error {
	jsonOut(w, 200, map[string]any{"id": u.ID, "username": u.Username, "displayName": u.Name, "workspace": u.Workspace, "role": u.Role, "permissions": rolePerms[u.Role], "csrf": u.CSRF, "mustChangePassword": u.MustChange, "gatewayId": a.Config.GatewayID})
	return nil
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, u *User) error {
	if _, e := a.DB.Exec(r.Context(), "DELETE FROM ra_login_sessions WHERE id_hash=$1", u.LoginHash); e != nil {
		return e
	}
	a.terminateLogin(u.LoginHash, "logout")
	if e := a.audit(r.Context(), u, "logout", u.ID, "success", "", map[string]any{}); e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: "infra_session", Value: "", Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.Config.Origin, "https://"), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) reauth(w http.ResponseWriter, r *http.Request, u *User) error {
	var in struct {
		Password string `json:"password"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !a.rate("reauth:"+u.ID, 5, 5*time.Minute) {
		return fail(429, "throttled", "验证过于频繁")
	}
	var hash string
	if e := a.DB.QueryRow(r.Context(), "SELECT password_hash FROM ra_users WHERE id=$1", u.ID).Scan(&hash); e != nil {
		return e
	}
	if !passwordOK(hash, in.Password) {
		return fail(403, "reauth_failed", "重新验证失败")
	}
	_, e := a.DB.Exec(r.Context(), "UPDATE ra_login_sessions SET reauth_at=now() WHERE id_hash=$1", u.LoginHash)
	if e != nil {
		return e
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
	return nil
}
func recent(u *User) error {
	if time.Since(u.Reauth) > 5*time.Minute {
		return fail(403, "reauth_required", "请重新验证平台密码后继续")
	}
	return nil
}
func (a *App) password(w http.ResponseWriter, r *http.Request, u *User) error {
	var in struct {
		Current string `json:"currentPassword"`
		New     string `json:"newPassword"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !a.rate("password:"+u.ID, 5, 5*time.Minute) {
		return fail(429, "throttled", "操作过于频繁")
	}
	var hash string
	if e := a.DB.QueryRow(r.Context(), "SELECT password_hash FROM ra_users WHERE id=$1", u.ID).Scan(&hash); e != nil {
		return e
	}
	if !passwordOK(hash, in.Current) {
		return fail(403, "reauth_failed", "当前密码无效")
	}
	next, e := PasswordHash(in.New)
	if e != nil {
		return e
	}
	tx, e := a.DB.Begin(r.Context())
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "UPDATE ra_users SET password_hash=$1,auth_version=auth_version+1,must_change_password=false WHERE id=$2", next, u.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM ra_login_sessions WHERE user_id=$1", u.ID); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	a.terminateUser(u.ID, "password_changed")
	if e = a.audit(r.Context(), u, "password.change", u.ID, "success", "", map[string]any{}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]bool{"ok": true, "loginRequired": true})
	return nil
}
func (a *App) users(w http.ResponseWriter, r *http.Request, u *User) error {
	if e := require(u, "user.manage"); e != nil {
		return e
	}
	ctx := r.Context()
	if r.Method == "GET" {
		v, e := a.list(ctx, "SELECT id,username,display_name,role,enabled,must_change_password,created_at FROM ra_users WHERE workspace=$1 ORDER BY username", u.Workspace)
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	if e := recent(u); e != nil {
		return e
	}
	var in struct {
		Username string `json:"username"`
		Name     string `json:"displayName"`
		Role     string `json:"role"`
		Password string `json:"initialPassword"`
		Enabled  *bool  `json:"enabled"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	id := r.PathValue("id")
	if id == "" {
		if !bounded(in.Username, 120) || !bounded(in.Name, 120) || rolePerms[in.Role] == nil {
			return fail(400, "invalid_user", "用户字段无效")
		}
		hash, e := PasswordHash(in.Password)
		if e != nil {
			return e
		}
		id = ID()
		if _, e = a.store(ctx).Exec(ctx, "INSERT INTO ra_users(id,workspace,username,display_name,password_hash,role,must_change_password) VALUES($1,$2,$3,$4,$5,$6,true)", id, u.Workspace, in.Username, in.Name, hash, in.Role); e != nil {
			return fail(409, "user_conflict", "用户名已存在或保存失败")
		}
	} else {
		var role string
		var enabled bool
		if e := a.store(ctx).QueryRow(ctx, "SELECT role,enabled FROM ra_users WHERE workspace=$1 AND id=$2", u.Workspace, id).Scan(&role, &enabled); e != nil {
			return fail(404, "user_not_found", "用户不存在")
		}
		if id == u.ID && (in.Enabled != nil && !*in.Enabled || in.Role != "" && in.Role != "admin") {
			return fail(409, "self_lockout", "不能在当前会话停用或降级自己")
		}
		if in.Role != "" && rolePerms[in.Role] == nil {
			return fail(400, "invalid_role", "角色无效")
		}
		if in.Role == "" {
			in.Role = role
		}
		if in.Enabled == nil {
			in.Enabled = &enabled
		}
		tx, e := a.DB.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, "UPDATE ra_users SET role=$1,enabled=$2,auth_version=auth_version+1 WHERE workspace=$3 AND id=$4", in.Role, *in.Enabled, u.Workspace, id); e != nil {
			return e
		}
		if in.Password != "" {
			hash, e := PasswordHash(in.Password)
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, "UPDATE ra_users SET password_hash=$1,must_change_password=true WHERE id=$2", hash, id); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, "DELETE FROM ra_login_sessions WHERE user_id=$1", id); e != nil {
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		a.terminateUser(id, "user_policy_changed")
	}
	if e := a.audit(ctx, u, "user.save", id, "success", "", map[string]any{"role": in.Role}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}
func (a *App) groups(w http.ResponseWriter, r *http.Request, u *User) error {
	if e := require(u, "group.manage"); e != nil {
		return e
	}
	ctx := r.Context()
	if r.Method == "GET" {
		v, e := a.list(ctx, `SELECT g.id,g.name,COALESCE((SELECT json_agg(m.user_id) FROM ra_group_members m WHERE m.group_id=g.id),'[]') AS members FROM ra_groups g WHERE g.workspace=$1 ORDER BY name`, u.Workspace)
		if e != nil {
			return e
		}
		jsonOut(w, 200, v)
		return nil
	}
	var in struct {
		Name    string   `json:"name"`
		Members []string `json:"members"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !bounded(in.Name, 120) || len(in.Members) > 500 {
		return fail(400, "group_invalid", "用户组无效")
	}
	id := r.PathValue("id")
	tx, e := a.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if id == "" {
		id = ID()
		_, e = tx.Exec(ctx, "INSERT INTO ra_groups(id,workspace,name) VALUES($1,$2,$3)", id, u.Workspace, in.Name)
	} else {
		res, err := tx.Exec(ctx, "UPDATE ra_groups SET name=$1 WHERE workspace=$2 AND id=$3", in.Name, u.Workspace, id)
		e = err
		if e == nil && res.RowsAffected() != 1 {
			return fail(404, "group_not_found", "用户组不存在")
		}
	}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "DELETE FROM ra_group_members WHERE workspace=$1 AND group_id=$2", u.Workspace, id); e != nil {
		return e
	}
	for _, uid := range in.Members {
		if _, e = tx.Exec(ctx, "INSERT INTO ra_group_members(workspace,group_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", u.Workspace, id, uid); e != nil {
			return fail(400, "group_member_invalid", "成员不存在或不属于当前组织")
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	if e = a.audit(ctx, u, "group.save", id, "success", "", map[string]any{"members": len(in.Members)}); e != nil {
		return e
	}
	jsonOut(w, 200, map[string]string{"id": id})
	return nil
}
