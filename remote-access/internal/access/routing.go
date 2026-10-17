package access

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func gatewayError(id string) error {
	return &apiError{Status: 503, Code: "gateway_route_required", Message: "请求需要路由到资源所属网关", Gateway: id}
}
func (a *App) routeGateway(w http.ResponseWriter, r *http.Request) {
	if !a.Config.Enabled {
		errorOut(w, fail(503, "module_disabled", "模块未启用"))
		return
	}
	u, e := a.sessionUser(r.Context(), r)
	if e != nil {
		errorOut(w, e)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && (!a.origin(r) || !equal(r.Header.Get("X-CSRF-Token"), u.CSRF)) {
		errorOut(w, fail(403, "csrf", "来源或 CSRF 校验失败"))
		return
	}
	id := r.PathValue("gateway")
	prefix := "/gateways/" + id
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if !strings.HasPrefix(rest, "/api/remote-access/") {
		http.NotFound(w, r)
		return
	}
	if id == a.Config.GatewayID {
		clone := r.Clone(r.Context())
		u2 := *r.URL
		u2.Path = rest
		u2.RawPath = ""
		clone.URL = &u2
		a.Handler().ServeHTTP(w, clone)
		return
	}
	destination, ok := a.Config.Peers[id]
	if !ok {
		errorOut(w, fail(503, "gateway_offline", "所属网关未在可信路由表中配置"))
		return
	}
	target, e := url.Parse(destination)
	if e != nil {
		errorOut(w, fail(503, "gateway_configuration", "网关路由配置无效"))
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	original := proxy.Director
	proxy.Director = func(req *http.Request) {
		req.URL.Path = rest
		req.URL.RawPath = ""
		original(req)
		req.Host = target.Host
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Host")
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		errorOut(w, fail(503, "gateway_offline", "所属网关暂时不可达；不会自动重建原会话"))
	}
	proxy.FlushInterval = -1
	proxy.ServeHTTP(w, r)
}
