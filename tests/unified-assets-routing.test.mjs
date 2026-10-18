import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import core from "../dist/remote-assets-core.js";

const source = readFileSync(new URL("../dist/remote-access.js", import.meta.url), "utf8");
const app = readFileSync(new URL("../dist/app.js", import.meta.url), "utf8");
const pending = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const response = (body, status = 200, type = "application/json") => ({ ok: status < 400, status, json: async () => body,
  headers: { get: () => type }, blob: async () => new Blob([String(body)]) });
const admin = { role: "admin", displayName: "Admin", csrf: "csrf", permissions: ["asset.manage", "remoteAccount.manage", "user.manage", "group.manage"] };
const asset = (id, canManage = false) => ({ id, name: "Real " + id, category: "server", kind: "physical", os_family: "linux", enabled: true,
  archived: false, version: 2, endpoints: [{ protocol: "ssh", host: "127.0.0.1", port: 22 }], ownership: { state: "pending", claimantId: "person-1" }, canManage });

// Lightweight DOM harness exercises async behavior; it does not claim browser/layout validation.
class Element {
  constructor() {
    this.dataset = {}; this.children = new Map(); this.isConnected = true; this.disabled = false; this.value = "";
    this.classList = { add() {}, remove() {}, toggle() {} }; this.options = [];
  }
  set innerHTML(value) {
    this.html = value; this.children.clear();
    this.options = [...value.matchAll(/<option value="([^"]*)"([^>]*)>(.*?)<\/option>/gs)].map((match) => ({ value: match[1], selected: /selected/.test(match[2]) }));
  }
  get innerHTML() { return this.html || ""; }
  get selectedOptions() { return this.options.filter((option) => option.selected); }
  querySelector(selector) {
    if (!this.children.has(selector)) {
      const element = new Element();
      const name = selector.match(/^\[name="([^"]+)"\]$/)?.[1];
      if (name) {
        const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const select = this.innerHTML.match(new RegExp(`<select name="${escaped}"[^>]*>([\\s\\S]*?)</select>`));
        if (select) element.innerHTML = select[1];
      }
      this.children.set(selector, element);
    }
    return this.children.get(selector);
  }
  querySelectorAll() { return []; }
  append(element) { this.dialog = element; }
  showModal() { this.open = true; }
  close() { this.open = false; this.onclose?.(); }
  remove() { this.isConnected = false; }
  addEventListener() {}
  click() { this.clicked = true; this.onclick?.(); }
}

function runtime(handler = async () => response([])) {
  const root = new Element(), calls = [], created = [];
  const window = { addEventListener() {}, InfraRemoteAssets: core };
  const document = { getElementById: (id) => id === "io-content" ? root : null, createElement: () => { const element = new Element(); created.push(element); return element; } };
  const context = vm.createContext({ window, document, crypto: { randomUUID: () => "test" }, URL, URLSearchParams, Blob, Date, console,
    location: { search: "", origin: "http://localhost", href: "http://localhost/#devices" }, setInterval: () => 1, clearInterval() {}, setTimeout: () => 1,
    fetch: async (url, options) => { calls.push({ url, options }); return handler(url, options); },
    FormData: class { constructor(form) { return form; } } });
  vm.runInContext(source.replace("window.InfraRemote = { render, leave };", "window.InfraRemote = { render, leave, show, S, assetParams, assetGroupEditor, assetDetails, assetTelemetry, agentEnrollment, exportAssets, passwordDialog, click, assetManage, setup: (element) => { root = element; view = element.querySelector('#ra-body'); } };"), context);
  const api = window.InfraRemote;
  api.setup(root); api.S.mounted = true; api.S.user = structuredClone(admin);
  const target = () => root.querySelector("#ra-view");
  return { api, root, calls, created, context, target };
}

test("original devices and directory navigation use the shared authenticated renderer, including failure without demo fallback", () => {
  for (const [page, expected] of [["devices", "assets"], ["directory", "people"], ["agents", "agents"], ["remote-access", undefined]]) {
    const renders = [], root = new Element(), content = new Element();
    root.querySelector = (selector) => selector === "#io-content" ? content : new Element();
    const base = { document: { getElementById: () => root, createElement: () => new Element() }, location: { hash: "#" + page }, history: { replaceState() {} }, window: {
      InfraRemote: { render: (...args) => renders.push(args), leave() { assert.fail("must remain mounted"); } },
      InfraInventory: { render() { assert.fail("must not route to demo inventory"); } },
      InfraWorkspace: { render() { assert.fail("must not route to demo directory"); } },
    } };
    vm.runInNewContext(app, base);
    assert.equal(renders[0][0], expected);
    base.window.InfraRemote = undefined;
    vm.runInNewContext(app, base);
    assert.match(content.innerHTML, /不会使用演示资产或人员作为替代/);
  }
});

test("asset read scopes never imply asset or remote-account management, even for another asset manager", async () => {
  const env = runtime(async () => response([asset("owned", true), asset("visible")]));
  env.api.S.user.role = "asset_manager";
  await env.api.show("assets");
  const html = env.target().innerHTML;
  assert.match(env.calls[0].url, /^\/api\/v1\/assets\?/);
  for (const action of ["asset-edit", "accounts", "hostkey", "asset-test", "ownership-history"]) {
    assert.match(html, new RegExp(`data-ra="${action}" data-id="owned"`));
    assert.doesNotMatch(html, new RegExp(`data-ra="${action}" data-id="visible"`));
  }
  assert.match(html, /data-ra="asset-detail" data-id="visible"/);
  env.api.S.user.permissions = ["asset.manage"];
  await env.api.show("assets");
  assert.doesNotMatch(env.target().innerHTML, /data-ra="accounts"/);
});

test("agent page reads canonical assets and only exposes enrollment to managers", async () => {
  const env = runtime(async () => response([asset("owned", true), asset("read-only")]));
  await env.api.show("agents");
  assert.match(env.calls[0].url, /^\/api\/v1\/assets\?/);
  assert.match(env.target().innerHTML, /data-ra="agent-enrollment" data-id="owned"/);
  assert.doesNotMatch(env.target().innerHTML, /data-ra="agent-enrollment" data-id="read-only"/);
  assert.match(env.target().innerHTML, /data-ra="asset-telemetry" data-id="read-only"/);
  assert.throws(() => env.api.agentEnrollment("read-only"), /仅可查看/);
});

test("late agent list does not overwrite a newer tab", async () => {
  const pendingList = pending();
  const env = runtime(url => url.startsWith("/api/v1/assets") ? pendingList.promise : Promise.resolve(response([])));
  const loading = env.api.show("agents"); await env.api.show("people");
  pendingList.resolve(response([asset("late")])); await loading;
  assert.match(env.target().innerHTML, /手工维护的责任联系人/);
  assert.equal(env.api.S.assets.length, 0);
});

test("telemetry sample JSON is escaped and unavailable never falls back to demos", async () => {
  const env = runtime(async () => response({ dataState: "stale", agents: [], samples: [{ kind: "host", observedAt: "2026-10-18T00:00:00Z", sequence: "1", health: { status: "error" }, metrics: { hostile: '<img src=x onerror="x">' } }] }));
  await env.api.assetTelemetry("asset-one");
  const html = env.created.at(-1).querySelector("[data-telemetry]").innerHTML;
  assert.match(html, /样本已过期/); assert.match(html, /健康 error/);
  assert.match(html, /&lt;img/); assert.doesNotMatch(html, /<img/);
  const broken = runtime(async () => response({ error: "unavailable" }, 503));
  await broken.api.assetTelemetry("asset-one");
  assert.match(broken.created.at(-1).querySelector("[data-telemetry]").textContent, /不使用模拟数据替代/);
});

test("closed telemetry dialog ignores a late response", async () => {
  const waiting = pending(), env = runtime(() => waiting.promise);
  const loading = env.api.assetTelemetry("asset-one"), d = env.created.at(-1);
  d.close(); waiting.resolve(response({ dataState: "fresh", agents: [], samples: [] })); await loading;
  assert.equal(d.querySelector("[data-telemetry]").innerHTML, "");
});

test("shared chrome labels distinguish real API pages from retained demos without changing theme", () => {
  for (const page of ["devices", "directory", "remote-access", "overview"]) {
    const root = new Element();
    root.querySelector("#io-content").prepend = node => { root.guideBanner = node; };
    const theme = root.querySelector("#wk-theme"); theme.value = "sage";
    vm.runInNewContext(app, { document: { getElementById: () => root, createElement: () => new Element() }, location: { hash: "#" + page }, history: { replaceState() {} },
      window: { InfraRemote: { render() {}, leave() {} }, InfraWorkspace: { render() {} } } });
    if (page === "overview") {
      assert.match(root.guideBanner.innerHTML, /data-page="getting-started"/);
      assert.match(root.guideBanner.innerHTML, /使用手册/);
      assert.equal(root.querySelector(".demo-tag").textContent, "DESIGN PREVIEW");
      assert.match(root.querySelector(".foot > span:first-child").innerHTML, /交互演示 · 非真实生产数据/);
      assert.match(root.querySelector(".workspace-switch small").textContent, /演示页面/);
    } else {
      assert.equal(root.querySelector(".demo-tag").textContent, "LOCAL DATA / 实际API");
      assert.match(root.querySelector(".foot > span:first-child").innerHTML, /真实资产 \/ 身份 API.*未验证/);
      assert.match(root.querySelector(".nav-bottom").innerHTML, /不代表完整生产验收/);
      assert.match(root.querySelector(".workspace-switch small").textContent, /本地开发/);
    }
    assert.equal(theme.value, "sage");
  }
});

test("manually injected asset management actions are rejected before requests", async () => {
  const env = runtime(); env.api.S.assets = [asset("visible")];
  for (const action of ["asset-edit", "accounts", "hostkey", "asset-test", "ownership-history", "account-new"]) {
    await env.api.click({ target: { closest: () => ({ dataset: { ra: action, id: "visible" }, isConnected: true }) }, preventDefault() {} });
    assert.match(env.root.querySelector("#ra-message").textContent, /仅可查看/);
  }
  assert.equal(env.calls.length, 0);
});

test("asset filters are sent to server and export excludes current pagination", () => {
  const env = runtime(); env.api.S.assetOffset = 300; env.api.S.assetQuery = "prod & team";
  env.api.S.assetFilters = { category: "nas", environment: "prod", site: "A", business: "B", ownerId: "person-1", groupId: "scope-1" };
  assert.equal(env.api.assetParams(true).get("offset"), "300");
  assert.equal(env.api.assetParams().has("offset"), false);
  for (const [key, value] of Object.entries(env.api.S.assetFilters)) assert.equal(env.api.assetParams().get(key), value);
  assert.equal(env.api.assetParams().get("q"), "prod & team");
});

test("late assets response cannot overwrite a newer people tab or mutate its asset state", async () => {
  const old = pending();
  const env = runtime((url) => url.startsWith("/api/v1/assets") ? old.promise : Promise.resolve(response([])));
  const assets = env.api.show("assets"); await env.api.show("people");
  old.resolve(response([asset("late")])); await assets;
  assert.match(env.target().innerHTML, /手工维护的责任联系人/);
  assert.equal(env.api.S.assets.length, 0);
});

test("late rejected tab requests do not surface an obsolete error", async () => {
  const old = pending();
  const env = runtime((url) => url.startsWith("/api/v1/assets") ? old.promise : Promise.resolve(response([])));
  const assets = env.api.show("assets"); await env.api.show("people");
  old.resolve(response({ error: "obsolete error" }, 403));
  await assert.doesNotReject(assets);
  assert.match(env.target().innerHTML, /手工维护的责任联系人/);
});

test("leave invalidates both old render authentication and tab responses", async () => {
  for (const render of [false, true]) {
    const old = pending(), env = runtime(() => old.promise);
    const work = render ? env.api.render("assets", "inventory") : env.api.show("assets");
    env.api.leave(); env.root.innerHTML = "new page";
    old.resolve(response(render ? admin : [asset("late")]));
    await work;
    assert.equal(env.root.innerHTML, "new page");
    assert.equal(env.api.S.assets.length, 0);
  }
});

test("new render wins over a previous authentication request", async () => {
  const first = pending(); let auth = 0;
  const env = runtime((url) => url.endsWith("/auth/me") ? ++auth === 1 ? first.promise : Promise.resolve(response(admin)) : Promise.resolve(response([])));
  const old = env.api.render("assets", "inventory");
  await env.api.render("people", "people"); first.resolve(response({ error: "old unauthorized" }, 401)); await old;
  assert.match(env.root.innerHTML, /组织与人员/);
  assert.doesNotMatch(env.root.querySelector("#ra-body").innerHTML, /ra-login/);
  assert.equal(env.api.S.tab, "people");
});

test("asset details use the same real ID and unknown metrics without directory fetches", async () => {
  const env = runtime(() => response({ ...asset("stable-id"), environment: "prod", site: "A", business: "Finance" }));
  await env.api.assetDetails("stable-id");
  assert.equal(env.calls[0].url, "/api/v1/assets/stable-id");
  assert.match(env.root.dialog.innerHTML, /stable-id/);
  assert.match(env.root.dialog.innerHTML, /Finance/);
  assert.match(env.root.dialog.innerHTML, /未知 \/ 未采集/);
  assert.match(env.root.dialog.innerHTML, /person-1/);
  assert.doesNotMatch(env.root.dialog.innerHTML, /0%|42%/);
  assert.equal(env.calls.length, 1);
});

test("export handles 422 and non-CSV responses without creating a download", async () => {
  for (const result of [response({ error: "超过 1000 项，请筛选" }, 422), response("<html>login</html>", 200, "text/html")]) {
    const env = runtime(() => result);
    await assert.rejects(env.api.exportAssets(), /1000|未提供 CSV/);
    assert.equal(env.created.length, 0);
  }
});

test("CSV download uses server data and current filter scope", async () => {
  const env = runtime(() => response("id,name\nstable,Actual\n", 200, "text/csv; charset=utf-8"));
  env.api.S.assetFilters = { category: "nas" };
  await env.api.exportAssets();
  assert.equal(env.calls[0].url, "/api/v1/assets/export?category=nas");
  assert.equal(env.created[0].download, "infrascope-assets.csv");
  assert.equal(env.created[0].clicked, true);
});

test("asset group administration is unavailable to nonadmins before API calls", async () => {
  const env = runtime(); env.api.S.user.role = "asset_manager";
  assert.throws(() => env.api.assetGroupEditor(), /仅平台管理员/);
  await assert.rejects(env.api.show("asset-groups"), /仅平台管理员/);
  assert.equal(env.calls.length, 0);
});

test("asset group picker restores over 100 selected IDs in chunks and preserves IDs across searches", async () => {
  const ids = Array.from({ length: 135 }, (_, index) => "saved-" + index);
  const env = runtime((url) => {
    if (url.includes("?ids=")) return response(new URL("http://local" + url).searchParams.get("ids").split(",").map((id) => asset(id)));
    if (url.includes("/api/v1/assets?")) return response([asset("page-only")]);
    return response([]);
  });
  env.api.assetGroupEditor({ id: "scope", name: "Scope", version: 4, enabled: true, asset_ids: ids, user_ids: ["missing-user"], group_ids: ["missing-group"], starts_at: "2026-10-01T00:00:00Z", expires_at: "2026-11-01T00:00:00Z" });
  await new Promise((resolve) => setImmediate(resolve));
  const d = env.root.dialog, select = d.querySelector('[name="assetIds"]');
  assert.equal(select.selectedOptions.length, 135);
  assert.deepEqual(env.calls.filter((call) => call.url.includes("?ids=")).map((call) => new URL("http://local" + call.url).searchParams.get("ids").split(",").length), [100, 35]);
  assert.equal(d.querySelector('[name="userIds"]').selectedOptions[0].value, "missing-user");
  assert.equal(d.querySelector('[name="groupIds"]').selectedOptions[0].value, "missing-group");
  assert.match(d.querySelector('[name="userIds"]').innerHTML, /缺失或不可访问/);
  d.querySelector('[name="scope-query"]').value = "different";
  d.querySelector("#ra-scope-search").click();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(select.selectedOptions.length, 135);
  assert.equal(d.dataset.submitBlocked, "false");
});

test("asset group directory failure blocks saving and preserves existing selections", async () => {
  const env = runtime((url) => url.endsWith("/users") ? response({ error: "directory unavailable" }, 503) : response([]));
  env.api.assetGroupEditor({ name: "Scope", asset_ids: ["keep-asset"], user_ids: ["keep-user"], group_ids: [], starts_at: "2026-10-01T00:00:00Z", expires_at: "2026-11-01T00:00:00Z" });
  await new Promise((resolve) => setImmediate(resolve));
  const d = env.root.dialog;
  assert.equal(d.dataset.submitBlocked, "true");
  assert.equal(d.querySelector("[type=submit]").disabled, true);
  assert.equal(d.querySelector('[name="assetIds"]').selectedOptions[0].value, "keep-asset");
  assert.equal(d.querySelector('[name="userIds"]').selectedOptions[0].value, "keep-user");
  assert.match(d.querySelector("#ra-principals-error").textContent, /禁止保存并保留输入/);
});

test("asset group save sends explicit read-scope fields, optimistic version and selected IDs", async () => {
  const env = runtime((url, options) => options.method === "PATCH" ? response({ ok: true }) : response([]));
  env.api.assetGroupEditor({ id: "scope", name: "Scope", version: 4, asset_ids: ["kept"], user_ids: [], group_ids: [], starts_at: "2026-10-01T00:00:00Z", expires_at: "2026-11-01T00:00:00Z" });
  await new Promise((resolve) => setImmediate(resolve));
  const d = env.root.dialog, values = new Map([["name", "Updated"], ["description", "Read only"], ["enabled", "on"], ["startsAt", "2026-10-01T00:00:00Z"], ["expiresAt", "2026-11-01T00:00:00Z"]]);
  values.getAll = (key) => key === "userIds" ? ["user"] : ["group"];
  await d.querySelector("form").onsubmit({ preventDefault() {}, target: values });
  const saved = env.calls.find((call) => call.options.method === "PATCH");
  assert.equal(saved.url, "/api/remote-access/asset-groups/scope");
  assert.deepEqual(JSON.parse(saved.options.body), { version: 4, name: "Updated", description: "Read only", enabled: true,
    startsAt: "2026-10-01T00:00:00Z", expiresAt: "2026-11-01T00:00:00Z", assetIds: ["kept"], userIds: ["user"], groupIds: ["group"] });
});

const logoutClick = (env) => env.api.click({ target: { closest: () => ({ dataset: { ra: "logout" }, isConnected: true }) }, preventDefault() {} });

test("logout immediately invalidates pending reads and clears identity-scoped caches before its response", async () => {
  const logout = pending(), env = runtime(() => logout.promise);
  for (const key of ["assets", "people", "access", "assetGroups", "accountRows", "records"]) env.api.S[key] = [{ id: "sensitive" }];
  env.api.S.files = { account: "account-id", list: [{ name: "private" }] };
  env.api.S.active = "session-id"; env.api.S.visible.add("session-id"); env.api.S.routes = new Map([["session-id", "gateway"]]);
  env.api.S.assetFilters = { ownerId: "private-person" }; env.api.S.assetQuery = "private-query";
  const oldRender = env.api.S.renderEpoch, oldView = env.api.S.viewEpoch;
  const work = logoutClick(env);
  assert.ok(env.api.S.renderEpoch > oldRender);
  assert.ok(env.api.S.viewEpoch > oldView);
  for (const key of ["assets", "people", "access", "assetGroups", "accountRows", "records"]) assert.equal(env.api.S[key].length, 0, key);
  assert.equal(env.api.S.user, null);
  assert.equal(env.api.S.files, null);
  assert.equal(env.api.S.active, null);
  assert.equal(env.api.S.visible.size, 0);
  assert.equal(env.api.S.routes.size, 0);
  assert.equal(env.api.S.assetQuery, "");
  assert.equal(Object.keys(env.api.S.assetFilters).length, 0);
  logout.resolve(response({ ok: true })); await work;
});

test("late asset detail, CSV and list responses cannot repopulate or open after logout", async () => {
  for (const action of ["detail", "export", "list"]) {
    const old = pending(), env = runtime((url) => url.endsWith("/auth/logout") ? response({ ok: true }) : old.promise);
    const work = action === "detail" ? env.api.assetDetails("private") : action === "export" ? env.api.exportAssets() : env.api.show("assets");
    await logoutClick(env);
    old.resolve(action === "detail" ? response(asset("private")) : action === "export" ? response("id,name\nprivate,Secret", 200, "text/csv") : response([asset("private")]));
    await work;
    assert.equal(env.created.length, 0, action + " must not create a dialog/download");
    assert.equal(env.api.S.assets.length, 0, action + " must not refill assets");
    assert.match(env.root.querySelector("#ra-body").innerHTML, /ra-login/);
  }
});

test("logout failure does not claim a confirmed logout and offers server session recheck", async () => {
  const env = runtime(() => response({ error: "logout backend unavailable" }, 503));
  await logoutClick(env);
  assert.equal(env.api.S.user, null, "local sensitive state is invalidated even when server status is unknown");
  assert.doesNotMatch(env.root.querySelector("#ra-body").innerHTML, /ra-login/);
  assert.match(env.root.querySelector("#ra-body").innerHTML, /注销未确认|注销失败/);
  assert.match(env.root.querySelector("#ra-body").innerHTML, /logout backend unavailable/);
  assert.match(env.root.querySelector("#ra-body").innerHTML, /data-ra="reload"/);
});

test("unrelated scope edits preserve exact original RFC3339 times including subsecond precision", async () => {
  const env = runtime((url, options) => options.method === "PATCH" ? response({ ok: true }) : response([]));
  const group = { id: "scope", name: "Scope", version: 4, asset_ids: [], user_ids: [], group_ids: [],
    starts_at: "2026-10-01T08:02:39.123456+08:00", expires_at: "2026-11-01T08:07:59.987654+08:00" };
  env.api.assetGroupEditor(group); await new Promise((resolve) => setImmediate(resolve));
  const d = env.root.dialog;
  const field = (name) => d.innerHTML.match(new RegExp(`name="${name}"[^>]*value="([^"]*)"`))[1];
  const values = new Map([["name", "Renamed"], ["description", ""], ["enabled", "on"], ["startsAt", field("startsAt")], ["expiresAt", field("expiresAt")]]);
  values.getAll = () => [];
  await d.querySelector("form").onsubmit({ preventDefault() {}, target: values });
  const payload = JSON.parse(env.calls.find((call) => call.options.method === "PATCH").options.body);
  assert.equal(payload.startsAt, group.starts_at);
  assert.equal(payload.expiresAt, group.expires_at);
  assert.match(d.innerHTML, /type="datetime-local"[^>]*step="any"/);
  assert.match(d.innerHTML, /本地时区/);
});

test("forbidden people entry retains navigation with a clear permission message, then remote entry opens access", async () => {
  const user = { ...admin, role: "operator", permissions: [] };
  const env = runtime((url) => response(url.endsWith("/auth/me") ? user : []));
  await env.api.render("people", "people");
  assert.match(env.root.querySelector("#ra-body").innerHTML, /ra-tabs/);
  assert.match(env.target().innerHTML, /权限|无权/);
  assert.doesNotMatch(env.root.querySelector("#ra-body").innerHTML, /网关尚不可用/);
  await env.api.render(undefined, "remote");
  assert.equal(env.api.S.tab, "access");
  assert.ok(env.calls.some((call) => call.url.endsWith("/my/access")));
});

test("lower-privilege login cannot inherit an administrator-only active tab", async () => {
  for (const tab of ["users", "groups", "asset-groups", "audit", "people", "grants"]) {
    const user = { ...admin, role: "operator", permissions: [] };
    const env = runtime((url) => response(url.endsWith("/auth/me") ? user : []));
    env.api.S.tab = tab;
    await env.api.render(undefined, "remote");
    assert.equal(env.api.S.tab, "access", tab);
    assert.match(env.root.querySelector("#ra-body").innerHTML, /ra-tabs/);
  }
});

test("expired authentication clears previous identity state instead of retaining cached admin access", async () => {
  const env = runtime(() => response({ error: "expired" }, 401));
  env.api.S.assets = [asset("old")];
  await env.api.render("assets", "inventory");
  assert.equal(env.api.S.user, null);
  assert.equal(env.api.S.assets.length, 0);
  assert.match(env.root.querySelector("#ra-body").innerHTML, /ra-login/);
});

test("password change clears cached data and invalidates a pending detail before showing login", async () => {
  const detail = pending(), env = runtime((url) => url.endsWith("/auth/password") ? response({ ok: true }) : detail.promise);
  env.api.S.assets = [asset("old")];
  const old = env.api.assetDetails("old");
  env.api.passwordDialog();
  const d = env.root.dialog;
  await d.querySelector("form").onsubmit({ preventDefault() {}, target: new Map([["currentPassword", "old"], ["newPassword", "new-password"]]) });
  const count = env.created.length;
  detail.resolve(response(asset("old"))); await old;
  assert.equal(env.created.length, count);
  assert.equal(env.api.S.assets.length, 0);
  assert.equal(env.api.S.user, null);
  assert.match(env.root.querySelector("#ra-body").innerHTML, /ra-login/);
});

test("logout failure after leaving does not replace another page and later recheck uses server identity", async () => {
  const old = pending(), user = { ...admin, role: "operator", permissions: [] };
  const env = runtime((url) => url.endsWith("/auth/logout") ? old.promise : response(url.endsWith("/auth/me") ? user : []));
  const work = logoutClick(env);
  env.api.leave(); env.root.innerHTML = "unrelated page";
  old.resolve(response({ error: "response lost" }, 503)); await work;
  assert.equal(env.root.innerHTML, "unrelated page");
  assert.equal(env.api.S.user, null);
  await env.api.render(undefined, "remote");
  assert.equal(env.api.S.user.role, "operator");
  assert.equal(env.api.S.tab, "access");
});

test("late auth response and late password change completion do not restore a logged-out or left view", async () => {
  const auth = pending(), env = runtime((url) => url.endsWith("/auth/logout") ? response({ ok: true }) : auth.promise);
  const old = env.api.render("assets", "inventory");
  await logoutClick(env); auth.resolve(response(admin)); await old;
  assert.equal(env.api.S.user, null);
  assert.match(env.root.querySelector("#ra-body").innerHTML, /ra-login/);
  const changed = pending(), next = runtime(() => changed.promise);
  next.api.passwordDialog();
  const work = next.root.dialog.querySelector("form").onsubmit({ preventDefault() {}, target: new Map([["currentPassword", "old"], ["newPassword", "new-password"]]) });
  next.api.leave(); next.root.innerHTML = "another page";
  changed.resolve(response({ ok: true })); await work;
  assert.equal(next.root.innerHTML, "another page");
});

test("scope time edited with milliseconds keeps those milliseconds instead of truncating to minutes", async () => {
  const env = runtime((url, options) => options.method === "PATCH" ? response({ ok: true }) : response([]));
  env.api.assetGroupEditor({ id: "scope", version: 4, asset_ids: [], user_ids: [], group_ids: [], starts_at: "2026-10-01T00:00:00Z", expires_at: "2026-11-01T00:00:00Z" });
  await new Promise((resolve) => setImmediate(resolve));
  const values = new Map([["name", "Edited time"], ["description", ""], ["enabled", "on"], ["startsAt", "2026-10-01T00:00:39.123Z"], ["expiresAt", "2026-11-01T00:07:59.987Z"]]);
  values.getAll = () => [];
  await env.root.dialog.querySelector("form").onsubmit({ preventDefault() {}, target: values });
  const payload = JSON.parse(env.calls.find((call) => call.options.method === "PATCH").options.body);
  assert.equal(payload.startsAt, "2026-10-01T00:00:39.123Z");
  assert.equal(payload.expiresAt, "2026-11-01T00:07:59.987Z");
});
