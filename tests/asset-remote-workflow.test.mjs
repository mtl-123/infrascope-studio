import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import core from "../dist/remote-assets-core.js";

const source = readFileSync(new URL("../dist/remote-access.js", import.meta.url), "utf8");
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const pending = () => { let resolve; const promise = new Promise((yes) => { resolve = yes; }); return { promise, resolve }; };
const admin = { id: "user-1", role: "admin", displayName: "Current admin", csrf: "csrf", gatewayId: "gateway-1", permissions: ["asset.manage", "remoteAccount.manage"] };
const asset = (os = "linux") => ({ id: "asset-1", name: "Target server", category: "server", kind: "physical", os_family: os, enabled: true, canManage: true, endpoints: ["ssh", "sftp", "rdp"].map((protocol) => ({ protocol, host: "192.0.2.10", port: protocol === "rdp" ? 3389 : 22 })) });
const account = (state = "ready_to_attempt") => ({ id: "account-1", name: "Target login", username: "operator", authType: "password", authorized: state !== "needs_grant", credentialConfigured: true, state, reason: "服务端真实条件", actions: ["ssh.connect"] });
const readiness = (state = "ready_to_attempt") => ({ assetId: "asset-1", assetName: "Target server", osFamily: "linux", canManage: true, canGrantSelf: true, connectorReady: false,
  protocols: ["ssh", "sftp", "rdp"].map((protocol) => ({ protocol, endpoint: asset().endpoints.find((e) => e.protocol === protocol), state, reason: "服务端真实条件", accounts: [account(state)] })) });
const access = (assetId = "asset-1", protocols = ["ssh", "sftp", "rdp"]) => ({ asset_id: assetId, account_id: "account-1", asset_name: "Target server", username: "operator", account_name: "Target login", grants: [{ protocols, actions: ["remoteAccount.use", "ssh.connect", "sftp.list", "rdp.launch"], expiresAt: new Date(Date.now() + 86400000).toISOString() }] });
const details = () => ({ id: "account-1", asset_id: "asset-1", name: "Target login", username: "operator", auth_type: "password", protocols: ["ssh"], enabled: true, credential_configured: true });
const connector = (id = "pc-1") => ({ id, name: "My computer", version: "1.0.0", approved_origin: "https://localhost", last_seen: new Date().toISOString(), browser_bindings: [{ id: "binding-1" }],
  capabilities: { ok: true, credentialApi: true, mstsc: true, rdpsign: true, signing: { ok: true, configured: true } } });

// Handler tests use a minimal DOM; hardware and real browser acceptance remain separate.
class Element {
  constructor() { this.dataset = {}; this.children = new Map(); this.isConnected = true; this.disabled = false; this.options = []; this.classList = { add() {}, remove() {}, toggle() {} }; }
  set innerHTML(value) {
    this.html = value; this.children.clear();
    this.options = [...value.matchAll(/<option value="([^"]*)"([^>]*)>(.*?)<\/option>/gs)].map((m) => ({ value: m[1], selected: /selected/.test(m[2]) }));
  }
  get innerHTML() { return this.html || ""; }
  get value() { return this.options.length ? this.options.find((o) => o.selected)?.value || this.options[0].value : this.rawValue || ""; }
  set value(value) { this.rawValue = value; for (const option of this.options) option.selected = option.value === value; }
  querySelector(selector) {
    if (!this.children.has(selector)) {
      const node = new Element(), name = selector.match(/^\[name="([^"]+)"\]$/)?.[1];
      if (name) {
        const options = this.innerHTML.match(new RegExp(`<select name="${name}"[^>]*>([\\s\\S]*?)</select>`));
        if (options) node.innerHTML = options[1];
      }
      this.children.set(selector, node);
    }
    return this.children.get(selector);
  }
  querySelectorAll() { return []; }
  append(node) { this.dialog = node; }
  showModal() { this.open = true; }
  close() { this.open = false; this.onclose?.(); }
  remove() { this.isConnected = false; }
  addEventListener() {}
}
function fields(values) {
  const entries = Object.entries(values);
  return { get: (key) => values[key] ?? null, has: (key) => Object.hasOwn(values, key), getAll: (key) => Object.hasOwn(values, key) ? [values[key]] : [], reset() {}, [Symbol.iterator]: () => entries[Symbol.iterator]() };
}
const submit = (d, values) => d.querySelector("form").onsubmit({ preventDefault() {}, target: fields(values) });
const panelClick = (d, action, protocol = "ssh", accountId = "account-1") => d.onclick({ preventDefault() {}, stopPropagation() {}, target: { closest: () => ({ dataset: { remoteAction: action, protocol, account: accountId }, isConnected: true }) } });
function runtime(handler) {
  const root = new Element(), created = [], calls = [], opened = [], auth = [];
  const window = { addEventListener() {}, InfraRemoteAssets: core };
  let uuid = 0;
  const context = vm.createContext({ window, document: { getElementById: () => null, createElement: () => { const node = new Element(); created.push(node); return node; } },
    crypto: { randomUUID: () => "00000000-0000-4000-8000-" + String(++uuid).padStart(12, "0") }, URL, URLSearchParams, Blob, Date, console,
    location: { search: "", origin: "https://localhost", href: "https://localhost/#devices" }, setInterval: () => 1, clearInterval() {}, setTimeout: () => 1,
    FormData: class { constructor(form) { return form; } }, fetch: async (url, options) => {
      calls.push({ url, options });
      const result = handler && await handler(url, options); if (result) return result;
      if (url.endsWith("/remote-readiness")) return response(readiness());
      if (url.endsWith("/my/access")) return response([access()]);
      if (url === "/api/v1/assets/asset-1") return response(asset());
      if (url.endsWith("/accounts/account-1") && options.method === "GET") return response(details());
      if (url.endsWith("/my/connectors")) return response([connector()]);
      return response({ id: "created-id" });
    } });
  vm.runInContext(source.replace("window.InfraRemote = { render, leave };", "window.InfraRemote = { render, leave, S, show, allowed, assetDetails, assetRemote, accountEditor, credential, grantSelf, rdp, setup: (element, auth, opened) => { root = element; view = element.querySelector('#ra-body'); reauth = async () => { auth.push('reauth'); }; addTerminal = async (...args) => opened.push(args); } };"), context);
  const api = window.InfraRemote; api.setup(root, auth, opened); api.S.mounted = true; api.S.user = structuredClone(admin); api.S.csrf = "csrf"; api.S.assets = [asset()];
  return { api, root, calls, created, opened, auth };
}

test("every visible asset row and detail offer asset-bound connection without granting anything", async () => {
  const env = runtime((url) => url.startsWith("/api/v1/assets?") ? response([{ ...asset(), canManage: false }]) : undefined);
  await env.api.show("assets");
  assert.match(env.root.querySelector("#ra-view").innerHTML, /data-ra="asset-remote" data-id="asset-1"/);
  await env.api.assetDetails("asset-1");
  assert.match(env.root.dialog.innerHTML, /data-ra="asset-remote" data-id="asset-1"/);
  assert.equal(env.calls.filter((call) => call.options.method !== "GET").length, 0);
});

test("connection panel renders three truthful protocols, requirements, and no implicit self grant", async () => {
  const env = runtime(); await env.api.assetRemote("asset-1");
  const html = env.root.dialog.querySelector("#ra-remote-cards").innerHTML;
  for (const label of ["LinuxTab", "SFTP", "RDP", "配置就绪，可尝试连接", "明确授权给我", "CIDR", "HTTPS"]) assert.match(html, new RegExp(label));
  assert.doesNotMatch(html, /认证成功|连接成功/);
  assert.equal(env.calls.length, 1); assert.equal(env.calls[0].options.method, "GET");
});

test("scope-only readers get no account creation, credential or self-grant controls", async () => {
  const data = readiness("needs_grant"); data.canManage = false; data.canGrantSelf = false;
  const env = runtime(() => response(data)); env.api.S.user = { role: "user", permissions: [] };
  await env.api.assetRemote("asset-1"); const d = env.root.dialog;
  assert.doesNotMatch(d.querySelector("#ra-remote-cards").innerHTML, /data-remote-action="(?:account-new|credential|grant|endpoint)"/);
  await panelClick(d, "grant");
  assert.equal(env.calls.filter((call) => call.options.method !== "GET").length, 0);
  assert.match(d.querySelector(".ra-error").textContent, /只读/);
});

test("late readiness after leaving never opens a dialog", async () => {
  const slow = pending(), env = runtime(() => slow.promise);
  const work = env.api.assetRemote("asset-1"); env.api.leave(); slow.resolve(response(readiness())); await work;
  assert.equal(env.created.length, 0);
});

test("wrong-asset readiness fails closed", async () => {
  const env = runtime(() => response({ ...readiness(), assetId: "different" }));
  await assert.rejects(env.api.assetRemote("asset-1"), /不属于当前资产/);
  assert.equal(env.created.length, 0);
});

test("actual SSH launch rechecks readiness and access then binds exact asset and account", async () => {
  const env = runtime(); await env.api.assetRemote("asset-1");
  env.api.S.access = [access("stale-other-asset")];
  await panelClick(env.root.dialog, "connect");
  const post = env.calls.find((call) => call.url.endsWith("/ssh/sessions"));
  assert.deepEqual(JSON.parse(post.options.body), { assetId: "asset-1", accountId: "account-1", cols: 100, rows: 28 });
  assert.equal(env.calls.filter((call) => call.url.endsWith("/remote-readiness")).length, 2);
  assert.deepEqual([...env.opened[0]], ["created-id", "Target server / operator"]);
});

test("fresh access containing another asset cannot reuse stale account metadata to launch", async () => {
  const env = runtime((url) => url.endsWith("/my/access") ? response([access("other-asset")]) : undefined);
  await env.api.assetRemote("asset-1"); await panelClick(env.root.dialog, "connect");
  assert.match(env.root.dialog.querySelector(".ra-error").textContent, /不会使用其他资产/);
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 0);
});

test("panel action lock survives redraw and prevents duplicate real SSH sessions", async () => {
  for (const stage of ["/my/access", "/ssh/sessions"]) {
    const slow = pending();
    const env = runtime((url) => url.endsWith(stage) ? slow.promise : undefined);
    await env.api.assetRemote("asset-1");
    const d = env.root.dialog, first = panelClick(d, "connect");
    await new Promise(setImmediate);
    await panelClick(d, "connect");
    assert.equal(env.calls.filter((call) => call.url.endsWith(stage)).length, 1);
    slow.resolve(response(stage === "/my/access" ? [access()] : { id: "session-1" }));
    await first;
    assert.equal(env.calls.filter((call) => call.url.endsWith("/ssh/sessions")).length, 1);
  }
});

test("closing or leaving during a real SSH POST reclaims only its newly returned session", async () => {
  for (const leave of [false, true]) {
    const slow = pending(), env = runtime((url) => url.endsWith("/ssh/sessions") ? slow.promise : undefined);
    await env.api.assetRemote("asset-1"); const d = env.root.dialog, work = panelClick(d, "connect");
    await new Promise(setImmediate);
    if (leave) env.api.leave(); else d.close();
    slow.resolve(response({ id: "created-session" })); await work;
    const mutations = env.calls.filter((call) => call.options.method !== "GET");
    assert.deepEqual(mutations.map((call) => [call.url, call.options.method]), [["/api/remote-access/ssh/sessions", "POST"], ["/api/remote-access/ssh/sessions/created-session", "DELETE"]]);
    assert.equal(env.opened.length, 0);
  }
});

test("a different identity must never reclaim a session created by the previous login", async () => {
  const slow = pending(), env = runtime((url) => url.endsWith("/ssh/sessions") ? slow.promise : undefined);
  await env.api.assetRemote("asset-1"); const d = env.root.dialog, work = panelClick(d, "connect");
  await new Promise(setImmediate); env.api.S.user = { ...admin, id: "different-user" }; env.api.S.renderEpoch++;
  slow.resolve(response({ id: "old-session" })); await work;
  assert.equal(env.calls.filter((call) => call.options.method === "DELETE").length, 0);
  assert.equal(env.opened.length, 0);
});

test("unconfirmed SSH cleanup reports orphan state instead of successful connection", async () => {
  const slow = pending(), env = runtime((url, options) => url.endsWith("/ssh/sessions") ? slow.promise : options.method === "DELETE" ? response({ error: "cleanup unavailable" }, 503) : undefined);
  await env.api.assetRemote("asset-1"); const d = env.root.dialog, work = panelClick(d, "connect");
  await new Promise(setImmediate); d.close(); slow.resolve(response({ id: "created-session" })); await work;
  assert.match(env.root.querySelector("#ra-message").textContent, /连接已创建但未附着，回收未确认/);
  assert.equal(env.opened.length, 0);
});

test("readiness revocation or dialog closing during access refresh prevents a launch", async () => {
  let n = 0;
  const revoked = runtime((url) => url.endsWith("/remote-readiness") ? response(readiness(++n > 1 ? "needs_grant" : "ready_to_attempt")) : undefined);
  await revoked.api.assetRemote("asset-1"); await panelClick(revoked.root.dialog, "connect");
  assert.equal(revoked.calls.filter((call) => call.url.endsWith("/my/access")).length, 0);
  const slow = pending(), env = runtime((url) => url.endsWith("/my/access") ? slow.promise : undefined);
  await env.api.assetRemote("asset-1"); const d = env.root.dialog, work = panelClick(d, "connect");
  await new Promise(setImmediate); d.close(); slow.resolve(response([access()])); await work;
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 0);
});

test("same grant must contain action, matching protocol, and remoteAccount.use", () => {
  const env = runtime();
  assert.equal(env.api.allowed(access(), "ssh.connect"), true);
  assert.equal(env.api.allowed(access("asset-1", ["sftp"]), "ssh.connect"), false);
  const split = { grants: [{ protocols: ["ssh"], actions: ["ssh.connect"] }, { protocols: ["ssh"], actions: ["remoteAccount.use"] }] };
  assert.equal(env.api.allowed(split, "ssh.connect"), false);
  assert.equal(env.api.allowed(null, "ssh.connect"), false);
});

test("Windows structured account defaults to RDP, while SFTP needs its own endpoint", () => {
  const env = runtime(); env.api.accountEditor(null, asset("windows"));
  const html = env.root.dialog.innerHTML;
  assert.doesNotMatch(html, /配置（JSON）|textarea name="json"/);
  assert.match(html, /name="protocol-rdp" checked/);
  assert.doesNotMatch(html, /name="protocol-(?:ssh|sftp)" checked/);
  const target = asset("windows"); target.endpoints = target.endpoints.filter((e) => e.protocol === "rdp");
  env.api.accountEditor(null, target);
  assert.doesNotMatch(env.root.dialog.innerHTML, /name="protocol-sftp"/);
});

test("structured accounts reject incompatible auth and preserve explicit enabled/protocol fields", async () => {
  const env = runtime(); let refreshed = 0;
  env.api.accountEditor(null, asset("windows"), async () => { refreshed++; }); const d = env.root.dialog;
  await submit(d, { name: "Login", username: "operator", authType: "private_key", "protocol-rdp": "on" });
  assert.match(d.querySelector(".ra-error").textContent, /RDP 不支持/);
  assert.equal(env.calls.length, 0);
  await submit(d, { name: "Login", username: "operator", authType: "password", "protocol-rdp": "on", enabled: "on" });
  assert.equal(env.calls.length, 1); assert.equal(refreshed, 1);
  assert.deepEqual(JSON.parse(env.calls[0].options.body), { name: "Login", username: "operator", authType: "password", protocols: ["rdp"], enabled: true, archived: false });
});

test("editing account shows saved credential state and immutable auth type without returning secrets", () => {
  const env = runtime(); env.api.accountEditor(details(), asset());
  assert.match(env.root.dialog.innerHTML, /创建后不可更改/);
  assert.match(env.root.dialog.innerHTML, /凭据已保存，不回显原值/);
  assert.doesNotMatch(env.root.dialog.innerHTML, /name="authType"|name="password"|name="privateKey"/);
});

test("saved account opens its credential step without closing the parent connection panel", async () => {
  const env = runtime((url, options) => url.endsWith("/assets/asset-1/accounts") ? response({ id: "account-1" }) : undefined);
  await env.api.assetRemote("asset-1"); const parent = env.root.dialog;
  await panelClick(parent, "account-new"); const editor = env.root.dialog;
  await submit(editor, { name: "Login", username: "operator", authType: "password", "protocol-ssh": "on", enabled: "on", setCredential: "on" });
  const credential = env.root.dialog;
  assert.equal(editor.isConnected, false); assert.equal(parent.isConnected, true); assert.equal(parent.open, true);
  assert.match(credential.innerHTML, /更新凭据/);
  const reads = env.calls.filter((call) => call.url.endsWith("/remote-readiness")).length;
  await submit(credential, { action: "set", password: "fake-test-secret" });
  assert.equal(parent.open, true); assert.equal(credential.isConnected, false);
  assert.equal(env.calls.filter((call) => call.url.endsWith("/remote-readiness")).length, reads + 1);
  assert.equal(env.auth.length, 1);
  assert.doesNotMatch(JSON.stringify(env.api.S), /fake-test-secret/);
});

test("late credential save after parent closes cannot reopen or refresh the server panel", async () => {
  const slow = pending(), env = runtime((url) => url.endsWith("/credential") ? slow.promise : undefined);
  let open = true, refreshed = 0;
  await env.api.credential("account-1", async () => { refreshed++; }, () => open);
  const d = env.root.dialog, work = submit(d, { action: "set", password: "fake-test-secret" });
  await new Promise(setImmediate); open = false; d.close(); slow.resolve(response({ id: "account-1" })); await work;
  assert.equal(refreshed, 0); assert.equal(env.created.length, 1);
});

test("self grant requires explicit confirmation and protocol; SFTP has no implicit root or writes", async () => {
  const env = runtime(); const d = env.api.grantSelf("asset-1", account("needs_grant"), "sftp", readiness(), async () => {}, () => true);
  assert.doesNotMatch(d.innerHTML, /name="grant-(?:ssh|sftp|rdp)" checked|name="allowFileWrite" checked/);
  await submit(d, { "grant-sftp": "on", hours: "8" });
  assert.match(d.querySelector(".ra-error").textContent, /确认/);
  await submit(d, { "grant-sftp": "on", hours: "8", confirm: "on" });
  assert.match(d.querySelector(".ra-error").textContent, /可读根目录/);
  assert.equal(env.calls.length, 0);
  await submit(d, { "grant-sftp": "on", hours: "8", confirm: "on", readRoots: "/srv/team" });
  const body = JSON.parse(env.calls[0].options.body);
  assert.deepEqual(body.protocols, ["sftp"]); assert.deepEqual(body.readRoots, ["/srv/team"]); assert.deepEqual(body.writeRoots, []);
  assert.equal(body.allowFileWrite, false); assert.equal(body.allowClipboard, false); assert.equal(body.confirm, true);
  assert.equal(env.auth.length, 1); assert.equal(env.calls[0].options.headers["X-CSRF-Token"], "csrf");
});

test("selfgrant retry keeps identical idempotency payload after a lost response", async () => {
  let attempts = 0;
  const env = runtime((url) => { if (url.endsWith("/grant-self") && ++attempts === 1) throw Error("network response lost"); });
  const d = env.api.grantSelf("asset-1", account(), "ssh", readiness(), async () => {}, () => true);
  const input = { "grant-ssh": "on", hours: "8", confirm: "on" };
  await submit(d, input); await submit(d, input);
  assert.equal(env.calls.length, 2); assert.equal(env.calls[0].options.body, env.calls[1].options.body);
});

test("non-admin and wrong asset selfgrant requests fail before mutation", () => {
  const env = runtime(); env.api.S.user.role = "asset_manager";
  assert.throws(() => env.api.grantSelf("asset-1", account(), "ssh", readiness(), async () => {}, () => true), /不能/);
  env.api.S.user.role = "admin";
  assert.throws(() => env.api.grantSelf("wrong", account(), "ssh", readiness(), async () => {}, () => true), /不能/);
  assert.equal(env.calls.length, 0);
});

test("RDP always requires explicit device selection, never first online and no default clipboard", async () => {
  const env = runtime(); env.api.S.access = [access()]; await env.api.rdp("account-1"); const d = env.root.dialog;
  assert.equal(d.querySelector('[name="device"]').value, "");
  assert.doesNotMatch(d.innerHTML, /name="redirectClipboard" checked/);
  await submit(d, { device: "" });
  assert.match(d.querySelector(".ra-error").textContent, /不会自动使用第一台/);
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 0);
});

test("RDP excludes unknown per-device capabilities even when another bound device is ready", async () => {
  const ready = connector(), unknown = { ...connector("pc-unknown"), capabilities: {} };
  const env = runtime((url) => url.endsWith("/my/connectors") ? response([unknown, ready]) : undefined);
  env.api.S.access = [access()]; await env.api.rdp("account-1"); const d = env.root.dialog;
  const choices = d.querySelector('[name="device"]').options.map((option) => option.value);
  assert.deepEqual(choices, ["", "pc-1|binding-1"]);
  assert.match(d.innerHTML, /已排除 1 项.*自检.*签名/);
  await submit(d, { device: "pc-unknown|binding-1" });
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 0);
});

test("RDP capability and signing booleans must all be explicitly true", async () => {
  for (const key of ["ok", "credentialApi", "mstsc", "rdpsign", "signing", "signing.ok", "signing.configured"]) {
    const device = connector();
    if (key.startsWith("signing.")) device.capabilities.signing[key.split(".")[1]] = false;
    else device.capabilities[key] = key === "signing" ? undefined : "true";
    const env = runtime((url) => url.endsWith("/my/connectors") ? response([device]) : undefined); env.api.S.access = [access()];
    await assert.rejects(env.api.rdp("account-1"), /自检或 RDP 签名配置/);
    assert.equal(env.created.length, 0);
  }
});

test("RDP retry after a lost response reuses the exact explicit device launch intent", async () => {
  let attempts = 0;
  const env = runtime((url, options) => {
    if (url.endsWith("/rdp/launches") && options.method === "POST") {
      if (++attempts === 1) throw Error("response lost after enqueue");
      return response({ id: "launch-1" });
    }
    if (url.endsWith("/rdp/launches")) return response([]);
  });
  env.api.S.access = [access()]; await env.api.rdp("account-1"); const d = env.root.dialog;
  const input = { device: "pc-1|binding-1", driveMode: "all", driveList: "", fullscreen: "on" };
  await submit(d, input); await submit(d, input);
  const launches = env.calls.filter((call) => call.url.endsWith("/rdp/launches") && call.options.method === "POST");
  assert.equal(launches.length, 2); assert.equal(launches[0].options.body, launches[1].options.body);
});

test("late RDP device or credential fetch cannot open after identity invalidation", async () => {
  for (const op of ["rdp", "credential"]) {
    const slow = pending(), env = runtime(() => slow.promise); env.api.S.access = [access()];
    const work = env.api[op]("account-1"); await new Promise(setImmediate);
    env.api.leave(); slow.resolve(response(op === "rdp" ? [] : details())); await work;
    assert.equal(env.created.length, 0);
  }
});

test("new asset form offers save and continue without auto grant code", () => {
  assert.match(source, /保存后继续配置连接（端点、远程账号和本人授权）/);
  const editor = source.slice(source.indexOf("function assetEditor("), source.indexOf("const remoteProtocolLabels"));
  assert.match(editor, /await assetRemote\(saved.id\)/);
  assert.doesNotMatch(editor, /grant-self|\/grants/);
});
