import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import vm from "node:vm";
import assetCore from "../dist/remote-assets-core.js";

const require = createRequire(import.meta.url);
const quickCore = require("../dist/quick-launch-core.js");
const source = readFileSync(new URL("../dist/remote-access.js", import.meta.url), "utf8");
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const pending = () => { let resolve; const promise = new Promise((yes) => { resolve = yes; }); return { promise, resolve }; };
const user = { id: "paired-user", displayName: "Paired user", role: "operator", csrf: "test-csrf", permissions: [], gatewayId: "gateway-1" };
const allowed = () => ({ asset_id: "asset-1", account_id: "account-1", asset_name: "Saved server", account_name: "System account", username: "tester", grants: [{ protocols: ["ssh", "sftp"], actions: ["remoteAccount.use", "ssh.connect", "sftp.list"], expiresAt: "2099-01-01T00:00:00Z" }] });

class Element {
  constructor() { this.children = new Map(); this.dataset = {}; this.isConnected = true; this.classList = { add() {}, remove() {}, toggle() {} }; }
  set innerHTML(value) { this.html = value; this.children.clear(); }
  get innerHTML() { return this.html || ""; }
  querySelector(selector) { if (!this.children.has(selector)) this.children.set(selector, new Element()); return this.children.get(selector); }
  querySelectorAll() { return []; }
  append() {}
}

// VM handler coverage only: terminal rendering/files UI are adapters, not real hosts or browser acceptance.
function runtime(protocol = "ssh", handler) {
  const root = new Element(), calls = [], opened = [], files = [], panels = [], stripped = [];
  const location = { origin: "https://localhost", pathname: "/remote-workspace.html", search: `?assetId=asset-1&accountId=account-1&protocol=${protocol}&userId=paired-user` };
  const window = { addEventListener() {}, InfraRemoteAssets: assetCore, InfraQuickLaunch: quickCore };
  let enabled = false;
  const context = vm.createContext({ window, document: { getElementById: (id) => enabled && id === "ra-root" ? root : null, createElement: () => new Element() },
    crypto: { randomUUID: () => "test-window" }, URL, URLSearchParams, Blob, Date, console, location,
    history: { replaceState(_state, _title, value) { stripped.push(value); location.search = ""; } },
    setInterval: () => 1, clearInterval() {}, setTimeout: () => 1,
    fetch: async (url, options) => {
      calls.push({ url, options });
      const result = handler && await handler(url, options); if (result) return result;
      if (url.endsWith("/auth/me")) return response(structuredClone(user));
      if (url.endsWith("/my/access")) return response([allowed()]);
      if (url.endsWith("/ssh/sessions") && options.method === "POST") return response({ id: "new-session" }, 201);
      return response({ ok: true });
    } });
  vm.runInContext(source.replace("window.InfraRemote = { render, leave };", "window.InfraRemote = { render, leave, logout, S, setup: (opened, files, panels) => { addTerminal = async (...args) => { opened.push(args); }; terminalView = () => {}; filesView = async () => files.push({ ...S.files }); assetRemote = async (id) => panels.push(id); } };"), context);
  enabled = true;
  const api = window.InfraRemote;
  api.setup(opened, files, panels);
  return { api, root, calls, opened, files, panels, stripped, location };
}
const mutations = (env) => env.calls.filter(({ options }) => options.method !== "GET");

test("quick SSH authenticates and refreshes exact access before one POST, consuming URL before connect", async () => {
  let env;
  env = runtime("ssh", (url, options) => {
    if (url.endsWith("/ssh/sessions") && options.method === "POST") assert.equal(env.location.search, "");
  });
  env.api.S.access = [{ ...allowed(), asset_id: "stale-asset" }];
  await env.api.render();
  assert.deepEqual(env.calls.slice(0, 3).map(({ url }) => url), ["/api/remote-access/auth/me", "/api/remote-access/my/access", "/api/remote-access/ssh/sessions"]);
  assert.deepEqual(JSON.parse(mutations(env)[0].options.body), { assetId: "asset-1", accountId: "account-1", cols: 100, rows: 28 });
  assert.deepEqual([...env.opened[0]], ["new-session", "Saved server / tester"]);
  assert.deepEqual(env.stripped, ["/remote-workspace.html"]);
  await env.api.render();
  assert.equal(mutations(env).length, 1);
  assert.equal(env.opened.length, 1);
});

test("different signed-in browser user is rejected before access lookup or POST", async () => {
  const env = runtime("ssh", (url) => url.endsWith("/auth/me") ? response({ ...user, id: "different-user" }) : undefined);
  await env.api.render();
  assert.equal(env.calls.length, 1);
  assert.equal(mutations(env).length, 0);
  assert.equal(env.opened.length, 0);
  assert.equal(env.stripped.length, 0);
  assert.match(env.root.querySelector("#ra-view").innerHTML, /配对用户不同/);
});

test("fresh access never substitutes a different asset, account, protocol or split grant", async () => {
  const cases = [[], [{ ...allowed(), asset_id: "other" }], [{ ...allowed(), account_id: "other" }], [{ ...allowed(), grants: [{ protocols: ["sftp"], actions: ["remoteAccount.use", "ssh.connect"] }] }], [{ ...allowed(), grants: [{ protocols: ["ssh"], actions: ["remoteAccount.use"] }, { protocols: ["ssh"], actions: ["ssh.connect"] }] }]];
  for (const access of cases) {
    const env = runtime("ssh", (url) => url.endsWith("/my/access") ? response(access) : undefined);
    env.api.S.access = [allowed()];
    await env.api.render();
    assert.equal(mutations(env).length, 0);
    assert.equal(env.opened.length, 0);
    assert.equal(env.stripped.length, 0);
    assert.match(env.root.querySelector("#ra-view").innerHTML, /没有该资产账号权限/);
  }
});

test("quick SFTP opens only the selected saved account with no SSH or RDP side effect", async () => {
  const env = runtime("sftp");
  await env.api.render();
  assert.deepEqual(JSON.parse(JSON.stringify(env.files)), [{ account: "account-1", path: "", offset: 0 }]);
  assert.equal(env.opened.length, 0);
  assert.equal(mutations(env).length, 0);
  assert.deepEqual(env.stripped, ["/remote-workspace.html"]);
  assert.equal(env.api.S.tab, "files");
});

test("failed quick SSH reports failure and opens this asset's remediation panel without fake terminal", async () => {
  const env = runtime("ssh", (url, options) => url.endsWith("/ssh/sessions") && options.method === "POST" ? response({ error: "Fingerprint approval required", code: "host_key_untrusted" }, 409) : undefined);
  await env.api.render();
  assert.equal(env.opened.length, 0);
  assert.deepEqual(env.panels, ["asset-1"]);
  assert.match(env.root.querySelector("#ra-message").textContent, /快捷 SSH 未连接.*Fingerprint approval required/);
  assert.equal(mutations(env).length, 1);
  assert.deepEqual(env.stripped, ["/remote-workspace.html"]);
});

test("late access refresh after failed SSH cannot open a stale remediation panel after leaving or switching identity", async () => {
  for (const transition of ["leave", "identity"]) {
    const slow = pending(); let accessReads = 0;
    const env = runtime("ssh", (url, options) => {
      if (url.endsWith("/my/access") && ++accessReads === 2) return slow.promise;
      if (url.endsWith("/ssh/sessions") && options.method === "POST") return response({ error: "Host key not approved" }, 409);
    });
    const work = env.api.render();
    await new Promise(setImmediate);
    assert.equal(accessReads, 2);
    if (transition === "leave") env.api.leave();
    else { env.api.S.user = { ...user, id: "different-user" }; env.api.S.renderEpoch++; }
    slow.resolve(response([allowed()]));
    await work;
    assert.deepEqual(env.panels, []);
    assert.equal(env.opened.length, 0);
    assert.equal(mutations(env).length, 1);
    assert.doesNotMatch(env.root.querySelector("#ra-message").textContent || "", /快捷 SSH 未连接/);
  }
});

test("leaving during auth or access refresh prevents a late quick connection", async () => {
  for (const stage of ["/auth/me", "/my/access"]) {
    const slow = pending(), env = runtime("ssh", (url) => url.endsWith(stage) ? slow.promise : undefined);
    const work = env.api.render();
    await new Promise(setImmediate);
    env.api.leave();
    slow.resolve(response(stage === "/auth/me" ? structuredClone(user) : [allowed()]));
    await work;
    assert.equal(mutations(env).length, 0);
    assert.equal(env.opened.length, 0);
  }
});

test("leaving during SSH POST reclaims just the returned session and never attaches it", async () => {
  const slow = pending(), env = runtime("ssh", (url, options) => url.endsWith("/ssh/sessions") && options.method === "POST" ? slow.promise : undefined);
  const work = env.api.render();
  await new Promise(setImmediate);
  env.api.leave();
  slow.resolve(response({ id: "late-session" }, 201));
  await work;
  assert.equal(env.opened.length, 0);
  assert.deepEqual(mutations(env).map(({ url, options }) => [url, options.method]), [["/api/remote-access/ssh/sessions", "POST"], ["/api/remote-access/ssh/sessions/late-session", "DELETE"]]);
});

test("logout during SSH POST invalidates identity and never attaches or deletes using a later login", async () => {
  const slow = pending(), env = runtime("ssh", (url, options) => url.endsWith("/ssh/sessions") && options.method === "POST" ? slow.promise : undefined);
  const work = env.api.render();
  await new Promise(setImmediate);
  await env.api.logout();
  env.api.S.user = { ...user, id: "another-login" };
  slow.resolve(response({ id: "old-login-session" }, 201));
  await work;
  assert.equal(env.opened.length, 0);
  assert.deepEqual(mutations(env).map(({ url, options }) => [url, options.method]), [["/api/remote-access/ssh/sessions", "POST"], ["/api/remote-access/auth/logout", "POST"]]);
});

test("expired platform login shows login form and never consumes or opens the intent", async () => {
  const env = runtime("ssh", (url) => url.endsWith("/auth/me") ? response({ error: "Session expired", code: "session_expired" }, 401) : undefined);
  await env.api.render();
  assert.equal(env.api.S.user, null);
  assert.equal(env.stripped.length, 0);
  assert.equal(mutations(env).length, 0);
  assert.match(env.root.querySelector("#ra-body").innerHTML, /id="ra-login"/);
});
