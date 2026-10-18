import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import core from "../dist/remote-assets-core.js";

const source = readFileSync(new URL("../dist/remote-access.js", import.meta.url), "utf8");
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const pending = () => { let resolve; const promise = new Promise((yes) => { resolve = yes; }); return { promise, resolve }; };
const admin = { id: "user-1", role: "admin", csrf: "test-csrf", permissions: ["asset.manage", "remoteAccount.manage"] };
const person = { id: "person-1", display_name: "Test contact", enabled: true };
const organization = { id: "org-1", name: "Test organization", enabled: true };
const secret = "synthetic-unit-test-password-not-a-real-credential";
const defaultInput = (changes = {}) => ({ name: " Test server ", osFamily: "linux", host: " 192.0.2.10 ", username: " operator ", authType: "password", password: secret,
  "proto-ssh": "on", "proto-sftp": "on", sshPort: "22", sftpPort: "2222", rdpPort: "3389", claimantId: "person-1", organizationId: "org-1", readRoots: " /srv/team, /home/operator ", hours: "8", confirm: "on", ...changes });

// Handler-only DOM and synthetic responses: these tests do not claim browser or target acceptance.
class Element {
  constructor(owner = null) {
    this.owner = owner; this.dataset = {}; this.children = new Map(); this.events = new Map(); this.isConnected = true; this.disabled = false; this.checked = false;
    this.options = []; this.resetCount = 0; this.classList = { add() {}, remove() {}, toggle() {} };
  }
  set innerHTML(value) {
    this.html = value; this.children.clear();
    this.options = [...value.matchAll(/<option value="([^"]*)"([^>]*)>(.*?)<\/option>/gs)].map((m) => ({ value: m[1], selected: /selected/.test(m[2]) }));
  }
  get innerHTML() { return this.html || ""; }
  get value() { return this.options.length ? this.options.find((option) => option.selected)?.value ?? this.options[0].value : this.rawValue || ""; }
  set value(value) { this.rawValue = value; for (const option of this.options) option.selected = option.value === value; }
  querySelector(selector) {
    if (!this.children.has(selector)) {
      const node = new Element(this), name = selector.match(/^\[name="([^"]+)"\]$/)?.[1];
      if (name) {
        const select = this.innerHTML.match(new RegExp(`<select name="${name}"[^>]*>([\\s\\S]*?)</select>`));
        if (select) node.innerHTML = select[1];
        const input = this.innerHTML.match(new RegExp(`<input(?=[^>]*name="${name}")[^>]*>`))?.[0] || "";
        node.checked = /\bchecked\b/.test(input);
        node.value = input.match(/\bvalue="([^"]*)"/)?.[1] ?? node.value;
      }
      this.children.set(selector, node);
    }
    return this.children.get(selector);
  }
  querySelectorAll(selector) { return selector === "dialog" ? this.dialogs || [] : []; }
  append(node) { this.dialog = node; (this.dialogs ??= []).push(node); }
  showModal() { this.open = true; }
  close() {
    if (!this.open) return;
    this.open = false; this.onclose?.();
    for (const listener of this.events.get("close") || []) listener();
  }
  remove() { this.isConnected = false; }
  addEventListener(name, listener) { if (!this.events.has(name)) this.events.set(name, []); this.events.get(name).push(listener); }
  reset() {
    this.resetCount++;
    if (this.owner) for (const field of ["password", "privateKey", "passphrase"]) this.owner.querySelector(`[name="${field}"]`).value = "";
  }
}

function runtime(handler) {
  const root = new Element(), created = [], calls = [], opened = [], auth = [], storage = [];
  const window = { addEventListener() {}, InfraRemoteAssets: core };
  const forbiddenStorage = { getItem() { return null; }, setItem(key, value) { storage.push({ key, value }); }, removeItem() {} };
  window.localStorage = window.sessionStorage = forbiddenStorage;
  let uuid = 0, now = Date.parse("2026-10-18T00:00:00Z");
  class Clock extends Date { constructor(...args) { super(...(args.length ? args : [now])); } static now() { return now; } }
  const hooks = { auth: async () => {}, opened };
  const context = vm.createContext({ window, document: { getElementById: () => null, createElement: () => { const node = new Element(); created.push(node); return node; } },
    crypto: { randomUUID: () => "00000000-0000-4000-8000-" + String(++uuid).padStart(12, "0") }, URL, URLSearchParams, Blob, Date: Clock, console,
    localStorage: forbiddenStorage, sessionStorage: forbiddenStorage,
    location: { search: "", origin: "https://localhost", href: "https://localhost/#devices" }, setInterval: () => 1, clearInterval() {}, setTimeout: () => 1,
    FormData: class { constructor(form) { return form.data; } }, fetch: async (url, options) => {
      calls.push({ url, options });
      const result = handler && await handler(url, options); if (result) return result;
      if (url.startsWith("/api/remote-access/people?")) return response([person]);
      if (url.startsWith("/api/remote-access/organizations/options")) return response([organization]);
      if (url.startsWith("/api/v1/assets?")) return response([]);
      if (url === "/api/v1/servers/onboard") return response({ assetId: "saved-asset", accountId: "saved-account" });
      throw Error("Unexpected test request: " + url);
    } });
  const exportMarker = "window.InfraRemote = { render, leave };";
  assert.ok(source.includes(exportMarker), "test export seam must match production");
  vm.runInContext(source.replace(exportMarker, "window.InfraRemote = { render, leave, show, S, serverOnboarding, setup: (element, hooks, auth) => { root = element; view = element.querySelector('#ra-body'); reauth = async () => { auth.push('reauth'); return hooks.auth(); }; assetRemote = async (id) => hooks.opened.push(id); } };"), context);
  const api = window.InfraRemote; api.setup(root, hooks, auth); api.S.mounted = true; api.S.user = structuredClone(admin); api.S.csrf = "test-csrf";
  return { api, root, calls, created, opened, auth, storage, hooks, advance: (milliseconds) => { now += milliseconds; } };
}

async function submit(dialog, values) {
  const form = dialog.querySelector("form");
  form.data = { get: (key) => values[key] ?? null, has: (key) => Object.hasOwn(values, key), getAll: (key) => Object.hasOwn(values, key) ? [values[key]] : [], [Symbol.iterator]: () => Object.entries(values)[Symbol.iterator]() };
  for (const key of ["password", "privateKey", "passphrase"]) dialog.querySelector(`[name="${key}"]`).value = values[key] || "";
  await form.onsubmit({ preventDefault() {}, target: form });
}
const posts = (env) => env.calls.filter((call) => call.options.method === "POST");

test("only administrators see the onboarding action and others cannot invoke it", async () => {
  for (const role of ["admin", "asset_manager", "user"]) {
    const env = runtime(); env.api.S.user.role = role;
    await env.api.show("assets");
    assert.equal(/data-ra="server-onboard"/.test(env.root.querySelector("#ra-view").innerHTML), role === "admin");
    if (role !== "admin") {
      const before = env.calls.length;
      await assert.rejects(env.api.serverOnboarding(), /管理员/);
      assert.equal(env.calls.length, before); assert.equal(env.created.length, 0);
    }
  }
});

test("Linux defaults to SSH and SFTP; Windows explicitly switches to RDP only", async () => {
  const env = runtime(); await env.api.serverOnboarding(); const d = env.root.dialog;
  assert.equal(d.querySelector('[name="osFamily"]').value, "linux");
  assert.equal(d.querySelector('[name="proto-ssh"]').checked, true);
  assert.equal(d.querySelector('[name="proto-sftp"]').checked, true);
  assert.equal(d.querySelector('[name="proto-rdp"]').checked, false);
  for (const name of ["confirm", "allowFileWrite", "allowClipboard", "allowDrives", "allowInteractive"]) assert.equal(d.querySelector(`[name="${name}"]`).checked, false);
  d.querySelector('[name="osFamily"]').onchange({ target: { value: "windows" } });
  assert.equal(d.querySelector('[name="proto-ssh"]').checked, false);
  assert.equal(d.querySelector('[name="proto-sftp"]').checked, false);
  assert.equal(d.querySelector('[name="proto-rdp"]').checked, true);
  assert.equal(d.querySelector("[data-onboard-files]").hidden, true);
  assert.equal(d.querySelector("[data-onboard-rdp]").hidden, false);
  d.querySelector('[name="osFamily"]').onchange({ target: { value: "linux" } });
  assert.equal(d.querySelector('[name="proto-rdp"]').checked, false);
  assert.equal(d.querySelector("[data-onboard-files]").hidden, false);
});

test("only enabled real directory contacts and organizations enter selection", async () => {
  const env = runtime((url) => url.includes("/people?") ? response([person, { ...person, id: "disabled-person", enabled: false }]) : url.includes("/organizations/options") ? response([organization, { ...organization, id: "disabled-org", enabled: false }]) : undefined);
  await env.api.serverOnboarding(); const html = env.root.dialog.innerHTML;
  assert.match(html, /value="person-1"/); assert.match(html, /value="org-1"/);
  assert.doesNotMatch(html, /disabled-person|disabled-org/);
});

test("empty real responsibility directory prevents creating an unowned server", async () => {
  const env = runtime((url) => url.includes("/people?") ? response([]) : undefined);
  await assert.rejects(env.api.serverOnboarding(), /责任联系人/);
  assert.equal(env.created.length, 0); assert.equal(posts(env).length, 0);
});

test("explicit confirmation, responsibility, protocol and readable roots gate submission", async () => {
  for (const missing of ["confirm", "claimantId", "protocols", "readRoots"]) {
    const env = runtime(); await env.api.serverOnboarding(); const input = defaultInput();
    if (missing === "protocols") { delete input["proto-ssh"]; delete input["proto-sftp"]; } else delete input[missing];
    await submit(env.root.dialog, input);
    assert.match(env.root.dialog.querySelector(".ra-error").textContent, /确认|协议|责任人|可读目录/);
    assert.equal(env.auth.length, 0); assert.equal(posts(env).length, 0);
  }
});

test("invalid grant duration is rejected before authentication or mutation", async () => {
  for (const hours of ["0", "721", "NaN", "Infinity", ""]) {
    const env = runtime(); await env.api.serverOnboarding(); await submit(env.root.dialog, defaultInput({ hours }));
    assert.match(env.root.dialog.querySelector(".ra-error").textContent, /授权时长/);
    assert.equal(env.auth.length, 0); assert.equal(posts(env).length, 0);
  }
});

test("password onboarding sends only exact declared fields, explicit roots and default-deny policies", async () => {
  const env = runtime(); await env.api.serverOnboarding(); const d = env.root.dialog;
  await submit(d, defaultInput({ injectedAdmin: "true", accountId: "other-account", allowClipboard: "on", allowDrives: "on", allowInteractive: "on", writeRoots: "/" }));
  assert.equal(posts(env).length, 1); const call = posts(env)[0], body = JSON.parse(call.options.body);
  assert.equal(call.url, "/api/v1/servers/onboard"); assert.equal(call.options.headers["X-CSRF-Token"], "test-csrf");
  assert.equal(call.options.credentials, "same-origin"); assert.equal(call.options.cache, "no-store");
  assert.deepEqual(body, { confirm: true, name: "Test server", osFamily: "linux", host: "192.0.2.10", username: "operator", authType: "password", protocols: ["ssh", "sftp"], sshPort: 22, sftpPort: 2222, rdpPort: 3389,
    claimantId: "person-1", organizationId: "org-1", secret: { password: secret }, readRoots: ["/srv/team", "/home/operator"], writeRoots: [], allowFileWrite: false, allowClipboard: false, allowDrives: false, allowInteractive: false,
    idempotencyKey: "00000000-0000-4000-8000-000000000002", expiresAt: "2026-10-18T08:00:00.000Z" });
  assert.deepEqual(env.opened, ["saved-asset"]); assert.equal(env.auth.length, 1);
  assert.equal(d.querySelector('[name="password"]').value, ""); assert.ok(d.querySelector("form").resetCount >= 1);
  assert.doesNotMatch(JSON.stringify(env.api.S), /synthetic-unit-test-password/); assert.deepEqual(env.storage, []);
});

test("explicit SFTP write consent only includes user-selected write roots", async () => {
  const env = runtime(); await env.api.serverOnboarding();
  await submit(env.root.dialog, defaultInput({ allowFileWrite: "on", writeRoots: " /srv/team/uploads, /home/operator/uploads " }));
  const body = JSON.parse(posts(env)[0].options.body);
  assert.equal(body.allowFileWrite, true); assert.deepEqual(body.writeRoots, ["/srv/team/uploads", "/home/operator/uploads"]);
});

test("private key and interactive auth exclude inactive secret fields", async () => {
  for (const type of ["private_key", "interactive"]) {
    const env = runtime(); await env.api.serverOnboarding(); const d = env.root.dialog;
    const input = defaultInput({ authType: type, privateKey: "synthetic-private-key", passphrase: "synthetic-key-passphrase" });
    if (type === "interactive") {
      delete input["proto-ssh"]; delete input["proto-sftp"];
      Object.assign(input, { osFamily: "windows", "proto-rdp": "on", allowInteractive: "on", allowClipboard: "on" });
    }
    await submit(d, input); const body = JSON.parse(posts(env)[0].options.body);
    assert.deepEqual(body.secret, type === "private_key" ? { privateKey: "synthetic-private-key", passphrase: "synthetic-key-passphrase" } : {});
    assert.equal(body.allowInteractive, type === "interactive");
    if (type === "interactive") { assert.deepEqual(body.readRoots, []); assert.equal(body.allowClipboard, true); }
    for (const field of ["password", "privateKey", "passphrase"]) assert.equal(d.querySelector(`[name="${field}"]`).value, "");
    assert.deepEqual(env.storage, []);
  }
});

test("retrying an identical intent after a lost response preserves exact expiry and idempotency key", async () => {
  let attempt = 0;
  const env = runtime((url) => { if (url.endsWith("/servers/onboard") && ++attempt === 1) throw Error("synthetic response lost"); });
  await env.api.serverOnboarding(); const d = env.root.dialog;
  await submit(d, defaultInput()); env.advance(75000); await submit(d, defaultInput());
  assert.equal(posts(env).length, 2); assert.equal(posts(env)[0].options.body, posts(env)[1].options.body);
  assert.deepEqual(env.opened, ["saved-asset"]); assert.deepEqual(env.storage, []);
});

test("editing a failed submission creates a distinct intent rather than replaying stale settings", async () => {
  let attempt = 0;
  const env = runtime((url) => { if (url.endsWith("/servers/onboard") && ++attempt === 1) throw Error("synthetic response lost"); });
  await env.api.serverOnboarding(); const d = env.root.dialog;
  await submit(d, defaultInput()); env.advance(75000); await submit(d, defaultInput({ host: "192.0.2.11" }));
  const [first, second] = posts(env).map((call) => JSON.parse(call.options.body));
  assert.notEqual(first.idempotencyKey, second.idempotencyKey); assert.notEqual(first.expiresAt, second.expiresAt); assert.equal(second.host, "192.0.2.11");
});

test("cancelled platform reauthentication does not post or clear the editable form", async () => {
  const env = runtime(); env.hooks.auth = async () => { throw Error("platform reauthentication cancelled"); };
  await env.api.serverOnboarding(); const d = env.root.dialog; await submit(d, defaultInput());
  assert.equal(posts(env).length, 0); assert.equal(d.open, true); assert.equal(d.querySelector("form").resetCount, 0);
  assert.match(d.querySelector(".ra-error").textContent, /cancelled/);
});

test("closing onboarding while reauthentication is pending resets secrets and never posts", async () => {
  const slow = pending(), env = runtime(); env.hooks.auth = () => slow.promise;
  await env.api.serverOnboarding(); const d = env.root.dialog, work = submit(d, defaultInput());
  await new Promise(setImmediate); d.close(); slow.resolve(); await work;
  assert.equal(posts(env).length, 0); assert.equal(d.querySelector('[name="password"]').value, ""); assert.deepEqual(env.opened, []);
});

test("duplicate submit while reauth or POST is pending does not issue a second operation", async () => {
  for (const stage of ["reauth", "post"]) {
    const slow = pending(), env = runtime((url) => stage === "post" && url.endsWith("/servers/onboard") ? slow.promise : undefined);
    if (stage === "reauth") env.hooks.auth = () => slow.promise;
    await env.api.serverOnboarding(); const d = env.root.dialog, work = submit(d, defaultInput());
    await new Promise(setImmediate); await submit(d, defaultInput());
    assert.equal(env.auth.length, 1); assert.ok(posts(env).length <= 1);
    slow.resolve(stage === "post" ? response({ assetId: "saved-asset" }) : undefined); await work;
    assert.equal(posts(env).length, 1);
  }
});

test("late directory responses after leaving or identity epoch changes never open onboarding", async () => {
  for (const directory of ["/people?", "/organizations/options"]) {
    const slow = pending(), env = runtime((url) => url.includes(directory) ? slow.promise : undefined);
    const work = env.api.serverOnboarding(); await new Promise(setImmediate);
    env.api.leave(); slow.resolve(response(directory === "/people?" ? [person] : [organization])); await work;
    assert.equal(env.created.length, 0); assert.equal(posts(env).length, 0);
  }
});

test("identity change during reauth prevents saving with another login", async () => {
  for (const bumpEpoch of [false, true]) {
    const slow = pending(), env = runtime(); env.hooks.auth = () => slow.promise;
    await env.api.serverOnboarding(); const d = env.root.dialog, work = submit(d, defaultInput());
    await new Promise(setImmediate); env.api.S.user = { ...admin, id: "different-admin" };
    if (bumpEpoch) env.api.S.renderEpoch++;
    slow.resolve(); await work; assert.equal(posts(env).length, 0); assert.deepEqual(env.opened, []);
  }
});

test("late successful save after close or identity invalidation never opens a connection dialog", async () => {
  for (const invalidate of ["close", "identity"]) {
    const slow = pending(), env = runtime((url) => url.endsWith("/servers/onboard") ? slow.promise : undefined);
    await env.api.serverOnboarding(); const d = env.root.dialog, work = submit(d, defaultInput());
    await new Promise(setImmediate);
    if (invalidate === "close") d.close(); else { env.api.S.user = { ...admin, id: "different-admin" }; env.api.S.renderEpoch++; }
    slow.resolve(response({ assetId: "saved-asset" })); await work;
    assert.deepEqual(env.opened, []); assert.equal(posts(env).length, 1); assert.equal(d.querySelector('[name="password"]').value, "");
  }
});

test("identity change during the post-save asset refresh cannot open the old user's connection", async () => {
  const slow = pending(), env = runtime((url) => url.startsWith("/api/v1/assets?") ? slow.promise : undefined);
  await env.api.serverOnboarding(); const work = submit(env.root.dialog, defaultInput());
  await new Promise(setImmediate); env.api.S.user = { ...admin, id: "different-admin" }; env.api.S.renderEpoch++;
  slow.resolve(response([])); await work;
  assert.deepEqual(env.opened, []);
});

test("logout starting during reauthentication prevents onboarding mutation", async () => {
  const slow = pending(), env = runtime(); env.hooks.auth = () => slow.promise;
  await env.api.serverOnboarding(); const work = submit(env.root.dialog, defaultInput());
  await new Promise(setImmediate); env.api.S.logoutPending = true; slow.resolve(); await work;
  assert.equal(posts(env).length, 0); assert.deepEqual(env.opened, []);
});
