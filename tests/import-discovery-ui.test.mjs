import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import core from "../dist/remote-assets-core.js";

const source = readFileSync(new URL("../dist/remote-access.js", import.meta.url), "utf8");
const deferred = () => { let resolve; const promise = new Promise((yes) => { resolve = yes; }); return { promise, resolve }; };
const tick = () => new Promise((resolve) => setImmediate(resolve));
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const admin = { role: "admin", displayName: "Admin", csrf: "test-csrf", permissions: ["asset.manage", "user.manage"] };
const people = [{ id: "person-1", display_name: "Alice", enabled: true }, { id: "person-2", display_name: "Disabled", enabled: false }];
const job = (state = "preview") => ({ id: "job-1", source: "csv", state, expiresAt: new Date(Date.now() + 1800000).toISOString(),
  counts: { ready: 1, duplicate: 1, invalid: 1 }, rows: [
    { rowNumber: 1, state: "ready", inventoryId: "unit-1", name: "First", payload: { ownership: { claimantId: "person-1" } } },
    { rowNumber: 2, state: "duplicate", inventoryId: "unit-2", name: "Duplicate" },
    { rowNumber: 3, state: "invalid", inventoryId: "unit-3", name: "<script>not markup</script>" },
  ] });

// These tests exercise handlers and race guards, not browser rendering or hardware acceptance.
class Element {
  constructor() { this.dataset = {}; this.children = new Map(); this.isConnected = true; this.disabled = false; this.options = []; this.listeners = new Map(); this.classList = { add() {}, remove() {}, toggle() {} }; this.checked = false; }
  set innerHTML(value) {
    this.html = value; this.children.clear();
    this.options = [...value.matchAll(/<option value="([^"]*)"([^>]*)>(.*?)<\/option>/gs)].map((match) => ({ value: match[1], selected: /selected/.test(match[2]), disabled: /disabled/.test(match[2]) }));
    this.rows = [...value.matchAll(/<input type="checkbox" name="importRow" value="([^"]*)"([^>]*)>/gs)].map((match) => ({ value: match[1], checked: /checked/.test(match[2]), disabled: /disabled/.test(match[2]) }));
  }
  get innerHTML() { return this.html || ""; }
  get selectedOptions() { return this.options.filter((option) => option.selected); }
  get value() { return this.options.length ? this.selectedOptions[0]?.value || this.options[0].value : this.rawValue || ""; }
  set value(value) { this.rawValue = value; for (const option of this.options) option.selected = option.value === value; }
  querySelector(selector) {
    if (!this.children.has(selector)) {
      const node = new Element();
      const name = selector.match(/^\[name="([^"]+)"\]$/)?.[1];
      if (name) {
        const select = this.innerHTML.match(new RegExp(`<select name="${name}"[^>]*>([\\s\\S]*?)</select>`));
        if (select) node.innerHTML = select[1];
      }
      this.children.set(selector, node);
    }
    return this.children.get(selector);
  }
  querySelectorAll(selector) { return selector === '[name="importRow"]:checked' ? this.rows.filter((row) => row.checked) : []; }
  append(node) { this.dialog = node; }
  showModal() { this.open = true; }
  close() { this.open = false; this.onclose?.(); }
  remove() { this.isConnected = false; }
  addEventListener(type, handler) { this.listeners.set(type, handler); }
  click() { this.onclick?.(); }
}

function runtime(handler) {
  const root = new Element(), calls = [], created = [];
  const window = { addEventListener() {}, InfraRemoteAssets: core };
  const document = { getElementById: (id) => id === "io-content" ? root : null, createElement: () => { const node = new Element(); created.push(node); return node; } };
  const context = vm.createContext({ window, document, Blob, TextDecoder, URL, URLSearchParams, Date, crypto: { randomUUID: () => "test" },
    location: { search: "", origin: "http://localhost", href: "http://localhost/#remote-access" }, setInterval: () => 1, clearInterval() {}, setTimeout: () => 1,
    confirm: () => true, fetch: async (url, options) => {
      calls.push({ url, options });
      if (handler) { const result = await handler(url, options); if (result) return result; }
      if (url.includes("/people?")) return response(people);
      if (url.endsWith("/organizations/options")) return response([{ id: "org-1", name: "Operations", enabled: true }]);
      if (url.endsWith("/users")) return response([{ id: "user-1", display_name: "Alice", username: "alice", enabled: true }]);
      if (url === "/api/v1/asset-imports/job-1") return response(job());
      return response([]);
    }, FormData: class { constructor(form) { return form; } } });
  vm.runInContext(source.replace("window.InfraRemote = { render, leave };", "window.InfraRemote = { render, leave, show, S, importEditor, importDetails, organizationPicker, organizationEditor, assetEditor, assetDetails, click, tabAllowed, setup: (element) => { root = element; view = element.querySelector('#ra-body'); } };"), context);
  const api = window.InfraRemote; api.setup(root); api.S.mounted = true; api.S.user = structuredClone(admin); api.S.csrf = "test-csrf";
  return { api, root, calls, created, context };
}
function form(fields) {
  const entries = Object.entries(fields).flatMap(([key, value]) => Array.isArray(value) ? value.map((item) => [key, item]) : [[key, value]]);
  return { get: (key) => entries.find(([name]) => name === key)?.[1] ?? null, getAll: (key) => entries.filter(([name]) => name === key).map(([, value]) => value), has: (key) => entries.some(([name]) => name === key), [Symbol.iterator]: () => entries[Symbol.iterator]() };
}
const submit = (d, fields) => d.querySelector("form").onsubmit({ preventDefault() {}, target: form(fields) });

test("preview requires a real active claimant, rejects oversized UTF-8 and excludes fabricated endpoint credentials", () => {
  for (const claimantId of ["", "unknown", "person-2"]) assert.throws(() => core.importPreviewPayload({ claimantId, csv: "inventoryId,name\nx,host" }, people), /负责人/);
  assert.throws(() => core.importPreviewPayload({ claimantId: "person-1", csv: "人".repeat(180000) }, people), /512/);
  assert.throws(() => core.importPreviewPayload({ claimantId: "person-1", csv: "" }, people), /CSV/);
  const result = core.importPreviewPayload({ claimantId: "person-1", organizationId: " org-1 ", csv: "inventoryId,name\nx,host", endpoints: ["fake"], password: "secret" }, people);
  assert.deepEqual(Object.keys(result).sort(), ["claimantId", "csv", "organizationId"]);
  assert.equal(result.organizationId, "org-1");
  assert.deepEqual(core.importPreviewPayload({ claimantId: "person-1", csv: "ignored" }, people, "local_discovery"), { claimantId: "person-1", organizationId: "" });
});

test("confirmation requires explicit unique ready/failed rows and a live preview, never selects all or created rows", () => {
  const preview = job();
  for (const values of [[], [1, 1], [2], [3], [4], [NaN], [1.5]]) assert.throws(() => core.importSelection(preview, values));
  assert.deepEqual(core.importSelection(preview, ["1"]), { confirm: true, rowNumbers: [1] });
  for (const state of ["confirmed", "cancelled", "unknown"]) assert.throws(() => core.importSelection({ ...preview, state }, [1]));
  for (const expiresAt of ["invalid", new Date(Date.now() - 1).toISOString()]) assert.throws(() => core.importSelection({ ...preview, expiresAt }, [1]), /过期/);
  preview.state = "partial"; preview.rows[0].state = "failed";
  assert.deepEqual(core.importSelection(preview, [1]).rowNumbers, [1]);
  preview.rows[0].state = "created";
  assert.throws(() => core.importSelection(preview, [1]));
});

test("asset organization is explicit only when present, preserving compatibility and explicit removal", () => {
  const base = { name: "Host", category: "server", kind: "physical", osFamily: "other", ownership: { state: "pending", claimantId: "person-1" }, endpoints: [] };
  assert.equal("organizationId" in core.assetPayload(base, { version: 2, organization_id: "org-1" }, people), false);
  assert.equal(core.assetPayload({ ...base, organizationId: "" }, { version: 2, organization_id: "org-1" }, people).organizationId, "");
  assert.equal(core.assetPayload({ ...base, organizationId: " org-2 " }, undefined, people).organizationId, "org-2");
  for (const organization_id of ["org-1", "missing-org", "disabled-org", ""]) {
    const existing = { version: 9, organization_id };
    assert.equal("organizationId" in core.assetPayload({ ...base, organizationId: organization_id, archived: true }, existing, people), false);
    assert.equal(core.assetPayload({ ...base, organizationId: "different-org" }, existing, people).organizationId, "different-org");
  }
});

test("read-only users cannot open import or organization operations, even with manually injected actions", async () => {
  const env = runtime(); env.api.S.user = { role: "user", permissions: [] };
  for (const action of ["import-new", "discovery-new", "import-detail", "import-template", "organization-new"]) {
    await env.api.click({ target: { closest: () => ({ dataset: { ra: action, id: "job-1" }, isConnected: true }) }, preventDefault() {} });
  }
  assert.equal(env.calls.length, 0); assert.equal(env.created.length, 0);
  assert.equal(env.api.tabAllowed("imports"), false); assert.equal(env.api.tabAllowed("organizations"), false);
});

test("import and organization views read real APIs without demo success and discard stale responses", async () => {
  const slow = deferred(); const env = runtime((url) => url === "/api/v1/asset-imports" ? slow.promise : undefined);
  const old = env.api.show("imports"); await env.api.show("organizations"); slow.resolve(response([job()])); await old;
  assert.equal(env.api.S.imports.length, 0);
  assert.match(env.root.querySelector("#ra-view").innerHTML, /不继承子组织或父组织权限/);
  const failed = runtime((url) => url === "/api/v1/asset-imports" ? response({ error: "database unavailable" }, 503) : undefined);
  await assert.rejects(failed.api.show("imports"), /database unavailable/);
  assert.equal(failed.api.S.imports.length, 0);
});

test("opening a preview loads real directories but never POSTs or preselects claimant", async () => {
  const env = runtime(); env.api.importEditor(); const d = env.root.dialog;
  assert.equal(d.querySelector("[type=submit]").disabled, true);
  await tick();
  assert.equal(d.querySelector("[type=submit]").disabled, false);
  assert.equal(d.querySelector('[name="claimantId"]').value, "");
  assert.equal(d.querySelector('[name="organizationId"]').value, "");
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 0);
  await submit(d, { claimantId: "", csv: "inventoryId,name\nx,Host", organizationId: "" });
  assert.match(d.querySelector(".ra-error").textContent, /负责人/);
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 0);
});

test("preview sends CSV with CSRF, then reads server preview; never auto-confirms or checks rows", async () => {
  const env = runtime((url, options) => url.endsWith("/preview") ? response(job()) : undefined);
  env.api.importEditor(); const d = env.root.dialog; await tick();
  await submit(d, { claimantId: "person-1", csv: "inventoryId,name\nunit-1,First", organizationId: "org-1" });
  const posts = env.calls.filter((call) => call.options.method === "POST");
  assert.equal(posts.length, 1); assert.equal(posts[0].url, "/api/v1/asset-imports/preview");
  assert.equal(posts[0].options.headers["X-CSRF-Token"], "test-csrf");
  assert.equal(JSON.parse(posts[0].options.body).claimantId, "person-1");
  assert.ok(env.calls.some((call) => call.url === "/api/v1/asset-imports/job-1"));
  const detail = env.root.dialog;
  assert.equal(detail.rows.filter((row) => row.checked).length, 0);
  assert.equal(detail.rows.filter((row) => !row.disabled).length, 1);
  assert.equal(detail.querySelector("[type=submit]").disabled, true);
  assert.match(detail.innerHTML, /&lt;script&gt;not markup&lt;\/script&gt;/);
  assert.equal(d.isConnected, false);
});

test("selected confirmation sends only explicit row numbers, rereads result and blocks duplicate submits", async () => {
  const slow = deferred(); let confirmed = false;
  const env = runtime((url) => {
    if (url.endsWith("/confirm")) return slow.promise;
    if (url.endsWith("/job-1") && confirmed) return response({ ...job("confirmed"), rows: [{ ...job().rows[0], state: "created", assetId: "asset-1" }] });
  });
  await env.api.importDetails("job-1"); const d = env.root.dialog;
  d.rows[0].checked = true; d.listeners.get("change")();
  const first = submit(d, { importRow: ["1"] });
  assert.equal(d.querySelector("[type=submit]").disabled, true);
  d.listeners.get("change")();
  await submit(d, { importRow: ["1"] });
  assert.equal(env.calls.filter((call) => call.url.endsWith("/confirm")).length, 1);
  confirmed = true; slow.resolve(response({ ...job("confirmed") })); await first;
  assert.deepEqual(JSON.parse(env.calls.find((call) => call.url.endsWith("/confirm")).options.body), { confirm: true, rowNumbers: [1] });
  assert.match(env.root.dialog.innerHTML, /asset-1/);
  assert.equal(env.root.dialog.querySelector("[type=submit]").disabled, true);
});

test("server conflict leaves selection and input intact and does not claim success", async () => {
  const env = runtime((url) => url.endsWith("/confirm") ? response({ error: "候选已过期", code: "preview_expired" }, 409) : undefined);
  await env.api.importDetails("job-1"); const d = env.root.dialog;
  d.rows[0].checked = true; d.listeners.get("change")();
  await submit(d, { importRow: ["1"] });
  assert.equal(d.isConnected, true); assert.equal(d.rows[0].checked, true);
  assert.match(d.querySelector(".ra-error").textContent, /候选已过期/);
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 1);
});

test("local discovery uses dedicated live route without CSV and labels hardware exclusions", async () => {
  const env = runtime((url) => {
    if (url === "/api/v1/discovery/local-preview") return response({ ...job(), source: "local_discovery" });
    if (url.endsWith("/job-1")) return response({ ...job(), source: "local_discovery", facts: { hostname: "wsl-host", kernel: "actual-kernel", interfaces: [{ name: "eth0", addresses: ["10.1.1.1"] }], mounts: [{ path: "/", type: "ext4" }] } });
  });
  env.api.importEditor("local_discovery"); const d = env.root.dialog; await tick();
  assert.match(d.innerHTML, /不等于 Rust Agent 或外部设备采集已完成/);
  await submit(d, { claimantId: "person-1", organizationId: "" });
  const post = env.calls.find((call) => call.options.method === "POST");
  assert.equal(post.url, "/api/v1/discovery/local-preview"); assert.equal("csv" in JSON.parse(post.options.body), false);
  assert.match(env.root.dialog.innerHTML, /wsl-host/); assert.match(env.root.dialog.innerHTML, /实际|真实/);
});

test("cancel sends explicit acknowledgement, preserves created-row display, and rereads server", async () => {
  let cancelled = false;
  const env = runtime((url) => {
    if (url.endsWith("/cancel")) { cancelled = true; return response(job("cancelled")); }
    if (url.endsWith("/job-1")) return response({ ...job(cancelled ? "cancelled" : "partial"), rows: [{ ...job().rows[0], state: "created", assetId: "already-created" }] });
  });
  await env.api.importDetails("job-1"); const d = env.root.dialog;
  d.querySelector("#ra-import-cancel").onclick(); await tick();
  const post = env.calls.find((call) => call.url.endsWith("/cancel"));
  assert.deepEqual(JSON.parse(post.options.body), { confirm: true });
  assert.match(env.root.dialog.innerHTML, /already-created/); assert.match(env.root.dialog.innerHTML, /已取消剩余候选/);
});

test("directory failure cannot unblock a preview or use stale demo contacts; retry keeps pending submit blocked", async () => {
  let fail = true; const pending = deferred();
  const env = runtime((url) => url.includes("/people?") && fail ? response({ error: "directory unavailable" }, 503) : url.endsWith("/preview") ? pending.promise : undefined);
  env.api.importEditor(); const d = env.root.dialog; await tick();
  assert.equal(d.querySelector("[type=submit]").disabled, true);
  assert.match(d.querySelector("#ra-import-people-error").textContent, /directory unavailable/);
  fail = false; d.querySelector("#ra-import-people-search").onclick(); await tick();
  const posting = submit(d, { claimantId: "person-1", csv: "inventoryId,name\na,Host", organizationId: "" });
  d.querySelector("#ra-import-people-search").onclick(); await tick();
  assert.equal(d.querySelector("[type=submit]").disabled, true);
  await submit(d, { claimantId: "person-1", csv: "inventoryId,name\na,Host", organizationId: "" });
  assert.equal(env.calls.filter((call) => call.url.endsWith("/preview")).length, 1);
  pending.resolve(response({ error: "validation failure" }, 422)); await posting;
});

test("late detail and directory responses after leaving cannot create dialogs or unlock old actions", async () => {
  const slow = deferred(), env = runtime((url) => url.endsWith("/job-1") ? slow.promise : undefined);
  const reading = env.api.importDetails("job-1"); env.api.leave(); slow.resolve(response(job())); await reading;
  assert.equal(env.created.length, 0);
  const directory = deferred(), second = runtime((url) => url.includes("/people?") ? directory.promise : undefined);
  second.api.importEditor(); const d = second.root.dialog; second.api.leave(); directory.resolve(response(people)); await tick();
  assert.equal(d.querySelector("[type=submit]").disabled, true);
});

test("organization picker preserves a disabled/missing original and blocks changes on failed reads", async () => {
  const env = runtime(); const d = new Element(); let ready;
  env.api.organizationPicker(d, "missing-org", (value) => { ready = value; }); await tick();
  assert.equal(ready, true); assert.equal(d.querySelector('[name="organizationId"]').value, "missing-org");
  assert.match(d.querySelector('[name="organizationId"]').innerHTML, /缺失或不可访问/);
  const failed = runtime((url) => url.endsWith("/organizations/options") ? response({ error: "directory denied" }, 403) : undefined);
  const other = new Element(); failed.api.organizationPicker(other, "org-kept", (value) => { ready = value; }); await tick();
  assert.equal(ready, false); assert.equal(other.querySelector('[name="organizationId"]').value, "org-kept");
  assert.match(other.querySelector("#ra-organization-error").textContent, /directory denied/);
});

test("organization options reads every page and excludes new disabled selections without losing original", async () => {
  const firstPage = Array.from({ length: 100 }, (_, index) => ({ id: "org-" + index, name: "Org " + index, enabled: true }));
  const env = runtime((url) => {
    if (url === "/api/remote-access/organizations/options") return response(firstPage);
    if (url === "/api/remote-access/organizations/options?offset=100") return response([{ id: "disabled", name: "Disabled", enabled: false }, { id: "last", name: "Last org", enabled: true }]);
  });
  const d = new Element(); let ready;
  env.api.organizationPicker(d, "org-0", (value) => { ready = value; }); await tick();
  assert.equal(ready, true);
  const select = d.querySelector('[name="organizationId"]');
  assert.equal(select.options.some((option) => option.value === "last"), true);
  assert.equal(select.options.find((option) => option.value === "disabled").disabled, true);
  assert.equal(select.value, "org-0");
});

test("organization editor preserves unknown members and optimistic version without granting connections", async () => {
  const env = runtime(); const org = { id: "org-1", name: "Ops", parent_id: "missing-parent", member_ids: ["user-1", "missing-user"], version: 7, enabled: true };
  env.api.organizationEditor(org); const d = env.root.dialog; await tick();
  assert.deepEqual(d.querySelector('[name="memberIds"]').selectedOptions.map((option) => option.value), ["user-1", "missing-user"]);
  assert.equal(d.querySelector('[name="parentId"]').value, "missing-parent");
  await submit(d, { name: "Ops", description: "Maintained", parentId: "", memberIds: ["user-1"], enabled: "on" });
  const post = env.calls.find((call) => call.options.method === "PATCH");
  assert.equal(post.url, "/api/remote-access/organizations/org-1");
  assert.deepEqual(JSON.parse(post.options.body), { version: 7, name: "Ops", description: "Maintained", parentId: "", memberIds: ["user-1"], enabled: true });
});

test("local CSV file decoding rejects malformed UTF-8 and oversized files while preserving prior text", async () => {
  const env = runtime(); env.api.importEditor(); const d = env.root.dialog; await tick();
  const textarea = d.querySelector('[name="csv"]'); textarea.value = "kept input";
  const fileInput = d.querySelector("#ra-import-file");
  for (const file of [{ name: "bad.csv", size: 2, arrayBuffer: async () => new Uint8Array([0xff, 0xfe]).buffer }, { name: "big.csv", size: 600000, arrayBuffer: async () => { assert.fail("must not read oversized bytes"); } }]) {
    fileInput.files = [file]; await fileInput.onchange({ target: fileInput });
    assert.equal(textarea.value, "kept input"); assert.match(d.querySelector("#ra-file-read-status").textContent, /失败/);
  }
  assert.equal(env.calls.filter((call) => call.options.method === "POST").length, 0);
});

test("asset editor waits for both independent directories and retains unchanged unavailable organization", async () => {
  const slow = deferred();
  const env = runtime((url) => url.endsWith("/organizations/options") ? slow.promise : undefined);
  env.api.S.user.permissions.push("remoteAccount.manage");
  env.api.assetEditor({ id: "asset-1", name: "Existing", version: 4, category: "server", kind: "physical", os_family: "other", organization_id: "missing-org", canManage: true,
    endpoints: [], ownershipLegacy: false, ownership: { state: "pending", claimantId: "person-1" } });
  const d = env.root.dialog; await tick();
  assert.equal(d.querySelector("[type=submit]").disabled, true, "people success alone cannot unlock organization loading");
  slow.resolve(response([])); await tick();
  assert.equal(d.querySelector("[type=submit]").disabled, false);
  assert.equal(d.querySelector('[name="organizationId"]').value, "missing-org");
  await submit(d, { name: "Renamed", category: "server", kind: "physical", osFamily: "other", organizationId: "missing-org", "ownership-state": "pending", "ownership-claimantId": "person-1", enabled: "on" });
  const patch = env.calls.find((call) => call.options.method === "PATCH");
  assert.ok(patch);
  const payload = JSON.parse(patch.options.body);
  assert.equal(payload.version, 4); assert.equal(payload.name, "Renamed");
  assert.equal("organizationId" in payload, false);
});

test("successful confirm followed by failed readback reports uncertain result with retained job ID", async () => {
  let committed = false;
  const env = runtime((url) => {
    if (url.endsWith("/confirm")) { committed = true; return response(job("confirmed")); }
    if (url.endsWith("/job-1") && committed) return response({ error: "read failure" }, 503);
  });
  await env.api.importDetails("job-1"); const d = env.root.dialog; d.rows[0].checked = true; d.listeners.get("change")();
  await submit(d, { importRow: ["1"] });
  assert.equal(d.isConnected, true);
  assert.match(d.querySelector(".ra-error").textContent, /服务器已处理.*job-1.*不要把此错误当作全部创建失败/);
  assert.equal(d.querySelector("[type=submit]").disabled, true, "successful mutation must not reenable old preview when result read fails");
  d.listeners.get("change")();
  assert.equal(d.querySelector("[type=submit]").disabled, true);
});

test("successful cancellation followed by failed readback disables stale preview and identifies committed cancellation", async () => {
  let cancelled = false;
  const env = runtime((url) => {
    if (url.endsWith("/cancel")) { cancelled = true; return response(job("cancelled")); }
    if (url.endsWith("/job-1") && cancelled) return response({ error: "read failure" }, 503);
  });
  await env.api.importDetails("job-1"); const d = env.root.dialog; d.rows[0].checked = true; d.listeners.get("change")();
  d.querySelector("#ra-import-cancel").onclick(); await tick();
  assert.match(d.querySelector(".ra-error").textContent, /取消已提交.*job-1.*待回读/);
  assert.equal(d.querySelector("[type=submit]").disabled, true);
  d.listeners.get("change")(); assert.equal(d.querySelector("[type=submit]").disabled, true);
  assert.equal(d.querySelector("#ra-import-refresh").disabled, false);
  await submit(d, { importRow: ["1"] });
  assert.equal(env.calls.filter((call) => call.url.endsWith("/confirm")).length, 0);
});

test("slow detail refresh cannot reopen its origin modal after close", async () => {
  const slow = deferred(); let reads = 0;
  const env = runtime((url) => url.endsWith("/job-1") && ++reads > 1 ? slow.promise : undefined);
  await env.api.importDetails("job-1"); const d = env.root.dialog;
  d.querySelector("#ra-import-refresh").onclick(); await tick();
  d.close(); slow.resolve(response(job())); await tick();
  assert.equal(env.created.length, 1, "closed origin must suppress late replacement modal");
  assert.equal(d.isConnected, false);
});

test("slow preview result cannot reopen a modal after the input dialog closes", async () => {
  const slow = deferred();
  const env = runtime((url) => url.endsWith("/preview") ? response(job()) : url.endsWith("/job-1") ? slow.promise : undefined);
  env.api.importEditor(); const d = env.root.dialog; await tick();
  const posting = submit(d, { claimantId: "person-1", csv: "inventoryId,name\na,Host", organizationId: "" }); await tick();
  d.close(); slow.resolve(response(job())); await posting;
  assert.equal(env.created.length, 1);
});

test("slow confirm result cannot reopen a modal after the confirmation dialog closes", async () => {
  const slow = deferred(); let reads = 0;
  const env = runtime((url) => url.endsWith("/confirm") ? response(job("confirmed")) : url.endsWith("/job-1") && ++reads > 1 ? slow.promise : undefined);
  await env.api.importDetails("job-1"); const d = env.root.dialog; d.rows[0].checked = true; d.listeners.get("change")();
  const posting = submit(d, { importRow: ["1"] }); await tick();
  d.close(); slow.resolve(response(job("confirmed"))); await posting;
  assert.equal(env.created.length, 1);
});

test("closing final preview, confirmed, or cancelled detail refreshes its imports list exactly once", async () => {
  for (const state of ["preview", "confirmed", "cancelled"]) {
    const env = runtime((url) => url === "/api/v1/asset-imports" ? response([job(state)]) : url.endsWith("/job-1") ? response(job(state)) : undefined);
    env.api.S.tab = "imports";
    await env.api.importDetails("job-1"); const d = env.root.dialog; d.close(); await tick();
    assert.equal(env.calls.filter((call) => call.url === "/api/v1/asset-imports").length, 1);
    assert.equal(env.api.S.imports[0].state, state);
    assert.match(env.root.querySelector("#ra-view").innerHTML, /job-1/);
  }
});

test("replacement detail does not refresh behind itself until the final dialog closes", async () => {
  let confirmed = false;
  const env = runtime((url) => {
    if (url.endsWith("/confirm")) { confirmed = true; return response(job("confirmed")); }
    if (url.endsWith("/job-1")) return response(job(confirmed ? "confirmed" : "preview"));
    if (url === "/api/v1/asset-imports") return response([job("confirmed")]);
  });
  env.api.S.tab = "imports";
  await env.api.importDetails("job-1"); const first = env.root.dialog; first.rows[0].checked = true; first.listeners.get("change")();
  await submit(first, { importRow: ["1"] });
  assert.equal(env.calls.filter((call) => call.url === "/api/v1/asset-imports").length, 0);
  const result = env.root.dialog; assert.notEqual(result, first); result.close(); await tick();
  assert.equal(env.calls.filter((call) => call.url === "/api/v1/asset-imports").length, 1);
  assert.equal(env.api.S.imports[0].state, "confirmed");
});

test("closing stale or left detail cannot navigate back to imports, and late refresh cannot override another tab", async () => {
  for (const leave of [false, true]) {
    const env = runtime(); env.api.S.tab = "imports";
    await env.api.importDetails("job-1"); const d = env.root.dialog;
    if (leave) env.api.leave(); else await env.api.show("organizations");
    d.close(); await tick();
    assert.equal(env.calls.filter((call) => call.url === "/api/v1/asset-imports").length, 0);
  }
  const slow = deferred(); const env = runtime((url) => url === "/api/v1/asset-imports" ? slow.promise : undefined);
  env.api.S.tab = "imports"; await env.api.importDetails("job-1"); env.root.dialog.close();
  await env.api.show("organizations"); slow.resolve(response([job()])); await tick();
  assert.equal(env.api.S.tab, "organizations"); assert.equal(env.api.S.imports.length, 0);
  assert.match(env.root.querySelector("#ra-view").innerHTML, /手工组织范围/);
});

test("preview created but failed detail read refreshes list on input close instead of hiding the task", async () => {
  const env = runtime((url) => url.endsWith("/preview") ? response(job()) : url.endsWith("/job-1") ? response({ error: "read failed" }, 503) : url === "/api/v1/asset-imports" ? response([job()]) : undefined);
  env.api.S.tab = "imports"; env.api.importEditor(); const d = env.root.dialog; await tick();
  await submit(d, { claimantId: "person-1", csv: "inventoryId,name\na,Host", organizationId: "" });
  assert.match(d.querySelector(".ra-error").textContent, /任务已生成/);
  d.close(); await tick(); assert.equal(env.api.S.imports[0].id, "job-1");
});

test("asset detail renders explicit server provenance without guessing missing origins or live health", async () => {
  const timestamp = "2026-10-18T09:20:31.123456789Z";
  for (const [origin, label] of [[undefined, "手工 / 旧记录待核实"], [{ kind: "csv", jobId: "csv-job", observedAt: timestamp }, "CSV 导入"], [{ kind: "local_discovery", jobId: "local-job", observedAt: timestamp }, "WSL 本机发现一次快照"], [{ kind: "unknown", jobId: "<unsafe>" }, "未识别的来源记录"]]) {
    const asset = { id: "asset-1", name: "Host", version: 1, category: "server", endpoints: [], origin };
    const env = runtime((url) => url === "/api/v1/assets/asset-1" ? response(asset) : undefined);
    await env.api.assetDetails("asset-1"); const html = env.root.dialog.innerHTML;
    assert.ok(html.includes(label)); assert.match(html, /不是实时趋势或持续采集/);
    if (origin?.observedAt) assert.ok(html.includes(timestamp), "must preserve server observation precision, not browser current time");
    assert.doesNotMatch(html, /<unsafe>/);
  }
});
