import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import test from "node:test";
import vm from "node:vm";
import core from "../dist/remote-assets-core.js";

const source = readFileSync(new URL("../dist/remote-access.js", import.meta.url), "utf8");
const app = readFileSync(new URL("../dist/app.js", import.meta.url), "utf8");
const deferred = () => { let resolve; const promise = new Promise((yes) => { resolve = yes; }); return { promise, resolve }; };
const reply = (body) => ({ ok: true, json: async () => body });
const access = (account = "account-A", asset = "asset-A") => ({ asset_id: asset, account_id: account, grants: [{ protocols: ["sftp"], actions: ["remoteAccount.use", "sftp.list", "sftp.upload", "sftp.download"] }] });
const file = () => Object.assign(new Blob(["x"]), { name: "test.txt", lastModified: 1 });
class Element {
  constructor() { this.children = new Map(); this.dataset = {}; this.isConnected = true; this.value = ""; this.classList = { add() {}, remove() {}, toggle() {} }; }
  querySelector(s) { if (!this.children.has(s)) this.children.set(s, new Element()); return this.children.get(s); }
  querySelectorAll() { return []; }
  append() {}
  addEventListener() {}
  click() { this.clicked = true; }
}
// These are VM/fake DOM regression tests, not browser/target acceptance.
function harness(handler, { realRun = false, picker, savePicker, digest } = {}) {
  const root = new Element(), created = [], calls = [], errors = [];
  root.querySelector("#ra-conflict").value = "ask";
  const window = { addEventListener() {}, InfraRemoteAssets: core, showDirectoryPicker: picker, showSaveFilePicker: savePicker };
  const context = vm.createContext({ window, document: { getElementById() { return null; }, createElement() { const e = new Element(); created.push(e); return e; } },
    crypto: { randomUUID: () => "test-window", subtle: digest ? { digest } : webcrypto.subtle }, URL, URLSearchParams, Blob, AbortController, console,
    setInterval() { return 1; }, clearInterval() {}, setTimeout() { return 1; }, confirm() { return true; }, showDirectoryPicker: picker, showSaveFilePicker: savePicker,
    fetch: async (url, options) => {
      calls.push({ url, options });
      const result = handler && await handler(url, options); if (result) return result;
      if (url.endsWith("/my/access")) return reply([access()]);
      if (url.endsWith("/transfers")) return reply({ id: "task-A" });
      return reply({});
    } });
  vm.runInContext(source.replace("window.InfraRemote = { render, leave };", "window.InfraRemote = { S, pickFiles, filesView, runUpload, download, invalidateIdentity, leave, setup: (element, errors, realRun) => { root = element; view = element.querySelector('#ra-body'); show = async () => {}; msg = (message) => errors.push(message); if (!realRun) runUpload = async () => {}; } };"), context);
  const api = window.InfraRemote;
  api.setup(root, errors, realRun);
  api.S.user = { id: "user-A", gatewayId: "gateway", permissions: [] };
  api.S.mounted = true; api.S.csrf = "csrf-A"; api.S.tab = "files";
  api.S.access = [access()]; api.S.files = { account: "account-A", path: "/root-A", offset: 0 };
  return { api, root, created, calls, errors };
}
const writes = (env) => env.calls.filter(({ options }) => options.method !== "GET");
async function choose(env) { await env.api.pickFiles(); env.created.at(-1).files = [file()]; return env.created.at(-1); }
function otherTarget(env) { env.api.S.files = { account: "account-B", path: "/root-B", offset: 0 }; env.api.S.access = [access("account-B", "asset-B")]; }
function otherIdentity(env) { env.api.invalidateIdentity(); env.api.S.user = { id: "user-B", gatewayId: "gateway" }; env.api.S.csrf = "csrf-B"; env.api.S.mounted = true; }

test("network menu writes its own hash so refresh retains the selected page", () => {
  const root = new Element(), clicks = [], location = { hash: "#devices" };
  root.addEventListener = (type, fn) => { if (type === "click") clicks.push(fn); };
  const window = { InfraRemote: { render() {}, leave() {} }, renderNetwork() {} };
  vm.runInNewContext(app, { window, document: { getElementById: () => root }, location, history: { replaceState(_s, _t, hash) { location.hash = hash; } } });
  clicks.at(-1)({ target: { closest: () => ({ dataset: { page: "network" } }) } });
  assert.equal(location.hash, "#network");
});

test("selected upload remains bound to original account and path after permission refresh", async () => {
  const env = harness(); const input = await choose(env); await input.onchange();
  assert.equal(env.calls[0].url, "/api/remote-access/my/access");
  const data = JSON.parse(writes(env)[0].options.body);
  assert.equal(data.accountId, "account-A"); assert.equal(data.target, "/root-A");
});

test("file picker result cannot upload into a newly selected server", async () => {
  const env = harness(); const input = await choose(env); otherTarget(env); await input.onchange();
  assert.equal(writes(env).length, 0); assert.ok(env.errors.length);
});

test("file picker result cannot upload into a changed directory on the same server", async () => {
  const env = harness(); const input = await choose(env); env.api.S.files.path = "/other"; await input.onchange();
  assert.equal(writes(env).length, 0);
});

test("late file picker result after logout cannot mutate using a new identity", async () => {
  const env = harness(); const input = await choose(env); otherIdentity(env); otherTarget(env); await input.onchange();
  assert.equal(writes(env).length, 0);
});

test("late folder scan cannot change its destination", async () => {
  const slow = deferred(); const folder = { name: "folder", kind: "directory", async *values() { await slow.promise; yield { name: "test.txt", kind: "file", getFile: async () => file() }; } };
  const env = harness(undefined, { picker: async () => folder }); const work = env.api.pickFiles(true);
  await new Promise(setImmediate); otherTarget(env); slow.resolve(); await work.catch(() => {});
  assert.equal(writes(env).length, 0);
});

test("drop scan cannot change its destination", async () => {
  const slow = deferred();
  const env = harness((url) => url.includes("/sftp/entries?") ? reply({ path: "/root-A", entries: [], readRoots: ["/root-A"], writeRoots: ["/root-A"], total: 0, nextOffset: 0 }) : undefined);
  const target = new Element(); await env.api.filesView(target);
  const entry = { name: "test.txt", isFile: true, file(resolve) { slow.promise.then(() => resolve(file())); } };
  const work = target.querySelector("#ra-drop").ondrop({ preventDefault() {}, dataTransfer: { items: [{ webkitGetAsEntry: () => entry }] } });
  await new Promise(setImmediate); otherTarget(env); slow.resolve(); await work;
  assert.equal(writes(env).length, 0);
});

test("revoked or split-grant upload permission prevents task creation", async () => {
  for (const rows of [[], [{ ...access(), grants: [{ protocols: ["sftp"], actions: ["remoteAccount.use"] }, { protocols: ["sftp"], actions: ["sftp.upload"] }] }], [access("account-A", "other-asset")]]) {
    const env = harness((url) => url.endsWith("/my/access") ? reply(rows) : undefined); const input = await choose(env); await input.onchange();
    assert.equal(writes(env).length, 0);
  }
});

test("target switch during permission refresh prevents task creation", async () => {
  const slow = deferred(); const env = harness((url) => url.endsWith("/my/access") ? slow.promise : undefined);
  const input = await choose(env); const work = input.onchange(); await new Promise(setImmediate); otherTarget(env); slow.resolve(reply([access()])); await work;
  assert.equal(writes(env).length, 0);
});

test("late transfer creation after logout does not submit manifests under the next identity", async () => {
  const slow = deferred(); const env = harness((url) => url.endsWith("/transfers") ? slow.promise : undefined);
  const input = await choose(env); const work = input.onchange(); await new Promise(setImmediate); otherIdentity(env); slow.resolve(reply({ id: "task-A" })); await work;
  assert.equal(writes(env).length, 1); assert.equal(env.api.S.uploads.size, 0);
});

function uploadTask() { return { id: "task-A", items: [{ id: "item-A", relative_path: "test.txt", state: "running", is_directory: false, size: 1, modified_ms: 1, offset_bytes: 0, chunks: [] }] }; }
function localSource(env) { env.api.S.uploads.set("task-A", new Map([["test.txt", { path: "test.txt", file: file(), directory: false }]])); }

test("pending upload task read is identity-bound and stops after logout", async () => {
  const slow = deferred(); const env = harness((url) => url.endsWith("/transfers/task-A") ? slow.promise : undefined, { realRun: true });
  localSource(env); const work = env.api.runUpload("task-A"); await new Promise(setImmediate); otherIdentity(env); slow.resolve(reply(uploadTask())); await work.catch(() => {});
  assert.equal(writes(env).length, 0); assert.equal(env.api.S.uploadControllers?.size || 0, 0);
});

test("parallel resume clicks share a lock before the task metadata request finishes", async () => {
  const slow = deferred(); const env = harness((url) => url.endsWith("/transfers/task-A") ? slow.promise : undefined, { realRun: true });
  localSource(env); const first = env.api.runUpload("task-A"), second = env.api.runUpload("task-A").catch(() => {});
  await new Promise(setImmediate); const reads = env.calls.length; otherIdentity(env); slow.resolve(reply(uploadTask())); await Promise.allSettled([first, second]);
  assert.equal(reads, 1); assert.equal(writes(env).length, 0);
});

test("logout during a local chunk digest prevents sending that chunk or commit", async () => {
  const slow = deferred(), hashing = deferred();
  const env = harness((url) => url.endsWith("/transfers/task-A") ? reply(uploadTask()) : undefined, { realRun: true, digest: async () => { hashing.resolve(); return slow.promise; } });
  localSource(env); const work = env.api.runUpload("task-A"); await hashing.promise; otherIdentity(env); slow.resolve(new Uint8Array(32).buffer); await work.catch(() => {});
  assert.equal(writes(env).length, 0);
});

test("leaving the module during task read prevents later upload writes", async () => {
  const slow = deferred(); const env = harness((url) => url.endsWith("/transfers/task-A") ? slow.promise : undefined, { realRun: true });
  localSource(env); const work = env.api.runUpload("task-A"); await new Promise(setImmediate); env.api.leave(); slow.resolve(reply(uploadTask())); await work.catch(() => {});
  assert.equal(writes(env).length, 0);
});

test("normal upload sends a real chunk payload and commits only after confirmation", async () => {
  const env = harness((url) => url.endsWith("/transfers/task-A") ? reply(uploadTask()) : url.endsWith("/content") ? reply({ offset: 1 }) : url.endsWith("/commit") ? reply({ state: "completed" }) : undefined, { realRun: true });
  localSource(env); await env.api.runUpload("task-A");
  assert.deepEqual(writes(env).map(({ options }) => options.method), ["PUT", "POST"]);
  assert.equal(writes(env)[0].options.body.size, 1); assert.equal(writes(env)[0].options.headers["Upload-SHA256"].length, 64);
  assert.equal(env.api.S.uploadControllers.size, 0);
});

function downloadable(env) { env.api.S.files.list = [{ name: "test.txt" }]; }
function writerFixture() {
  const trace = [];
  const writer = { async write(bytes) { trace.push(["write", bytes.length]); }, async close() { trace.push(["close"]); }, async abort() { trace.push(["abort"]); } };
  const reader = { reads: 0, async read() { return this.reads++ ? { done: true } : { done: false, value: new Uint8Array([120]) }; }, async cancel() { trace.push(["cancel"]); }, releaseLock() { trace.push(["release"]); } };
  return { trace, writer, reader, handle: { createWritable: async () => writer }, response: { ok: true, body: { getReader: () => reader } } };
}

test("download picker cannot combine old names with a newly changed remote path", async () => {
  const slow = deferred(), io = writerFixture();
  const env = harness((url) => url.includes("/content") ? io.response : url.endsWith("/transfers/task-A") ? reply({ state: "completed" }) : undefined, { savePicker: () => slow.promise });
  downloadable(env); const work = env.api.download([0], true); env.api.S.files.path = "/different-directory"; slow.resolve(io.handle); await work.catch(() => {});
  assert.equal(writes(env).length, 0); assert.equal(io.trace.length, 0);
});

test("download picker cannot submit after logout as a different identity", async () => {
  const slow = deferred(), io = writerFixture();
  const env = harness((url) => url.includes("/content") ? io.response : url.endsWith("/transfers/task-A") ? reply({ state: "completed" }) : undefined, { savePicker: () => slow.promise });
  downloadable(env); const work = env.api.download([0], true); otherIdentity(env); slow.resolve(io.handle); await work.catch(() => {});
  assert.equal(writes(env).length, 0); assert.equal(io.trace.length, 0);
});

test("download rechecks same-account permission before creating any task", async () => {
  const io = writerFixture();
  const env = harness((url) => url.endsWith("/my/access") ? reply([]) : url.includes("/content") ? io.response : url.endsWith("/transfers/task-A") ? reply({ state: "completed" }) : undefined, { savePicker: async () => io.handle });
  downloadable(env); await env.api.download([0], true).catch(() => {});
  assert.equal(writes(env).length, 0); assert.equal(io.trace.length, 0);
});

test("late accepted download task after logout never opens a file writer or stream", async () => {
  const slow = deferred(), io = writerFixture();
  const env = harness((url) => url.endsWith("/transfers") ? slow.promise : url.includes("/content") ? io.response : url.endsWith("/transfers/task-A") ? reply({ state: "completed" }) : undefined, { savePicker: async () => io.handle });
  downloadable(env); const work = env.api.download([0], true); await new Promise(setImmediate); otherIdentity(env); slow.resolve(reply({ id: "task-A" })); await work.catch(() => {});
  assert.equal(writes(env).length, 1); assert.equal(io.trace.length, 0); assert.ok(!env.calls.some(({ url }) => url.includes("/content")));
});

test("logout during download read aborts the writer without declaring completion", async () => {
  const slow = deferred(), reading = deferred(), io = writerFixture();
  io.reader.read = async () => { reading.resolve(); return slow.promise; };
  const env = harness((url) => url.includes("/content") ? io.response : url.endsWith("/transfers/task-A") ? reply({ state: "completed" }) : undefined, { savePicker: async () => io.handle });
  downloadable(env); const work = env.api.download([0], true); await reading.promise; otherIdentity(env); slow.resolve({ done: true }); await work.catch(() => {});
  assert.ok(io.trace.some(([kind]) => kind === "abort")); assert.ok(!io.trace.some(([kind]) => kind === "close")); assert.ok(io.trace.some(([kind]) => kind === "release"));
});

test("normal download closes a local writer only after the server confirms completed", async () => {
  const io = writerFixture();
  const env = harness((url) => url.includes("/content") ? io.response : url.endsWith("/transfers/task-A") ? reply({ state: "completed" }) : undefined, { savePicker: async () => io.handle });
  downloadable(env); await env.api.download([0], true);
  assert.equal(JSON.parse(writes(env)[0].options.body).target, "/root-A");
  assert.ok(io.trace.some(([kind]) => kind === "write")); assert.ok(io.trace.some(([kind]) => kind === "close")); assert.ok(!io.trace.some(([kind]) => kind === "abort"));
});

test("incomplete server download aborts the writer rather than reporting local success", async () => {
  const io = writerFixture();
  const env = harness((url) => url.includes("/content") ? io.response : url.endsWith("/transfers/task-A") ? reply({ state: "failed" }) : undefined, { savePicker: async () => io.handle });
  downloadable(env); await env.api.download([0], true);
  assert.ok(io.trace.some(([kind]) => kind === "abort")); assert.ok(!io.trace.some(([kind]) => kind === "close")); assert.ok(env.errors.some((message) => message.includes("failed")));
});
