import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import {
  validateLauncherQuery,
  validateLauncherRequest,
  launcherPayload,
  validateLauncherURL,
  launcherCatalog,
} from "../protocol.mjs";

const userId = "paired-user";
const request = {
  assetId: "_asset-1",
  accountId: "-account_1",
  protocol: "ssh",
  confirmed: true,
  idempotencyKey: "e3b484c2-3f28-4dfe-97c8-11cd34010e96",
  userId,
};
const platform = "https://127.0.0.1:18443";
const browserRequest = { ...request, userId };
const workspace = `${platform}/remote-workspace.html?assetId=_asset-1&accountId=-account_1&protocol=ssh&userId=${userId}`;
const item = {
  assetId: request.assetId,
  assetName: "Server",
  accountId: request.accountId,
  accountName: "SSH account",
  username: "operator",
  osFamily: "linux",
  protocol: "ssh",
  host: "192.0.2.1",
  port: 22,
};

test("native launcher requests contain only existing identifiers and explicit confirmation", () => {
  assert.deepEqual(validateLauncherRequest(request), request);
  for (const protocol of ["ssh", "sftp", "rdp"])
    assert.doesNotThrow(() => validateLauncherRequest({ ...request, protocol }));
  for (const extra of [
    { address: "192.0.2.2" },
    { host: "192.0.2.2" },
    { password: "never expose" },
    { privateKey: "never expose" },
    { username: "root" },
    { port: 3389 },
    { confirmed: false },
    { confirmed: "true" },
    { protocol: "RDP" },
    { protocol: "telnet" },
    { assetId: "" },
    { assetId: "a".repeat(121) },
    { assetId: "a\nb" },
    { assetId: "../asset" },
    { accountId: 42 },
    { userId: "" },
    { userId: 42 },
    { idempotencyKey: "" },
    { idempotencyKey: "a;b" },
  ]) assert.throws(() => validateLauncherRequest({ ...request, ...extra }));
  for (const field of Object.keys(request)) {
    const incomplete = { ...request };
    delete incomplete[field];
    assert.throws(() => validateLauncherRequest(incomplete));
  }
  for (const body of [null, [], true, "{}"])
    assert.throws(() => validateLauncherRequest(body));
});

test("launcher search limits size and excludes control characters", () => {
  assert.equal(validateLauncherQuery(" server "), "server");
  assert.equal(validateLauncherQuery(""), "");
  assert.equal(validateLauncherQuery("a".repeat(200)).length, 200);
  assert.equal(validateLauncherQuery("\u670d".repeat(66)).length, 66);
  for (const query of [null, 42, "a".repeat(201), "\u670d".repeat(67), "server\r\n", "x\0", "x\x7f"])
    assert.throws(() => validateLauncherQuery(query));
});

test("launcher never reuses a stale selection after pairing switches users", () => {
  const { userId: expected, ...payload } = request;
  assert.deepEqual(launcherPayload(request, expected), payload);
  assert(!Object.hasOwn(launcherPayload(request, expected), "userId"));
  for (const pairedUser of ["different-user", null, undefined]) {
    assert.throws(() => launcherPayload(request, pairedUser), { status: 409, code: "paired_user_changed" });
  }
  assert.throws(() => launcherPayload({ ...request, browserBindingId: "forged" }, expected));
  assert.throws(() => launcherPayload(payload, expected));
});

test("launcher workspace URLs cannot carry credentials, redirects or changed selections", () => {
  assert.equal(validateLauncherURL(workspace, platform, browserRequest), workspace);
  assert.equal(
    validateLauncherURL(workspace.replace("protocol=ssh", "protocol=sftp"), platform, { ...browserRequest, protocol: "sftp" }),
    workspace.replace("protocol=ssh", "protocol=sftp"),
  );
  for (const url of [
    workspace.replace("https:", "http:"),
    workspace.replace("127.0.0.1:18443", "evil.example"),
    workspace.replace("127.0.0.1:18443", "127.0.0.1:18444"),
    workspace.replace("https://", "https://user:password@"),
    workspace.replace("remote-workspace.html", "index.html"),
    workspace.replace("remote-workspace.html", "remote-workspace.html/extra"),
    workspace.replace("assetId=_asset-1", "assetId=other"),
    workspace.replace("accountId=-account_1", "accountId=other"),
    workspace.replace("protocol=ssh", "protocol=rdp"),
    workspace.replace("userId=paired-user", "userId=other-user"),
    workspace.replace("&userId=paired-user", ""),
    workspace.replace("&protocol=ssh", ""),
    workspace + "&token=secret",
    workspace + "&password=secret",
    workspace + "&assetId=_asset-1",
    workspace + "&userId=paired-user",
    workspace + "&returnUrl=https://evil.example",
    workspace + "#secret",
    "not a URL",
  ]) assert.throws(() => validateLauncherURL(url, platform, browserRequest));
  assert.throws(() => validateLauncherURL(workspace, platform, { ...browserRequest, protocol: "rdp" }));
  assert.throws(() => validateLauncherURL(workspace, platform, { ...request, userId: undefined }));
  assert.throws(() => validateLauncherURL(workspace, platform, { ...browserRequest, userId: "different-user" }));
});

test("catalog responses whitelist display metadata and discard all secret-shaped fields", () => {
  const result = launcherCatalog({
    items: [{ ...item, password: "secret", privateKey: "key", token: "token", credential: { password: "secret" } }],
    truncated: false,
    userId,
    signingKey: "never return",
  }, userId);
  assert.deepEqual(result, { items: [item], truncated: false, userId });
  assert.doesNotMatch(JSON.stringify(result), /secret|privateKey|token|credential|signingKey/);
  assert.deepEqual(launcherCatalog({ items: [], truncated: true, userId }, userId), { items: [], truncated: true, userId });
  assert.throws(() => launcherCatalog({ items: [item], truncated: false, userId }, "different-user"));
  assert.throws(() => launcherCatalog({ items: [item], truncated: false }, userId));
  assert.throws(() => launcherCatalog({ items: [item], truncated: false, userId }));
  for (const invalid of [
    null,
    { items: [], truncated: "false" },
    { items: Array(501).fill(item), truncated: false },
    { items: [{ ...item, protocol: "exec" }], truncated: false },
    { items: [{ ...item, port: 0 }], truncated: false },
    { items: [{ ...item, host: "server\ncommand" }], truncated: false },
    { items: [{ ...item, username: "x".repeat(513) }], truncated: false },
    { items: [{ ...item, assetId: "../asset" }], truncated: false },
  ]) assert.throws(() => launcherCatalog(invalid && { ...invalid, userId }, userId));
});

function requestHTTP(port, path, headers = {}, method = "GET", body) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, path, headers, method }, (response) => {
      let raw = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => raw += chunk);
      response.on("end", () => resolve({ status: response.statusCode, data: JSON.parse(raw) }));
    });
    request.on("error", reject);
    request.end(body);
  });
}

test("real loopback launcher API blocks cross-origin access, secret input and unpaired requests", async (t) => {
  const port = 44174;
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("../", import.meta.url),
    env: { ...process.env, PORT: String(port), INFRASCOPE_MODE: "controlled", INFRASCOPE_PLATFORM: "" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => child.kill());
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("Connector did not start")), 15000);
    child.stdout.once("data", () => { clearTimeout(timer); resolve(); });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code) => { clearTimeout(timer); reject(Error("Connector exited " + code)); });
  });
  const local = await requestHTTP(port, "/api/local-token");
  const headers = { "X-Pulse-Token": local.data.token };
  for (const path of ["/api/launcher/catalog", "/api/launcher/open"]) {
    assert.equal((await requestHTTP(port, path)).status, 403);
    assert.equal((await requestHTTP(port, path, { ...headers, Host: `evil.example:${port}` })).status, 403);
    assert.equal((await requestHTTP(port, path, { ...headers, Origin: platform })).status, 403);
    assert.equal((await requestHTTP(port, path, { ...headers, "Sec-Fetch-Site": "cross-site" })).status, 403);
  }
  assert.equal((await requestHTTP(port, "/api/launcher/catalog?q=server", headers)).status, 409);
  for (const query of ["?q=x&q=y", "?password=x", "?q=x%00", "?q=" + "x".repeat(201), "?q=" + encodeURIComponent("\u670d".repeat(67))])
    assert.equal((await requestHTTP(port, "/api/launcher/catalog" + query, headers)).status, 400);
  const jsonHeaders = { ...headers, "Content-Type": "application/json" };
  assert.equal((await requestHTTP(port, "/api/launcher/open", jsonHeaders, "POST", JSON.stringify(request))).status, 409);
  for (const body of ["{", "[]", "{}", JSON.stringify({ ...request, password: "secret" }), JSON.stringify({ ...request, confirmed: false })])
    assert.equal((await requestHTTP(port, "/api/launcher/open", jsonHeaders, "POST", body)).status, 400);
  assert.equal((await requestHTTP(port, "/api/launcher/open", headers, "POST", JSON.stringify(request))).status, 415);
  assert.equal((await requestHTTP(port, "/api/launcher/open?password=x", jsonHeaders, "POST", JSON.stringify(request))).status, 400);
  const status = await requestHTTP(port, "/api/status", headers);
  assert.equal(status.data.device, null);
  assert.deepEqual(status.data.launches, []);
});
