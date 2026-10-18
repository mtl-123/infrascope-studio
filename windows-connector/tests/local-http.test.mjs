import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
const port = 44173;
const child = spawn(process.execPath, ["server.mjs"], {
  cwd: new URL("../", import.meta.url),
  env: { ...process.env, PORT: String(port), INFRASCOPE_MODE: "controlled" },
  stdio: ["ignore", "pipe", "pipe"],
});
await new Promise((resolve, reject) => {
  child.stdout.once("data", resolve);
  child.once("error", reject);
  child.once("exit", (code) => reject(Error("Connector exited " + code)));
});
function req(path, headers = {}, method = "GET", body) {
  return new Promise((resolve, reject) => {
    const r = http.request(
      { host: "127.0.0.1", port, path, method, headers },
      (res) => {
        let data = "";
        res.on("data", (b) => (data += b));
        res.on("end", () =>
          resolve({ status: res.statusCode, headers: res.headers, data }),
        );
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}
test("real HTTP API protects localhost and reports unsupported platform", async () => {
  try {
    const page = await req("/");
    assert.equal(page.status, 200);
    assert.match(page.data, /rdpForm/);
    assert.match(
      page.headers["content-security-policy"],
      /frame-ancestors 'none'/,
    );
    assert.equal(page.headers["x-frame-options"], "DENY");
    assert.equal(
      (await req("/api/local-token", { Host: "evil.example:44173" })).status,
      403,
    );
    assert.equal(
      (await req("/api/local-token", { Origin: "https://evil.example" }))
        .status,
      403,
    );
    assert.equal((await req("/api/status")).status, 403);
    const navigation = {
      "Sec-Fetch-Site": "cross-site",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Dest": "document",
    };
    assert.equal((await req("/", navigation)).status, 200);
    assert.equal((await req("/index.html", navigation, "HEAD")).status, 200);
    assert.equal((await req("/", { ...navigation, "Sec-Fetch-Site": "same-site" })).status, 200);
    assert.equal((await req("/api/local-token", navigation)).status, 403);
    assert.equal((await req("/api/status", navigation)).status, 403);
    assert.equal((await req("/app.js", navigation)).status, 403);
    assert.equal((await req("/", { ...navigation, "Sec-Fetch-Dest": "iframe" })).status, 403);
    assert.equal((await req("/", { ...navigation, "Sec-Fetch-Mode": "no-cors" })).status, 403);
    assert.equal((await req("/", { ...navigation, Origin: "https://127.0.0.1:18443" })).status, 403);
    assert.equal((await req("/", navigation, "POST")).status, 403);
    assert.equal((await req("/app.js", { "Sec-Fetch-Site": "same-origin" })).status, 200);
    const token = JSON.parse((await req("/api/local-token")).data);
    assert.equal(typeof token.token, "string");
    const status = await req("/api/status", { "X-Pulse-Token": token.token });
    assert.equal(status.status, 200);
    assert.equal(JSON.parse(status.data).mode, "controlled");
    assert(!JSON.stringify(JSON.parse(status.data)).includes(token.token));
    assert.equal((await req("/api/status", { ...navigation, "X-Pulse-Token": token.token })).status, 403);
    if (process.platform !== "win32") {
      assert.equal(token.available, false);
      assert.equal(
        (
          await req(
            "/api/rdp/connect",
            {
              "X-Pulse-Token": token.token,
              "Content-Type": "application/json",
            },
            "POST",
            "{}",
          )
        ).status,
        501,
      );
    }
    assert.equal((await req("/missing")).status, 404);
    assert.equal((await req("/", {}, "POST")).status, 405);
  } finally {
    child.kill();
  }
});
