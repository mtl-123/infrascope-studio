import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateConfig,
  normalizeDrives,
  secureLocalRequest,
  tokenEqual,
  newToken,
  approvedOrigin,
  deviceCanonical,
} from "../protocol.mjs";
const config = {
  address: "host.example",
  port: 3389,
  username: "DOMAIN\\user",
  password: "  password  ",
  redirectClipboard: true,
  redirectDrives: true,
  driveMode: "custom",
  driveList: "c:, D:\\",
  fullscreen: true,
  multiMonitor: false,
};
test("strict config preserves passwords and account notation", () => {
  assert.equal(validateConfig(config).password, "  password  ");
  assert.equal(normalizeDrives(config.driveList), "C:\\;D:\\");
  for (const username of [".\\user", "user@example.com", "电脑\\用户"])
    assert.equal(validateConfig({ ...config, username }).username, username);
  assert.equal(
    validateConfig({ ...config, address: "2001:db8::1" }).address,
    "2001:db8::1",
  );
});
test("invalid ports, targets, fields and booleans fail closed", () => {
  for (const invalid of [
    { port: "3389" },
    { port: 0 },
    { port: 65536 },
    { port: 22.5 },
    { address: "https://host" },
    { address: "host\nfoo" },
    { username: "x\r\ny" },
    { username: "" },
    { redirectDrives: "false" },
    { driveList: "C:\\secret" },
    { driveList: "\\\\server\\share" },
    { unknown: true },
    { password: "x".repeat(2049) },
  ])
    assert.throws(() => validateConfig({ ...config, ...invalid }));
  assert.doesNotThrow(() =>
    validateConfig({
      ...config,
      redirectDrives: false,
      driveList: "ignored invalid",
    }),
  );
  assert.doesNotThrow(() =>
    validateConfig({ ...config, username: "", password: "" }),
  );
});
test("loopback, DNS rebinding, Origin and token isolation", () => {
  const req = {
    socket: { remoteAddress: "127.0.0.1" },
    headers: {
      host: "localhost:4173",
      origin: "http://localhost:4173",
      "sec-fetch-site": "same-origin",
    },
  };
  assert(secureLocalRequest(req, 4173));
  for (const headers of [
    { host: "attacker.example:4173" },
    { origin: "https://attacker.example" },
    { "sec-fetch-site": "cross-site" },
  ])
    assert(
      !secureLocalRequest(
        { ...req, headers: { ...req.headers, ...headers } },
        4173,
      ),
    );
  assert(
    !secureLocalRequest(
      { ...req, socket: { remoteAddress: "192.0.2.1" } },
      4173,
    ),
  );
  const token = newToken();
  assert(tokenEqual(token, token));
  assert(!tokenEqual(token, token + "x"));
  assert(!tokenEqual(undefined, token));
  assert.throws(() => approvedOrigin("http://example.com"));
  assert.throws(() => approvedOrigin("https://user:password@example.com"));
  assert.equal(approvedOrigin("https://example.com"), "https://example.com");
  assert.notEqual(
    deviceCanonical("POST", "/a", "1", "nonce", "{}"),
    deviceCanonical("POST", "/b", "1", "nonce", "{}"),
  );
});
