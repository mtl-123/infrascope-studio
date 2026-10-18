import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { parseIntent, authorizedAccount } = require("../dist/quick-launch-core.js");

test("quick links carry only validated references, never credentials", () => {
  assert.deepEqual(parseIntent("?assetId=_asset&accountId=-account&protocol=ssh&userId=u"), { assetId: "_asset", accountId: "-account", protocol: "ssh", userId: "u" });
  assert.equal(parseIntent("?sessionId=existing"), null);
  for (const query of ["?assetId=a", "?assetId=a&accountId=b&protocol=rdp", "?assetId=a&accountId=b&protocol=ssh&password=x", "?assetId=a&assetId=c&accountId=b&protocol=ssh", "?assetId=../a&accountId=b&protocol=sftp", "?assetId=a&accountId=b&protocol=ssh&token=x"]) assert.throws(() => parseIntent(query));
  assert.throws(() => parseIntent("?assetId=a&accountId=b&protocol=ssh"));
});
test("quick launch reauthorizes the exact asset, account and same-grant protocol", () => {
  const intent = { assetId: "a", accountId: "b", protocol: "ssh" };
  const valid = { asset_id: "a", account_id: "b", grants: [{ protocols: ["ssh"], actions: ["remoteAccount.use", "ssh.connect"] }] };
  assert.equal(authorizedAccount([valid], intent), valid);
  assert.throws(() => authorizedAccount([{ ...valid, asset_id: "other" }], intent));
  assert.throws(() => authorizedAccount([{ ...valid, grants: [{ protocols: ["sftp"], actions: ["remoteAccount.use", "ssh.connect"] }] }], intent));
  assert.throws(() => authorizedAccount([{ ...valid, grants: [{ protocols: ["ssh"], actions: ["remoteAccount.use"] }, { protocols: ["ssh"], actions: ["ssh.connect"] }] }], intent));
  assert.throws(() => authorizedAccount([], intent));
});
