import assert from "node:assert/strict";
import test from "node:test";
import core from "../dist/remote-assets-core.js";

const people = [{ id: "operator-1", enabled: true }, { id: "owner-2", enabled: true }, { id: "disabled-person", enabled: false }];
const payload = (value, existing) => core.assetPayload(value, existing, people);
const fields = () => ({ name: "Lab host", kind: "virtual", osFamily: "linux", category: "server", enabled: true, archived: false,
  ownership: { state: "assigned", userId: "operator-1" },
  tags: "lab, lab, testing", endpoints: [{ enabled: true, protocol: "ssh", host: "127.0.0.1", port: "22", gatewayId: "lab" }] });

test("asset form preserves optimistic version and protocol boundaries", () => {
  const value = fields();
  value.endpoints.push({ enabled: false, protocol: "rdp", host: "", port: "", gatewayId: "" });
  const result = payload(value, { version: 3, inventory_id: "existing-reference" });
  assert.equal(result.version, 3);
  assert.equal(result.inventoryId, "existing-reference");
  assert.equal(result.endpoints.length, 1);
  assert.equal(result.endpoints[0].port, 22);
  assert.deepEqual(result.tags, ["lab", "testing"]);
  assert.equal("password" in result, false);
  assert.equal("version" in payload(fields()), false);
});

test("invalid asset fields cannot be submitted; disabled-only protocols allow inventory-only assets", () => {
  for (const port of ["", "0", "65536", "22.5", "NaN"]) {
    const value = fields(); value.endpoints[0].port = port;
    assert.throws(() => payload(value), /端口/);
  }
  const value = fields(); value.endpoints[0].enabled = false;
  assert.deepEqual(payload(value).endpoints, []);
  assert.throws(() => payload({ ...fields(), name: " " }), /资产名称/);
  const badHost = fields(); badHost.endpoints[0].host = "ssh://host/path";
  assert.throws(() => payload(badHost), /地址/);
});

test("IPv6 and independent SFTP/RDP ports remain unchanged", () => {
  const value = fields();
  value.endpoints = [{ enabled: true, protocol: "sftp", host: "::1", port: "2222", gatewayId: "lab" },
    { enabled: true, protocol: "rdp", host: "rdp.example.test", port: "3390", gatewayId: "lab" }];
  assert.deepEqual(payload(value).endpoints.map((endpoint) => endpoint.port), [2222, 3390]);
});

test("asset category is independent of kind and OS and stores contextual fields", () => {
  for (const category of ["server", "nas", "pve", "switch", "printer", "scanner", "other"]) {
    const result = payload({ ...fields(), category, kind: "physical", osFamily: "other", endpoints: [], environment: " prod ", site: " lab ", business: " finance " });
    assert.equal(result.category, category);
    assert.equal(result.kind, "physical");
    assert.equal(result.osFamily, "other");
    assert.equal(result.environment, "prod");
    assert.equal(result.site, "lab");
    assert.equal(result.business, "finance");
    assert.deepEqual(result.endpoints, []);
    assert.equal("online" in result, false);
    assert.equal("collected" in result, false);
  }
  for (const [key, value] of [["category", ""], ["category", "fake"], ["kind", "printer"], ["osFamily", "pve"]]) {
    assert.throws(() => payload({ ...fields(), [key]: value }));
  }
});

test("asset update preserves exposed fields and inventory version while excluding unknown metadata and fake status", () => {
  const value = { ...fields(), description: " Existing description ", groupName: " Business ", provider: " PVE ", vmName: "VM", instanceId: "100", hypervisorLabel: "node", metadata: { unknown: "must-not-send" }, online: true };
  const result = payload(value, { version: 8, inventory_id: "inventory-1", metadata: { unknown: "must-not-send" } });
  assert.equal(result.version, 8);
  assert.equal(result.inventoryId, "inventory-1");
  assert.equal(result.description, "Existing description");
  assert.equal(result.groupName, "Business");
  assert.deepEqual(result.metadata, { provider: "PVE", vmName: "VM", instanceId: "100", hypervisorLabel: "node" });
  assert.equal("online" in result, false);
});

test("new and legacy assets require explicit responsibility state and a valid assigned or pending person", () => {
  for (const ownership of [undefined, {}, { state: "" }, { state: "assigned" }, { state: "pending" }, { state: "pending", userId: "operator-1" },
    { state: "assigned", userId: "operator-1", claimantId: "owner-2" }, { state: "pending", userId: "operator-1", claimantId: "owner-2" }]) {
    assert.throws(() => payload({ ...fields(), ownership }));
    assert.throws(() => payload({ ...fields(), ownership }, { version: 2, ownershipLegacy: true }));
  }
  assert.deepEqual(payload({ ...fields(), ownership: { state: "pending", claimantId: "owner-2" } }).ownership, {
    state: "pending", userId: "", claimantId: "owner-2", operationsId: "", businessId: "", notificationIds: [], backupIds: [],
  });
  const result = payload(fields(), { version: 7, ownershipLegacy: true });
  assert.equal(result.version, 7);
  assert.equal("ownershipLegacy" in result, false);
  assert.equal(result.ownership.userId, "operator-1");
});

test("missing, disabled, duplicate and oversized responsibility selections are rejected without fake fallback", () => {
  for (const id of ["unknown", "disabled-person", "x".repeat(121)]) {
    assert.throws(() => payload({ ...fields(), ownership: { state: "assigned", userId: id } }));
    assert.throws(() => payload({ ...fields(), ownership: { state: "assigned", userId: "operator-1", notificationIds: [id] } }));
  }
  assert.throws(() => core.assetPayload(fields(), undefined, []), /责任人员/);
  for (const key of ["notificationIds", "backupIds"]) {
    for (const values of [["operator-1", "operator-1"], [""], "operator-1"]) {
      assert.throws(() => payload({ ...fields(), ownership: { ...fields().ownership, [key]: values } }));
    }
    const many = Array.from({ length: 21 }, (_, index) => ({ id: "person-" + index, enabled: true }));
    assert.throws(() => core.assetPayload({ ...fields(), ownership: { ...fields().ownership, [key]: many.map((person) => person.id) } }, undefined, [...people, ...many]), /20/);
    const ownership = { ...fields().ownership, operationsId: "operator-1", [key]: ["operator-1", "owner-2"] };
    assert.deepEqual(payload({ ...fields(), ownership }).ownership[key], ownership[key]);
  }
});

test("unchanged nonlegacy responsibility omits ownership so disabled or missing prior references do not block archival", () => {
  for (const personId of ["disabled-person", "missing-person", "operator-1"]) {
    const ownership = { state: "assigned", userId: personId, claimantId: "", operationsId: "", businessId: "",
      notificationIds: ["owner-2", personId], backupIds: ["operator-1", "owner-2"] };
    const existing = { version: 12, ownershipLegacy: false, ownership };
    const before = structuredClone(existing);
    const value = { ...fields(), enabled: false, archived: true, ownership: { ...ownership, notificationIds: [...ownership.notificationIds].reverse(), backupIds: [...ownership.backupIds].reverse() } };
    const inputBefore = structuredClone(value);
    const result = payload(value, existing);
    assert.equal("ownership" in result, false);
    assert.equal(result.version, 12);
    assert.equal(result.enabled, false);
    assert.equal(result.archived, true);
    assert.deepEqual(existing, before, "comparison must not mutate the original history snapshot");
    assert.deepEqual(value, inputBefore, "set comparison must not sort the form arrays in place");
  }
});

test("changing any responsibility requires every retained reference to remain active", () => {
  const ownership = { state: "assigned", userId: "operator-1", operationsId: "disabled-person", notificationIds: ["owner-2"], backupIds: [] };
  const existing = { version: 2, ownershipLegacy: false, ownership };
  for (const change of [{ businessId: "owner-2" }, { userId: "owner-2" }, { notificationIds: [] }, { backupIds: ["operator-1"] }, { state: "pending", userId: "", claimantId: "owner-2" }]) {
    assert.throws(() => payload({ ...fields(), ownership: { ...ownership, ...change } }, existing), /责任人员/);
  }
  const result = payload({ ...fields(), ownership: { ...ownership, operationsId: "owner-2" } }, existing);
  assert.equal(result.ownership.operationsId, "owner-2");
  assert.throws(() => payload({ ...fields(), ownership }, { ...existing, ownershipLegacy: true }), /责任人员/);
  assert.throws(() => payload({ ...fields(), ownership }, { ...existing, ownershipLegacy: undefined }), /责任人员/);
});

test("unchanged pending ownership normalizes absent optional fields but never treats changes or duplicates as equal", () => {
  const ownership = { state: "pending", claimantId: "disabled-person", notificationIds: ["owner-2"], backupIds: [] };
  const existing = { version: 3, ownershipLegacy: false, ownership };
  const value = { ...fields(), ownership: { ...ownership, userId: null, operationsId: "", businessId: "" } };
  assert.equal("ownership" in payload(value, existing), false);
  for (const change of [{ claimantId: "owner-2" }, { state: "assigned", claimantId: "", userId: "operator-1" }, { notificationIds: ["owner-2", "owner-2"] }, { notificationIds: "owner-2" }]) {
    assert.equal(core.ownershipUnchanged(existing, { ...ownership, ...change }), false);
  }
  assert.equal(core.ownershipUnchanged(existing, undefined), false);
});

test("submit gate keeps duplicate saves blocked when a picker refresh finishes during a pending save", async () => {
  let submitting = false, ready = true, posts = 0, finish;
  const pending = new Promise((resolve) => { finish = resolve; });
  const save = async () => {
    if (core.submitDisabled(submitting, ready)) return;
    submitting = true;
    posts++;
    try { await pending; } finally { submitting = false; }
  };
  const first = save();
  ready = false;
  assert.equal(core.submitDisabled(submitting, ready), true);
  ready = true;
  assert.equal(core.submitDisabled(submitting, ready), true, "successful picker reload cannot unlock a pending save");
  await save();
  assert.equal(posts, 1);
  ready = false;
  finish();
  await first;
  assert.equal(core.submitDisabled(submitting, ready), true, "a finished save cannot unlock a failed picker load");
  await save();
  assert.equal(posts, 1);
  ready = true;
  assert.equal(core.submitDisabled(submitting, ready), false);
});

test("UTF-8 byte lengths match server constraints for Chinese asset and person fields", () => {
  assert.equal(payload({ ...fields(), name: "人".repeat(60) }).name.length, 60);
  assert.throws(() => payload({ ...fields(), name: "人".repeat(61) }), /UTF-8/);
  for (const field of ["environment", "site", "business"]) {
    assert.equal(payload({ ...fields(), [field]: "人".repeat(40) })[field].length, 40);
    assert.throws(() => payload({ ...fields(), [field]: "人".repeat(41) }), /UTF-8/);
  }
  const person = { displayName: "人".repeat(60), department: "部".repeat(80), email: "", contactType: "internal", enabled: true };
  assert.equal(core.personPayload(person).department.length, 80);
  assert.throws(() => core.personPayload({ ...person, displayName: "人".repeat(61) }), /UTF-8/);
  assert.throws(() => core.personPayload({ ...person, department: "部".repeat(81) }), /UTF-8/);
  assert.throws(() => core.personPayload({ ...person, department: "first\nsecond" }), /换行/);
  assert.throws(() => payload({ ...fields(), site: "first\x00second" }), /控制字符/);
});

test("person form records manual contacts without implying login, delivery or source synchronization", () => {
  const person = { displayName: " Alice ", department: " Operations ", email: " alice@example.test ", contactType: "external", enabled: true, source: "wecom", password: "not-accepted" };
  assert.deepEqual(core.personPayload(person, { version: 4 }), {
    version: 4, displayName: "Alice", department: "Operations", email: "alice@example.test", contactType: "external", enabled: true,
  });
  assert.equal("version" in core.personPayload(person), false);
  assert.equal(core.personPayload({ ...person, email: "", enabled: false }).email, "");
  assert.throws(() => core.personPayload({ ...person, displayName: " " }), /姓名/);
  assert.throws(() => core.personPayload({ ...person, email: "not-an-email" }), /邮箱/);
  assert.throws(() => core.personPayload({ ...person, contactType: "wecom" }), /联系人/);
});
