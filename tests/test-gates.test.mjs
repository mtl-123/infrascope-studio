import assert from "node:assert/strict";
import test from "node:test";
import { summarizeGoTests } from "../scripts/go-test-results.mjs";

const events = (...items) => items.map((item) => JSON.stringify({ Package: "access", ...item })).join("\n");

test("a successful package with skipped integration tests does not pass the gate", () => {
  const result = summarizeGoTests(events(
    { Test: "TestUnit", Action: "pass" },
    { Test: "TestIntegration", Action: "skip" },
    { Action: "pass" },
  ), ["TestIntegration"]);
  assert.equal(result.ok, false);
  assert.equal(result.skip, 1);
});

test("missing, failed, empty, and malformed test runs fail closed", () => {
  assert.equal(summarizeGoTests(events({ Test: "TestUnit", Action: "pass" }), ["TestIntegration"]).ok, false);
  assert.equal(summarizeGoTests(events({ Test: "TestUnit", Action: "fail" })).ok, false);
  assert.equal(summarizeGoTests(events({ Action: "pass" })).ok, false);
  assert.equal(summarizeGoTests("PASS").ok, false);
  assert.equal(summarizeGoTests(events({ Test: "TestUnit", Action: "pass" }, { Action: "fail" })).ok, false);
});

test("all required tests must execute and pass", () => {
  const result = summarizeGoTests(events(
    { Test: "TestUnit", Action: "run" },
    { Test: "TestUnit", Action: "pass" },
    { Test: "TestIntegration", Action: "pass" },
    { Action: "pass" },
  ), ["TestUnit", "TestIntegration"]);
  assert.equal(result.ok, true);
  assert.equal(result.pass, 2);
});
