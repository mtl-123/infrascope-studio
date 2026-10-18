import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const image = "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873";
const runId = new Date().toISOString().replace(/[:.]/g, "-") + "-recovery-" + randomBytes(3).toString("hex");
const target = "infrascope-" + runId.toLowerCase();
const directory = join(root, "docs/implementation/evidence", runId);
const report = { runId, startedAt: new Date().toISOString(), status: "BLOCKED", scope: "Local development database dump/restore only; no production recovery or secret/key rotation claim", image };
let created = false;

function run(args, options = {}) {
  const result = spawnSync("docker", args, { timeout: 90000, maxBuffer: 32 * 1024 * 1024, ...options });
  if (result.error || result.status !== 0) throw Error(`Docker ${args[0]} failed (${result.error?.code || result.status}); no secret-bearing output recorded`);
  return result.stdout;
}
function sql(container, query) {
  return run(["exec", container, "psql", "-U", "postgres", "-d", "infrascope_dev", "-v", "ON_ERROR_STOP=1", "-Atc", query]).toString("utf8").trim();
}
function snapshot(container, tables) {
  const result = {};
  for (const name of tables) {
    if (!/^ra_[a-z_]+$/.test(name)) throw Error("Unexpected table identifier");
    const json = sql(container, `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM "${name}" t`);
    result[name] = { count: JSON.parse(json).length, sha256: createHash("sha256").update(json).digest("hex") };
  }
  return result;
}
await mkdir(directory, { recursive: true });
try {
  const config = JSON.parse(await readFile(join(root, ".local-dev/config.json"), "utf8"));
  const owner = run(["inspect", "--format", '{{index .Config.Labels "infrascope.dev.root"}}', config.container]).toString("utf8").trim();
  if (owner !== root) throw Error("Source database is not owned by this development checkout");
  const tables = sql(config.container, "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'ra_%' ORDER BY tablename").split("\n").filter(Boolean);
  if (!tables.includes("ra_asset_groups")) throw Error("P2 migrations must be applied before recovery validation");
  const before = snapshot(config.container, tables);
  const dump = run(["exec", config.container, "pg_dump", "-U", "postgres", "-d", "infrascope_dev", "-Fc", "--no-owner", "--no-acl"]);
  const after = snapshot(config.container, tables);
  if (JSON.stringify(before) !== JSON.stringify(after)) throw Error("Source changed during backup; retry with local edits paused");
  report.dumpBytes = dump.length;
  report.dumpSha256 = createHash("sha256").update(dump).digest("hex");
  const password = randomBytes(32).toString("hex");
  run(["run", "--detach", "--rm", "--name", target, "--label", "infrascope.purpose=isolated-recovery",
    "--network", "none", "--memory", "512m", "--cpus", "2", "--tmpfs", "/var/lib/postgresql:rw,nosuid,size=384m",
    "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=infrascope_dev", image,
  ], { env: { ...process.env, POSTGRES_PASSWORD: password } });
  created = true;
  let ready = false;
  for (let i = 0; i < 60; i++) {
    const result = spawnSync("docker", ["exec", target, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], { stdio: "ignore", timeout: 5000 });
    if (result.status === 0) { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  if (!ready) throw Error("Restore target did not become ready");
  run(["exec", "-i", target, "pg_restore", "-U", "postgres", "-d", "infrascope_dev", "--exit-on-error", "--no-owner", "--no-acl"], { input: dump });
  dump.fill(0);
  const restoredTables = sql(target, "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'ra_%' ORDER BY tablename").split("\n").filter(Boolean);
  if (JSON.stringify(tables) !== JSON.stringify(restoredTables)) throw Error("Restored table set differs from source");
  const restored = snapshot(target, tables);
  report.tables = restored;
  if (JSON.stringify(before) !== JSON.stringify(restored)) throw Error("Restored row counts or canonical content hashes differ");
  report.schemaVersions = sql(target, "SELECT string_agg(version::text,',' ORDER BY version) FROM ra_schema_versions");
  report.status = "PASS";
  report.limitations = ["No production dataset or load", "No external-device connectivity or Windows GUI", "Development DB has no remote credentials; encrypted-secret recovery is separately covered by migration integration tests", "Application startup after restore not part of this database-level check"];
} catch (error) {
  report.error = error.message;
  process.exitCode = 1;
} finally {
  if (created) {
    const removed = spawnSync("docker", ["rm", "--force", target], { stdio: "ignore", timeout: 30000 });
    report.cleanup = removed.status === 0 ? "PASS" : "FAIL";
    if (removed.status !== 0) { report.status = "FAIL"; process.exitCode = 1; }
  }
  report.finishedAt = new Date().toISOString();
  await writeFile(join(directory, "report.json"), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ ...report, tables: undefined, evidenceDirectory: directory }, null, 2));
}
