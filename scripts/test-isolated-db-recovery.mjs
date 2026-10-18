import { spawn, spawnSync } from "node:child_process";
import { createHash, createDecipheriv, randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";
import { createServer } from "node:net";

const root = fileURLToPath(new URL("../", import.meta.url));
const image = "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873";
const local = join(root, ".local-dev");
const previewPath = join(local, "full-qa-preview.json");
const keepPreview = process.argv.includes("--keep-preview");
const runId = new Date().toISOString().replace(/[:.]/g, "-") + "-recovery-" + randomBytes(3).toString("hex");
const directory = join(root, "docs/implementation/evidence/full-qa-20261018/backend", runId);
const binaryDirectory = join(local, runId);
const binary = join(binaryDirectory, "infrascope-recovery-test");
const workspace = "isolated-recovery-" + randomBytes(6).toString("hex");
const report = { runId, startedAt: new Date().toISOString(), status: "BLOCKED", image,
  scope: "Synthetic isolated native PostgreSQL backup/restore and real application HTTP roundtrip; never reads the live development database",
  commands: [], checks: [], limitations: ["No production backup, production load, or disaster recovery SLA", "No external SSH/SFTP target, Windows RDP desktop, enterprise identity provider, notification receiver, or continuous telemetry", "All API fixtures are synthetic; TEST-NET addresses are never dialled", "HTTP loopback test origin, not a new HTTPS or connector-pairing acceptance test"] };
const containers = new Set();
const apps = new Set();
const secretValues = [];
let retainedContainer = "", retainedApp, dump;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = value => createHash("sha256").update(value).digest("hex");
const randomSecret = () => { const v = randomBytes(32).toString("base64url"); secretValues.push(v); return v; };
const redact = value => secretValues.reduce((s, v) => s.replaceAll(v, "[REDACTED]"), value);
function check(condition, label) {
  report.checks.push({ label, status: condition ? "PASS" : "FAIL" });
  if (!condition) throw Error(label);
}
function run(command, args, { env = process.env, input, cwd = root, timeout = 90000, expect = 0, label } = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, { cwd, env, input, timeout, maxBuffer: 64 * 1024 * 1024 });
  report.commands.push({ command: [relative(root, command).startsWith("..") ? command : relative(root, command), ...args],
    label, exitCode: result.status, durationMs: Date.now() - started, stdoutBytes: result.stdout?.length || 0,
    stdoutSha256: sha(result.stdout || ""), stderrSha256: sha(result.stderr || ""), input: input ? "supplied privately via stdin; not recorded" : undefined });
  if (result.error || result.status !== expect) throw Error(`${label || command} failed (${result.error?.code || result.status}): ${redact(result.stderr?.toString() || "")}`);
  return result.stdout;
}
const docker = (args, options) => run("docker", args, options);
const sql = (container, query) => docker(["exec", "-i", container, "psql", "-X", "-U", "postgres", "-d", "infrascope_recovery", "-v", "ON_ERROR_STOP=1", "-At"], { input: query, label: "isolated SQL" }).toString().trim();
async function hashes(path, out = {}) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    if (["bin", ".git", "node_modules"].includes(entry.name)) continue;
    const file = join(path, entry.name);
    if (entry.isDirectory()) await hashes(file, out);
    else out[relative(root, file)] = sha(await readFile(file));
  }
  return out;
}
async function availablePort(preferred = 0) {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(preferred, "127.0.0.1", () => { const port = server.address().port; server.close(() => resolve(port)); });
  });
}
async function startDatabase(suffix) {
  const name = `infrascope-qa-${runId}-${suffix}`.toLowerCase(), password = randomSecret();
  docker(["run", "--detach", "--rm", "--name", name, "--label", "infrascope.purpose=isolated-full-qa", "--label", `infrascope.qa.run=${runId}`,
    "--memory", "512m", "--cpus", "2", "--shm-size", "128m", "--tmpfs", "/var/lib/postgresql:rw,nosuid,size=384m",
    "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=infrascope_recovery", image],
  { env: { ...process.env, POSTGRES_PASSWORD: password }, label: "create own isolated PostgreSQL" });
  containers.add(name);
  let ready = false;
  for (let i = 0; i < 80; i++) {
    const result = spawnSync("docker", ["exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "infrascope_recovery"], { timeout: 5000, stdio: "ignore" });
    if (result.status === 0) { ready = true; break; }
    await delay(250);
  }
  check(ready, `PostgreSQL ${suffix} TCP ready`);
  const address = docker(["port", name, "5432/tcp"]).toString().trim();
  check(/^127\.0\.0\.1:\d+$/.test(address), `PostgreSQL ${suffix} loopback only`);
  return { name, password, address };
}
function environment(db, port, key, rotatedKey, originHost = "127.0.0.1") {
  return { ...process.env, DATABASE_URL: `postgres://postgres:${db.password}@${db.address}/infrascope_recovery?sslmode=disable`,
    REMOTE_ENABLED: "true", REMOTE_LOOPBACK_TEST: "true", REMOTE_LISTEN: `127.0.0.1:${port}`, REMOTE_PUBLIC_ORIGIN: `http://${originHost}:${port}`,
    REMOTE_TLS_CERT: "", REMOTE_TLS_KEY: "", REMOTE_HTTP_REDIRECT_LISTEN: "", REMOTE_STATIC_DIR: join(root, "dist"),
    REMOTE_WORKSPACE: workspace, REMOTE_GATEWAY_ID: workspace, REMOTE_ALLOWED_CIDRS: "", REMOTE_GATEWAY_PEERS: "{}",
    REMOTE_SECRET_KEYS: JSON.stringify({ "recovery-key": key, ...(rotatedKey ? { "rotated-key": rotatedKey } : {}) }),
    REMOTE_ACTIVE_KEY_VERSION: rotatedKey ? "rotated-key" : "recovery-key" };
}
async function startApp(env, suffix) {
  const logPath = join(binaryDirectory, `${suffix}.log`);
  const log = await open(logPath, "wx", 0o600);
  const child = spawn(binary, ["serve"], { cwd: root, env, detached: true, stdio: ["ignore", log.fd, log.fd] });
  await log.close();
  apps.add(child);
  let ready = false;
  for (let i = 0; i < 80; i++) {
    if (child.exitCode !== null) break;
    try {
      const response = await fetch(env.REMOTE_PUBLIC_ORIGIN + "/api/remote-access/auth/me", { signal: AbortSignal.timeout(1500) });
      if (response.status === 401) { ready = true; break; }
    } catch {}
    await delay(100);
  }
  check(ready, `Application ${suffix} starts and unauthenticated API is 401`);
  return child;
}
async function stopApp(child) {
  if (!child || !apps.has(child)) return;
  child.kill("SIGTERM");
  for (let i = 0; i < 100 && child.exitCode === null; i++) await delay(100);
  if (child.exitCode === null) child.kill("SIGKILL");
  check(child.exitCode === 0, "Isolated application clean shutdown");
  apps.delete(child);
}
function apiClient(origin) {
  let cookie = "", csrf = "";
  return async function request(method, path, body, expected = 200, options = {}) {
    const response = await fetch(origin + path, { method, headers: { Origin: origin, "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}),
      ...(csrf ? { "X-CSRF-Token": csrf } : {}), ...options.headers }, body: options.rawBody ?? (body === undefined ? undefined : JSON.stringify(body)), signal: AbortSignal.timeout(10000) });
    const text = await response.text();
    check(response.status === expected, `${method} ${path} HTTP ${expected} (actual ${response.status})`);
    if (options.text) return text;
    const data = JSON.parse(text);
    check(!secretValues.some(value => text.includes(value)), `${method} ${path} has no supplied credential material`);
    const nextCookie = response.headers.get("set-cookie");
    if (nextCookie) cookie = nextCookie.split(";")[0];
    if (data.csrf) csrf = data.csrf;
    return data;
  };
}
function databaseSnapshot(container) {
  const tables = sql(container, "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").split("\n").filter(Boolean);
  const rows = {};
  for (const table of tables) {
    if (!/^ra_[a-z_]+$/.test(table)) throw Error("Unexpected table identifier");
    const raw = sql(container, `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM "${table}" t`);
    rows[table] = { count: JSON.parse(raw).length, sha256: sha(raw) };
  }
  const structure = {};
  for (const [name, query] of Object.entries({
    columns: "SELECT table_name,column_name,ordinal_position,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position",
    indexes: "SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY tablename,indexname",
    constraints: "SELECT c.relname,k.conname,k.contype,k.convalidated,pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,k.conname",
  })) {
    const raw = sql(container, `SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb)::text FROM (${query}) x`);
    structure[name] = { count: JSON.parse(raw).length, sha256: sha(raw) };
  }
  const sequences = {};
  for (const name of sql(container, "SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename").split("\n").filter(Boolean)) {
    if (!/^ra_[a-z_]+$/.test(name)) throw Error("Unexpected sequence identifier");
    sequences[name] = sha(sql(container, `SELECT last_value,is_called FROM "${name}"`));
  }
  return { tables: rows, structure, sequences, schemaVersions: sql(container, "SELECT string_agg(version::text,',' ORDER BY version) FROM ra_schema_versions") };
}
function decryptedSecrets(container, key) {
  const rows = JSON.parse(sql(container, "SELECT COALESCE(jsonb_agg(jsonb_build_object('workspace',workspace,'account',account_id,'version',version,'keyVersion',key_version,'nonce',encode(nonce,'hex'),'ciphertext',encode(ciphertext,'hex'))),'[]')::text FROM ra_secrets"));
  return rows.map(row => {
    const ct = Buffer.from(row.ciphertext, "hex"), iv = Buffer.from(row.nonce, "hex");
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(Buffer.from(`${row.workspace}:${row.account}:${row.version}`));
    decipher.setAuthTag(ct.subarray(ct.length - 16));
    const plaintext = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]);
    const parsed = JSON.parse(plaintext.toString());
    plaintext.fill(0);
    return { account: row.account, keyVersion: row.keyVersion, value: parsed };
  });
}
async function cleanupPreview() {
  const config = JSON.parse(await readFile(previewPath, "utf8"));
  if (!/^infrascope-qa-[a-z0-9-]+-restore$/.test(config.container) || !config.binary.startsWith(local + "/") || !config.runId.includes("-recovery-")) throw Error("Invalid isolated preview ownership metadata");
  const owner = docker(["inspect", "--format", '{{index .Config.Labels "infrascope.qa.run"}}', config.container]).toString().trim();
  if (owner !== config.runId) throw Error("Refusing unrelated container cleanup");
  let command;
  try { command = await readFile(`/proc/${config.pid}/cmdline`, "utf8"); } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (command) {
    if (command.split("\0")[0] !== config.binary) throw Error("Refusing unrelated process cleanup");
    process.kill(config.pid, "SIGTERM");
    await delay(1500);
  }
  docker(["rm", "--force", config.container]);
  await rm(previewPath);
  console.log("Isolated preview app and owned disposable database stopped; live service was not touched.");
}

if (process.argv.includes("--cleanup-preview")) {
  await cleanupPreview();
} else {
  await mkdir(directory, { recursive: true });
  await mkdir(binaryDirectory, { recursive: true, mode: 0o700 });
  try {
    if (keepPreview) {
      try { await readFile(previewPath); throw Error("Existing isolated preview must be cleaned up first"); } catch (error) { if (error.code !== "ENOENT") throw error; }
    }
    report.commit = run("git", ["rev-parse", "HEAD"]).toString().trim();
    report.sourceSha256 = await hashes(join(root, "remote-access"));
    report.sourceSha256["scripts/test-isolated-db-recovery.mjs"] = sha(await readFile(fileURLToPath(import.meta.url)));
    run("go", ["build", "-o", binary, "./cmd/infrascope"], { cwd: join(root, "remote-access"), timeout: 120000, label: "build isolated application" });
    report.binarySha256 = sha(await readFile(binary));
    docker(["image", "inspect", image, "--format", "{{.Id}}"]);
    const source = await startDatabase("source"), target = await startDatabase("restore");
    const sourcePort = await availablePort(), targetPort = await availablePort(keepPreview ? 18090 : 0);
    const key = randomBytes(32), key64 = key.toString("base64"), rotatedKey = randomBytes(32);
    secretValues.push(key64, rotatedKey.toString("base64"));
    // Cookies are scoped by hostname, not port; isolate browser preview from live 127.0.0.1.
    const previewHost = keepPreview ? "localhost" : "127.0.0.1";
    const env = environment(source, sourcePort, key64), restoreEnv = environment(target, targetPort, key64, undefined, previewHost);
    const admin = { username: "qa-admin-" + randomBytes(5).toString("hex"), displayName: "Isolated full QA administrator", password: randomSecret() };
    run(binary, ["migrate"], { env, label: "fresh migrations 001-008" });
    check(sql(source.name, "SELECT string_agg(version::text,',' ORDER BY version) FROM ra_schema_versions") === "1,2,3,4,5,6,7,8", "Fresh database contains exactly schema versions 001-008");
    run(binary, ["bootstrap"], { env, input: JSON.stringify(admin), label: "private stdin bootstrap" });
    run(binary, ["bootstrap"], { env, input: JSON.stringify(admin), expect: 1, label: "duplicate bootstrap rejected" });
    const sourceApp = await startApp(env, "source");
    const request = apiClient(env.REMOTE_PUBLIC_ORIGIN), prefix = "/api/remote-access";
    await request("POST", prefix + "/auth/login", adminBody(admin), 403, { headers: { Origin: "https://untrusted.example.invalid" } });
    await request("POST", prefix + "/auth/login", { username: admin.username, password: randomSecret() }, 401);
    const login = await request("POST", prefix + "/auth/login", adminBody(admin));
    await request("POST", prefix + "/people", {}, 415, { headers: { "Content-Type": "text/plain" } });
    await request("POST", prefix + "/people", {}, 400, { rawBody: '{"displayName":"x"}{}' });
    await request("POST", prefix + "/people", { displayName: "x", unrecognizedField: true }, 400);
    await request("POST", prefix + "/people", {}, 413, { rawBody: JSON.stringify({ displayName: "x".repeat(1048577) }) });
    await request("POST", prefix + "/people", { displayName: "CSRF forbidden", contactType: "internal", enabled: true }, 403, { headers: { "X-CSRF-Token": "" } });
    const person = await request("POST", prefix + "/people", { displayName: "QA Recovery owner", department: "Recovery QA", email: "qa@example.invalid", contactType: "internal", enabled: true });
    const org = await request("POST", prefix + "/organizations", { name: "QA Recovery organization", description: "Synthetic", parentId: "", enabled: true, memberIds: [login.id] });
    const group = await request("POST", prefix + "/groups", { name: "QA Recovery group", members: [login.id] });
    const readerPassword = randomSecret(), changedReaderPassword = randomSecret();
    const readerName = "qa-reader-" + randomBytes(4).toString("hex");
    const reader = await request("POST", prefix + "/users", { username: readerName, displayName: "Synthetic recovery reader", role: "operator", initialPassword: readerPassword });
    const readerRequest = apiClient(env.REMOTE_PUBLIC_ORIGIN);
    const readerLogin = await readerRequest("POST", prefix + "/auth/login", { username: readerName, password: readerPassword });
    check(readerLogin.mustChangePassword === true, "New user must change initial password");
    await readerRequest("GET", "/api/v1/assets", undefined, 403);
    await readerRequest("POST", prefix + "/auth/password", { currentPassword: readerPassword, newPassword: changedReaderPassword });
    await readerRequest("GET", prefix + "/auth/me", undefined, 401);
    await readerRequest("POST", prefix + "/auth/login", { username: readerName, password: changedReaderPassword });
    await readerRequest("POST", prefix + "/users", {}, 403);
    await readerRequest("POST", prefix + "/people", {}, 403);
    await readerRequest("POST", "/api/v1/servers/onboard", {}, 403);
    const expiry = new Date(Date.now() + 3600000).toISOString();
    const remotePassword = randomSecret();
    const onboarding = { idempotencyKey: randomBytes(24).toString("base64url"), confirm: true, name: "QA Synthetic Linux (never dial)", osFamily: "linux", host: "192.0.2.19", sshPort: 2222, sftpPort: 2222,
      protocols: ["ssh", "sftp"], username: "qa-synthetic", authType: "password", secret: { password: remotePassword }, claimantId: person.id,
      organizationId: org.id, readRoots: ["/qa"], writeRoots: ["/qa"], allowFileWrite: true, expiresAt: expiry };
    const server = await request("POST", "/api/v1/servers/onboard", onboarding);
    const replay = await request("POST", "/api/v1/servers/onboard", onboarding);
    check(replay.created === false && replay.assetId === server.assetId, "Onboarding idempotent replay preserves identity");
    await request("POST", prefix + "/accounts/" + server.accountId + "/grant-self", { idempotencyKey: randomBytes(24).toString("base64url"), confirm: true, protocols: ["ssh"], expiresAt: expiry });
    await request("POST", prefix + "/asset-groups", { name: "QA recovery asset scope", description: "Synthetic", enabled: true, startsAt: new Date(Date.now() - 60000).toISOString(), expiresAt: expiry, assetIds: [server.assetId], userIds: [login.id], groupIds: [group.id] });
    const imported = await request("POST", "/api/v1/asset-imports/preview", { claimantId: person.id, csv: "inventoryId,name,category,kind,osFamily\nqa-recovery-01,QA imported inventory,server,virtual,linux\nqa-recovery-02,QA cancelled inventory,nas,physical,other\n" });
    const confirmed = await request("POST", `/api/v1/asset-imports/${imported.id}/confirm`, { confirm: true, rowNumbers: [1] });
    check(confirmed.rows[0].state === "created" && confirmed.rows[1].state === "ready", "CSV confirmation creates only selected row");
    await request("POST", `/api/v1/asset-imports/${imported.id}/cancel`, { confirm: true });
    const originalAsset = await request("GET", "/api/v1/assets/" + server.assetId);
    const originalAccount = await request("GET", prefix + "/accounts/" + server.accountId);
    const originalPeople = await request("GET", prefix + "/people");
    const originalAccess = await request("GET", prefix + "/my/access");
    const originalCSV = await request("GET", "/api/v1/assets/export", undefined, 200, { text: true });
    check((await readerRequest("GET", "/api/v1/assets")).length === 0, "Unassigned reader cannot see synthetic assets");
    await readerRequest("GET", "/api/v1/assets/" + server.assetId, undefined, 404);
    await request("PATCH", prefix + "/organizations/" + org.id, { name: "QA Recovery organization", description: "Synthetic", parentId: "", enabled: true, memberIds: [login.id, reader.id], version: 1 });
    const visible = await readerRequest("GET", "/api/v1/assets");
    check(visible.length === 1 && visible[0].id === server.assetId && visible[0].canManage === false, "Organization member sees only direct scoped asset metadata without management");
    await readerRequest("PATCH", "/api/v1/assets/" + server.assetId, {}, 403);
    await readerRequest("GET", prefix + "/accounts/" + server.accountId, undefined, 404);
    check((await readerRequest("GET", prefix + "/my/access")).length === 0, "Organization visibility never creates remote account grants");
    await request("PATCH", prefix + "/organizations/" + org.id, { name: "QA Recovery organization", description: "Synthetic", parentId: "", enabled: true, memberIds: [login.id], version: 2 });
    check((await readerRequest("GET", "/api/v1/assets")).length === 0, "Organization removal revokes scoped access in the same reader session");
    const finalOrgs = await request("GET", prefix + "/organizations");
    const originalAudit = await request("GET", prefix + "/audit-events");
    check(!JSON.stringify(originalAudit).includes(remotePassword), "Audit never exposes synthetic remote password");
    await stopApp(sourceApp);
    const before = databaseSnapshot(source.name);
    run(binary, ["migrate"], { env, label: "reapply all seven migrations on populated database" });
    check(JSON.stringify(before) === JSON.stringify(databaseSnapshot(source.name)), "Repeated migrations preserve every table row, index, constraint and sequence");
    dump = docker(["exec", source.name, "pg_dump", "-U", "postgres", "-d", "infrascope_recovery", "-Fc", "--no-owner", "--no-acl"], { label: "actual custom-format pg_dump" });
    report.dump = { bytes: dump.length, sha256: sha(dump) };
    check(JSON.stringify(before) === JSON.stringify(databaseSnapshot(source.name)), "Source remains unchanged throughout dump");
    docker(["exec", "-i", target.name, "pg_restore", "-U", "postgres", "-d", "infrascope_recovery", "--exit-on-error", "--no-owner", "--no-acl"], { input: dump, label: "actual pg_restore into separate empty PostgreSQL" });
    const restored = databaseSnapshot(target.name);
    report.snapshot = restored;
    check(JSON.stringify(before) === JSON.stringify(restored), "Restore matches ALL table hashes/counts, column definitions, indexes, FK/check constraints, sequences and seven schema versions");
    const secrets = decryptedSecrets(target.name, key);
    check(secrets.length === 1 && secrets[0].account === server.accountId && secrets[0].value.password === remotePassword, "Restored AES-GCM credential authenticates and equals original in memory");
    const unavailableKeyEnv = environment(target, targetPort, key64, rotatedKey.toString("base64"), previewHost);
    unavailableKeyEnv.REMOTE_SECRET_KEYS = JSON.stringify({ "rotated-key": rotatedKey.toString("base64") });
    run(binary, ["rotate-keys"], { env: unavailableKeyEnv, expect: 1, label: "restored secret cannot rotate without its original encryption key" });
    check(JSON.stringify(restored) === JSON.stringify(databaseSnapshot(target.name)), "Missing original key fails closed without modifying any restored row");
    const restoreApp = await startApp(restoreEnv, "restored");
    const restoredRequest = apiClient(restoreEnv.REMOTE_PUBLIC_ORIGIN);
    const restoredLogin = await restoredRequest("POST", prefix + "/auth/login", adminBody(admin));
    check(restoredLogin.id === login.id, "Fresh login after restore resolves same persisted user");
    for (const [path, expected] of [["/api/v1/assets/" + server.assetId, originalAsset], [prefix + "/accounts/" + server.accountId, originalAccount], [prefix + "/people", originalPeople], [prefix + "/organizations", finalOrgs], [prefix + "/my/access", originalAccess]]) {
      check(JSON.stringify(await restoredRequest("GET", path)) === JSON.stringify(expected), `Restored API payload exact match: ${path}`);
    }
    check(await restoredRequest("GET", "/api/v1/assets/export", undefined, 200, { text: true }) === originalCSV, "Restored scoped CSV exact match");
    const restoredReplay = await restoredRequest("POST", "/api/v1/servers/onboard", onboarding);
    check(restoredReplay.created === false && restoredReplay.assetId === server.assetId, "Restored onboarding retry remains idempotent");
    await stopApp(restoreApp);
    const rotatedEnv = environment(target, targetPort, key64, rotatedKey.toString("base64"), previewHost);
    run(binary, ["rotate-keys"], { env: rotatedEnv, label: "real application decrypt/re-encrypt restored secret" });
    const rotated = decryptedSecrets(target.name, rotatedKey);
    check(rotated.length === 1 && rotated[0].value.password === remotePassword && rotated[0].keyVersion === "rotated-key", "Application key rotation decrypts restored secret and re-encrypts without losing plaintext");
    const finalApp = await startApp(rotatedEnv, "rotated-restored");
    const finalRequest = apiClient(rotatedEnv.REMOTE_PUBLIC_ORIGIN);
    await finalRequest("POST", prefix + "/auth/login", adminBody(admin));
    await finalRequest("GET", "/api/v1/assets/" + server.assetId);
    await finalRequest("POST", prefix + "/auth/logout", {});
    await finalRequest("GET", prefix + "/auth/me", undefined, 401);
    if (keepPreview) {
      await writeFile(previewPath, JSON.stringify({ runId, origin: rotatedEnv.REMOTE_PUBLIC_ORIGIN, username: admin.username, password: admin.password, workspace, pid: finalApp.pid, binary, container: target.name, evidenceDirectory: directory }, null, 2) + "\n", { mode: 0o600, flag: "wx" });
      await chmod(previewPath, 0o600);
      retainedContainer = target.name;
      retainedApp = finalApp;
      finalApp.unref();
      report.preview = { origin: rotatedEnv.REMOTE_PUBLIC_ORIGIN, credentialsFile: ".local-dev/full-qa-preview.json (0600, never included in evidence)", cleanup: "node scripts/test-isolated-db-recovery.mjs --cleanup-preview" };
    } else await stopApp(finalApp);
    report.status = "PASS";
  } catch (error) {
    report.status = "FAIL";
    report.error = redact(error.stack || error.message);
    process.exitCode = 1;
  } finally {
    if (dump) dump.fill(0);
    for (const child of apps) if (child !== retainedApp) {
      try { await stopApp(child); } catch (error) { report.cleanupError = error.message; report.status = "FAIL"; process.exitCode = 1; }
    }
    for (const name of containers) if (name !== retainedContainer) {
      try { docker(["rm", "--force", name], { label: "remove own disposable database" }); } catch (error) { report.cleanupError = error.message; report.status = "FAIL"; process.exitCode = 1; }
    }
    report.finishedAt = new Date().toISOString();
    await writeFile(join(directory, "report.json"), redact(JSON.stringify(report, null, 2)) + "\n");
    console.log(JSON.stringify({ status: report.status, checks: report.checks.length, error: report.error, evidenceDirectory: directory, preview: report.preview }, null, 2));
  }
}
function adminBody(admin) { return { username: admin.username, password: admin.password }; }
