import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";
import { summarizeGoTests } from "./go-test-results.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const image = "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873";
const runId = new Date().toISOString().replace(/[:.]/g, "-") + "-" + randomBytes(3).toString("hex");
const name = `infrascope-test-${runId.toLowerCase()}`;
const outputDir = join(root, "docs", "implementation", "evidence", runId);
const report = {
  runId,
  startedAt: new Date().toISOString(),
  evidenceLevel: "L2",
  database: "Native PostgreSQL in an isolated disposable Docker container",
  sshTarget: "In-process Go test SSH/SFTP target; NOT a real OpenSSH/Windows target",
  windowsGUI: "NOT_RUN",
  browserE2E: "NOT_RUN",
  image,
  status: "BLOCKED",
};
let containerStarted = false;

function run(command, args, { cwd = root, env = process.env, timeout = 30000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "", timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeout);
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => { stderr += error.message; });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, signal, timedOut, stdout, stderr });
    });
  });
}

async function check(command, args, options) {
  const result = await run(command, args, options);
  if (result.code !== 0) throw new Error(`${command} failed: ${result.stderr.trim() || result.signal || result.code}`);
  return result.stdout.trim();
}

async function sourceHashes(directory) {
  const hashes = {};
  for (const item of await readdir(directory, { withFileTypes: true })) {
    if ([".git", ".dev-tools", ".local-dev", "node_modules", "evidence", "bin", "test-results", "target", "release", "build", "dist", ".runtime"].includes(item.name)) continue;
    const path = join(directory, item.name);
    if (item.isDirectory()) Object.assign(hashes, await sourceHashes(path));
    else if (item.isFile()) hashes[relative(root, path)] = createHash("sha256").update(await readFile(path)).digest("hex");
  }
  return hashes;
}

await mkdir(outputDir, { recursive: true });
try {
  report.commit = await check("git", ["rev-parse", "HEAD"]);
  report.worktree = await check("git", ["status", "--porcelain"]);
  report.goVersion = await check("go", ["version"]);
  report.kernel = await check("uname", ["-srmo"]);
  report.sourceSha256 = await sourceHashes(root);
  if (await check("go", ["env", "CGO_ENABLED"]) !== "1") {
    throw new Error("Race checks require CGO_ENABLED=1 and a C compiler; no test was run");
  }
  await check(process.env.CC || "cc", ["--version"]);
  await check("docker", ["info", "--format", "{{.ServerVersion}}"]);
  // Never pull a moving tag or touch a user's existing PostgreSQL container.
  await check("docker", ["image", "inspect", image, "--format", "{{.Id}}"]);
  const password = randomBytes(32).toString("hex");
  await check("docker", ["run", "--detach", "--rm", "--name", name,
    "--label", "infrascope.purpose=isolated-test", "--memory", "512m", "--cpus", "2",
    "--shm-size", "128m", "--tmpfs", "/var/lib/postgresql:rw,nosuid,size=384m",
    "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD",
    "--env", "POSTGRES_DB=infrascope_test", image,
  ], { env: { ...process.env, POSTGRES_PASSWORD: password } });
  containerStarted = true;
  let ready = false;
  for (let attempt = 0; attempt < 40; attempt++) {
    // The image's temporary initialization server accepts Unix sockets before TCP is ready.
    const result = await run("docker", ["exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "infrascope_test"]);
    if (result.code === 0) { ready = true; break; }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!ready) throw new Error("Isolated PostgreSQL did not become ready");
  report.postgresVersion = await check("docker", ["exec", name, "psql", "-U", "postgres", "-d", "infrascope_test", "-Atc", "SELECT version()"]);
  const address = await check("docker", ["port", name, "5432/tcp"]);
  if (!/^127\.0\.0\.1:\d+$/.test(address)) throw new Error("Test database was not bound exclusively to loopback");
  const required = [];
  const testDir = join(root, "remote-access", "internal", "access");
  for (const file of await readdir(testDir)) {
    if (!file.endsWith("_test.go")) continue;
    const text = await readFile(join(testDir, file), "utf8");
    required.push(...[...text.matchAll(/^func (Test\w+)\(t \*testing\.T\)/gm)].map((match) => match[1]));
  }
  report.requiredTests = required;
  const args = ["test", "-race", "-count=1", "-json", "-timeout", "240s", "./..."];
  report.command = ["go", ...args];
  const result = await run("go", args, {
    cwd: join(root, "remote-access"), timeout: 270000,
    env: { ...process.env, INFRA_TEST_DATABASE_URL: `postgres://postgres:${password}@${address}/infrascope_test?sslmode=disable` },
  });
  const redact = (value) => value.replaceAll(password, "[REDACTED]");
  await writeFile(join(outputDir, "go-test.jsonl"), redact(result.stdout));
  await writeFile(join(outputDir, "go-test.stderr.txt"), redact(result.stderr));
  report.exitCode = result.code;
  report.tests = summarizeGoTests(result.stdout, required);
  report.status = result.code === 0 && report.tests.ok ? "PASS" : "FAIL";
  process.exitCode = report.status === "PASS" ? 0 : 1;
} catch (error) {
  report.error = error.message;
  process.exitCode = 2;
} finally {
  if (containerStarted) {
    const cleanup = await run("docker", ["rm", "--force", name]);
    report.cleanup = cleanup.code === 0 ? "PASS" : "FAIL";
    if (cleanup.code !== 0) { report.status = "FAIL"; process.exitCode = 1; }
  }
  report.finishedAt = new Date().toISOString();
  await writeFile(join(outputDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ ...report, worktree: undefined, sourceSha256: undefined, evidenceDirectory: outputDir }, null, 2));
}
