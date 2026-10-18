import { prepareOnboarding } from "./prepare-onboarding.mjs";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const local = join(root, ".local-dev");
const mode = process.argv[2];
const image = "postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8", ...options });
  if (result.error || result.status !== 0) throw new Error(`${command} failed: ${result.error?.message || result.stderr || result.status}`);
  return result.stdout.trim();
}

async function savePrivate(path, value) {
  await writeFile(path, JSON.stringify(value, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  await chmod(path, 0o600);
}

async function load() {
  return JSON.parse(await readFile(join(local, "config.json"), "utf8"));
}

function assertOwned(config) {
  const owner = run("docker", ["inspect", "--format", '{{index .Config.Labels "infrascope.dev.root"}}', config.container]);
  if (owner !== root) throw new Error("Refusing to operate on a database container owned by another checkout");
}

function environment(config) {
  const address = run("docker", ["port", config.container, "5432/tcp"]);
  if (!/^127\.0\.0\.1:\d+$/.test(address)) throw new Error("Development database must listen only on loopback");
  const tlsCert = join(local, "tls", "server.crt"), tlsKey = join(local, "tls", "server.key");
  const certExists = existsSync(tlsCert), keyExists = existsSync(tlsKey);
  if (certExists !== keyExists) throw new Error("Local TLS certificate and key must both exist; refusing HTTP fallback");
  return {
    ...process.env,
    REMOTE_ENABLED: "true", REMOTE_LOOPBACK_TEST: certExists ? "false" : "true",
    REMOTE_LISTEN: certExists ? "127.0.0.1:18443" : "127.0.0.1:18080",
    REMOTE_PUBLIC_ORIGIN: certExists ? "https://127.0.0.1:18443" : "http://127.0.0.1:18080",
    REMOTE_TLS_CERT: certExists ? tlsCert : "", REMOTE_TLS_KEY: keyExists ? tlsKey : "",
    REMOTE_HTTP_REDIRECT_LISTEN: certExists ? "127.0.0.1:18080" : "",
    REMOTE_STATIC_DIR: join(root, "dist"), REMOTE_WORKSPACE: "wsl-development",
    REMOTE_GATEWAY_ID: "wsl-development", REMOTE_ALLOWED_CIDRS: process.env.REMOTE_ALLOWED_CIDRS || "",
    REMOTE_SECRET_KEYS: JSON.stringify({ "dev-key-1": config.key }), REMOTE_ACTIVE_KEY_VERSION: "dev-key-1",
    DATABASE_URL: `postgres://postgres:${config.databasePassword}@${address}/infrascope_dev?sslmode=disable`,
  };
}

try {
  if (!['init', 'serve', 'stop-db'].includes(mode)) throw new Error("Usage: node scripts/dev-wsl.mjs init|serve|stop-db");
  if (mode === "init") {
    await mkdir(local, { recursive: true, mode: 0o700 });
    await chmod(local, 0o700);
    let config;
    try { config = await load(); } catch (error) { if (error.code !== "ENOENT") throw error; }
    if (!config) {
      config = {
        container: `infrascope-dev-${randomBytes(5).toString("hex")}`,
        databasePassword: randomBytes(32).toString("hex"), key: randomBytes(32).toString("base64"),
      };
      await savePrivate(join(local, "config.json"), config);
      await savePrivate(join(local, "admin.json"), {
        username: "local-admin", displayName: "WSL Development Administrator", password: randomBytes(24).toString("base64url"),
      });
    }
    const existing = spawnSync("docker", ["inspect", config.container], { stdio: "ignore" });
    if (existing.status !== 0) {
      await mkdir(join(local, "postgres"), { recursive: true });
      run("docker", ["run", "--detach", "--name", config.container,
        "--label", `infrascope.dev.root=${root}`, "--memory", "512m", "--cpus", "2",
        "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=infrascope_dev",
        "--mount", `type=bind,source=${join(local, "postgres")},target=/var/lib/postgresql`, image,
      ], { env: { ...process.env, POSTGRES_PASSWORD: config.databasePassword } });
    } else { assertOwned(config); run("docker", ["start", config.container]); }
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      if (spawnSync("docker", ["exec", config.container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "infrascope_dev"], { stdio: "ignore" }).status === 0) { ready = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    if (!ready) throw new Error("Development PostgreSQL is not ready");
    const env = environment(config), binary = join(root, "remote-access", "bin", "infrascope");
    run("go", ["build", "-o", binary, "./cmd/infrascope"], { cwd: join(root, "remote-access") });
    console.log(run(binary, ["migrate"], { env }));
    const count = run("docker", ["exec", config.container, "psql", "-U", "postgres", "-d", "infrascope_dev", "-Atc", "SELECT count(*) FROM ra_users"]);
    if (count === "0") console.log(run(binary, ["bootstrap"], { env, input: await readFile(join(local, "admin.json"), "utf8") }));
    await prepareOnboarding();
    console.log("WSL development database initialized. No target assets were created.");
    console.log("Random local-only admin credentials: .local-dev/admin.json (mode 0600; never commit).");
  } else {
    const config = await load();
    assertOwned(config);
    if (mode === "stop-db") {
      run("docker", ["stop", config.container]);
      console.log("Development database stopped; persistent data retained.");
    } else {
      const env = environment(config);
      const child = spawn(join(root, "remote-access", "bin", "infrascope"), ["serve"], { cwd: root, env, stdio: "inherit" });
      for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
      child.on("error", (error) => { console.error(error.message); process.exitCode = 1; });
      child.on("exit", (code) => { process.exitCode = code ?? 1; });
      console.log(`${env.REMOTE_TLS_CERT ? "Local HTTPS" : "Local HTTP (no connector pairing)"}: ${env.REMOTE_PUBLIC_ORIGIN}/#remote-access`);
      console.log("Local development only. Monitoring pages remain explicitly labelled demonstrations.");
    }
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
