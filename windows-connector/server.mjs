import http from "node:http";
import { StringDecoder } from "node:string_decoder";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import {
  generateKeyPairSync,
  sign,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import {
  newToken,
  tokenEqual,
  validateConfig,
  approvedOrigin,
  secureLocalRequest,
  deviceCanonical,
} from "./protocol.mjs";
const here = path.dirname(fileURLToPath(import.meta.url)),
  publicDir = path.join(here, "public"),
  launcher = path.join(here, "launcher");
const port = Number(process.env.PORT || 4173),
  mode = process.env.INFRASCOPE_MODE || "controlled",
  token = newToken();
if (!Number.isInteger(port) || port < 1 || port > 65535)
  throw Error("Invalid PORT");
if (!["controlled", "standalone"].includes(mode))
  throw Error("INFRASCOPE_MODE must be controlled or standalone");
const platform =
  mode === "controlled" && process.env.INFRASCOPE_PLATFORM
    ? approvedOrigin(process.env.INFRASCOPE_PLATFORM)
    : null;
const statePath = path.join(
  process.env.LOCALAPPDATA || here,
  "InfraScope",
  "connector.dpapi.json",
);
let identity = null,
  device = null,
  key = null,
  pending = [],
  pollError = "",
  capabilities = {},
  polling = false,
  lastCapabilityCheck = 0;
const launches = new Map(),
  locks = new Set(),
  children = new Set();
const ps = path.join(
  process.env.SystemRoot || "C:\\Windows",
  "System32",
  "WindowsPowerShell",
  "v1.0",
  "powershell.exe",
);
function json(res, status, data) {
  const raw = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(raw),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(raw);
}
function powershell(
  script,
  args = [],
  input,
  timeout = 30000,
  first = false,
  onCleanup,
) {
  return new Promise((resolve, reject) => {
    if (process.platform !== "win32") {
      reject(Error("Windows PowerShell requires Windows"));
      return;
    }
    const child = spawn(
      ps,
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        path.join(launcher, script),
        ...args,
      ],
      { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
    );
    children.add(child);
    const decoder = new StringDecoder("utf8");
    let output = "",
      line = "",
      settled = false,
      hadError = false;
    let timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill();
        reject(
          Error(
            first ? "mstsc launcher timed out" : "RDP signing setup timed out",
          ),
        );
      }
    }, timeout);
    child.on("error", () => {
      hadError = true;
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(Error("Windows PowerShell could not start"));
      }
    });
    child.stderr.on("data", () => {
      hadError = true;
    });
    child.stdin.on("error", () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(Error("PowerShell stdin failed"));
      }
    });
    child.stdout.on("data", (buffer) => {
      const text = decoder.write(buffer);
      if (!first) {
        output += text;
        if (output.length > 65536) {
          child.kill();
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            reject(Error("PowerShell output exceeded limit"));
          }
        }
        return;
      }
      line += text;
      let idx;
      while ((idx = line.indexOf("\n")) >= 0) {
        const value = line.slice(0, idx).trim();
        line = line.slice(idx + 1);
        if (!value) continue;
        let data;
        try {
          data = JSON.parse(value);
        } catch {
          continue;
        }
        if (data.type === "cleanup") {
          onCleanup?.(data);
          continue;
        }
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(data);
        }
      }
    });
    child.on("close", (code) => {
      children.delete(child);
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (first) {
        reject(Error(`mstsc launcher exited without a result (${code})`));
        return;
      }
      if (code !== 0) {
        try {
          const result = JSON.parse(output);
          reject(Error(result.error || "RDP signing configuration failed"));
        } catch {
          reject(
            Error(
              hadError
                ? "PowerShell operation failed"
                : `PowerShell exited with code ${code}`,
            ),
          );
        }
        return;
      }
      try {
        resolve(JSON.parse(output));
      } catch {
        reject(Error("PowerShell returned invalid output"));
      }
    });
    if (input !== undefined) child.stdin.end(JSON.stringify(input), "utf8");
    else child.stdin.end();
  });
}
async function signedRequest(operation, payload) {
  if (!device || !key || !platform) throw Error("Device is not paired");
  const route = "/api/remote-access/connector/" + operation,
    raw = JSON.stringify(payload),
    time = String(Math.floor(Date.now() / 1000)),
    nonce = newToken(),
    sig = sign(
      null,
      Buffer.from(deviceCanonical("POST", route, time, nonce, raw)),
      key,
    ).toString("base64");
  const response = await fetch(platform + route, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Connector-Id": device.connectorId,
      "X-Connector-Time": time,
      "X-Connector-Nonce": nonce,
      "X-Connector-Signature": sig,
    },
    body: raw,
    signal: AbortSignal.timeout(12000),
    redirect: "error",
  });
  const result = await response.json();
  if (!response.ok) throw Error(result.code || "platform_request_failed");
  return result;
}
async function persistDevice(privatePem) {
  const protectedValue = await powershell(
    "device-secrets.ps1",
    ["-Mode", "Protect"],
    { value: JSON.stringify({ ...device, privatePem, platform }) },
  );
  await fs.mkdir(path.dirname(statePath), { recursive: true });
  await fs.writeFile(
    statePath,
    JSON.stringify({ protected: protectedValue.protected }),
    { mode: 0o600 },
  );
}
async function loadDevice() {
  try {
    const raw = JSON.parse(await fs.readFile(statePath, "utf8"));
    const result = await powershell(
      "device-secrets.ps1",
      ["-Mode", "Unprotect"],
      raw,
    );
    const saved = JSON.parse(result.value);
    if (
      saved.platform !== platform ||
      saved.windowsUserHash !== identity.windowsUserHash
    )
      throw Error(
        "Device belongs to another approved platform or Windows user",
      );
    key = createPrivateKey(saved.privatePem);
    device = {
      connectorId: saved.connectorId,
      browserBindingId: saved.browserBindingId,
      userId: saved.userId,
      workspace: saved.workspace,
      windowsUserHash: saved.windowsUserHash,
      name: saved.name,
    };
    saved.privatePem = "";
    result.value = "";
  } catch (e) {
    if (e.code !== "ENOENT")
      pollError = "配对信息无法解密或平台不匹配，请重新配对。";
  }
}
async function poll() {
  if (polling || !device || !platform) return;
  polling = true;
  try {
    if (Date.now() - lastCapabilityCheck > 30000) {
      capabilities = {
        ...(await powershell("launch-rdp.ps1", ["-SelfTest"])),
        signing: await powershell("setup-rdp-signing.ps1", ["-Mode", "Status"]),
      };
      lastCapabilityCheck = Date.now();
    }
    const result = await signedRequest("poll", {
      capabilities,
      windowsUserHash: identity.windowsUserHash,
    });
    pending = result.launches.filter((x) => !launches.has(x.id));
    pollError = "";
  } catch (e) {
    pollError = e.message;
    pending = [];
  } finally {
    polling = false;
  }
}
async function pair(body) {
  if (mode !== "controlled" || !platform)
    throw Error(
      "Start controlled mode with INFRASCOPE_PLATFORM set to an approved HTTPS origin",
    );
  if (!identity?.interactive)
    throw Error("Interactive Windows desktop required");
  if (
    typeof body.challenge !== "string" ||
    body.challenge.length > 100 ||
    typeof body.name !== "string" ||
    !body.name.trim()
  )
    throw Error("Invalid pairing input");
  const keys = generateKeyPairSync("ed25519");
  const pub = keys.publicKey.export({ type: "spki", format: "pem" }),
    priv = keys.privateKey.export({ type: "pkcs8", format: "pem" });
  const proof = sign(
    null,
    Buffer.from(
      ["pair", body.challenge, platform, identity.windowsUserHash].join("\n"),
    ),
    keys.privateKey,
  ).toString("base64");
  const response = await fetch(platform + "/api/remote-access/connector/pair", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge: body.challenge,
      publicKey: pub,
      name: body.name.trim(),
      windowsUserHash: identity.windowsUserHash,
      version: "1.0.0",
      signature: proof,
      origin: platform,
    }),
    signal: AbortSignal.timeout(12000),
    redirect: "error",
  });
  const result = await response.json();
  if (!response.ok) throw Error(result.error || "Pairing failed");
  device = {
    ...result,
    name: body.name.trim(),
    windowsUserHash: identity.windowsUserHash,
  };
  key = keys.privateKey;
  await persistDevice(priv);
  await poll();
  return { ok: true, connectorId: device.connectorId, name: device.name };
}
async function launch(config, id = null) {
  const c = validateConfig(config),
    target = c.address.toLowerCase();
  if (locks.has(target))
    return {
      ok: false,
      code: "credential_target_busy",
      error: "同一目标的凭据租约正在使用，请等待清理完成",
    };
  locks.add(target);
  let cleanupObserved = false;
  try {
    const result = await powershell(
      "launch-rdp.ps1",
      [],
      c,
      10000,
      true,
      async (result) => {
        cleanupObserved = true;
        locks.delete(target);
        if (id) {
          launches.set(id, { ...launches.get(id), cleanup: result.state });
          await signedRequest("event", {
            launchId: id,
            state: result.state,
            code: result.ok ? "" : "cleanup_failed",
          }).catch(() => {});
        }
      },
    );
    c.password = "";
    if (!result.ok) locks.delete(target);
    if (id) {
      launches.set(id, {
        id,
        state: result.ok
          ? "started"
          : result.code === "signing_setup_required"
            ? "signing_setup_required"
            : "failed",
        pid: result.pid || 0,
      });
      await signedRequest("event", {
        launchId: id,
        state: launches.get(id).state,
        pid: result.pid || 0,
        code: result.code || "",
      }).catch(() => {
        pollError = "启动反馈回传失败；请在本机核实，勿重复点击";
      });
    }
    return result;
  } catch (e) {
    c.password = "";
    if (cleanupObserved) locks.delete(target);
    else {
      setTimeout(() => locks.delete(target), 65000);
      pollError = "启动失败，临时残留需回收检查";
    }
    throw e;
  }
}
async function launchTask(body) {
  if (
    !body ||
    Object.keys(body).some((k) => !["launchId", "confirmed"].includes(k)) ||
    mode !== "controlled" ||
    typeof body.launchId !== "string" ||
    body.confirmed !== true
  )
    throw Error("Local confirmation and a platform task are required");
  if (launches.has(body.launchId)) return launches.get(body.launchId);
  const item = pending.find((x) => x.id === body.launchId);
  if (!item || Date.parse(item.expires_at) <= Date.now())
    throw Error("Task is absent or expired");
  const data = await signedRequest("redeem", {
    launchId: body.launchId,
    locallyConfirmed: true,
  });
  if (
    data.connectorId !== device.connectorId ||
    data.windowsUserHash !== identity.windowsUserHash ||
    Date.parse(data.expiresAt) <= Date.now()
  )
    throw Error("Task binding mismatch");
  const o = data.options;
  if (
    (o.redirectClipboard && !data.permittedActions.includes("rdp.clipboard")) ||
    (o.redirectDrives && !data.permittedActions.includes("rdp.driveRedirect"))
  )
    throw Error("Resource policy denied");
  const config = {
    address: data.address,
    port: data.port,
    username: data.username,
    password: data.password,
    ...o,
  };
  data.password = "";
  launches.set(body.launchId, { id: body.launchId, state: "received" });
  pending = pending.filter((x) => x.id !== body.launchId);
  try {
    return await launch(config, body.launchId);
  } finally {
    config.password = "";
  }
}
async function readJSON(req) {
  if (!String(req.headers["content-type"] || "").startsWith("application/json"))
    throw Object.assign(Error("Content-Type must be application/json"), {
      status: 415,
    });
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16384)
      throw Object.assign(Error("Request is too large"), { status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(Error("Invalid JSON"), { status: 400 });
  }
}
const server = http.createServer(async (req, res) => {
  if (!secureLocalRequest(req, port)) {
    json(res, 403, { error: "Local launcher authorization failed" });
    return;
  }
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  try {
    if (url.pathname === "/api/local-token" && req.method === "GET") {
      json(res, 200, { token, available: process.platform === "win32", mode });
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      if (!tokenEqual(req.headers["x-pulse-token"], token)) {
        json(res, 403, { error: "Local launcher authorization failed" });
        return;
      }
      if (url.pathname === "/api/status" && req.method === "GET") {
        json(res, 200, {
          mode,
          platform,
          device: device ? { id: device.connectorId, name: device.name } : null,
          identity: identity ? { interactive: identity.interactive } : null,
          pending,
          launches: [...launches.values()],
          capabilities,
          error: pollError,
        });
        return;
      }
      if (process.platform !== "win32") {
        json(res, 501, { error: "mstsc launcher requires Windows" });
        return;
      }
      if (url.pathname === "/api/rdp/signing-status" && req.method === "GET") {
        json(
          res,
          200,
          await powershell("setup-rdp-signing.ps1", ["-Mode", "Status"]),
        );
        return;
      }
      if (url.pathname === "/api/rdp/setup-signing" && req.method === "POST") {
        const result = await powershell(
          "setup-rdp-signing.ps1",
          ["-Mode", "Install"],
          undefined,
          30000,
        );
        json(res, result.configured ? 200 : 500, result);
        return;
      }
      if (url.pathname === "/api/pair" && req.method === "POST") {
        json(res, 200, await pair(await readJSON(req)));
        return;
      }
      if (url.pathname === "/api/rdp/connect" && req.method === "POST") {
        const body = await readJSON(req);
        const result =
          mode === "controlled" ? await launchTask(body) : await launch(body);
        json(res, result.ok ? 200 : 409, result);
        return;
      }
      json(res, 404, { error: "Not found" });
      return;
    }
    if (!["GET", "HEAD"].includes(req.method)) {
      json(res, 405, { error: "Method not allowed" });
      return;
    }
    const pathname = decodeURIComponent(url.pathname),
      file = path.resolve(
        publicDir,
        "." + (pathname === "/" ? "/index.html" : pathname),
      ),
      relative = path.relative(publicDir, file);
    if (
      relative.startsWith("..") ||
      path.isAbsolute(relative) ||
      pathname.includes("\0")
    ) {
      json(res, 403, { error: "Forbidden" });
      return;
    }
    let stat;
    try {
      stat = await fs.lstat(file);
    } catch {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }
    const resolved = await fs.realpath(file),
      realRoot = await fs.realpath(publicDir),
      realRelative = path.relative(realRoot, resolved);
    if (
      realRelative.startsWith("..") ||
      path.isAbsolute(realRelative) ||
      !stat.isFile() ||
      stat.isSymbolicLink()
    ) {
      json(res, 404, { error: "Not found" });
      return;
    }
    const data = await fs.readFile(file),
      mime =
        {
          ".html": "text/html",
          ".js": "text/javascript",
          ".css": "text/css",
          ".json": "application/json",
          ".svg": "image/svg+xml",
          ".png": "image/png",
        }[path.extname(file)] || "application/octet-stream";
    res.writeHead(200, {
      "Content-Type":
        mime + (mime.startsWith("text/") ? "; charset=utf-8" : ""),
      "Content-Length": data.length,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Permissions-Policy": "display-capture=(self)",
      "Content-Security-Policy":
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    });
    res.end(req.method === "HEAD" ? undefined : data);
  } catch (e) {
    json(
      res,
      e.status ||
        (/^(Invalid |Password is too long|Username is required|Local confirmation)/.test(
          e.message,
        )
          ? 400
          : 500),
      { error: e.message || "Operation failed" },
    );
  }
});
server.requestTimeout = 15000;
server.headersTimeout = 10000;
if (process.platform === "win32") {
  identity = await powershell("device-secrets.ps1", ["-Mode", "Identity"]);
  if (!identity.interactive)
    throw Error("Connector must run in the interactive Windows user session");
  await powershell("launch-rdp.ps1", ["-Recover"]).catch(() => {
    pollError = "临时凭据残留回收失败，请检查本机状态";
  });
  if (platform) await loadDevice();
}
server.listen(port, "127.0.0.1", () => {
  process.stdout.write(
    `InfraScope Windows connector: http://127.0.0.1:${port}\nMode: ${mode}. Loopback only.\n`,
  );
});
const timer = setInterval(() => poll(), 4000);
timer.unref();
for (const sig of ["SIGINT", "SIGTERM"])
  process.on(sig, () => {
    clearInterval(timer);
    server.close();
    if (children.size)
      process.stdout.write("Waiting for owned launch cleanup processes.\n");
    setTimeout(() => process.exit(0), 35000).unref();
  });
