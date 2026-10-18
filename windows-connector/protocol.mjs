import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
export const newToken = () => randomBytes(32).toString("hex");
export const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");
export const tokenEqual = (a, b) =>
  typeof a === "string" &&
  typeof b === "string" &&
  Buffer.byteLength(a) === Buffer.byteLength(b) &&
  timingSafeEqual(Buffer.from(a), Buffer.from(b));
export function isLoopback(ip) {
  return ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(ip);
}
export function normalizeDrives(value) {
  const parts = String(value)
    .split(/[,;]/)
    .map((v) => v.trim())
    .filter(Boolean);
  if (!parts.length) throw Error("Invalid drive list");
  if (parts.some((v) => !/^[A-Za-z]:\\?$/.test(v)))
    throw Error("Invalid drive list");
  return [...new Set(parts.map((v) => v[0].toUpperCase() + ":\\"))].join(";");
}
export function validateConfig(body) {
  if (!body || typeof body !== "object" || Array.isArray(body))
    throw Error("Invalid JSON");
  const keys = [
    "address",
    "port",
    "username",
    "password",
    "redirectClipboard",
    "redirectDrives",
    "driveMode",
    "driveList",
    "fullscreen",
    "multiMonitor",
  ];
  if (
    Object.keys(body).some((k) => !keys.includes(k)) ||
    keys.some((k) => !Object.hasOwn(body, k))
  )
    throw Error("Invalid request fields");
  if (typeof body.address !== "string") throw Error("Invalid target address");
  const address = body.address.trim();
  if (
    !address ||
    address.length > 255 ||
    /[\s\x00/\\@?#]/.test(address) ||
    (!isIP(address) &&
      !/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(address))
  )
    throw Error("Invalid target address");
  if (
    typeof body.port !== "number" ||
    !Number.isInteger(body.port) ||
    body.port < 1 ||
    body.port > 65535
  )
    throw Error("Invalid RDP port");
  if (
    typeof body.username !== "string" ||
    body.username.length > 512 ||
    /[\r\n\x00]/.test(body.username)
  )
    throw Error("Invalid username");
  if (
    typeof body.password !== "string" ||
    body.password.length > 2048 ||
    Buffer.byteLength(body.password, "utf16le") > 2560
  )
    throw Error("Password is too long");
  const username = body.username.trim();
  if (body.password && !username)
    throw Error("Username is required when a password is provided");
  for (const key of [
    "redirectClipboard",
    "redirectDrives",
    "fullscreen",
    "multiMonitor",
  ])
    if (typeof body[key] !== "boolean") throw Error("Invalid boolean option");
  if (
    !["all", "custom"].includes(body.driveMode) ||
    typeof body.driveList !== "string" ||
    body.driveList.length > 256
  )
    throw Error("Invalid drive list");
  if (body.redirectDrives && body.driveMode === "custom")
    normalizeDrives(body.driveList);
  return { ...body, address, username };
}
export function approvedOrigin(value) {
  const u = new URL(value);
  if (
    u.protocol !== "https:" ||
    u.username ||
    u.password ||
    u.pathname !== "/" ||
    u.search ||
    u.hash
  )
    throw Error("Platform must be an exact HTTPS origin");
  return u.origin;
}
export function secureLocalRequest(req, port) {
  const hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
  if (
    !isLoopback(req.socket.remoteAddress) ||
    !hosts.includes(req.headers.host)
  )
    return false;
  const origin = req.headers.origin;
  if (origin && !hosts.some((h) => origin === `http://${h}`)) return false;
  const site = req.headers["sec-fetch-site"];
  if (site && !["same-origin", "none"].includes(site)) {
    // Opening the public shell from the platform must not relax any API guard.
    const shellNavigation =
      !origin &&
      ["same-site", "cross-site"].includes(site) &&
      ["GET", "HEAD"].includes(req.method) &&
      ["/", "/index.html"].includes(req.url) &&
      req.headers["sec-fetch-mode"] === "navigate" &&
      req.headers["sec-fetch-dest"] === "document";
    if (!shellNavigation) return false;
  }
  return true;
}
export function deviceCanonical(method, path, time, nonce, body) {
  return [method, path, time, nonce, sha256(body)].join("\n");
}
const launcherId = /^[A-Za-z0-9_-]{1,120}$/;
export function validateLauncherQuery(query) {
  if (
    typeof query !== "string" ||
    Buffer.byteLength(query, "utf8") > 200 ||
    /[\x00-\x1f\x7f]/.test(query)
  )
    throw Error("Invalid launcher query");
  return query.trim();
}
export function validateLauncherRequest(body) {
  const fields = [
    "assetId",
    "accountId",
    "protocol",
    "confirmed",
    "idempotencyKey",
    "userId",
  ];
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.keys(body).some((key) => !fields.includes(key)) ||
    fields.some((key) => !Object.hasOwn(body, key)) ||
    ![body.assetId, body.accountId, body.idempotencyKey, body.userId].every(
      (value) => typeof value === "string" && launcherId.test(value),
    ) ||
    !["ssh", "sftp", "rdp"].includes(body.protocol) ||
    body.confirmed !== true
  )
    throw Error("Invalid launcher request; explicit local confirmation is required");
  return Object.fromEntries(fields.map((field) => [field, body[field]]));
}
export function launcherPayload(body, pairedUserId) {
  const { userId, ...payload } = validateLauncherRequest(body);
  if (userId !== pairedUserId)
    throw Object.assign(Error("The paired user changed; refresh the connection catalog before opening a target"), {
      status: 409,
      code: "paired_user_changed",
    });
  return payload;
}
export function validateLauncherURL(value, platform, request) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw Error("Invalid launcher workspace URL");
  }
  const keys = [...url.searchParams.keys()];
  if (
    typeof value !== "string" ||
    value.length > 1024 ||
    url.origin !== approvedOrigin(platform) ||
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.pathname !== "/remote-workspace.html" ||
    keys.length !== 4 ||
    new Set(keys).size !== 4 ||
    keys.some((key) => !["assetId", "accountId", "protocol", "userId"].includes(key)) ||
    typeof request.userId !== "string" ||
    !launcherId.test(request.userId) ||
    !["ssh", "sftp"].includes(request.protocol) ||
    ["assetId", "accountId", "protocol", "userId"].some(
      (key) => url.searchParams.get(key) !== request[key],
    )
  )
    throw Error("Invalid launcher workspace URL");
  return url.href;
}
export function launcherCatalog(result, userId) {
  if (
    !result ||
    !Array.isArray(result.items) ||
    result.items.length > 500 ||
    typeof result.truncated !== "boolean" ||
    typeof userId !== "string" ||
    !launcherId.test(userId) ||
    result.userId !== userId
  )
    throw Error("Invalid launcher catalog response");
  const fields = [
    "assetId",
    "assetName",
    "accountId",
    "accountName",
    "username",
    "osFamily",
    "protocol",
    "host",
    "port",
  ];
  const items = result.items.map((item) => {
    if (
      !item ||
      typeof item !== "object" ||
      ![item.assetId, item.accountId].every(
        (value) => typeof value === "string" && launcherId.test(value),
      ) ||
      !["ssh", "sftp", "rdp"].includes(item.protocol) ||
      !Number.isInteger(item.port) ||
      item.port < 1 ||
      item.port > 65535 ||
      fields.filter((key) => key !== "port").some(
        (key) => typeof item[key] !== "string" || item[key].length > 512 || /[\x00-\x1f\x7f]/.test(item[key]),
      )
    )
      throw Error("Invalid launcher catalog item");
    // Only reviewed display metadata crosses into the native search window.
    return Object.fromEntries(fields.map((field) => [field, item[field]]));
  });
  return { items, truncated: result.truncated, userId };
}
