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
  if (site && !["same-origin", "none"].includes(site)) return false;
  return true;
}
export function deviceCanonical(method, path, time, nonce, body) {
  return [method, path, time, nonce, sha256(body)].join("\n");
}
