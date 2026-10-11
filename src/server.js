import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isIP } from "node:net";
import { scanWebsite } from "./scanner.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "127.0.0.1";
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 12;
const MAX_RATE_KEYS = 10_000;
const MAX_REQUEST_BYTES = 8192;
const rate = new Map();
let rateRequestsSincePrune = 0;
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml" };

function isLoopbackBind(value) {
  const normalized = value.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "::1" || (isIP(normalized) === 4 && normalized.startsWith("127."));
}

const remoteBinding = !isLoopbackBind(host);
const apiToken = process.env.SITESENTRY_API_TOKEN || "";
if (remoteBinding && process.env.SITESENTRY_ALLOW_REMOTE !== "true") {
  throw new Error("Refusing to bind to a network interface. For a protected remote deployment, set SITESENTRY_ALLOW_REMOTE=true and SITESENTRY_API_TOKEN (at least 32 characters). Prefer the default loopback binding for local use.");
}
if (remoteBinding && apiToken.length < 32) {
  throw new Error("Remote binding requires SITESENTRY_API_TOKEN to contain at least 32 characters.");
}

function send(res, status, data, type = "application/json; charset=utf-8", extraHeaders = {}) {
  res.writeHead(status, {
    "content-type": type,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "cache-control": "no-store",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    ...extraHeaders
  });
  res.end(type.startsWith("application/json") ? JSON.stringify(data) : data);
}

function getClientKey(req) {
  // Forwarded headers are deliberately ignored. Configure trusted proxy handling outside this app if needed.
  return req.socket.remoteAddress || "unknown";
}

function allowRequest(key) {
  const now = Date.now();
  if (++rateRequestsSincePrune >= 128) {
    rateRequestsSincePrune = 0;
    for (const [client, record] of rate) {
      if (now - record.start >= RATE_WINDOW_MS) rate.delete(client);
    }
  }
  let record = rate.get(key);
  if (!record) {
    if (rate.size >= MAX_RATE_KEYS) return false;
    record = { start: now, count: 0 };
    rate.set(key, record);
  }
  if (now - record.start >= RATE_WINDOW_MS) {
    record.start = now;
    record.count = 0;
  }
  record.count++;
  return record.count <= RATE_LIMIT;
}

function validBearerToken(req) {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || "");
  if (!match) return false;
  const supplied = Buffer.from(match[1], "utf8");
  const expected = Buffer.from(apiToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readJson(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > MAX_REQUEST_BYTES) {
      const error = new Error("Request body is too large.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); }
  catch { throw new Error("Invalid JSON body."); }
}

const server = http.createServer(async (req, res) => {
  // Do not use the caller-controlled Host header as a URL base for routing.
  const url = new URL(req.url || "/", "http://localhost");
  if (req.method === "GET" && url.pathname === "/api/health") {
    return send(res, 200, { ok: true, name: "SiteSentry", version: "1.2.0" });
  }
  if (req.method === "POST" && url.pathname === "/api/scan") {
    const key = getClientKey(req);
    if (!allowRequest(key)) return send(res, 429, { error: "Rate limit reached. Wait one minute and try again." });
    if (remoteBinding && !validBearerToken(req)) {
      return send(res, 401, { error: "Authentication required. Enter the configured API token." }, "application/json; charset=utf-8", { "www-authenticate": "Bearer realm=\"SiteSentry API\"" });
    }
    if (String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase() !== "application/json") {
      return send(res, 415, { error: "Content-Type must be application/json." });
    }
    try {
      const body = await readJson(req);
      if (typeof body.url !== "string") return send(res, 400, { error: "Provide a URL string." });
      const result = await scanWebsite(body.url);
      return send(res, 200, result);
    } catch (error) {
      const message = error?.message || "Scan failed.";
      const status = error.statusCode || (/URL|domain|hostname|HTTP|private|reserved|credentials|too long|redirect|public|local|port|DNS|address|downgrade|resolve|internal|multicast|link-local|invalid JSON/i.test(message) ? 400 : 502);
      return send(res, status, { error: message });
    }
  }
  if (req.method === "GET" && url.pathname !== "/" && url.pathname.includes("..")) {
    return send(res, 403, { error: "Forbidden." });
  }
  if (req.method === "GET") {
    const requested = url.pathname === "/" ? "/index.html" : url.pathname;
    const publicRoot = path.resolve(root, "public");
    const safePath = path.resolve(publicRoot, `.${requested}`);
    if (safePath !== publicRoot && !safePath.startsWith(publicRoot + path.sep)) return send(res, 403, { error: "Forbidden." });
    try {
      const content = await readFile(safePath);
      return send(res, 200, content, MIME[path.extname(safePath)] || "application/octet-stream");
    } catch {
      return send(res, 404, { error: "Not found." });
    }
  }
  return send(res, 404, { error: "Not found." });
});

server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 50;

server.listen(port, host, () => {
  console.log(`SiteSentry 1.2.0 running at http://${host}:${port}`);
  if (remoteBinding) console.warn("Remote mode enabled: keep HTTPS termination, firewall egress controls, and API token rotation configured.");
});
