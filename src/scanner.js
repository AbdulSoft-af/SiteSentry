import http from "node:http";
import https from "node:https";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 512 * 1024;
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const LOCAL_SUFFIXES = ["localhost", "local", "internal", "test", "example", "invalid", "onion", "lan"];

const BLOCKED_IPV4_CIDRS = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
  "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
  "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
  "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"
];
const BLOCKED_IPV6_CIDRS = ["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"];

function parseIPv4(ip) {
  if (isIP(ip) !== 4) return null;
  return ip.split(".").map(Number).reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
}

function ipv4CidrContains(ip, cidr) {
  const [network, prefixText] = cidr.split("/");
  const addressValue = parseIPv4(ip);
  const networkValue = parseIPv4(network);
  if (addressValue === null || networkValue === null) return false;
  const prefix = Number(prefixText);
  const mask = prefix === 0 ? 0n : ((0xffffffffn << BigInt(32 - prefix)) & 0xffffffffn);
  return (addressValue & mask) === (networkValue & mask);
}

function ipv6ToBigInt(input) {
  let address = input.toLowerCase().split("%")[0];
  if (address.includes(".")) {
    const match = address.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (!match) return null;
    const ipv4 = match[1].split(".").map(Number);
    if (ipv4.some(value => !Number.isInteger(value) || value < 0 || value > 255)) return null;
    const tail = `${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
    address = address.slice(0, match.index) + tail;
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fillCount = 8 - left.length - right.length;
  if ((halves.length === 1 && fillCount !== 0) || (halves.length === 2 && fillCount < 1)) return null;
  const groups = [...left, ...Array(fillCount).fill("0"), ...right];
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n);
}

function ipv6CidrContains(ip, cidr) {
  const [network, prefixText] = cidr.split("/");
  const addressValue = ipv6ToBigInt(ip);
  const networkValue = ipv6ToBigInt(network);
  if (addressValue === null || networkValue === null) return false;
  const prefix = Number(prefixText);
  const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
  return (addressValue & mask) === (networkValue & mask);
}

/** Returns true only for globally routable IPv4/IPv6 addresses. Unknown formats fail closed. */
export function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) return !BLOCKED_IPV4_CIDRS.some(cidr => ipv4CidrContains(address, cidr));
  if (family !== 6) return false;
  // Globally assigned IPv6 unicast space is within 2000::/3. Fail closed for all other ranges.
  if (!ipv6CidrContains(address, "2000::/3")) return false;
  return !BLOCKED_IPV6_CIDRS.some(cidr => ipv6CidrContains(address, cidr));
}

function hostnameWithoutBrackets(hostname) {
  return hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
}

export function validateTarget(input) {
  if (typeof input !== "string" || !input.trim()) throw new Error("Enter a website URL.");
  if (input.length > 2048) throw new Error("URL is too long.");
  let url;
  try {
    const value = input.trim();
    url = new URL(value.includes("://") ? value : `https://${value}`);
  } catch {
    throw new Error("Enter a valid domain, such as https://example.com.");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS URLs are allowed.");
  if (url.username || url.password) throw new Error("URLs containing usernames or passwords are not allowed.");
  if (url.port) throw new Error("Only standard HTTP (port 80) and HTTPS (port 443) ports are allowed.");

  const host = hostnameWithoutBrackets(url.hostname);
  if (!host) throw new Error("Enter a valid public hostname.");
  if (LOCAL_SUFFIXES.some(suffix => host === suffix || host.endsWith(`.${suffix}`)) ||
      host === "localhost" || host.endsWith(".localhost")) {
    throw new Error("Local and internal hostnames are not allowed.");
  }

  const family = isIP(host);
  if (family) {
    if (!isPublicAddress(host)) throw new Error("Private, loopback, link-local, multicast, or reserved IP addresses are not allowed.");
  } else {
    if (!host.includes(".")) throw new Error("Enter a public fully qualified domain name.");
    const labels = host.split(".");
    if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
      throw new Error("Enter a valid public fully qualified domain name.");
    }
  }
  url.hash = "";
  return url;
}

/** Resolve once, validate every answer, and return the exact addresses used for pinned requests. */
export async function resolvePublicTarget(hostname, resolver = dnsLookup) {
  const host = hostnameWithoutBrackets(hostname);
  const family = isIP(host);
  if (family) {
    if (!isPublicAddress(host)) throw new Error("The target IP is private, loopback, link-local, multicast, or reserved; scan blocked.");
    return [{ address: host, family }];
  }

  let answers;
  try {
    answers = await resolver(host, { all: true, verbatim: true });
  } catch {
    throw new Error("Could not resolve the target hostname. Check the domain and DNS configuration.");
  }
  if (!Array.isArray(answers) || answers.length === 0) throw new Error("The target hostname did not resolve to an IP address.");
  const normalized = answers.map(answer => ({ address: answer.address, family: answer.family || isIP(answer.address) }));
  // Fail closed if even one answer is unsafe. Do not pick only the apparently safe answer from a mixed set.
  if (normalized.some(answer => !answer.family || !isPublicAddress(answer.address))) {
    throw new Error("The target hostname resolves to a private, loopback, link-local, multicast, or reserved IP address; scan blocked.");
  }
  return normalized;
}

export function createPinnedLookup(expectedHost, address) {
  const expected = hostnameWithoutBrackets(expectedHost);
  return (hostname, options, callback) => {
    if (hostnameWithoutBrackets(hostname) !== expected) {
      callback(new Error("Unexpected hostname requested during pinned DNS lookup."));
      return;
    }
    if (options && options.all) callback(null, [{ address: address.address, family: address.family }]);
    else callback(null, address.address, address.family);
  };
}

function headersFromNode(responseHeaders) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(responseHeaders)) {
    if (value === undefined) continue;
    // Never expose session cookies in the web UI or exported reports.
    if (["set-cookie", "set-cookie2"].includes(key.toLowerCase())) continue;
    headers.set(key, Array.isArray(value) ? value.join(", ") : String(value));
  }
  return headers;
}

function requestPinned(url, addresses, timeoutMs, signal) {
  const protocol = url.protocol === "https:" ? https : http;
  const hostname = hostnameWithoutBrackets(url.hostname);
  // The address is pinned to a verified DNS answer: Node cannot resolve the name again between check and connect.
  const selectedAddress = addresses[0];
  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    const finish = (handler, value) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      handler(value);
    };
    const onAbort = () => request?.destroy(Object.assign(new Error("The scan timed out."), { name: "AbortError" }));

    try {
      request = protocol.request({
        protocol: url.protocol,
        hostname,
        port: url.protocol === "https:" ? 443 : 80,
        method: "GET",
        path: `${url.pathname}${url.search}`,
        agent: false,
        lookup: createPinnedLookup(hostname, selectedAddress),
        ...(url.protocol === "https:" && !isIP(hostname) ? { servername: hostname } : {}),
        headers: {
          host: url.host,
          "user-agent": "SiteSentry/1.2 (+permission-based website diagnostics)",
          accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
          "accept-encoding": "identity",
          connection: "close"
        }
      }, response => {
        const headers = headersFromNode(response.headers);
        const status = response.statusCode || 0;
        if (REDIRECT_CODES.has(status)) {
          response.destroy();
          finish(resolve, { status, headers, body: "", bytes: 0, truncated: false });
          return;
        }

        const chunks = [];
        let bytes = 0;
        response.on("data", chunk => {
          if (settled) return;
          const remaining = MAX_BODY_BYTES - bytes;
          if (chunk.length <= remaining) {
            chunks.push(chunk);
            bytes += chunk.length;
            return;
          }
          if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
          bytes = MAX_BODY_BYTES;
          const body = Buffer.concat(chunks).toString("utf8");
          finish(resolve, { status, headers, body, bytes, truncated: true });
          response.destroy();
        });
        response.on("end", () => finish(resolve, {
          status, headers, body: Buffer.concat(chunks).toString("utf8"), bytes, truncated: false
        }));
        response.on("error", error => finish(reject, error));
      });
      request.on("error", error => finish(reject, error));
      request.setTimeout(timeoutMs, () => request.destroy(Object.assign(new Error("The scan timed out."), { name: "AbortError" })));
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) onAbort();
      else request.end();
    } catch (error) {
      finish(reject, error);
    }
  });
}

function headerChecks(headers, finalUrl) {
  const checks = [];
  const add = (id, title, pass, severity, detail, recommendation) =>
    checks.push({ id, title, status: pass ? "pass" : "warning", severity, detail, recommendation });

  add("https", "HTTPS enabled", finalUrl.protocol === "https:", "high",
    finalUrl.protocol === "https:" ? "The final page uses HTTPS." : "The final page uses plain HTTP.",
    "Serve the entire site over HTTPS and redirect HTTP to HTTPS.");
  add("hsts", "Strict-Transport-Security", Boolean(headers.get("strict-transport-security")), "medium",
    headers.get("strict-transport-security") || "Header not detected.",
    "For HTTPS sites, consider a carefully tested HSTS policy.");
  add("csp", "Content-Security-Policy", Boolean(headers.get("content-security-policy")), "high",
    headers.get("content-security-policy") || "Header not detected.",
    "Define a restrictive Content Security Policy and test it before enforcement.");
  add("xfo", "Clickjacking protection", Boolean(headers.get("x-frame-options")) ||
    /frame-ancestors/i.test(headers.get("content-security-policy") || ""), "medium",
    headers.get("x-frame-options") || (/frame-ancestors/i.test(headers.get("content-security-policy") || "") ?
      "CSP frame-ancestors directive detected." : "X-Frame-Options and CSP frame-ancestors not detected."),
    "Use CSP frame-ancestors; X-Frame-Options can support older browsers.");
  add("nosniff", "X-Content-Type-Options", headers.get("x-content-type-options")?.toLowerCase() === "nosniff", "low",
    headers.get("x-content-type-options") || "Header not detected.",
    "Set X-Content-Type-Options: nosniff.");
  add("referrer", "Referrer-Policy", Boolean(headers.get("referrer-policy")), "low",
    headers.get("referrer-policy") || "Header not detected.",
    "Set an appropriate Referrer-Policy, such as strict-origin-when-cross-origin.");
  add("permissions", "Permissions-Policy", Boolean(headers.get("permissions-policy")), "low",
    headers.get("permissions-policy") || "Header not detected.",
    "Disable browser features your site does not need using Permissions-Policy.");
  add("server", "Server banner exposure", !headers.get("server"), "info",
    headers.get("server") || "No Server header detected.",
    "Avoid exposing unnecessary implementation details in response headers.");
  return checks;
}

export async function scanWebsite(input, options = {}) {
  const initial = validateTarget(input);
  const timeoutMs = Math.min(Math.max(Number(options.timeoutMs) || DEFAULT_TIMEOUT_MS, 1000), 15000);
  const maxRedirects = 3;
  const resolver = options.resolveDns || dnsLookup;
  let current = initial;
  let response;
  const redirectChain = [];
  const controller = new AbortController();
  const abortPromise = new Promise((_, reject) => {
    controller.signal.addEventListener("abort", () => reject(Object.assign(new Error("The scan timed out."), { name: "AbortError" })), { once: true });
  });
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    for (let hops = 0; hops <= maxRedirects; hops++) {
      current = validateTarget(current.href);
      const addressPromise = resolvePublicTarget(current.hostname, resolver);
      const addresses = await Promise.race([addressPromise, abortPromise]);
      if (controller.signal.aborted) throw Object.assign(new Error("The scan timed out."), { name: "AbortError" });

      response = await requestPinned(current, addresses, Math.max(1, timeoutMs), controller.signal);
      if (REDIRECT_CODES.has(response.status)) {
        const location = response.headers.get("location");
        if (!location) break;
        if (hops === maxRedirects) throw new Error("Too many redirects; scan stopped.");
        const next = new URL(location, current);
        const safeNext = validateTarget(next.href);
        if (current.protocol === "https:" && safeNext.protocol === "http:") {
          throw new Error("HTTPS downgrade redirects are not allowed.");
        }
        redirectChain.push({ status: response.status, from: current.origin, to: safeNext.origin });
        current = safeNext;
        continue;
      }
      break;
    }
  } catch (error) {
    if (error.name === "AbortError" || error.code === "ETIMEDOUT") throw new Error("The scan timed out. Try again later.");
    if (/socket hang up|ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|fetch failed/i.test(error.message || "")) {
      throw new Error("Could not reach this website. Check the URL and try again.");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }

  if (!response) throw new Error("No response received.");
  const headers = Object.fromEntries([...response.headers.entries()]);
  const checks = headerChecks(response.headers, current);
  const html = response.headers.get("content-type")?.includes("text/html") ? response.body : "";
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.replace(/\s+/g, " ").trim().slice(0, 180) || null;
  const hasForm = /<form\b/i.test(html);
  const hasPasswordField = /<input\b[^>]*type\s*=\s*["']?password/i.test(html);
  const mixedContent = current.protocol === "https:" && /(?:src|href)\s*=\s*["']http:\/\//i.test(html);
  checks.push({
    id: "mixed-content", title: "Mixed-content references",
    status: mixedContent ? "warning" : "pass", severity: "medium",
    detail: mixedContent ? "The HTML contains at least one HTTP asset reference." : "No obvious HTTP asset references found in the downloaded HTML.",
    recommendation: "Load page assets over HTTPS and inspect browser console warnings."
  });
  checks.push({
    id: "forms", title: "Forms and password fields",
    status: hasPasswordField ? "info" : "pass", severity: "info",
    detail: hasPasswordField ? "A password input was detected; this scanner does not submit or test forms." :
      (hasForm ? "A form was detected; its security was not tested." : "No HTML form detected in the inspected response."),
    recommendation: "Review form validation, CSRF protections, secure cookies, and server-side authorization manually."
  });
  if (response.truncated) {
    checks.push({
      id: "response-limit", title: "Response body inspection limit", status: "info", severity: "info",
      detail: `Only the first ${MAX_BODY_BYTES.toLocaleString()} bytes were inspected; the response was larger than the configured limit.`,
      recommendation: "Treat page-content findings as partial; response headers were still inspected."
    });
  }

  const warnings = checks.filter(check => check.status === "warning").length;
  const passed = checks.filter(check => check.status === "pass").length;
  return {
    scannedAt: new Date().toISOString(),
    requestedUrl: initial.origin,
    finalUrl: current.href,
    statusCode: response.status,
    contentType: response.headers.get("content-type") || "unknown",
    title,
    responseBytesInspected: response.bytes,
    redirectChain,
    summary: { total: checks.length, passed, warnings, informational: checks.filter(check => check.status === "info").length },
    checks,
    headers,
    limitations: [
      "This is a lightweight, non-invasive check, not a penetration test.",
      "Only the initial HTML response and response headers are inspected; JavaScript execution is not performed.",
      "A missing header is not automatically proof of a vulnerability. Confirm recommendations against your architecture.",
      "DNS answers are validated and the selected address is pinned for each request to reduce DNS-rebinding and TOCTOU risks.",
      "Only standard HTTP/HTTPS ports are scanned; unsafe or mixed private/public DNS answers are rejected.",
      "Only scan websites you own or have explicit permission to assess."
    ]
  };
}
