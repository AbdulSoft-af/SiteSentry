import test from "node:test";
import assert from "node:assert/strict";
import { createPinnedLookup, isPublicAddress, resolvePublicTarget, validateTarget } from "../src/scanner.js";

test("accepts public HTTPS hostname", () => {
  const url = validateTarget("https://example.com/path?q=1");
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, "example.com");
  assert.equal(url.hash, "");
});

test("adds HTTPS scheme when omitted", () => {
  assert.equal(validateTarget("example.com").href, "https://example.com/");
});

test("rejects unsupported schemes", () => {
  assert.throws(() => validateTarget("file:///etc/passwd"), /Only HTTP and HTTPS/);
});

test("rejects local and reserved hostnames", () => {
  for (const host of ["localhost", "printer.local", "router.internal", "service.test", "site.example", "hidden.onion"]) {
    assert.throws(() => validateTarget(`http://${host}`), /Local and internal/);
  }
});

test("rejects private, loopback, link-local and reserved IPv4 ranges", () => {
  for (const host of [
    "127.0.0.1", "10.0.0.2", "192.168.1.1", "172.16.0.1", "169.254.169.254",
    "100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "0.2.3.4"
  ]) {
    assert.equal(isPublicAddress(host), false, `${host} must not be considered public`);
    assert.throws(() => validateTarget(`http://${host}`), /not allowed/);
  }
});

test("accepts ordinary public IPv4 and globally routable IPv6", () => {
  assert.equal(isPublicAddress("1.1.1.1"), true);
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("2606:4700:4700::1111"), true);
  assert.equal(isPublicAddress("2001:4860:4860::8888"), true);
});

test("rejects loopback, mapped and documentation IPv6", () => {
  for (const address of ["::", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "2001:db8::1", "2002::1", "3fff::1"]) {
    assert.equal(isPublicAddress(address), false, `${address} must not be considered public`);
  }
});

test("rejects alternate numeric spellings of loopback IPv4", () => {
  for (const address of ["127.1", "2130706433", "0x7f000001"]) {
    assert.throws(() => validateTarget(`http://${address}`), /not allowed/);
  }
});

test("rejects non-standard ports to avoid arbitrary TCP service probes", () => {
  assert.throws(() => validateTarget("http://example.com:8080"), /standard HTTP/);
  assert.throws(() => validateTarget("https://example.com:8443"), /standard HTTP/);
});

test("rejects embedded credentials", () => {
  assert.throws(() => validateTarget("https://user:pass@example.com"), /usernames or passwords/);
});

test("rejects malformed or empty values", () => {
  assert.throws(() => validateTarget(""), /Enter a website URL/);
  assert.throws(() => validateTarget("not a domain"), /valid domain|fully qualified/);
  assert.throws(() => validateTarget("https://example.com:abc"), /valid domain/);
});

test("DNS resolution fails closed if any answer is private", async () => {
  const resolver = async () => [
    { address: "93.184.216.34", family: 4 },
    { address: "10.0.0.8", family: 4 }
  ];
  await assert.rejects(resolvePublicTarget("mixed.example", resolver), /resolves to a private/);
});

test("DNS resolution rejects empty and malformed answer sets", async () => {
  await assert.rejects(resolvePublicTarget("empty.example", async () => []), /did not resolve/);
  await assert.rejects(resolvePublicTarget("bad.example", async () => [{ address: "not-an-ip", family: 0 }]), /resolves to a private/);
});

test("DNS resolution returns only validated addresses for pinning", async () => {
  const expected = [{ address: "93.184.216.34", family: 4 }];
  const result = await resolvePublicTarget("example.com", async () => expected);
  assert.deepEqual(result, expected);
});

test("literal public IP avoids DNS lookup and literal private IP is blocked", async () => {
  let called = false;
  const resolver = async () => { called = true; return [{ address: "93.184.216.34", family: 4 }]; };
  assert.deepEqual(await resolvePublicTarget("93.184.216.34", resolver), [{ address: "93.184.216.34", family: 4 }]);
  assert.equal(called, false);
  await assert.rejects(resolvePublicTarget("127.0.0.1", resolver), /private, loopback/);
});


test("pinned lookup returns the validated address without re-resolving DNS", async () => {
  const pinned = createPinnedLookup("example.com", { address: "93.184.216.34", family: 4 });
  const single = await new Promise((resolve, reject) => pinned("example.com", {}, (error, address, family) => {
    if (error) reject(error); else resolve({ address, family });
  }));
  assert.deepEqual(single, { address: "93.184.216.34", family: 4 });
  const all = await new Promise((resolve, reject) => pinned("example.com", { all: true }, (error, addresses) => {
    if (error) reject(error); else resolve(addresses);
  }));
  assert.deepEqual(all, [{ address: "93.184.216.34", family: 4 }]);
  await assert.rejects(new Promise((resolve, reject) => pinned("rebound.example", {}, error => {
    if (error) reject(error); else resolve();
  })), /Unexpected hostname/);
});
