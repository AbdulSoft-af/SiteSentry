# SiteSentry

SiteSentry is a self-hosted website diagnostics tool for developers and site owners. It checks a focused set of transport-security headers and page signals, then presents findings with clear explanations and next steps. The interface uses plain HTML, CSS and browser JavaScript; the backend uses built-in Node.js modules and does not require a third-party runtime package.

SiteSentry is intentionally a **non-invasive first-pass review**, not a penetration test, vulnerability certification, or replacement for a qualified security assessment.

## At a glance

- Reviews HTTPS, HTTP status, redirects and common response-security headers.
- Checks simple HTML signals such as a page title, forms, password fields and obvious HTTP asset references on HTTPS pages.
- Includes searchable/filterable findings and JSON/CSV exports.
- Uses DNS resolution validation and pinned addresses to reduce DNS-rebinding and DNS-check/connect race risks.
- Rejects private, loopback, link-local, multicast, documentation and reserved address ranges, including unsafe mixed DNS answers.
- Restricts requests to standard HTTP/HTTPS ports, GET requests, a short timeout, a limited redirect chain and a maximum inspected response size.
- Runs locally by default. Remote binding requires explicit opt-in and a strong bearer token.

## Requirements

- Node.js 20 or newer
- npm (included with Node.js)

No database, account, frontend build step, or third-party UI framework is needed.

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/SiteSentry.git
cd SiteSentry
npm run check
npm test
npm start
```

Open <http://127.0.0.1:4173>. The default listener is `127.0.0.1`, so the service is available only from the same machine.

To change the local port:

**macOS / Linux**

```bash
PORT=5000 npm start
```

**Windows PowerShell**

```powershell
$env:PORT = "5000"
npm start
```

For development with automatic restarts, run `npm run dev`.

## Use the dashboard

1. Start SiteSentry and open the local address in a browser.
2. Enter a public website URL, such as `https://example.com`.
3. Select **Scan website**.
4. Review the response status, passed checks, warnings and recommendations.
5. Search or filter findings to focus on a particular issue.
6. Select **Export JSON** for a complete machine-readable report or **Export CSV** for a spreadsheet-friendly report.

Only assess websites you own or have explicit permission to review. A warning is a prompt to investigate, not proof that a vulnerability can be exploited. A pass indicates only that the scanner observed a particular signal; it is not a security guarantee.

### Transport and response

- Whether the final URL uses HTTPS
- HTTP status, content type, final URL and bounded redirect chain
- Response headers, including CSP, HSTS, clickjacking protections, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`
- An obvious HTML title, form/password-field presence and simple HTTP asset references inside an HTTPS HTML response

### Defensive request boundaries

- HTTP and HTTPS only; URL credentials are rejected
- Standard ports only: HTTP port 80 and HTTPS port 443
- DNS A/AAAA answers are resolved before connecting and every returned address is validated
- Mixed DNS answer sets containing any unsafe address are rejected
- Each request is connected to one of the exact addresses validated for that request, instead of performing a second DNS lookup at connect time
- Redirects are followed manually; each next destination is revalidated, and HTTPS-to-HTTP downgrade redirects are blocked
- Local, private, loopback, link-local, multicast, documentation and reserved targets are rejected
- GET only, default 8-second total scan timeout, up to three redirects, and a 512 KiB maximum inspected response body
- Basic in-memory per-client request throttling, request-size limits and HTTP server timeouts

These controls reduce risk, but they do not replace network-level egress restrictions, operating-system isolation, or review of the deployed environment.


## Result interpretation and limitations

- **Pass:** the expected signal was observed, not that the whole configuration is correct.
- **Warning:** a signal is missing or a possible issue was observed. Confirm it against the site's architecture.
- **Info:** a detected feature needs manual review rather than an automatic verdict.
- **Severity:** a triage hint, not a calculated risk score.

SiteSentry does not execute JavaScript, crawl an entire site, log in, submit forms, test CSRF, exploit vulnerabilities, inspect source repositories, audit server-side code, or verify ownership of the target. It cannot reliably judge the quality of every CSP, authentication flow, cookie policy, or application authorization rule. DNS pinning does not protect against every routing, proxy, kernel, or infrastructure misconfiguration. Egress firewall rules remain an important independent control.

Report exports may contain hostnames and response metadata. Store and share them carefully.


## Development

Run the syntax checks and tests before submitting changes:

```bash
npm run check
npm test
```

GitHub Actions runs these checks on pushes and pull requests. Security-sensitive changes should include both rejected-input tests and positive tests for legitimate public targets.

## Contributing

Focused bug reports, documentation improvements and tests are welcome. Include expected behavior, safe reproduction steps and relevant test output. Avoid unnecessary dependencies. Do not contribute features intended for stealth, credential theft, unauthorized exploitation, or bypassing access controls.

