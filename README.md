# 🛡️ SiteSentry

<p align="center">
  <strong>Lightweight Website Security Diagnostics</strong>
  <br>
  <em>Inspect · Understand · Improve</em>
  <br><br>
  A self-hosted, non-invasive website diagnostics tool for developers and site owners.
</p>

<p align="center">
  <strong>🔒 HTTPS & Headers</strong> ·
  <strong>🌐 DNS Safety</strong> ·
  <strong>📊 Security Reports</strong>
</p>

---

## 📌 Overview

SiteSentry is a lightweight, self-hosted website diagnostics tool that examines a focused set of transport-security headers, HTTP responses, redirects, and basic HTML signals.

Built with **HTML, CSS, Vanilla JavaScript, and native Node.js modules**, it presents findings with clear explanations and actionable next steps — without requiring third-party runtime packages.

> **Security by design:** SiteSentry is a non-invasive first-pass review tool, not a penetration test, vulnerability certification, or replacement for a qualified security assessment.

## ✨ Key Features

- 🔐 **HTTPS Analysis** — Check HTTPS usage, HTTP status codes, and final destinations.
- 🛡️ **Security Header Checks** — Review CSP, HSTS, clickjacking protections, and other common response headers.
- 🌐 **DNS Validation** — Validate DNS answers and reject unsafe mixed address sets.
- 🔗 **Redirect Inspection** — Revalidate redirect destinations and block HTTPS-to-HTTP downgrade redirects.
- 🧩 **HTML Signal Detection** — Inspect page titles, forms, password fields, and obvious HTTP asset references on HTTPS pages.
- 🔎 **Search & Filtering** — Find relevant diagnostic results quickly.
- 📤 **JSON & CSV Exports** — Export reports for further analysis and documentation.
- ⚡ **Lightweight Runtime** — Use built-in Node.js modules without third-party runtime dependencies.
- 🖥️ **Local-First Operation** — Run locally by default, with explicit safeguards for remote access.

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| HTML5 | Dashboard structure |
| CSS3 | Styling and responsive layout |
| Vanilla JavaScript | Frontend interactions |
| Node.js 20+ | Backend and scanning engine |
| Built-in Node.js modules | HTTP, HTTPS, DNS, and networking |
| Node.js Test Runner | Automated testing |

## 📋 Requirements

- Node.js 20 or newer
- npm, included with Node.js

No database, user account, frontend build step, or third-party UI framework is required.

## 🚀 Quick Start

### 1. Clone the repository

Replace `YOUR-USERNAME` with your GitHub username.

```bash
git clone https://github.com/YOUR-USERNAME/SiteSentry.git
cd SiteSentry
```

### 2. Run checks and tests

```bash
npm run check
npm test
```

### 3. Start SiteSentry

```bash
npm start
```

### 4. Open the dashboard

Visit:

**http://127.0.0.1:4173**

By default, SiteSentry listens on `127.0.0.1`, so it is accessible only from the same machine.

### ⚙️ Change the Local Port

**Windows PowerShell**

```powershell
$env:PORT = "5000"
npm start
```

**macOS / Linux**

```bash
PORT=5000 npm start
```

For automatic restarts during development:

```bash
npm run dev
```

## 🖥️ Using the Dashboard

1. Start SiteSentry and open the local dashboard.
2. Enter a public website URL, such as `https://example.com`.
3. Select **Scan website**.
4. Review the response status, passed checks, warnings, and recommendations.
5. Search or filter findings to investigate specific signals.
6. Select **Export JSON** or **Export CSV** to save the report.

Only assess websites you own or have explicit permission to review.

## 🔍 Diagnostic Coverage

### 🌐 Transport & Response

SiteSentry inspects:

- Whether the final URL uses HTTPS
- HTTP status and content type
- Final URL and bounded redirect chain
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- Clickjacking protection headers
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- Basic HTML title and form/password-field signals
- Obvious HTTP asset references within HTTPS HTML responses

### 🛡️ Defensive Request Boundaries

SiteSentry implements request restrictions designed to reduce the risk of unsafe outbound connections:

- Allows HTTP and HTTPS only; rejects URL credentials.
- Restricts destinations to standard ports: HTTP `80` and HTTPS `443`.
- Resolves DNS A/AAAA answers before connecting and validates every returned address.
- Rejects mixed DNS responses containing any unsafe address.
- Pins each connection to an address validated for that request, reducing DNS-rebinding and DNS-check/connect race risks.
- Follows redirects manually and revalidates each destination.
- Blocks HTTPS-to-HTTP downgrade redirects.
- Rejects local, private, loopback, link-local, multicast, documentation, reserved, and other prohibited address ranges.
- Uses GET requests only.
- Applies a default total scan timeout of 8 seconds.
- Limits redirects to three and inspected response bodies to 512 KiB.
- Applies basic in-memory per-client throttling, request-size limits, and HTTP server timeouts.

These controls reduce risk but do not eliminate every possible networking or infrastructure threat.

## 📊 Understanding Results

| Finding | Meaning |
|---|---|
| ✅ Pass | An expected signal was observed. |
| ⚠️ Warning | A possible issue or missing signal requires investigation. |
| ℹ️ Info | A detected feature requires manual review. |
| Severity | A triage hint, not a calculated risk score. |

A **Pass** does not mean the website is completely secure. A **Warning** does not prove that a vulnerability is exploitable. Always interpret findings within the context of the target website's architecture.

## ⚠️ Scope & Limitations

SiteSentry is a first-pass diagnostics tool. It does not:

- Execute JavaScript or crawl an entire website.
- Log in to websites or submit forms.
- Test CSRF or exploit vulnerabilities.
- Inspect source repositories or audit server-side application code.
- Verify ownership of the target website.
- Fully evaluate CSP quality, authentication flows, cookie policies, or application authorization rules.

DNS pinning does not protect against every routing, proxy, kernel, or infrastructure misconfiguration. Network-level egress filtering and appropriate operating-system isolation remain important independent controls.

**Responsible use:** Only scan websites you own or have explicit permission to assess.

Exported reports may contain hostnames and response metadata. Store and share them carefully.

## 🧪 Development & Testing

Run syntax checks and tests before submitting changes:

```bash
npm run check
npm test
```

GitHub Actions runs these checks on pushes and pull requests.

Security-sensitive changes should include both rejected-input tests and positive tests for legitimate public targets.

## 🤝 Contributing

Contributions are welcome!

You can contribute by submitting:

- Focused bug fixes
- Documentation improvements
- Automated tests
- Defensive security enhancements
- Usability and accessibility improvements

Please include expected behavior, safe reproduction steps, and relevant test output.

Avoid unnecessary dependencies and features designed for stealth, credential theft, unauthorized exploitation, or bypassing access controls.

## 📄 License

SiteSentry is distributed under the **MIT License**.

You are free to use, copy, modify, distribute, sublicense, and sell copies of the software, subject to the terms and conditions of the license.

**[📜 Read the MIT License](LICENSE)**

To complete the license setup, create a file named `LICENSE` in the repository root containing the official MIT License text, with the appropriate copyright year and copyright holder.


<p align="center">
  <strong>🛡️ SiteSentry</strong>
  <br>
  <em>Clearer Insights. Safer Websites.</em>
  <br><br>
  Built for developers who take website security seriously.
</p>
