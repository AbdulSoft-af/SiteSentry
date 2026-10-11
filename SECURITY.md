# Security Policy

## Scope

SiteSentry is a lightweight, non-invasive website diagnostics tool. It is not a penetration-testing framework and should not be operated as an unrestricted public scanning service.

## Reporting a concern

Please do not publish sensitive details about a live target in a public issue. Contact the repository maintainer privately using the contact method listed on the GitHub profile. Include a concise description, impact, affected version and safe reproduction steps.

## Safe operation

- Scan only websites you own or have explicit permission to assess.
- Keep the default `127.0.0.1` listener for personal use.
- Non-loopback binding is disabled unless `SITESENTRY_ALLOW_REMOTE=true` is set and a `SITESENTRY_API_TOKEN` of at least 32 characters is configured.
- Put any remote deployment behind HTTPS and a maintained reverse proxy. Never send bearer tokens over untrusted plain HTTP.
- Enforce outbound network/egress restrictions at the operating system, container or cloud firewall layer. Do not rely on application checks alone to protect metadata endpoints or control-plane networks.
- SiteSentry resolves hostnames, rejects unsafe or mixed DNS answer sets, pins each outbound request to a validated address, checks every redirect destination, blocks HTTPS-to-HTTP downgrade redirects and restricts requests to standard web ports.
- The built-in limiter is in-memory and is not a replacement for edge rate-limits, abuse monitoring or distributed controls.
- Do not commit API tokens or scan reports containing sensitive target metadata.

## Known limitations

The application does not validate authorization to scan a target. A valid DNS result and an HTTP response do not establish ownership or permission. DNS pinning and application-level address filtering are defense-in-depth, not guarantees against every infrastructure, routing, proxy or operating-system error. Remote deployments must use egress controls and should receive an independent security review before use by other people.
