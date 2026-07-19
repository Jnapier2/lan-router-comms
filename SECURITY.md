# Security model

Use LAN Router Comms only on Windows computers and private networks you own or administer. Do not expose the receiver to the internet or configure port forwarding for it.

## Controls

- The OS negotiates TLS; the application rejects protocols below TLS 1.2.
- Connections must match the stored SHA-256 certificate fingerprint, expected peer name, validity window, and RSA key floor.
- HMAC-SHA256, sender/correlation validation, timestamps, and replay records authenticate each request.
- DPAPI `CurrentUser` protects certificate-password material, peer secrets, invitation state, and queued text at rest.
- File chunks and final files are hash-verified; delivery is duplicate-safe and resumable.
- The visible receiver applies private-address checks, timeouts, keepalive, session quotas, queue bounds, a 10 GiB per-transfer ceiling, and free-space admission.

An invitation is a bearer secret until it is used or expires. Compare the verification code out of band and authorize only an expected peer. DPAPI is not a defense against malware or an attacker controlling the signed-in Windows session.

## Local data

Runtime paths under `config/`, `state/`, `inbox/`, `logs/`, `diag/`, `exports/`, and `temp/` can contain sensitive metadata or content. Never commit real identities, peer records, invitations, messages, files, logs, or diagnostic archives. Support exports omit content and secrets and redact common local identifiers, but review every exported file before sharing.

## Firewall side effect and rollback

No firewall change occurs during normal use. The explicit add/repair action requests UAC and creates one inbound TCP rule scoped to the configured port, `Private` profiles, `LocalSubnet`, and Windows PowerShell. It snapshots matching current and legacy rules before mutation; if creation or verification fails, it removes partial state and restores those prior rules. The explicit remove action requests UAC when needed and removes current and recognized legacy rules for that port.

The program does not disable firewall profiles, change endpoint-security settings, add exclusions, install a service, create a scheduled task, or add startup persistence.

## Received files

Authentication and hashes identify the paired sender and integrity in transit; they do not prove that content is harmless. Scan received files before opening.

Use private vulnerability reporting when available. Never post real invitations, identity files, peer records, diagnostics, or network details in a public issue. This project has not received an independent security audit.
