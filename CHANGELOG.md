# Changelog

## 2.3.0 - Adaptive Transport Guard

- Added OS-adaptive TLS negotiation with a strict TLS 1.2 floor.
- Added socket-level keepalive, incoming free-space admission, bounded sessions, and jittered retry backoff.
- Preserved certificate pinning, per-peer HMAC, replay protection, resumable delivery, and protocol 2 compatibility.
- Removed execution-policy bypasses from the public source path.
- Added public security documentation, sanitized example configuration, static policy checks, and CI.
- Capped individual transfers at 10 GiB and made firewall repair transactional.
- Replaced package-specific diagnostics with a bounded, redacted support export.
