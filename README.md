# Gateway LAN Link

[![PowerShell checks](https://github.com/Jnapier2/lan-router-comms/actions/workflows/powershell-static.yml/badge.svg)](https://github.com/Jnapier2/lan-router-comms/actions/workflows/powershell-static.yml)

[Portfolio](https://jerry-napier-portfolio.netlify.app/) · [GitHub profile](https://github.com/Jnapier2)

Repository slug and historical alias: **LAN Router Comms** (`lan-router-comms`).

Gateway LAN Link provides a direct, cloud-free path for authenticated text and resumable file exchange between two managed Windows computers on a trusted private network. It supports local continuity and data-control needs without adding a cloud relay, port forwarding, remote shell, background service, scheduled task, or startup persistence.

Durable queues and hash receipts make delivery a state-reconciliation problem rather than a blind resend: after an interruption, peers can continue from authenticated, recorded progress and retain duplicate-safe completion evidence.

## Protocol and safeguards

- OS-negotiated TLS with a strict TLS 1.2 floor.
- Exact SHA-256 certificate pinning, peer-name validation, validity checks, and an RSA 2048-bit minimum.
- HMAC-SHA256 authentication, replay protection, and request correlation for every protocol envelope.
- DPAPI `CurrentUser` protection for local identity passwords, pairing state, peer secrets, and queued text.
- Durable queues, duplicate-safe delivery, resumable file transfer, free-space admission, and SHA-256 receipts.
- Bounded timeouts, session quotas, TCP keepalive, and jittered backoff.
- Explicit, narrowly scoped Windows Firewall setup with a matching rollback.
- A read-only runtime identity and managed-file gate before identity access, pairing, authenticated transport, or optional firewall actions.

## Requirements and scope

- Windows 10 or 11 with Windows PowerShell 5.1
- Two Windows computers you own or administer
- Direct reachability on the same trusted RFC1918 private network

The receiver is visible and foreground-only. Guest Wi-Fi isolation, VLANs, VPN routing, Public profiles, or local security policy can block connectivity. This project is not designed for internet exposure.

## Quick start

Double-click `GatewayLANLink.bat` for the canonical Windows menu. The BAT file is intentionally a thin, root-relative launcher; `LAN_Router_Comms.ps1` remains the single source of application behavior and accepts the direct modes below.

Both the BAT and the PowerShell engine invoke `Verify-Release.ps1` before runtime initialization. Direct PowerShell execution therefore cannot bypass release identity or managed-file verification.

Review the source and run the checks:

```powershell
powershell.exe -NoProfile -File .\Verify-Release.ps1
powershell.exe -NoProfile -File .\tests\Test-SafetyContracts.ps1
powershell.exe -NoProfile -File .\tests\Test-LauncherContract.ps1
powershell.exe -NoProfile -File .\tests\Test-RuntimeIdentityContract.ps1
.\GatewayLANLink.bat -Mode StartupTest
.\GatewayLANLink.bat -Mode Menu
```

The repository does not bypass local execution-policy controls.

To pair two computers, create a one-time invitation on computer A, keep its visible receiver open, move the `.llinvite` file to computer B through a trusted channel, and compare the displayed verification code out of band before typing `PAIR`. An invitation is a bearer secret until used or expired.

## Release identity and managed-file integrity

The v2.17.9-aligned source package uses four cooperating contracts:

- `VERSION.txt` — package ID, source version, build ID, parameter baseline, canonical entrypoint, and execution namespace;
- `PACKAGE_METADATA.json` — authenticated-activity boundary, project-local roots, security boundary, and repair policy;
- `MANIFEST.json` — deterministic canonical-text size and SHA-256 records for every runtime-managed file;
- `Verify-Release.ps1` — read-only identity and managed-file verification.

Verification fails closed when files are absent, mixed between builds, linked/reparse points, outside the project root, duplicated in the manifest, the wrong size, or hash-mismatched. It also confirms that the package, metadata, manifest, source version, and build ID agree.

On failure, authenticated startup is blocked. Replace the folder with one complete checksum-verified package; do not copy individual runtime files between builds. The verifier never repairs or rewrites managed files while deciding whether they are trusted.

The current manifest hashes UTF-8 text after normalizing line endings to LF, preventing Git checkout line-ending conversion from creating a false integrity failure while still detecting content changes.

## Optional firewall rule

Normal startup, pairing, sending, receiving, health checks, and diagnostics do not change firewall state. The firewall helper acts only after an explicit user choice, a passing release-integrity gate, and UAC when needed.

```powershell
# Add or repair the narrow rule
.\GatewayLANLink.bat -Mode FirewallAdd -Port 57222

# Roll it back, including recognized legacy rules for that port
.\GatewayLANLink.bat -Mode FirewallRemove -Port 57222
```

The add action allows one inbound TCP port on `Private` profiles from `LocalSubnet`, limited to Windows PowerShell. Before replacing any current or recognized legacy rule, it captures the existing rule properties. If creation or exact-scope verification fails, it removes partial state and restores the prior matching rules. TLS pinning and HMAC remain the application authorization boundary. The program never disables Windows Firewall or changes endpoint-security settings.

## Redacted support export

Create a bounded, read-only diagnostic archive with:

```powershell
.\GatewayLANLink.bat -Mode SupportExport
```

The archive excludes message and file contents, pairing secrets, and raw identity material, and labels generated metadata `support-redacted`. Redaction is a safeguard, not a guarantee; review every file before sharing the archive.

## Runtime data

On first use, the program creates local configuration and state. Real settings, identities, peers, invitations, messages, files, logs, diagnostics, and exports are ignored by Git. `config/settings.example.json` contains only non-secret defaults.

The project-local runtime roots are `config`, `state`, `logs`, `temp`, `exports`, `diag`, and `inbox`. The launcher and engine derive these paths from their own source location rather than the caller's working directory.

That versioned settings contract centralizes the port, message and file limits, timeouts, session quotas, retry behavior, retention windows, and free-space reserve.

Received files are authenticated and hash-verified in transit but remain ordinary files after delivery. Scan them before opening.

Individual transfers are capped at 10 GiB. The receiver also preserves the configured free-space reserve before accepting incoming data.

## Validation

Windows CI verifies:

- PowerShell parsing and the established TLS, HMAC, DPAPI, certificate, firewall, cleanup, and transfer-limit invariants;
- the one canonical root launcher;
- clean-package identity success with no source-tree writes;
- rejection of source tamper, escaping manifest paths, and duplicate manifest entries;
- both canonical-BAT and direct-engine startup from unrelated working directories;
- no runtime folder creation beneath the caller working directory.

## Limits

This transparent PowerShell implementation has not received an independent security audit or formal protocol review. DPAPI inherits the security of the signed-in Windows account. Certificate rotation is manual, and there is no NAT traversal, cloud relay, multi-user service, or non-Windows client.

See [SECURITY.md](SECURITY.md) for operational guidance.

Copyright © 2026 Gateway Information Group LLC. All rights reserved. See [LICENSE.md](LICENSE.md).
