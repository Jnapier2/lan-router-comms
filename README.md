# LAN Router Comms

[![PowerShell checks](https://github.com/Jnapier2/lan-router-comms/actions/workflows/powershell-static.yml/badge.svg)](https://github.com/Jnapier2/lan-router-comms/actions/workflows/powershell-static.yml)

LAN Router Comms is a foreground Windows utility for authenticated text and resumable file delivery between paired computers on the same trusted private LAN. It uses no cloud relay, port forwarding, remote shell, background service, scheduled task, or startup persistence.

## Protocol and safeguards

- OS-negotiated TLS with a strict TLS 1.2 floor.
- Exact SHA-256 certificate pinning, peer-name validation, validity checks, and an RSA 2048-bit minimum.
- HMAC-SHA256 authentication, replay protection, and request correlation for every protocol envelope.
- DPAPI `CurrentUser` protection for local identity passwords, pairing state, peer secrets, and queued text.
- Durable queues, duplicate-safe delivery, resumable file transfer, free-space admission, and SHA-256 receipts.
- Bounded timeouts, session quotas, TCP keepalive, and jittered backoff.
- Explicit, narrowly scoped Windows Firewall setup with a matching rollback.

## Requirements and scope

- Windows 10 or 11 with Windows PowerShell 5.1
- Two Windows computers you own or administer
- Direct reachability on the same trusted RFC1918 private network

The receiver is visible and foreground-only. Guest Wi-Fi isolation, VLANs, VPN routing, Public profiles, or local security policy can block connectivity. This project is not designed for internet exposure.

## Quick start

Review the source and run the static checks:

```powershell
powershell.exe -NoProfile -File .\tests\Test-SafetyContracts.ps1
powershell.exe -NoProfile -File .\LAN_Router_Comms.ps1 -Mode StartupTest
powershell.exe -NoProfile -File .\LAN_Router_Comms.ps1 -Mode Menu
```

The repository does not bypass local execution-policy controls.

To pair two computers, create a one-time invitation on computer A, keep its visible receiver open, move the `.llinvite` file to computer B through a trusted channel, and compare the displayed verification code out of band before typing `PAIR`. An invitation is a bearer secret until used or expired.

## Optional firewall rule

Normal startup, pairing, sending, receiving, health checks, and diagnostics do not change firewall state. The firewall helper acts only after an explicit user choice and requests UAC when needed.

```powershell
# Add or repair the narrow rule
powershell.exe -NoProfile -File .\LAN_Router_Comms.ps1 -Mode FirewallAdd -Port 57222

# Roll it back, including recognized legacy rules for that port
powershell.exe -NoProfile -File .\LAN_Router_Comms.ps1 -Mode FirewallRemove -Port 57222
```

The add action allows one inbound TCP port on `Private` profiles from `LocalSubnet`, limited to Windows PowerShell. Before replacing any current or recognized legacy rule, it captures the existing rule properties. If creation or exact-scope verification fails, it removes partial state and restores the prior matching rules. TLS pinning and HMAC remain the application authorization boundary. The program never disables Windows Firewall or changes endpoint-security settings.

## Redacted support export

Create a bounded, read-only diagnostic archive with:

```powershell
powershell.exe -NoProfile -File .\LAN_Router_Comms.ps1 -Mode SupportExport
```

The archive excludes message and file contents, pairing secrets, and raw identity material, and labels generated metadata `support-redacted`. Redaction is a safeguard, not a guarantee; review every file before sharing the archive.

## Runtime data

On first use, the program creates local configuration and state. Real settings, identities, peers, invitations, messages, files, logs, diagnostics, and exports are ignored by Git. `config/settings.example.json` contains only non-secret defaults.

Received files are authenticated and hash-verified in transit but remain ordinary files after delivery. Scan them before opening.

Individual transfers are capped at 10 GiB. The receiver also preserves the configured free-space reserve before accepting incoming data.

## Limits

This transparent PowerShell implementation has not received an independent security audit or formal protocol review. DPAPI inherits the security of the signed-in Windows account. Certificate rotation is manual, and there is no NAT traversal, cloud relay, multi-user service, or non-Windows client.

See [SECURITY.md](SECURITY.md) for operational guidance. Copyright (c) 2026 Gateway Information Group LLC; see [LICENSE.md](LICENSE.md).
