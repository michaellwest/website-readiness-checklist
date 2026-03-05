# IIS NetScaler Onboarding — Project Context

## Purpose

This project contains tooling to validate and execute the onboarding of on-premises IIS servers behind a Citrix NetScaler load balancer. Nothing is being migrated or replaced — this is greenfield VIP creation with existing IIS servers being brought under NetScaler management for the first time.

The primary deliverable is `Test-IISServerReadiness.ps1`. Supporting scripts for DNS cutover, rollback, and pre-flight checks are planned. A runbook/cutover checklist document is also in scope.

---

## Repository Layout

```
/
├── CLAUDE.md                          ← you are here
├── CHANGELOG.md                       ← design decisions and change history
├── CHECKS.md                          ← machine-readable check catalogue
├── SCHEMA.md                          ← output schema reference
├── TODO.md                            ← known gaps and planned work
├── Test-IISServerReadiness.ps1        ← primary readiness validation script
├── README.md                          ← operator guide (human-facing)
└── (planned)
    ├── Invoke-DNSCutover.ps1
    ├── Invoke-Rollback.ps1
    ├── Test-PreFlight.ps1
    └── runbook/
        └── Cutover-Runbook.md
```

> **Source of truth:** The `.ps1` script is authoritative. `README.md` and `CHECKS.md` document what the script does. If they diverge, update the docs to match the script — not the other way around.

---

## Test-IISServerReadiness.ps1 — Architecture

### What it does

Runs from the operator's workstation. For each server in `$Servers`:

1. Workstation-side checks (Network, DNS, WinRM) run directly.
2. A single `Invoke-Command` session dispatches the remote scriptblock which runs IIS and Certificate checks on the server, returns a hashtable array.
3. The returned rows are deserialized and merged with workstation-side rows.
4. HTTPS/HTTP checks run from the workstation after remote checks complete (so SSL offload detection, resolved port, and IIS thumbprint are all available).

### Hard constraints

| Constraint | Detail |
|---|---|
| **PowerShell 5.1** | No ternary operators (`? :`), no null-coalescing (`??`), no `[System.Management.Automation.SemanticVersion]`. Use `if/else` assignments throughout. |
| **Flat output** | One `PSCustomObject` row per check per server. No nested objects, no arrays as column values. |
| **Remedy in Detail** | Remediation text is appended to `Detail` using the separator ` \| Remedy: `. There is no separate `Remedy` column in the output object. |
| **No external modules** | Workstation-side only uses built-in cmdlets. Remote side requires `WebAdministration` (standard IIS feature) but handles its absence gracefully. |
| **Mixed auth** | Kerberos by default; optional `-Credential` parameter for PSCredential fallback. |

### Output schema

```
ServerName | CheckedAt | SourceIP | DestinationIP | Layer | Name | Status | Detail
```

Full column definitions: see `SCHEMA.md`.

### Check functions

| Function | Side | Layers produced |
|---|---|---|
| `Test-NetworkLayer` | Workstation | Network |
| `Test-DNSLayer` | Workstation | DNS |
| `Test-WinRMLayer` | Workstation | WinRM |
| Remote scriptblock (anonymous) | Server | IIS, Certificate |
| `Test-TLSLayer` | Workstation | Network (non-standard port TNC), HTTPS, HTTP |
| `Invoke-TLSCheck` | Workstation | (helper called by Test-TLSLayer) |
| `Invoke-HttpStatusCheck` | Workstation | (helper for HTTP status checks, used by Invoke-TLSCheck and SSL offload path) |

### Key design decisions

**`New-Check` vs `rCheck`**
Two check constructors exist because remote code cannot call the workstation-scope `New-Check` function. The remote scriptblock defines its own `rCheck` helper that builds identical hashtables (not `PSCustomObject`). On return, the main loop deserializes them and re-stamps `ServerName`, `CheckedAt`, `SourceIP`, and `DestinationIP`.

**SourceIP / DestinationIP**
- `SourceIP`: for workstation-side checks, the workstation's first non-loopback IPv4. For remote checks (IIS, Certificate), the server's own IPv4 resolved inside `Invoke-Command`. Both fall back to `'unknown'` on error.
- `DestinationIP`: the actual IP contacted — `ServerIP` for Direct checks, `ExpectedVIP` for VIP checks, the resolved DNS IP for DNS checks. `$null` for remote/IIS/Certificate checks (WinRM makes those connections, not the workstation directly).

**SSL offload detection**
Determined by the `protocol` field of the winning IIS binding (`http` vs `https`), not the port number. A binding on port 8080 with `protocol=http` is offloaded; one on port 8443 with `protocol=https` is not. When offload is detected, Direct TLS checks are skipped and an HTTP Status Code check runs instead.

**Site auto-detection ladder**
When `SiteName` is not provided, bindings are evaluated against three rules (highest to lowest confidence). First match wins. See `CHECKS.md` → Site Resolution for the full table.

**TLS protocol negotiation**
`AuthenticateAsClient` uses the four-argument overload with explicit `Tls12 -bor Tls13` flags. The single-argument overload defers to OS SCHANNEL and may negotiate deprecated versions. Side effect: servers that only support TLS 1.0/1.1 will actively fail the handshake rather than negotiate down — this is intentional.

**Non-standard port support**
`$resolvedPort` and `$resolvedProtocol` are returned from the remote scriptblock after binding inspection. `ExpectedVIPPort` defaults to `443`. Non-standard ports trigger additional TNC checks after remote results are available.

**Lifecycle skip logic**
The script is designed to be run iteratively across the onboarding lifecycle, not just at cutover. Missing inputs (`ServerIP`, `ExpectedVIP`, `ExpectedSAN`) produce `Skip` rows with remediation text rather than `Fail` rows. See `SCHEMA.md` → Skip semantics.

---

## Planned Scripts

### `Test-PreFlight.ps1`
Pre-requisite checks before the readiness script is run. Intended scope: WinRM TrustedHosts configuration, DNS server reachability, operator privilege verification.

### `Invoke-DNSCutover.ps1`
Automates the DNS A record change from the server IP to the NetScaler VIP. Should support `-WhatIf`, log before/after state, and output a record suitable for the change log.

### `Invoke-Rollback.ps1`
Reverts the DNS change. Takes the pre-cutover state captured by `Invoke-DNSCutover.ps1` as input.

---

## Conventions

- **Parameter names** match the server hashtable keys where possible (`ExpectedVIP`, `ExpectedSAN`, `ServerIP`).
- **Status values**: `Pass`, `Warn`, `Fail`, `Info`, `Skip` — no other values are valid.
- **Layer names**: `Network`, `DNS`, `WinRM`, `IIS`, `Certificate`, `HTTPS`, `HTTP` — capitalised, no spaces.
- **Check names** use title case with parenthetical suffixes for path variants: `TLS Handshake (Direct)`, `TLS Handshake (VIP)`.
- **Remedy text** is imperative, present tense, and ends without a period: `Enable SNI on this binding...`
- **PS 5.1 if/else pattern** for conditional assignment:
  ```powershell
  $value = if ($condition) { 'a' } else { 'b' }
  ```
  Never: `$value = $condition ? 'a' : 'b'`

---

## Working with this project

When asked to modify `Test-IISServerReadiness.ps1`:

1. Read the relevant function(s) before writing any changes.
2. Verify brace balance after edits — the script uses `#region`/`#endregion` markers to delineate sections.
3. Remote scriptblock changes must use `rCheck`, not `New-Check`.
4. Any new check must follow the existing pattern: `Layer`, `Name`, `Status`, `Detail`, optional `Remedy`, optional `SourceIP`/`DestinationIP`.
5. Update `CHECKS.md` and `CHANGELOG.md` after any structural change.
6. Do not add module dependencies without explicit approval.
