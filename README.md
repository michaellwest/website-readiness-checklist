# IIS NetScaler Onboarding Readiness Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)

A PowerShell toolkit for validating IIS server readiness before onboarding behind a Citrix NetScaler load balancer. Runs from an operator workstation — no agents or modules to install on target servers.

`Test-IISServerReadiness.ps1` performs 30–40 checks per server across seven layers (Network, DNS, WinRM, IIS, Certificate, HTTPS, HTTP), producing a flat CSV-exportable result set with actionable remediation guidance for every failure.

---

## Table of Contents

- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Server Inventory](#server-inventory)
- [Parameters](#parameters)
- [Check Layers](#check-layers)
- [Output](#output)
- [Interpreting Results](#interpreting-results)
- [Lifecycle Usage](#lifecycle-usage)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| **PowerShell** | 5.1+ | Ships with Windows 10 / Server 2016+. PS 7 is compatible but not required. |
| **Workstation OS** | Windows 10 / Server 2016+ | Uses `Test-NetConnection`, `Test-WSMan`, and .NET TLS APIs. |
| **Target servers** | IIS installed, WinRM enabled | `WebAdministration` module required for IIS config checks (standard IIS feature). |
| **Network** | WinRM port open (default 5985) | Kerberos auth by default; `-Credential` for explicit credentials. |

No external modules are required on the workstation. Target servers need only the standard `WebAdministration` module that ships with the IIS Management Scripts and Tools feature.

---

## Quick Start

### 1. Define your servers

```powershell
$servers = @(
    @{
        Name        = 'web01.corp.local'
        ServerIP    = '10.10.2.11'
        ExpectedVIP = '10.10.1.50'
        ExpectedSAN = 'www.contoso.com'
        SiteName    = 'ContosoWeb'
        AppPoolName = 'ContosoAppPool'
    },
    @{
        Name        = 'web02.corp.local'
        ServerIP    = '10.10.2.12'
        ExpectedVIP = '10.10.1.50'
        ExpectedSAN = 'www.contoso.com'
    }
)
```

### 2. Run the script

```powershell
$results = .\Test-IISServerReadiness.ps1 -Servers $servers -Verbose
```

### 3. Review results

```powershell
# All failures and warnings
$results | Where-Object { $_.Status -in 'Fail','Warn' } | Format-Table -AutoSize

# Export to CSV for spreadsheet review
$results | Export-Csv -Path results.csv -NoTypeInformation
```

### With readiness summary

```powershell
# Summary prints to console; pipeline output is preserved for export
.\Test-IISServerReadiness.ps1 -Servers $servers -Summary | Export-Csv results.csv -NoTypeInformation
```

### With explicit credentials

```powershell
$cred = Get-Credential
$results = .\Test-IISServerReadiness.ps1 -Servers $servers -Credential $cred
```

---

## Server Inventory

Each server is a hashtable with the following keys:

| Key | Required | Default | Description |
|---|---|---|---|
| `Name` | **Yes** | — | Server hostname (FQDN). Used for network connectivity, WinRM, and DNS. |
| `ServerIP` | No | `$null` → Skip | Direct IP of the IIS server. Enables direct TLS/HTTP checks that bypass the load balancer. |
| `ExpectedVIP` | No | `$null` → Skip | NetScaler VIP address. Enables VIP TLS checks and DNS resolution validation. |
| `ExpectedVIPPort` | No | `443` | Port the VIP listens on. Non-standard ports trigger additional connectivity checks. |
| `ExpectedSAN` | No | `$null` → Skip | Expected certificate SAN (the public hostname). Enables DNS and certificate SAN validation. |
| `SiteName` | No | Auto-detected | IIS site name. When omitted, the script auto-detects using binding inspection. |
| `AppPoolName` | No | Auto-detected | IIS application pool name. Derived from the resolved site when omitted. |
| `WinRMPort` | No | `5985` | WinRM port for remote PowerShell checks. |

### CSV inventory

A CSV template is provided in [`examples/inventory-template.csv`](examples/inventory-template.csv). Load it with:

```powershell
$servers = Import-Csv .\examples\inventory-template.csv | ForEach-Object {
    $h = @{}
    $_.PSObject.Properties | ForEach-Object {
        if ($_.Value -ne '') { $h[$_.Name] = $_.Value }
    }
    $h
}

.\Test-IISServerReadiness.ps1 -Servers $servers -Verbose
```

Empty CSV cells become absent hashtable keys, triggering the script's `Skip` logic rather than passing empty strings. See [`examples/README.md`](examples/README.md) for column details.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Servers` | `hashtable[]` | *(required)* | Array of server hashtables. See [Server Inventory](#server-inventory). |
| `-Credential` | `PSCredential` | Kerberos | Explicit credentials for WinRM and `Invoke-Command`. |
| `-CertExpiryThresholdDays` | `int` | `30` | Days before certificate expiry that triggers a `Warn` status. |
| `-CheckRevocation` | `switch` | Off | Enables certificate revocation checking via CRL/OCSP. Adds `Leaf Revocation`, `Cert Revocation (Direct/VIP)`, and `CRL Reachability` checks. Makes outbound HTTP/LDAP calls to CRL distribution point endpoints — may timeout on firewalled networks. |
| `-Summary` | `switch` | Off | Prints a human-readable readiness summary to the console after all checks complete. Uses `Write-Host` so pipeline output is not affected. |

---

## Check Layers

The script executes checks in a fixed order. Each layer builds on the previous — a WinRM failure skips all IIS and Certificate checks.

| Layer | Runs on | What it validates |
|---|---|---|
| **Network** | Workstation | ICMP ping, TCP port 443, WinRM port, traceroute. Non-standard ports checked after IIS binding inspection. |
| **DNS** | Workstation | Forward lookup (A record → VIP match), reverse PTR. Requires `ExpectedSAN`. |
| **WinRM** | Workstation | `Test-WSMan` connectivity and `Invoke-Command` execution permission. |
| **IIS** | Target server | W3SVC service state, `WebAdministration` module, site resolution, site/pool state, bindings, SNI, URL Rewrite module. |
| **Certificate** | Target server | Certificate store access, leaf SAN match, expiry, chain validity, root CA presence and expiry. |
| **HTTPS** | Workstation | TLS handshake (TLS 1.2/1.3 only), protocol version, certificate SAN/expiry/chain — tested against both the direct server IP and the VIP. Cross-path thumbprint comparison (IIS vs VIP). |
| **HTTP** | Workstation | HTTP status code check. Only emitted when SSL offload is detected on the direct path. |

For the full check catalogue with statuses and emission conditions, see [`CHECKS.md`](CHECKS.md).

### Site auto-detection

When `SiteName` is not provided, the script inspects all IIS bindings and selects the best match using a priority ladder:

| Priority | Condition | Status |
|---|---|---|
| 1 | Exact hostname match on any port (requires `ExpectedSAN`) | Pass |
| 2 | Port 443 catchall binding (empty/wildcard hostname) | Warn |
| 3 | Port 80 catchall binding (SSL offload) | Warn |

### SSL offload detection

SSL offload is determined by the matched IIS binding's `protocol` field (`http` vs `https`), not the port number. When offload is detected, direct-path TLS checks are skipped and an HTTP status code check runs instead.

---

## Output

Every check produces a single flat row:

```
ServerName | CheckedAt | SourceIP | DestinationIP | Layer | Name | Status | Detail
```

| Column | Description |
|---|---|
| `ServerName` | Server hostname from the `Name` key. |
| `CheckedAt` | UTC timestamp (ISO 8601). Shared across all rows for the same server. |
| `SourceIP` | IP of the machine that ran the check — workstation for local checks, server for remote checks. |
| `DestinationIP` | IP contacted for this check. `$null` for remote IIS/Certificate checks (carried over WinRM). |
| `Layer` | Logical layer: `Network`, `DNS`, `WinRM`, `IIS`, `Certificate`, `HTTPS`, `HTTP`. |
| `Name` | Check identifier. Direct/VIP variants carry `(Direct)` or `(VIP)` suffixes. |
| `Status` | `Pass`, `Warn`, `Fail`, `Info`, or `Skip`. |
| `Detail` | Result detail. Remediation text (when present) is appended after ` \| Remedy: `. |

For the full column specification, see [`SCHEMA.md`](SCHEMA.md).

### Export and filtering

```powershell
# Failures only
$results | Where-Object Status -eq 'Fail'

# All checks for one server
$results | Where-Object ServerName -eq 'web01.corp.local'

# Summary by server and status
$results | Group-Object ServerName, Status | Select-Object Name, Count

# Checks that contacted the VIP
$results | Where-Object DestinationIP -eq '10.10.1.50'

# Skipped checks — shows what is not yet validated
$results | Where-Object Status -eq 'Skip' | Group-Object ServerName

# Export to CSV
$results | Export-Csv -Path results.csv -NoTypeInformation
```

---

## Interpreting Results

| Status | Meaning | Action |
|---|---|---|
| **Pass** | Check evaluated and met. | None. |
| **Warn** | Suboptimal but not necessarily blocking. | Investigate before cutover. |
| **Fail** | Check evaluated and not met. Remedy is in `Detail`. | Must be resolved. |
| **Info** | No assertion made — contextual data (traceroute, auto-detection method). | Review for awareness. |
| **Skip** | Check not run due to missing input or prerequisite. | Supply the missing input and re-run. |

### Skip does not mean Pass

A server with all `Skip` rows for HTTPS checks is **not validated** — it means the required inputs (`ServerIP`, `ExpectedVIP`) were not provided. The operator must supply them and re-run.

| Missing input | Checks skipped |
|---|---|
| `ServerIP` | All `(Direct)` HTTPS/HTTP checks |
| `ExpectedVIP` | All `(VIP)` HTTPS checks, `Cert Thumbprint IIS vs VIP`, `Reverse PTR Match` |
| `ExpectedSAN` | All DNS checks; certificate SAN match falls back to longest-lived cert |
| WinRM unreachable | All IIS and Certificate checks |

### Extracting remediation text

Remedy text is appended to the `Detail` column after ` | Remedy: `. To split:

```powershell
$results | Where-Object Status -eq 'Fail' | ForEach-Object {
    $parts = $_.Detail -split ' \| Remedy: ', 2
    [PSCustomObject]@{
        Server  = $_.ServerName
        Check   = $_.Name
        Result  = $parts[0]
        Remedy  = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    }
} | Format-Table -Wrap
```

---

## Lifecycle Usage

The script is designed for iterative use across the onboarding lifecycle. Start with minimal inputs early and add details as infrastructure is provisioned:

### Phase 1 — Server provisioned, no VIP yet

```powershell
@{ Name = 'web01.corp.local' }
```

Validates: network connectivity, WinRM, IIS configuration, certificates.
Skips: DNS, VIP TLS checks, direct TLS checks.

### Phase 2 — Server IP and VIP assigned

```powershell
@{
    Name        = 'web01.corp.local'
    ServerIP    = '10.10.2.11'
    ExpectedVIP = '10.10.1.50'
}
```

Adds: direct and VIP TLS handshakes, certificate inspection, thumbprint comparison.

### Phase 3 — DNS hostname known, ready for cutover

```powershell
@{
    Name        = 'web01.corp.local'
    ServerIP    = '10.10.2.11'
    ExpectedVIP = '10.10.1.50'
    ExpectedSAN = 'www.contoso.com'
}
```

Adds: DNS forward/reverse checks, certificate SAN assertion, SNI validation.

### Multiple sites on one server

Add a separate hashtable entry per site with the same `Name` but different `SiteName`, `ExpectedSAN`, and binding details.

---

## Troubleshooting

### WinRM connection failures

All IIS and Certificate checks require WinRM. If `Test-WSMan` fails:

1. Verify the WinRM service is running on the target: `winrm quickconfig`
2. Check that the workstation can reach the WinRM port (default 5985): `Test-NetConnection -ComputerName <server> -Port 5985`
3. Verify Kerberos trust or add the server to TrustedHosts: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<server>'`
4. If using explicit credentials, pass `-Credential (Get-Credential)` to the script

### TLS handshake failures

The script enforces TLS 1.2 and 1.3 only. Servers offering only TLS 1.0 or 1.1 will fail the handshake intentionally. Check the `Detail` column for the specific error and remedy.

### WebAdministration module unavailable

IIS configuration checks require the `WebAdministration` module on the target server. Install via:

```
Add Roles and Features > Web Server > Management Tools > IIS Management Scripts and Tools
```

### Non-standard ports

For IIS bindings on non-standard ports or NetScaler VIPs not on 443, set `ExpectedVIPPort` in the server hashtable. The script runs additional port connectivity checks automatically.

---

## Project Structure

```
├── Test-IISServerReadiness.ps1    Primary readiness validation script
├── README.md                      This file — operator guide
├── CHECKS.md                      Full check catalogue with statuses and conditions
├── SCHEMA.md                      Output column definitions and filtering examples
├── CHANGELOG.md                   Design decisions and change history
├── TODO.md                        Known gaps and planned work
└── examples/
    ├── inventory-template.csv     CSV template with all server hashtable keys
    └── README.md                  CSV column docs and loader snippet
```

### Planned scripts

| Script | Purpose |
|---|---|
| `Test-PreFlight.ps1` | Pre-run environment checks (WinRM config, DNS reachability, operator privileges) |
| `Invoke-DNSCutover.ps1` | Automated DNS A record change with `-WhatIf` and state capture |
| `Invoke-Rollback.ps1` | Revert DNS to pre-cutover state |

---

## Contributing

1. The `.ps1` script is the source of truth. If docs diverge from the script, update the docs.
2. All code must be compatible with PowerShell 5.1 — no ternary operators (`? :`), no null-coalescing (`??`).
3. Every check must produce a flat `PSCustomObject` row with the standard column set.
4. Remedy text is appended to `Detail` with ` | Remedy: ` — no separate column.
5. Status values are restricted to `Pass`, `Warn`, `Fail`, `Info`, `Skip`.
6. Update `CHECKS.md` and `CHANGELOG.md` after any structural change.
