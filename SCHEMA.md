# Output Schema Reference

## Row structure

Every row emitted by `Test-IISServerReadiness.ps1` is a `PSCustomObject` with the following columns in order:

```
ServerName | CheckedAt | SourceIP | DestinationIP | Layer | Name | Status | Detail
```

---

## Columns

### ServerName
`String` — The `Name` key from the server hashtable. Stamped on every row by the main loop after checks return, not inside the check functions.

### CheckedAt
`String` — UTC timestamp in ISO 8601 round-trip format (`Get-Date -Format 'o'`). Resolved once at the start of each server's iteration. All rows for the same server run share this value.

### SourceIP
`String` — The IP of the machine that ran the check.

- **Workstation-side checks** (Network, DNS, WinRM, HTTPS, HTTP): The first non-loopback IPv4 address of the workstation, resolved once per server via `GetHostAddresses`. Falls back to `'unknown'` on error.
- **Remote checks** (IIS, Certificate): The first non-loopback IPv4 address of the target server itself, resolved inside the `Invoke-Command` session. This reflects that these checks execute on the server, not the workstation.

### DestinationIP
`String | $null` — The actual IP address contacted for this check.

| Check category | Value |
|---|---|
| Direct-path TLS/HTTP checks | `ServerIP` as supplied in server hashtable |
| VIP-path TLS checks | `ExpectedVIP` as supplied |
| DNS forward lookup | The resolved IP(s) from `GetHostAddresses` |
| DNS PTR check | `ExpectedVIP` |
| TNC checks | The IP the OS connected to (`$tnc.RemoteAddress.ToString()`) |
| WinRM meta checks | `ServerName` (hostname, not IP) |
| IIS checks (remote) | `$null` |
| Certificate checks (remote) | `$null` |

`$null` for IIS and Certificate checks is intentional — these run inside the `Invoke-Command` session. A single WinRM TCP connection carries all of them; attributing a web-layer IP to each individual IIS sub-check would be misleading. Note that `SourceIP` for these rows reflects the server's own IP (where the check ran), not the workstation's IP.

### Layer
`String` — The logical layer. Valid values:

| Value | Description |
|---|---|
| `Network` | TCP reachability and ICMP from workstation |
| `DNS` | Forward and reverse DNS resolution |
| `WinRM` | Remote PowerShell connectivity |
| `IIS` | Server-side IIS service, site, pool, binding checks |
| `Certificate` | Server-side certificate store inspection |
| `HTTPS` | TLS handshake, certificate, and HTTP checks over HTTPS |
| `HTTP` | HTTP-only checks (SSL offload path) |

### Name
`String` — Check identifier. Unique within a layer. Checks that run against both Direct and VIP paths carry a `(Direct)` or `(VIP)` suffix. Non-standard port TNC checks carry the port number in the name: `TNC Port 8443 (Direct)`.

### Status
`String` — One of five values. See [Status semantics](#status-semantics) below.

### Detail
`String` — Human-readable result detail. When a remedy is available it is appended with the separator:
```
 | Remedy: <remedy text>
```
Splitting on ` | Remedy: ` (note leading space) reliably separates result from remedy. The remedy is always the last segment.

---

## Status semantics

| Status | Meaning | Action required |
|---|---|---|
| `Pass` | Condition evaluated and met. | None. |
| `Warn` | Condition evaluated; result is suboptimal but not necessarily blocking. | Investigate before cutover. |
| `Fail` | Condition evaluated and not met. | Must be resolved. Remedy is in `Detail`. |
| `Info` | No assertion made. Contextual data (e.g. traceroute path, auto-detection method). | None — review for situational awareness. |
| `Skip` | Check not run due to missing prerequisite or input. | See `Detail` for what is needed to enable the check. |

### Skip semantics

`Skip` does not mean the check passed — it means the check was not evaluated. A server with all `Skip` rows for HTTPS checks but no `ServerIP` or `ExpectedVIP` is **not validated**. The operator must supply the missing inputs and re-run.

Common skip causes:

| Missing input | Checks skipped |
|---|---|
| `ServerIP` not provided | All `(Direct)` HTTPS/HTTP checks; non-standard port TNC (Direct) |
| `ExpectedVIP` not provided | All `(VIP)` HTTPS checks; `Cert Thumbprint IIS vs VIP`; `Reverse PTR Match` |
| `ExpectedSAN` not provided | All DNS checks; Certificate SAN match falls back to longest-lived cert |
| WinRM unreachable | All IIS and Certificate checks |
| `WebAdministration` unavailable | All IIS sub-checks after `WebAdministration Module` |
| SSL offload detected | Direct `TLS Handshake`, `TLS Version`, `Cert SAN`, `Cert Expiry`, `Cert Chain` |

---

## Filtering and grouping examples

```powershell
# Failures and warnings only
$results | Where-Object { $_.Status -in 'Fail','Warn' }

# All checks for a specific server
$results | Where-Object { $_.ServerName -eq 'WEBSVR01' }

# All checks that contacted the VIP
$results | Where-Object { $_.DestinationIP -eq '10.20.1.100' }

# Summary by server and status
$results | Group-Object ServerName,Status | Select-Object Name,Count

# Export to CSV
$results | Export-Csv -Path results.csv -NoTypeInformation

# Skipped checks only, grouped by server to show what is not yet validated
$results | Where-Object { $_.Status -eq 'Skip' } | Group-Object ServerName
```

---

## CSV column order

`Export-Csv` respects the property order of the first object. The script constructs rows in this order:
```
ServerName, CheckedAt, SourceIP, DestinationIP, Layer, Name, Status, Detail
```
This is stable across all check types including deserialized remote rows.
