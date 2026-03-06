# Changelog

Design decisions are recorded here with rationale. For operator-facing changes see `README.md`.

---

## [Unreleased]

_Planned: `Test-PreFlight.ps1`, `Invoke-DNSCutover.ps1`, `Invoke-Rollback.ps1`, cutover runbook._

### Server inventory template

**Change:** Added `examples/inventory-template.csv` with all supported server hashtable keys and two example rows (minimal and fully populated). Companion `examples/README.md` documents each column, provides a CSV-to-hashtable loader snippet, and covers lifecycle staging and multi-site usage.

---

## 2026-03-06 — Bug fixes, robustness, code quality

### TcpClient/SslStream resource leak fix

**Change:** `Invoke-TLSCheck` now uses `try-catch-finally` with disposal in `finally`. Previously, if `AuthenticateAsClient` threw, `$tcp`, `$stream`, and `$ssl` were not disposed.

### TLS handshake timeout

**Change:** `Invoke-TLSCheck` uses `TcpClient.ConnectAsync` with a 10-second timeout and sets `SendTimeout`/`ReceiveTimeout` to 10 seconds. Previously the TLS handshake could block indefinitely.

### WebException null-access fix

**Change:** HTTP status checks now verify `$we.Response` is not null before accessing `.StatusCode`. Previously, accessing `$we.Response.StatusCode` when `$we.Response` was null caused a null-reference error.

### Remote SourceIP

**Change:** The remote scriptblock now resolves the server's own IPv4 address and returns it as `RemoteSourceIP`. The main loop stamps this on deserialized remote check rows instead of `$null`. This reflects that IIS and Certificate checks execute on the server, not the workstation.

### IIS thumbprint returned explicitly

**Change:** The remote scriptblock returns `IISThumbprint` directly in the return hashtable rather than requiring the main loop to parse it from `Detail` strings using regex. Eliminates stale `$Matches` capture risk.

### rCheck status validation

**Change:** The remote `rCheck` function now validates the `Status` parameter against the valid set (`Pass`, `Warn`, `Fail`, `Info`, `Skip`), matching the workstation-side `New-Check` `ValidateSet` behaviour.

### HTTP request code deduplication

**Change:** Extracted `Invoke-HttpStatusCheck` helper function that handles `HttpWebRequest` creation, `WebException` handling, and status code resolution. Replaces near-identical code in `Invoke-TLSCheck` and the SSL offload direct-path HTTP check.

### UTF-8 BOM added

**Change:** Added UTF-8 BOM to `Test-IISServerReadiness.ps1`. PowerShell 5.1 defaults to the system codepage when no BOM is present, corrupting em-dash characters in strings and causing parse errors.

### Remedy text convention

**Change:** Mid-sentence periods in remedy strings replaced with em-dashes to comply with the convention that remedy text ends without a period.

---

## 2026-03-06 — Non-standard port support, ExpectedVIPPort, SNI binding checks

### Non-standard port support

**Change:** IIS binding inspection now returns `$resolvedPort` and `$resolvedProtocol` from the remote scriptblock. The auto-detection ladder evaluates the binding's `protocol` field (`http`/`https`) rather than comparing port numbers. Non-standard ports trigger an additional TNC check after remote results are available.

**Rationale:** Several onboarding candidates have IIS bindings on ports other than 80/443 for internal routing reasons. The previous port-number comparison (`$port -eq 443`) was insufficient — a port 8443 HTTPS binding was indistinguishable from a non-standard port at the workstation side before remote inspection ran.

### ExpectedVIPPort

**Change:** New optional server hashtable key. Defaults to `443`. Extracted with `ContainsKey` guard and cast to `[int]`. Enables VIP TNC and TLS checks on non-standard NetScaler virtual server ports.

**Rationale:** NetScaler virtual servers are not constrained to port 443. Without this key, the VIP TLS checks hardcoded port 443 and would fail silently for non-standard VIPs.

### Site Binding SNI check

**Change:** New `Site Binding SNI` check emitted per HTTPS binding. Reads the `sslFlags` bitmask; bit 0 = SNI. Missing SNI (`sslFlags & 1 == 0`) produces `Warn` with IIS Manager path and `Set-WebBinding` remedy. No HTTPS bindings → `Skip`.

**Rationale:** SNI is mandatory on multi-site IIS servers. Without it, IIS presents the first certificate bound to the IP for all hostnames, causing certificate mismatch errors on every site after the first. This is a common omission that is invisible until a second site is added.

---

## 2026-03-06 — TLS protocol fix (AuthenticateAsClient overload)

**Change:** `SslStream.AuthenticateAsClient` changed from the single-argument overload to the four-argument overload:
```powershell
$tlsFlags = [System.Security.Authentication.SslProtocols]::Tls12 -bor
            [System.Security.Authentication.SslProtocols]::Tls13
$ssl.AuthenticateAsClient($SniHostname, $null, $tlsFlags, $false)
```

**Rationale:** The single-argument overload defers protocol selection to the OS SCHANNEL configuration. On hardened hosts this can produce inconsistent results or negotiate deprecated versions (TLS 1.0/1.1) without the script being aware. Explicitly requesting TLS 1.2/1.3 means the script's own `TLS Version` check accurately reflects the version that a hardened client would negotiate, not whatever the OS happens to allow.

**Side effect (intentional):** Servers that only support TLS 1.0 or 1.1 now actively fail the handshake rather than negotiating down. The `TLS Version` check catch block includes a version-mismatch remedy directing the operator to disable legacy TLS on the server.

---

## 2026-03-06 — SourceIP / DestinationIP schema columns

**Change:** Two new columns added to every output row.

- `SourceIP`: workstation's first non-loopback IPv4, resolved once per server via `[System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName())`. Falls back to `'unknown'` on error. Repeated on every row for that server.
- `DestinationIP`: the actual IP contacted for this check. `ServerIP` for Direct checks, `ExpectedVIP` for VIP checks, resolved DNS IP for DNS checks. `$null` for IIS/Certificate/WinRM meta checks where the connection was made by WinRM, not the workstation directly.

**Rationale:** Previously IPs appeared only in `Detail` strings, making them inaccessible to `Where-Object`, `Group-Object`, or CSV pivot operations without string parsing. Discrete columns allow: grouping by `SourceIP` to confirm all runs came from the same jump host; filtering by `DestinationIP` to isolate all checks against a specific VIP; pivot-table analysis in Excel without splitting columns.

**Design decision — $null for remote checks:** WinRM checks, IIS checks, and Certificate checks execute inside the `Invoke-Command` session. The workstation makes one TCP connection (to WinRM port) that carries all of them. Attributing a single `DestinationIP` to each individual IIS sub-check would be misleading — the IP contacted was the WinRM port, not a web port. `$null` is explicit and filterable.

---

## Initial build — core architecture decisions

### PS 5.1 as minimum target

**Decision:** All syntax constrained to PowerShell 5.1. No ternary operators, no null-coalescing, no `[SemanticVersion]`.

**Rationale:** The target environment includes Windows Server 2016 and 2019 hosts where PS 7.x has not been deployed. Operator workstations are domain-joined Windows machines, not guaranteed to have PS 7. PS 5.1 is the lowest common denominator across all environments.

### Flat PSCustomObject output

**Decision:** One row per check. No nested hashtables or arrays as column values. Remedy text is appended to `Detail` with a ` | Remedy: ` separator rather than a separate column.

**Rationale:** The primary consumer is `Export-Csv`. Nested objects serialize poorly to CSV. A separate `Remedy` column would be empty on most rows (Pass/Info/Skip), creating visual noise in spreadsheet review. Appending to `Detail` keeps the output clean for the common case while preserving the remedy text for the cases that need it.

### New-Check vs rCheck

**Decision:** Two separate check constructors — `New-Check` (workstation scope, returns `PSCustomObject`) and `rCheck` (remote scriptblock scope, returns a hashtable added to a local `$checks` array).

**Rationale:** Remote scriptblocks run in a separate session scope and cannot call workstation-scope functions. `PSCustomObject` instances created remotely are deserialized on return and lose their type fidelity. Returning plain hashtables from the remote scriptblock and reconstructing rows on the workstation side with `New-Check` ensures consistent object structure and allows `ServerName`, `CheckedAt`, `SourceIP`, and `DestinationIP` to be stamped once at the workstation, not duplicated in every remote check.

### Single Invoke-Command per server

**Decision:** All remote checks (IIS + Certificate) run in a single `Invoke-Command` session rather than separate calls per check.

**Rationale:** Multiple `Invoke-Command` calls per server would multiply authentication round-trips and introduce latency proportional to server count. The remote scriptblock is self-contained — it runs all checks, collects results into `$checks`, and returns the array in a single hashtable alongside metadata (`SslOffload`, `ResolvedPort`, `ResolvedProtocol`, `IISThumbprint`, `RemoteSourceIP`).

### SSL offload detection by protocol, not port

**Decision:** Offload is determined by `$binding.protocol` (`http` vs `https`), not by comparing the port number to 80 or 443.

**Rationale:** Non-standard ports make port-based detection unreliable. A binding on port 8080 with `protocol=http` is offloaded; a binding on port 8443 with `protocol=https` is not. The IIS configuration surface already expresses this distinction correctly — reading it directly is more reliable than inferring it from port numbers.
