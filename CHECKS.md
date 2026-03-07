# Check Catalogue

Quick-reference table of every check emitted by `Test-IISServerReadiness.ps1`. Ordered by layer execution sequence.

For full background and rules see `README.md` section 4.

---

## Network layer

| Name | Statuses | Side | Condition for emission |
|---|---|---|---|
| `ICMP Ping` | Pass, Fail | Workstation | Always |
| `TNC Port 443` | Pass, Fail | Workstation | Always |
| `TNC WinRM Port {N}` | Pass, Fail | Workstation | Always (`N` = `WinRMPort`, default 5985) |
| `TNC Port {N} (Direct)` | Pass, Fail | Workstation | `ServerIP` provided AND `$resolvedPort` ≠ 443 and ≠ 80 (emitted in TLS layer after remote inspection) |
| `TNC Port {N} (VIP)` | Pass, Fail | Workstation | `ExpectedVIP` provided AND `ExpectedVIPPort` ≠ 443 (emitted in TLS layer after remote inspection) |
| `TraceRoute` | Info | Workstation | Always |

---

## DNS layer

> All DNS checks are **skipped** when `ExpectedSAN` is not provided.

| Name | Statuses | Side | Notes |
|---|---|---|---|
| `Forward Lookup (VIP match)` | Pass, Warn, Fail | Workstation | Emitted when `ExpectedVIP` is provided. Pass = exactly one record matching VIP. Warn = VIP present but additional records exist. Fail = no match or no record. |
| `Forward Lookup (no VIP assertion)` | Info, Warn | Workstation | Emitted when `ExpectedVIP` is **not** provided. No assertion — reports current resolution. Warn if multiple A records returned. |
| `Reverse PTR Match` | Pass, Warn, Skip | Workstation | Skip when `ExpectedVIP` not provided. |

---

## WinRM layer

| Name | Statuses | Side | Notes |
|---|---|---|---|
| `Test-WSMan` | Pass, Fail | Workstation | Failure causes all IIS and Certificate checks to be skipped. |
| `Invoke-Command Execution` | Pass, Fail | Workstation | Validates execution permission beyond WSMan connectivity. |

---

## IIS layer

> All IIS checks run **remotely** (inside `Invoke-Command`). They are skipped if WinRM fails.
> Checks after `WebAdministration Module` are skipped if the module is unavailable.

### Service and module

| Name | Statuses | Notes |
|---|---|---|
| `IIS Service (W3SVC) Running` | Pass, Fail | Queries `W3SVC` service state. |
| `WebAdministration Module` | Pass, Warn | Warn = module unavailable; remaining IIS checks skipped. |

### Site resolution

| Name | Statuses | Notes |
|---|---|---|
| `Site Resolution` | Pass, Warn, Fail, Info | Info when `SiteName` provided manually. Pass/Warn based on auto-detection rule (see table below). Fail if no binding matched. |

**Auto-detection ladder** (first match wins):

| Rule | Condition | Resulting status |
|---|---|---|
| 1 | Exact hostname match on any port (requires `ExpectedSAN`) | Pass |
| 2 | Port 443 catchall binding (any protocol, empty/wildcard hostname) | Warn |
| 3 | Port 80 catchall binding (SSL offload) | Warn |

SSL offload is determined by the matched binding's `protocol` field (`http` vs `https`), not the port number.

### Site and pool

| Name | Statuses | Notes |
|---|---|---|
| `Website Exists` | Pass, Fail | |
| `Website Started` | Pass, Fail | Stopped site → 503. |
| `Application Pool Exists` | Pass, Fail | |
| `Application Pool Started` | Pass, Fail | Stopped pool → 503. |

### Bindings

| Name | Statuses | Notes |
|---|---|---|
| `Site Binding` | Pass, Warn, Fail | Pass = HTTPS bindings found. Warn = HTTP only (SSL offload). Fail = no bindings. |
| `Site Binding SNI` | Pass, Warn, Skip | Checks `sslFlags` bit 0 per HTTPS binding. Warn = SNI not set. Skip = no HTTPS bindings. |

### Modules

| Name | Statuses | Notes |
|---|---|---|
| `URL Rewrite Module` | Pass, Warn | Checks IIS global modules list. |

---

## Certificate layer

> All certificate checks run **remotely** (inside `Invoke-Command`). They are skipped if WinRM fails or `Certificate Store Access` fails.

| Name | Statuses | Notes |
|---|---|---|
| `Certificate Store Access` | Pass, Fail | Opens `LocalMachine\My` and `LocalMachine\Root`. Failure skips all remaining cert checks. |
| `Leaf SAN Match` | Pass, Warn, Fail | Emitted when `ExpectedSAN` provided. Exact match → Pass. Wildcard on public TLD → Warn. No match → Fail. |
| `Leaf Cert Located` | Pass, Warn | Emitted when `ExpectedSAN` **not** provided. Fallback: selects cert with furthest expiry. |
| `Leaf Expiry (threshold: {N} days)` | Pass, Warn | `N` = `CertExpiryThresholdDays` param (default 30). |
| `Leaf Chain Valid` | Pass, Warn | Builds chain with `X509Chain` on server, revocation disabled. On failure, extracts AIA CA Issuers URL from the leaf certificate (if present) and appends it to Detail. |
| `{CA label} Present in Root Store` | Pass, Warn | One row per CA in chain. |
| `{CA label} Expiry` | Pass, Warn | One row per CA in chain, same threshold. |
| `Leaf Revocation` | Pass, Warn, Fail | Only when `-CheckRevocation` specified. Builds chain with `Online` revocation and `EntireChain` flag. 10s timeout. |
| `CRL Reachability` | Pass, Fail, Info | Only when `-CheckRevocation` specified. TCP connectivity test to each CRL Distribution Point URL host. One row per CDP URL. Info if no CDP extension. |

---

## HTTPS layer

> Direct-path checks require `ServerIP`. VIP-path checks require `ExpectedVIP`.
> Direct TLS checks are replaced by an HTTP check when SSL offload is detected.

### Direct path

| Name | Statuses | Notes |
|---|---|---|
| `SSL Offload (Direct)` | Info | Emitted instead of TLS checks when offload detected. |
| `TLS Handshake (Direct)` | Pass, Fail, Skip | Skip if `ServerIP` not provided or offload active. Uses TLS 1.2/1.3 only. |
| `TLS Version (Direct)` | Pass, Fail, Skip | TLS 1.2/1.3 = Pass. TLS 1.0/1.1 = Fail. |
| `Cert SAN (Direct)` | Pass, Warn, Fail, Skip | SAN match against `ExpectedSAN`. |
| `Cert Expiry (Direct)` | Pass, Warn, Skip | `CertExpiryThresholdDays` threshold. |
| `Cert Chain (Direct)` | Pass, Warn, Skip | Chain built from workstation trust store. On failure, extracts AIA CA Issuers URL (if present) and appends to Detail. |
| `Cert Revocation (Direct)` | Pass, Warn, Fail | Only when `-CheckRevocation` specified. Builds chain with `Online` revocation and `EntireChain` flag. 10s timeout. |
| `CRL Reachability (Direct)` | Pass, Fail, Info | Only when `-CheckRevocation` specified. TCP connectivity test to each CRL Distribution Point URL host. One row per CDP URL. Info if no CDP extension. |

### VIP path

| Name | Statuses | Notes |
|---|---|---|
| `TLS Handshake (VIP)` | Pass, Fail, Skip | Skip if `ExpectedVIP` not provided. |
| `TLS Version (VIP)` | Pass, Fail, Skip | Same TLS 1.2/1.3 rule. |
| `Cert SAN (VIP)` | Pass, Warn, Fail, Skip | SAN match against `ExpectedSAN`. |
| `Cert Expiry (VIP)` | Pass, Warn, Skip | |
| `Cert Chain (VIP)` | Pass, Warn, Skip | Same AIA extraction as Direct. |
| `Cert Revocation (VIP)` | Pass, Warn, Fail | Only when `-CheckRevocation` specified. Same revocation logic as Direct. |
| `CRL Reachability (VIP)` | Pass, Fail, Info | Only when `-CheckRevocation` specified. TCP connectivity test per CDP URL. |

### Cross-path comparison

| Name | Statuses | Notes |
|---|---|---|
| `Cert Thumbprint IIS vs VIP` | Pass, Warn, Skip | Compares SHA-1 thumbprint from IIS store (Certificate layer) against VIP-presented cert. Warn = mismatch (different certs on NetScaler vs IIS). |

---

## HTTP layer

> Emitted only when SSL offload is detected on the Direct path.

| Name | Statuses | Notes |
|---|---|---|
| `HTTP Status Code (Direct)` | Pass, Warn, Fail, Skip | GET to `http://ServerIP` with `Host: ExpectedSAN`. 2xx/4xx/401 = Pass. 5xx = Warn. No response = Fail. |

---

## VIP HTTP status

> Emitted as part of the HTTPS layer VIP path (within `Invoke-TLSCheck`). This is not a separate HTTP-layer check — it runs after the VIP TLS handshake as an HTTP status probe over the established HTTPS connection.

| Name | Statuses | Notes |
|---|---|---|
| `HTTP Status Code (VIP)` | Pass, Warn, Fail, Skip | GET to `https://ExpectedVIP:{ExpectedVIPPort}` with `Host: ExpectedSAN`. Same 2xx/4xx/5xx rules. Layer = `HTTPS`. |

---

## Total check count

| Layer | Min rows | Max rows | Variable factors |
|---|---|---|---|
| Network | 3 | 5 | +1 if non-standard Direct port, +1 if non-standard VIP port |
| DNS | 0 | 3 | 0 if `ExpectedSAN` absent |
| WinRM | 2 | 2 | |
| IIS | 2 | 11 | Varies with WebAdministration availability and binding count |
| Certificate | 1 | ~8+N | Varies with chain depth. +1 revocation +N CRL rows when `-CheckRevocation` active |
| HTTPS | 6 | 13+2+2N | Varies with `ServerIP`/`ExpectedVIP` presence and offload state. +2 revocation +2N CRL rows when `-CheckRevocation` active |
| HTTP | 0 | 1 | Only when offload active |

Typical full run (all inputs provided, no offload, 2-CA chain): **~38 rows per server**.
