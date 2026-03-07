# TODO

Items inferred from development history and known gaps. Prefix legend:
- `[ ]` — not started
- `[~]` — partially addressed / needs revisit
- `[?]` — needs decision before work can begin

---

## Scripts

- [ ] **`Test-PreFlight.ps1`** — Pre-run environment checks: WinRM TrustedHosts configuration, DNS server reachability from workstation, operator local admin verification on target server.
- [ ] **`Invoke-DNSCutover.ps1`** — Automated DNS A record change (server IP → NetScaler VIP). Must support `-WhatIf`, capture pre-cutover state for rollback input, emit a structured change log row.
- [ ] **`Invoke-Rollback.ps1`** — Revert DNS to pre-cutover state. Takes the state object from `Invoke-DNSCutover.ps1` as input.

---

## Test-IISServerReadiness.ps1

- [?] **WinRM HTTPS (`-UseSSL`) support** — `WinRMPort = 5986` is honoured for TNC but `Invoke-Command` currently uses HTTP transport regardless. Needs a `-UseSSL` switch wired through, or at minimum a `Warn` when port 5986 is specified but HTTPS transport is not used.
- [?] **Multiple SAN assertion** — Currently one `ExpectedSAN` per server hashtable entry. Some servers host multiple sites. Evaluate whether `ExpectedSAN` should accept an array, or whether the operator should supply multiple hashtable entries for the same server.
- [x] **Certificate revocation check** — Implemented via `-CheckRevocation` switch. Adds `Leaf Revocation`, `Cert Revocation (Direct/VIP)`, and `CRL Reachability` checks using `Online` revocation mode with 10s timeout. Existing chain checks remain `NoCheck`.
- [ ] **AppPool identity check** — No check currently validates the application pool identity account, whether it exists, or whether it has the necessary file system permissions. Common gap on freshly provisioned servers.
- [x] **Intermediate CA download on chain failure** — AIA CA Issuers URL is now extracted from the leaf certificate and surfaced in the `Detail` field when chain validation fails. Auto-download was rejected for security reasons (SSRF risk, scope creep from read-only to state-modifying, enterprise policy conflicts).
- [x] **Output timestamp timezone annotation** — Resolved: `CheckedAt` value now uses explicit `Z` suffix (`yyyy-MM-ddTHH:mm:ssZ` format).
- [?] **Parallel server execution** — Currently servers are processed sequentially. For large inventories (20+) `ForEach-Object -Parallel` (PS 7) or runspace-based parallelism could reduce total run time significantly. **Blocked by PS 5.1 constraint** — needs a decision on whether PS 7 support is added alongside 5.1 or as a replacement.

---

## Documentation

- [ ] **Cutover runbook** (`runbook/Cutover-Runbook.md`) — Step-by-step operator checklist covering pre-cutover validation, DNS change execution, post-cutover validation, rollback criteria, and sign-off.
- [x] **Server inventory template** (`examples/inventory-template.csv`) — Starter CSV with all supported server hashtable keys, minimal and fully-populated examples, and a loader snippet in `examples/README.md`.
- [ ] **CHECKS.md row counts** — The "total check count" table at the bottom of `CHECKS.md` uses estimates. Validate against actual script output for a fully-populated server entry.

---

## Hygiene

- [ ] **Pester tests** — No unit tests exist. At minimum: `New-Check` output shape, status `ValidateSet` enforcement, remedy separator format, `SourceIP` fallback behaviour.
- [ ] **Script signing** — If deployed to environments with `AllSigned` execution policy, the script and any supporting scripts will need to be signed. Track as a deployment requirement.
