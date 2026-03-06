# Server Inventory Template

A CSV template for defining server entries consumed by `Test-IISServerReadiness.ps1`.

## Columns

| Column | Required | Default | Description |
|---|---|---|---|
| `Name` | **Yes** | — | Server hostname. Used for network connectivity, WinRM, and DNS checks. |
| `ServerIP` | No | `$null` → Skip | Direct IP address of the IIS server. Enables direct TLS handshake checks. |
| `ExpectedVIP` | No | `$null` → Skip | NetScaler VIP address. Enables VIP TLS handshake and DNS resolution checks. |
| `ExpectedVIPPort` | No | `443` | Port the VIP listens on. Non-standard ports trigger additional connectivity checks. |
| `ExpectedSAN` | No | `$null` → Skip | Expected certificate Subject Alternative Name (the public hostname). Enables DNS and certificate SAN validation. |
| `SiteName` | No | Auto-detected | IIS site name. When omitted, the script auto-detects using binding inspection. |
| `AppPoolName` | No | Auto-detected | IIS application pool name. When omitted, derived from the resolved site. |
| `WinRMPort` | No | `5985` | WinRM port for remote PowerShell checks. |

## Examples

The template includes two example rows:

1. **Minimal** (`WEB01`) — Only `Name` is provided. The script runs network, WinRM, and remote IIS checks. DNS, VIP, and certificate SAN checks produce `Skip` rows with remediation guidance. Use this when onboarding a server early in the lifecycle before VIP and DNS details are known.

2. **Fully populated** (`WEB02`) — All columns filled. The script runs the complete check suite including direct and VIP TLS handshakes, DNS resolution, certificate SAN matching, and HTTP status checks.

## Loading the CSV

The script expects `[hashtable[]]` input. Use this loader snippet to convert the CSV:

```powershell
$Servers = Import-Csv .\examples\inventory-template.csv | ForEach-Object {
    $h = @{}
    $_.PSObject.Properties | ForEach-Object {
        if ($_.Value -ne '') { $h[$_.Name] = $_.Value }
    }
    $h
}
```

This skips empty CSV cells so optional columns become absent hashtable keys, triggering the script's `Skip` logic rather than passing empty strings.

Then run the readiness script:

```powershell
.\Test-IISServerReadiness.ps1 -Servers $Servers -Verbose
```

Or with explicit credentials:

```powershell
$cred = Get-Credential
.\Test-IISServerReadiness.ps1 -Servers $Servers -Credential $cred -Verbose
```

## Tips

- **Lifecycle staging** — Start with just `Name` and add columns as infrastructure details become available. The script is designed to be run iteratively.
- **Multiple sites on one server** — Add a separate row per site with the same `Name` but different `SiteName`, `ExpectedSAN`, and binding details.
- **Non-standard ports** — Set `ExpectedVIPPort` to the VIP listener port (e.g., `8443`). The script runs additional port connectivity checks for non-443 ports.
