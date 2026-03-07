#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies IIS server readiness from a workstation, combining remote and local checks.

.DESCRIPTION
    Runs layered checks (network, DNS, WinRM, IIS, certificate, HTTPS) against one or more
    target servers. Workstation-side checks run locally; IIS/cert checks are dispatched via
    Invoke-Command and merged into a single result object per server.

.PARAMETER Servers
    Array of hashtables, one per target server. Supported keys:
        Name          (required) Server FQDN — must be resolvable in AD/DNS at all phases
        SiteName      (required) IIS website name
        AppPoolName   (required) IIS application pool name
        ServerIP      (optional) Direct IP of the server; enables TLS/HTTP (Direct) checks that bypass NetScaler
        ExpectedVIP   (optional) NetScaler VIP IP; enables DNS checks and TLS/HTTP (VIP) checks
        ExpectedSAN    (optional) Friendly URL hostname (the A record); enables DNS forward/PTR checks and SAN cert assertion
        WinRMPort     (optional) 5985 (default) or 5986
        ExpectedVIPPort (optional) NetScaler VIP port; defaults to 443

    Checks enabled per phase:
        Phase 1 — ServerIP only       : Network, WinRM, IIS, Certificate, TLS/HTTP (Direct)
        Phase 2 — + ExpectedVIP       : adds TLS/HTTP (VIP)
        Phase 3 — + ExpectedSAN        : adds DNS forward/PTR, SAN assertion, correct SNI on TLS checks

.PARAMETER Credential
    PSCredential used when Kerberos is unavailable or explicitly needed.

.PARAMETER CertExpiryThresholdDays
    Number of days before certificate expiry that triggers a Warn. Default: 30.

.PARAMETER CheckRevocation
    When specified, enables certificate revocation checking via CRL/OCSP. Adds Leaf Revocation,
    Cert Revocation (Direct/VIP), and CRL Reachability checks. Makes outbound HTTP/LDAP calls to
    CRL distribution point endpoints. Off by default to avoid timeouts on firewalled networks.

.EXAMPLE
    $servers = @(
        @{
            Name        = 'web01.corp.local'
            ExpectedVIP = '10.10.1.50'
            SiteName    = 'MySite'
            AppPoolName = 'MySitePool'
            ExpectedSAN  = 'web.corp.local'
            ServerIP    = '10.10.2.11'
        },
        @{
            Name        = 'web02.corp.local'
            ExpectedVIP = '10.10.1.50'
            SiteName    = 'MySite'
            AppPoolName = 'MySitePool'
            ServerIP    = '10.10.2.12'
        }
    )
    $results = Test-IISServerReadiness -Servers $servers
    # All rows across all servers
    $results | Format-Table -AutoSize
    # Failures only
    $results | Where-Object Status -eq 'Fail'
    # Per-server summary
    $results | Select-Object ServerName, Status -Unique

.EXAMPLE
    # With explicit credentials and custom expiry threshold
    $cred = Get-Credential
    Test-IISServerReadiness -Servers $servers -Credential $cred -CertExpiryThresholdDays 60
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [hashtable[]]$Servers,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [int]$CertExpiryThresholdDays = 30,

    [Parameter()]
    [switch]$CheckRevocation
)

#region --- Helpers ---

function New-Check {
    param(
        [string]$Layer,
        [string]$Name,
        [ValidateSet('Pass','Warn','Fail','Info','Skip')]
        [string]$Status,
        [string]$Detail,
        [string]$Remedy,
        [string]$SourceIP,
        [string]$DestinationIP
    )
    $fullDetail = if (-not [string]::IsNullOrWhiteSpace($Remedy)) { "$Detail | Remedy: $Remedy" } else { $Detail }
    [PSCustomObject]@{
        Layer         = $Layer
        Name          = $Name
        Status        = $Status
        Detail        = $fullDetail
        SourceIP      = $SourceIP
        DestinationIP = $DestinationIP
    }
}

function Invoke-HttpStatusCheck {
    # Shared helper for HTTP/HTTPS status code checks.
    # Emits a single New-Check row with the result.
    param(
        [string]$Url,         # Full URL to request
        [string]$HostHeader,  # Host header value
        [string]$ConnectTo,   # IP/hostname for DestinationIP and detail
        [string]$Label,       # e.g. '(Direct)' or '(VIP)'
        [string]$Layer,       # 'HTTPS' or 'HTTP'
        [string]$SourceIP
    )
    try {
        $request                   = [System.Net.HttpWebRequest]::Create($Url)
        $request.Host              = $HostHeader
        $request.Timeout           = 10000
        $request.AllowAutoRedirect = $false
        $request.ServerCertificateValidationCallback = { $true }

        $response = $request.GetResponse()
        $code     = [int]$response.StatusCode
        $response.Close()

        $httpResult = Resolve-HttpStatus -Code $code
        New-Check -Layer $Layer -Name "HTTP Status Code $Label" `
            -Status $httpResult.Status `
            -Detail "HTTP $code$($httpResult.Note) | Host: $HostHeader -> $ConnectTo" `
            -Remedy $httpResult.Remedy `
            -SourceIP $SourceIP -DestinationIP $ConnectTo
    } catch [System.Net.WebException] {
        $we   = $_.Exception
        $code = 0
        if ($we.Response) {
            $code = [int]$we.Response.StatusCode
            $we.Response.Close()
        }
        if ($code -gt 0) {
            $httpResult = Resolve-HttpStatus -Code $code
            New-Check -Layer $Layer -Name "HTTP Status Code $Label" `
                -Status $httpResult.Status `
                -Detail "HTTP $code$($httpResult.Note) | Host: $HostHeader -> $ConnectTo" `
                -Remedy $httpResult.Remedy `
                -SourceIP $SourceIP -DestinationIP $ConnectTo
        } else {
            New-Check -Layer $Layer -Name "HTTP Status Code $Label" -Status 'Fail' `
                -Detail "$($we.Message) | Host: $HostHeader -> $ConnectTo" `
                -Remedy "No HTTP response received. Verify IIS is running, the target port is reachable, and the Host header matches a configured site binding" `
                -SourceIP $SourceIP -DestinationIP $ConnectTo
        }
    } catch {
        New-Check -Layer $Layer -Name "HTTP Status Code $Label" -Status 'Fail' `
            -Detail $_.Exception.Message `
            -Remedy "Unexpected error during HTTP request. Verify IIS is running and the target is reachable" `
            -SourceIP $SourceIP -DestinationIP $ConnectTo
    }
}

#endregion

#region --- Workstation-side check functions ---

function Test-NetworkLayer {
    param(
        [string]$ServerName,
        [int]$WinRMPort,
        [string]$SourceIP
    )
    $checks = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ProgressPreference = 'SilentlyContinue'

    # ICMP — destination is the server name; no resolved IP available without a separate lookup
    try {
        $ping = Test-Connection -ComputerName $ServerName -Count 1 -Quiet -ErrorAction Stop
        $icmpStatus = if ($ping) { 'Pass' } else { 'Fail' }
        $icmpDetail = if ($ping) { 'Host responded to ping' } else { 'No ICMP response' }
        $icmpRemedy = if (-not $ping) { 'Verify the server is powered on, reachable on the network, and that ICMP is not blocked by a host or network firewall' } else { $null }
        $checks.Add((New-Check -Layer 'Network' -Name 'ICMP Ping' -Status $icmpStatus -Detail $icmpDetail -Remedy $icmpRemedy `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    } catch {
        $checks.Add((New-Check -Layer 'Network' -Name 'ICMP Ping' -Status 'Fail' -Detail $_.Exception.Message `
            -Remedy 'Verify the server name resolves in DNS and the host is reachable from this workstation' `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    }

    # TNC port 443 — RemoteAddress is the actual IP the OS resolved and connected to
    try {
        $tnc443 = Test-NetConnection -ComputerName $ServerName -Port 443 -WarningAction SilentlyContinue
        $tnc443Dest   = if ($tnc443.RemoteAddress) { $tnc443.RemoteAddress.ToString() } else { $ServerName }
        $tnc443Status = if ($tnc443.TcpTestSucceeded) { 'Pass' } else { 'Fail' }
        $tnc443Detail = if ($tnc443.TcpTestSucceeded) { 'TCP 443 open' } else { "TCP 443 not reachable (RemoteAddress: $tnc443Dest)" }
        $tnc443Remedy = if (-not $tnc443.TcpTestSucceeded) { 'Check that IIS is running and bound to port 443, and that no firewall is blocking TCP 443 between this workstation and the server' } else { $null }
        $checks.Add((New-Check -Layer 'Network' -Name 'TNC Port 443' -Status $tnc443Status -Detail $tnc443Detail -Remedy $tnc443Remedy `
            -SourceIP $SourceIP -DestinationIP $tnc443Dest))
    } catch {
        $checks.Add((New-Check -Layer 'Network' -Name 'TNC Port 443' -Status 'Fail' -Detail $_.Exception.Message `
            -Remedy 'Verify the server is reachable and IIS is listening on port 443' `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    }

    # TNC WinRM port — RemoteAddress is the actual IP connected to
    try {
        $tncWinRM = Test-NetConnection -ComputerName $ServerName -Port $WinRMPort -WarningAction SilentlyContinue
        $tncWinRMDest   = if ($tncWinRM.RemoteAddress) { $tncWinRM.RemoteAddress.ToString() } else { $ServerName }
        $tncWinRMStatus = if ($tncWinRM.TcpTestSucceeded) { 'Pass' } else { 'Fail' }
        $tncWinRMDetail = if ($tncWinRM.TcpTestSucceeded) { "TCP $WinRMPort open" } else { "TCP $WinRMPort not reachable" }
        $tncWinRMRemedy = if (-not $tncWinRM.TcpTestSucceeded) { "Verify WinRM is enabled on the server (winrm quickconfig) and that TCP $WinRMPort is open in the firewall" } else { $null }
        $checks.Add((New-Check -Layer 'Network' -Name "TNC WinRM Port $WinRMPort" -Status $tncWinRMStatus -Detail $tncWinRMDetail -Remedy $tncWinRMRemedy `
            -SourceIP $SourceIP -DestinationIP $tncWinRMDest))
    } catch {
        $checks.Add((New-Check -Layer 'Network' -Name "TNC WinRM Port $WinRMPort" -Status 'Fail' -Detail $_.Exception.Message `
            -Remedy "Verify WinRM is enabled on the server and TCP $WinRMPort is not blocked" `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    }

    # Traceroute — Info only, no pass/fail assertion; destination is the server name
    try {
        $trace = Test-NetConnection -ComputerName $ServerName -TraceRoute -WarningAction SilentlyContinue
        $hops  = ($trace.TraceRoute | Where-Object { $_ -ne '0.0.0.0' }) -join ' -> '
        $checks.Add((New-Check -Layer 'Network' -Name 'TraceRoute' -Status 'Info' `
            -Detail "Hops: $hops" -SourceIP $SourceIP -DestinationIP $ServerName))
    } catch {
        $checks.Add((New-Check -Layer 'Network' -Name 'TraceRoute' -Status 'Info' -Detail "TraceRoute failed: $($_.Exception.Message)" `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    }

    return $checks
}

function Test-DNSLayer {
    param(
        [string]$Hostname,      # The friendly URL / ExpectedSAN to resolve
        [string]$ExpectedVIP,   # Optional — if provided, asserts forward lookup resolves to this IP
        [string]$SourceIP
    )
    $checks = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Forward lookup — DestinationIP is the DNS server (not resolvable here); we use the
    # resolved IP(s) as the destination since that is what the check is asserting against.
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($Hostname) | Select-Object -ExpandProperty IPAddressToString
        $multipleRecords = $resolved.Count -gt 1
        $resolvedFirst   = $resolved | Select-Object -First 1  # Primary for DestinationIP; all listed in Detail

        if (-not [string]::IsNullOrWhiteSpace($ExpectedVIP)) {
            $matched = $resolved -contains $ExpectedVIP

            if (-not $matched) {
                # VIP not present at all
                $checks.Add((New-Check -Layer 'DNS' -Name 'Forward Lookup (VIP match)' -Status 'Fail' `
                    -Detail "Resolved: $($resolved -join ', ') | Expected: $ExpectedVIP" `
                    -Remedy "The A record for '$Hostname' does not point to the expected VIP ($ExpectedVIP). Create or update the DNS A record, then allow time for replication and TTL expiry" `
                    -SourceIP $SourceIP -DestinationIP $resolvedFirst))
            } elseif ($multipleRecords) {
                # VIP present but additional records exist — could be stale entries or unintended round-robin
                $others = ($resolved | Where-Object { $_ -ne $ExpectedVIP }) -join ', '
                $checks.Add((New-Check -Layer 'DNS' -Name 'Forward Lookup (VIP match)' -Status 'Warn' `
                    -Detail "Resolved: $($resolved -join ', ') | Expected: $ExpectedVIP | Extra records: $others" `
                    -Remedy "Multiple A records exist for '$Hostname'. If '$others' are stale or unintended, remove them to ensure all clients resolve to the correct VIP ($ExpectedVIP)" `
                    -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
            } else {
                # Single record, matches VIP exactly
                $checks.Add((New-Check -Layer 'DNS' -Name 'Forward Lookup (VIP match)' -Status 'Pass' `
                    -Detail "Resolved: $ExpectedVIP | Expected: $ExpectedVIP" `
                    -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
            }
        } else {
            # No VIP to assert — report what is currently in DNS as Info
            # Warn if multiple records exist since this may indicate a misconfiguration pre-cutover
            $noVipStatus = if ($multipleRecords) { 'Warn' } else { 'Info' }
            $noVipDetail = "Resolved: $($resolved -join ', ') | Note: record already exists — verify this is not a stale or conflicting entry before cutover"
            $noVipRemedy = if ($multipleRecords) { "Multiple A records exist for '$Hostname' with no expected VIP to validate against. Review whether all returned IPs are intentional before cutover" } else { $null }
            $checks.Add((New-Check -Layer 'DNS' -Name 'Forward Lookup (no VIP assertion)' `
                -Status $noVipStatus `
                -Detail $noVipDetail `
                -Remedy $noVipRemedy `
                -SourceIP $SourceIP -DestinationIP $resolvedFirst))
        }
    } catch {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedVIP)) {
            $checks.Add((New-Check -Layer 'DNS' -Name 'Forward Lookup (VIP match)' -Status 'Fail' -Detail $_.Exception.Message `
                -Remedy "No DNS record found for '$Hostname'. Create the A record pointing to $ExpectedVIP" `
                -SourceIP $SourceIP -DestinationIP $null))
        } else {
            # No record found and no VIP expected yet — this is the normal pre-cutover state
            $checks.Add((New-Check -Layer 'DNS' -Name 'Forward Lookup (no VIP assertion)' `
                -Status 'Info' `
                -Detail "No DNS record currently exists for '$Hostname' | Note: expected pre-cutover if the record has not been created yet" `
                -SourceIP $SourceIP -DestinationIP $null))
        }
    }

    # Reverse PTR — destination is the VIP being queried
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVIP)) {
        try {
            $ptr       = [System.Net.Dns]::GetHostEntry($ExpectedVIP).HostName
            $ptrMatch  = $ptr -eq $Hostname
            $ptrStatus = if ($ptrMatch) { 'Pass' } else { 'Warn' }
            $ptrRemedy = if (-not $ptrMatch) { "Create or update the PTR record for $ExpectedVIP to resolve to '$Hostname'. This is managed in the reverse lookup zone in DNS" } else { $null }
            $checks.Add((New-Check -Layer 'DNS' -Name 'Reverse PTR Match' `
                -Status $ptrStatus `
                -Detail "PTR for $ExpectedVIP resolves to '$ptr' | Expected: '$Hostname'" `
                -Remedy $ptrRemedy `
                -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
        } catch {
            $checks.Add((New-Check -Layer 'DNS' -Name 'Reverse PTR Match' -Status 'Warn' `
                -Detail "PTR lookup failed for $ExpectedVIP : $($_.Exception.Message)" `
                -Remedy "Verify a reverse lookup zone exists for the $ExpectedVIP subnet and a PTR record is configured" `
                -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
        }
    } else {
        $checks.Add((New-Check -Layer 'DNS' -Name 'Reverse PTR Match' -Status 'Skip' `
            -Detail 'Skipped — ExpectedVIP not provided, no IP to perform PTR lookup against' `
            -Remedy 'Add ExpectedVIP to the server hashtable once the NetScaler VIP has been assigned' `
            -SourceIP $SourceIP -DestinationIP $null))
    }

    return $checks
}

function Test-WinRMLayer {
    param(
        [string]$ServerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$SourceIP
    )
    $checks  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $icmOpts = @{ ComputerName = $ServerName; ErrorAction = 'Stop' }
    if ($Credential) { $icmOpts.Credential = $Credential }

    # Test-WSMan — destination is the server name; WinRM resolves it internally
    try {
        $wsman = Test-WSMan -ComputerName $ServerName -ErrorAction Stop
        $checks.Add((New-Check -Layer 'WinRM' -Name 'Test-WSMan' -Status 'Pass' `
            -Detail "ProductVersion: $($wsman.ProductVersion)" `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    } catch {
        $checks.Add((New-Check -Layer 'WinRM' -Name 'Test-WSMan' -Status 'Fail' -Detail $_.Exception.Message `
            -Remedy 'Run ''winrm quickconfig'' on the target server, verify the WinRM service is running, and that the server is in TrustedHosts or on the same domain' `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    }

    # Invoke-Command connectivity
    try {
        $icmResult = Invoke-Command @icmOpts -ScriptBlock { $env:COMPUTERNAME }
        $checks.Add((New-Check -Layer 'WinRM' -Name 'Invoke-Command Execution' -Status 'Pass' `
            -Detail "Remote COMPUTERNAME: $icmResult" `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    } catch {
        $checks.Add((New-Check -Layer 'WinRM' -Name 'Invoke-Command Execution' -Status 'Fail' -Detail $_.Exception.Message `
            -Remedy 'Verify credentials are correct, the account has remote execution rights, and WinRM is configured to allow connections from this workstation (check TrustedHosts or Kerberos delegation)' `
            -SourceIP $SourceIP -DestinationIP $ServerName))
    }

    return $checks
}

function Resolve-HttpStatus {
    # Evaluates an HTTP status code and returns a hashtable with Status and Detail suffix.
    #
    # Classification:
    #   Pass  — 2xx (success) or 4xx (client error — IIS responded, stack is healthy)
    #   Warn  — 5xx (server error — IIS responded but something is failing server-side)
    #   Fail  — reserved for no-response / exception cases handled by callers
    #
    # 401 is Pass but annotated in Detail to indicate a Windows Auth challenge was received.
    # All other 2xx/4xx codes are Pass without annotation.
    param([int]$Code)

    $is2xx = $Code -ge 200 -and $Code -lt 300
    $is4xx = $Code -ge 400 -and $Code -lt 500
    $is5xx = $Code -ge 500 -and $Code -lt 600

    if ($Code -eq 401) {
        return @{ Status = 'Pass'; Note = ' (Windows Auth challenge — credentials required)'; Remedy = $null }
    } elseif ($is2xx -or $is4xx) {
        return @{ Status = 'Pass'; Note = ''; Remedy = $null }
    } elseif ($is5xx) {
        return @{ Status = 'Warn'; Note = ''; Remedy = "HTTP $Code indicates a server-side error. Check the IIS and application event logs, verify the app pool is running, and confirm the application deployed correctly" }
    } else {
        return @{ Status = 'Warn'; Note = ''; Remedy = "Unexpected HTTP $Code returned. Verify the IIS site configuration and application deployment" }
    }
}

function Invoke-TLSCheck {
    # Performs TLS handshake + HTTP status check against one target.
    # Returns @{ Checks = [List]; Certificate = [X509Certificate2] or $null }
    param(
        [string]$ConnectTo,   # IP or hostname to open TCP connection against
        [string]$SniHostname, # Hostname for SNI and Host header
        [string]$Label,       # Suffix for check names, e.g. '(Direct)' or '(VIP)'
        [string]$SourceIP,
        [int]$Port = 443      # Target port for TLS connection and HTTP request
    )
    $checks = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cert   = $null

    # TLS handshake — capture the presented certificate and negotiated protocol for later inspection
    $tcp    = $null
    $stream = $null
    $ssl    = $null
    try {
        $tcp    = [System.Net.Sockets.TcpClient]::new()
        $tcp.SendTimeout    = 10000
        $tcp.ReceiveTimeout = 10000
        $connectTask = $tcp.ConnectAsync($ConnectTo, $Port)
        if (-not $connectTask.Wait(10000)) {
            throw [System.TimeoutException]::new("TCP connect to ${ConnectTo}:${Port} timed out after 10 seconds")
        }
        $stream = $tcp.GetStream()
        $ssl    = [System.Net.Security.SslStream]::new($stream, $false,
                    { param($s,$c,$ch,$e) $true })  # Suppress validation; we inspect cert explicitly below

        # Explicitly request TLS 1.2 or 1.3 — without this the runtime defers to OS SCHANNEL
        # negotiation which may fail or select a deprecated version depending on policy.
        # SslProtocols flags are combined with -bor so either version is acceptable.
        $tlsFlags = [System.Security.Authentication.SslProtocols]::Tls12 -bor `
                    [System.Security.Authentication.SslProtocols]::Tls13
        $ssl.AuthenticateAsClient($SniHostname, $null, $tlsFlags, $false)
        $proto  = $ssl.SslProtocol
        $cipher = $ssl.CipherAlgorithm

        # Capture and cast to X509Certificate2 for full inspection API surface
        if ($null -ne $ssl.RemoteCertificate) {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
        }

        $checks.Add((New-Check -Layer 'HTTPS' -Name "TLS Handshake $Label" -Status 'Pass' `
            -Detail "Protocol: $proto | Cipher: $cipher | SNI: $SniHostname -> ${ConnectTo}:${Port}" `
            -SourceIP $SourceIP -DestinationIP $ConnectTo))

        # TLS version check — 1.2 and 1.3 are required; 1.0 and 1.1 must be remediated.
        # $proto is a SslProtocols enum; ToString() returns 'Tls', 'Tls11', 'Tls12', 'Tls13'.
        $protoStr      = $proto.ToString()
        $acceptedStr   = @('Tls12', 'Tls13')
        $deprecatedStr = @('Tls', 'Tls11')   # 'Tls' = TLS 1.0 in the enum

        # Friendly display name for the detail string
        $protoDisplay = switch ($protoStr) {
            'Tls'   { 'TLS 1.0' }
            'Tls11' { 'TLS 1.1' }
            'Tls12' { 'TLS 1.2' }
            'Tls13' { 'TLS 1.3' }
            default { $protoStr }
        }

        if ($acceptedStr -contains $protoStr) {
            $checks.Add((New-Check -Layer 'HTTPS' -Name "TLS Version $Label" -Status 'Pass' `
                -Detail "Negotiated: $protoDisplay | SNI: $SniHostname -> ${ConnectTo}:${Port}" `
                -SourceIP $SourceIP -DestinationIP $ConnectTo))
        } elseif ($deprecatedStr -contains $protoStr) {
            $checks.Add((New-Check -Layer 'HTTPS' -Name "TLS Version $Label" -Status 'Fail' `
                -Detail "Negotiated: $protoDisplay (deprecated) | SNI: $SniHostname -> ${ConnectTo}:${Port}" `
                -Remedy "TLS 1.0 and 1.1 are deprecated and must not be used. Disable them in the SCHANNEL registry (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols) and ensure TLS 1.2 or 1.3 is enabled. For NetScaler, update the SSL profile bound to the virtual server" `
                -SourceIP $SourceIP -DestinationIP $ConnectTo))
        } else {
            $checks.Add((New-Check -Layer 'HTTPS' -Name "TLS Version $Label" -Status 'Fail' `
                -Detail "Negotiated: $protoDisplay (unrecognised or unsupported) | SNI: $SniHostname -> ${ConnectTo}:${Port}" `
                -Remedy "Verify TLS 1.2 or 1.3 is enabled and preferred on the server or NetScaler SSL profile" `
                -SourceIP $SourceIP -DestinationIP $ConnectTo))
        }
    } catch {
        $checks.Add((New-Check -Layer 'HTTPS' -Name "TLS Handshake $Label" -Status 'Fail' `
            -Detail $_.Exception.Message `
            -Remedy 'Verify the certificate is bound to the site or NetScaler virtual server, and that TLS 1.2 or higher is enabled' `
            -SourceIP $SourceIP -DestinationIP $ConnectTo))

        # Emit TLS Version as Fail — handshake failure may be caused by a version mismatch
        # (e.g. server only offers TLS 1.0/1.1 but client has those disabled, or no shared cipher).
        $checks.Add((New-Check -Layer 'HTTPS' -Name "TLS Version $Label" -Status 'Fail' `
            -Detail "Version could not be negotiated — handshake failed | SNI: $SniHostname -> ${ConnectTo}:${Port}" `
            -Remedy 'A TLS version mismatch may be the cause. Verify TLS 1.2 or 1.3 is enabled on both the client (SCHANNEL) and the server or NetScaler SSL profile. On NetScaler: check the SSL profile bound to the virtual server and confirm TLSv12 or TLSv13 is enabled' `
            -SourceIP $SourceIP -DestinationIP $ConnectTo))
    } finally {
        if ($ssl)    { try { $ssl.Dispose()    } catch {} }
        if ($stream) { try { $stream.Dispose() } catch {} }
        if ($tcp)    { try { $tcp.Dispose()    } catch {} }
    }

    # HTTP status — 2xx and 4xx are Pass (IIS responded); 5xx is Warn (server error).
    # 401 is Pass with a note that a Windows Auth challenge was received.
    # No response or connection failure is Fail, handled in catch blocks below.
    $httpUrl = if ($Port -eq 443) { "https://$ConnectTo" } else { "https://${ConnectTo}:${Port}" }
    Invoke-HttpStatusCheck -Url $httpUrl -HostHeader $SniHostname -ConnectTo $ConnectTo `
        -Label $Label -Layer 'HTTPS' -SourceIP $SourceIP |
        ForEach-Object { $checks.Add($_) }

    return @{ Checks = $checks; Certificate = $cert }
}

function Test-SANMatch {
    # Returns 'Pass', 'Warn', or 'Fail'.
    # Exact match always returns Pass.
    # Wildcard match returns Pass for internal suffixes (.local, .corp, .internal), Warn otherwise.
    # No match returns Fail.
    param(
        [string[]]$SANs,
        [string]$Hostname
    )
    $privateSuffixes = @('.local', '.corp', '.internal')

    foreach ($san in $SANs) {
        if ($san -eq $Hostname) { return 'Pass' }
        if ($san -match '^\*\.') {
            $wildcardSuffix = $san.Substring(1)  # e.g. '.dev.local'
            $prefix = $Hostname.Substring(0, $Hostname.Length - $wildcardSuffix.Length)
            if ($Hostname -like "*$wildcardSuffix" -and $prefix -notmatch '\.') {
                # Wildcard matched — check if the domain is an internal suffix
                $isPrivate = $false
                foreach ($suffix in $privateSuffixes) {
                    if ($wildcardSuffix -eq $suffix -or $wildcardSuffix -like "*$suffix") {
                        $isPrivate = $true
                        break
                    }
                }
                if ($isPrivate) { return 'Pass' } else { return 'Warn' }
            }
        }
    }
    return 'Fail'
}

function Invoke-CertInspection {
    # Inspects a presented X509Certificate2 and emits check rows.
    # Used for both Direct and VIP TLS endpoints.
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$Label,                # e.g. '(Direct)' or '(VIP)'
        [string]$ExpectedSAN,          # optional; if provided, asserts SAN match
        [int]$CertExpiryThresholdDays,
        [bool]$CheckRevocation = $false
    )
    $checks   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now      = [datetime]::UtcNow
    $threshold = $now.AddDays($CertExpiryThresholdDays)

    # SAN match
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSAN)) {
        $sans = @()
        try {
            $sanExt = $Certificate.Extensions |
                        Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
            if ($sanExt) {
                # Format($true) produces one entry per line; strip type prefix e.g. 'DNS Name='
                $sans = $sanExt.Format($true) -split "`r?`n" |
                            ForEach-Object { $_.Trim() } |
                            Where-Object { $_ } |
                            ForEach-Object { ($_ -replace '^.*?=', '').Trim() }
            }
        } catch {}

        $sanStatus = Test-SANMatch -SANs $sans -Hostname $ExpectedSAN
        $sanDetail = "SANs: $($sans -join '; ') | Expected: '$ExpectedSAN' | Thumbprint: $($Certificate.Thumbprint)"
        $sanRemedy = switch ($sanStatus) {
            'Fail' { "The certificate presented by this endpoint does not include '$ExpectedSAN' as a SAN. Verify the correct certificate is bound in IIS/NetScaler and that it was issued with the expected SAN entries" }
            'Warn' { "Wildcard SAN matched '$ExpectedSAN' on a public domain. Verify this is intentional and that the wildcard scope is acceptable for this service" }
            default { $null }
        }
        $checks.Add((New-Check -Layer 'HTTPS' -Name "Cert SAN $Label" -Status $sanStatus -Detail $sanDetail -Remedy $sanRemedy))
    } else {
        $checks.Add((New-Check -Layer 'HTTPS' -Name "Cert SAN $Label" -Status 'Skip' `
            -Detail "Skipped — ExpectedSAN not provided | Thumbprint: $($Certificate.Thumbprint)" `
            -Remedy 'Provide ExpectedSAN in the server hashtable to enable SAN assertion'))
    }

    # Expiry
    $expiry   = $Certificate.NotAfter.ToUniversalTime()
    $daysLeft = ($expiry - $now).Days
    $expiryStatus = if ($expiry -gt $threshold) { 'Pass' } else { 'Warn' }
    $expiryRemedy = if (-not ($expiry -gt $threshold)) { "Certificate expires in $daysLeft days. Renew and rebind the certificate before expiry to avoid service disruption" } else { $null }
    $checks.Add((New-Check -Layer 'HTTPS' -Name "Cert Expiry $Label" `
        -Status $expiryStatus `
        -Detail "Expires: $($expiry.ToString('yyyy-MM-dd')) UTC ($daysLeft days remaining) | Thumbprint: $($Certificate.Thumbprint)" `
        -Remedy $expiryRemedy))

    # Chain
    try {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode =
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $valid       = $chain.Build($Certificate)
        $chainStatus = if ($valid) { 'Pass' } else { 'Warn' }
        $chainDetail = if ($valid) {
            "Chain valid | Thumbprint: $($Certificate.Thumbprint)"
        } else {
            $issues = ($chain.ChainStatus |
                        ForEach-Object { $_.StatusInformation.Trim() } |
                        Where-Object { $_ }) -join '; '
            $aiaUrl = $null
            $aiaExt = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }
            if ($aiaExt) {
                $aiaText = $aiaExt.Format($false)
                $aiaUrl = if ($aiaText -match 'CA Issuers[^U]*URI:(\S+)') { $Matches[1] } else { $null }
            }
            $aiaFragment = if ($aiaUrl) { " | AIA: $aiaUrl" } else { '' }
            "Chain issues: $issues | Thumbprint: $($Certificate.Thumbprint)$aiaFragment"
        }
        $chainRemedy = if (-not $valid) {
            $aiaHint = if ($aiaUrl) { 'Download the intermediate CA certificate from the AIA URL shown in Detail, verify its thumbprint with your CA team, then install into LocalMachine\CA on the server' }
                       else { 'Install missing intermediate or root CA certificates in LocalMachine\CA and LocalMachine\Root respectively on the server, then verify the chain using certutil -verify' }
            $aiaHint
        } else { $null }
        $checks.Add((New-Check -Layer 'HTTPS' -Name "Cert Chain $Label" -Status $chainStatus -Detail $chainDetail -Remedy $chainRemedy))
    } catch {
        $checks.Add((New-Check -Layer 'HTTPS' -Name "Cert Chain $Label" -Status 'Warn' `
            -Detail "Chain build failed: $($_.Exception.Message)" `
            -Remedy 'Unable to build certificate chain. Verify the certificate store is accessible and intermediate CA certs are installed'))
    }

    # Revocation (opt-in)
    if ($CheckRevocation) {
        # Part 1: X509Chain revocation verdict
        try {
            $revChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $revChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            $revChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
            $revChain.ChainPolicy.UrlRetrievalTimeout = [timespan]::FromSeconds(10)
            $revValid = $revChain.Build($Certificate)
            $revoked = $revChain.ChainStatus | Where-Object { $_.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked }
            $offlineOrTimeout = $revChain.ChainStatus | Where-Object {
                $_.Status -band ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -bor
                                 [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation)
            }
            if ($revoked) {
                $revStatus = 'Fail'
                $revDetail = "Certificate is revoked | Thumbprint: $($Certificate.Thumbprint)"
                $revRemedy = 'This certificate has been revoked by the issuing CA. Obtain a new certificate immediately and rebind it in IIS'
            } elseif ($offlineOrTimeout) {
                $revStatus = 'Warn'
                $issues = ($offlineOrTimeout | ForEach-Object { $_.StatusInformation.Trim() } | Where-Object { $_ }) -join '; '
                $revDetail = "Revocation check inconclusive — CRL/OCSP endpoint unreachable: $issues | Thumbprint: $($Certificate.Thumbprint)"
                $revRemedy = 'CRL or OCSP endpoint is unreachable from this workstation. Verify outbound HTTP/LDAP access to the CRL distribution points listed in the certificate'
            } elseif ($revValid) {
                $revStatus = 'Pass'
                $revDetail = "Revocation check passed | Thumbprint: $($Certificate.Thumbprint)"
                $revRemedy = $null
            } else {
                $revStatus = 'Warn'
                $issues = ($revChain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() } | Where-Object { $_ }) -join '; '
                $revDetail = "Revocation check inconclusive — chain issues: $issues | Thumbprint: $($Certificate.Thumbprint)"
                $revRemedy = 'Resolve chain trust issues first, then re-run with -CheckRevocation'
            }
            $checks.Add((New-Check -Layer 'HTTPS' -Name "Cert Revocation $Label" -Status $revStatus -Detail $revDetail -Remedy $revRemedy))
        } catch {
            $checks.Add((New-Check -Layer 'HTTPS' -Name "Cert Revocation $Label" -Status 'Warn' `
                -Detail "Revocation check failed: $($_.Exception.Message) | Thumbprint: $($Certificate.Thumbprint)" `
                -Remedy 'Unable to perform revocation check. Verify CRL/OCSP endpoint reachability and certificate store integrity'))
        }

        # Part 2: CRL Distribution Point reachability (TCP connectivity)
        $cdpExt = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.31' }
        if ($cdpExt) {
            $cdpText = $cdpExt.Format($false)
            $cdpUrls = [System.Collections.Generic.List[string]]::new()
            # Format() returns text like "... URL=http://crl.example.com/ca.crl ..."
            $cdpRegex = [regex]'URL=(\S+)'
            foreach ($m in $cdpRegex.Matches($cdpText)) {
                $cdpUrls.Add($m.Groups[1].Value)
            }
            foreach ($cdpUrl in $cdpUrls) {
                try {
                    $uri = [System.Uri]::new($cdpUrl)
                    $cdpHost = $uri.Host
                    $cdpPort = if ($uri.Port -gt 0 -and $uri.Port -ne -1) { $uri.Port }
                               elseif ($uri.Scheme -eq 'https') { 443 }
                               else { 80 }
                    $tnc = Test-NetConnection -ComputerName $cdpHost -Port $cdpPort -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
                    $tncStatus = if ($tnc) { 'Pass' } else { 'Fail' }
                    $tncDetail = if ($tnc) { "CRL endpoint reachable: $cdpUrl | Host: $cdpHost Port: $cdpPort" }
                                 else { "CRL endpoint unreachable: $cdpUrl | Host: $cdpHost Port: $cdpPort" }
                    $tncRemedy = if (-not $tnc) { "Open firewall access from this workstation to $cdpHost on port $cdpPort to allow CRL downloads for certificate revocation checking" } else { $null }
                    $checks.Add((New-Check -Layer 'HTTPS' -Name "CRL Reachability $Label" -Status $tncStatus -Detail $tncDetail -Remedy $tncRemedy))
                } catch {
                    $checks.Add((New-Check -Layer 'HTTPS' -Name "CRL Reachability $Label" -Status 'Fail' `
                        -Detail "CRL endpoint test failed for $cdpUrl — $($_.Exception.Message)" `
                        -Remedy 'Verify the CRL distribution point URL is valid and accessible'))
                }
            }
        } else {
            $checks.Add((New-Check -Layer 'HTTPS' -Name "CRL Reachability $Label" -Status 'Info' `
                -Detail "No CRL Distribution Point URLs found in certificate | Thumbprint: $($Certificate.Thumbprint)"))
        }
    }

    return $checks
}

function Test-TLSLayer {
    param(
        [string]$ServerName,
        [string]$ServerIP,
        [string]$ExpectedVIP,
        [string]$ExpectedSAN,
        [int]$CertExpiryThresholdDays,
        [string]$IISThumbprint,
        [bool]$SslOffload = $false,
        [string]$SourceIP,
        [int]$ResolvedPort = 443,       # Port from IIS binding inspection
        [string]$ResolvedProtocol = 'https',  # Protocol from IIS binding
        [int]$ExpectedVIPPort = 443,    # NetScaler VIP port
        [bool]$CheckRevocation = $false
    )
    $checks      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sniHostname = if (-not [string]::IsNullOrWhiteSpace($ExpectedSAN)) { $ExpectedSAN } else { $ServerName }
    $directCert  = $null
    $vipCert     = $null

    # Non-standard port TNC checks — emitted when the resolved port differs from 443/80
    if (-not [string]::IsNullOrWhiteSpace($ServerIP) -and $ResolvedPort -ne 443 -and $ResolvedPort -ne 80) {
        try {
            $tnc = Test-NetConnection -ComputerName $ServerIP -Port $ResolvedPort -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            $tncStatus = if ($tnc) { 'Pass' } else { 'Fail' }
            $tncDetail = if ($tnc) { "Port $ResolvedPort open on $ServerIP" } else { "Port $ResolvedPort closed on $ServerIP" }
            $tncRemedy = if (-not $tnc) { "Verify port $ResolvedPort is open on the server firewall and any intermediate network firewalls" } else { $null }
            $checks.Add((New-Check -Layer 'Network' -Name "TNC Port $ResolvedPort (Direct)" -Status $tncStatus -Detail $tncDetail -Remedy $tncRemedy `
                -SourceIP $SourceIP -DestinationIP $ServerIP))
        } catch {
            $checks.Add((New-Check -Layer 'Network' -Name "TNC Port $ResolvedPort (Direct)" -Status 'Fail' -Detail $_.Exception.Message `
                -Remedy "Verify port $ResolvedPort is open on the server" -SourceIP $SourceIP -DestinationIP $ServerIP))
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVIP) -and $ExpectedVIPPort -ne 443) {
        try {
            $tnc = Test-NetConnection -ComputerName $ExpectedVIP -Port $ExpectedVIPPort -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            $tncStatus = if ($tnc) { 'Pass' } else { 'Fail' }
            $tncDetail = if ($tnc) { "Port $ExpectedVIPPort open on $ExpectedVIP" } else { "Port $ExpectedVIPPort closed on $ExpectedVIP" }
            $tncRemedy = if (-not $tnc) { "Verify port $ExpectedVIPPort is open on the NetScaler VIP and any intermediate network firewalls" } else { $null }
            $checks.Add((New-Check -Layer 'Network' -Name "TNC Port $ExpectedVIPPort (VIP)" -Status $tncStatus -Detail $tncDetail -Remedy $tncRemedy `
                -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
        } catch {
            $checks.Add((New-Check -Layer 'Network' -Name "TNC Port $ExpectedVIPPort (VIP)" -Status 'Fail' -Detail $_.Exception.Message `
                -Remedy "Verify port $ExpectedVIPPort is open on the VIP" -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
        }
    }

    # Direct path
    if (-not [string]::IsNullOrWhiteSpace($ServerIP)) {
        if ($SslOffload) {
            # SSL terminates at NetScaler — run HTTP on port 80 instead of HTTPS.
            # TLS and certificate check rows retain the HTTPS layer since they describe
            # TLS-layer state (skipped because offloaded). The HTTP status check uses
            # the HTTP layer to reflect the protocol actually used for that request.
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'SSL Offload (Direct)' -Status 'Info' `
                -Detail "SSL offload detected — IIS site is bound on port $ResolvedPort with protocol ${ResolvedProtocol} — TLS checks skipped for direct path; running HTTP status check instead" `
                -SourceIP $SourceIP -DestinationIP $ServerIP))
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'TLS Handshake (Direct)' -Status 'Skip' `
                -Detail "Skipped — SSL terminated at NetScaler; IIS listens on port $ResolvedPort" `
                -Remedy 'This is expected for SSL offload configurations. If TLS should terminate at IIS, add an HTTPS binding on port 443' `
                -SourceIP $SourceIP -DestinationIP $ServerIP))
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'TLS Version (Direct)' -Status 'Skip' -Detail 'Skipped — SSL offload; no TLS at IIS' `
                -SourceIP $SourceIP -DestinationIP $ServerIP))
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert SAN (Direct)'    -Status 'Skip' -Detail 'Skipped — SSL offload; no TLS at IIS' `
                -SourceIP $SourceIP -DestinationIP $ServerIP))
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Expiry (Direct)' -Status 'Skip' -Detail 'Skipped — SSL offload; no TLS at IIS' `
                -SourceIP $SourceIP -DestinationIP $ServerIP))
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Chain (Direct)'  -Status 'Skip' -Detail 'Skipped — SSL offload; no TLS at IIS' `
                -SourceIP $SourceIP -DestinationIP $ServerIP))

            # HTTP status check — layer is HTTP to reflect actual protocol used
            $httpPort = $ResolvedPort
            $httpUrl  = if ($httpPort -eq 80) { "http://$ServerIP" } else { "http://${ServerIP}:${httpPort}" }
            Invoke-HttpStatusCheck -Url $httpUrl -HostHeader $sniHostname -ConnectTo $ServerIP `
                -Label '(Direct)' -Layer 'HTTP' -SourceIP $SourceIP |
                ForEach-Object { $checks.Add($_) }
        } else {
            # Normal HTTPS direct path
            $directResult = Invoke-TLSCheck -ConnectTo $ServerIP -SniHostname $sniHostname -Label '(Direct)' -SourceIP $SourceIP -Port $ResolvedPort
            $directResult.Checks | ForEach-Object { $checks.Add($_) }
            $directCert = $directResult.Certificate

            if ($null -ne $directCert) {
                Invoke-CertInspection -Certificate $directCert -Label '(Direct)' `
                    -ExpectedSAN $ExpectedSAN -CertExpiryThresholdDays $CertExpiryThresholdDays `
                    -CheckRevocation $CheckRevocation |
                    ForEach-Object { $checks.Add($_) }
            } else {
                $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert SAN (Direct)'    -Status 'Skip' -Detail 'No certificate returned from TLS handshake' -Remedy 'TLS handshake likely failed — resolve the TLS Handshake (Direct) failure first' -SourceIP $SourceIP -DestinationIP $ServerIP))
                $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Expiry (Direct)' -Status 'Skip' -Detail 'No certificate returned from TLS handshake' -Remedy 'TLS handshake likely failed — resolve the TLS Handshake (Direct) failure first' -SourceIP $SourceIP -DestinationIP $ServerIP))
                $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Chain (Direct)'  -Status 'Skip' -Detail 'No certificate returned from TLS handshake' -Remedy 'TLS handshake likely failed — resolve the TLS Handshake (Direct) failure first' -SourceIP $SourceIP -DestinationIP $ServerIP))
            }
        }
    } else {
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'TLS Handshake (Direct)'    -Status 'Skip' -Detail 'Skipped — ServerIP not provided' -Remedy 'Add ServerIP to the server hashtable to enable direct server TLS checks' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'TLS Version (Direct)'      -Status 'Skip' -Detail 'Skipped — ServerIP not provided' -Remedy 'Add ServerIP to the server hashtable to enable direct server TLS checks' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'HTTP Status Code (Direct)' -Status 'Skip' -Detail 'Skipped — ServerIP not provided' -Remedy 'Add ServerIP to the server hashtable to enable direct server HTTP checks' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert SAN (Direct)'         -Status 'Skip' -Detail 'Skipped — ServerIP not provided' -Remedy 'Add ServerIP to the server hashtable to enable direct server certificate checks' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Expiry (Direct)'      -Status 'Skip' -Detail 'Skipped — ServerIP not provided' -Remedy 'Add ServerIP to the server hashtable to enable direct server certificate checks' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Chain (Direct)'       -Status 'Skip' -Detail 'Skipped — ServerIP not provided' -Remedy 'Add ServerIP to the server hashtable to enable direct server certificate checks' -SourceIP $SourceIP))
    }

    # VIP — connects to NetScaler VIP, validates the full load-balanced path
    if (-not [string]::IsNullOrWhiteSpace($ExpectedVIP)) {
        $vipResult = Invoke-TLSCheck -ConnectTo $ExpectedVIP -SniHostname $sniHostname -Label '(VIP)' -SourceIP $SourceIP -Port $ExpectedVIPPort
        $vipResult.Checks | ForEach-Object { $checks.Add($_) }
        $vipCert = $vipResult.Certificate

        if ($null -ne $vipCert) {
            Invoke-CertInspection -Certificate $vipCert -Label '(VIP)' `
                -ExpectedSAN $ExpectedSAN -CertExpiryThresholdDays $CertExpiryThresholdDays `
                -CheckRevocation $CheckRevocation |
                ForEach-Object { $checks.Add($_) }
        } else {
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert SAN (VIP)'    -Status 'Skip' -Detail 'No certificate returned from TLS handshake' -Remedy 'TLS handshake likely failed — resolve the TLS Handshake (VIP) failure first' -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Expiry (VIP)' -Status 'Skip' -Detail 'No certificate returned from TLS handshake' -Remedy 'TLS handshake likely failed — resolve the TLS Handshake (VIP) failure first' -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
            $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Chain (VIP)'  -Status 'Skip' -Detail 'No certificate returned from TLS handshake' -Remedy 'TLS handshake likely failed — resolve the TLS Handshake (VIP) failure first' -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
        }
    } else {
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'TLS Handshake (VIP)'    -Status 'Skip' -Detail 'Skipped — ExpectedVIP not provided' -Remedy 'Add ExpectedVIP to the server hashtable once the NetScaler VIP has been assigned' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'TLS Version (VIP)'      -Status 'Skip' -Detail 'Skipped — ExpectedVIP not provided' -Remedy 'Add ExpectedVIP to the server hashtable once the NetScaler VIP has been assigned' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'HTTP Status Code (VIP)' -Status 'Skip' -Detail 'Skipped — ExpectedVIP not provided' -Remedy 'Add ExpectedVIP to the server hashtable once the NetScaler VIP has been assigned' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert SAN (VIP)'         -Status 'Skip' -Detail 'Skipped — ExpectedVIP not provided' -Remedy 'Add ExpectedVIP to the server hashtable once the NetScaler VIP has been assigned' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Expiry (VIP)'      -Status 'Skip' -Detail 'Skipped — ExpectedVIP not provided' -Remedy 'Add ExpectedVIP to the server hashtable once the NetScaler VIP has been assigned' -SourceIP $SourceIP))
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Chain (VIP)'       -Status 'Skip' -Detail 'Skipped — ExpectedVIP not provided' -Remedy 'Add ExpectedVIP to the server hashtable once the NetScaler VIP has been assigned' -SourceIP $SourceIP))
    }

    # Cross-comparison — IIS cert vs VIP-presented cert
    # Requires both a VIP cert to have been retrieved and an IIS thumbprint from the remote checks
    if ($null -ne $vipCert -and -not [string]::IsNullOrWhiteSpace($IISThumbprint)) {
        $vipThumbprint = $vipCert.Thumbprint
        $match         = $vipThumbprint -eq $IISThumbprint
        $matchStatus   = if ($match) { 'Pass' } else { 'Warn' }
        $matchDetail   = if ($match) {
            "IIS and VIP present the same cert | Thumbprint: $vipThumbprint"
        } else {
            "Thumbprint mismatch — IIS: $IISThumbprint | VIP: $vipThumbprint"
        }
        $matchRemedy = if (-not $match) { 'The NetScaler VIP is presenting a different certificate than IIS. Verify the correct certificate is bound on the NetScaler virtual server and that it matches the certificate installed in IIS' } else { $null }
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Thumbprint IIS vs VIP' -Status $matchStatus -Detail $matchDetail -Remedy $matchRemedy `
            -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
    } elseif ($null -ne $vipCert -and [string]::IsNullOrWhiteSpace($IISThumbprint)) {
        $checks.Add((New-Check -Layer 'HTTPS' -Name 'Cert Thumbprint IIS vs VIP' -Status 'Skip' `
            -Detail 'Skipped — IIS thumbprint unavailable (remote cert checks may have failed)' `
            -Remedy 'Resolve any failures in the Certificate layer checks so the IIS thumbprint can be retrieved for comparison' `
            -SourceIP $SourceIP -DestinationIP $ExpectedVIP))
    }
    # If VIP cert is null, no comparison row — VIP TLS failure already surfaced above

    return $checks
}

#endregion

#region --- Server-side scriptblock (runs inside Invoke-Command) ---

$RemoteScriptBlock = {
    param(
        [string]$SiteNameOverride,   # Optional — caller-supplied override; skips auto-detection when provided
        [string]$AppPoolOverride,    # Optional — caller-supplied override
        [string]$ExpectedSAN,
        [int]$CertExpiryThresholdDays,
        [bool]$CheckRevocation
    )

    $results        = [System.Collections.Generic.List[hashtable]]::new()
    $sslOffload     = $false  # Set to $true when site is found on port 80 with no 443 binding
    $iisThumbprint  = $null   # Leaf cert thumbprint, returned explicitly for cross-comparison
    $resolvedPort   = 443     # Port from IIS binding inspection
    $resolvedProto  = 'https' # Protocol from IIS binding inspection

    # Resolve this server's own IPv4 for SourceIP on remote check rows
    $remoteSourceIP = $null
    try {
        $remoteSourceIP = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.ToString() -ne '127.0.0.1' } |
            Select-Object -First 1 -ExpandProperty IPAddressToString
    } catch {
        $remoteSourceIP = 'unknown'
    }

    function rCheck {
        param([string]$Layer, [string]$Name, [string]$Status, [string]$Detail, [string]$Remedy)
        $validStatuses = @('Pass','Warn','Fail','Info','Skip')
        if ($validStatuses -notcontains $Status) {
            $Status = 'Fail'
            $Detail = "Invalid status value provided. Original detail: $Detail"
        }
        $fullDetail = if (-not [string]::IsNullOrWhiteSpace($Remedy)) { "$Detail | Remedy: $Remedy" } else { $Detail }
        $results.Add(@{ Layer=$Layer; Name=$Name; Status=$Status; Detail=$fullDetail })
    }

    # --- IIS service ---
    try {
        $svc = Get-Service -Name 'W3SVC' -ErrorAction Stop
        $svcStatus = if ($svc.Status -eq 'Running') { 'Pass' } else { 'Fail' }
        $svcRemedy = if ($svc.Status -ne 'Running') { "Start the W3SVC service: 'Start-Service W3SVC' or via services.msc — if it fails to start, check the Windows Event Log (System and Application) for errors" } else { $null }
        rCheck 'IIS' 'IIS Service (W3SVC) Running' $svcStatus "Status: $($svc.Status)" $svcRemedy
    } catch {
        rCheck 'IIS' 'IIS Service (W3SVC) Running' 'Fail' $_.Exception.Message 'Verify IIS is installed on this server (Add Roles and Features) and the W3SVC service exists'
    }

    # --- WebAdministration module ---
    $webAdminAvailable = $false
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $webAdminAvailable = $true
        rCheck 'IIS' 'WebAdministration Module' 'Pass' 'Module loaded successfully'
    } catch {
        rCheck 'IIS' 'WebAdministration Module' 'Warn' "Module unavailable — IIS config checks skipped: $($_.Exception.Message)" 'Install the WebAdministration module: ensure the IIS Management Scripts and Tools feature is installed (Add Roles and Features > Web Server > Management Tools)'
    }

    # --- Site and app pool resolution ---
    $SiteName   = $null
    $AppPoolName = $null

    if ($webAdminAvailable) {
        if (-not [string]::IsNullOrWhiteSpace($SiteNameOverride)) {
            # Manual override — use as-is
            $SiteName    = $SiteNameOverride
            $AppPoolName = $AppPoolOverride
            rCheck 'IIS' 'Site Resolution' 'Info' "Using provided SiteName: '$SiteName' | AppPool: '$AppPoolName'"
        } else {
            # Auto-detect site and app pool.
            #
            # All bindings across all sites are collected into a flat list first.
            # A priority ladder is then walked top-to-bottom; the first rule that
            # finds a matching binding wins.
            #
            # Priority order (highest to lowest):
            #   1 — exact hostname match on any port  (most specific — unambiguous)
            #   2 — port 443, catchall/empty hostname  (HTTPS without host-header routing)
            #   3 — port 80,  catchall/empty hostname  (HTTP — SSL offload)
            #
            # If ExpectedSAN is not provided, rule 1 is never satisfied and the first
            # site with a 443 binding wins, falling back to the first with an 80 binding.
            try {
                # Build a flat list of every binding across every site.
                # Each entry carries the site object alongside the parsed port and hostname
                # so the priority ladder can work against a single collection.
                $allBindings = [System.Collections.Generic.List[hashtable]]::new()
                foreach ($s in (Get-Website)) {
                    foreach ($b in (Get-WebBinding -Name $s.Name)) {
                        $parts = $b.bindingInformation -split ':'
                        $allBindings.Add(@{
                            Site     = $s
                            Port     = if ($parts.Count -ge 2) { $parts[1] } else { '' }
                            BHost    = if ($parts.Count -ge 3) { $parts[2].Trim() } else { '' }
                            Protocol = $b.protocol
                        })
                    }
                }

                $resolved        = $null
                $matchLabel      = $null
                $matchedPort     = $null
                $matchedProtocol = $null
                $hasSAN          = -not [string]::IsNullOrWhiteSpace($ExpectedSAN)

                # Rule 1 — exact hostname match (any port)
                # Checked before port preference so a site correctly configured with a
                # host-header binding is always preferred over a catchall on another site.
                if ($hasSAN -and $null -eq $resolved) {
                    foreach ($entry in $allBindings) {
                        if ($entry.BHost -eq $ExpectedSAN) {
                            $resolved        = $entry.Site
                            $matchedPort     = $entry.Port
                            $matchedProtocol = $entry.Protocol
                            $matchLabel      = "exact hostname match on port $($entry.Port)"
                            break
                        }
                    }
                }

                # Rule 2 — port 443, catchall binding
                if ($null -eq $resolved) {
                    foreach ($entry in $allBindings) {
                        if ($entry.Port -eq '443') {
                            $resolved        = $entry.Site
                            $matchedPort     = '443'
                            $matchedProtocol = $entry.Protocol
                            $matchLabel      = 'port 443, catchall binding (no hostname-level match)'
                            break
                        }
                    }
                }

                # Rule 3 — port 80, catchall binding (SSL offload)
                if ($null -eq $resolved) {
                    foreach ($entry in $allBindings) {
                        if ($entry.Port -eq '80') {
                            $resolved        = $entry.Site
                            $matchedPort     = '80'
                            $matchedProtocol = $entry.Protocol
                            $matchLabel      = 'port 80, catchall binding (SSL offload)'
                            break
                        }
                    }
                }

                if ($null -eq $resolved) {
                    rCheck 'IIS' 'Site Resolution' 'Fail' 'No IIS sites with a port 443 or port 80 binding found' 'Create an IIS website with an appropriate binding on port 443 (HTTPS) or port 80 (HTTP if SSL is offloaded at the NetScaler)'
                } else {
                    $SiteName      = $resolved.Name
                    $AppPoolName   = $resolved.applicationPool
                    $sslOffload    = $matchedProtocol -eq 'http'
                    $resolvedPort  = [int]$matchedPort
                    $resolvedProto = $matchedProtocol

                    # Confidence-based status:
                    #   Exact hostname match  — Pass (high confidence, correct site identified)
                    #   Port 443 catchall     — Warn (medium confidence, no hostname verification)
                    #   Port 80 catchall      — Warn (SSL offload, operator should confirm intent)
                    if ($hasSAN -and -not $sslOffload -and $matchLabel -like 'exact*') {
                        $resStatus = 'Pass'
                        $resRemedy = $null
                    } elseif (-not $sslOffload) {
                        $resStatus = 'Warn'
                        $resRemedy = "Site resolved by port 443 catchall — no binding hostname matched '$ExpectedSAN'. Provide SiteName explicitly or add a host-header binding for '$ExpectedSAN' to improve detection confidence"
                    } else {
                        $resStatus = 'Warn'
                        $resRemedy = "SSL is terminated at the NetScaler — Direct TLS checks will be replaced with HTTP checks on port $resolvedPort. If this is unexpected, verify the IIS site bindings"
                    }

                    rCheck 'IIS' 'Site Resolution' $resStatus "Resolved '$SiteName' via $matchLabel | AppPool: '$AppPoolName'" $resRemedy
                }
            } catch {
                rCheck 'IIS' 'Site Resolution' 'Fail' "Auto-detection failed: $($_.Exception.Message)" 'Provide SiteName and AppPoolName explicitly in the server hashtable'
            }
        }
    }

    if ($webAdminAvailable -and -not [string]::IsNullOrWhiteSpace($SiteName)) {
        # --- Website state ---
        try {
            $site = Get-Website -Name $SiteName -ErrorAction Stop
            if ($null -eq $site) {
                rCheck 'IIS' 'Website Exists' 'Fail' "Site '$SiteName' not found" "Create the IIS website named '$SiteName' using IIS Manager or: New-Website -Name '$SiteName'"
            } else {
                rCheck 'IIS' 'Website Exists' 'Pass' "Site '$SiteName' found (ID: $($site.Id))"
                $siteState         = $site.State
                $siteStartedStatus = if ($siteState -eq 'Started') { 'Pass' } else { 'Fail' }
                $siteStartedRemedy = if ($siteState -ne 'Started') { "Start the site in IIS Manager or run: Start-Website -Name '$SiteName' — check the Application Event Log if the site fails to start" } else { $null }
                rCheck 'IIS' 'Website Started' $siteStartedStatus "State: $siteState" $siteStartedRemedy
            }
        } catch {
            rCheck 'IIS' 'Website Exists' 'Fail' $_.Exception.Message 'Verify the WebAdministration module loaded correctly and the IIS configuration is not corrupt'
        }

        # --- App pool state ---
        if (-not [string]::IsNullOrWhiteSpace($AppPoolName)) {
            try {
                $pool = Get-WebConfiguration -Filter "system.applicationHost/applicationPools/add[@name='$AppPoolName']"
                if ($null -eq $pool) {
                    rCheck 'IIS' 'Application Pool Exists' 'Fail' "App pool '$AppPoolName' not found" "Create the application pool: New-WebAppPool -Name '$AppPoolName', then assign it to the site"
                } else {
                    rCheck 'IIS' 'Application Pool Exists' 'Pass' "App pool '$AppPoolName' found"
                    $poolState         = (Get-WebAppPoolState -Name $AppPoolName).Value
                    $poolStartedStatus = if ($poolState -eq 'Started') { 'Pass' } else { 'Fail' }
                    $poolStartedRemedy = if ($poolState -ne 'Started') { "Start the app pool: Start-WebAppPool -Name '$AppPoolName' — if it crashes on start, check the Application Event Log and HTTP Error logs for the failure reason" } else { $null }
                    rCheck 'IIS' 'Application Pool Started' $poolStartedStatus "State: $poolState" $poolStartedRemedy
                }
            } catch {
                rCheck 'IIS' 'Application Pool Exists' 'Fail' $_.Exception.Message 'Verify the WebAdministration module loaded correctly and the IIS configuration is not corrupt'
            }
        }

        # --- Binding check ---
        try {
            $bindings     = Get-WebBinding -Name $SiteName -ErrorAction Stop
            $httpsBindings = $bindings | Where-Object { $_.protocol -eq 'https' }
            $has80         = $bindings | Where-Object { $_.bindingInformation -match ':80:' }

            if ($httpsBindings) {
                $bindingInfo = ($httpsBindings | ForEach-Object { $_.bindingInformation }) -join ', '
                rCheck 'IIS' 'Site Binding' 'Pass' "HTTPS binding(s) found: $bindingInfo"
            } elseif ($has80) {
                rCheck 'IIS' 'Site Binding' 'Warn' "No HTTPS binding — port 80 binding present: $($has80.bindingInformation). SSL likely offloaded at NetScaler" 'If SSL offload is intentional no action is needed. If HTTPS should terminate at IIS, add an HTTPS binding on port 443 and bind a certificate'
            } else {
                rCheck 'IIS' 'Site Binding' 'Fail' "No HTTPS or HTTP binding on site '$SiteName'" "Add an HTTPS binding on port 443: New-WebBinding -Name '$SiteName' -Protocol https -Port 443, then assign the certificate in IIS Manager under Site Bindings"
            }

            # SNI check per HTTPS binding — sslFlags bit 0 indicates SNI is enabled
            if ($httpsBindings) {
                foreach ($hb in $httpsBindings) {
                    $sslFlags = 0
                    try { $sslFlags = [int]$hb.sslFlags } catch {}
                    $sniEnabled = ($sslFlags -band 1) -eq 1
                    $parts      = $hb.bindingInformation -split ':'
                    $bPort      = if ($parts.Count -ge 2) { $parts[1] } else { '?' }
                    $bHost      = if ($parts.Count -ge 3) { $parts[2].Trim() } else { '' }
                    $bLabel     = if ($bHost) { "${bHost}:${bPort}" } else { "*:${bPort}" }
                    if ($sniEnabled) {
                        rCheck 'IIS' 'Site Binding SNI' 'Pass' "SNI enabled on HTTPS binding $bLabel (sslFlags=$sslFlags)"
                    } else {
                        rCheck 'IIS' 'Site Binding SNI' 'Warn' "SNI not enabled on HTTPS binding $bLabel (sslFlags=$sslFlags)" "Enable SNI on this binding in IIS Manager (Edit Site Binding > Require Server Name Indication) or run: Set-WebBinding -Name '$SiteName' -BindingInformation '$($hb.bindingInformation)' -PropertyName sslFlags -Value 1"
                    }
                }
            } else {
                rCheck 'IIS' 'Site Binding SNI' 'Skip' 'No HTTPS bindings to check for SNI'
            }
        } catch {
            rCheck 'IIS' 'Site Binding' 'Fail' $_.Exception.Message 'Unable to query site bindings. Verify the site exists and the WebAdministration module is loaded'
        }

        # --- URL Rewrite module ---
        try {
            $rewrite       = Get-WebGlobalModule -Name 'RewriteModule' -ErrorAction Stop
            $rewriteStatus = if ($null -ne $rewrite) { 'Pass' } else { 'Warn' }
            $rewriteDetail = if ($null -ne $rewrite) { "RewriteModule found: $($rewrite.Image)" } else { 'RewriteModule not registered in IIS global modules' }
            $rewriteRemedy = if ($null -eq $rewrite) { 'Download and install the IIS URL Rewrite module from Microsoft (iis.net/downloads/microsoft/url-rewrite), then verify it appears under IIS > Modules' } else { $null }
            rCheck 'IIS' 'URL Rewrite Module' $rewriteStatus $rewriteDetail $rewriteRemedy
        } catch {
            rCheck 'IIS' 'URL Rewrite Module' 'Warn' "Could not query global modules: $($_.Exception.Message)" 'Verify the WebAdministration module is loaded and IIS configuration is accessible'
        }
    }

    # --- Certificate checks ---
    # Leaf cert looked up in LocalMachine\My; chain CAs verified against LocalMachine\Root
    try {
        $storePersonal = [System.Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine')
        $storePersonal.Open('ReadOnly')
        $personalCerts = $storePersonal.Certificates
        $storePersonal.Close()

        $storeRoot = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
        $storeRoot.Open('ReadOnly')
        $rootCerts = $storeRoot.Certificates
        $storeRoot.Close()

        $now         = [datetime]::UtcNow
        $threshold   = $now.AddDays($CertExpiryThresholdDays)
        $matchedCert = $null

        # --- Leaf cert: search LocalMachine\My then LocalMachine\Root ---
        $allCerts   = @($personalCerts) + @($rootCerts)
        $foundStore = $null

        if ($ExpectedSAN) {
            # Match on SAN across both stores
            $sanMatchStatus = 'Fail'
            foreach ($cert in $allCerts) {
                $sans = @()
                try {
                    $sanExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
                    if ($sanExt) {
                        $sans = $sanExt.Format($true) -split "`r?`n" |
                                    ForEach-Object { $_.Trim() } |
                                    Where-Object { $_ } |
                                    ForEach-Object { ($_ -replace '^.*?=', '').Trim() }
                    }
                } catch {}
                $privateSuffixes  = @('.local', '.corp', '.internal')
                $sanMatchStatus   = 'Fail'
                foreach ($san in $sans) {
                    if ($san -eq $ExpectedSAN) { $sanMatchStatus = 'Pass'; break }
                    if ($san -match '^\*\.') {
                        $wildcardSuffix = $san.Substring(1)
                        $prefix = $ExpectedSAN.Substring(0, [Math]::Max(0, $ExpectedSAN.Length - $wildcardSuffix.Length))
                        if ($ExpectedSAN -like "*$wildcardSuffix" -and $prefix -notmatch '\.') {
                            $isPrivate = $false
                            foreach ($suffix in $privateSuffixes) {
                                if ($wildcardSuffix -eq $suffix -or $wildcardSuffix -like "*$suffix") {
                                    $isPrivate = $true; break
                                }
                            }
                            $sanMatchStatus = if ($isPrivate) { 'Pass' } else { 'Warn' }
                            break
                        }
                    }
                }
                if ($sanMatchStatus -ne 'Fail') {
                    $matchedCert = $cert
                    $foundStore  = if ($personalCerts | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }) { 'LocalMachine\My' } else { 'LocalMachine\Root' }
                    break
                }
            }
            $sanStatus = if ($null -ne $matchedCert) { $sanMatchStatus } else { 'Fail' }
            $sanDetail = if ($null -ne $matchedCert) { "Cert matched on SAN '$ExpectedSAN' in $foundStore | Thumbprint: $($matchedCert.Thumbprint)" } else { "No cert in LocalMachine\My or LocalMachine\Root matched SAN '$ExpectedSAN'" }
            $sanRemedy = switch ($sanStatus) {
                'Fail' { "Import a certificate with '$ExpectedSAN' as a SAN entry into LocalMachine\My or LocalMachine\Root, then bind it to the IIS site on port 443" }
                'Warn' { "Wildcard SAN matched '$ExpectedSAN' on a public domain. Verify this is intentional and that the wildcard scope is acceptable for this service" }
                default { $null }
            }
            rCheck 'Certificate' 'Leaf SAN Match' $sanStatus $sanDetail $sanRemedy
        } else {
            # No SAN provided — resolve by IIS binding thumbprint first, then fall back to newest across both stores
            if ($webAdminAvailable) {
                try {
                    $binding443 = Get-WebBinding -Name $SiteName -Protocol 'https' | Select-Object -First 1
                    if ($binding443) {
                        $boundThumbprint = (Get-Item 'IIS:\SslBindings\0.0.0.0!443' -ErrorAction Stop).Thumbprint
                        $matchedCert     = $allCerts | Where-Object { $_.Thumbprint -eq $boundThumbprint } | Select-Object -First 1
                        if ($null -ne $matchedCert) {
                            $foundStore = if ($personalCerts | Where-Object { $_.Thumbprint -eq $boundThumbprint }) { 'LocalMachine\My' } else { 'LocalMachine\Root' }
                        }
                    }
                } catch {}
            }
            if (-not $matchedCert) {
                $matchedCert = $allCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
                if ($null -ne $matchedCert) {
                    $foundStore = if ($personalCerts | Where-Object { $_.Thumbprint -eq $matchedCert.Thumbprint }) { 'LocalMachine\My' } else { 'LocalMachine\Root' }
                }
            }
            $locatedStatus = if ($null -ne $matchedCert) { 'Pass' } else { 'Warn' }
            $locatedDetail = if ($null -ne $matchedCert) { "Using cert Thumbprint: $($matchedCert.Thumbprint) from $foundStore" } else { 'No certs found in LocalMachine\My or LocalMachine\Root' }
            $locatedRemedy = if ($null -eq $matchedCert) { 'No certificate found in either store. Import a valid certificate into LocalMachine\My and bind it to the IIS site on port 443' } else { $null }
            rCheck 'Certificate' 'Leaf Cert Located' $locatedStatus $locatedDetail $locatedRemedy
        }

        if ($null -ne $matchedCert) {
            $iisThumbprint = $matchedCert.Thumbprint
            # Leaf expiry
            $expiry   = $matchedCert.NotAfter.ToUniversalTime()
            $daysLeft = ($expiry - $now).Days
            $expiryStatus = if ($expiry -gt $threshold) { 'Pass' } else { 'Warn' }
            $expiryRemedy = if (-not ($expiry -gt $threshold)) { "Certificate expires in $daysLeft days. Renew the certificate, import it into the appropriate store, and rebind it in IIS before expiry" } else { $null }
            rCheck 'Certificate' "Leaf Expiry (threshold: $CertExpiryThresholdDays days)" `
                $expiryStatus `
                "Expires: $($expiry.ToString('yyyy-MM-dd')) UTC ($daysLeft days remaining) | Thumbprint: $($matchedCert.Thumbprint)" `
                $expiryRemedy

            # Build chain — used both for overall validity and to enumerate CA certs for Root store checks
            try {
                $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $valid  = $chain.Build($matchedCert)

                $chainStatus = if ($valid) { 'Pass' } else { 'Warn' }
                $chainDetail = if ($valid) {
                    'Chain valid'
                } else {
                    $chainIssues = ($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() } | Where-Object { $_ }) -join '; '
                    $aiaUrl = $null
                    $aiaExt = $matchedCert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }
                    if ($aiaExt) {
                        $aiaText = $aiaExt.Format($false)
                        $aiaUrl = if ($aiaText -match 'CA Issuers[^U]*URI:(\S+)') { $Matches[1] } else { $null }
                    }
                    $aiaFragment = if ($aiaUrl) { " | AIA: $aiaUrl" } else { '' }
                    "Chain issues: $chainIssues$aiaFragment"
                }
                $chainRemedy = if (-not $valid) {
                    if ($aiaUrl) { 'Download the intermediate CA certificate from the AIA URL shown in Detail, verify its thumbprint with your CA team, then install into LocalMachine\CA on this server' }
                    else { 'Install missing intermediate or root CA certificates into LocalMachine\CA and LocalMachine\Root respectively, then verify with: certutil -verify -urlfetch <certfile>' }
                } else { $null }
                rCheck 'Certificate' 'Leaf Chain Valid' $chainStatus $chainDetail $chainRemedy

                # --- CA certs: verify each chain element (skip index 0 — that is the leaf) exists in LocalMachine\Root ---
                $caElements = $chain.ChainElements | Select-Object -Skip 1
                foreach ($element in $caElements) {
                    $caCert    = $element.Certificate
                    $caSubject = $caCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                    $caThumb   = $caCert.Thumbprint
                    $caExpiry  = $caCert.NotAfter.ToUniversalTime()
                    $caDays    = ($caExpiry - $now).Days
                    $isRoot    = $caCert.Subject -eq $caCert.Issuer

                    $caLabel   = if ($isRoot) { 'Root CA' } else { 'Intermediate CA' }

                    # Presence in Root store
                    $inRoot     = $null -ne ($rootCerts | Where-Object { $_.Thumbprint -eq $caThumb })
                    $presStatus = if ($inRoot) { 'Pass' } else { 'Warn' }
                    $presDetail = if ($inRoot) {
                        "$caLabel '$caSubject' present in LocalMachine\Root | Thumbprint: $caThumb"
                    } else {
                        "$caLabel '$caSubject' NOT found in LocalMachine\Root | Thumbprint: $caThumb"
                    }
                    $presRemedy = if (-not $inRoot) { "Import the '$caSubject' $caLabel certificate into LocalMachine\Root on this server. Obtain it from your CA or extract it from the certificate chain using: certutil -dump <certfile>" } else { $null }
                    rCheck 'Certificate' "$caLabel Present in Root Store" $presStatus $presDetail $presRemedy

                    # CA cert expiry
                    $caExpiryStatus = if ($caExpiry -gt $threshold) { 'Pass' } else { 'Warn' }
                    $caExpiryRemedy = if (-not ($caExpiry -gt $threshold)) { "The '$caSubject' $caLabel certificate expires in $caDays days. Contact your CA to obtain a renewed CA certificate and distribute it to all servers and clients before expiry" } else { $null }
                    rCheck 'Certificate' "$caLabel Expiry" `
                        $caExpiryStatus `
                        "Expires: $($caExpiry.ToString('yyyy-MM-dd')) UTC ($caDays days remaining) | Subject: '$caSubject' | Thumbprint: $caThumb" `
                        $caExpiryRemedy
                }
            } catch {
                rCheck 'Certificate' 'Leaf Chain Valid' 'Warn' "Chain build failed: $($_.Exception.Message)" 'Unable to build certificate chain on the server. Verify intermediate CA certificates are installed and the certificate store is not corrupted'
            }

            # Revocation (opt-in)
            if ($CheckRevocation) {
                # Part 1: X509Chain revocation verdict
                try {
                    $revChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                    $revChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                    $revChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                    $revChain.ChainPolicy.UrlRetrievalTimeout = [timespan]::FromSeconds(10)
                    $revValid = $revChain.Build($matchedCert)
                    $revoked = $revChain.ChainStatus | Where-Object { $_.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked }
                    $offlineOrTimeout = $revChain.ChainStatus | Where-Object {
                        $_.Status -band ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -bor
                                         [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation)
                    }
                    if ($revoked) {
                        rCheck 'Certificate' 'Leaf Revocation' 'Fail' "Certificate is revoked | Thumbprint: $($matchedCert.Thumbprint)" 'This certificate has been revoked by the issuing CA. Obtain a new certificate immediately and rebind it in IIS'
                    } elseif ($offlineOrTimeout) {
                        $issues = ($offlineOrTimeout | ForEach-Object { $_.StatusInformation.Trim() } | Where-Object { $_ }) -join '; '
                        rCheck 'Certificate' 'Leaf Revocation' 'Warn' "Revocation check inconclusive — CRL/OCSP endpoint unreachable: $issues | Thumbprint: $($matchedCert.Thumbprint)" 'CRL or OCSP endpoint is unreachable from this server. Verify outbound HTTP/LDAP access to the CRL distribution points listed in the certificate'
                    } elseif ($revValid) {
                        rCheck 'Certificate' 'Leaf Revocation' 'Pass' "Revocation check passed | Thumbprint: $($matchedCert.Thumbprint)"
                    } else {
                        $issues = ($revChain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() } | Where-Object { $_ }) -join '; '
                        rCheck 'Certificate' 'Leaf Revocation' 'Warn' "Revocation check inconclusive — chain issues: $issues | Thumbprint: $($matchedCert.Thumbprint)" 'Resolve chain trust issues first, then re-run with -CheckRevocation'
                    }
                } catch {
                    rCheck 'Certificate' 'Leaf Revocation' 'Warn' "Revocation check failed: $($_.Exception.Message) | Thumbprint: $($matchedCert.Thumbprint)" 'Unable to perform revocation check. Verify CRL/OCSP endpoint reachability and certificate store integrity'
                }

                # Part 2: CRL Distribution Point reachability (TCP connectivity from server)
                $cdpExt = $matchedCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.31' }
                if ($cdpExt) {
                    $cdpText = $cdpExt.Format($false)
                    $cdpUrls = [System.Collections.Generic.List[string]]::new()
                    $cdpRegex = [regex]'URL=(\S+)'
                    foreach ($m in $cdpRegex.Matches($cdpText)) {
                        $cdpUrls.Add($m.Groups[1].Value)
                    }
                    foreach ($cdpUrl in $cdpUrls) {
                        try {
                            $uri = [System.Uri]::new($cdpUrl)
                            $cdpHost = $uri.Host
                            $cdpPort = if ($uri.Port -gt 0 -and $uri.Port -ne -1) { $uri.Port }
                                       elseif ($uri.Scheme -eq 'https') { 443 }
                                       else { 80 }
                            $tnc = Test-NetConnection -ComputerName $cdpHost -Port $cdpPort -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
                            $tncStatus = if ($tnc) { 'Pass' } else { 'Fail' }
                            $tncDetail = if ($tnc) { "CRL endpoint reachable: $cdpUrl | Host: $cdpHost Port: $cdpPort" }
                                         else { "CRL endpoint unreachable: $cdpUrl | Host: $cdpHost Port: $cdpPort" }
                            $tncRemedy = if (-not $tnc) { "Open firewall access from this server to $cdpHost on port $cdpPort to allow CRL downloads for certificate revocation checking" } else { $null }
                            rCheck 'Certificate' 'CRL Reachability' $tncStatus $tncDetail $tncRemedy
                        } catch {
                            rCheck 'Certificate' 'CRL Reachability' 'Fail' "CRL endpoint test failed for $cdpUrl — $($_.Exception.Message)" 'Verify the CRL distribution point URL is valid and accessible from this server'
                        }
                    }
                } else {
                    rCheck 'Certificate' 'CRL Reachability' 'Info' "No CRL Distribution Point URLs found in certificate | Thumbprint: $($matchedCert.Thumbprint)"
                }
            }
        }
    } catch {
        rCheck 'Certificate' 'Certificate Store Access' 'Fail' $_.Exception.Message 'Unable to open the certificate store. Verify the script is running with sufficient privileges (local administrator) on the target server'
    }

    # Return checks and metadata as a single hashtable (serialisation-safe)
    return @{
        Checks           = $results.ToArray()
        SslOffload       = $sslOffload
        IISThumbprint    = $iisThumbprint
        ResolvedPort     = $resolvedPort
        ResolvedProtocol = $resolvedProto
        RemoteSourceIP   = $remoteSourceIP
    }
}

#endregion

#region --- Main function ---

function Test-IISServerReadiness {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Servers,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [int]$CertExpiryThresholdDays = 30,

        [Parameter()]
        [switch]$CheckRevocation
    )

    foreach ($server in $Servers) {
        # Only Name is required — SiteName/AppPoolName are auto-detected remotely if absent
        if (-not $server.ContainsKey('Name') -or [string]::IsNullOrWhiteSpace($server['Name'])) {
            Write-Error "Server entry missing required key 'Name'. Skipping."
            continue
        }

        $name        = $server.Name
        $vip         = $server.ExpectedVIP
        $siteName    = if ($server.ContainsKey('SiteName'))    { $server.SiteName }    else { $null }
        $poolName    = if ($server.ContainsKey('AppPoolName')) { $server.AppPoolName } else { $null }
        $expectedSAN = $server.ExpectedSAN
        $serverIP    = $server.ServerIP
        $winRMPort      = if ($server.ContainsKey('WinRMPort'))      { $server.WinRMPort }      else { 5985 }
        $expectedVIPPort = if ($server.ContainsKey('ExpectedVIPPort')) { [int]$server.ExpectedVIPPort } else { 443 }

        Write-Verbose "[$name] Starting checks..."
        $allChecks = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Resolve the workstation's outbound IP once — stamped on every output row for this server.
        # Uses the first non-loopback IPv4 address found on the workstation's network interfaces.
        $sourceIP = $null
        try {
            $sourceIP = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' -and $_.ToString() -ne '127.0.0.1' } |
                Select-Object -First 1 -ExpandProperty IPAddressToString
        } catch {
            $sourceIP = 'unknown'
        }

        # --- Workstation-side ---
        Write-Verbose "[$name] Network layer..."
        Test-NetworkLayer -ServerName $name -WinRMPort $winRMPort -SourceIP $sourceIP | ForEach-Object { $allChecks.Add($_) }

        Write-Verbose "[$name] DNS layer..."
        if (-not [string]::IsNullOrWhiteSpace($expectedSAN)) {
            Test-DNSLayer -Hostname $expectedSAN -ExpectedVIP $vip -SourceIP $sourceIP | ForEach-Object { $allChecks.Add($_) }
        } else {
            $allChecks.Add((New-Check -Layer 'DNS' -Name 'DNS Checks' -Status 'Skip' `
                -Detail 'Skipped — ExpectedSAN not provided, no hostname to resolve' `
                -Remedy 'Provide ExpectedSAN in the server hashtable to enable DNS checks' `
                -SourceIP $sourceIP))
        }

        Write-Verbose "[$name] WinRM layer..."
        $winrmChecks = Test-WinRMLayer -ServerName $name -Credential $Credential -SourceIP $sourceIP
        $winrmChecks | ForEach-Object { $allChecks.Add($_) }

        if ($winRMPort -eq 5986) {
            $allChecks.Add((New-Check -Layer 'WinRM' -Name 'WinRM HTTPS Transport' -Status 'Warn' `
                -Detail 'WinRMPort is 5986 (HTTPS) but the script connects over HTTP transport' `
                -Remedy 'WinRM HTTPS (-UseSSL) is not yet supported; connections use HTTP regardless of port setting. Use port 5985 or note that traffic is unencrypted' `
                -SourceIP $sourceIP -DestinationIP $name))
        }

        # Only attempt remote checks if Invoke-Command succeeded
        $canRemote     = ($winrmChecks | Where-Object { $_.Name -eq 'Invoke-Command Execution' -and $_.Status -eq 'Pass' }) -ne $null
        $iisThumbprint = $null
        $sslOffload    = $false
        $resolvedPort  = 443
        $resolvedProto = 'https'

        if ($canRemote) {
            Write-Verbose "[$name] Dispatching server-side checks via Invoke-Command..."
            try {
                $icmOpts = @{
                    ComputerName = $name
                    ScriptBlock  = $RemoteScriptBlock
                    ArgumentList = $siteName, $poolName, $expectedSAN, $CertExpiryThresholdDays, $CheckRevocation.IsPresent
                    ErrorAction  = 'Stop'
                }
                if ($Credential) { $icmOpts.Credential = $Credential }

                $remoteRaw = Invoke-Command @icmOpts

                # Unpack return hashtable — Checks array + metadata
                $sslOffload      = $false
                $remoteChecks    = $null
                $iisThumbprint   = $null
                $resolvedPort    = 443
                $resolvedProto   = 'https'
                $remoteSourceIP  = $null
                if ($remoteRaw -is [hashtable]) {
                    $sslOffload     = $remoteRaw.SslOffload -eq $true
                    $remoteChecks   = $remoteRaw.Checks
                    $iisThumbprint  = $remoteRaw.IISThumbprint
                    $resolvedPort   = if ($remoteRaw.ContainsKey('ResolvedPort') -and $remoteRaw.ResolvedPort) { [int]$remoteRaw.ResolvedPort } else { 443 }
                    $resolvedProto  = if ($remoteRaw.ContainsKey('ResolvedProtocol') -and $remoteRaw.ResolvedProtocol) { $remoteRaw.ResolvedProtocol } else { 'https' }
                    $remoteSourceIP = $remoteRaw.RemoteSourceIP
                } else {
                    # Fallback: older shape returned bare array (shouldn't occur but defensive)
                    $remoteChecks = $remoteRaw
                }

                # Deserialise check hashtable array back to PSCustomObjects
                # Remote checks use the remote server's SourceIP; DestinationIP is $null
                # since they execute inside the remoting session, not via workstation TCP.
                foreach ($r in $remoteChecks) {
                    $allChecks.Add([PSCustomObject]@{
                        Layer         = $r.Layer
                        Name          = $r.Name
                        Status        = $r.Status
                        Detail        = $r.Detail
                        SourceIP      = $remoteSourceIP
                        DestinationIP = $null
                    })
                }
            } catch {
                $allChecks.Add((New-Check -Layer 'Remote' -Name 'Server-side Check Dispatch' `
                    -Status 'Fail' -Detail "Invoke-Command failed during remote checks: $($_.Exception.Message)" `
                    -Remedy 'Resolve WinRM connectivity issues above. Verify the account has remote execution rights and the execution policy on the target allows the script to run'))
            }
        } else {
            $allChecks.Add((New-Check -Layer 'Remote' -Name 'Server-side Checks' `
                -Status 'Skip' -Detail 'Skipped — WinRM connectivity check failed' `
                -Remedy 'Resolve the WinRM layer failures above before server-side IIS and certificate checks can run'))
        }

        Write-Verbose "[$name] TLS/HTTPS layer..."
        Test-TLSLayer -ServerName $name -ServerIP $serverIP -ExpectedVIP $vip -ExpectedSAN $expectedSAN `
            -CertExpiryThresholdDays $CertExpiryThresholdDays -IISThumbprint $iisThumbprint `
            -SslOffload $sslOffload -SourceIP $sourceIP `
            -ResolvedPort $resolvedPort -ResolvedProtocol $resolvedProto -ExpectedVIPPort $expectedVIPPort `
            -CheckRevocation $CheckRevocation |
            ForEach-Object { $allChecks.Add($_) }

        $checkedAt = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

        foreach ($check in $allChecks) {
            # Use the check's own SourceIP if set (remote checks carry the server's IP);
            # fall back to workstation SourceIP for workstation-side checks.
            $checkSourceIP = if (-not [string]::IsNullOrWhiteSpace($check.SourceIP)) { $check.SourceIP } else { $sourceIP }
            [PSCustomObject]@{
                ServerName    = $name
                CheckedAt     = $checkedAt
                SourceIP      = $checkSourceIP
                DestinationIP = $check.DestinationIP
                Layer         = $check.Layer
                Name          = $check.Name
                Status        = $check.Status
                Detail        = $check.Detail
            }
        }

        Write-Verbose "[$name] Done."
    }
}

#endregion

#region --- Entry point ---

$splat = @{
    Servers                 = $Servers
    CertExpiryThresholdDays = $CertExpiryThresholdDays
}
if ($Credential)      { $splat.Credential      = $Credential }
if ($CheckRevocation) { $splat.CheckRevocation  = $CheckRevocation }

Test-IISServerReadiness @splat

#endregion