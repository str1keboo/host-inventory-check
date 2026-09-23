<#
.SYNOPSIS
    Checks whether hosts are enrolled in SentinelOne, Wazuh, and Rapid7 InsightVM,
    and reports coverage gaps.

.DESCRIPTION
    Input is a headerless CSV: hostname,ip - either field may be blank.

        web01,10.0.0.10     -> hostname first, IP as fallback
        appliance01,        -> hostname only
        ,10.0.0.20          -> IP only

    For each host in each enabled console: match by hostname first, fall back to IP.
    Output is a CSV plus a console summary of hosts missing from one or more consoles.

    Credentials are never stored in this file. They are read from a SecretManagement
    vault, then environment variables, then an interactive prompt. See README.md.

.NOTES
    Runs on Windows PowerShell 5.1 and PowerShell 7+.
#>

#region ================= CONFIG =================

# ---- Input / output ----
$InputCsvPath  = ".\hosts.csv"                        # headerless: hostname,ip
$OutputCsvPath = ".\host-inventory-check-results.csv"

# ---- Which consoles to query ----
$EnableSentinelOne = $true
$EnableWazuh       = $true
$EnableRapid7      = $true

# ---- SentinelOne ----
# Your console hostname, e.g. https://euce1-000.sentinelone.net
$S1BaseUrl = "https://<your-tenant>.sentinelone.net"

# ---- Wazuh ----
# 'direct'    = self-managed manager, Server API on :55000
# 'dashboard' = Wazuh Cloud, proxied through the dashboard plugin
$WazuhMode = "dashboard"

# direct mode only
$WazuhBaseUrl = "https://<wazuh-manager>:55000"

# Allow self-signed certificates when talking to Wazuh in direct mode.
# Only takes effect on PowerShell 7+, and only for Wazuh requests.
# Leave $false unless your on-prem manager uses a self-signed cert.
$AllowSelfSignedWazuh = $false

# dashboard mode only
$WazuhDashUrl = "https://<your-env>.cloud.wazuh.com"
$WazuhIdHost  = ""     # blank = auto-discover from /hosts/apis (usually "1")

# ---- Rapid7 InsightVM ----
# Region codes: us, us2, us3, eu, ca, au, ap, aps2, me1
$R7Region  = "<region>"
$R7BaseUrl = "https://$R7Region.api.insight.rapid7.com/vm/v4/integration"

#endregion ========================================

$ErrorActionPreference = "Stop"

# ---------- PowerShell version compatibility ----------
$script:IsPS7Plus = $PSVersionTable.PSVersion.Major -ge 7
if (-not $script:IsPS7Plus) {
    # Windows PowerShell 5.1 may default to TLS 1.0/1.1, which these APIs reject.
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 }
    catch { Write-Warning "Could not force TLS 1.2." }
}

# ---------- Credential retrieval ----------
function Get-SocSecret {
    param(
        [Parameter(Mandatory)][string]$Name,   # vault secret name
        [Parameter(Mandatory)][string]$EnvVar, # environment variable name
        [string]$Prompt                        # text shown if we must ask
    )

    # 1. SecretManagement vault
    if (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement) {
        try {
            $s = Get-Secret -Name $Name -AsPlainText -ErrorAction Stop
            if ($s) { return $s }
        } catch { }   # not set in vault - fall through
    }

    # 2. Environment variable
    $envVal = [Environment]::GetEnvironmentVariable($EnvVar, 'User')
    if (-not $envVal) { $envVal = [Environment]::GetEnvironmentVariable($EnvVar, 'Process') }
    if ($envVal) { return $envVal }

    # 3. Prompt (not persisted)
    if (-not $Prompt) { $Prompt = $Name }
    $sec = Read-Host -Prompt "Enter $Prompt" -AsSecureString
    return [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    )
}

# ---------- HTTP helper ----------
function Invoke-SafeRest {
    param(
        [string]$Uri, [string]$Method = "GET", [hashtable]$Headers, $Body,
        [string]$ContentType = "application/json", [string]$ConsoleName = "Console",
        $WebSession, [int]$TimeoutSec = 60
    )
    try {
        $p = @{ Uri=$Uri; Method=$Method; Headers=$Headers; TimeoutSec=$TimeoutSec; ErrorAction="Stop" }

        # Certificate validation stays ON by default. It is only relaxed for Wazuh in
        # direct mode, when explicitly opted in, and only on PS7+ where the parameter exists.
        if ($script:IsPS7Plus -and $AllowSelfSignedWazuh -and
            $WazuhMode -eq 'direct' -and $ConsoleName -like 'Wazuh*') {
            $p["SkipCertificateCheck"] = $true
        }

        if ($Body)       { $p["Body"] = $Body; $p["ContentType"] = $ContentType }
        if ($WebSession) { $p["WebSession"] = $WebSession }
        return @{ Success = $true; Data = (Invoke-RestMethod @p); Error = $null }
    }
    catch {
        $code = $null
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        $msg = $_.Exception.Message
        $hint = switch -Regex ($msg) {
            "could not be resolved|No such host" { "DNS failure - check the hostname." }
            "actively refused|refused"           { "Port closed or blocked." }
            "timed out|timeout"                  { "Timed out - firewall block or wrong port." }
            default { $null }
        }
        if ($code -eq 401) { $hint = "401 - credentials/token wrong or expired." }
        if ($code -eq 403) { $hint = "403 - valid creds, insufficient permission." }
        if ($code -eq 404) { $hint = "404 - wrong URL path." }
        Write-Warning "[$ConsoleName] $Uri failed. HTTP $code. $msg$(if ($hint) { " -> $hint" })"
        return @{ Success = $false; Data = $null; Error = $msg }
    }
}

function ConvertTo-UrlSafe {
    param([string]$Value)
    return [System.Uri]::EscapeDataString($Value)
}

# ================= SENTINELONE =================
function Test-SentinelOneHost {
    param([string]$Hostname, [string]$IP)
    $result = [ordered]@{ Found=$false; MatchedBy="None"; MatchedValue=""; Details="" }
    if (-not $EnableSentinelOne) {
        $result.Details = "SentinelOne check disabled in config"
        return [pscustomobject]$result
    }

    $headers = @{ Authorization = "ApiToken $S1ApiToken" }

    if ($Hostname) {
        $q    = ConvertTo-UrlSafe $Hostname
        $uri  = "$S1BaseUrl/web/api/v2.1/agents?computerName__like=$q&limit=5"
        $resp = Invoke-SafeRest -Uri $uri -Headers $headers -ConsoleName "SentinelOne"
        if ($resp.Success -and $resp.Data.data.Count -gt 0) {
            $a = $resp.Data.data[0]
            $result.Found=$true; $result.MatchedBy="Hostname"; $result.MatchedValue=$a.computerName
            $result.Details = "Status: $($a.networkStatus); LastActive: $($a.lastActiveDate)"
            return [pscustomobject]$result
        }
    }
    if ($IP) {
        $q    = ConvertTo-UrlSafe $IP
        $uri  = "$S1BaseUrl/web/api/v2.1/agents?networkInterfaceInet__contains=$q&limit=5"
        $resp = Invoke-SafeRest -Uri $uri -Headers $headers -ConsoleName "SentinelOne"
        if ($resp.Success -and $resp.Data.data.Count -gt 0) {
            $a = $resp.Data.data[0]
            $result.Found=$true; $result.MatchedBy="IP"; $result.MatchedValue=$a.computerName
            $result.Details = "Matched via IP - console name differs from expected"
        }
    }
    return [pscustomobject]$result
}

# ================= WAZUH =================
$script:WzSession = $null
$script:WzIdHost  = $null
$script:WzReady   = $false
$script:WzLoginAt = $null
$script:WzTtlSec  = 780   # manager JWT lasts ~900s; refresh early
$script:WzToken   = $null # direct mode only

$script:WzHeaders = @{ "osd-xsrf" = "true"; "Content-Type" = "application/json" }

# ---- direct mode: self-managed manager on :55000 ----
function Connect-WazuhDirect {
    if ($script:WzToken -and $script:WzLoginAt -and
        ((Get-Date) - $script:WzLoginAt).TotalSeconds -lt $script:WzTtlSec) {
        return $true
    }
    $pair  = "$($WazuhUser):$($WazuhPassword)"
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $r = Invoke-SafeRest -Uri "$WazuhBaseUrl/security/user/authenticate?raw=true" -Method POST `
            -Headers @{ Authorization = "Basic $basic" } -ConsoleName "Wazuh (auth)"
    if (-not $r.Success) { $script:WzToken = $null; return $false }
    $script:WzToken   = $r.Data
    $script:WzLoginAt = Get-Date
    return $true
}

# ---- dashboard mode: Wazuh Cloud via the dashboard plugin proxy ----
function Connect-WazuhDashboard {
    if ($script:WzReady -and $script:WzLoginAt -and
        ((Get-Date) - $script:WzLoginAt).TotalSeconds -lt $script:WzTtlSec) {
        return $true
    }
    $script:WzReady = $false

    # 1. Dashboard session cookie
    try {
        $body = @{ username = $WazuhUser; password = $WazuhPassword } | ConvertTo-Json
        $null = Invoke-WebRequest -Uri "$WazuhDashUrl/auth/login" -Method POST -Body $body `
                    -Headers $script:WzHeaders -SessionVariable sv -TimeoutSec 30 `
                    -UseBasicParsing -ErrorAction Stop
        $script:WzSession = $sv
    } catch {
        Write-Warning "[Wazuh] Dashboard login failed: $($_.Exception.Message)"
        return $false
    }

    # 2. Resolve idHost - the registry ID from API Connections, not the cluster name
    if (-not $script:WzIdHost) {
        if ($WazuhIdHost) {
            $script:WzIdHost = $WazuhIdHost
        } else {
            $r = Invoke-SafeRest -Uri "$WazuhDashUrl/hosts/apis" -Headers $script:WzHeaders `
                    -WebSession $script:WzSession -ConsoleName "Wazuh"
            if ($r.Success) {
                foreach ($e in @($r.Data)) {
                    foreach ($item in @($e)) {
                        if ($item.id) { $script:WzIdHost = "$($item.id)"; break }
                    }
                    if ($script:WzIdHost) { break }
                }
            }
            if (-not $script:WzIdHost) { $script:WzIdHost = "1" }
        }
    }

    # 3. Plugin login - sets wz-token / wz-user / wz-api cookies on the session
    $r = Invoke-SafeRest -Uri "$WazuhDashUrl/api/login" -Method POST `
            -Body (@{ idHost = "$($script:WzIdHost)" } | ConvertTo-Json) `
            -Headers $script:WzHeaders -WebSession $script:WzSession -ConsoleName "Wazuh (api/login)"
    if (-not $r.Success) { return $false }

    $script:WzLoginAt = Get-Date
    $script:WzReady   = $true
    return $true
}

function Invoke-WazuhApi {
    param([string]$Path)

    if ($WazuhMode -eq 'direct') {
        if (-not (Connect-WazuhDirect)) { return $null }
        $r = Invoke-SafeRest -Uri "$WazuhBaseUrl$Path" `
                -Headers @{ Authorization = "Bearer $($script:WzToken)" } -ConsoleName "Wazuh"
        if (-not $r.Success) { return $null }
        return $r.Data.data.affected_items
    }

    if (-not (Connect-WazuhDashboard)) { return $null }

    $payload = @{ method = "GET"; path = $Path; body = @{}; id = "$($script:WzIdHost)" } |
               ConvertTo-Json -Depth 5

    # Send ONLY osd-xsrf. The plugin authenticates from the cookies set by /api/login;
    # adding an Authorization header overrides that and returns 401 "Authentication Exception".
    $r = Invoke-SafeRest -Uri "$WazuhDashUrl/api/request" -Method POST -Body $payload `
            -Headers $script:WzHeaders -WebSession $script:WzSession -ConsoleName "Wazuh"
    if (-not $r.Success) { return $null }

    $items = $r.Data.data.data.affected_items
    if ($null -eq $items) { $items = $r.Data.data.affected_items }
    if ($null -eq $items) { $items = $r.Data.affected_items }
    return $items
}

function Test-WazuhHost {
    param([string]$Hostname, [string]$IP)
    $result = [ordered]@{ Found=$false; MatchedBy="None"; MatchedValue=""; Details="" }
    if (-not $EnableWazuh) {
        $result.Details = "Wazuh check disabled in config"
        return [pscustomobject]$result
    }

    if ($Hostname) {
        $q = ConvertTo-UrlSafe $Hostname
        $items = Invoke-WazuhApi -Path "/agents?q=name=$q"
        if ($items -and @($items).Count -gt 0) {
            $a = @($items)[0]
            $result.Found=$true; $result.MatchedBy="Hostname"; $result.MatchedValue=$a.name
            $result.Details = "Status: $($a.status); IP: $($a.ip); LastKeepAlive: $($a.lastKeepAlive)"
            return [pscustomobject]$result
        }
    }
    if ($IP) {
        $q = ConvertTo-UrlSafe $IP
        $items = Invoke-WazuhApi -Path "/agents?q=ip=$q"
        if ($items -and @($items).Count -gt 0) {
            $a = @($items)[0]
            $result.Found=$true; $result.MatchedBy="IP"; $result.MatchedValue=$a.name
            $result.Details = "Matched via IP - agent name '$($a.name)' differs from expected; Status: $($a.status)"
        }
    }
    return [pscustomobject]$result
}

# ================= RAPID7 INSIGHTVM =================
function Get-R7Name {
    param($Asset)
    if ($Asset.host_name) { return $Asset.host_name }
    if ($Asset.hostName)  { return $Asset.hostName }
    if ($Asset.hostNames -and $Asset.hostNames.Count -gt 0) { return $Asset.hostNames[0].name }
    return "(name field not found)"
}

function Test-Rapid7Host {
    param([string]$Hostname, [string]$IP)
    $result = [ordered]@{ Found=$false; MatchedBy="None"; MatchedValue=""; Details="" }
    if (-not $EnableRapid7) {
        $result.Details = "Rapid7 check disabled in config"
        return [pscustomobject]$result
    }

    $headers = @{ "X-Api-Key" = $R7ApiKey }

    if ($Hostname) {
        # Single quotes are the string delimiter in Rapid7's query syntax - escape any in the value.
        $safe = $Hostname -replace "'", "''"
        $body = @{ asset = "asset.name CONTAINS '$safe'" } | ConvertTo-Json
        $resp = Invoke-SafeRest -Uri "$R7BaseUrl/assets?size=5" -Method POST -Headers $headers `
                    -Body $body -ConsoleName "Rapid7"
        if ($resp.Success -and $resp.Data.data.Count -gt 0) {
            $a = $resp.Data.data[0]
            $result.Found=$true; $result.MatchedBy="Hostname"; $result.MatchedValue=(Get-R7Name $a)
            $result.Details = "Asset ID: $($a.id)"
            return [pscustomobject]$result
        }
    }
    if ($IP) {
        $safe = $IP -replace "'", "''"
        $body = @{ asset = "asset.ip_address = '$safe'" } | ConvertTo-Json
        $resp = Invoke-SafeRest -Uri "$R7BaseUrl/assets?size=5" -Method POST -Headers $headers `
                    -Body $body -ConsoleName "Rapid7"
        if ($resp.Success -and $resp.Data.data.Count -gt 0) {
            $a = $resp.Data.data[0]
            $result.Found=$true; $result.MatchedBy="IP"; $result.MatchedValue=(Get-R7Name $a)
            $result.Details = "Matched via IP (Asset ID: $($a.id))"
        }
    }
    return [pscustomobject]$result
}

# ================= MAIN =================

# Validate input BEFORE asking for credentials, so a missing file doesn't cost
# the user four secret prompts first.
if (-not (Test-Path $InputCsvPath)) {
    Write-Error "Input CSV not found at '$InputCsvPath'. Plain lines: hostname,ip (no header row)."
    return
}
if (-not ($EnableSentinelOne -or $EnableWazuh -or $EnableRapid7)) {
    Write-Error "All consoles are disabled in config - nothing to check."
    return
}

# Only prompt for credentials the enabled consoles actually need.
if ($EnableSentinelOne) {
    $S1ApiToken = Get-SocSecret -Name 'S1ApiToken' -EnvVar 'S1_API_TOKEN' -Prompt 'SentinelOne API token'
}
if ($EnableWazuh) {
    $WazuhUser     = Get-SocSecret -Name 'WazuhUser'     -EnvVar 'WAZUH_USER'     -Prompt 'Wazuh username'
    $WazuhPassword = Get-SocSecret -Name 'WazuhPassword' -EnvVar 'WAZUH_PASSWORD' -Prompt 'Wazuh password'
}
if ($EnableRapid7) {
    $R7ApiKey = Get-SocSecret -Name 'R7ApiKey' -EnvVar 'R7_API_KEY' -Prompt 'Rapid7 API key'
}

$rows    = Import-Csv -Path $InputCsvPath -Header "Hostname","IP"
$report  = New-Object System.Collections.Generic.List[object]
$total   = @($rows).Count
$counter = 0

foreach ($row in $rows) {
    $counter++
    $hostname = if ($row.Hostname) { $row.Hostname.Trim() } else { "" }
    $ip       = if ($row.IP)       { $row.IP.Trim() }       else { "" }

    if (-not $hostname -and -not $ip) {
        Write-Host "[$counter/$total] Skipping blank row." -ForegroundColor DarkYellow
        continue
    }

    $label = if ($hostname -and $ip) { "$hostname ($ip)" }
             elseif ($hostname)      { "$hostname (no IP)" }
             else                    { "(no hostname) $ip" }
    Write-Host "[$counter/$total] Checking $label..." -ForegroundColor Cyan

    $s1 = Test-SentinelOneHost -Hostname $hostname -IP $ip
    $wz = Test-WazuhHost       -Hostname $hostname -IP $ip
    $r7 = Test-Rapid7Host      -Hostname $hostname -IP $ip

    $report.Add([pscustomobject]@{
        Hostname           = $hostname
        IP                 = $ip
        Wazuh_Found        = $wz.Found
        Wazuh_MatchedBy    = $wz.MatchedBy
        Wazuh_MatchedName  = $wz.MatchedValue
        Wazuh_Details      = $wz.Details
        S1_Found           = $s1.Found
        S1_MatchedBy       = $s1.MatchedBy
        S1_MatchedName     = $s1.MatchedValue
        S1_Details         = $s1.Details
        Rapid7_Found       = $r7.Found
        Rapid7_MatchedBy   = $r7.MatchedBy
        Rapid7_MatchedName = $r7.MatchedValue
        Missing_From       = (@(
                                if ($EnableWazuh       -and -not $wz.Found) { "Wazuh" }
                                if ($EnableSentinelOne -and -not $s1.Found) { "S1" }
                                if ($EnableRapid7      -and -not $r7.Found) { "Rapid7" }
                              ) -join ", ")
    })
}

$report | Select-Object Hostname, IP, Wazuh_Found, Wazuh_MatchedBy, S1_Found, S1_MatchedBy,
                        Rapid7_Found, Rapid7_MatchedBy, Missing_From | Format-Table -AutoSize
$report | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8

Write-Host "`nResults written to $OutputCsvPath" -ForegroundColor Green
$gaps = @($report | Where-Object { $_.Missing_From -ne "" })
if ($gaps.Count -gt 0) {
    Write-Host "`n$($gaps.Count) host(s) with coverage gaps (check any warnings above):" -ForegroundColor Yellow
    $gaps | Select-Object Hostname, IP, Missing_From | Format-Table -AutoSize
} else {
    Write-Host "`nAll hosts covered in all enabled consoles." -ForegroundColor Green
}
