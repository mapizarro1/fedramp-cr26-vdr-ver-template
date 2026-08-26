<#
    FedRAMP-NoticeWatch.ps1

    Watches the FedRAMP Public Notices and Changelog RSS feeds and emails when a
    new item appears, flagging PRIORITY when the item matches CR26 watch keywords
    (VER/VDR/CDS/trust center/security inbox/BOD 26-04/etc). PowerShell port of
    fedramp_notice_watch.py so the box needs no Python.

    Self-contained by design: carries its own copy of the mail functions
    (Graph + Office 365 SMTP), mirroring FedRAMP-KEV-ConMon.ps1, so it can move
    hosts without a shared module.

    Requires: Windows PowerShell 5.1 or PowerShell 7+. No modules, no Python.
    Egress: www.fedramp.gov / fedramp.gov, and (for Graph) login.microsoftonline.com
    + graph.microsoft.com.

    EXIT CODES: 0 = ran clean (no new items or baseline), 2 = new item(s) emailed,
    1 = error.
#>

[CmdletBinding()]
param(
    [switch]$Init,          # seed baseline, no email
    [switch]$TestParseOnly  # fetch + parse check only
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# CONFIG
# ============================================================================
$Feeds = [ordered]@{
    notices   = 'https://www.fedramp.gov/notices/rss.xml'
    changelog = 'https://www.fedramp.gov/changelog/rss.xml'
}

# Items whose title/description match any of these (case-insensitive) are
# flagged PRIORITY. Everything new still emails; priority just gets flagged.
$PriorityPatterns = @(
    '\bVER\b', '\bVDR\b',
    'vulnerability (evaluation|detection|report)',
    'reporting guidance', 'delivery',
    'certification data sharing', '\bCDS\b', 'trust center',
    'USDA Connect', 'security inbox', 'BOD 26-04',
    'machine[- ]readable', 'corrective action',
    'december 7', 'march 7', '\bNTC-\d{4}\b',
    'grace period', 'rev ?5', 'class c'
)

# --- state + log: scaffold-relative (<root>\state, <root>\logs) with fallback ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir   = Split-Path -Parent $ScriptDir
$StateDir  = Join-Path $RootDir 'state'
$LogDir    = Join-Path $RootDir 'logs'
if (-not (Test-Path $StateDir)) { $StateDir = $ScriptDir }
if (-not (Test-Path $LogDir))   { $LogDir   = $ScriptDir }
$StatePath = Join-Path $StateDir 'noticewatch_state.json'
$LogPath   = Join-Path $LogDir   'noticewatch.log'

# ============================================================================
# EMAIL CONFIG  (mirrors FedRAMP-KEV-ConMon.ps1; identical to SchemaWatch)
# ============================================================================
$EmailMode = 'Office365SMTP'   # or 'Graph' once $env:GRAPH_CLIENT_SECRET is set

$MailFrom = 'noreply@example.com'          # SET: sender mailbox
$MailTo   = @('security@example.com')     # SET: alert recipients
$MailCc   = @()

$Office365SmtpServer   = 'smtp.office365.com'
$Office365SmtpPort     = 587
$Office365SmtpUsername = $MailFrom
# TEMPORARY test slot; prefer $env:O365_SMTP_PASSWORD (machine scope).
$Office365SmtpPassword = ''

$TenantId     = '<TENANT-ID>'   # SET: Entra tenant ID
$ClientId     = '<CLIENT-ID>'   # SET: app registration (client) ID
$ClientSecret = if ($env:GRAPH_CLIENT_SECRET) { $env:GRAPH_CLIENT_SECRET } else { '' }
$GraphScope   = 'https://graph.microsoft.com/.default'

$HttpTimeoutSec = 30
$UserAgent      = 'fedramp-notice-watch-ps/1.0'

# ============================================================================
# LOGGING
# ============================================================================
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "[$stamp] [$Level] $Message"
    Write-Output $line
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch { }
}

# ============================================================================
# HTTP + FEED PARSE
# ============================================================================
function Invoke-HttpGet {
    # Returns [pscustomobject]@{ Status=<int>; Body=<string> }. Status 0 on
    # transport failure. Uses -SkipHttpErrorCheck so HTTP 4xx/5xx do not throw,
    # avoiding version-dependent exception shapes. StrictMode-safe.
    param([string]$Url)
    try {
        $iwrArgs = @{
            Uri             = $Url
            Headers         = @{ 'User-Agent' = $UserAgent }
            TimeoutSec      = $HttpTimeoutSec
            UseBasicParsing = $true
            ErrorAction     = 'Stop'
        }
        if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('SkipHttpErrorCheck')) {
            $iwrArgs['SkipHttpErrorCheck'] = $true
        }
        $resp = Invoke-WebRequest @iwrArgs
        $sc = 0
        if ($resp -and $resp.PSObject.Properties.Name -contains 'StatusCode') { $sc = [int]$resp.StatusCode }
        $bd = ''
        if ($resp -and $resp.PSObject.Properties.Name -contains 'Content') { $bd = [string]$resp.Content }
        return [pscustomobject]@{ Status = $sc; Body = $bd }
    } catch {
        $status = 0
        try {
            $r = $_.Exception.Response
            if ($r -and $r.PSObject.Properties.Name -contains 'StatusCode') { $status = [int]$r.StatusCode }
        } catch { $status = 0 }
        if ($status -lt 400) { Write-Log "GET failed $Url : $($_.Exception.Message)" 'WARN' }
        return [pscustomobject]@{ Status = $status; Body = '' }
    }
}

function Get-SwapHostUrl {
    param([string]$Url)
    if ($Url -like '*://www.fedramp.gov*') { return $Url -replace '://www\.fedramp\.gov', '://fedramp.gov' }
    if ($Url -like '*://fedramp.gov*')     { return $Url -replace '://fedramp\.gov', '://www.fedramp.gov' }
    return $null
}

function Get-NodeText {
    # Safely read the text of a child element whether it's a plain-text node
    # (exposed as a string) or an XmlElement with a '#text' property. Returns
    # '' if absent. StrictMode-safe: no blind property access.
    param($Parent, [string]$Name)
    $node = $Parent.$Name
    if ($null -eq $node) { return '' }
    if ($node -is [string]) { return $node }
    # XmlElement or similar: try #text, then InnerText
    $props = $node.PSObject.Properties.Name
    if ($props -contains '#text') { return [string]$node.'#text' }
    try { return [string]$node.InnerText } catch { return [string]$node }
}

function Get-FeedItems {
    # Returns array of @{ id; title; link; pubDate; description }
    param([string]$Url)
    $r = Invoke-HttpGet -Url $Url
    if ($r.Status -ne 200 -or -not $r.Body) { $alt = Get-SwapHostUrl $Url; if ($alt) { $r = Invoke-HttpGet -Url $alt } }
    if ($r.Status -ne 200 -or -not $r.Body) { return @() }
    $items = @()
    try {
        [xml]$xml = $r.Body
        foreach ($it in $xml.rss.channel.item) {
            $guid = Get-NodeText $it 'guid'
            if (-not $guid) { $guid = Get-NodeText $it 'link' }
            if (-not $guid) { $guid = Get-NodeText $it 'title' }
            $desc = "$($it.description)"
            $desc = ($desc -replace '<[^>]+>', ' ')
            if ($desc.Length -gt 500) { $desc = $desc.Substring(0, 500) }
            $items += @{
                id          = ("$guid").Trim()
                title       = ("$($it.title)").Trim()
                link        = ("$($it.link)").Trim()
                pubDate     = ("$($it.pubDate)").Trim()
                description = $desc.Trim()
            }
        }
    } catch {
        Write-Log "parse failed $Url : $($_.Exception.Message)" 'WARN'
        return @()
    }
    return $items
}

function Test-Priority {
    param($Item)
    $hay = "$($Item.title) $($Item.description)"
    foreach ($p in $PriorityPatterns) { if ($hay -imatch $p) { return $true } }
    return $false
}

# ============================================================================
# STATE
# ============================================================================
function Import-State {
    if (-not (Test-Path $StatePath)) { return $null }
    try { return Get-Content -Path $StatePath -Raw | ConvertFrom-Json } catch { return $null }
}
function Export-State {
    param($State)
    $tmp = "$StatePath.tmp"
    $State | ConvertTo-Json -Depth 20 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $StatePath -Force
}

# ============================================================================
# EMAIL  (self-contained; mirrors FedRAMP-KEV-ConMon.ps1)
# ============================================================================
function Get-GraphToken {
    if ([string]::IsNullOrWhiteSpace($ClientSecret)) { throw "Graph client secret not set. Configure `$env:GRAPH_CLIENT_SECRET." }
    $tok = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id = $ClientId; scope = $GraphScope; client_secret = $ClientSecret; grant_type = 'client_credentials'
    }
    return $tok.access_token
}
function Send-GraphEmail {
    param([string[]]$To, [string[]]$Cc = @(), [string]$Subject, [string]$BodyText)
    $token = Get-GraphToken
    $toR = @($To | Where-Object { $_ } | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    $msg = @{ subject = $Subject; body = @{ contentType = 'Text'; content = $BodyText }; toRecipients = $toR }
    if ($Cc.Count) { $msg.ccRecipients = @($Cc | Where-Object { $_ } | ForEach-Object { @{ emailAddress = @{ address = $_ } } }) }
    $body = @{ message = $msg; saveToSentItems = $true } | ConvertTo-Json -Depth 12 -Compress
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$MailFrom/sendMail" `
        -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } -Method POST -Body $body | Out-Null
}
function Send-Office365SmtpEmail {
    param([string[]]$To, [string[]]$Cc = @(), [string]$Subject, [string]$BodyText)
    $pwd = if (-not [string]::IsNullOrWhiteSpace($Office365SmtpPassword)) { $Office365SmtpPassword }
           elseif (-not [string]::IsNullOrWhiteSpace($env:O365_SMTP_PASSWORD)) { $env:O365_SMTP_PASSWORD }
           else { $null }
    if ([string]::IsNullOrWhiteSpace($pwd)) { throw "[EMAIL][SMTP] No password. Set `$Office365SmtpPassword or `$env:O365_SMTP_PASSWORD." }
    $sec  = ConvertTo-SecureString $pwd -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($Office365SmtpUsername, $sec)
    $msg  = New-Object System.Net.Mail.MailMessage
    $smtp = New-Object System.Net.Mail.SmtpClient($Office365SmtpServer, $Office365SmtpPort)
    try {
        $msg.From = $MailFrom
        foreach ($a in $To) { if ($a) { $msg.To.Add($a) } }
        foreach ($a in $Cc) { if ($a) { $msg.CC.Add($a) } }
        $msg.Subject = $Subject; $msg.Body = $BodyText; $msg.IsBodyHtml = $false
        $smtp.EnableSsl = $true
        $smtp.Credentials = $cred.GetNetworkCredential()
        $smtp.Send($msg)
    } finally { if ($msg) { $msg.Dispose() }; if ($smtp) { $smtp.Dispose() } }
}
function Send-Alert {
    param([string]$Subject, [string]$BodyText)
    Write-Log "ALERT: $Subject"
    try {
        switch ($EmailMode) {
            'Graph'         { Send-GraphEmail        -To $MailTo -Cc $MailCc -Subject $Subject -BodyText $BodyText }
            'Office365SMTP' { Send-Office365SmtpEmail -To $MailTo -Cc $MailCc -Subject $Subject -BodyText $BodyText }
            default         { Write-Log "Unknown EmailMode '$EmailMode'." 'ERROR' }
        }
        Write-Log 'Email sent.'
    } catch { Write-Log "Email failed: $($_.Exception.Message)" 'ERROR' }
}

# ============================================================================
# MAIN
# ============================================================================
function Invoke-Main {
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $prev = Import-State
    $firstRun = ($null -eq $prev)

    # Build a hashtable of previously-seen ids per feed
    $seen = @{}
    if (-not $firstRun -and $prev.seen) {
        foreach ($p in $prev.seen.PSObject.Properties) { $seen[$p.Name] = @($p.Value) }
    }

    $newItems = @()   # list of @{ feed; item }
    $errors   = @()

    foreach ($feedName in $Feeds.Keys) {
        $url = $Feeds[$feedName]
        $items = @(Get-FeedItems -Url $url)
        if ($items.Count -eq 0) { $errors += "$feedName ($url) returned no items"; continue }

        if ($TestParseOnly) {
            Write-Log "$feedName : parsed $($items.Count) items; newest: $($items[0].title)"
            continue
        }

        $known = if ($seen.ContainsKey($feedName)) { $seen[$feedName] } else { @() }
        $ids = @($known)
        foreach ($it in $items) {
            if ($it.id -notin $known) {
                $ids += $it.id
                if (-not $firstRun) { $newItems += @{ feed = $feedName; item = $it } }
            }
        }
        # keep state bounded to last 500 ids
        if ($ids.Count -gt 500) { $ids = $ids[-500..-1] }
        $seen[$feedName] = $ids
    }

    if ($TestParseOnly) {
        if ($errors.Count) { Write-Log ("Errors: " + ($errors -join '; ')) 'ERROR'; return 1 }
        return 0
    }

    Export-State -State @{ checked_at = $now; seen = $seen }

    if ($errors.Count) {
        Send-Alert -Subject 'FedRAMP notice watch: feed error' -BodyText ("Feed problems:`n" + ($errors -join "`n"))
        # still process any new items we did find, then return error
    }

    if ($firstRun) {
        $total = ($seen.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        Write-Log "Baseline established. $total items seeded across $($Feeds.Count) feeds. No alerts on baseline."
        return $(if ($errors.Count) { 1 } else { 0 })
    }

    if ($newItems.Count -eq 0) {
        Write-Log "No new notices or changelog entries at $now"
        return $(if ($errors.Count) { 1 } else { 0 })
    }

    $priority = @($newItems | Where-Object { Test-Priority $_.item })
    $routine  = @($newItems | Where-Object { -not (Test-Priority $_.item) })

    function Format-Entries($entries) {
        ($entries | ForEach-Object {
            "  [$($_.feed)] $($_.item.pubDate)`n    $($_.item.title)`n    $($_.item.link)"
        }) -join "`n"
    }

    if ($priority.Count) {
        $body = "Items matching CR26 watch keywords (VER/VDR/CDS/inbox/etc):`n" + (Format-Entries $priority)
        if ($routine.Count) { $body += "`n`nAlso new (routine):`n" + (Format-Entries $routine) }
        Send-Alert -Subject "FedRAMP notice watch: $($priority.Count) PRIORITY item(s)" -BodyText $body
    } else {
        Send-Alert -Subject "FedRAMP notice watch: $($routine.Count) new item(s)" -BodyText (Format-Entries $routine)
    }
    return 2
}

exit (Invoke-Main)
