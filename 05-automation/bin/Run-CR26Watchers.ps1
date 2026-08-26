<#
    Run-CR26Watchers.ps1

    Single entry point called by Task Scheduler (as SYSTEM). Runs both watchers
    in one pass, then emits a HEARTBEAT so a silently-dead task or an expired
    mail credential cannot hide.

    Why a heartbeat: the watchers only email on CHANGE. Silence is therefore
    ambiguous - "nothing changed" and "the task died / mail broke" look identical
    from your inbox. This wrapper writes a heartbeat file every run and emails a
    short "still alive" summary on a fixed cadence (default: Mondays). If you stop
    getting the weekly heartbeat, the automation itself is down - that is the
    signal you could not get before.

    Layout assumed (from Initialize-CR26Scaffold.ps1):
        C:\FedRAMP-CR26\bin\    this file + the two watchers
        C:\FedRAMP-CR26\state\  watcher state + heartbeat.json
        C:\FedRAMP-CR26\logs\   per-script logs + wrapper.log

    Mail: reuses the SAME config the watchers use (edit the block below to match).
    Default transport is Office 365 SMTP so it works before Graph is wired.

    EXIT CODES: 0 = both watchers clean, 2 = a watcher reported a change,
    1 = a watcher errored (heartbeat will also flag it).

    Schedule (elevated, once):
        schtasks /Create /TN "FedRAMP CR26 Watchers" /RU SYSTEM /SC DAILY /ST 07:00 ^
          /TR "pwsh.exe -NoProfile -ExecutionPolicy Bypass -File C:\FedRAMP-CR26\bin\Run-CR26Watchers.ps1"
    (use powershell.exe instead of pwsh.exe if PS7 is not on PATH for SYSTEM)
#>

[CmdletBinding()]
param(
    # Day-of-week to send the "all is well" heartbeat email. Change-alerts and
    # error-alerts are sent every run regardless; this only gates the routine
    # heartbeat so you are not emailed a heartbeat daily.
    [string]$HeartbeatDay = 'Monday',
    # Force a heartbeat email this run regardless of day (for testing).
    [switch]$ForceHeartbeat
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # one watcher failing must not abort the other

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir   = Split-Path -Parent $ScriptDir
$StateDir  = Join-Path $RootDir 'state'
$LogDir    = Join-Path $RootDir 'logs'
if (-not (Test-Path $StateDir)) { $StateDir = $ScriptDir }
if (-not (Test-Path $LogDir))   { $LogDir   = $ScriptDir }
$HeartbeatPath = Join-Path $StateDir 'heartbeat.json'
$WrapperLog    = Join-Path $LogDir   'wrapper.log'

$SchemaScript = Join-Path $ScriptDir 'FedRAMP-SchemaWatch.ps1'
$NoticeScript = Join-Path $ScriptDir 'FedRAMP-NoticeWatch.ps1'

# ============================================================================
# MAIL CONFIG (keep identical to the watchers)
# ============================================================================
$EmailMode = 'Office365SMTP'
$MailFrom  = 'noreply@example.com'          # SET: sender mailbox
$MailTo    = @('security@example.com')     # SET: alert recipients

$Office365SmtpServer   = 'smtp.office365.com'
$Office365SmtpPort     = 587
$Office365SmtpUsername = $MailFrom
$Office365SmtpPassword = ''   # prefer $env:O365_SMTP_PASSWORD (machine scope)

$TenantId     = '<TENANT-ID>'   # SET: Entra tenant ID
$ClientId     = '<CLIENT-ID>'   # SET: app registration (client) ID
$ClientSecret = if ($env:GRAPH_CLIENT_SECRET) { $env:GRAPH_CLIENT_SECRET } else { '' }
$GraphScope   = 'https://graph.microsoft.com/.default'
$HttpTimeoutSec = 30

function Write-WLog {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "[$stamp] [$Level] $Message"
    Write-Output $line
    try { Add-Content -Path $WrapperLog -Value $line -Encoding UTF8 } catch { }
}

# --- mail (same functions as the watchers) ---
function Get-GraphToken {
    if ([string]::IsNullOrWhiteSpace($ClientSecret)) { throw "Graph client secret not set." }
    $tok = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id = $ClientId; scope = $GraphScope; client_secret = $ClientSecret; grant_type = 'client_credentials'
    }
    return $tok.access_token
}
function Send-GraphEmail {
    param([string[]]$To, [string]$Subject, [string]$BodyText)
    $token = Get-GraphToken
    $toR = @($To | Where-Object { $_ } | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    $body = @{ message = @{ subject = $Subject; body = @{ contentType = 'Text'; content = $BodyText }; toRecipients = $toR }; saveToSentItems = $true } | ConvertTo-Json -Depth 12 -Compress
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$MailFrom/sendMail" `
        -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } -Method POST -Body $body | Out-Null
}
function Send-SmtpEmail {
    param([string[]]$To, [string]$Subject, [string]$BodyText)
    $pwd = if (-not [string]::IsNullOrWhiteSpace($Office365SmtpPassword)) { $Office365SmtpPassword }
           elseif (-not [string]::IsNullOrWhiteSpace($env:O365_SMTP_PASSWORD)) { $env:O365_SMTP_PASSWORD }
           else { $null }
    if ([string]::IsNullOrWhiteSpace($pwd)) { throw "No SMTP password." }
    $sec  = ConvertTo-SecureString $pwd -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($Office365SmtpUsername, $sec)
    $msg  = New-Object System.Net.Mail.MailMessage
    $smtp = New-Object System.Net.Mail.SmtpClient($Office365SmtpServer, $Office365SmtpPort)
    try {
        $msg.From = $MailFrom
        foreach ($a in $To) { if ($a) { $msg.To.Add($a) } }
        $msg.Subject = $Subject; $msg.Body = $BodyText
        $smtp.EnableSsl = $true
        $smtp.Credentials = $cred.GetNetworkCredential()
        $smtp.Send($msg)
    } finally { if ($msg) { $msg.Dispose() }; if ($smtp) { $smtp.Dispose() } }
}
function Send-Mail {
    param([string]$Subject, [string]$BodyText)
    try {
        switch ($EmailMode) {
            'Graph'         { Send-GraphEmail -To $MailTo -Subject $Subject -BodyText $BodyText }
            'Office365SMTP' { Send-SmtpEmail  -To $MailTo -Subject $Subject -BodyText $BodyText }
        }
        Write-WLog "Mail sent: $Subject"
        return $true
    } catch { Write-WLog "Mail FAILED: $($_.Exception.Message)" 'ERROR'; return $false }
}

# ============================================================================
# RUN BOTH WATCHERS
# ============================================================================
$psExe = (Get-Process -Id $PID).Path   # same host (pwsh.exe or powershell.exe)

function Invoke-Watcher {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path $Path)) { Write-WLog "$Label MISSING at $Path" 'ERROR'; return ,([pscustomobject]@{ rc = 1; label = $Label }) }
    Write-WLog "Running $Label..."
    # Let the child's own console/log output flow to the transcript, but do NOT
    # let it land in this function's return stream: redirect child output to the
    # wrapper log, capture only the exit code.
    & $psExe -NoProfile -ExecutionPolicy Bypass -File $Path *>> $WrapperLog
    $rc = $LASTEXITCODE
    Write-WLog "$Label exit $rc"
    return ,([pscustomobject]@{ rc = $rc; label = $Label })
}

$results = @()
$results += Invoke-Watcher -Path $SchemaScript -Label 'SchemaWatch'
$results += Invoke-Watcher -Path $NoticeScript -Label 'NoticeWatch'

# Safe accessor: find a result's rc by label without StrictMode blowups.
function Get-Rc {
    param($Results, [string]$Label)
    foreach ($r in $Results) {
        if ($r -and ($r.PSObject.Properties.Name -contains 'label') -and $r.label -eq $Label) { return $r.rc }
    }
    return $null
}

$errored = @($results | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'rc') -and $_.rc -eq 1 })
$changed = @($results | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'rc') -and $_.rc -eq 2 })

# ============================================================================
# HEARTBEAT
# ============================================================================
$now = (Get-Date).ToUniversalTime()
$hb = @{
    last_run_utc = $now.ToString('o')
    schema_rc    = (Get-Rc $results 'SchemaWatch')
    notice_rc    = (Get-Rc $results 'NoticeWatch')
    errored      = @($errored | ForEach-Object { $_.label })
}
try { $hb | ConvertTo-Json -Depth 6 | Set-Content -Path $HeartbeatPath -Encoding UTF8 } catch { Write-WLog "heartbeat write failed: $($_.Exception.Message)" 'WARN' }

# Error alert: always, immediately.
if ($errored.Count) {
    $b = "One or more CR26 watchers ERRORED on $($now.ToString('o')):`n" +
         (($errored | ForEach-Object { "  - $($_.label) (exit 1)" }) -join "`n") +
         "`n`nCheck logs in $LogDir."
    [void](Send-Mail -Subject "CR26 watchers: ERROR ($($errored.Count))" -BodyText $b)
}

# Weekly heartbeat: only on the chosen day (or when forced). Confirms the whole
# chain - task fired, scripts ran, mail works - even on a week with no changes.
$isHeartbeatDay = $ForceHeartbeat -or ($now.DayOfWeek.ToString() -eq $HeartbeatDay)
if ($isHeartbeatDay -and $errored.Count -eq 0) {
    $b = "CR26 watchers alive and well.`n`n" +
         "Run (UTC): $($now.ToString('o'))`n" +
         "SchemaWatch: exit $($hb.schema_rc)  (0=clean, 2=change detected)`n" +
         "NoticeWatch: exit $($hb.notice_rc)`n`n" +
         "You are receiving this because it is $HeartbeatDay. If a $HeartbeatDay passes" +
         " with no heartbeat, the automation is down - investigate the scheduled task" +
         " 'FedRAMP CR26 Watchers' on $env:COMPUTERNAME.`n"
    [void](Send-Mail -Subject "CR26 watchers: weekly heartbeat (OK)" -BodyText $b)
}

Write-WLog "Wrapper done. schema=$($hb.schema_rc) notice=$($hb.notice_rc) errored=$($errored.Count) changed=$($changed.Count)"

if ($errored.Count) { exit 1 }
if ($changed.Count) { exit 2 }
exit 0
