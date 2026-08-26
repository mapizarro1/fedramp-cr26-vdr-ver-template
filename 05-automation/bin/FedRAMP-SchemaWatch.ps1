<#
    FedRAMP-SchemaWatch.ps1

    Watches the FedRAMP Consolidated Rules for 2026 for changes that matter to a
    Rev5 Moderate (Class C) vulnerability-management / ConMon program, and emails
    when something moves. PowerShell port of fedramp_schema_watch.py so the box
    needs no Python.

    Self-contained by design: this script carries its own copy of the mail
    functions (Graph + Office 365 SMTP) so it can be moved to another host without
    dragging a shared module along. The mail code mirrors FedRAMP-KEV-ConMon.ps1
    so it behaves identically to the KEV job.

    What it catches in one pass:
      1. rules   : ruleset version, schema-URL set changes, VER/VDR/IEC/CCM/CDS
                   rule text + class timeframe changes, and effective-date changes
                   (handles BOTH date shapes: info.effective AND info.20x/info.rev5).
      2. schemas : content hash + HTTP liveness of each referenced schema.
      3. rss     : FedRAMP Public Notices + Changelog feeds (human cross-check).

    Requires: Windows PowerShell 5.1 or PowerShell 7+. No modules, no Python.
    Egress needed: raw.githubusercontent.com, www.fedramp.gov, fedramp.gov,
    and (for Graph) login.microsoftonline.com + graph.microsoft.com.

    EXIT CODES: 0 = ran clean (no changes or baseline), 2 = changes emailed,
    1 = error. Lets a wrapper branch on "something changed".
#>

[CmdletBinding()]
param(
    [switch]$Init,          # seed baseline, do not email diffs
    [switch]$TestParseOnly  # fetch + parse check, no state write, no email
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# CONFIG
# ============================================================================

# --- what to watch ---
$RulesUrl = 'https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json'

# Rule families fingerprinted for text/timeframe/date changes. Expanded beyond
# the original Python list to cover the CR26 families that matter to Class C:
#   VDR/VER = the Dec 7 vulnerability regime
#   IEC     = incident evaluation & communication
#   CCM     = collaborative continuous monitoring (OCR/Quarterly Review)
#   CDS     = certification data sharing / trust center
#   SCN     = significant change notifications
$RuleFamilies = @('VDR','VER','IEC','CCM','CDS','SCN')

# FedRAMP RSS (best-effort; tolerates 404 and www<->apex swap).
$RssFeeds = @(
    'https://www.fedramp.gov/changelog/rss.xml',
    'https://www.fedramp.gov/notices/rss.xml'
)

# --- state + log ---
# Resolve scaffold-relative paths: script lives in <root>\bin, state and logs
# are siblings under <root>\state and <root>\logs. If the expected sibling
# folders are not found (e.g. script run standalone outside the scaffold), fall
# back to writing beside the script so it still works anywhere.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir   = Split-Path -Parent $ScriptDir
$StateDir  = Join-Path $RootDir 'state'
$LogDir    = Join-Path $RootDir 'logs'
if (-not (Test-Path $StateDir)) { $StateDir = $ScriptDir }
if (-not (Test-Path $LogDir))   { $LogDir   = $ScriptDir }
$StatePath = Join-Path $StateDir 'schemawatch_state.json'
$LogPath   = Join-Path $LogDir   'schemawatch.log'

$AlertOnBaseline = $true   # one "baseline established" email on first run

# ============================================================================
# EMAIL CONFIG  (mirrors FedRAMP-KEV-ConMon.ps1)
#   $EmailMode = "Office365SMTP"  -> System.Net.Mail via smtp.office365.com
#   $EmailMode = "Graph"          -> Microsoft Graph sendMail (app-only)
# SMTP is the working default for now; flip to "Graph" once
# $env:GRAPH_CLIENT_SECRET is set at machine scope. See KEV script.
# ============================================================================
$EmailMode = 'Office365SMTP'

$MailFrom = 'noreply@example.com'          # SET: sender mailbox
$MailTo   = @('security@example.com')     # SET: alert recipients
$MailCc   = @()

# --- Office 365 SMTP ---
$Office365SmtpServer   = 'smtp.office365.com'
$Office365SmtpPort     = 587
$Office365SmtpUsername = $MailFrom
# Resolution order at send time: $Office365SmtpPassword -> $env:O365_SMTP_PASSWORD.
# TEMPORARY: paste the (rotated) SMTP password here to test, then move it to
# $env:O365_SMTP_PASSWORD (machine scope) and blank this line. Do NOT commit a
# real password to source control.
$Office365SmtpPassword = ''

# --- Microsoft Graph (app-only client credentials) ---
$TenantId     = '<TENANT-ID>'   # SET: Entra tenant ID
$ClientId     = '<CLIENT-ID>'   # SET: app registration (client) ID
$ClientSecret = if ($env:GRAPH_CLIENT_SECRET) { $env:GRAPH_CLIENT_SECRET } else { '' }
$GraphScope   = 'https://graph.microsoft.com/.default'

$HttpTimeoutSec = 30
$UserAgent      = 'fedramp-schema-watch-ps/1.0'

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
# HELPERS
# ============================================================================
function Get-Prop {
    # StrictMode-safe property read. Returns $null if the property is absent.
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
    return $null
}

function Get-KeyNames {
    # Return the set of "keys" whether $Obj is a live Hashtable (fresh snapshot)
    # or a PSCustomObject (state read back from JSON via ConvertFrom-Json).
    param($Obj)
    if ($null -eq $Obj) { return @() }
    if ($Obj -is [System.Collections.IDictionary]) { return @($Obj.Keys) }
    return @($Obj.PSObject.Properties.Name)
}

function Get-ByKey {
    # Index into a Hashtable or PSCustomObject by key name, shape-agnostic.
    param($Obj, [string]$Key)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Key)) { return $Obj[$Key] }
        return $null
    }
    return (Get-Prop $Obj $Key)
}

# ============================================================================
# HTTP
# ============================================================================
function Invoke-HttpGet {
    # Returns [pscustomobject]@{ Status=<int>; Body=<string> }. Status 0 on
    # transport failure. Uses -SkipHttpErrorCheck so HTTP 4xx/5xx come back as
    # a normal response (no throw), avoiding version-dependent exception shapes.
    # StrictMode-safe: never accesses a property that might be absent.
    param([string]$Url, [int]$Retries = 2)
    for ($i = 0; $i -le $Retries; $i++) {
        try {
            $iwrArgs = @{
                Uri             = $Url
                Headers         = @{ 'User-Agent' = $UserAgent }
                TimeoutSec      = $HttpTimeoutSec
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            # -SkipHttpErrorCheck exists in PS 6+; guard for 5.1 just in case.
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
            # Only reached on transport-level failure (DNS, TLS, timeout, proxy).
            $status = 0
            try {
                $r = $_.Exception.Response
                if ($r -and $r.PSObject.Properties.Name -contains 'StatusCode') { $status = [int]$r.StatusCode }
            } catch { $status = 0 }
            if ($status -ge 400) { return [pscustomobject]@{ Status = $status; Body = '' } }
            if ($i -eq $Retries) { Write-Log "GET failed $Url : $($_.Exception.Message)" 'WARN' }
        }
    }
    return [pscustomobject]@{ Status = 0; Body = '' }
}

function Get-SwapHostUrl {
    param([string]$Url)
    if ($Url -like '*://www.fedramp.gov*') { return $Url -replace '://www\.fedramp\.gov', '://fedramp.gov' }
    if ($Url -like '*://fedramp.gov*')     { return $Url -replace '://fedramp\.gov', '://www.fedramp.gov' }
    return $null
}

function Get-Sha256Hex {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLower()
    } finally { $sha.Dispose() }
}

# ============================================================================
# RULES LAYER
# ============================================================================
function Get-SchemaRefs {
    # Walk the ruleset collecting every {schema:{url:...}} and the rule id nearest above it.
    param($Node)
    $refs = @{}
    function Test-RuleId([string]$s) {
        return ($s -and $s.Length -eq 11 -and $s[3] -eq '-' -and $s[7] -eq '-')
    }
    function Walk($o, $lastRule) {
        if ($o -is [System.Collections.IDictionary] -or $o -is [pscustomobject]) {
            $props = if ($o -is [pscustomobject]) { $o.PSObject.Properties } else {
                $o.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Name = $_.Key; Value = $_.Value } }
            }
            foreach ($p in $props) {
                if ($p.Name -eq 'schema' -and $p.Value -and $p.Value.PSObject.Properties.Name -contains 'url') {
                    $u = $p.Value.url
                    if (-not $refs.ContainsKey($u)) { $refs[$u] = New-Object System.Collections.Generic.HashSet[string] }
                    if ($lastRule) { [void]$refs[$u].Add($lastRule) }
                }
                $nextRule = if (Test-RuleId $p.Name) { $p.Name } else { $lastRule }
                Walk $p.Value $nextRule
            }
        } elseif ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
            foreach ($v in $o) { Walk $v $lastRule }
        }
    }
    Walk $Node $null
    $out = @{}
    foreach ($k in $refs.Keys) { $out[$k] = ($refs[$k] | Sort-Object) -join ',' }
    return $out
}

function Get-FamilyEffective {
    # Handles BOTH shapes: info.effective (single) and info.20x/info.rev5 (split).
    # Note: Get-Prop is defined below Get-FamilyFingerprint; both are in scope
    # at call time (all functions load before Invoke-Main runs).
    param($Rules, [string]$Fam)
    $info = Get-Prop (Get-Prop $Rules.FRR $Fam) 'info'
    if (-not $info) { return $null }
    $out = [ordered]@{}
    $eff = Get-Prop $info 'effective'
    if ($null -ne $eff) { $out['all'] = ((Get-Prop $eff 'date') | ConvertTo-Json -Depth 8 -Compress) }
    foreach ($t in @('20x','rev5')) {
        $tNode = Get-Prop $info $t
        if ($null -ne $tNode) {
            $tEff = Get-Prop $tNode 'effective'
            if ($null -ne $tEff) { $out[$t] = ((Get-Prop $tEff 'date') | ConvertTo-Json -Depth 8 -Compress) }
        }
    }
    if ($out.Count -eq 0) { return $null }
    return ($out | ConvertTo-Json -Depth 8 -Compress)
}

function Get-FamilyFingerprint {
    # Per-rule fingerprint: name/statement/force + per-class statement+timeframe_num+pain.
    param($Rules, [string]$Fam)
    $out = @{}
    $famNode = Get-Prop (Get-Prop $Rules.FRR $Fam) 'data'
    if (-not $famNode) { return $out }
    foreach ($scopeProp in $famNode.PSObject.Properties) {
        if ($null -eq $scopeProp.Value) { continue }
        foreach ($subsetProp in $scopeProp.Value.PSObject.Properties) {
            if ($null -eq $subsetProp.Value) { continue }
            foreach ($ruleProp in $subsetProp.Value.PSObject.Properties) {
                $r = $ruleProp.Value
                $fp = [ordered]@{
                    name      = (Get-Prop $r 'name')
                    statement = (Get-Prop $r 'statement')
                    force     = (Get-Prop $r 'force')
                }
                $vbcNode = Get-Prop $r 'varies_by_class'
                if ($vbcNode) {
                    $vbc = [ordered]@{}
                    foreach ($clsProp in $vbcNode.PSObject.Properties) {
                        $cd = $clsProp.Value
                        $pain = Get-Prop $cd 'pain_timeframes'
                        $vbc[$clsProp.Name] = [ordered]@{
                            statement       = (Get-Prop $cd 'statement')
                            timeframe_num   = (Get-Prop $cd 'timeframe_num')
                            pain_timeframes = if ($null -ne $pain) { ($pain | ConvertTo-Json -Depth 8 -Compress) } else { $null }
                        }
                    }
                    $fp['varies_by_class'] = $vbc
                }
                $out[$ruleProp.Name] = ($fp | ConvertTo-Json -Depth 10 -Compress)
            }
        }
    }
    return $out
}

function Get-RulesSnapshot {
    $r = Invoke-HttpGet -Url $RulesUrl
    if ($r.Status -ne 200 -or -not $r.Body) { return @{ error = "rules file unreachable (HTTP $($r.Status))" } }
    try { $rules = $r.Body | ConvertFrom-Json } catch { return @{ error = "rules file did not parse: $($_.Exception.Message)" } }
    $fams = @{}; $eff = @{}
    foreach ($f in $RuleFamilies) { $fams[$f] = Get-FamilyFingerprint $rules $f; $eff[$f] = Get-FamilyEffective $rules $f }
    return @{
        snapshot = @{
            schemas       = Get-SchemaRefs $rules
            families      = $fams
            effective     = $eff
            rules_version = $rules.info.version
        }
    }
}

function Compare-Rules {
    param($OldSnap, $NewSnap)
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $OldSnap) { return $lines }
    if ((Get-ByKey $OldSnap 'rules_version') -ne (Get-ByKey $NewSnap 'rules_version')) {
        $lines.Add("[rules] ruleset version: $(Get-ByKey $OldSnap 'rules_version') -> $(Get-ByKey $NewSnap 'rules_version')")
    }
    # schema URL set
    $oldSchemas = Get-ByKey $OldSnap 'schemas'; $newSchemas = Get-ByKey $NewSnap 'schemas'
    $oldUrls = Get-KeyNames $oldSchemas; $newUrls = Get-KeyNames $newSchemas
    foreach ($u in ($newUrls | Where-Object { $_ -notin $oldUrls } | Sort-Object)) { $lines.Add("[schema-ref NEW] $u (by $(Get-ByKey $newSchemas $u))") }
    foreach ($u in ($oldUrls | Where-Object { $_ -notin $newUrls } | Sort-Object)) { $lines.Add("[schema-ref REMOVED] $u") }
    foreach ($u in ($newUrls | Where-Object { $_ -in $oldUrls } | Sort-Object)) {
        if ((Get-ByKey $oldSchemas $u) -ne (Get-ByKey $newSchemas $u)) { $lines.Add("[schema-ref REMAPPED] $u : $(Get-ByKey $oldSchemas $u) -> $(Get-ByKey $newSchemas $u)") }
    }
    # rule families
    $oldFams = Get-ByKey $OldSnap 'families'; $newFams = Get-ByKey $NewSnap 'families'
    $oldEff  = Get-ByKey $OldSnap 'effective'; $newEff = Get-ByKey $NewSnap 'effective'
    foreach ($fam in $RuleFamilies) {
        $of = Get-ByKey $oldFams $fam; $nf = Get-ByKey $newFams $fam
        $ofKeys = Get-KeyNames $of; $nfKeys = Get-KeyNames $nf
        foreach ($rid in ($nfKeys | Where-Object { $_ -notin $ofKeys } | Sort-Object)) { $lines.Add("[$fam NEW RULE] $rid") }
        foreach ($rid in ($ofKeys | Where-Object { $_ -notin $nfKeys } | Sort-Object)) { $lines.Add("[$fam RULE REMOVED] $rid") }
        foreach ($rid in ($ofKeys | Where-Object { $_ -in $nfKeys } | Sort-Object)) {
            if ((Get-ByKey $of $rid) -ne (Get-ByKey $nf $rid)) { $lines.Add("[$fam RULE CHANGED] $rid") }
        }
        $oe = Get-ByKey $oldEff $fam; $ne = Get-ByKey $newEff $fam
        if ($oe -ne $ne) { $lines.Add("[$fam EFFECTIVE DATES CHANGED] $oe -> $ne") }
    }
    return $lines
}

# ============================================================================
# SCHEMAS LAYER
# ============================================================================
function Get-SchemasSnapshot {
    param([string[]]$SchemaUrls)
    $out = @{}
    foreach ($u in $SchemaUrls) {
        $r = Invoke-HttpGet -Url $u
        if ($r.Status -ne 200) { $alt = Get-SwapHostUrl $u; if ($alt) { $r = Invoke-HttpGet -Url $alt } }
        $out[$u] = @{
            status = $r.Status
            sha256 = if ($r.Status -eq 200 -and $r.Body) { Get-Sha256Hex $r.Body } else { $null }
            bytes  = if ($r.Body) { $r.Body.Length } else { 0 }
        }
    }
    return $out
}

function Compare-Schemas {
    param($OldSnap, $NewSnap)
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $OldSnap) {
        foreach ($u in (Get-KeyNames $NewSnap | Sort-Object)) { $n = Get-ByKey $NewSnap $u; if ((Get-ByKey $n 'status') -ne 200) { $lines.Add("[schema NOT-LIVE @baseline] $u (HTTP $(Get-ByKey $n 'status'))") } }
        return $lines
    }
    $oldKeys = Get-KeyNames $OldSnap; $newKeys = Get-KeyNames $NewSnap
    foreach ($u in ($newKeys | Where-Object { $_ -notin $oldKeys } | Sort-Object)) { $n = Get-ByKey $NewSnap $u; $lines.Add("[schema ADDED to watch] $u (HTTP $(Get-ByKey $n 'status'))") }
    foreach ($u in ($oldKeys | Where-Object { $_ -notin $newKeys } | Sort-Object)) { $lines.Add("[schema DROPPED from watch] $u") }
    foreach ($u in ($oldKeys | Where-Object { $_ -in $newKeys } | Sort-Object)) {
        $o = Get-ByKey $OldSnap $u; $n = Get-ByKey $NewSnap $u
        $os_ = [int](Get-ByKey $o 'status'); $ns_ = [int](Get-ByKey $n 'status')
        if ($os_ -ne $ns_) {
            $tag = if ($os_ -ne 200 -and $ns_ -eq 200) { 'WENT LIVE' } else { 'STATUS' }
            $lines.Add("[schema $tag] $u : HTTP $os_ -> $ns_")
        }
        $oh = [string](Get-ByKey $o 'sha256'); $nh = [string](Get-ByKey $n 'sha256')
        if ($oh -ne $nh -and $ns_ -eq 200 -and $os_ -eq 200) {
            $osh = if ($oh) { $oh.Substring(0,12) } else { 'none' }
            $nsh = if ($nh) { $nh.Substring(0,12) } else { 'none' }
            $lines.Add("[schema CONTENT CHANGED] $u (sha $osh -> $nsh, $(Get-ByKey $o 'bytes') -> $(Get-ByKey $n 'bytes') bytes)")
        }
    }
    return $lines
}

# ============================================================================
# RSS LAYER
# ============================================================================
function Get-NodeText {
    # Safely read child element text whether plain-text node (string) or
    # XmlElement with '#text'. Returns '' if absent. StrictMode-safe.
    param($Parent, [string]$Name)
    $node = $Parent.$Name
    if ($null -eq $node) { return '' }
    if ($node -is [string]) { return $node }
    $props = $node.PSObject.Properties.Name
    if ($props -contains '#text') { return [string]$node.'#text' }
    try { return [string]$node.InnerText } catch { return [string]$node }
}

function Get-RssSnapshot {
    param([string]$Url)
    $r = Invoke-HttpGet -Url $Url
    if ($r.Status -ne 200 -or -not $r.Body) { $alt = Get-SwapHostUrl $Url; if ($alt) { $r = Invoke-HttpGet -Url $alt } }
    if ($r.Status -ne 200 -or -not $r.Body) { return @{ status = $r.Status; items = @() } }
    $items = @()
    try {
        [xml]$xml = $r.Body
        foreach ($it in $xml.rss.channel.item) {
            $guid = Get-NodeText $it 'guid'
            if (-not $guid) { $guid = Get-NodeText $it 'link' }
            if (-not $guid) { $guid = Get-NodeText $it 'title' }
            $items += @{ guid = ("$guid").Trim(); title = ("$(Get-NodeText $it 'title')").Trim() }
        }
    } catch { return @{ status = $r.Status; items = @() } }
    return @{ status = $r.Status; items = @($items | Select-Object -First 30) }
}

function Compare-Rss {
    param([string]$Url, $OldSnap, $NewSnap)
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not $OldSnap) { return $lines }
    $oldItems = Get-ByKey $OldSnap 'items'; $newItems = Get-ByKey $NewSnap 'items'
    $oldG = @($oldItems | ForEach-Object { Get-ByKey $_ 'guid' })
    $fresh = @($newItems | Where-Object { (Get-ByKey $_ 'guid') -notin $oldG })
    $label = if ($Url -match 'notices') { 'notices' } elseif ($Url -match 'changelog') { 'changelog' } else { $Url }
    foreach ($i in ($fresh | Select-Object -First 10)) { $lines.Add("[rss $label] $($i.title)") }
    return $lines
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
    $State | ConvertTo-Json -Depth 40 | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $StatePath -Force
}

# ============================================================================
# EMAIL  (self-contained; mirrors FedRAMP-KEV-ConMon.ps1)
# ============================================================================
function Get-GraphToken {
    if ([string]::IsNullOrWhiteSpace($ClientSecret)) { throw "Graph client secret not set. Configure `$env:GRAPH_CLIENT_SECRET." }
    Write-Log '[EMAIL] Requesting Microsoft Graph OAuth token...' 'INFO'
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
    Write-Log '[EMAIL] Sending via Microsoft Graph...' 'INFO'
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$MailFrom/sendMail" `
        -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } -Method POST -Body $body | Out-Null
    Write-Log '[EMAIL] Sent.' 'INFO'
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
        Write-Log "[EMAIL] Sending via O365 SMTP ($Office365SmtpServer`:$Office365SmtpPort)..." 'INFO'
        $smtp.Send($msg)
        Write-Log '[EMAIL] Sent.' 'INFO'
    } finally { if ($msg) { $msg.Dispose() }; if ($smtp) { $smtp.Dispose() } }
}

function Send-Alert {
    param([string]$Subject, [string]$BodyText)
    try {
        switch ($EmailMode) {
            'Graph'         { Send-GraphEmail        -To $MailTo -Cc $MailCc -Subject $Subject -BodyText $BodyText }
            'Office365SMTP' { Send-Office365SmtpEmail -To $MailTo -Cc $MailCc -Subject $Subject -BodyText $BodyText }
            default         { Write-Log "Unknown EmailMode '$EmailMode'; alert not emailed." 'ERROR' }
        }
    } catch {
        Write-Log "Email failed: $($_.Exception.Message)" 'ERROR'
    }
}

# ============================================================================
# MAIN
# ============================================================================
function Invoke-Main {
    $now = (Get-Date).ToUniversalTime().ToString('o')
    $prev = Import-State
    $firstRun = ($null -eq $prev)

    # RULES
    $rulesResult = Get-RulesSnapshot
    if ($rulesResult.ContainsKey('error')) {
        Write-Log "[rules ERROR] $($rulesResult.error)" 'ERROR'
        Send-Alert -Subject 'FedRAMP schema watch: rules fetch error' -BodyText $rulesResult.error
        return 1
    }
    $newRules = $rulesResult.snapshot

    if ($TestParseOnly) {
        Write-Log "Parse OK. version=$($newRules.rules_version) schemas=$($newRules.schemas.Count) families=$($RuleFamilies -join ',')"
        return 0
    }

    $changes = New-Object System.Collections.Generic.List[string]
    if (-not $firstRun) { Compare-Rules (Get-ByKey $prev 'rules') $newRules | ForEach-Object { $changes.Add($_) } }

    # SCHEMAS
    $schemaUrls = Get-KeyNames (Get-ByKey $newRules 'schemas')
    $newSchemas = Get-SchemasSnapshot -SchemaUrls $schemaUrls
    if (-not $firstRun) { Compare-Schemas (Get-ByKey $prev 'schemas') $newSchemas | ForEach-Object { $changes.Add($_) } }

    # RSS
    $newRss = @{}
    $prevRss = if (-not $firstRun) { Get-ByKey $prev 'rss' } else { $null }
    foreach ($u in $RssFeeds) {
        $snap = Get-RssSnapshot -Url $u
        $newRss[$u] = $snap
        if (-not $firstRun) { $prevSnap = Get-ByKey $prevRss $u; Compare-Rss $u $prevSnap $snap | ForEach-Object { $changes.Add($_) } }
    }

    # persist
    $state = @{ checked_at = $now; rules = $newRules; schemas = $newSchemas; rss = $newRss }
    Export-State -State $state

    if ($firstRun) {
        $msg = "FedRAMP schema watch baseline established at $now`nRuleset version: $($newRules.rules_version)`nSchemas tracked: $($schemaUrls.Count)`nFamilies: $($RuleFamilies -join ', ')`nNo diff alerts on baseline."
        Write-Log $msg
        if ($AlertOnBaseline) { Send-Alert -Subject 'FedRAMP schema watch: baseline established' -BodyText $msg }
        return 0
    }

    if ($changes.Count -eq 0) { Write-Log "No changes detected at $now"; return 0 }

    $body = "FedRAMP Consolidated Rules / schema change(s) at $now`n$('-'*60)`n" + ($changes -join "`n") + "`n`nSource: $RulesUrl`n"
    Write-Log $body
    Send-Alert -Subject "FedRAMP rules/schema change: $($changes.Count) item(s)" -BodyText $body
    return 2
}

exit (Invoke-Main)
