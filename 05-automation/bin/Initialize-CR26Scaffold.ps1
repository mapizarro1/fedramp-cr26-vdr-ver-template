<#
    Initialize-CR26Scaffold.ps1

    Builds the C:\FedRAMP-CR26 directory tree on the automation host to house CR26
    ConMon automation: the schema watcher, the notice watcher, and future
    CR26 scripts (VER pipeline, CDS/trust-center tooling, etc.).

    Leaves C:\KEV-Scripts untouched.

    Design:
      bin\      the .ps1 scripts themselves (SchemaWatch, NoticeWatch, ...)
      state\    *_state.json baselines - the files that MUST persist between runs
      logs\     rolling per-script logs
      config\   shared config (mail settings); secrets belong in machine env vars, NOT here
      archive\  retired scripts / superseded state
      README.md what lives here, how it's scheduled, how mail is wired

    ACL hardening (default): SYSTEM + BUILTIN\Administrators FullControl only,
    inheritance disabled. Matches the IRV scaffold. The scheduled tasks run as
    SYSTEM, so SYSTEM needs access; Administrators keeps it manageable.

    Idempotent: safe to re-run. Creates only what is missing, re-applies ACLs,
    never deletes existing content.

    Run ELEVATED on the automation host:
        pwsh -File .\Initialize-CR26Scaffold.ps1
    Preview without making changes:
        pwsh -File .\Initialize-CR26Scaffold.ps1 -WhatIf
    Add your user with read/write (instead of admin-only):
        pwsh -File .\Initialize-CR26Scaffold.ps1 -GrantUser '<DOMAIN>\<user>'
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Root = 'C:\FedRAMP-CR26',
    # Optional: an additional principal to grant Modify (read/write). Leave empty
    # for locked-down SYSTEM+Administrators only.
    [string]$GrantUser = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SubDirs = @('bin', 'state', 'logs', 'config', 'archive')

function Write-Step { param([string]$Msg) Write-Host "[scaffold] $Msg" }

# ---------------------------------------------------------------------------
# 1. Create directory tree
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Root)) {
    if ($PSCmdlet.ShouldProcess($Root, 'Create root directory')) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        Write-Step "Created root $Root"
    }
} else {
    Write-Step "Root already exists: $Root"
}

foreach ($d in $SubDirs) {
    $p = Join-Path $Root $d
    if (-not (Test-Path -LiteralPath $p)) {
        if ($PSCmdlet.ShouldProcess($p, 'Create subdirectory')) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
            Write-Step "Created $d\"
        }
    } else {
        Write-Step "Exists: $d\"
    }
}

# ---------------------------------------------------------------------------
# 2. Seed README.md (only if absent - never overwrite an edited one)
# ---------------------------------------------------------------------------
$readmePath = Join-Path $Root 'README.md'
if (-not (Test-Path -LiteralPath $readmePath)) {
    $readme = @'
# FedRAMP CR26 ConMon Automation

Deployment home on the automation host for CR26 continuous-monitoring automation.
Mirrors the SCM repo `fedramp-cr26-modernization`. KEV automation lives
separately in C:\KEV-Scripts and is NOT part of this tree.

## Layout
- bin\      PowerShell scripts (schema watcher, notice watcher, future VER pipeline)
- state\    *_state.json baselines. THESE MUST PERSIST. Do not delete; losing a
            state file makes the next run a silent baseline (no diff alert).
- logs\     Per-script rolling logs.
- config\   Shared config. NO secrets in here. Mail secret is $env:GRAPH_CLIENT_SECRET
            (machine scope). SMTP password, if used temporarily, is $env:O365_SMTP_PASSWORD.
- archive\  Retired scripts / superseded state.

## Scripts
- FedRAMP-SchemaWatch.ps1  Watches the CR26 ruleset (version, schemas, VER/VDR/
                           IEC/CCM/CDS/SCN rule text + effective dates) and RSS
                           feeds; emails on change.
- FedRAMP-NoticeWatch.ps1  Watches FedRAMP notices/changelog RSS; emails on new items.

## Email
Both scripts carry their own copy of the mail functions (Graph + O365 SMTP),
matching FedRAMP-KEV-ConMon.ps1. Default $EmailMode = "Office365SMTP" for now;
flip to "Graph" once $env:GRAPH_CLIENT_SECRET is set at machine scope.

## Scheduling
Run as SYSTEM in Task Scheduler (same as KEV). Suggested: daily 07:00.
Exit codes: 0 = clean, 2 = change detected/emailed, 1 = error.

## State files must persist
The watchers alert only on CHANGES vs the stored baseline. If a state file is
deleted the next run re-baselines silently. Back up state\ if you rebuild the box.
'@
    if ($PSCmdlet.ShouldProcess($readmePath, 'Write README.md')) {
        Set-Content -Path $readmePath -Value $readme -Encoding UTF8
        Write-Step 'Wrote README.md'
    }
} else {
    Write-Step 'README.md exists (left as-is)'
}

# ---------------------------------------------------------------------------
# 3. Harden ACLs: disable inheritance, SYSTEM + Administrators FullControl,
#    optional GrantUser Modify. Applied to root and all subdirs.
# ---------------------------------------------------------------------------
function Set-HardenedAcl {
    param([string]$Path, [string]$ExtraUser)

    $acl = Get-Acl -LiteralPath $Path

    # Remove inherited rules, keep no copies (we set explicit rules below).
    $acl.SetAccessRuleProtection($true, $false)

    # Drop any existing explicit rules so re-runs converge to the same state.
    $existing = @($acl.Access)
    foreach ($rule in $existing) { [void]$acl.RemoveAccessRule($rule) }

    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $prop    = [System.Security.AccessControl.PropagationFlags]::None
    $allow   = [System.Security.AccessControl.AccessControlType]::Allow

    $rules = @(
        (New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', $inherit, $prop, $allow)),
        (New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', $inherit, $prop, $allow))
    )
    if ($ExtraUser) {
        $rules += (New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ExtraUser, 'Modify', $inherit, $prop, $allow))
    }
    foreach ($r in $rules) { $acl.AddAccessRule($r) }

    Set-Acl -LiteralPath $Path -AclObject $acl
}

$targets = @($Root) + ($SubDirs | ForEach-Object { Join-Path $Root $_ })
foreach ($t in $targets) {
    if (Test-Path -LiteralPath $t) {
        if ($PSCmdlet.ShouldProcess($t, 'Apply hardened ACL')) {
            try {
                Set-HardenedAcl -Path $t -ExtraUser $GrantUser
                Write-Step "ACL hardened: $t"
            } catch {
                Write-Warning "ACL failed on $t : $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Report final state
# ---------------------------------------------------------------------------
Write-Host ''
Write-Step 'Scaffold complete. Tree:'
if (Test-Path -LiteralPath $Root) {
    Get-ChildItem -LiteralPath $Root -Directory | Select-Object Name |
        ForEach-Object { Write-Host "    $Root\$($_.Name)\" }
}
Write-Host ''
Write-Step 'ACL on root:'
if (Test-Path -LiteralPath $Root) {
    (Get-Acl -LiteralPath $Root).Access |
        Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited |
        Format-Table -AutoSize
}
Write-Host ''
Write-Step 'Next: copy the watcher .ps1 files into bin\, then schedule them as SYSTEM.'
Write-Step 'Suggested move:'
Write-Host  "    Move-Item C:\path\to\FedRAMP-SchemaWatch.ps1  $Root\bin\"
Write-Host  "    Move-Item C:\path\to\FedRAMP-NoticeWatch.ps1  $Root\bin\"
