#requires -Version 5.1
#requires -RunAsAdministrator
<#
.SYNOPSIS
  Build the on-disk scaffold for the CR26 T1 IRV automation on the automation host:
  a directory tree for the script, dated evidence, diagnostics, and run logs, with NTFS ACLs
  hardened so evidence cannot be tampered with by non-privileged users.

.DESCRIPTION
  Creates (idempotently):
    <Root>\CR26-IRV\
      bin\           the Build-IrvMap.v2.ps1 script (and future helpers)
      config\        externalized config / manifest, if you later split it out
      evidence\      dated irv-*.csv and irv-*.json  <- the archival IRV evidence
      diagnostics\   dated irv-*.diagnostics.json    <- always written, even on failed runs
      logs\          scheduled-task transcripts and run logs
      archive\       rotated older evidence (manual or scheduled rotation)
      README.md      what this tree is, retention note, ACL model

  ACL model (inheritance broken on <Root>\CR26-IRV so parent perms don't widen it):
    - BUILTIN\Administrators : FullControl   (so you cannot self-lock-out)
    - NT AUTHORITY\SYSTEM    : FullControl   (scheduled task under SYSTEM, if used)
    - <AutomationAccount>    : Modify        (the identity the job runs as; write new files)
    - <AuditorsGroup>        : ReadAndExecute (optional read-only access for assessors)
  evidence\ additionally has the automation account's Delete removed where supported, so the
  job can create evidence but not delete or overwrite prior dated artifacts (append-only-ish).

.PARAMETER Root
  Base path. Prefer a dedicated DATA drive over the OS drive if the host has one
  (e.g. 'E:\FedRAMP'); falls back to 'C:\FedRAMP'.

.PARAMETER AutomationAccount
  The account the scheduled IRV job will run as (e.g. '<HOST>\svc-irv' or, once you move to
  the system-assigned managed identity executing via SYSTEM/Task Scheduler, leave as SYSTEM).
  Optional; if omitted, only Administrators + SYSTEM are granted.

.PARAMETER AuditorsGroup
  Optional group granted read-only access to evidence (e.g. a local 'FedRAMP-Auditors' group).

.PARAMETER ScriptSource
  Optional path to Build-IrvMap.v2.ps1 to copy into bin\.

.EXAMPLE
  .\Initialize-IrvScaffold.ps1 -Root 'E:\FedRAMP' -AutomationAccount '<HOST>\svc-irv' `
     -ScriptSource 'C:\path\to\Build-IrvMap.v3.ps1'
#>

[CmdletBinding()]
param(
    [string]$Root              = 'C:\FedRAMP',
    [string]$AutomationAccount,
    [string]$AuditorsGroup,
    [string]$ScriptSource
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$base = Join-Path $Root 'CR26-IRV'
$dirs = 'bin','config','evidence','diagnostics','logs','archive' | ForEach-Object { Join-Path $base $_ }

Write-Host "Scaffold root: $base"

# --- Create directories (idempotent) ---
foreach ($d in @($base) + $dirs) {
    if (Test-Path $d) { Write-Host "  exists : $d" }
    else { New-Item -ItemType Directory -Path $d | Out-Null; Write-Host "  created: $d" }
}

# --- Harden ACLs on the base tree ---
# Break inheritance and rebuild an explicit, minimal DACL.
function Set-HardenedAcl {
    param([string]$Path, [switch]$EvidenceMode)

    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)   # protect (break inheritance), drop inherited rules
    # Clear any explicit rules we might be re-running over.
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $prop    = [System.Security.AccessControl.PropagationFlags]::None
    $allow   = [System.Security.AccessControl.AccessControlType]::Allow

    $rules = @(
        (New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl',$inherit,$prop,$allow)),
        (New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','FullControl',$inherit,$prop,$allow))
    )

    if ($AutomationAccount) {
        # On evidence, grant Modify but strip Delete/DeleteSubdirectoriesAndFiles so the job can
        # write new dated artifacts without being able to remove or overwrite prior evidence.
        if ($EvidenceMode) {
            $rights = [System.Security.AccessControl.FileSystemRights]'Modify' `
                      -band -bnot [System.Security.AccessControl.FileSystemRights]'Delete' `
                      -band -bnot [System.Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles'
        } else {
            $rights = [System.Security.AccessControl.FileSystemRights]'Modify'
        }
        $rules += New-Object System.Security.AccessControl.FileSystemAccessRule($AutomationAccount,$rights,$inherit,$prop,$allow)
    }

    if ($AuditorsGroup) {
        $rules += New-Object System.Security.AccessControl.FileSystemAccessRule($AuditorsGroup,'ReadAndExecute',$inherit,$prop,$allow)
    }

    foreach ($r in $rules) { $acl.AddAccessRule($r) }
    Set-Acl -Path $Path -AclObject $acl
    Write-Host "  hardened ACL: $Path" -ForegroundColor Green
}

Write-Host "`nApplying ACLs..."
Set-HardenedAcl -Path $base                                   # applies to whole tree by inheritance
Set-HardenedAcl -Path (Join-Path $base 'evidence') -EvidenceMode

# --- README ---
$readme = @"
# CR26 T1 - Internet-Reachability (IRV) automation

This tree hosts the CR26 VER-EVA-EIR asset-exposure automation (Jira <STORY-KEY>).

## Layout
- bin\          Build-IrvMap.v2.ps1 and helpers
- config\       externalized manifest/config (if split out later)
- evidence\     dated irv-YYYYMMDD-HHMMSS.csv / .json  (archival IRV evidence)
- diagnostics\  dated irv-*.diagnostics.json (written on every run, incl. failures)
- logs\         scheduled-task transcripts / run logs
- archive\      rotated older evidence

## Running
  pwsh -File .\bin\Build-IrvMap.v2.ps1 -OutputDir .\evidence

Diagnostics land next to evidence unless -OutputDir is split. The prior-artifact flicker
diff reads the most recent irv-*.json in -OutputDir (diagnostics files excluded).

## Evidence integrity
Inheritance is broken on this tree. The automation account has Modify but not Delete on
evidence\, so dated artifacts are create-only from the job's perspective. Do not loosen
these ACLs; evidence is Certification Data feeding the CR26 machine-readable reports.

## Retention
Retain dated artifacts per the SSP / ConMon records schedule. Rotate aged files to archive\
rather than deleting; deletion should be a governed, logged action.

Generated: $(Get-Date -Format o)
"@
Set-Content -Path (Join-Path $base 'README.md') -Value $readme -Encoding UTF8
Write-Host "  wrote: $(Join-Path $base 'README.md')"

# --- Optionally stage the script ---
if ($ScriptSource) {
    if (-not (Test-Path $ScriptSource)) { throw "ScriptSource not found: $ScriptSource" }
    $target = Join-Path (Join-Path $base 'bin') (Split-Path $ScriptSource -Leaf)
    Copy-Item -Path $ScriptSource -Destination $target -Force
    Write-Host "  staged script: $target" -ForegroundColor Green
}

Write-Host "`nScaffold ready at $base" -ForegroundColor Green
Write-Host "Next: run the mapper with -OutputDir '$(Join-Path $base 'evidence')'"
Write-Host "Tree:"
Get-ChildItem $base -Recurse -Directory | Select-Object FullName | Format-Table -AutoSize
