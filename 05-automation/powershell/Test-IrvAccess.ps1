#requires -Version 7.0
<#
.SYNOPSIS
  Firmly determine whether you actually have the Azure access the IRV mapper needs.

.DESCRIPTION
  Get-AzContext is NOT a check. It is a client-side cache of what you last connected to, and it
  will happily report the expected subscription name while every read returns 403 or empty. This was observed
  repeatedly: context said connected, Get-AzVM returned 0, and an unguarded run would have
  emitted a dataset claiming nothing in the boundary is internet-reachable.

  This probe does not ask what the client thinks. It performs the ACTUAL reads the IRV mapper
  depends on and reports what came back. Azure returns EMPTY (not an error) for many reads when
  access is absent, so an empty result is treated as a FAILURE, not as an empty environment.

  Probes, in order of the mapper's dependency:
    1. Context present            (necessary, not sufficient)
    2. Subscription/tenant match  (right place)
    3. ARM compute read           Get-AzVM
    4. ARM network read           Get-AzVirtualNetwork / Get-AzPublicIpAddress
    5. ARG read                   Search-AzGraph  (separate code path from ARM cmdlets)
    6. DEEP read: firewall policy rule collection groups
                                  Microsoft.Network/firewallPolicies/ruleCollectionGroups/read
    7. DEEP read: cloud-service role-instance NIC
                                  Microsoft.Compute/cloudServices/roleInstances/networkInterfaces/read

  Probes 6 and 7 matter most: they are the exact permissions that 403'd when PIM lapsed while the
  shallower reads still worked. A PASS on 3-5 with a FAIL on 6-7 is the partial-decay state.

.PARAMETER Quiet
  Emit nothing; just set the exit code. For use as a gate in a scheduled wrapper.

.EXAMPLE
  .\Test-IrvAccess.ps1

.EXAMPLE
  # Gate the mapper on a verified-access check:
  .\Test-IrvAccess.ps1 -Quiet
  if ($LASTEXITCODE -ne 0) { throw 'Access check failed - not running IRV map.' }

.NOTES
  Exit 0 = all probes passed. Exit 1 = at least one probe failed.
  Read-only. Safe to run any time.
#>

[CmdletBinding()]
param(
    [string]$ExpectedSubscriptionName = '<SUBSCRIPTION-NAME>',   # SET
    [string]$ExpectedSubscriptionId   = '<SUBSCRIPTION-ID>',     # SET
    [string]$ExpectedTenantId         = '<TENANT-ID>',           # SET
    [string]$FirewallPolicyName       = '<FIREWALL-POLICY-NAME>', # SET
    [string]$FirewallPolicyRg         = '<HUB-RG>',              # SET
    [string]$CloudServiceRg           = '<APP-RG>',              # SET (only if using Cloud Services)
    [string]$CloudServiceName         = '<CLOUD-SERVICE-NAME>',  # SET (only if using Cloud Services)
    [string]$RoleInstanceName         = 'WebRole_IN_0',
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Probe {
    param($Name, $Status, $Detail)
    $results.Add([pscustomobject]@{ Probe=$Name; Status=$Status; Detail=$Detail })
}

# --- 1. Context present (necessary, NOT sufficient) -------------------------------------------
$ctx = $null
try {
    $ctx = Get-AzContext
    if ($ctx) { Add-Probe 'Context present' 'PASS' "$($ctx.Account.Id) -> $($ctx.Subscription.Name)" }
    else      { Add-Probe 'Context present' 'FAIL' 'No Az context. Run Connect-AzAccount.' }
} catch { Add-Probe 'Context present' 'FAIL' $_.Exception.Message }

# --- 2. Right subscription / tenant -----------------------------------------------------------
if ($ctx) {
    if ($ctx.Subscription.Id -eq $ExpectedSubscriptionId) { Add-Probe 'Subscription match' 'PASS' $ctx.Subscription.Name }
    else { Add-Probe 'Subscription match' 'FAIL' "Expected $ExpectedSubscriptionName ($ExpectedSubscriptionId), got $($ctx.Subscription.Name) ($($ctx.Subscription.Id))" }
    if ($ctx.Tenant.Id -eq $ExpectedTenantId) { Add-Probe 'Tenant match' 'PASS' $ctx.Tenant.Id }
    else { Add-Probe 'Tenant match' 'FAIL' "Expected $ExpectedTenantId, got $($ctx.Tenant.Id)" }
} else {
    Add-Probe 'Subscription match' 'SKIP' 'no context'
    Add-Probe 'Tenant match'       'SKIP' 'no context'
}

# --- 3-5. Reads that return EMPTY rather than erroring when access is absent --------------------
# Empty is treated as FAILURE. This environment is known non-empty; a zero count means no access.
$readProbes = @(
    @{ Name='ARM compute read (Get-AzVM)';               Script={ @(Get-AzVM).Count };              Expect='>0' }
    @{ Name='ARM network read (Get-AzVirtualNetwork)';   Script={ @(Get-AzVirtualNetwork).Count };  Expect='>0' }
    @{ Name='ARM network read (Get-AzPublicIpAddress)';  Script={ @(Get-AzPublicIpAddress).Count }; Expect='>0' }
)
foreach ($p in $readProbes) {
    try {
        $n = & $p.Script
        if ($n -gt 0) { Add-Probe $p.Name 'PASS' "$n returned" }
        else          { Add-Probe $p.Name 'FAIL' 'Returned 0. Azure returns EMPTY (not an error) when access is absent - this is the silent-decay signature, not an empty environment.' }
    } catch { Add-Probe $p.Name 'FAIL' $_.Exception.Message }
}

# ARG uses a different code path than the ARM cmdlets and can differ.
try {
    $r = Search-AzGraph -Query "Resources | where type =~ 'microsoft.network/publicipaddresses' | count | project total = Count"
    $n = [int](@($r)[0].total)
    if ($n -gt 0) { Add-Probe 'ARG read (Search-AzGraph)' 'PASS' "$n public IPs indexed" }
    else          { Add-Probe 'ARG read (Search-AzGraph)' 'FAIL' 'ARG returned 0. ARG returns empty rather than erroring without access.' }
} catch { Add-Probe 'ARG read (Search-AzGraph)' 'FAIL' $_.Exception.Message }

# --- 6. DEEP: firewall policy rule collection groups -------------------------------------------
# Microsoft.Network/firewallPolicies/ruleCollectionGroups/read
# This 403'd while shallower reads still worked - the partial-decay canary.
try {
    $pol = Get-AzFirewallPolicy -Name $FirewallPolicyName -ResourceGroupName $FirewallPolicyRg
    $grpName = ($pol.RuleCollectionGroups | Select-Object -First 1).Id -split '/' | Select-Object -Last 1
    if (-not $grpName) { throw 'No rule collection groups returned from policy.' }
    $null = Get-AzFirewallPolicyRuleCollectionGroup -Name $grpName `
              -AzureFirewallPolicyName $FirewallPolicyName -ResourceGroupName $FirewallPolicyRg
    Add-Probe 'DEEP: firewall policy ruleCollectionGroups/read' 'PASS' "read '$grpName'"
} catch {
    Add-Probe 'DEEP: firewall policy ruleCollectionGroups/read' 'FAIL' $_.Exception.Message
}

# --- 7. DEEP: cloud-service role-instance NIC --------------------------------------------------
# Microsoft.Compute/cloudServices/roleInstances/networkInterfaces/read
# The mapper cannot resolve any Cloud Service (classic role) backend without this.
try {
    $nicId = "/subscriptions/$ExpectedSubscriptionId/resourceGroups/$CloudServiceRg/providers/Microsoft.Compute/cloudServices/$CloudServiceName/roleInstances/$RoleInstanceName/networkInterfaces/nic1"
    $nic   = Get-AzResource -ResourceId $nicId -ExpandProperties
    $ip    = ($nic.Properties.ipConfigurations | Select-Object -First 1).properties.privateIPAddress
    if ($ip) { Add-Probe 'DEEP: cloudServices roleInstances NIC read' 'PASS' "$RoleInstanceName -> $ip" }
    else     { Add-Probe 'DEEP: cloudServices roleInstances NIC read' 'FAIL' 'NIC read returned no private IP.' }
} catch {
    Add-Probe 'DEEP: cloudServices roleInstances NIC read' 'FAIL' $_.Exception.Message
}

# --- Verdict -----------------------------------------------------------------------------------
$failed = @($results | Where-Object { $_.Status -eq 'FAIL' })
$ok = ($failed.Count -eq 0)

if (-not $Quiet) {
    Write-Host ''
    foreach ($r in $results) {
        $c = switch ($r.Status) { 'PASS' {'Green'} 'FAIL' {'Red'} default {'DarkGray'} }
        Write-Host ("  [{0}] {1}" -f $r.Status, $r.Probe) -ForegroundColor $c
        if ($r.Status -ne 'PASS') { Write-Host ("         {0}" -f $r.Detail) -ForegroundColor DarkGray }
    }
    Write-Host ''
    if ($ok) {
        Write-Host '  ACCESS VERIFIED - PIM is active and all reads the IRV mapper needs succeeded.' -ForegroundColor Green
    } else {
        Write-Host "  ACCESS NOT VERIFIED - $($failed.Count) probe(s) failed. DO NOT trust IRV output right now." -ForegroundColor Red
        $shallowOk = @($results | Where-Object { $_.Probe -like 'ARM*' -and $_.Status -eq 'PASS' }).Count -gt 0
        $deepBad   = @($failed  | Where-Object { $_.Probe -like 'DEEP*' }).Count -gt 0
        if ($shallowOk -and $deepBad) {
            Write-Host '  PARTIAL DECAY: shallow reads work but PIM-granted deep reads do not.' -ForegroundColor Yellow
            Write-Host '  This is the dangerous state - enumeration half-succeeds and can look like a real result.' -ForegroundColor Yellow
        }
        Write-Host ''
        Write-Host '  To fix:' -ForegroundColor Cyan
        Write-Host '    1. Portal -> Entra ID -> Privileged Identity Management -> My roles ->'
        Write-Host '       Azure resources -> Reader on <SUBSCRIPTION-NAME> -> Activate (use max duration).'
        Write-Host '    2. Force a fresh token (the cached one is the problem):'
        Write-Host '       Disconnect-AzAccount; Connect-AzAccount; Set-AzContext -Subscription ''<SUBSCRIPTION-NAME>'''
        Write-Host '    3. Re-run this probe.'
    }
    Write-Host ''
}

exit ($ok ? 0 : 1)
