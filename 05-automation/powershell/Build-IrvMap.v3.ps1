#requires -Version 7.0
#requires -Modules Az.Accounts, Az.Network, Az.Compute, Az.Resources, Az.ResourceGraph, Az.CloudService
<#
.SYNOPSIS
  CR26 T1 - Asset-exposure / internet-reachability map for a FedRAMP authorization boundary in Azure.
  SUPPORTS VER-EVA-EIR evaluation. Emits a dated, joinable resource->exposure dataset.

.DESCRIPTION
  This produces a RESOURCE->EXPOSURE MAP - one input to a per-vulnerability IRV determination.
  It is NOT the determination. FedRAMP requires IRV per DETECTED VULNERABILITY, formed by joining:
    Nessus finding -> scanned asset -> CM-8-approved component -> Azure exposure path -> IRV
  This script produces the exposure-path link and part of the asset link. The CM-8 link is
  CURRENTLY MISSING (see INVENTORY AUTHORITY below).

  ------------------------------------------------------------------------------------------
  INVENTORY AUTHORITY - READ THIS BEFORE TREATING OUTPUT AS EVIDENCE
  ------------------------------------------------------------------------------------------
  There is no confirmed authoritative CM-8 System Component Inventory for this system at the
  time of writing. CM-8 (NIST SP 800-53 Rev5, in the FedRAMP Rev5 Moderate baseline - NOT a
  CR26 rule) requires an inventory that accurately reflects the system and includes all
  components within the authorization boundary.

  This script therefore reconciles TWO REAL AXES only:
      Azure discovery          = compute that currently EXISTS (ARM enumeration)
      Nessus observed baseline = hosts that ANSWERED a discovery scan
  Neither axis is an approval authority. A discovery scan records what was OBSERVED, not what
  is APPROVED; it can never say "this asset is unauthorized". An offline VM, a blocked host, a
  newly created VM, a non-IP resource, or a host that did not answer the probes will not appear
  in it. Accordingly this script does NOT populate any 'ApprovedInCM8' field - a field named
  'approved' populated from observation would be actively misleading to every consumer.

  Until a controlled, approved inventory exists:
      InventoryAuthority       = None
      InventoryAuthorityStatus = CM8InventoryUnavailable
  and the run CANNOT report 'Clean'. Best achievable status is 'InventoryBaselineMissing'.
  Note: 'InventoryDrift' is NOT reportable without an authority - there is nothing to drift from.

  Path to closing this (each step is a governance act, not a script feature):
    1. Start from Azure-discovered boundary components (this script; -EmitCm8Seed writes a draft).
    2. Reconcile against the Nessus observed baseline (this script).
    3. Add known non-Azure components: appliances, databases, containers, supporting resources.
    4. Have the system owner / CM / compliance owner REVIEW AND APPROVE it.
    5. Save the approved result as a controlled cm8-inventory.csv.
    6. Version it and maintain it through the normal configuration-management process.
  Only after step 4 may the file be passed to -Cm8InventoryPath and treated as authoritative.

  ------------------------------------------------------------------------------------------
  NESSUS INPUTS - TWO DIFFERENT THINGS, DO NOT CONFLATE
  ------------------------------------------------------------------------------------------
  -NessusObservedPath : a discovery SCAN RESULT export (what answered). Weaker. Labeled as
                        'observed'. This is what a Host Discovery CSV is.
  -NessusRosterPath   : the CONFIGURED SCAN TARGET LIST (what we authorized scanning of).
                        Stronger for coverage claims. Optional; absent until exportable.
  Only the roster can support a defensible NessusCoverageGap claim. The observed baseline can
  only ever say "did not answer", which has many innocent explanations.

  ------------------------------------------------------------------------------------------
  RUN STATUS
  ------------------------------------------------------------------------------------------
    Failed            : cannot demonstrate coverage - unsupported edge, unresolvable backend/NAT/
                        FQDN target, ARG results that do not reconcile, traversal with no
                        defensible target. Diagnostics written; NO dataset emitted.
    ManifestDrift     : a supported edge discovered outside the approved manifest, or a manifest
                        edge not discovered, or exposure resolved to a host not in Azure discovery.
    InventoryDrift    : discovery/baseline disagreement requiring review.
    NessusCoverageGap : an existing asset is absent from the Nessus axis.
    InventoryBaselineMissing : reconciled as far as the available axes allow, but no approved
                        CM-8 inventory exists, so completeness against the authorization boundary
                        is NOT demonstrated. Azure/Nessus differences are recorded as observation
                        mismatches, NOT as inventory drift (drift requires an authority).
    Clean             : reserved. Unreachable until an approved CM-8 inventory is supplied.
  Precedence: Failed > ManifestDrift > InventoryDrift > NessusCoverageGap > InventoryBaselineMissing > Clean.
    InventoryDrift is only reachable when an approved CM-8 inventory is supplied.

  ------------------------------------------------------------------------------------------
  IRV REACHABILITY TREATMENT - conservative
  ------------------------------------------------------------------------------------------
    - An internet-facing edge that forwards into an application path containing a resource makes
      that resource IRV=true BY DEFAULT.
    - WAF rules, NSGs, host firewalls, and authentication controls are RECORDED AS MITIGATION
      CONTEXT but do NOT automatically negate reachability here - not because controls can never
      negate IRV, but because this script performs no effective-rule or payload-specific analysis
      and therefore cannot PROVE the triggering payload is intercepted before the vulnerable
      component. FedRAMP permits a non-internet-reachable classification when the triggering
      payload is demonstrably intercepted/filtered/rejected before processing; this tool lacks
      that evidence, so it errs toward IRV=true to avoid under-reporting.
    - IRV is current-state: recomputed every run. Prior artifact is loaded and per-resource
      changes annotated (PriorIRV / PriorRunUtc / IRVChanged) so a legitimate control-driven
      change does not read as unexplained flicker.

  JOIN PRIORITY (never private IP alone - it changes and is reused):
      Azure resource ID / ip-config ID -> primary, exact
      Private IP                       -> secondary fallback
      Hostname                         -> tertiary fallback + cross-check
  Ambiguous matches are FLAGGED, never silently accepted.

.NOTES
  Static-reviewed; NOT yet validated against a live subscription. '# VALIDATE:' marks points
  needing a live-run check. Targets PowerShell 7.
#>

[CmdletBinding()]
param(
    [string]$OutputDir                = (Join-Path (Get-Location) 'irv-runs'),
    [string]$ExpectedSubscriptionName = '<SUBSCRIPTION-NAME>',   # SET
    [string]$ExpectedSubscriptionId   = '<SUBSCRIPTION-ID>',     # SET
    [string]$ExpectedTenantId         = '<TENANT-ID>',           # SET

    # Approved CM-8 inventory. OPTIONAL and currently expected to be absent.
    # Only pass this once a controlled inventory has been reviewed and APPROVED.
    [string]$Cm8InventoryPath,

    # Nessus discovery SCAN RESULT export (what answered). Weak/observed axis.
    [string]$NessusObservedPath,

    # Nessus CONFIGURED TARGET LIST (what we authorized scanning of). Strong/roster axis.
    [string]$NessusRosterPath,

    # Write a draft cm8-seed CSV from Azure discovery to bootstrap the inventory (step 1 above).
    [switch]$EmitCm8Seed,

    # Bypass the hand-verified known-truth regression assertion. Use ONLY for a first run in a
    # different environment. Never use to silence a failing assertion in this one - a baseline
    # miss means either the environment changed (update the baseline) or the tool regressed.
    [switch]$SkipBaselineAssertion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------------------------
# Governance baseline. Discovery is compared against this; it does NOT drive discovery.
# ---------------------------------------------------------------------------------------------
# TEMPLATE: replace with the approved internet-facing edges of YOUR boundary.
# Supported classes: AppGateway, LoadBalancer, Firewall, Bastion (see resolvers below).
$EdgeManifest = @(
    [pscustomobject]@{ Class='AppGateway';   Name='<appgw-example-01>' }
    [pscustomobject]@{ Class='LoadBalancer'; Name='<lb-example-01>'    }
    [pscustomobject]@{ Class='LoadBalancer'; Name='<lb-example-02>'    }
    [pscustomobject]@{ Class='Firewall';     Name='<fw-hub-01>'        }
    [pscustomobject]@{ Class='Bastion';      Name='<bastion-hub-01>'   }
)

# Expected assertions about edges. These are VALIDATED against the run, not asserted as fact.
# A contradicted expectation becomes a finding rather than a stale claim in the artifact.
$EdgeExpectations = @(
    [pscustomobject]@{ Edge='<fw-hub-01>';     Expect='NoInboundDnat'
                       Basis='Egress-only. Firewall policy DNAT rule collection group contained 0 rule collections at time of determination; no inbound forwarding.' }
    [pscustomobject]@{ Edge='<bastion-hub-01>'; Expect='NoForwardingPath'
                       Basis='Management plane; authenticated session brokering. Not an internet-forwarding path into an application. Bastion-only access is not internet-reachable.' }
)

# ---------------------------------------------------------------------------------------------
# KNOWN-TRUTH REGRESSION BASELINE
# TEMPLATE: populate from a manual traversal of YOUR environment, then confirm with the first
# clean automated run. The example rows below are placeholders and WILL fail the assertion;
# run with -SkipBaselineAssertion until you have replaced them.
# This is a REGRESSION GUARD, not a source of truth: the map must keep finding what we know is
# there. It exists because two silent-failure classes were observed during development -
# private-IP collision (wrong attribution) and permission decay (wrong absence) - both of which
# produced plausible-looking output that only a known baseline would have caught.
#
# MAINTENANCE: when the environment legitimately changes, update this baseline as a deliberate,
# reviewed act - never by deleting the assertion to make a run pass.
# Set -SkipBaselineAssertion only for a first run in a DIFFERENT environment, never to silence a
# failure in this one.
# ---------------------------------------------------------------------------------------------
$KnownReachable = @(
    [pscustomobject]@{ Hostname='<mgmt-vm-01>';  PrivateIp='10.0.1.4'; Edge='<appgw-example-01>' }
    [pscustomobject]@{ Hostname='WebRole_IN_0';  PrivateIp='10.0.2.4'; Edge='<lb-example-01>'    }
    [pscustomobject]@{ Hostname='WebRole_IN_1';  PrivateIp='10.0.2.5'; Edge='<lb-example-01>'    }
    [pscustomobject]@{ Hostname='WebRole_IN_0';  PrivateIp='10.0.3.4'; Edge='<lb-example-02>'    }
    [pscustomobject]@{ Hostname='WebRole_IN_1';  PrivateIp='10.0.3.5'; Edge='<lb-example-02>'    }
)
# Hand-verified NOT reachable: no LB rule forwards to any worker role. A worker turning up
# IRV=true is the signature of an attribution bug (this exact false positive was observed).
$KnownNotReachable = @('WorkerRole_IN_0','WorkerRole_IN_1','WorkerRoleLowPriority_IN_0','WorkerRoleLowPriority_IN_1','WorkerRoleLowPriority_IN_2')

# ---------------------------------------------------------------------------------------------
function Invoke-ArgPaged {
    param([Parameter(Mandatory)][string]$Query, [int]$ExpectedCount = -1)    $all = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    do {
        $page = if ($skip) { Search-AzGraph -Query $Query -First 1000 -SkipToken $skip }
                else        { Search-AzGraph -Query $Query -First 1000 }
        foreach ($r in $page) { $all.Add($r) }
        $skip = $page.SkipToken
    } while ($skip)
    if ($ExpectedCount -ge 0 -and $all.Count -ne $ExpectedCount) {
        throw "ARG_RECONCILE_FAIL: collected $($all.Count) rows, count query expected $ExpectedCount. Results incomplete; coverage cannot be demonstrated."
    }
    # An access failure makes ARG return EMPTY rather than erroring - 0 == 0 would reconcile
    # "successfully" and silently produce an empty environment. Callers that expect a non-empty
    # universe must say so.
    return $all
}
function Get-ArgCount {
    param([Parameter(Mandatory)][string]$FilterQuery)
    # NOTE: KQL's 'count' operator returns a column literally named 'Count', which collides with
    # PowerShell's array .Count property - reading .Count on the result gives the ROW COUNT (1),
    # not the value. Project to an unambiguous name and index the row explicitly.
    $r   = Search-AzGraph -Query "$FilterQuery | count | project total = Count"
    $row = @($r)[0]
    if ($null -eq $row) { throw "ARG_COUNT_FAIL: count query returned no rows for filter: $FilterQuery" }
    return [int]$row.total
}

function Assert-Context {
    $ctx = Get-AzContext
    if (-not $ctx)                                        { throw "No Az context. Connect / activate PIM first." }
    if ($ctx.Subscription.Id -ne $ExpectedSubscriptionId){ throw "Wrong subscription: expected $ExpectedSubscriptionName ($ExpectedSubscriptionId), got $($ctx.Subscription.Name) ($($ctx.Subscription.Id))." }
    if ($ctx.Tenant.Id       -ne $ExpectedTenantId)      { throw "Wrong tenant: expected $ExpectedTenantId, got $($ctx.Tenant.Id)." }
    return $ctx
}

# ---------------------------------------------------------------------------------------------
# Resolve an ip-config resource ID -> { Hostname; PrivateIp; IpConfigId; ResolvePath }.
# Selects the EXACT named ip-config (never the first on the NIC - that returns the wrong private
# IP on a multi-ip-config NIC and corrupts the IP-keyed join).
# ---------------------------------------------------------------------------------------------
function Resolve-BackendHost {
    param([Parameter(Mandatory)][string]$IpConfigId)
    $nicId        = ($IpConfigId -split '/ipConfigurations/')[0]
    $ipConfigName = ($IpConfigId -split '/ipConfigurations/')[-1]

    $selectExact = {
        param($nicRes)
        $nicRes.Properties.ipConfigurations |
            Where-Object { $_.id -ieq $IpConfigId -or $_.name -ieq $ipConfigName } |
            Select-Object -First 1
    }
    # Subnet ID carries the VNet; VNet+Subnet scope makes a repeated private IP unambiguous.
    $subnetOf = {
        param($ipObj)
        if ($ipObj.PSObject.Properties.Name -contains 'properties' -and
            $ipObj.properties.PSObject.Properties.Name -contains 'subnet') { $ipObj.properties.subnet.id } else { $null }
    }

    if ($IpConfigId -match '/cloudServices/([^/]+)/roleInstances/([^/]+)/networkInterfaces/') {
        $cloudService = $Matches[1]; $roleInstance = $Matches[2]
        $nicRes = Get-AzResource -ResourceId $nicId -ExpandProperties
        $ipObj  = & $selectExact $nicRes
        if (-not $ipObj) { return $null }
        $subnetId = & $subnetOf $ipObj
        return [pscustomobject]@{
            Hostname=$roleInstance; PrivateIp=$ipObj.properties.privateIPAddress
            IpConfigId=$IpConfigId; ResolvePath="cloudService:$cloudService"
            SubnetId=$subnetId; VNetId=($subnetId ? (($subnetId -split '/subnets/')[0]) : $null)
            CloudServiceName=$cloudService; RoleInstanceName=$roleInstance }
    }
    elseif ($IpConfigId -match '/networkInterfaces/[^/]+/ipConfigurations/') {
        $nicRes = Get-AzResource -ResourceId $nicId -ExpandProperties
        $ipObj  = & $selectExact $nicRes
        if (-not $ipObj) { return $null }
        $vmName = if ($nicRes.Properties.virtualMachine.id) { ($nicRes.Properties.virtualMachine.id -split '/')[-1] } else { $nicRes.Name }
        $subnetId = & $subnetOf $ipObj
        return [pscustomobject]@{
            Hostname=$vmName; PrivateIp=$ipObj.properties.privateIPAddress
            IpConfigId=$IpConfigId; ResolvePath='armNic'
            SubnetId=$subnetId; VNetId=($subnetId ? (($subnetId -split '/subnets/')[0]) : $null)
            CloudServiceName=$null; RoleInstanceName=$null }
    }
    return $null
}

# ---------------------------------------------------------------------------------------------
# DISCOVERY: PIP-anchored public-edge inventory, plus public-IP-PREFIX frontend detection.
# ---------------------------------------------------------------------------------------------
function Get-PublicEdgeInventory {
    $pipFilter = "Resources | where type =~ 'microsoft.network/publicipaddresses'"
    $pipCount  = Get-ArgCount -FilterQuery $pipFilter
    $pips = Invoke-ArgPaged -ExpectedCount $pipCount -Query @"
$pipFilter
| project id, name, resourceGroup,
          ipAddress = tostring(properties.ipAddress),
          assocId   = tostring(properties.ipConfiguration.id)
"@

    # Edge-side frontend mapping, FLATTENED IN KQL. Walking these nested properties in PowerShell
    # under Set-StrictMode throws when a frontend has no publicIPAddress (e.g. a private frontend);
    # in KQL a missing path is simply an empty string, so private/public frontends coexist safely.
    $feQuery = @"
Resources
| where type in~ ('microsoft.network/applicationgateways','microsoft.network/loadbalancers','microsoft.network/azurefirewalls','microsoft.network/bastionhosts')
| extend feList = iff(type =~ 'microsoft.network/applicationgateways' or type =~ 'microsoft.network/loadbalancers',
                      properties.frontendIPConfigurations, properties.ipConfigurations)
| mv-expand fe = feList
| project ownerId = id, ownerName = name, ownerType = tolower(tostring(type)), resourceGroup,
          feName   = tostring(fe.name),
          pipId    = tostring(fe.properties.publicIPAddress.id),
          prefixId = tostring(fe.properties.publicIPPrefix.id)
"@
    $fes = Invoke-ArgPaged -Query $feQuery

    $classOf = @{
        'microsoft.network/applicationgateways' = 'AppGateway'
        'microsoft.network/loadbalancers'       = 'LoadBalancer'
        'microsoft.network/azurefirewalls'      = 'Firewall'
        'microsoft.network/bastionhosts'        = 'Bastion'
    }

    # pipId -> owning edge
    $owner = @{}
    foreach ($fe in $fes) {
        if (-not [string]::IsNullOrEmpty($fe.pipId)) {
            $owner[$fe.pipId.ToLower()] = @{ Class=$classOf[$fe.ownerType]; OwnerName=$fe.ownerName; OwnerId=$fe.ownerId }
        }
        # A public frontend backed by a PUBLIC IP PREFIX has no publicIPAddresses resource and is
        # therefore invisible to the PIP-anchored universe above - cannot demonstrate its exposure.
        if (-not [string]::IsNullOrEmpty($fe.prefixId)) {
            $script:FailReasons += "PUBLIC_IP_PREFIX_UNSUPPORTED: $($classOf[$fe.ownerType]) '$($fe.ownerName)' frontend '$($fe.feName)' is backed by public IP prefix $($fe.prefixId); this version does not traverse prefix-backed frontends, so its exposure cannot be demonstrated."
        }
    }

    $edges = foreach ($p in $pips) {
        $o = $owner[$p.id.ToLower()]
        if ($o) { [pscustomobject]@{ Class=$o.Class; Name=$o.OwnerName; OwnerId=$o.OwnerId; PipId=$p.id; PipAddress=$p.ipAddress } }
        elseif ([string]::IsNullOrEmpty($p.ipAddress)) { [pscustomobject]@{ Class='Unattached'; Name=$p.name; OwnerId=$null; PipId=$p.id; PipAddress=$null } }
        elseif ($p.assocId -match '/networkInterfaces/[^/]+/ipConfigurations/') { [pscustomobject]@{ Class='DirectNic'; Name=$p.name; OwnerId=$p.assocId; PipId=$p.id; PipAddress=$p.ipAddress } }
        elseif ([string]::IsNullOrEmpty($p.assocId)) { [pscustomobject]@{ Class='Unattached'; Name=$p.name; OwnerId=$null; PipId=$p.id; PipAddress=$p.ipAddress } }
        else { [pscustomobject]@{ Class='Unsupported'; Name=$p.name; OwnerId=$p.assocId; PipId=$p.id; PipAddress=$p.ipAddress } }
    }
    return $edges | Sort-Object Class, Name, PipId -Unique
}

# ---------------------------------------------------------------------------------------------
# TRAVERSAL WALKERS
# ---------------------------------------------------------------------------------------------
function New-ExposureRow {
    param($Hostname,$PrivateIp,$IpConfigId,$Path,$Port,$Protocol,$EdgeDevice,$PublicIp,$Mitigation,$Context,$VNetId,$SubnetId)
    [pscustomobject]@{ Hostname=$Hostname; PrivateIp=$PrivateIp; IpConfigId=$IpConfigId; Path=$Path
                       Port=$Port; Protocol=$Protocol; EdgeDevice=$EdgeDevice; PublicIp=$PublicIp
                       Mitigation=$Mitigation; Context=$Context; VNetId=$VNetId; SubnetId=$SubnetId }
}

function Resolve-FqdnTarget {
    param([string]$Fqdn, [string]$Who)
    $ips = @()
    try { $ips = [System.Net.Dns]::GetHostAddresses($Fqdn) | ForEach-Object { $_.IPAddressToString } } catch {}
    if (-not $ips) {
        $script:FailReasons += "FQDN_TARGET_UNRESOLVED [$Who]: backend FQDN '$Fqdn' could not be resolved to an address; its exposure cannot be demonstrated."
    }
    return $ips
}

function Get-AppGatewayExposure {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup)
    $agw = Get-AzApplicationGateway -Name $Name -ResourceGroupName $ResourceGroup   # RG-qualified: names not globally unique
    if ($agw.OperationalState -ne 'Running') { Write-Warning "$Name OperationalState=$($agw.OperationalState); forwards nothing."; return @() }

    # Label WAF only if the gateway actually is one - not by assumption.
    $isWaf = ($agw.Sku.Tier -match 'WAF') -or ($agw.WebApplicationFirewallConfiguration -and $agw.WebApplicationFirewallConfiguration.Enabled) -or ($null -ne $agw.FirewallPolicy)
    $mitig = if ($isWaf) { 'WAF' } else { 'none' }

    $publicFeIds  = @($agw.FrontendIpConfigurations | Where-Object { $_.PublicIPAddress } | ForEach-Object { $_.Id })
    $poolById     = @{}; $agw.BackendAddressPools            | ForEach-Object { $poolById[$_.Id] = $_ }
    $settingsById = @{}; $agw.BackendHttpSettingsCollection  | ForEach-Object { $settingsById[$_.Id] = $_ }
    $pathMapById  = @{}; $agw.UrlPathMaps                    | ForEach-Object { $pathMapById[$_.Id] = $_ }
    $script:__agw = @()

    $emitPool = {
        param($poolId,$settingsId,$listener,$pip,$pathCtx)
        $pool = $poolById[$poolId]; if (-not $pool) { return }
        $settings = $settingsById[$settingsId]
        $bport  = if ($settings) { $settings.Port }     else { $null }   # backend port lives on settings, NOT the listener
        $bproto = if ($settings) { $settings.Protocol } else { $null }
        foreach ($cfg in $pool.BackendIPConfigurations) {
            $r = Resolve-BackendHost -IpConfigId $cfg.Id
            if ($r) {
                $script:__agw += New-ExposureRow $r.Hostname $r.PrivateIp $r.IpConfigId "Internet->AppGW->backend" `
                    $bport $bproto $Name ($pip -split '/')[-1] $mitig "listener=$($listener.Name); host=$($listener.HostName); $pathCtx; resolve=$($r.ResolvePath)"
            } else {
                $script:FailReasons += "APPGW_BACKEND_UNRESOLVED [$Name]: pool member ip-config $($cfg.Id) could not be resolved."
            }
        }
        foreach ($ba in $pool.BackendAddresses) {
            if ($ba.IpAddress) {
                $script:__agw += New-ExposureRow $ba.IpAddress $ba.IpAddress $null "Internet->AppGW->backend(explicit-ip)" `
                    $bport $bproto $Name ($pip -split '/')[-1] $mitig "listener=$($listener.Name); EXPLICIT-IP-REVIEW; $pathCtx"
            }
            elseif ($ba.Fqdn) {
                foreach ($ip in (Resolve-FqdnTarget -Fqdn $ba.Fqdn -Who "AppGW $Name")) {
                    $script:__agw += New-ExposureRow $ba.Fqdn $ip $null "Internet->AppGW->backend(fqdn)" `
                        $bport $bproto $Name ($pip -split '/')[-1] $mitig "listener=$($listener.Name); fqdn=$($ba.Fqdn); FQDN-DNS-VIEW-CAVEAT; $pathCtx"
                }
            }
        }
    }

    foreach ($rule in $agw.RequestRoutingRules) {
        $listener = $agw.HttpListeners | Where-Object { $_.Id -eq $rule.HttpListener.Id }
        if (-not $listener) { continue }
        if ($listener.FrontendIpConfiguration.Id -notin $publicFeIds) { continue }   # private listener -> not internet
        $pip = ($agw.FrontendIpConfigurations | Where-Object { $_.Id -eq $listener.FrontendIpConfiguration.Id }).PublicIPAddress.Id

        if ($rule.BackendAddressPool -and $rule.BackendAddressPool.Id) {
            & $emitPool $rule.BackendAddressPool.Id $rule.BackendHttpSettings.Id $listener $pip 'path=basic'
        }
        if ($rule.UrlPathMap -and $rule.UrlPathMap.Id) {
            $pm = $pathMapById[$rule.UrlPathMap.Id]
            if ($pm) {
                & $emitPool $pm.DefaultBackendAddressPool.Id $pm.DefaultBackendHttpSettings.Id $listener $pip 'path=default'
                foreach ($pr in $pm.PathRules) {
                    $sId = if ($pr.BackendHttpSettings.Id) { $pr.BackendHttpSettings.Id } else { $pm.DefaultBackendHttpSettings.Id }
                    & $emitPool $pr.BackendAddressPool.Id $sId $listener $pip ("path=" + ($pr.Paths -join '|'))
                }
            } else {
                $script:FailReasons += "APPGW_PATHMAP_UNRESOLVED [$Name]: rule $($rule.Name) references URL path map $($rule.UrlPathMap.Id) not found."
            }
        }
    }
    return $script:__agw
}

function Get-LoadBalancerExposure {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup)
    $lb = Get-AzLoadBalancer -Name $Name -ResourceGroupName $ResourceGroup
    $publicFeIds = @($lb.FrontendIpConfigurations | Where-Object { $_.PublicIpAddress } | ForEach-Object { $_.Id })
    $poolById = @{}; $lb.BackendAddressPools | ForEach-Object { $poolById[$_.Id] = $_ }
    $sku = if ($lb.Sku) { $lb.Sku.Name } else { 'Unknown' }
    $mitig = "none(LB-Sku=$sku)"    # do not assert 'Basic' regardless of actual SKU
    $script:__lb = @()
    $pipFor = { param($feId) (($lb.FrontendIpConfigurations | Where-Object { $_.Id -eq $feId }).PublicIpAddress.Id -split '/')[-1] }

    $emitPoolMembers = {
        param($pool, $port, $proto, $feId, $kind, $ruleName)
        # Model 1: NIC / ip-configuration membership.
        foreach ($cfg in $pool.BackendIpConfigurations) {
            $r = Resolve-BackendHost -IpConfigId $cfg.Id
            if ($r) {
                $script:__lb += New-ExposureRow $r.Hostname $r.PrivateIp $r.IpConfigId "Internet->LB($kind)->backend" `
                    $port $proto $Name (& $pipFor $feId) $mitig "rule=$ruleName; resolve=$($r.ResolvePath)"
            } else {
                $script:FailReasons += "LB_BACKEND_UNRESOLVED [$Name]: rule $ruleName backend ip-config $($cfg.Id) could not be resolved."
            }
        }
        # Model 2: IP-address-based membership (LoadBalancerBackendAddresses).
        # NOTE: Azure populates this collection for NIC-based pools too, as a parallel view where
        # NetworkInterfaceIPConfiguration is set and IpAddress is null. Those members are ALREADY
        # resolved by the BackendIpConfigurations loop above - they are not failures. Only a member
        # with neither an address nor a NIC reference is genuinely unresolvable.
        if ($pool.PSObject.Properties.Name -contains 'LoadBalancerBackendAddresses') {
            foreach ($ba in @($pool.LoadBalancerBackendAddresses)) {
                $ip     = $ba.IpAddress
                $nicRef = $null
                if ($ba.PSObject.Properties.Name -contains 'NetworkInterfaceIPConfiguration') { $nicRef = $ba.NetworkInterfaceIPConfiguration }
                if ($ip) {
                    $script:__lb += New-ExposureRow $ip $ip $null "Internet->LB($kind)->backend(ip-based)" `
                        $port $proto $Name (& $pipFor $feId) $mitig "rule=$ruleName; poolMember=$($ba.Name); IP-BASED-POOL"
                }
                elseif ($nicRef) {
                    # NIC-referenced member: same backend as the ip-config loop already emitted. Skip.
                    continue
                }
                else {
                    $script:FailReasons += "LB_POOL_MEMBER_UNRESOLVED [$Name]: rule $ruleName pool member '$($ba.Name)' has neither an IP address nor a NIC reference."
                }
            }
        }
    }

    foreach ($lbr in $lb.LoadBalancingRules) {
        if ($lbr.FrontendIPConfiguration.Id -notin $publicFeIds) { continue }
        $pool = $poolById[$lbr.BackendAddressPool.Id]
        if (-not $pool) { $script:FailReasons += "LB_POOL_MISSING [$Name]: rule $($lbr.Name) references pool $($lbr.BackendAddressPool.Id) not found."; continue }
        & $emitPoolMembers $pool $lbr.BackendPort $lbr.Protocol $lbr.FrontendIPConfiguration.Id 'rule' $lbr.Name
    }

    # Inbound NAT rules: resolve-or-fail.
    foreach ($nat in $lb.InboundNatRules) {
        if ($nat.FrontendIPConfiguration.Id -notin $publicFeIds) { continue }
        $mflag = if ($nat.BackendPort -in 3389,22,5985,5986) { '; MANAGEMENT-PORT-BASTION-BYPASS-FINDING' } else { '' }
        $resolved = $false
        if ($nat.BackendIPConfiguration -and $nat.BackendIPConfiguration.Id) {
            $r = Resolve-BackendHost -IpConfigId $nat.BackendIPConfiguration.Id
            if ($r) {
                $script:__lb += New-ExposureRow $r.Hostname $r.PrivateIp $r.IpConfigId "Internet->LB(nat)->host" `
                    $nat.BackendPort $nat.Protocol $Name (& $pipFor $nat.FrontendIPConfiguration.Id) $mitig "rule=$($nat.Name)$mflag; resolve=$($r.ResolvePath)"
                $resolved = $true
            }
        }
        elseif ($nat.BackendAddressPool -and $nat.BackendAddressPool.Id -and $poolById[$nat.BackendAddressPool.Id]) {
            & $emitPoolMembers $poolById[$nat.BackendAddressPool.Id] $nat.BackendPort $nat.Protocol $nat.FrontendIPConfiguration.Id 'nat-pool' "$($nat.Name)$mflag"
            $resolved = $true
        }
        if (-not $resolved) {
            $script:FailReasons += "LB_NAT_UNRESOLVED [$Name]: public inbound NAT rule $($nat.Name) has no resolvable backend target."
        }
    }

    # Inbound NAT POOLS: traverse-or-fail. A public NAT pool forwards a port RANGE to a backend
    # pool (typically a VMSS); leaving it unhandled would silently omit that exposure.
    if ($lb.PSObject.Properties.Name -contains 'InboundNatPools') {
        foreach ($np in @($lb.InboundNatPools)) {
            if ($np.FrontendIPConfiguration.Id -notin $publicFeIds) { continue }
            $script:FailReasons += "LB_NAT_POOL_UNSUPPORTED [$Name]: public inbound NAT pool '$($np.Name)' (frontend ports $($np.FrontendPortRangeStart)-$($np.FrontendPortRangeEnd) -> backend $($np.BackendPort)) is not traversed by this version; its exposure cannot be demonstrated."
        }
    }
    return $script:__lb
}

function Get-FirewallExposure {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup)
    $out = @()
    $fw  = Get-AzFirewall -Name $Name -ResourceGroupName $ResourceGroup

    # This firewall's OWN public addresses. DNAT rules are only internet exposure if their
    # destination is one of these - a policy can be shared, and Azure Firewall supports
    # private-IP DNAT, which is NOT internet exposure.
    $fwPublicIps = @()
    foreach ($ic in $fw.IpConfigurations) {
        if ($ic.PublicIpAddress -and $ic.PublicIpAddress.Id) {
            try { $fwPublicIps += (Get-AzResource -ResourceId $ic.PublicIpAddress.Id -ExpandProperties).Properties.ipAddress } catch {}
        }
    }
    $fwPublicIps = $fwPublicIps | Where-Object { $_ }

    if (-not $fw.FirewallPolicy) {
        # Classic inline NAT rule collections.
        if ($fw.NatRuleCollections -and $fw.NatRuleCollections.Count -gt 0) {
            $script:FailReasons += "FW_CLASSIC_NAT_UNSUPPORTED [$Name]: firewall has no policy and carries $($fw.NatRuleCollections.Count) classic NAT rule collection(s), which this version does not traverse; its inbound exposure cannot be demonstrated."
        }
        return $out
    }

    $polName = ($fw.FirewallPolicy.Id -split '/')[-1]
    $polRg   = ($fw.FirewallPolicy.Id -split '/')[4]
    $pol     = Get-AzFirewallPolicy -Name $polName -ResourceGroupName $polRg

    foreach ($g in $pol.RuleCollectionGroups) {
        $grpName = ($g.Id -split '/')[-1]
        $grp = Get-AzFirewallPolicyRuleCollectionGroup -Name $grpName -AzureFirewallPolicyName $polName -ResourceGroupName $polRg
        foreach ($rc in $grp.Properties.RuleCollection) {
            # Identify NAT collections by TYPE, never by group/collection NAME.  # VALIDATE: property name
            $isNat = ($rc.RuleCollectionType -eq 'FirewallPolicyNatRuleCollection') -or
                     (($rc.PSObject.Properties.Name -contains 'Action') -and $rc.Action.Type -eq 'Dnat')
            if (-not $isNat) { continue }
            foreach ($rule in $rc.Rules) {
                # Scope to THIS firewall's public frontend. Private-IP DNAT is not internet exposure.
                $dests = @($rule.DestinationAddresses)
                $hitsPublic = $dests | Where-Object { $_ -in $fwPublicIps }
                if (-not $hitsPublic) { continue }

                $target = $rule.TranslatedAddress
                if (-not $target -and $rule.TranslatedFqdn) {
                    foreach ($ip in (Resolve-FqdnTarget -Fqdn $rule.TranslatedFqdn -Who "FW $Name rule $($rule.Name)")) {
                        $mflag = if ("$($rule.TranslatedPort)" -in '3389','22','5985','5986') { '; MANAGEMENT-PORT-BASTION-BYPASS-FINDING' } else { '' }
                        $out += New-ExposureRow $rule.TranslatedFqdn $ip $null "Internet->FW-DNAT->target(fqdn)" `
                            $rule.TranslatedPort ($rule.IpProtocols -join ',') $Name ($hitsPublic -join ',') 'firewall' `
                            "rule=$($rule.Name); group=$grpName; src=$($rule.SourceAddresses -join ',')$mflag"
                    }
                    continue
                }
                if (-not $target) {
                    $script:FailReasons += "FW_DNAT_NO_TARGET [$Name]: NAT rule $($rule.Name) in group $grpName has no translated target."
                    continue
                }
                $mflag = if ("$($rule.TranslatedPort)" -in '3389','22','5985','5986') { '; MANAGEMENT-PORT-BASTION-BYPASS-FINDING' } else { '' }
                $out += New-ExposureRow $target $rule.TranslatedAddress $null "Internet->FW-DNAT->target" `
                    $rule.TranslatedPort ($rule.IpProtocols -join ',') $Name ($hitsPublic -join ',') 'firewall' `
                    "rule=$($rule.Name); group=$grpName; src=$($rule.SourceAddresses -join ',')$mflag"
            }
        }
    }
    return $out
}

function Get-DirectNicExposure {
    param([Parameter(Mandatory)]$Edge)
    $r = Resolve-BackendHost -IpConfigId $Edge.OwnerId
    if (-not $r) {
        $script:FailReasons += "DIRECTNIC_UNRESOLVED: PIP $($Edge.Name) ($($Edge.PipAddress)) attached NIC ip-config $($Edge.OwnerId) could not be resolved."
        return @()
    }
    return @(New-ExposureRow $r.Hostname $r.PrivateIp $r.IpConfigId "Internet->direct-NIC-PIP" `
        '*(NSG-governed)' 'any' "NIC:$($Edge.Name)" $Edge.PipAddress 'NSG-only' "directPublicIp; resolve=$($r.ResolvePath)")
}

# ---------------------------------------------------------------------------------------------
# AXIS 1: Azure discovery - compute that currently EXISTS.
# ---------------------------------------------------------------------------------------------
function Get-BoundaryComputeHosts {
    $hosts = @()
    foreach ($vm in Get-AzVM) {
        foreach ($nicRef in $vm.NetworkProfile.NetworkInterfaces) {
            $nic = Get-AzResource -ResourceId $nicRef.Id -ExpandProperties
            foreach ($ip in $nic.Properties.ipConfigurations) {
                $subnetId = if ($ip.properties.PSObject.Properties.Name -contains 'subnet') { $ip.properties.subnet.id } else { $null }
                $hosts += [pscustomobject]@{
                    Hostname=$vm.Name; PrivateIp=$ip.properties.privateIPAddress
                    IpConfigId=$ip.id; AzureResourceId=$vm.Id
                    SubnetId=$subnetId; VNetId=($subnetId ? (($subnetId -split '/subnets/')[0]) : $null)
                    CloudServiceName=$null; RoleInstanceName=$null
                    Kind='arm-vm'; ResourceGroup=$vm.ResourceGroupName }
            }
        }
    }
    foreach ($cs in Get-AzResource -ResourceType 'Microsoft.Compute/cloudServices') {
        foreach ($ri in Get-AzCloudServiceRoleInstance -ResourceGroupName $cs.ResourceGroupName -CloudServiceName $cs.Name -WarningAction SilentlyContinue) {
            $nicRef = $ri.NetworkProfileNetworkInterface | Select-Object -First 1
            if (-not $nicRef) { continue }
            $nic = Get-AzResource -ResourceId $nicRef.Id -ExpandProperties
            foreach ($ip in $nic.Properties.ipConfigurations) {
                $subnetId = if ($ip.properties.PSObject.Properties.Name -contains 'subnet') { $ip.properties.subnet.id } else { $null }
                $hosts += [pscustomobject]@{
                    Hostname=$ri.Name; PrivateIp=$ip.properties.privateIPAddress
                    IpConfigId="$($nicRef.Id)/ipConfigurations/$($ip.name)"
                    AzureResourceId="$($cs.ResourceId)/roleInstances/$($ri.Name)"
                    SubnetId=$subnetId; VNetId=($subnetId ? (($subnetId -split '/subnets/')[0]) : $null)
                    CloudServiceName=$cs.Name; RoleInstanceName=$ri.Name
                    Kind='cloudservice-roleinstance'; ResourceGroup=$cs.ResourceGroupName }
            }
        }
    }
    return $hosts
}

# ---------------------------------------------------------------------------------------------
# AXIS 2: Nessus OBSERVED baseline - hosts that ANSWERED a discovery scan.
# This is NOT an inventory and NOT an approval source. It records what responded.
# ---------------------------------------------------------------------------------------------
function Import-NessusObserved {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "NessusObservedPath not found: $Path" }
    $rows = Import-Csv -Path $Path
    if (-not ($rows | Get-Member -Name 'Host')) { throw "Nessus observed export has no 'Host' column: $Path" }

    # Provenance from plugin 19506 (Nessus Scan Information), if present.
    $meta = @{ ScanName=$null; Policy=$null; Credentialed=$null; PortScanner=$null; ScannerIp=$null; PluginFeed=$null }
    $info = $rows | Where-Object { $_.'Plugin ID' -eq '19506' } | Select-Object -First 1
    if ($info) {
        $o = $info.'Plugin Output'
        if ($o -match 'Scan name\s*:\s*(.+)')          { $meta.ScanName     = $Matches[1].Trim() }
        if ($o -match 'Scan policy used\s*:\s*(.+)')   { $meta.Policy       = $Matches[1].Trim() }
        if ($o -match 'Credentialed checks\s*:\s*(.+)'){ $meta.Credentialed = $Matches[1].Trim() }
        if ($o -match 'Scanner IP\s*:\s*(.+)')         { $meta.ScannerIp    = $Matches[1].Trim() }
        if ($o -match 'Plugin feed version\s*:\s*(.+)'){ $meta.PluginFeed   = $Matches[1].Trim() }
        $meta.PortScanner = if ($o -match 'No port scanner was enabled') { 'none-enabled' } else { 'unknown' }
    }
    $hosts = $rows | ForEach-Object { $_.Host.Trim() } | Where-Object { $_ } | Sort-Object -Unique
    return [pscustomobject]@{ Hosts=$hosts; Meta=$meta; SourceFile=(Split-Path $Path -Leaf) }
}

# ---------------------------------------------------------------------------------------------
# AXIS 3 (optional): Nessus configured TARGET ROSTER - what we authorized scanning of.
# One target per line, or a CSV with a Target/Host/IP column.
# ---------------------------------------------------------------------------------------------
function Import-NessusRoster {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "NessusRosterPath not found: $Path" }
    $targets = @()
    try {
        $csv = Import-Csv -Path $Path
        $col = @('Target','Host','IP','IpAddress','Address') | Where-Object { $csv | Get-Member -Name $_ } | Select-Object -First 1
        if ($col) { $targets = $csv | ForEach-Object { $_.$col } }
    } catch {}
    if (-not $targets) { $targets = Get-Content -Path $Path | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' } }
    return ($targets | Where-Object { $_ } | Sort-Object -Unique)
}

# ---------------------------------------------------------------------------------------------
# APPROVAL AXIS (optional, currently expected absent): approved CM-8 inventory.
# ---------------------------------------------------------------------------------------------
function Import-Cm8Inventory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Cm8InventoryPath not found: $Path" }
    $rows = Import-Csv -Path $Path
    $cols = ($rows | Select-Object -First 1).PSObject.Properties.Name
    return [pscustomobject]@{ Rows=$rows; Columns=$cols; SourceFile=(Split-Path $Path -Leaf)
                              HasResourceId=($cols -contains 'AzureResourceId')
                              HasStatus=($cols -contains 'AssetStatus') }
}

# =============================================================================================
# MAIN
# =============================================================================================
$runStart = Get-Date
$script:FailReasons = @()

# Establish output dir + stamp FIRST so any failure still yields diagnostics.
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$stamp    = $runStart.ToString('yyyyMMdd-HHmmss')
$csvPath  = Join-Path $OutputDir "irv-$stamp.csv"
$jsonPath = Join-Path $OutputDir "irv-$stamp.json"
$diagPath = Join-Path $OutputDir "irv-$stamp.diagnostics.json"
$seedPath = Join-Path $OutputDir "cm8-seed-$stamp.csv"

$ctx=$null; $edges=@(); $exposure=@(); $boundary=@(); $records=@()
$unapproved=@(); $missing=@(); $unmatched=@(); $expectationFindings=@()
$nessusObserved=$null; $nessusRoster=@(); $cm8=$null
$ambiguousIps=@(); $script:AmbiguousIpMatches=@()
$inventoryAuthority='None'; $inventoryAuthorityStatus='CM8InventoryUnavailable'
$runStatus='Failed'; $fatal=$null

try {
    $ctx = Assert-Context

    # ---- Load axes ----
    if ($Cm8InventoryPath) {
        $cm8 = Import-Cm8Inventory -Path $Cm8InventoryPath
        $inventoryAuthority       = "CM8:$($cm8.SourceFile)"
        $inventoryAuthorityStatus = 'Cm8InventoryProvided'
        if (-not $cm8.HasResourceId) {
            Write-Warning "CM-8 inventory has no AzureResourceId column; falling back to PrivateIp+Hostname joins. Ambiguous matches will be flagged."
        }
    }
    if ($NessusObservedPath) { $nessusObserved = Import-NessusObserved -Path $NessusObservedPath }
    if ($NessusRosterPath)   { $nessusRoster   = Import-NessusRoster   -Path $NessusRosterPath }

    # ---- Discover & classify edges ----
    $edges = Get-PublicEdgeInventory
    foreach ($e in ($edges | Where-Object { $_.Class -eq 'Unsupported' })) {
        $script:FailReasons += "UNSUPPORTED_EDGE: PIP $($e.Name) ($($e.PipAddress)) attached to unsupported resource $($e.OwnerId)."
    }

    # ---- Manifest reconciliation (drift, not failure) ----
    $manifestNames  = $EdgeManifest.Name
    $discoveredReal = $edges | Where-Object { $_.Class -in @('AppGateway','LoadBalancer','Firewall','Bastion','DirectNic') }
    $discoveredNames = @($discoveredReal | ForEach-Object { $_.Name })
    $unapproved = @($discoveredReal | Where-Object { $_.Name -notin $manifestNames })
    $missing    = @($EdgeManifest   | Where-Object { $_.Name -notin $discoveredNames })

    # ---- Traverse ----
    # Track per-edge traversal success: an expectation can only be evaluated against an edge we
    # actually READ. A failed traversal yields zero exposure rows, which must NOT be mistaken for
    # "no forwarding path exists" (observed: a 403 on the firewall policy produced Held=true).
    $edgeTraversed = @{}
    foreach ($e in $edges) {
        try {
            switch ($e.Class) {
                'AppGateway'   { $exposure += Get-AppGatewayExposure   -Name $e.Name -ResourceGroup (($e.OwnerId -split '/')[4]) }
                'LoadBalancer' { $exposure += Get-LoadBalancerExposure -Name $e.Name -ResourceGroup (($e.OwnerId -split '/')[4]) }
                'Firewall'     { $exposure += Get-FirewallExposure     -Name $e.Name -ResourceGroup (($e.OwnerId -split '/')[4]) }
                'DirectNic'    { $exposure += Get-DirectNicExposure    -Edge $e }
                'Bastion'      { }   # expectation validated below
                'Unattached'   { }   # dark today; one association from live
            }
            $edgeTraversed[$e.Name] = $true
        } catch {
            $edgeTraversed[$e.Name] = $false
            $script:FailReasons += "EDGE_TRAVERSAL_ERROR [$($e.Class) $($e.Name)]: $($_.Exception.Message)"
        }
    }

    # ---- Validate edge EXPECTATIONS against what was actually observed this run ----
    # An expectation contradicted by the run becomes a finding, never a stale claim.
    # An expectation whose edge could not be read is UNVERIFIED - never "held".
    foreach ($x in $EdgeExpectations) {
        $traversed = $edgeTraversed.ContainsKey($x.Edge) -and $edgeTraversed[$x.Edge]
        if (-not $traversed) {
            $expectationFindings += [pscustomobject]@{
                Edge=$x.Edge; Expect=$x.Expect; Held=$null; Verified=$false
                Finding="EXPECTATION_UNVERIFIED: '$($x.Expect)' for $($x.Edge) could NOT be validated this run because the edge was not successfully traversed (permission error, missing resource, or traversal failure). Absence of discovered forwarding paths here is absence of evidence, NOT evidence of absence. The recorded basis is neither confirmed nor refuted."
                RecordedBasis=$x.Basis; ObservedPaths=@() }
            continue
        }
        $rows = @($exposure | Where-Object { $_.EdgeDevice -eq $x.Edge })
        $holds = ($rows.Count -eq 0)
        if (-not $holds) {
            $expectationFindings += [pscustomobject]@{
                Edge=$x.Edge; Expect=$x.Expect; Held=$false; Verified=$true
                Finding="EXPECTATION_CONTRADICTED: '$($x.Expect)' for $($x.Edge) is contradicted by $($rows.Count) forwarding path(s) discovered this run. The recorded basis is now STALE and must be re-determined."
                RecordedBasis=$x.Basis; ObservedPaths=@($rows | ForEach-Object { $_.Path } | Select-Object -Unique) }
        } else {
            $expectationFindings += [pscustomobject]@{ Edge=$x.Edge; Expect=$x.Expect; Held=$true; Verified=$true
                                                       Finding=$null; RecordedBasis=$x.Basis; ObservedPaths=@() }
        }
    }

    # ---- Axis 1: Azure discovery ----
    $boundary = Get-BoundaryComputeHosts

    if ($EmitCm8Seed) {
        $boundary | Select-Object @{n='AssetId';e={''}},
            @{n='AzureResourceId';e={$_.AzureResourceId}},
            @{n='ResourceGroup';e={$_.ResourceGroup}},
            @{n='CloudServiceName';e={$_.CloudServiceName}},
            @{n='RoleInstanceName';e={$_.RoleInstanceName}},
            Hostname, PrivateIp,
            @{n='VNetId';e={$_.VNetId}}, @{n='SubnetId';e={$_.SubnetId}},
            @{n='IpConfigId';e={$_.IpConfigId}},
            @{n='Kind';e={$_.Kind}},
            @{n='AssetStatus';e={'DRAFT-UNAPPROVED'}}, @{n='BoundaryStatus';e={'DRAFT-UNAPPROVED'}},
            @{n='Source';e={'azure-discovery'}}, @{n='SeededUtc';e={$runStart.ToUniversalTime().ToString('o')}} |
            Export-Csv -Path $seedPath -NoTypeInformation -Encoding UTF8
    }

    # ---- Exposure indices ----
    # CRITICAL: private IPs are NOT unique in this boundary. Each cloud service has its own VNet
    # with an auto-generated DefaultVNetSubnet allocating from the same range, so the same private IP
    # can be REUSED across cloud services. Join tiers, strongest first:
    #   1. exact ip-config resource ID          (always unambiguous)
    #   2. VNetId + SubnetId + PrivateIp        (disambiguates repeated IPs across VNets)
    #   3. PrivateIp with exactly one candidate (limited fallback)
    #   4. PrivateIp with multiple candidates   -> AMBIGUOUS_PRIVATE_IP = hard failure
    $expByCfg=@{}; $expByScoped=@{}; $expByIp=@{}
    foreach ($x in $exposure) {
        if ($x.IpConfigId) { [void]($expByCfg[$x.IpConfigId.ToLower()] ??= @()); $expByCfg[$x.IpConfigId.ToLower()] += $x; continue }
        if (-not $x.PrivateIp -or $x.PrivateIp -like '*NSG-governed*') { continue }
        if ($x.SubnetId) {
            $k = "$($x.SubnetId)|$($x.PrivateIp)".ToLower()
            [void]($expByScoped[$k] ??= @()); $expByScoped[$k] += $x
        } else {
            [void]($expByIp[$x.PrivateIp] ??= @()); $expByIp[$x.PrivateIp] += $x
        }
    }

    # Boundary IP uniqueness: an IP owned by >1 distinct ip-config cannot be matched by IP alone.
    $ipOwners = @{}
    foreach ($h in $boundary) {
        if ($h.PrivateIp) { [void]($ipOwners[$h.PrivateIp] ??= @()); $ipOwners[$h.PrivateIp] += $h.IpConfigId }
    }
    $ambiguousIps = @($ipOwners.Keys | Where-Object { @($ipOwners[$_] | Select-Object -Unique).Count -gt 1 })
    $script:AmbiguousIpMatches = @()

    # ---- Prior EVIDENCE artifact (never a diagnostics file) for flicker annotation ----
    $priorMap=@{}; $priorName=$null; $priorRunUtc=$null
    $priorFile = Get-ChildItem -Path $OutputDir -Filter 'irv-*.json' -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -notlike '*.diagnostics.json' } | Sort-Object Name | Select-Object -Last 1
    if ($priorFile) {
        try {
            $prior = Get-Content $priorFile.FullName -Raw | ConvertFrom-Json
            $priorName = $priorFile.Name; $priorRunUtc = $prior.runMetadata.runUtc
            foreach ($pr in $prior.records) { $priorMap["$($pr.IpConfigId)|$($pr.PrivateIp)".ToLower()] = $pr }
        } catch { Write-Warning "Could not parse prior artifact $($priorFile.Name): $($_.Exception.Message)" }
    }

    # ---- Build records across the axes ----
    $records = foreach ($h in $boundary) {
        $hits = @()
        # Tier 1: exact ip-config resource ID.
        if ($h.IpConfigId -and $expByCfg.ContainsKey($h.IpConfigId.ToLower())) { $hits += $expByCfg[$h.IpConfigId.ToLower()] }
        # Tier 2: VNet+Subnet-scoped IP - unambiguous even when the IP repeats across VNets.
        if ($h.SubnetId -and $h.PrivateIp) {
            $sk = "$($h.SubnetId)|$($h.PrivateIp)".ToLower()
            if ($expByScoped.ContainsKey($sk)) { $hits += $expByScoped[$sk] }
        }
        # Tier 3/4: bare-IP rows (no ID, no subnet scope). Safe only if the IP has one owner.
        if ($h.PrivateIp -and $expByIp.ContainsKey($h.PrivateIp)) {
            if ($h.PrivateIp -in $ambiguousIps) {
                $script:FailReasons += "AMBIGUOUS_PRIVATE_IP: an exposure row identified only by private IP $($h.PrivateIp) cannot be attributed - that IP is owned by $(@($ipOwners[$h.PrivateIp] | Select-Object -Unique).Count) distinct ip-configs in this boundary (overlapping VNet address space). Attribution is not defensible; coverage cannot be demonstrated for this path."
                $script:AmbiguousIpMatches += [pscustomobject]@{
                    Hostname=$h.Hostname; PrivateIp=$h.PrivateIp; IpConfigId=$h.IpConfigId
                    SharedWith=@($ipOwners[$h.PrivateIp] | Select-Object -Unique) }
            } else {
                $hits += $expByIp[$h.PrivateIp]
            }
        }
        $hits = @($hits | Sort-Object Path, EdgeDevice, Port, Protocol, PublicIp, Context -Unique)
        $irv  = [bool]($hits.Count -gt 0)

        $pk = "$($h.IpConfigId)|$($h.PrivateIp)".ToLower()
        $priorIrv = if ($priorMap.ContainsKey($pk)) { [bool]$priorMap[$pk].IRV } else { $null }

        $observed = if ($nessusObserved) { [bool]($h.PrivateIp -in $nessusObserved.Hosts) } else { $null }
        $inRoster = if ($nessusRoster.Count) { [bool]($h.PrivateIp -in $nessusRoster) } else { $null }

        [pscustomobject]@{
            Hostname                 = $h.Hostname
            PrivateIp                = $h.PrivateIp
            IpConfigId               = $h.IpConfigId
            AzureResourceId          = $h.AzureResourceId
            CloudServiceName         = $h.CloudServiceName
            RoleInstanceName         = $h.RoleInstanceName
            VNetId                   = $h.VNetId
            SubnetId                 = $h.SubnetId
            Kind                     = $h.Kind
            ResourceGroup            = $h.ResourceGroup
            IRV                      = $irv
            PriorIRV                 = $priorIrv
            PriorRunUtc              = ($null -ne $priorIrv ? $priorRunUtc : $null)
            IRVChanged               = ($null -ne $priorIrv -and $priorIrv -ne $irv)
            DiscoveredInAzure        = $true
            ObservedInNessusBaseline = $observed
            IncludedInNessusRoster   = $inRoster
            InventoryAuthority       = $inventoryAuthority
            InventoryAuthorityStatus = $inventoryAuthorityStatus
            # NOTE: $hits.Prop (member enumeration) throws on an EMPTY array under StrictMode,
            # which is the common case (any host with no exposure). ForEach-Object is empty-safe.
            Ports                    = (@($hits | ForEach-Object { $_.Port })       | Where-Object { $_ } | Select-Object -Unique) -join ','
            Protocols                = (@($hits | ForEach-Object { $_.Protocol })   | Where-Object { $_ } | Select-Object -Unique) -join ','
            EdgeDevices              = (@($hits | ForEach-Object { $_.EdgeDevice }) | Where-Object { $_ } | Select-Object -Unique) -join ','
            Paths                    = (@($hits | ForEach-Object { $_.Path })       | Where-Object { $_ } | Select-Object -Unique) -join '; '
            Mitigations              = (@($hits | ForEach-Object { $_.Mitigation }) | Where-Object { $_ } | Select-Object -Unique) -join ','
            Context                  = (@($hits | ForEach-Object { $_.Context })    | Where-Object { $_ } | Select-Object -Unique) -join ' || '
        }
    }
    $records = @($records | Sort-Object Hostname, PrivateIp)

    # ---- Cross-axis reconciliation ----
    # NOTE: @( ) is load-bearing. A pipeline that matches nothing assigns $null, not @(), and
    # $null.Count throws under Set-StrictMode. Force array semantics on every result.
    $azureIps = @($records | ForEach-Object { $_.PrivateIp } | Where-Object { $_ } | Sort-Object -Unique)
    $observedNotInAzure = if ($nessusObserved) {
        @($nessusObserved.Hosts | Where-Object { $_ -notin $azureIps } | ForEach-Object {
            [pscustomobject]@{ Host=$_; Meaning='Responded to discovery scan but not found by the Azure compute enumeration: possibly deleted, renamed, out-of-Azure, stale, or an appliance/resource type not covered by this query. Requires review.' } })
    } else { @() }
    $azureNotObserved = if ($nessusObserved) {
        @($records | Where-Object { $false -eq $_.ObservedInNessusBaseline } | ForEach-Object {
            [pscustomobject]@{ Hostname=$_.Hostname; PrivateIp=$_.PrivateIp; IRV=$_.IRV
                               Meaning='Exists in Azure but did not answer the discovery scan: possible scan-coverage gap, powered-off host, blocked probe, or newly created. Requires review.' } })
    } else { @() }
    $azureNotInRoster = if ($nessusRoster.Count) {
        @($records | Where-Object { $false -eq $_.IncludedInNessusRoster } | ForEach-Object {
            [pscustomobject]@{ Hostname=$_.Hostname; PrivateIp=$_.PrivateIp; IRV=$_.IRV
                               Meaning='Exists in Azure but is not in the configured Nessus target roster: scanning-coverage gap.' } })
    } else { @() }

    # Exposure resolved to an IP no discovered host owns.
    $unmatched = @(foreach ($x in $exposure) {
        if (-not $x.PrivateIp -or $x.PrivateIp -like '*NSG-governed*') { continue }
        if (-not ($boundary | Where-Object { $_.PrivateIp -eq $x.PrivateIp })) { $x }
    })

    # ---- KNOWN-TRUTH REGRESSION ASSERTION ----
    # Verify the map still finds what manual traversal proved is there, and still excludes what it
    # proved is not. A miss here means either the environment genuinely changed (update the
    # baseline deliberately) or the tool regressed (fix it) - both must stop the run.
    if (-not $SkipBaselineAssertion) {
        foreach ($k in $KnownReachable) {
            $hit = $records | Where-Object {
                $_.Hostname -eq $k.Hostname -and $_.PrivateIp -eq $k.PrivateIp -and $_.IRV -eq $true -and $_.EdgeDevices -match [regex]::Escape($k.Edge) }
            if (-not $hit) {
                $script:FailReasons += "BASELINE_MISS: known-reachable $($k.Hostname) ($($k.PrivateIp)) via $($k.Edge) was NOT found IRV=true this run. Either the environment changed (update `$KnownReachable deliberately) or the map regressed. Refusing to emit."
            }
        }
        foreach ($n in $KnownNotReachable) {
            $bad = $records | Where-Object { $_.Hostname -eq $n -and $_.IRV -eq $true }
            if ($bad) {
                $script:FailReasons += "BASELINE_FALSE_POSITIVE: $n resolved IRV=true, but manual traversal established no LB rule forwards to any worker role. This is the signature of an attribution bug (private-IP collision). Refusing to emit."
            }
        }
    }

    # ---- Sanity gates: distinguish genuine drift from BROKEN DISCOVERY ----
    # Drift = a few things moved. If the ENTIRE approved manifest is undiscovered, or discovery
    # returned no edges at all, that is not drift - it is a failed enumeration (expired
    # credentials, lost RBAC, throttling, wrong context). ARG returns EMPTY rather than erroring
    # when access is missing, so an empty result must never be mistaken for an empty environment.
    if ($EdgeManifest.Count -gt 0 -and $missing.Count -eq $EdgeManifest.Count) {
        $script:FailReasons += "DISCOVERY_IMPLAUSIBLE: none of the $($EdgeManifest.Count) approved manifest edges were discovered. This is not drift - it indicates discovery itself failed (expired PIM/credentials, lost RBAC, throttling, or wrong subscription context). ARG returns empty rather than erroring when access is absent. Refusing to emit a dataset that would falsely report no exposure."
    }
    if (@($edges).Count -eq 0) {
        $script:FailReasons += "DISCOVERY_EMPTY: subscription-wide public-IP discovery returned zero resources. Coverage cannot be demonstrated."
    }
    if (@($boundary).Count -eq 0) {
        $script:FailReasons += "BOUNDARY_EMPTY: compute enumeration returned zero hosts. Coverage cannot be demonstrated."
    }
    # Manifest expects IRV-capable edges but nothing resolved as reachable - implausible for this
    # boundary and far more likely a resolution failure than a genuine zero.
    $irvCapable = @($EdgeManifest | Where-Object { $_.Class -in @('AppGateway','LoadBalancer') }).Count
    $irvTrue    = @($records | Where-Object { $_.IRV }).Count
    if ($irvCapable -gt 0 -and $irvTrue -eq 0 -and $script:FailReasons.Count -eq 0) {
        $script:FailReasons += "IRV_ZERO_IMPLAUSIBLE: the approved manifest contains $irvCapable IRV-capable edge(s) (App Gateway / Load Balancer) but zero hosts resolved as internet-reachable. Emitting 'nothing is reachable' would be a dangerous false negative; treating as a resolution failure pending investigation."
    }

    # ---- Run status.
    # InventoryDrift REQUIRES an authority to drift from. With no approved CM-8 inventory there is
    # nothing authoritative to compare against, so the correct terminal status is
    # InventoryBaselineMissing - the Azure/Nessus differences are recorded as observation
    # mismatches, not as inventory drift.
    # Precedence: Failed > ManifestDrift > InventoryDrift > NessusCoverageGap > InventoryBaselineMissing > Clean
    $haveAuthority = ($inventoryAuthorityStatus -ne 'CM8InventoryUnavailable')
    $runStatus =
        if ($script:FailReasons.Count -gt 0 -or @($expectationFindings | Where-Object { $_.Held -ne $true }).Count -gt 0) { 'Failed' }
        elseif ($unapproved.Count -or $missing.Count -or $unmatched.Count)   { 'ManifestDrift' }
        elseif ($haveAuthority -and $observedNotInAzure.Count -gt 0)         { 'InventoryDrift' }
        elseif ($azureNotObserved.Count -gt 0 -or $azureNotInRoster.Count -gt 0) { 'NessusCoverageGap' }
        elseif (-not $haveAuthority)                                         { 'InventoryBaselineMissing' }
        else { 'Clean' }
}
catch {
    $fatal = $_
    $script:FailReasons += "FATAL: $($_.Exception.Message) @ $($_.InvocationInfo.ScriptLineNumber)"
    $runStatus = 'Failed'
}
finally {
    $diag = [ordered]@{
        runUtc=$runStart.ToUniversalTime().ToString('o'); runStatus=$runStatus
        failReasons=$script:FailReasons; fatal=($fatal ? ($fatal | Out-String) : $null)
        contextOk=($null -ne $ctx)
        inventoryAuthority=$inventoryAuthority; inventoryAuthorityStatus=$inventoryAuthorityStatus
        edgesDiscovered=$edges; manifestUnapproved=$unapproved; manifestMissing=$missing
        edgeExpectations=$expectationFindings
        exposedNotInInventory=$unmatched
        boundaryCount=@($boundary).Count; recordCount=@($records).Count
    }
    $diag | ConvertTo-Json -Depth 8 | Set-Content -Path $diagPath -Encoding UTF8
}

if ($runStatus -eq 'Failed') {
    Write-Host "`n=== IRV RUN FAILED - coverage cannot be demonstrated ===" -ForegroundColor Red
    $script:FailReasons | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    # Guarded: $expectationFindings is empty when the run dies before expectations are evaluated,
    # and property access on an empty result throws under StrictMode - which would mask the real error.
    if ($expectationFindings -and $expectationFindings.Count -gt 0) {
        foreach ($ef in $expectationFindings) {
            if ($ef.Held -ne $true -and $ef.Finding) { Write-Host "  $($ef.Finding)" -ForegroundColor Red }
        }
    }
    Write-Host "Diagnostics: $diagPath" -ForegroundColor Red
    throw "IRV run failed; no evidence dataset emitted. Resolve the reasons above and re-run."
}

$records | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$artifact = [ordered]@{
    schema='cr26-irv/v0'; supports='VER-EVA-EIR'; runStatus=$runStatus
    note='Resource->exposure map; ONE INPUT to a per-vulnerability IRV determination, not the determination itself. Final IRV requires joining: Nessus finding -> scanned asset -> CM-8-approved component -> Azure exposure path.'
    inventoryAuthority=[ordered]@{
        authority=$inventoryAuthority; status=$inventoryAuthorityStatus
        caveat='No approved CM-8 System Component Inventory was supplied. The axes below record what EXISTS (Azure) and what RESPONDED (Nessus discovery). Neither is an approval authority; a discovery scan cannot identify an unauthorized asset. Completeness against the authorization boundary is NOT demonstrated by this run.'
        cm8Control='CM-8 System Component Inventory (NIST SP 800-53 Rev5; FedRAMP Rev5 Moderate baseline). Not a CR26 rule.'
    }
    axes=[ordered]@{
        azureDiscovery=@{ meaning='compute that currently exists'; count=@($boundary).Count }
        nessusObserved=($nessusObserved ? [ordered]@{
            meaning='hosts that ANSWERED a discovery scan - observation, not inventory, not approval'
            sourceFile=$nessusObserved.SourceFile; hostCount=@($nessusObserved.Hosts).Count
            scanName=$nessusObserved.Meta.ScanName; scanPolicy=$nessusObserved.Meta.Policy
            credentialedChecks=$nessusObserved.Meta.Credentialed; portScanner=$nessusObserved.Meta.PortScanner
            scannerIp=$nessusObserved.Meta.ScannerIp; pluginFeed=$nessusObserved.Meta.PluginFeed
            limitation='Uncredentialed discovery scan with no port scanner enabled. Nessus itself warns results may be incomplete. An offline VM, blocked host, newly created VM, non-IP resource, or non-responsive target will not appear.'
        } : $null)
        nessusRoster=($nessusRoster.Count ? @{ meaning='configured scan targets - what we authorized scanning of'; count=$nessusRoster.Count } : $null)
        cm8Inventory=($cm8 ? @{ sourceFile=$cm8.SourceFile; columns=$cm8.Columns; hasResourceId=$cm8.HasResourceId } : $null)
    }
    runMetadata=[ordered]@{
        runUtc=$runStart.ToUniversalTime().ToString('o'); account=$ctx.Account.Id
        subscriptionId=$ctx.Subscription.Id; subscriptionName=$ctx.Subscription.Name; tenantId=$ctx.Tenant.Id
        host=$env:COMPUTERNAME; psEdition=$PSVersionTable.PSEdition; psVersion=$PSVersionTable.PSVersion.ToString()
        azNetworkVer=(Get-Module Az.Network).Version.ToString()
        priorArtifact=$priorName
        reachabilityModel='conservative: edge-forwarding-path => IRV=true by default; WAF/NSG/authn recorded as mitigation context, NOT auto-negating (no effective-rule/payload analysis performed); recomputed each run.'
    }
    manifest=$EdgeManifest; edgeExpectations=$expectationFindings
    edgesDiscovered=$edges; manifestUnapproved=$unapproved; manifestMissing=$missing
    reconciliation=[ordered]@{
        observedNotInAzure=$observedNotInAzure; azureNotObserved=$azureNotObserved; azureNotInRoster=$azureNotInRoster
        ambiguousPrivateIps=@($ambiguousIps)
        ambiguousIpMatches=@($script:AmbiguousIpMatches)
        ambiguousIpNote='Private IP addresses are reused across this boundary because each cloud service has its own VNet with an auto-generated DefaultVNetSubnet allocating from the same range. IP-based attribution is therefore NOT unique. Exposure is attributed by exact ip-config resource ID; IP matching is used only for ID-less exposure rows and only where the IP resolves to a single host.'
    }
    exposedNotInInventory=$unmatched
    records=$records
}
$artifact | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8

# ---- Console summary ----
$trueCount = @($records | Where-Object { $_.IRV }).Count
$changed   = @($records | Where-Object { $_.IRVChanged }).Count
$color = switch ($runStatus) { 'Clean' {'Green'} 'InventoryBaselineMissing' {'Cyan'} 'Failed' {'Red'} default {'Yellow'} }
Write-Host "`n=== IRV run: $runStatus ($stamp) ===" -ForegroundColor $color
Write-Host ("Inventory authority : {0} [{1}]" -f $inventoryAuthority, $inventoryAuthorityStatus) -ForegroundColor Cyan
Write-Host ("Boundary hosts      : {0}   IRV=true: {1}   IRV changed: {2}" -f $records.Count, $trueCount, $changed)
Write-Host ("CSV / JSON          : {0}" -f $csvPath)
if ($EmitCm8Seed) { Write-Host ("CM-8 seed draft     : {0}  (DRAFT-UNAPPROVED - requires owner review/approval)" -f $seedPath) -ForegroundColor Cyan }
if ($ambiguousIps.Count) { Write-Host "`nAmbiguous private IPs (owned by >1 host - IP-based attribution unsafe):" -ForegroundColor Yellow; $ambiguousIps | ForEach-Object { Write-Host "  $_" } }
if (@($script:AmbiguousIpMatches).Count) { Write-Host "ID-less exposure rows NOT attributed due to IP ambiguity:" -ForegroundColor Yellow; $script:AmbiguousIpMatches | Format-Table Hostname,PrivateIp -AutoSize }
if ($unapproved)         { Write-Host "`nManifest drift - discovered edges NOT approved:" -ForegroundColor Yellow; $unapproved | Format-Table Class,Name,PipAddress -AutoSize }
if ($missing)            { Write-Host "Manifest drift - approved edges NOT discovered:" -ForegroundColor Yellow; $missing | Format-Table Class,Name -AutoSize }
if ($unmatched)          { Write-Host "Exposure resolved to hosts NOT in Azure discovery:" -ForegroundColor Yellow; $unmatched | Format-Table Hostname,PrivateIp,Path,EdgeDevice -AutoSize }
if ($observedNotInAzure) { Write-Host "Nessus-observed but NOT in Azure discovery:" -ForegroundColor Yellow; $observedNotInAzure | Format-Table Host -AutoSize }
if ($azureNotObserved)   { Write-Host "In Azure but did NOT answer discovery scan:" -ForegroundColor Yellow; $azureNotObserved | Format-Table Hostname,PrivateIp,IRV -AutoSize }
if ($azureNotInRoster)   { Write-Host "In Azure but NOT in Nessus roster:" -ForegroundColor Yellow; $azureNotInRoster | Format-Table Hostname,PrivateIp,IRV -AutoSize }
$records | Where-Object { $_.IRV } | Format-Table Hostname,PrivateIp,Ports,EdgeDevices,Paths -AutoSize
Write-Host "`nNOTE: status 'Clean' is unreachable until an approved CM-8 inventory is supplied via -Cm8InventoryPath." -ForegroundColor Cyan
