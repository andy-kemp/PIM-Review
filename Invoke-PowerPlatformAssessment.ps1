<#
.SYNOPSIS
Power Platform privileged access assessment: turns the evidence from Get-PowerPlatformReview.ps1 into the
registers, control checks, HTML report and Excel workbook. Runs offline; re-run it whenever the catalogue
or rules change.

.DESCRIPTION
Reads <RunFolder>\Raw and writes to <RunFolder>:
- PP_People.csv: one row per person (account type, linked CLAD/everyday account, highest trust level, tenant
  roles and how held, production System Administrator, flows/apps/connections owned, licences, sign-in methods,
  Conditional Access coverage, persona, recommended action)
- PP_AccessPaths.csv: every route to Power Platform admin rights, with trust level and state
- PP_TrustLevels.csv: the trust-level model for Power Platform (what each role can do, what it needs, what PIM changes)
- PP_PimImpact.csv: per admin, what changes and what breaks when their rights become just-in-time
- PP_CladProvisioning.csv: everyone doing admin work from an everyday account, with existing or proposed CLAD
- PP_FlowsAtRisk.csv / PP_ConnectionsAtRisk.csv
- PP_PimCoverage.csv / PP_PolicyGaps.csv / PP_RoleSettings.csv
- PP_MigrationWorksheet.csv: one row per privileged route, proposed action, blank Wave / Owner / Decision
- PP_Controls.csv / PP_NcscCafBenchmark.csv / PP_Ssa.csv
- PP_Environments.csv / PP_ConditionalAccess.csv / PP_Dlp.csv
- PP_Metrics.csv/.json, PP_Summary.json (used by the partnership roll-up)
- PowerPlatform_Audit_<tenant>.html, and PowerPlatform_Audit_<tenant>.xlsx when ImportExcel works

.PARAMETER RunFolder
A PowerPlatform-<timestamp> folder written by Get-PowerPlatformReview.ps1.

.PARAMETER IdentityMapCsv
Optional CSV with columns PrivilegedUpn, EverydayUpn, Person to link CLAD and everyday accounts where names do
not match. Defaults to the catalogue's Identity.IdentityMapCsv.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RunFolder,
    [string]$IdentityMapCsv,
    [switch]$NoWorkbook
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules\PimReview.Common.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot 'New-PimPhase2Report.ps1')
. (Join-Path $PSScriptRoot 'Get-PowerPlatformAuditControls.ps1')

#region load
$raw = Join-Path $RunFolder 'Raw'
if (-not (Test-Path $raw)) { $raw = $RunFolder }
function Import-PpCsv {
    param([string]$Name)
    $p = Join-Path $raw $Name
    if (-not (Test-Path $p) -or (Get-Item $p).Length -lt 3) { return @() }
    return @(Import-Csv -Path $p)
}
function Test-True { param($v) return ([string]$v -eq 'True') }
function Get-Json { param([string]$Name) $p = Join-Path $raw $Name; if (Test-Path $p) { try { return (Get-Content $p -Raw | ConvertFrom-Json) } catch { } }; return $null }

$meta = Get-Json 'pp-run.json'
if (-not $meta) { throw "No pp-run.json in $raw. Is this a Power Platform audit run folder?" }
$tenantRoles = Import-PpCsv 'pp-tenant-roles.csv'
$roleSettings = Import-PpCsv 'pp-role-settings.csv'
$activations = Import-PpCsv 'pp-activations.csv'
$caRows = Import-PpCsv 'pp-conditional-access.csv'
$envs = Import-PpCsv 'pp-environments.csv'
$envRolesRaw = Import-PpCsv 'pp-environment-roles.csv'
$flows = Import-PpCsv 'pp-flows.csv'
$apps = Import-PpCsv 'pp-apps.csv'
$connections = Import-PpCsv 'pp-connections.csv'
$inventory = Import-PpCsv 'pp-inventory.csv'
$ppRbac = Import-PpCsv 'pp-rbac-assignments.csv'
$mgmtApps = Import-PpCsv 'pp-management-apps.csv'
$dlp = Import-PpCsv 'pp-dlp-policies.csv'
$users = Import-PpCsv 'pp-users.csv'
$userGroups = Import-PpCsv 'pp-user-groups.csv'
$cladAccounts = Import-PpCsv 'pp-clad-accounts.csv'
$elevations = Import-PpCsv 'pp-elevations.csv'
$tenantSettings = Get-Json 'pp-tenant-settings.json'

$catPath = Join-Path $PSScriptRoot 'Config\pim-phase2.catalogue.local.json'
if (-not (Test-Path $catPath)) { $catPath = Join-Path $PSScriptRoot 'Config\pim-phase2.catalogue.json' }
$catalogue = $null
if (Test-Path $catPath) { try { $catalogue = Get-Content $catPath -Raw | ConvertFrom-Json } catch { } }
$brand = if ($catalogue) { $catalogue.Branding } else { $null }
$idCfg = if ($catalogue) { $catalogue.Identity } else { $null }
$baselines = if ($catalogue) { $catalogue.TrustLevelBaselines } else { $null }
#endregion

#region identity classification and linking
$cladPrefixes = @($meta.cladPrefixes | Where-Object { $_ })
if ($cladPrefixes.Count -eq 0) { $cladPrefixes = @('clad_') }
$pat = { param($name) if ($idCfg -and $idCfg.PSObject.Properties[$name]) { @($idCfg.$name | Where-Object { $_ }) } else { @() } }
$cladNamePats = & $pat 'CladDisplayNamePatterns'; if ($cladNamePats.Count -eq 0) { $cladNamePats = @('^\(Cloud Admin\)\s*') }
$otherAdminPats = & $pat 'OtherAdminPatterns'
$genericPats = & $pat 'GenericPatterns'
$bgPats = & $pat 'BreakGlassPatterns'
$bgUpns = @(& $pat 'BreakGlassUpns' | ForEach-Object { ([string]$_).ToLowerInvariant() })

function Get-AccountType {
    param([string]$Upn, [string]$Name, [string]$UserType)
    if ([string]::IsNullOrWhiteSpace($Upn)) { return 'Unknown' }
    $u = $Upn.ToLowerInvariant(); $local = ($u -split '@')[0]
    if ($bgUpns -contains $u) { return 'Break-glass' }
    foreach ($p in $bgPats) { if ($local -match $p -or $Name -match $p) { return 'Break-glass' } }
    foreach ($p in $cladPrefixes) { if ($u.StartsWith(([string]$p).ToLowerInvariant())) { return 'CLAD' } }
    foreach ($p in $cladNamePats) { if ($Name -match $p) { return 'CLAD' } }
    if ($UserType -eq 'Guest' -or $u -match '#ext#') { return 'Guest' }
    foreach ($p in $genericPats) { if ($local -match $p -or $Name -match $p) { return 'Generic/Service' } }
    foreach ($p in $otherAdminPats) { if ($local -match $p -or $Name -match $p) { return 'Other admin account' } }
    return 'Everyday'
}

function Get-NameKey {
    # Same rule as the Phase 2 assessment: first and last name of the cleaned display name.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    foreach ($p in $cladNamePats) { $Name = $Name -replace $p, '' }
    $n = $Name -replace '\[[^\]]*\]', '' -replace '\([^)]*\)', ''
    if ($n -match '^\s*([^,]+),\s*(.+)$') { $n = "$($Matches[2]) $($Matches[1])" }
    $n = $n.ToLowerInvariant() -replace ("[" + [char]0x2019 + "']"), '' -replace '[^a-z ]', ' '
    $t = @($n.Split(' ') | Where-Object { $_.Length -gt 0 })
    if ($t.Count -lt 2) { return $null }
    return "$($t[0]) $($t[$t.Count - 1])"
}

if (-not $IdentityMapCsv -and $idCfg -and $idCfg.IdentityMapCsv) { $IdentityMapCsv = Join-Path $PSScriptRoot $idCfg.IdentityMapCsv }
$mapP2E = @{}; $mapE2P = @{}
if ($IdentityMapCsv -and (Test-Path $IdentityMapCsv)) {
    foreach ($m in Import-Csv $IdentityMapCsv) { $p = ([string]$m.PrivilegedUpn).ToLowerInvariant(); $e = ([string]$m.EverydayUpn).ToLowerInvariant(); if ($p -and $e) { $mapP2E[$p] = $e; $mapE2P[$e] = $p } }
}

$cladByKey = @{}; $cladBySurInit = @{}; $cladUpns = @{}
foreach ($c in $cladAccounts) {
    $upn = ([string]$c.UserPrincipalName).ToLowerInvariant(); $cladUpns[$upn] = $c
    $k = Get-NameKey $c.DisplayName; if ($k) { $cladByKey[$k] = $upn }
    $local = ($upn -split '@')[0]
    foreach ($p in $cladPrefixes) { $pp = ([string]$p).ToLowerInvariant(); if ($local.StartsWith($pp)) { $local = $local.Substring($pp.Length) } }
    if ($c.Surname -and $c.GivenName) { $cladBySurInit["$(([string]$c.Surname).ToLowerInvariant() -replace '[^a-z]','')|$(([string]$c.GivenName).Substring(0,1).ToLowerInvariant())"] = $upn }
    elseif ($local -match '^([a-z]+)([a-z])$') { $cladBySurInit["$($Matches[1])|$($Matches[2])"] = $upn }
}
$cladDomain = @($cladAccounts | ForEach-Object { ([string]$_.UserPrincipalName -split '@')[-1].ToLowerInvariant() } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1 -ExpandProperty Name)
if ($idCfg -and $idCfg.CladUpnDomain) { $cladDomain = @([string]$idCfg.CladUpnDomain) }

$userById = @{}
foreach ($u in $users) { $userById[([string]$u.UserId).ToLowerInvariant()] = $u }
$everydayByKey = @{}
foreach ($u in $users) {
    if ((Get-AccountType $u.UserPrincipalName $u.DisplayName $u.UserType) -eq 'Everyday') { $k = Get-NameKey $u.DisplayName; if ($k) { $everydayByKey[$k] = ([string]$u.UserPrincipalName).ToLowerInvariant() } }
}
$proposedTaken = @{}
function Get-ProposedCladUpn {
    param($U)
    $sur = ([string]$U.Surname).ToLowerInvariant() -replace '[^a-z]', ''
    $given = ([string]$U.GivenName).ToLowerInvariant() -replace '[^a-z]', ''
    if (-not $sur -or -not $given) { $k = Get-NameKey $U.DisplayName; if ($k) { $parts = $k.Split(' '); $given = $parts[0]; $sur = $parts[-1] } }
    if (-not $sur -or -not $given) { return $null }
    $dom = if ($cladDomain) { $cladDomain[0] } else { ([string]$U.UserPrincipalName -split '@')[-1] }
    $pfx = ([string]$cladPrefixes[0]).ToLowerInvariant()
    for ($n = 1; $n -le $given.Length; $n++) {
        $cand = "$pfx$sur$($given.Substring(0, $n))@$dom"
        if (-not $cladUpns.ContainsKey($cand) -and -not $proposedTaken.ContainsKey($cand)) { $proposedTaken[$cand] = $true; return $cand }
    }
    return $null
}
#endregion

#region trust levels and access paths
$model = @(Get-PpTrustLevelModel -Catalogue $catalogue)
$tlOf = @{}; foreach ($m in $model) { $tlOf[$m.Key] = $m.TrustLevel }
$tlRank = @{ TL1 = 1; TL2 = 2; TL3 = 3; TL4 = 4; '' = 9 }
$adminRoleNames = @('Power Platform Administrator', 'Dynamics 365 Administrator')
$envAdminRoleNames = @('System Administrator', 'EnvironmentAdmin', 'Environment Admin')
$envById = @{}
foreach ($e in $envs) {
    $isProd = (Test-True $e.IsDefault) -or ([string]$e.Type -eq 'Production')
    $e | Add-Member -NotePropertyName IsProd -NotePropertyValue $isProd -Force
    $envById[[string]$e.EnvironmentId] = $e
}
function Get-EnvRoleTl {
    param($Row)
    $env = $envById[[string]$Row.EnvironmentId]
    $type = if ($env) { [string]$env.Type } else { [string]$Row.EnvironmentType }
    $prod = if ($env) { $env.IsProd } else { ($type -eq 'Production') -or (Test-True $Row.IsDefault) }
    switch -Regex ([string]$Row.RoleName) {
        '^System Administrator$' { if ($prod) { return $tlOf['System Administrator (production or default)'] } elseif ($type -eq 'Developer') { return $tlOf['System Administrator (developer environment)'] } else { return $tlOf['System Administrator (sandbox, test, trial)'] } }
        '^System Customizer$' { return $tlOf['System Customizer'] }
        '^Environment ?Admin$' { if ($prod) { return $tlOf['Environment Admin (no Dataverse)'] } else { return 'TL4' } }
        default { return $tlOf['Environment Maker'] }
    }
}

$paths = New-Object System.Collections.ArrayList
foreach ($r in $tenantRoles) {
    $state = if ($r.State -like 'Eligible*') { 'Eligible' } elseif ($r.State -like 'Active (activated*') { 'Activated now' } elseif (Test-True $r.Permanent) { 'Permanent' } else { 'Time-bound active' }
    $null = $paths.Add([pscustomobject]@{
        UserId = ([string]$r.UserId).ToLowerInvariant(); PrincipalType = $r.PrincipalType; UserPrincipalName = $r.UserPrincipalName; DisplayName = $r.DisplayName
        Plane = 'Entra role'; Role = $r.RoleName; Scope = 'Tenant'; ScopeId = $null; TrustLevel = $tlOf[[string]$r.RoleName]
        State = $state; Standing = ($state -eq 'Permanent'); Via = $(if ($r.AssignedVia -eq 'Group') { "Group: $($r.GroupName) ($($r.GroupMembership))" } else { 'Direct' }); IsProd = $null
    })
}
$envRoles = New-Object System.Collections.ArrayList
foreach ($r in $envRolesRaw) {
    $env = $envById[[string]$r.EnvironmentId]
    $isProd = if ($env) { $env.IsProd } else { $false }
    $tl = Get-EnvRoleTl $r
    $r | Add-Member -NotePropertyName IsProd -NotePropertyValue $isProd -Force
    $r | Add-Member -NotePropertyName IsAdminRole -NotePropertyValue ([string]$r.RoleName -in $envAdminRoleNames) -Force
    $r | Add-Member -NotePropertyName TrustLevel -NotePropertyValue $tl -Force
    $null = $envRoles.Add($r)
    $null = $paths.Add([pscustomobject]@{
        UserId = ([string]$r.UserId).ToLowerInvariant(); PrincipalType = $r.PrincipalType; UserPrincipalName = $r.UserPrincipalName; DisplayName = $r.DisplayName
        Plane = $(if ($r.Source -eq 'Dataverse') { 'Dataverse role' } else { 'Environment role' }); Role = $r.RoleName; Scope = $r.Environment; ScopeId = $r.EnvironmentId; TrustLevel = $tl
        State = 'Standing (outside PIM)'; Standing = $true; Via = $(if ($r.AssignedVia -eq 'Direct') { 'Direct' } else { "$($r.AssignedVia): $($r.TeamName)" }); IsProd = $isProd
    })
}
foreach ($r in $ppRbac) {
    $null = $paths.Add([pscustomobject]@{
        UserId = ([string]$r.PrincipalId).ToLowerInvariant(); PrincipalType = $r.PrincipalType; UserPrincipalName = $null; DisplayName = $null
        Plane = 'Power Platform RBAC'; Role = $r.RoleName; Scope = $r.Scope; ScopeId = $null; TrustLevel = $(if ([string]$r.RoleName -match 'reader') { 'TL4' } else { 'TL2' })
        State = 'Standing (outside PIM)'; Standing = $true; Via = 'Direct'; IsProd = $null
    })
}
foreach ($a in $mgmtApps) {
    $null = $paths.Add([pscustomobject]@{
        UserId = ([string]$a.ServicePrincipalId).ToLowerInvariant(); PrincipalType = 'ServicePrincipal'; UserPrincipalName = $a.ApplicationId; DisplayName = $a.DisplayName
        Plane = 'Management application'; Role = 'Power Platform admin (application)'; Scope = 'Tenant'; ScopeId = $null; TrustLevel = $tlOf['Management application (service principal)']
        State = 'Standing (outside PIM)'; Standing = $true; Via = 'Registration'; IsProd = $null
    })
}
#endregion

#region conditional access evaluation
$ppAppIds = @('microsoftadminportals', '00000007-0000-0000-c000-000000000000', '475226c6-020e-4fb2-8a90-7a972cbfc1d4', '7df0a125-d3be-4c96-aa54-591f83ff541c', '8578e004-a5c6-46e7-913e-12f58912df43')
$groupsOf = @{}
foreach ($g in $userGroups) { $k = ([string]$g.UserId).ToLowerInvariant(); if (-not $groupsOf.ContainsKey($k)) { $groupsOf[$k] = New-Object System.Collections.Generic.HashSet[string] }; $null = $groupsOf[$k].Add(([string]$g.GroupId).ToLowerInvariant()) }
$activeRoleIds = @{}
foreach ($r in $tenantRoles) { if ($r.State -like 'Active*' -and $r.UserId) { $k = ([string]$r.UserId).ToLowerInvariant(); if (-not $activeRoleIds.ContainsKey($k)) { $activeRoleIds[$k] = @() }; $activeRoleIds[$k] += ([string]$r.RoleId).ToLowerInvariant() } }
$split = { param($s) @(([string]$s) -split ';\s*' | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLowerInvariant() }) }
$enabledCa = @($caRows | Where-Object { $_.State -eq 'enabled' })
function Get-CaCoverage {
    param([string]$UserId, [string]$AccountType)
    $res = @{ Mfa = $false; Phish = $false; Device = $false; Policies = @() }
    $uid = $UserId.ToLowerInvariant()
    $gs = if ($groupsOf.ContainsKey($uid)) { $groupsOf[$uid] } else { New-Object System.Collections.Generic.HashSet[string] }
    $rs = if ($activeRoleIds.ContainsKey($uid)) { $activeRoleIds[$uid] } else { @() }
    foreach ($p in $enabledCa) {
        $iu = & $split $p.IncludeUsers; $ig = & $split $p.IncludeGroups; $ir = & $split $p.IncludeRoles
        $eu = & $split $p.ExcludeUsers; $eg = & $split $p.ExcludeGroups; $er = & $split $p.ExcludeRoles
        $in = ($iu -contains 'all') -or ($iu -contains $uid) -or (@($ig | Where-Object { $gs.Contains($_) }).Count -gt 0) -or (@($ir | Where-Object { $rs -contains $_ }).Count -gt 0) -or ($AccountType -eq 'Guest' -and $iu -contains 'guestsorexternalusers')
        if (-not $in) { continue }
        if (($eu -contains $uid) -or (@($eg | Where-Object { $gs.Contains($_) }).Count -gt 0) -or (@($er | Where-Object { $rs -contains $_ }).Count -gt 0)) { continue }
        $ia = & $split $p.IncludeApps; $xa = & $split $p.ExcludeApps
        $appHit = ($ia -contains 'all') -or (@($ia | Where-Object { $_ -in $ppAppIds }).Count -gt 0)
        if (-not $appHit -or $xa -contains 'microsoftadminportals') { continue }
        $bc = & $split $p.BuiltInControls
        $ctrl = @($bc); if ($p.AuthStrength) { $ctrl += 'authstrength' }
        $orMany = ([string]$p.GrantOperator -eq 'OR' -and $ctrl.Count -gt 1)
        $mfa = ($ctrl -contains 'mfa' -or $ctrl -contains 'authstrength') -and (-not $orMany -or @($ctrl | Where-Object { $_ -notin @('mfa', 'authstrength') }).Count -eq 0)
        $phish = (Test-True $p.AuthStrengthPhishingResistant) -and -not $orMany
        $dev = ($ctrl -contains 'compliantdevice' -or $ctrl -contains 'domainjoineddevice') -and -not $orMany
        if ($mfa) { $res.Mfa = $true }; if ($phish) { $res.Phish = $true }; if ($dev) { $res.Device = $true }
        if ($mfa -or $phish -or $dev) { $res.Policies += $p.PolicyName }
    }
    return $res
}
#endregion

#region people register
$ids = New-Object System.Collections.Generic.HashSet[string]
foreach ($p in $paths) { if ($p.UserId -and $p.PrincipalType -eq 'User') { $null = $ids.Add($p.UserId) } }
foreach ($f in $flows) { if ($f.OwnerId -and $f.OwnerType -eq 'User') { $null = $ids.Add(([string]$f.OwnerId).ToLowerInvariant()) } }
foreach ($a in $apps) { if ($a.OwnerId) { $null = $ids.Add(([string]$a.OwnerId).ToLowerInvariant()) } }
foreach ($c in $connections) { if ($c.OwnerId -and $c.OwnerType -ne 'ServicePrincipal') { $null = $ids.Add(([string]$c.OwnerId).ToLowerInvariant()) } }
foreach ($i in $inventory) { if ($i.OwnerId) { $null = $ids.Add(([string]$i.OwnerId).ToLowerInvariant()) } }

function New-Index {
    param($Rows, [string]$Prop)
    $ix = @{}
    foreach ($r in $Rows) { $k = ([string]$r.$Prop).ToLowerInvariant(); if (-not $k) { continue }; if (-not $ix.ContainsKey($k)) { $ix[$k] = New-Object System.Collections.ArrayList }; $null = $ix[$k].Add($r) }
    return $ix
}
$flowsBy = New-Index $flows 'OwnerId'; $appsBy = New-Index $apps 'OwnerId'; $connBy = New-Index $connections 'OwnerId'; $invBy = New-Index $inventory 'OwnerId'
$pathsBy = New-Index $paths 'UserId'; $actBy = New-Index $activations 'UserId'
$get = { param($ix, $k) if ($ix.ContainsKey($k)) { @($ix[$k]) } else { @() } }

$people = New-Object System.Collections.ArrayList
foreach ($id in $ids) {
    $u = $userById[$id]
    $pp = & $get $pathsBy $id
    $f = & $get $flowsBy $id; $a = & $get $appsBy $id; $c = & $get $connBy $id; $inv = & $get $invBy $id
    $upn = if ($u) { $u.UserPrincipalName } else { @($pp | Where-Object UserPrincipalName | Select-Object -First 1 -ExpandProperty UserPrincipalName) }
    $name = if ($u) { $u.DisplayName } else { @($pp | Where-Object DisplayName | Select-Object -First 1 -ExpandProperty DisplayName) }
    if (-not $upn -and $f.Count) { $upn = $f[0].OwnerUserPrincipalName; $name = $f[0].OwnerDisplayName }
    if (-not $upn -and $c.Count) { $upn = $c[0].OwnerUserPrincipalName; $name = $c[0].OwnerDisplayName }
    $upn = [string](@($upn) | Select-Object -First 1); $name = [string](@($name) | Select-Object -First 1)
    $acct = Get-AccountType $upn $name $(if ($u) { $u.UserType } else { $null })
    $enabled = if ($u -and $u.AccountEnabled -ne '') { Test-True $u.AccountEnabled } else { $null }
    $found = if ($u) { Test-True $u.Found } else { $false }

    $tenantP = @($pp | Where-Object Plane -eq 'Entra role')
    $adminP = @($tenantP | Where-Object { $_.Role -in $adminRoleNames })
    $envP = @($pp | Where-Object { $_.Plane -in @('Dataverse role', 'Environment role') })
    $sysProd = @($envP | Where-Object { $_.Role -in $envAdminRoleNames -and $_.IsProd })
    $sysOther = @($envP | Where-Object { $_.Role -in $envAdminRoleNames -and -not $_.IsProd })
    $cust = @($envP | Where-Object { $_.Role -eq 'System Customizer' })
    $highest = [string](@($pp | Where-Object TrustLevel | Sort-Object { $tlRank[[string]$_.TrustLevel] } | Select-Object -First 1 -ExpandProperty TrustLevel) | Select-Object -First 1)
    $acts = @((& $get $actBy $id) | Where-Object { $_.RoleName -in $adminRoleNames })
    $lastAct = @($acts | Sort-Object Created -Descending | Select-Object -First 1 -ExpandProperty Created)
    $pimState = @($adminP | ForEach-Object { $_.State.ToLower() } | Sort-Object -Unique) -join ', '
    $roleText = (@($tenantP | Group-Object Role | ForEach-Object { "$($_.Name) ($(@($_.Group | ForEach-Object { $s = $_.State.ToLower(); if ($_.Via -ne 'Direct') { $s += ' via group' }; $s } | Sort-Object -Unique) -join ', '))" }) -join '; ')

    $linked = $null
    $lu = $upn.ToLowerInvariant()
    if ($acct -eq 'CLAD') {
        if ($mapP2E.ContainsKey($lu)) { $linked = $mapP2E[$lu] }
        else { $k = Get-NameKey $name; if ($k -and $everydayByKey.ContainsKey($k)) { $linked = $everydayByKey[$k] } }
    }
    elseif ($acct -in @('Everyday', 'Guest', 'Other admin account')) {
        if ($mapE2P.ContainsKey($lu)) { $linked = $mapE2P[$lu] }
        else {
            $k = Get-NameKey $name
            if ($k -and $cladByKey.ContainsKey($k)) { $linked = $cladByKey[$k] }
            elseif ($u -and $u.Surname -and $u.GivenName) {
                $sk = "$(([string]$u.Surname).ToLowerInvariant() -replace '[^a-z]','')|$(([string]$u.GivenName).Substring(0,1).ToLowerInvariant())"
                if ($cladBySurInit.ContainsKey($sk)) { $linked = $cladBySurInit[$sk] }
            }
        }
    }

    $ca = if ($highest -and $tlRank[$highest] -le 3) { Get-CaCoverage -UserId $id -AccountType $acct } else { $null }
    $premium = if ($u) { Test-True $u.PremiumPowerPlatformLicence } else { $false }
    $office = if ($u) { Test-True $u.OfficeLicence } else { $false }
    $owns = ($f.Count + $a.Count + $c.Count + $inv.Count) -gt 0
    $flowsOn = @($f | Where-Object State -eq 'On').Count

    $persona = 'Other role holder'; $action = 'Review.'
    if ($enabled -eq $false -or ($u -and -not $found)) { $persona = 'Disabled or deleted account'; $action = 'Remove its roles; reassign its flows, apps and connections to an active owner.' }
    elseif ($acct -eq 'Break-glass') { $persona = 'Break-glass'; $action = 'Keep as the documented exception; not used for Power Platform work.' }
    elseif ($acct -eq 'CLAD') {
        $persona = 'CLAD administrator'; $action = 'Keep for admin only: roles eligible and assigned directly.'
        if ($owns -or $premium -or $office) { $action = 'Move what this CLAD owns to the everyday or a service account and remove its licences: a CLAD administers, it does not build.' }
    }
    elseif ($acct -eq 'Generic/Service') { $persona = 'Shared or service account'; $action = 'Replace with a service principal or a named CLAD; if it must stay, register it as an exception with an owner.' }
    elseif ($adminP.Count -gt 0) {
        $persona = if ($owns) { 'Tenant admin and maker on everyday account' } else { 'Tenant admin on everyday account' }
        $action = $(if ($linked) { "Use the existing CLAD $linked" } else { 'Create a CLAD' }) + " and make it eligible (assigned directly) for $(@($adminP | ForEach-Object Role | Sort-Object -Unique) -join ' and '). Remove the role from this account once the CLAD is proven."
        if ($flowsOn -gt 0) { $action += " Check its $flowsOn active flow(s) first." }
    }
    elseif (@($tenantP | Where-Object Role -eq 'Global Administrator').Count -gt 0) { $persona = 'Global Administrator (Power Platform reach)'; $action = 'Covered by the Entra HLD. Global Administrator can self-elevate into every Dataverse environment.' }
    elseif ($sysProd.Count -gt 0) {
        $persona = if ($owns) { 'Production environment admin and maker' } else { 'Production environment admin' }
        $action = 'Replace System Administrator on this account with a scoped role (System Customizer or a custom role). Production admin work moves to a CLAD through PIM activation and self-elevation.'
        if ($flowsOn -gt 0) { $action += " Check its $flowsOn active flow(s) before removing the role." }
    }
    elseif ($sysOther.Count -gt 0) { $persona = 'Non-production environment admin'; $action = 'Acceptable on the everyday account for non-production environments; record it, and use just-in-time where live data is copied in.' }
    elseif ($tenantP.Count -gt 0) { $persona = 'Other admin role'; $action = 'Make eligible on a CLAD.' }
    elseif ($cust.Count -gt 0 -or $owns) { $persona = 'Maker'; $action = 'No change.' }

    $null = $people.Add([pscustomobject]@{
        DisplayName = $name; UserPrincipalName = $upn; AccountType = $acct; LinkedAccount = $linked
        Enabled = $enabled; Found = $found; HighestTrustLevel = $highest; Persona = $persona
        TenantRoles = $roleText; TenantAdminRoles = (@($adminP | ForEach-Object Role | Sort-Object -Unique) -join '; '); TenantAdminPim = $pimState
        Activations90d = $acts.Count; LastActivation = [string](@($lastAct) | Select-Object -First 1)
        ProdSysAdminEnvironments = (@($sysProd | ForEach-Object Scope | Sort-Object -Unique) -join '; ')
        OtherSysAdminEnvironments = (@($sysOther | ForEach-Object Scope | Sort-Object -Unique) -join '; ')
        CustomizerEnvironments = (@($cust | ForEach-Object Scope | Sort-Object -Unique) -join '; ')
        SysAdminViaTeam = (@($envP | Where-Object { $_.Role -in $envAdminRoleNames -and $_.Via -ne 'Direct' }).Count -gt 0)
        FlowsOwned = $f.Count; FlowsOn = $flowsOn
        FlowsUsingDataverse = @($f | Where-Object { Test-True $_.UsesDataverse }).Count
        FlowsUsingAdminConnectors = @($f | Where-Object { Test-True $_.UsesAdminConnector }).Count
        AppsOwned = $a.Count; ConnectionsOwned = $c.Count; OtherResourcesOwned = $inv.Count
        AdminConnectorConnections = @($c | Where-Object { Test-True $_.IsAdminConnector }).Count
        PremiumLicence = $premium; OfficeLicence = $office
        PhishingResistant = $(if ($u) { $u.PhishingResistant } else { $null }); AuthMethods = $(if ($u) { $u.AuthMethods } else { $null })
        CaAdminMfa = $(if ($ca) { $ca.Mfa } else { $null }); CaPhishingResistant = $(if ($ca) { $ca.Phish } else { $null }); CaCompliantDevice = $(if ($ca) { $ca.Device } else { $null })
        CaPolicies = $(if ($ca) { ($ca.Policies -join '; ') } else { $null })
        LastSignIn = $(if ($u) { $u.LastSignIn } else { $null })
        RecommendedAction = $action; UserId = $id
    })
}
$personaOrder = @{ 'Disabled or deleted account' = 0; 'Tenant admin and maker on everyday account' = 1; 'Tenant admin on everyday account' = 2; 'Production environment admin and maker' = 3; 'Production environment admin' = 4; 'Shared or service account' = 5; 'Global Administrator (Power Platform reach)' = 6; 'CLAD administrator' = 7; 'Break-glass' = 8; 'Other admin role' = 9; 'Non-production environment admin' = 10; 'Maker' = 11; 'Other role holder' = 12 }
$people = @($people | Sort-Object @{ Expression = { $personaOrder[$_.Persona] } }, DisplayName)
$personById = @{}; foreach ($p in $people) { $personById[$p.UserId] = $p }
foreach ($r in $envRoles) { $p = $personById[([string]$r.UserId).ToLowerInvariant()]; $r | Add-Member -NotePropertyName AccountType -NotePropertyValue $(if ($p) { $p.AccountType } else { $null }) -Force; $r | Add-Member -NotePropertyName Enabled -NotePropertyValue $(if ($p) { $p.Enabled } else { $null }) -Force }
foreach ($p in $paths) { $q = $personById[$p.UserId]; $p | Add-Member -NotePropertyName AccountType -NotePropertyValue $(if ($q) { $q.AccountType } elseif ($p.PrincipalType -ne 'User') { 'Workload' } else { $null }) -Force; if ($q -and -not $p.UserPrincipalName) { $p.UserPrincipalName = $q.UserPrincipalName; $p.DisplayName = $q.DisplayName } }
#endregion

#region flows and connections at risk
$risk = New-Object System.Collections.ArrayList
foreach ($f in $flows) {
    if ($f.OwnerType -ne 'User' -or -not $f.OwnerId) { continue }
    $oid = ([string]$f.OwnerId).ToLowerInvariant()
    $p = $personById[$oid]; $pp = & $get $pathsBy $oid
    $on = ($f.State -eq 'On')
    $tenantAdmin = @($pp | Where-Object { $_.Plane -eq 'Entra role' -and ($_.Role -in $adminRoleNames -or $_.Role -eq 'Global Administrator') }).Count -gt 0
    $sysHere = @($pp | Where-Object { $_.ScopeId -eq $f.EnvironmentId -and $_.Role -in $envAdminRoleNames }).Count -gt 0
    $gone = (Test-True $f.OwnerDisabled) -or ($p -and ($p.Enabled -eq $false -or -not $p.Found))
    $isClad = ($p -and $p.AccountType -eq 'CLAD')
    $level = $null; $why = $null
    if ($gone -and $on) { $level = 'High'; $why = 'Owner account is disabled or missing; the flow runs on its connections until they fail.' }
    elseif ((Test-True $f.UsesAdminConnector) -and ($tenantAdmin -or $sysHere)) { $level = $(if ($on) { 'High' } else { 'Low' }); $why = 'Uses an admin connector: fails whenever the owner''s admin role is not active (PIM) or is removed.' }
    elseif ((Test-True $f.UsesDataverse) -and $sysHere) { $level = $(if ($on) { 'High' } else { 'Low' }); $why = 'Uses Dataverse and the owner is System Administrator here: may lose access to records when that role is removed.' }
    elseif ($isClad) { $level = $(if ($on) { 'Medium' } else { 'Low' }); $why = 'Owned by a CLAD: its connections are privileged credentials outside PIM. Move to the everyday or a service account.' }
    elseif (($tenantAdmin -or $sysHere) -and -not (Test-True $f.ConnectorsKnown)) { $level = $(if ($on) { 'Medium' } else { 'Low' }); $why = 'Owner holds admin rights and the connectors could not be read; check with the owner.' }
    elseif ($tenantAdmin -or $sysHere) { $level = 'Low'; $why = 'Owner holds admin rights but the flow uses no Dataverse or admin connectors; unlikely to break.' }
    if (-not $level) { continue }
    $null = $risk.Add([pscustomobject]@{
        Severity = $level; Environment = $f.Environment; EnvironmentType = $f.EnvironmentType; FlowName = $f.FlowName; State = $f.State
        Owner = $(if ($p) { $p.DisplayName } else { $f.OwnerDisplayName }); OwnerUserPrincipalName = $(if ($p) { $p.UserPrincipalName } else { $f.OwnerUserPrincipalName })
        OwnerAccountType = $(if ($p) { $p.AccountType } else { $null }); OwnerPersona = $(if ($p) { $p.Persona } else { $null })
        OwnerIsTenantAdmin = $tenantAdmin; OwnerIsSysAdminHere = $sysHere; Connectors = $f.Connectors; Trigger = $f.Trigger; Reason = $why; FlowId = $f.FlowId
    })
}
$sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
$risk = @($risk | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Environment, FlowName)

$connRisk = New-Object System.Collections.ArrayList
foreach ($c in $connections) {
    if ($c.OwnerType -eq 'ServicePrincipal' -or -not $c.OwnerId) { continue }
    $oid = ([string]$c.OwnerId).ToLowerInvariant(); $p = $personById[$oid]; $pp = & $get $pathsBy $oid
    $admin = @($pp | Where-Object { $_.Plane -eq 'Entra role' -and ($_.Role -in $adminRoleNames -or $_.Role -eq 'Global Administrator') }).Count -gt 0
    $sysHere = @($pp | Where-Object { $_.ScopeId -eq $c.EnvironmentId -and $_.Role -in $envAdminRoleNames }).Count -gt 0
    $why = $null; $lvl = $null
    if ($p -and $p.AccountType -eq 'CLAD') { $lvl = 'High'; $why = 'Connection owned by a CLAD: a stored privileged credential that works outside PIM.' }
    elseif ((Test-True $c.IsAdminConnector) -and ($admin -or $sysHere)) { $lvl = 'High'; $why = 'Admin connector connection: acts with the owner''s admin rights; fails when the role is not active.' }
    elseif ((Test-True $c.IsDataverse) -and $sysHere) { $lvl = 'Medium'; $why = 'Dataverse connection of a System Administrator: anything using it inherits full data access.' }
    elseif ((Test-True $c.IsPrivilegedConnector) -and ($admin -or $sysHere)) { $lvl = 'Medium'; $why = 'Privileged connector (Entra, Azure, Key Vault) owned by an admin.' }
    if (-not $lvl) { continue }
    $null = $connRisk.Add([pscustomobject]@{ Severity = $lvl; Environment = $c.Environment; Connector = $c.Connector; ConnectionName = $c.DisplayName; Owner = $(if ($p) { $p.DisplayName } else { $c.OwnerDisplayName }); OwnerUserPrincipalName = $(if ($p) { $p.UserPrincipalName } else { $c.OwnerUserPrincipalName }); OwnerAccountType = $(if ($p) { $p.AccountType } else { $null }); Status = $c.Status; Reason = $why; ConnectionId = $c.ConnectionId })
}
$connRisk = @($connRisk | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Environment)
#endregion

#region PIM settings, coverage and impact
$tlBase = { param($tl) if ($baselines -and $tl -and $baselines.PSObject.Properties[$tl]) { $baselines.$tl } else { $null } }
$policyGaps = @(foreach ($s in $roleSettings) {
    $tl = $tlOf[[string]$s.RoleName]; $b = & $tlBase $tl
    $g = @()
    if ($b) {
        if ($b.MaxActivationHours -and $s.MaxActivationHours -and [double]$s.MaxActivationHours -gt [double]$b.MaxActivationHours) { $g += "activation $($s.MaxActivationHours)h (baseline $($b.MaxActivationHours)h)" }
        if ($b.MfaOrAuthContextRequired -and -not (Test-True $s.MfaRequired) -and -not (Test-True $s.AuthContextRequired)) { $g += 'no MFA or authentication context on activation' }
        if ($b.AuthContextTarget -and -not (Test-True $s.AuthContextRequired)) { $g += 'no authentication context (target)' }
        if ($b.JustificationRequired -and -not (Test-True $s.JustificationRequired)) { $g += 'no justification' }
        if ($b.ApprovalRequired -eq $true -and -not (Test-True $s.ApprovalRequired)) { $g += 'no approval' }
        if ($b.PermanentEligibleAllowed -eq $false -and (Test-True $s.PermanentEligibleAllowed)) { $g += 'permanent eligible allowed' }
        if ($b.PermanentActiveAllowed -eq $false -and (Test-True $s.PermanentActiveAllowed)) { $g += 'permanent active allowed' }
    }
    [pscustomobject]@{ RoleName = $s.RoleName; TrustLevel = $tl; Result = $(if ($g.Count -eq 0) { 'Good' } elseif ($g.Count -le 2) { 'Partial' } else { 'Weak' }); MaxActivationHours = $s.MaxActivationHours; ApprovalRequired = $s.ApprovalRequired; Approvers = $s.Approvers; MfaRequired = $s.MfaRequired; AuthContextRequired = $s.AuthContextRequired; JustificationRequired = $s.JustificationRequired; PermanentEligibleAllowed = $s.PermanentEligibleAllowed; PermanentActiveAllowed = $s.PermanentActiveAllowed; Gaps = ($g -join '; ') }
})

$coverage = New-Object System.Collections.ArrayList
foreach ($g in @($paths | Where-Object { $_.Plane -eq 'Entra role' -and $_.PrincipalType -eq 'User' } | Group-Object Role)) {
    $rs = @($g.Group); $ppl = @($rs | Select-Object -ExpandProperty UserId -Unique)
    $perm = @($rs | Where-Object Standing | Select-Object -ExpandProperty UserId -Unique)
    $jit = @($ppl | Where-Object { $x = $_; @($rs | Where-Object { $_.UserId -eq $x -and $_.State -notin @('Eligible', 'Activated now') }).Count -eq 0 })
    $tb = [Math]::Max(0, $ppl.Count - $jit.Count - $perm.Count)
    $status = if ($perm.Count -eq 0 -and $jit.Count -gt 0) { 'Just-in-time (PIM)' } elseif ($perm.Count -eq 0) { 'Time-bound active' } elseif ($jit.Count -eq 0) { 'Permanent (no PIM)' } else { 'Mixed' }
    $null = $coverage.Add([pscustomobject]@{ Role = $g.Name; TrustLevel = $tlOf[$g.Name]; People = $ppl.Count; JustInTime = $jit.Count; TimeBound = $tb; Permanent = $perm.Count; PimStatus = $status; ViaGroups = (@($rs | Where-Object { $_.Via -ne 'Direct' } | ForEach-Object Via | Sort-Object -Unique | Select-Object -First 3) -join '; ') })
}
foreach ($g in @($paths | Where-Object { $_.Plane -in @('Dataverse role', 'Environment role') -and $_.PrincipalType -eq 'User' -and $_.Role -in $envAdminRoleNames } | Group-Object { if ($_.IsProd) { 'System Administrator (production or default)' } else { 'System Administrator (other environments)' } })) {
    $n = @($g.Group | Select-Object -ExpandProperty UserId -Unique).Count
    $null = $coverage.Add([pscustomobject]@{ Role = $g.Name; TrustLevel = [string](@($g.Group | Sort-Object { $tlRank[[string]$_.TrustLevel] } | Select-Object -First 1 -ExpandProperty TrustLevel) | Select-Object -First 1); People = $n; JustInTime = 0; TimeBound = 0; Permanent = $n; PimStatus = 'Permanent (no PIM)'; ViaGroups = (@($g.Group | Where-Object { $_.Via -ne 'Direct' } | ForEach-Object Via | Sort-Object -Unique | Select-Object -First 3) -join '; ') })
}

$days = [int]$meta.activationHistoryDays; if ($days -le 0) { $days = 90 }
$impact = New-Object System.Collections.ArrayList
foreach ($p in @($people | Where-Object { $_.TenantAdminRoles -or $_.ProdSysAdminEnvironments })) {
    $pp = & $get $pathsBy $p.UserId
    $myRisk = @($risk | Where-Object { $_.OwnerUserPrincipalName -eq $p.UserPrincipalName -and $_.Severity -ne 'Low' })
    $myConn = @($connRisk | Where-Object { $_.OwnerUserPrincipalName -eq $p.UserPrincipalName -and $_.Severity -eq 'High' })
    $grp = @($pp | Where-Object { $_.Plane -eq 'Entra role' -and $_.Role -in $adminRoleNames -and $_.Via -ne 'Direct' }).Count -gt 0
    $perWeek = [Math]::Round([int]$p.Activations90d / ($days / 7.0), 1)
    $prodEnvCount = @(([string]$p.ProdSysAdminEnvironments) -split '; ' | Where-Object { $_ }).Count
    $changes = @(); $breaks = @(); $mitig = @()
    if ($p.AccountType -ne 'CLAD' -and $p.TenantAdminRoles) { $changes += 'admin work moves to a CLAD (separate sign-in)' }
    if ($p.TenantAdminPim -match 'permanent|time-bound') { $changes += 'activate in PIM before using the admin centre or admin PowerShell, then sign out and in' }
    if ($prodEnvCount -gt 0) { $changes += "self-elevate (Environment > Membership > Add me) in $prodEnvCount production environment(s) when needed; removed when the activation ends" }
    if ($grp) { $breaks += 'role comes through a group: not supported by Power Platform, so self-elevation fails'; $mitig += 'assign the role directly (eligible)' }
    if ($myRisk.Count) { $breaks += "$($myRisk.Count) flow(s) rely on their admin rights or their CLAD"; $mitig += 'give scoped roles or move flows to a service account first' }
    if ($myConn.Count) { $breaks += "$($myConn.Count) admin or CLAD connection(s)"; $mitig += 'move governance automation to a service principal registered as a management app' }
    if ($perWeek -ge 5) { $changes += "activates about $perWeek times a week today: expect friction"; $mitig += 'move routine environment work to scoped environment roles' }
    if ($p.PhishingResistant -ne 'True') { $mitig += 'register a passkey before phishing-resistant enforcement' }
    $lvl = if ($breaks.Count -gt 0) { 'High' } elseif ($perWeek -ge 5 -or $prodEnvCount -gt 0) { 'Medium' } else { 'Low' }
    $null = $impact.Add([pscustomobject]@{
        Impact = $lvl; DisplayName = $p.DisplayName; UserPrincipalName = $p.UserPrincipalName; AccountType = $p.AccountType; LinkedAccount = $p.LinkedAccount
        Roles = $p.TenantAdminRoles; HeldAs = $p.TenantAdminPim; ProductionSysAdmin = $p.ProdSysAdminEnvironments
        Activations90d = $p.Activations90d; ActivationsPerWeek = $perWeek
        WhatChanges = ($changes -join '; '); WhatBreaks = ($breaks -join '; '); BeforeTheChange = ($mitig -join '; ')
    })
}
$impact = @($impact | Sort-Object @{ Expression = { $sevOrder[$_.Impact] } }, DisplayName)
#endregion

#region CLAD provisioning and migration worksheet
$cladProv = @(foreach ($p in @($people | Where-Object { $_.AccountType -in @('Everyday', 'Guest', 'Other admin account') -and $_.Enabled -ne $false -and ($_.TenantRoles -or $_.ProdSysAdminEnvironments) })) {
    $u = $userById[$p.UserId]
    $keep = @()
    if ($p.CustomizerEnvironments) { $keep += "System Customizer: $($p.CustomizerEnvironments)" }
    if ($p.OtherSysAdminEnvironments) { $keep += "System Administrator (non-production): $($p.OtherSysAdminEnvironments)" }
    if ($p.PremiumLicence) { $keep += 'Power Platform licence' }
    if ([int]$p.FlowsOwned -gt 0 -or [int]$p.AppsOwned -gt 0) { $keep += "ownership of $($p.FlowsOwned) flow(s) and $($p.AppsOwned) app(s)" }
    $move = @()
    if ($p.TenantRoles) { $move += $p.TenantRoles }
    if ($p.ProdSysAdminEnvironments) { $move += "System Administrator in production ($($p.ProdSysAdminEnvironments)) -> just-in-time from the CLAD" }
    $prop = if ($p.LinkedAccount) { $null } elseif ($u) { Get-ProposedCladUpn $u } else { $null }
    [pscustomobject]@{
        Person = $p.DisplayName; EverydayUpn = $p.UserPrincipalName; AccountType = $p.AccountType
        ExistingClad = $p.LinkedAccount; ProposedCladUpn = $prop
        RightsToMove = ($move -join '; '); KeepOnEveryday = ($keep -join '; ')
        FlowsToCheckFirst = @($risk | Where-Object { $_.OwnerUserPrincipalName -eq $p.UserPrincipalName -and $_.Severity -ne 'Low' }).Count
        Notes = $(if ($p.AccountType -eq 'Guest') { 'Guest: supplier CLAD in this tenant, eligible, with an end date' } elseif (-not $p.LinkedAccount -and -not $prop) { 'Name could not be derived; set manually' } else { '' })
    }
})

$migration = @(foreach ($p in @($paths | Where-Object { $_.PrincipalType -eq 'User' -and $_.TrustLevel -in @('TL1', 'TL2', 'TL3') })) {
    $q = $personById[$p.UserId]
    $acct = if ($q) { $q.AccountType } else { $null }
    $act = 'Keep; record and review'
    if ($q -and ($q.Enabled -eq $false -or -not $q.Found)) { $act = 'Remove (disabled or deleted account)' }
    elseif ($p.Plane -eq 'Entra role') {
        if ($acct -in @('Everyday', 'Guest', 'Other admin account', 'Generic/Service')) { $act = 'Move to CLAD, eligible, assigned directly' }
        elseif ($p.Via -ne 'Direct' -and $p.Role -in $adminRoleNames) { $act = 'Assign directly (eligible): Power Platform does not support group assignment' }
        elseif ($p.State -eq 'Permanent' -and $acct -ne 'Break-glass') { $act = 'Convert to eligible' }
    }
    elseif ($p.Role -in $envAdminRoleNames -and $p.IsProd) {
        if ($p.Via -ne 'Direct') { $act = 'Put the team''s group under PIM for Groups, or remove the role from the team' }
        elseif ($acct -eq 'CLAD') { $act = 'Remove the standing assignment; use activation and self-elevation' }
        else { $act = 'Replace with a scoped role on the everyday account; production admin from a CLAD just-in-time' }
    }
    elseif ($p.Role -eq 'System Customizer' -and $p.IsProd -and $p.Via -ne 'Direct') { $act = 'Keep through a PIM for Groups group' }
    [pscustomobject]@{ Person = $p.DisplayName; UserPrincipalName = $p.UserPrincipalName; AccountType = $acct; Plane = $p.Plane; Role = $p.Role; Scope = $p.Scope; TrustLevel = $p.TrustLevel; State = $p.State; Via = $p.Via; ProposedAction = $act; TargetPath = ''; Wave = ''; RoleOwner = ''; Decision = '' }
})
$migration = @($migration | Sort-Object @{ Expression = { $tlRank[[string]$_.TrustLevel] } }, Person)
#endregion

#region environments summary
$envSummary = @(foreach ($e in $envs) {
    $eid = [string]$e.EnvironmentId
    $sa = @($envRoles | Where-Object { [string]$_.EnvironmentId -eq $eid -and $_.IsAdminRole -and $_.PrincipalType -eq 'User' })
    [pscustomobject]@{
        Environment = $e.DisplayName; Type = $e.Type; IsDefault = (Test-True $e.IsDefault); IsProd = $e.IsProd; Dataverse = (Test-True $e.HasDataverse)
        SecurityGroup = $e.SecurityGroupName; SecurityGroupMembers = $e.SecurityGroupMembers; Managed = (Test-True $e.Managed)
        SystemAdminPeople = @($sa | Select-Object -ExpandProperty UserId -Unique).Count
        SystemAdminEveryday = @($sa | Where-Object { $_.AccountType -in @('Everyday', 'Guest') } | Select-Object -ExpandProperty UserId -Unique).Count
        SystemAdminViaTeams = @($sa | Where-Object { $_.AssignedVia -ne 'Direct' } | Select-Object -ExpandProperty UserId -Unique).Count
        AppUsersSysAdmin = @($envRoles | Where-Object { [string]$_.EnvironmentId -eq $eid -and $_.PrincipalType -eq 'Application user' -and $_.RoleName -eq 'System Administrator' }).Count
        AuditEnabled = $e.AuditEnabled; DataverseUsers = $e.DataverseUsers
        Flows = @($flows | Where-Object { [string]$_.EnvironmentId -eq $eid }).Count
        RolesRead = (([string]$e.DataverseAccess -like 'OK*') -or ($e.DataverseAccess -eq 'NotApplicable')); DataverseAccess = $e.DataverseAccess; Elevated = $e.Elevated
        EnvironmentId = $eid
    }
})
#endregion

#region controls
$trForCtx = @($tenantRoles | ForEach-Object { $_.UserId = ([string]$_.UserId).ToLowerInvariant(); $_ })
$ctx = @{
    Meta = $meta; People = $people; TenantRoles = $trForCtx
    EnvRoles = $envRoles; Environments = $envs; EnvSummary = $envSummary; RoleSettings = $roleSettings; PolicyGaps = $policyGaps
    FlowsAtRisk = $risk; Connections = $connections; ManagementApps = $mgmtApps; PpRbac = $ppRbac; Dlp = $dlp; TenantSettings = $tenantSettings
    Baseline = (& $tlBase 'TL2')
}
$audit = Get-PpAuditControls -Ctx $ctx
#endregion

#region metrics and CSV output
$tenantAdmins = @($people | Where-Object TenantAdminRoles)
$prKnown = @($tenantAdmins | Where-Object { $_.PhishingResistant -in @('True', 'False') })
$metrics = [ordered]@{
    TenantName = $meta.tenantName; TenantShortName = $meta.tenantShortName; Run = (Split-Path $RunFolder -Leaf)
    Environments = $envs.Count; ProductionOrDefault = @($envs | Where-Object IsProd).Count; EnvironmentsWithDataverse = @($envs | Where-Object { Test-True $_.HasDataverse }).Count
    EnvironmentsNotRead = @($envs | Where-Object { $_.DataverseAccess -in @('NoDataverseAccess', 'Failed') }).Count
    TenantAdmins = $tenantAdmins.Count
    TenantAdminsEveryday = @($tenantAdmins | Where-Object { $_.AccountType -in @('Everyday', 'Guest') -and $_.Enabled -ne $false }).Count
    TenantAdminsClad = @($tenantAdmins | Where-Object AccountType -eq 'CLAD').Count
    TenantAdminsPermanent = @($tenantAdmins | Where-Object { $_.TenantAdminPim -match 'permanent' }).Count
    TenantAdminsViaGroups = @($paths | Where-Object { $_.Plane -eq 'Entra role' -and $_.Role -in $adminRoleNames -and $_.Via -ne 'Direct' } | Select-Object -ExpandProperty UserId -Unique).Count
    GlobalAdmins = @($paths | Where-Object { $_.Plane -eq 'Entra role' -and $_.Role -eq 'Global Administrator' -and $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty UserId -Unique).Count
    ProdSysAdmins = @($envRoles | Where-Object { $_.IsAdminRole -and $_.IsProd -and $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty UserId -Unique).Count
    ProdSysAdminsEveryday = @($envRoles | Where-Object { $_.IsAdminRole -and $_.IsProd -and $_.PrincipalType -eq 'User' -and $_.AccountType -in @('Everyday', 'Guest') } | Select-Object -ExpandProperty UserId -Unique).Count
    PeopleNeedingClad = @($cladProv | Where-Object { -not $_.ExistingClad }).Count
    PeopleWithClad = @($cladProv | Where-Object { $_.ExistingClad }).Count
    CladsOwningResources = @($people | Where-Object { $_.AccountType -eq 'CLAD' -and ([int]$_.FlowsOwned + [int]$_.AppsOwned + [int]$_.ConnectionsOwned) -gt 0 }).Count
    Flows = $flows.Count; FlowsOn = @($flows | Where-Object State -eq 'On').Count
    FlowsAtRiskHigh = @($risk | Where-Object Severity -eq 'High').Count; FlowsAtRiskMedium = @($risk | Where-Object Severity -eq 'Medium').Count
    ConnectionsAtRiskHigh = @($connRisk | Where-Object Severity -eq 'High').Count
    PimImpactHigh = @($impact | Where-Object Impact -eq 'High').Count
    Apps = $apps.Count; Connections = $connections.Count; OtherResources = $inventory.Count
    Makers = @($people | Where-Object { ([int]$_.FlowsOwned + [int]$_.AppsOwned + [int]$_.OtherResourcesOwned) -gt 0 }).Count
    AdminsPhishingResistantPct = $(if ($prKnown.Count) { [int][Math]::Round(100 * @($prKnown | Where-Object PhishingResistant -eq 'True').Count / $prKnown.Count) } else { $null })
    ControlsGood = @($audit.Controls | Where-Object Result -eq 'Good').Count; ControlsPartial = @($audit.Controls | Where-Object Result -eq 'Partial').Count; ControlsWeak = @($audit.Controls | Where-Object Result -eq 'Weak').Count
    Elevations = $elevations.Count; ElevationsNotRemoved = @($elevations | Where-Object { $_.ElevationResult -eq 'OK' -and $_.RemovalResult -ne 'OK' }).Count
}
foreach ($c in $audit.Caf) { $metrics["Caf_$($c.Outcome -replace '\.', '')"] = $c.Rating }

$outputs = [ordered]@{
    'PP_Controls.csv' = $audit.Controls; 'PP_NcscCafBenchmark.csv' = $audit.Caf; 'PP_Ssa.csv' = $audit.Ssa
    'PP_People.csv' = $people; 'PP_CladProvisioning.csv' = $cladProv; 'PP_PimImpact.csv' = $impact; 'PP_TrustLevels.csv' = $model
    'PP_AccessPaths.csv' = $paths; 'PP_PimCoverage.csv' = $coverage; 'PP_PolicyGaps.csv' = $policyGaps; 'PP_RoleSettings.csv' = $roleSettings
    'PP_FlowsAtRisk.csv' = $risk; 'PP_ConnectionsAtRisk.csv' = $connRisk; 'PP_MigrationWorksheet.csv' = $migration
    'PP_Environments.csv' = $envSummary; 'PP_ConditionalAccess.csv' = $caRows; 'PP_Dlp.csv' = $dlp
}
#endregion

#region html
$enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
$plf = { param($n, $one, $many) if ([int]$n -eq 1) { "$n $one" } else { "$n $many" } }
$programme = if ($brand -and $brand.Programme) { $brand.Programme } else { 'PIM review' }
$preparedBy = if ($brand -and $brand.PreparedBy) { $brand.PreparedBy } else { 'PIM review' }
$classification = if ($brand -and $brand.Classification) { $brand.Classification } else { 'Confidential' }
$css = ''
$src = Get-Content (Join-Path $PSScriptRoot 'New-PimPhase2Report.ps1') -Raw
if ($src -match "(?s)\`$css = @'\r?\n(.*?)\r?\n'@") { $css = $Matches[1] }
$resultClass = { param($r) switch ($r) { 'Good' { 'good' } 'Achieved' { 'good' } 'Strong' { 'good' } 'Partial' { 'part' } 'Partially achieved' { 'part' } 'Partly in place' { 'part' } 'Weak' { 'weak' } 'Not achieved' { 'weak' } default { 'na' } } }
$tile = { param($n, $label, $cls, $guide) $g = if ($guide) { "<div class=""g"">$(& $enc $guide)</div>" } else { '' }; "<div class=""tile $cls""><div class=""n"">$(& $enc $n)</div><div class=""l"">$(& $enc $label)</div>$g</div>" }
$controls = @($audit.Controls); $good = @($audit.Strengths); $weak = @($audit.Weaknesses)
$nPart = @($controls | Where-Object Result -eq 'Partial').Count; $nWeak = @($controls | Where-Object Result -eq 'Weak').Count

# Holders per trust-level row
foreach ($m in $model) {
    $k = $m.Key
    $n = switch -Regex ($k) {
        '^System Administrator \(production' { @($paths | Where-Object { $_.Role -in $envAdminRoleNames -and $_.IsProd -and $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty UserId -Unique).Count }
        '^System Administrator \(sandbox' { @($paths | Where-Object { $_.Role -eq 'System Administrator' -and -not $_.IsProd -and $_.TrustLevel -ne 'TL4' -and $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty UserId -Unique).Count }
        '^System Administrator \(developer' { @($paths | Where-Object { $_.Role -eq 'System Administrator' -and -not $_.IsProd -and $_.TrustLevel -eq 'TL4' -and $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty UserId -Unique).Count }
        '^System Customizer' { @($paths | Where-Object { $_.Role -eq 'System Customizer' -and $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty UserId -Unique).Count }
        '^Environment Admin' { @($paths | Where-Object { $_.Role -match '^Environment ?Admin$' } | Select-Object -ExpandProperty UserId -Unique).Count }
        '^Environment Maker' { @($paths | Where-Object { $_.Role -match 'Maker' } | Select-Object -ExpandProperty UserId -Unique).Count }
        '^Power Platform RBAC' { @($ppRbac).Count }
        '^Management application' { @($mgmtApps).Count }
        default { @($paths | Where-Object { $_.Role -eq $k -and $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty UserId -Unique).Count }
    }
    $m | Add-Member -NotePropertyName Holders -NotePropertyValue $n -Force
}

$h = New-Object System.Text.StringBuilder
$null = $h.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>Power Platform Privileged Access Audit - $(& $enc $meta.tenantName)</title><style>$css</style></head><body><main>")
$null = $h.Append("<div class=""cover""><div class=""kicker"">$(& $enc $programme)</div><h1>Power Platform Privileged Access Audit: $(& $enc $meta.tenantName)</h1>")
$null = $h.Append('<div class="meta">Who can administer Power Platform, from which accounts, how that access is held (PIM or standing), and what would change or break when it moves to CLAD accounts under PIM. Measured against the Trust Level model and benchmarked against the NCSC Cyber Assessment Framework (CAF 4.0, Principle B2).</div>')
$runRoles = (@($meta.runAccountRoles) -join ', '); if (-not $runRoles) { $runRoles = 'no admin role active' }
$null = $h.Append("<div class=""meta"">Evidence: $(& $enc (Split-Path $RunFolder -Leaf)) collected by $(& $enc $meta.runAccount) ($(& $enc $runRoles)) &middot; Prepared by $(& $enc $preparedBy) &middot; $(Get-Date -Format 'd MMMM yyyy') &middot; $(& $enc $classification)</div></div>")
$sections = @(@('glance', 'At a glance'), @('tl', 'Trust levels in Power Platform'), @('good', 'What is working well'), @('attention', 'What needs attention'), @('accounts', 'Everyday and CLAD accounts'), @('pimimpact', 'What changes, and what breaks, with Power Platform admin in PIM'), @('pim', 'Where PIM is used, and where it is not'), @('risk', 'Flows and connections at risk'), @('benchmark', 'NCSC benchmark'), @('envs', 'Environments'), @('controls', 'All control checks'), @('method', 'How to read this report'))
$null = $h.Append('<ol class="toc">'); foreach ($s in $sections) { $null = $h.Append("<li><a href=""#$($s[0])"">$($s[1])</a></li>") }; $null = $h.Append('</ol>')

$null = $h.Append('<h2 id="glance">At a glance</h2>')
$assessed = @($controls | Where-Object Result -ne 'Not assessed').Count
$topGood = @($good | Select-Object -First 3 | ForEach-Object { $_.Control })
$topGap = @($weak | Where-Object { $_.Result -eq 'Weak' -and $_.Gap } | Select-Object -First 4 | ForEach-Object { $_.Gap })
$verdict = "Of $assessed controls checked, <strong>$($good.Count) are in place</strong>, $nPart are partly in place and <strong>$nWeak are weak</strong>."
if ($topGood.Count) { $verdict += ' Working well: ' + (& $enc ($topGood -join '; ')) + '.' }
if ($topGap.Count) { $verdict += ' The most important gaps are that ' + (& $enc ($topGap -join '; ')) + '.' }
$null = $h.Append("<p class=""verdict"">$verdict</p><div class=""tiles"">")
$null = $h.Append((& $tile $metrics.TenantAdmins 'People with Power Platform or Dynamics 365 Administrator' '' $null))
$null = $h.Append((& $tile $metrics.TenantAdminsEveryday 'of them on everyday accounts' $(if ($metrics.TenantAdminsEveryday) { 'weak' } else { 'good' }) 'Target: none'))
$null = $h.Append((& $tile $metrics.TenantAdminsPermanent 'held permanently (no PIM)' $(if ($metrics.TenantAdminsPermanent) { 'weak' } else { 'good' }) 'Target: none'))
$null = $h.Append((& $tile $metrics.ProdSysAdminsEveryday 'Everyday accounts with production System Administrator' $(if ($metrics.ProdSysAdminsEveryday) { 'weak' } else { 'good' }) 'Target: none'))
$null = $h.Append((& $tile $metrics.GlobalAdmins 'Global Admins (reach every environment)' $(if ($metrics.GlobalAdmins -lt 5) { 'good' } else { 'weak' }) 'Microsoft: fewer than 5'))
$null = $h.Append((& $tile $metrics.PeopleNeedingClad 'People who need a new CLAD' $(if ($metrics.PeopleNeedingClad) { 'part' } else { 'good' }) $null))
$null = $h.Append((& $tile $metrics.FlowsAtRiskHigh 'Active flows likely to break' $(if ($metrics.FlowsAtRiskHigh) { 'weak' } else { 'good' }) 'Fix before the change'))
$null = $h.Append((& $tile $metrics.Makers 'People who build (unaffected)' '' $null))
$null = $h.Append('</div>')
$gapEnv = @($envSummary | Where-Object { -not $_.RolesRead -and $_.Dataverse })
if ($gapEnv.Count -or -not $meta.powerPlatformApiAvailable) {
    $t = if (-not $meta.powerPlatformApiAvailable) { 'The Power Platform admin APIs could not be reached (Power Platform Administrator not active for the run account), so environments, flows, apps and connections are missing.' } else { "$(& $plf $gapEnv.Count 'environment' 'environments') could not be read inside Dataverse, so their System Administrators are missing: $((@($gapEnv | ForEach-Object Environment)) -join ', '). Re-run with -ElevateForAudit." }
    $null = $h.Append("<p class=""note""><strong>Coverage:</strong> $(& $enc $t)</p>")
}
if ([int]$metrics.ElevationsNotRemoved -gt 0) { $null = $h.Append("<p class=""note""><strong>Action needed:</strong> the audit elevated the run account in $($metrics.ElevationsNotRemoved) environment(s) and could not remove it. See Raw\pp-elevations.csv.</p>") }
$null = $h.Append('<h3>NCSC CAF Principle B2 (indicative)</h3><div class="caf">')
foreach ($c in @($audit.Caf)) { $null = $h.Append("<div class=""cafc $(& $resultClass $c.Rating)""><div class=""id"">$(& $enc $c.Outcome) $(& $enc $c.Title)</div><div class=""t"">$(& $enc $c.WhatTheOutcomeMeans)</div><span class=""$(Get-P2BadgeClass -Value $c.Rating)"">$(& $enc $c.Rating)</span> <span class=""more"">$($c.Good) good, $($c.Partial) partial, $($c.Weak) weak</span></div>") }
$null = $h.Append('</div>')

$null = $h.Append('<h2 id="tl">Trust levels in Power Platform</h2><p class="lede">Power Platform has two layers of admin rights. Entra roles (Power Platform Administrator, Dynamics 365 Administrator, Global Administrator) are tenant-wide and PIM governs them. Dataverse roles (System Administrator and others) are assigned inside each environment and PIM does not see them. Tenant admins no longer get System Administrator automatically: they self-elevate per environment, and the role is removed when their PIM activation ends. The table places each kind of access in the Trust Level model, with what it can do, what it needs and what PIM changes.</p>')
$tlView = @($model | ForEach-Object { [pscustomobject]@{ Access = $_.Key; Layer = $_.Layer; TrustLevel = $_.TrustLevel; Holders = $_.Holders; WhatItCanDo = $_.CanDo; WhatItNeeds = $_.Needs; WhatPimChanges = $_.UnderPim } })
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $tlView -Columns @('Access', 'Layer', 'TrustLevel', 'Holders', 'WhatItCanDo', 'WhatItNeeds', 'WhatPimChanges')))

$null = $h.Append('<h2 id="good">What is working well</h2><p class="lede">Controls that already meet the expected standard.</p>')
if ($good.Count -eq 0) { $null = $h.Append('<p class="more">No control fully met the standard in this evidence.</p>') }
else { $null = $h.Append('<ul class="list">'); foreach ($c in $good) { $null = $h.Append("<li><div class=""h"">$(& $enc $c.Control)</div><div class=""d"">$(& $enc $c.Finding)</div></li>") }; $null = $h.Append('</ul>') }
$null = $h.Append('<h2 id="attention">What needs attention</h2><p class="lede">In priority order: weak controls first, by severity, then controls that are partly in place.</p>')
foreach ($c in $weak) {
    $null = $h.Append("<div class=""$(if ($c.Result -eq 'Partial') { 'card part' } else { 'card' })""><div class=""top""><span class=""$(Get-P2BadgeClass -Value $c.Result)"">$(& $enc $c.Result)</span>")
    if ($c.Severity) { $null = $h.Append("<span class=""$(Get-P2BadgeClass -Value $c.Severity)"">$(& $enc $c.Severity)</span>") }
    $null = $h.Append("<span class=""title"">$(& $enc $c.Control)</span></div><div class=""found"">$(& $enc $c.Finding)</div><dl>")
    if ($c.WhyItMatters) { $null = $h.Append("<dt>Why it matters</dt><dd>$(& $enc $c.WhyItMatters)</dd>") }
    if ($c.WhatGoodLooksLike) { $null = $h.Append("<dt>What good looks like</dt><dd>$(& $enc $c.WhatGoodLooksLike)</dd>") }
    if ($c.RecommendedAction) { $null = $h.Append("<dt>Recommended action</dt><dd>$(& $enc $c.RecommendedAction)</dd>") }
    $refs = @(); if ($c.CafOutcome) { $refs += "NCSC CAF $($c.CafOutcome)" }; if ($c.NcscPrinciple) { $refs += "NCSC secure system administration $($c.NcscPrinciple -replace 'SSA ', 'principle ')" }; if ($c.Reference) { $refs += $c.Reference }; if ($c.Evidence) { $refs += "Evidence: $($c.Evidence)" }
    $null = $h.Append("</dl><div class=""ref"">$(& $enc ($refs -join ' | ')) &middot; $(& $enc $c.Id)</div></div>")
}

$null = $h.Append('<h2 id="accounts">Everyday and CLAD accounts</h2><p class="lede">The target is two identities per admin: the CLAD administers (no licence, eligible roles, assigned directly); the everyday account builds (licence, maker and scoped environment roles, no tenant admin role). This shows where each person stands today.</p>')
$acctRows = @(foreach ($t in @('Everyday', 'CLAD', 'Guest', 'Other admin account', 'Generic/Service', 'Break-glass', 'Unknown')) {
    $g = @($people | Where-Object AccountType -eq $t); if ($g.Count -eq 0) { continue }
    [pscustomobject]@{ AccountType = $t; People = $g.Count; TenantAdmin = @($g | Where-Object TenantAdminRoles).Count; ProductionSysAdmin = @($g | Where-Object ProdSysAdminEnvironments).Count; OwnFlowsOrApps = @($g | Where-Object { ([int]$_.FlowsOwned + [int]$_.AppsOwned) -gt 0 }).Count; PowerPlatformLicence = @($g | Where-Object PremiumLicence).Count; PhishingResistant = @($g | Where-Object PhishingResistant -eq 'True').Count }
})
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $acctRows -Columns @('AccountType', 'People', 'TenantAdmin', 'ProductionSysAdmin', 'OwnFlowsOrApps', 'PowerPlatformLicence', 'PhishingResistant')))
$null = $h.Append('<h3>Who does what</h3>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($people | Where-Object { $_.Persona -ne 'Maker' }) -Columns @('DisplayName', 'UserPrincipalName', 'AccountType', 'LinkedAccount', 'HighestTrustLevel', 'Persona', 'TenantRoles', 'ProdSysAdminEnvironments', 'FlowsOn', 'AppsOwned', 'ConnectionsOwned', 'RecommendedAction') -MaxRows 150 -CsvName 'PP_People.csv'))
$makers = @($people | Where-Object Persona -eq 'Maker').Count
if ($makers) { $null = $h.Append("<p class=""more"">$makers maker(s) with no admin rights are in PP_People.csv; nothing changes for them.</p>") }
$null = $h.Append('<h3>CLAD provisioning</h3><p class="more">Everyone doing Power Platform admin work from an everyday or guest account, with the CLAD to use (existing, or a proposed name on the clad_&lt;surname&gt;&lt;initial&gt; pattern), what moves to it and what stays on the everyday account.</p>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $cladProv -Columns @('Person', 'EverydayUpn', 'ExistingClad', 'ProposedCladUpn', 'RightsToMove', 'KeepOnEveryday', 'FlowsToCheckFirst', 'Notes') -MaxRows 100 -CsvName 'PP_CladProvisioning.csv'))

$null = $h.Append('<h2 id="pimimpact">What changes, and what breaks, with Power Platform admin in PIM</h2>')
$null = $h.Append('<p class="lede">PIM is the right control for Power Platform Administrator and Dynamics 365 Administrator: both are TL2 roles with tenant-wide reach. It needs care in four places. Admin connectors and admin PowerShell only work while the role is active. System Administrator gained by self-elevation is removed when the activation ends. Microsoft does not support these roles through groups. Flows owned by admins may rely on their standing System Administrator role. Makers, end users, apps and ordinary flows are not affected.</p>')
$null = $h.Append('<div class="cols"><div><h3>Stops working outside an activation</h3><ul class="list"><li><div class="h">Power Platform admin centre and admin APIs</div><div class="d">Environment management, tenant settings, DLP, capacity, support tickets. Sign out and in after activating.</div></li><li><div class="h">Admin connectors and admin PowerShell</div><div class="d">Flows using Power Platform for Admins, and scheduled admin scripts, fail when the owner''s role is not active. CoE Starter Kit included.</div></li><li><div class="h">Self-elevated System Administrator</div><div class="d">Removed when the activation ends; admins re-elevate per environment each session.</div></li><li><div class="h">Group-assigned admins</div><div class="d">Not supported for Power Platform: assign these roles directly (eligible).</div></li></ul></div>')
$null = $h.Append('<div><h3>Not affected</h3><ul class="list"><li><div class="h">Makers and end users</div><div class="d">They hold environment roles and licences, not the Entra admin role.</div></li><li><div class="h">Apps and most flows</div><div class="d">Flows run on their connections, not the owner''s admin role, unless they use admin connectors or rely on System Administrator for data access.</div></li><li><div class="h">DLP, security groups, environment roles</div><div class="d">Enforced by the platform whether or not an admin is active.</div></li></ul></div></div>')
$null = $h.Append('<h3>Impact per admin</h3>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $impact -Columns @('Impact', 'DisplayName', 'AccountType', 'Roles', 'HeldAs', 'ActivationsPerWeek', 'WhatChanges', 'WhatBreaks', 'BeforeTheChange') -MaxRows 100 -CsvName 'PP_PimImpact.csv'))
$null = $h.Append('<h3>PIM settings against the trust-level baseline</h3>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $policyGaps -Columns @('RoleName', 'TrustLevel', 'Result', 'MaxActivationHours', 'ApprovalRequired', 'MfaRequired', 'AuthContextRequired', 'JustificationRequired', 'PermanentEligibleAllowed', 'PermanentActiveAllowed', 'Gaps')))

$null = $h.Append('<h2 id="pim">Where PIM is used, and where it is not</h2><p class="lede">Every role that reaches Power Platform, by whether people hold it just-in-time (eligible in PIM), time-bound or permanently. Dataverse System Administrator is always standing: PIM cannot govern it directly.</p>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($coverage) -Columns @('Role', 'TrustLevel', 'People', 'JustInTime', 'TimeBound', 'Permanent', 'PimStatus', 'ViaGroups')))

$null = $h.Append('<h2 id="risk">Flows and connections at risk</h2><p class="lede">Flows and connections that depend on a person''s admin rights, are owned by a CLAD, or whose owner has left. High means likely to break when admin rights move to PIM or a CLAD; check these with the owner first.</p>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($risk | Where-Object Severity -ne 'Low') -Columns @('Severity', 'Environment', 'FlowName', 'State', 'Owner', 'OwnerAccountType', 'Connectors', 'Reason') -MaxRows 200 -CsvName 'PP_FlowsAtRisk.csv'))
$low = @($risk | Where-Object Severity -eq 'Low').Count; if ($low) { $null = $h.Append("<p class=""more"">$low further low-risk flow(s) in PP_FlowsAtRisk.csv.</p>") }
$null = $h.Append('<h3>Connections</h3>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $connRisk -Columns @('Severity', 'Environment', 'Connector', 'ConnectionName', 'Owner', 'OwnerAccountType', 'Reason') -MaxRows 150 -CsvName 'PP_ConnectionsAtRisk.csv'))

$null = $h.Append('<h2 id="benchmark">NCSC benchmark</h2><p class="lede">Indicative ratings from configuration evidence only, using the same rules as the Entra and Azure audit.</p>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $audit.Caf -Columns @('Outcome', 'Title', 'Rating', 'Good', 'Partial', 'Weak', 'Controls')))
$null = $h.Append('<h3>NCSC secure system administration principles</h3>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $audit.Ssa -Columns @('Principle', 'Title', 'Rating', 'Good', 'Partial', 'Weak', 'Controls')))

$null = $h.Append('<h2 id="envs">Environments</h2>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($envSummary | Sort-Object @{ Expression = { if ($_.IsProd) { 0 } else { 1 } } }, Environment) -Columns @('Environment', 'Type', 'Dataverse', 'SecurityGroup', 'Managed', 'SystemAdminPeople', 'SystemAdminEveryday', 'SystemAdminViaTeams', 'AppUsersSysAdmin', 'AuditEnabled', 'Flows', 'DataverseAccess') -MaxRows 300 -CsvName 'PP_Environments.csv'))

$null = $h.Append('<h2 id="controls">All control checks</h2>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $controls -Columns @('Id', 'Area', 'Control', 'Result', 'Severity', 'CafOutcome', 'NcscPrinciple', 'Evidence')))

$null = $h.Append('<h2 id="method">How to read this report</h2><div class="note">')
$null = $h.Append('<p><strong>Trust levels.</strong> TL1 Strategic Control, TL2 Service Administration, TL3 Operational Administration, TL4 Workforce, as in the Entra and Azure audit. Power Platform Administrator and Dynamics 365 Administrator are TL2; production System Administrator is TL2 because it gives full control of a business system''s data.</p>')
$null = $h.Append('<p><strong>Account types</strong> come from the catalogue''s identity patterns (CLAD prefix and display name, break-glass, generic, other admin). CLAD and everyday accounts are linked by name, by surname and initial, or by the identity map CSV.</p>')
$null = $h.Append('<p><strong>Conditional Access</strong> coverage is evaluated per admin from enabled policies (users, groups and active roles, exclusions, apps, grant controls). Location, platform and device-filter conditions are not evaluated, so treat coverage as indicative. Policies that target directory roles only cover people while their role is active.</p>')
$null = $h.Append('<p><strong>Flows at risk</strong> are estimated from the owner''s rights and the connectors in each flow. A Dataverse action can target another environment, so confirm with the owner before acting.</p>')
$null = $h.Append('<p><strong>Evidence.</strong> Raw\pp-*.csv (as collected) and PP_*.csv (registers) in the run folder; Raw\pp-collection-log.csv lists anything that could not be read.</p></div>')
$null = $h.Append('</main></body></html>')
#endregion

#region write
foreach ($k in $outputs.Keys) { Export-PimData -Data @($outputs[$k]) -CsvPath (Join-Path $RunFolder $k) }
[pscustomobject]$metrics | Export-Csv (Join-Path $RunFolder 'PP_Metrics.csv') -NoTypeInformation -Encoding UTF8
$metrics | ConvertTo-Json -Depth 4 | Out-File (Join-Path $RunFolder 'PP_Metrics.json') -Encoding UTF8
[ordered]@{
    TenantName = $meta.tenantName; TenantShortName = $meta.tenantShortName; TenantId = $meta.tenantId; Run = (Split-Path $RunFolder -Leaf); Generated = (Get-Date).ToString('s')
    Metrics = $metrics; Controls = @($audit.Controls | Select-Object Id, Area, Control, Result, Severity); Caf = @($audit.Caf | Select-Object Outcome, Title, Rating)
} | ConvertTo-Json -Depth 6 | Out-File (Join-Path $RunFolder 'PP_Summary.json') -Encoding UTF8

$sn = Get-SafeFileName -Name ([string]$meta.tenantShortName)
$reportPath = Join-Path $RunFolder "PowerPlatform_Audit_$sn.html"
$h.ToString() | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Power Platform audit report: $reportPath" -ForegroundColor Green

$workbookPath = $null
if (-not $NoWorkbook -and (Get-Module -ListAvailable -Name ImportExcel)) {
    try {
        Import-Module ImportExcel -ErrorAction Stop
        $probe = New-Object -TypeName OfficeOpenXml.ExcelPackage; $probe.Dispose()
        $workbookPath = Join-Path $RunFolder "PowerPlatform_Audit_$sn.xlsx"
        if (Test-Path $workbookPath) { Remove-Item $workbookPath -Force }
        $sheets = [ordered]@{ Controls = $audit.Controls; People = $people; CladProvisioning = $cladProv; PimImpact = $impact; TrustLevels = $model; AccessPaths = $paths; PimCoverage = $coverage; PolicyGaps = $policyGaps; FlowsAtRisk = $risk; ConnectionsAtRisk = $connRisk; Migration = $migration; Environments = $envSummary; ConditionalAccess = $caRows; Dlp = $dlp; NcscCaf = $audit.Caf }
        foreach ($k in $sheets.Keys) {
            $rows = @($sheets[$k] | Where-Object { $null -ne $_ })
            if ($rows.Count -eq 0) { $rows = @([pscustomobject]@{ Note = 'None found' }) }
            $rows | Export-Excel -Path $workbookPath -WorksheetName $k -TableName ('t' + $k) -AutoSize -FreezeTopRow -AutoFilter -Append
        }
        Write-Host "Workbook: $workbookPath" -ForegroundColor Green
    }
    catch { Write-Host "Excel workbook not produced: $($_.Exception.Message). Open the PP_*.csv files instead." -ForegroundColor Yellow; $workbookPath = $null }
}
#endregion

[pscustomobject]@{ ReportPath = $reportPath; WorkbookPath = $workbookPath; RunFolder = $RunFolder; Metrics = $metrics }
