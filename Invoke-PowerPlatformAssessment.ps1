<#
.SYNOPSIS
Offline assessment of a Power Platform review run folder: who does what, flows at risk, findings, HTML report.

.DESCRIPTION
Reads the CSVs written by Get-PowerPlatformReview.ps1 and writes into the same folder:
- pp-people-register.csv   one row per person: tenant roles, environment roles, flows and apps owned,
                           licence, persona and the recommended action (the "who does what" view)
- pp-flows-at-risk.csv     flows likely to break, or worth checking, when admin rights move to CLADs
- pp-findings.csv          numbered findings (PP-01 ...) with severity, count and recommendation
- pp-summary.json          headline metrics (used by the partnership roll-up)
- PowerPlatform_Review_<tenant>_<date>.html

Runs without a connection, so it can be re-run after changing the rules.

.PARAMETER RunFolder
A PowerPlatform-<timestamp> folder from Get-PowerPlatformReview.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RunFolder
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules\PimReview.Common.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot 'New-PimPhase2Report.ps1')

#region load
function Import-PpCsv {
    param([string]$Name)
    $p = Join-Path $RunFolder $Name
    if (-not (Test-Path $p)) { return @() }
    if ((Get-Item $p).Length -lt 3) { return @() }
    return @(Import-Csv -Path $p)
}
function ConvertTo-Bool { param($v) return ([string]$v -eq 'True') }
function Get-Col { param($Row, [string]$Name) $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value } return $null }

$meta = Get-Content (Join-Path $RunFolder 'pp-run.json') -Raw | ConvertFrom-Json
$tenantRoles = Import-PpCsv 'pp-tenant-roles.csv'
$envs = Import-PpCsv 'pp-environments.csv'
$envRoles = Import-PpCsv 'pp-environment-roles.csv'
$flows = Import-PpCsv 'pp-flows.csv'
$apps = Import-PpCsv 'pp-apps.csv'
$users = Import-PpCsv 'pp-users.csv'
$log = Import-PpCsv 'pp-collection-log.csv'
$dlp = Import-PpCsv 'pp-dlp-policies.csv'

$catPath = Join-Path $PSScriptRoot 'Config\pim-phase2.catalogue.local.json'
if (-not (Test-Path $catPath)) { $catPath = Join-Path $PSScriptRoot 'Config\pim-phase2.catalogue.json' }
$brand = $null
if (Test-Path $catPath) { try { $brand = (Get-Content $catPath -Raw | ConvertFrom-Json).Branding } catch { } }
#endregion

#region lookups
$AdminRoleNames = @('Power Platform Administrator', 'Dynamics 365 Administrator')
$EnvAdminRoleNames = @('System Administrator', 'EnvironmentAdmin', 'Environment Admin')
$userById = @{}
foreach ($u in $users) { $userById[([string]$u.UserId).ToLowerInvariant()] = $u }
$envById = @{}
foreach ($e in $envs) { $envById[$e.EnvironmentId] = $e }
function Test-ProdEnv { param($EnvRow) return ((ConvertTo-Bool $EnvRow.IsDefault) -or ([string]$EnvRow.Type -eq 'Production') -or ([string]$EnvRow.EnvironmentType -eq 'Production')) }

$humanTenantRoles = @($tenantRoles | Where-Object { $_.PrincipalType -eq 'User' -and $_.UserId })
$humanEnvRoles = @($envRoles | Where-Object { $_.PrincipalType -eq 'User' -and $_.UserId })

# Index everything by person
$ids = New-Object System.Collections.Generic.HashSet[string]
foreach ($r in $humanTenantRoles) { $null = $ids.Add(([string]$r.UserId).ToLowerInvariant()) }
foreach ($r in $humanEnvRoles) { $null = $ids.Add(([string]$r.UserId).ToLowerInvariant()) }
foreach ($f in $flows) { if ($f.OwnerId) { $null = $ids.Add(([string]$f.OwnerId).ToLowerInvariant()) } }
foreach ($a in $apps) { if ($a.OwnerId) { $null = $ids.Add(([string]$a.OwnerId).ToLowerInvariant()) } }

$byPerson = @{}
foreach ($id in $ids) { $byPerson[$id] = @{ T = New-Object System.Collections.ArrayList; E = New-Object System.Collections.ArrayList; F = New-Object System.Collections.ArrayList; A = New-Object System.Collections.ArrayList } }
foreach ($r in $humanTenantRoles) { $null = $byPerson[([string]$r.UserId).ToLowerInvariant()].T.Add($r) }
foreach ($r in $humanEnvRoles) { $null = $byPerson[([string]$r.UserId).ToLowerInvariant()].E.Add($r) }
foreach ($f in $flows) { if ($f.OwnerId) { $null = $byPerson[([string]$f.OwnerId).ToLowerInvariant()].F.Add($f) } }
foreach ($a in $apps) { if ($a.OwnerId) { $null = $byPerson[([string]$a.OwnerId).ToLowerInvariant()].A.Add($a) } }
#endregion

#region people register
function Format-RoleState {
    param($Rows)
    $parts = foreach ($g in ($Rows | Group-Object RoleName)) {
        $states = @($g.Group | ForEach-Object {
            $s = if ($_.State -like 'Eligible*') { 'eligible' } elseif ((ConvertTo-Bool $_.Permanent) -and $_.State -eq 'Active') { 'permanent' } elseif ($_.State -like 'Active (activated*') { 'activated now' } else { 'time-bound active' }
            if ($_.AssignedVia -eq 'Group') { $s += " via $($_.GroupName)" }
            $s
        } | Sort-Object -Unique)
        "$($g.Name) ($($states -join ', '))"
    }
    return (@($parts) -join '; ')
}

$people = New-Object System.Collections.ArrayList
foreach ($id in $byPerson.Keys) {
    $d = $byPerson[$id]
    $u = $userById[$id]
    $upn = if ($u) { $u.UserPrincipalName } else { $null }
    $name = if ($u) { $u.DisplayName } else { $null }
    if (-not $upn) { foreach ($src in @($d.T + $d.E)) { if ($src.UserPrincipalName) { $upn = $src.UserPrincipalName; $name = $src.DisplayName; break } } }
    if (-not $upn) { foreach ($src in $d.F) { if ($src.OwnerUserPrincipalName) { $upn = $src.OwnerUserPrincipalName; $name = $src.OwnerDisplayName; break } } }
    $isClad = if ($u) { ConvertTo-Bool $u.IsClad } else { $false }
    $enabled = if ($u -and $u.AccountEnabled -ne '') { ConvertTo-Bool $u.AccountEnabled } else { $null }

    $ppAdmin = @($d.T | Where-Object { $_.RoleName -in $AdminRoleNames })
    $ga = @($d.T | Where-Object { $_.RoleName -eq 'Global Administrator' })
    $otherTenant = @($d.T | Where-Object { $_.RoleName -notin $AdminRoleNames -and $_.RoleName -ne 'Global Administrator' })
    $permanentAdmin = @($ppAdmin + $ga | Where-Object { $_.State -eq 'Active' -and (ConvertTo-Bool $_.Permanent) })

    $envAdmin = @($d.E | Where-Object { $_.RoleName -in $EnvAdminRoleNames })
    $envAdminProd = @($envAdmin | Where-Object { Test-ProdEnv $_ })
    $envAdminOther = @($envAdmin | Where-Object { -not (Test-ProdEnv $_) })
    $customizer = @($d.E | Where-Object { $_.RoleName -eq 'System Customizer' })
    $flowsOn = @($d.F | Where-Object { $_.State -eq 'On' })
    $ownsSomething = ($d.F.Count + $d.A.Count) -gt 0
    $premium = if ($u) { ConvertTo-Bool $u.PremiumPowerPlatformLicence } else { $false }

    $persona = 'Other role holder'
    $action = 'Review.'
    if ($enabled -eq $false) {
        $persona = 'Disabled account'
        $action = 'Remove its roles; reassign its flows and apps to an active owner.'
    }
    elseif ($isClad) {
        $persona = 'CLAD administrator'
        $action = 'Keep for admin only. Make admin roles eligible (not permanent).'
        if ($ownsSomething -or $premium) { $action = 'Move flows and apps it owns to the everyday or a service account and remove any Power Platform licence: a CLAD should administer, not build.' }
    }
    elseif ($ppAdmin.Count -gt 0) {
        $persona = if ($ownsSomething) { 'Tenant admin and maker on everyday account' } else { 'Tenant admin on everyday account' }
        $action = "Create a CLAD and make it eligible for $((@($ppAdmin | ForEach-Object RoleName | Sort-Object -Unique)) -join ' and '). Remove the role from this account once the CLAD is proven."
        if ($flowsOn.Count -gt 0) { $action += " Check its $($flowsOn.Count) active flow(s) first (see flows at risk)." }
    }
    elseif ($ga.Count -gt 0) {
        $persona = 'Global Administrator (Power Platform reach)'
        $action = 'Covered by the Entra HLD. Note that this role can self-elevate into every Dataverse environment.'
    }
    elseif ($envAdminProd.Count -gt 0) {
        $persona = if ($ownsSomething) { 'Production environment admin and maker' } else { 'Production environment admin' }
        $action = 'Replace System Administrator on this account with a scoped role (for example System Customizer or a custom role). Admin work moves to a CLAD through self-elevation.'
        if ($flowsOn.Count -gt 0) { $action += " Check its $($flowsOn.Count) active flow(s) before removing the role." }
    }
    elseif ($envAdminOther.Count -gt 0) {
        $persona = 'Dev / sandbox environment admin'
        $action = 'Acceptable on the everyday account for non-production environments. Record it.'
    }
    elseif ($ownsSomething) {
        $persona = 'Maker'
        $action = 'No change.'
    }

    $null = $people.Add([pscustomobject]@{
        DisplayName = $name
        UserPrincipalName = $upn
        AccountType = if ($isClad) { 'CLAD' } else { 'Everyday' }
        Enabled = $enabled
        Persona = $persona
        TenantRoles = Format-RoleState @($ppAdmin + $ga + $otherTenant)
        PermanentTenantAdmin = ($permanentAdmin.Count -gt 0)
        SysAdminProductionEnvironments = (@($envAdminProd | ForEach-Object Environment | Sort-Object -Unique) -join '; ')
        SysAdminOtherEnvironments = (@($envAdminOther | ForEach-Object Environment | Sort-Object -Unique) -join '; ')
        SysAdminViaTeam = (@($envAdmin | Where-Object { $_.AssignedVia -ne 'Direct' }).Count -gt 0)
        CustomizerEnvironments = (@($customizer | ForEach-Object Environment | Sort-Object -Unique) -join '; ')
        FlowsOwned = $d.F.Count
        FlowsOn = $flowsOn.Count
        FlowsUsingDataverse = @($d.F | Where-Object { ConvertTo-Bool $_.UsesDataverse }).Count
        FlowsUsingAdminConnectors = @($d.F | Where-Object { ConvertTo-Bool $_.UsesAdminConnector }).Count
        AppsOwned = $d.A.Count
        PremiumLicence = $premium
        Licences = if ($u) { $u.Licences } else { $null }
        LastSignIn = if ($u) { $u.LastSignIn } else { $null }
        RecommendedAction = $action
        UserId = $id
    })
}
$personaOrder = @{ 'Disabled account' = 0; 'Tenant admin and maker on everyday account' = 1; 'Tenant admin on everyday account' = 2; 'Production environment admin and maker' = 3; 'Production environment admin' = 4; 'Global Administrator (Power Platform reach)' = 5; 'CLAD administrator' = 6; 'Dev / sandbox environment admin' = 7; 'Maker' = 8; 'Other role holder' = 9 }
$people = @($people | Sort-Object @{ Expression = { $personaOrder[$_.Persona] } }, DisplayName)
$personById = @{}
foreach ($p in $people) { $personById[$p.UserId] = $p }
#endregion

#region flows at risk
$risk = New-Object System.Collections.ArrayList
foreach ($f in $flows) {
    if ($f.OwnerType -ne 'User' -or -not $f.OwnerId) { continue }
    $oid = ([string]$f.OwnerId).ToLowerInvariant()
    $d = $byPerson[$oid]
    $p = $personById[$oid]
    $u = $userById[$oid]
    $on = ($f.State -eq 'On')
    $tenantAdmin = @($d.T | Where-Object { $_.RoleName -in $AdminRoleNames -or $_.RoleName -eq 'Global Administrator' }).Count -gt 0
    $sysAdminHere = @($d.E | Where-Object { $_.EnvironmentId -eq $f.EnvironmentId -and $_.RoleName -in $EnvAdminRoleNames }).Count -gt 0
    $ownerGone = (ConvertTo-Bool $f.OwnerDisabled) -or ($u -and $u.AccountEnabled -eq 'False') -or ($u -and $u.Found -eq 'False')
    $usesDv = ConvertTo-Bool $f.UsesDataverse
    $usesAdm = ConvertTo-Bool $f.UsesAdminConnector
    $known = ConvertTo-Bool $f.ConnectorsKnown

    $level = $null; $why = $null
    if ($ownerGone -and $on) { $level = 'High'; $why = 'Owner account is disabled or missing; the flow runs on its connections until they fail.' }
    elseif ($usesAdm -and ($tenantAdmin -or $sysAdminHere)) { $level = if ($on) { 'High' } else { 'Low' }; $why = 'Uses an admin connector; fails when the owner no longer holds the admin role.' }
    elseif ($usesDv -and $sysAdminHere) { $level = if ($on) { 'High' } else { 'Low' }; $why = 'Uses Dataverse and the owner is System Administrator here; may lose access to records when that role is removed.' }
    elseif (($tenantAdmin -or $sysAdminHere) -and -not $known) { $level = if ($on) { 'Medium' } else { 'Low' }; $why = 'Owner holds admin rights and the connectors could not be read; check manually.' }
    elseif ($tenantAdmin -or $sysAdminHere) { $level = 'Low'; $why = 'Owner holds admin rights but the flow uses no Dataverse or admin connectors; unlikely to break.' }
    if (-not $level) { continue }

    $null = $risk.Add([pscustomobject]@{
        Severity = $level
        Environment = $f.Environment
        EnvironmentType = $f.EnvironmentType
        FlowName = $f.FlowName
        State = $f.State
        Owner = if ($p) { $p.DisplayName } else { $f.OwnerDisplayName }
        OwnerUserPrincipalName = if ($p) { $p.UserPrincipalName } else { $f.OwnerUserPrincipalName }
        OwnerPersona = if ($p) { $p.Persona } else { $null }
        OwnerIsTenantAdmin = $tenantAdmin
        OwnerIsSysAdminHere = $sysAdminHere
        Connectors = $f.Connectors
        Reason = $why
        FlowId = $f.FlowId
    })
}
$sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
$risk = @($risk | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Environment, FlowName)
#endregion

#region findings
$findings = New-Object System.Collections.ArrayList
function Add-Finding {
    param([string]$Id, [string]$Title, [string]$Severity, [int]$Count, [string]$Detail, [string]$Recommendation, [string[]]$Affected)
    $status = if ($Count -eq 0) { 'Good' } else { $Severity }
    $aff = @($Affected | Where-Object { $_ } | Sort-Object -Unique)
    $null = $findings.Add([pscustomobject]@{
        Id = $Id; Finding = $Title; Severity = $Severity; Status = $status; Count = $Count
        Detail = $Detail; Recommendation = $Recommendation
        Affected = (@($aff | Select-Object -First 25) -join '; ') + $(if ($aff.Count -gt 25) { "; and $($aff.Count - 25) more" } else { '' })
    })
}

$everydayAdmins = @($people | Where-Object { $_.AccountType -eq 'Everyday' -and $_.Persona -like 'Tenant admin*' })
Add-Finding 'PP-01' 'Power Platform or Dynamics 365 Administrator held by everyday accounts' 'High' $everydayAdmins.Count `
    'These accounts are also used for email, Teams and building apps and flows, so a phished session carries tenant-wide Power Platform admin rights.' `
    'Give each person a CLAD made eligible for the role; remove the role from the everyday account once flows are checked.' `
    @($everydayAdmins | ForEach-Object UserPrincipalName)

$permAdmin = @($humanTenantRoles | Where-Object { $_.RoleName -in $AdminRoleNames -and $_.State -eq 'Active' -and (ConvertTo-Bool $_.Permanent) })
Add-Finding 'PP-02' 'Standing (permanent) Power Platform or Dynamics 365 Administrator assignments' 'High' @($permAdmin | ForEach-Object UserId | Sort-Object -Unique).Count `
    'Permanent active assignments bypass PIM: no activation, approval, justification or time limit.' `
    'Convert to eligible assignments with activation in PIM, matching the TL2 settings in the Entra HLD.' `
    @($permAdmin | ForEach-Object { "$($_.UserPrincipalName) ($($_.RoleName))" })

$grpAdmin = @($humanTenantRoles | Where-Object { $_.RoleName -in $AdminRoleNames -and $_.AssignedVia -eq 'Group' })
Add-Finding 'PP-03' 'Power Platform or Dynamics 365 Administrator assigned through groups' 'Medium' @($grpAdmin | ForEach-Object UserId | Sort-Object -Unique).Count `
    'Microsoft documents self-elevation to System Administrator as supported only for roles assigned directly to the user. Group-assigned admins may be unable to self-elevate after PIM activation.' `
    'Test self-elevation for a group-assigned eligible CLAD. If it fails, make these roles direct-eligible and register the exception to the function-group model.' `
    @($grpAdmin | ForEach-Object { "$($_.UserPrincipalName) via $($_.GroupName)" })

$gaPeople = @($humanTenantRoles | Where-Object { $_.RoleName -eq 'Global Administrator' } | ForEach-Object UserPrincipalName | Sort-Object -Unique)
Add-Finding 'PP-04' 'Global Administrators can self-elevate into every Dataverse environment' 'Low' $gaPeople.Count `
    'Global Administrator is a pathway into all Power Platform data, like the Azure elevate-access pathway. Elevation is logged to Microsoft Purview.' `
    'Treat as part of the GA residual risk in the Entra and Azure HLDs; alert on Power Platform self-elevation in the Purview audit log.' `
    $gaPeople

$sysProd = @($humanEnvRoles | Where-Object { $_.RoleName -in $EnvAdminRoleNames -and (Test-ProdEnv $_) })
$sysProdEveryday = @($sysProd | Where-Object { $p = $personById[([string]$_.UserId).ToLowerInvariant()]; $p -and $p.AccountType -eq 'Everyday' -and $p.Enabled -ne $false })
Add-Finding 'PP-05' 'Everyday accounts with System Administrator in production or default environments' 'High' @($sysProdEveryday | ForEach-Object UserId | Sort-Object -Unique).Count `
    'Standing System Administrator in Dataverse is assigned inside each environment, so PIM never sees it. It gives full control of the environment''s data, security roles and solutions.' `
    'Replace with scoped roles on the everyday account. Production admin work is done from a CLAD through PIM activation and self-elevation.' `
    @($sysProdEveryday | ForEach-Object { "$($_.UserPrincipalName) ($($_.Environment))" })

$sysTeam = @($humanEnvRoles | Where-Object { $_.RoleName -in $EnvAdminRoleNames -and $_.AssignedVia -ne 'Direct' })
Add-Finding 'PP-06' 'System Administrator granted through teams or groups' 'Medium' @($sysTeam | ForEach-Object UserId | Sort-Object -Unique).Count `
    'Anyone added to the team or group becomes System Administrator, often without the Power Platform team knowing.' `
    'Review membership and owners of these teams and groups. Put PIM for Groups on any group that must keep the role, so membership is just-in-time.' `
    @($sysTeam | ForEach-Object { "$($_.UserPrincipalName) via $($_.TeamName) ($($_.Environment))" })

$riskHigh = @($risk | Where-Object Severity -eq 'High')
Add-Finding 'PP-07' 'Active flows likely to break when admin rights are removed' 'High' $riskHigh.Count `
    'These flows use admin connectors or Dataverse with an owner who is System Administrator, or their owner is disabled.' `
    'Before removing roles: give the owner a scoped role that covers the flow, or move the flow to a service account or service principal inside a solution.' `
    @($riskHigh | ForEach-Object { "$($_.FlowName) ($($_.Environment), owner $($_.OwnerUserPrincipalName))" })

$admFlows = @($flows | Where-Object { ConvertTo-Bool $_.UsesAdminConnector })
Add-Finding 'PP-08' 'Flows using Power Platform admin connectors' 'Medium' $admFlows.Count `
    'Admin connectors act with the owner''s admin rights. These are usually governance flows (for example the CoE Starter Kit).' `
    'Move to a dedicated service account registered as a PIM exception, with monitoring; never a person''s account.' `
    @($admFlows | ForEach-Object { "$($_.FlowName) ($($_.Environment), owner $($_.OwnerUserPrincipalName))" })

$orphan = @($risk | Where-Object { $_.Reason -like 'Owner account is disabled*' })
Add-Finding 'PP-09' 'Active flows owned by disabled or missing accounts' 'Medium' $orphan.Count `
    'They keep running on stored connections until a token expires, then fail without warning.' `
    'Reassign an owner or turn them off.' `
    @($orphan | ForEach-Object { "$($_.FlowName) ($($_.Environment))" })

$cladBuild = @($people | Where-Object { $_.AccountType -eq 'CLAD' -and (($_.FlowsOwned + $_.AppsOwned) -gt 0 -or $_.PremiumLicence) })
Add-Finding 'PP-10' 'CLAD accounts that own flows or apps, or hold Power Platform licences' 'Medium' $cladBuild.Count `
    'A flow or connection created by a CLAD is a privileged credential that keeps working outside the PIM window.' `
    'CLADs administer only: move what they own to the everyday or a service account and remove the licence.' `
    @($cladBuild | ForEach-Object UserPrincipalName)

$prodNoSg = @($envs | Where-Object { (ConvertTo-Bool $_.HasDataverse) -and $_.Type -eq 'Production' -and -not (ConvertTo-Bool $_.IsDefault) -and -not $_.SecurityGroupId })
Add-Finding 'PP-11' 'Production environments with no security group' 'Medium' $prodNoSg.Count `
    'Any licensed user in the tenant can be added to the environment. Dynamics 365 Administrators are only limited by security groups.' `
    'Assign an Entra security group to each production environment.' `
    @($prodNoSg | ForEach-Object DisplayName)

$appSys = @($envRoles | Where-Object { $_.PrincipalType -eq 'Application user' -and $_.RoleName -eq 'System Administrator' })
Add-Finding 'PP-12' 'Application users (service principals) with System Administrator' 'Low' $appSys.Count `
    'Non-human identities with full control of an environment. Often needed for integrations and pipelines, but should be known and owned.' `
    'Inventory owners and credentials in the workload identity review; scope down where possible.' `
    @($appSys | ForEach-Object { "$($_.DisplayName) ($($_.Environment))" })

$disabledRoles = @($people | Where-Object { $_.Enabled -eq $false -and ($_.TenantRoles -or $_.SysAdminProductionEnvironments -or $_.SysAdminOtherEnvironments) })
Add-Finding 'PP-13' 'Disabled accounts still holding admin roles' 'Medium' $disabledRoles.Count `
    'Leftover assignments that would return immediately if the account were re-enabled.' `
    'Remove the roles.' `
    @($disabledRoles | ForEach-Object UserPrincipalName)

$gap = @($envs | Where-Object { $_.RolesCollection -ne 'OK' -and $_.RolesCollection -ne 'Skipped' })
Add-Finding 'PP-14' 'Environments whose role holders could not be read' 'Low' $gap.Count `
    'Coverage gap in this review, usually because the run account had no access to that environment''s Dataverse.' `
    'Re-run for these environments with an account holding read access (for example after self-elevation), or accept the gap in the report.' `
    @($gap | ForEach-Object { "$($_.DisplayName) ($($_.RolesCollection))" })
#endregion

#region metrics and output
$prodEnvs = @($envs | Where-Object { (ConvertTo-Bool $_.IsDefault) -or $_.Type -eq 'Production' })
$metrics = [ordered]@{
    Environments = $envs.Count
    EnvironmentsWithDataverse = @($envs | Where-Object { ConvertTo-Bool $_.HasDataverse }).Count
    ProductionOrDefault = $prodEnvs.Count
    EnvironmentsNotRead = $gap.Count
    TenantAdminsEveryday = $everydayAdmins.Count
    TenantAdminsClad = @($people | Where-Object { $_.AccountType -eq 'CLAD' -and $_.TenantRoles -match 'Power Platform Administrator|Dynamics 365 Administrator' }).Count
    PermanentTenantAdmins = @($permAdmin | ForEach-Object UserId | Sort-Object -Unique).Count
    GlobalAdmins = $gaPeople.Count
    ProdSysAdminsEveryday = @($sysProdEveryday | ForEach-Object UserId | Sort-Object -Unique).Count
    PeopleNeedingClad = @($people | Where-Object { $_.Persona -like 'Tenant admin*' -or $_.Persona -like 'Production environment admin*' }).Count
    Flows = $flows.Count
    FlowsOn = @($flows | Where-Object State -eq 'On').Count
    FlowsAtRiskHigh = $riskHigh.Count
    FlowsAtRiskMedium = @($risk | Where-Object Severity -eq 'Medium').Count
    Apps = $apps.Count
    Makers = @($people | Where-Object { $_.FlowsOwned + $_.AppsOwned -gt 0 }).Count
    DlpPolicies = $dlp.Count
}

$people | Export-Csv (Join-Path $RunFolder 'pp-people-register.csv') -NoTypeInformation -Encoding UTF8
if ($risk.Count) { $risk | Export-Csv (Join-Path $RunFolder 'pp-flows-at-risk.csv') -NoTypeInformation -Encoding UTF8 } else { Set-Content (Join-Path $RunFolder 'pp-flows-at-risk.csv') '' -Encoding UTF8 }
$findings | Export-Csv (Join-Path $RunFolder 'pp-findings.csv') -NoTypeInformation -Encoding UTF8
$summary = [ordered]@{
    TenantName = $meta.tenantName; TenantShortName = $meta.tenantShortName; TenantId = $meta.tenantId; Run = (Split-Path $RunFolder -Leaf)
    Generated = (Get-Date).ToString('s'); Metrics = $metrics
    Findings = @($findings | Select-Object Id, Finding, Severity, Status, Count)
    PersonaCounts = @($people | Group-Object Persona | ForEach-Object { [ordered]@{ Persona = $_.Name; Count = $_.Count } })
}
$summary | ConvertTo-Json -Depth 6 | Out-File (Join-Path $RunFolder 'pp-summary.json') -Encoding UTF8
#endregion

#region html
$enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
$programme = if ($brand -and $brand.Programme) { $brand.Programme } else { 'PIM Phase 2' }
$preparedBy = if ($brand -and $brand.PreparedBy) { $brand.PreparedBy } else { 'PIM review' }
$classification = if ($brand -and $brand.Classification) { $brand.Classification } else { 'Confidential' }
$css = @'
:root{--ink:#1b2430;--muted:#5d6878;--line:#e1e6ec;--soft:#f5f7fa;--accent:#1f4e78;--good:#1e7b45;--goodbg:#e8f5ee;--part:#a15c00;--partbg:#fff4e0;--weak:#b42318;--weakbg:#fdecea;--na:#6b7785;--nabg:#eef1f4}
*{box-sizing:border-box}body{font-family:"Segoe UI",system-ui,-apple-system,Arial,sans-serif;margin:0;color:var(--ink);line-height:1.55;font-size:15px}
main{max-width:1180px;margin:0 auto;padding:28px 16px 80px}h1{font-size:30px;line-height:1.2;margin:0 0 6px}h2{font-size:22px;margin:44px 0 6px;color:var(--accent)}h3{font-size:16px;margin:22px 0 8px}
.cover{border-bottom:3px solid var(--accent);padding-bottom:18px;margin-bottom:8px}.kicker{text-transform:uppercase;letter-spacing:.08em;font-size:12px;color:var(--muted);font-weight:600}.meta{color:var(--muted);font-size:13px;margin-top:6px}
.lede{color:var(--muted);max-width:860px;margin:4px 0 16px}.verdict{font-size:18px;margin:18px 0;max-width:900px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin:16px 0}.tile{border:1px solid var(--line);border-radius:8px;padding:12px 14px}.tile .n{font-size:28px;font-weight:700;line-height:1.1}.tile .l{font-size:13px;color:var(--muted);margin-top:4px}.tile.weak .n{color:var(--weak)}.tile.part .n{color:var(--part)}.tile.good .n{color:var(--good)}
.card{border:1px solid var(--line);border-left:5px solid var(--weak);border-radius:8px;padding:14px 16px;margin:12px 0;page-break-inside:avoid}.card.med{border-left-color:#d27a00}.card.low{border-left-color:#55606e}.card .title{font-weight:700;font-size:16px}.card dl{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;margin:8px 0 0;font-size:14px}.card dt{color:var(--muted)}.card dd{margin:0}
.b{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}.b.good{background:var(--goodbg);color:var(--good)}.b.high{background:var(--weak);color:#fff}.b.med{background:#d27a00;color:#fff}.b.low{background:#55606e;color:#fff}.b.na{background:var(--nabg);color:var(--na)}
.tw{overflow-x:auto;margin:8px 0}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}th{background:var(--soft);font-weight:600;position:sticky;top:0}
.none{color:var(--good);font-style:italic}.more{color:var(--muted);font-size:12px;font-style:italic}.note{background:var(--soft);border-radius:8px;padding:12px 14px;font-size:14px}.toc{columns:2;font-size:14px}
.passes{font-size:14px;color:var(--muted)}details{border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:10px 0}details>summary{cursor:pointer;font-weight:600}
@media (max-width:760px){.toc{columns:1}.card dl{grid-template-columns:1fr}h1{font-size:24px}}
'@
$label = $meta.tenantShortName
$h = New-Object System.Text.StringBuilder
$null = $h.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>Power Platform Admin Review - $(& $enc $meta.tenantName)</title><style>$css</style></head><body><main>")
$null = $h.Append("<div class=""cover""><div class=""kicker"">$(& $enc $programme)</div><h1>Power Platform Admin Review: $(& $enc $meta.tenantName)</h1>")
$null = $h.Append('<div class="meta">Who holds Power Platform admin rights, who builds, and what could break when admin rights move to CLAD accounts under PIM.</div>')
$null = $h.Append("<div class=""meta"">Run $(& $enc (Split-Path $RunFolder -Leaf)) &middot; collected by $(& $enc $meta.runAccount) &middot; Prepared by $(& $enc $preparedBy) &middot; $(Get-Date -Format 'd MMMM yyyy') &middot; $(& $enc $classification)</div></div>")

$sections = @(@('glance', 'At a glance'), @('findings', 'Findings'), @('people', 'Who does what'), @('risk', 'Flows at risk'), @('envs', 'Environments'), @('method', 'How to read this report'))
$null = $h.Append('<ol class="toc">'); foreach ($s in $sections) { $null = $h.Append("<li><a href=""#$($s[0])"">$($s[1])</a></li>") }; $null = $h.Append('</ol>')

$open = @($findings | Where-Object { $_.Status -ne 'Good' })
$highOpen = @($open | Where-Object Severity -eq 'High')
$null = $h.Append('<h2 id="glance">At a glance</h2>')
$verdict = "$($metrics.PeopleNeedingClad) people do Power Platform admin work from everyday accounts and need a CLAD. $($metrics.FlowsAtRiskHigh) active flows are likely to break if their owners' admin rights are removed without preparation."
if ($highOpen.Count -eq 0) { $verdict += ' No high-severity findings are open.' } else { $verdict += " $($highOpen.Count) of $($findings.Count) checks are high-severity findings." }
$null = $h.Append("<p class=""verdict"">$(& $enc $verdict)</p>")
$tile = { param($n, $l, $cls) "<div class=""tile $cls""><div class=""n"">$n</div><div class=""l"">$(& $enc $l)</div></div>" }
$null = $h.Append('<div class="tiles">')
$null = $h.Append((& $tile $metrics.Environments 'Environments' ''))
$null = $h.Append((& $tile $metrics.ProductionOrDefault 'Production or default' ''))
$null = $h.Append((& $tile $metrics.TenantAdminsEveryday 'Tenant admins on everyday accounts' $(if ($metrics.TenantAdminsEveryday) { 'weak' } else { 'good' })))
$null = $h.Append((& $tile $metrics.PermanentTenantAdmins 'Permanent tenant admins' $(if ($metrics.PermanentTenantAdmins) { 'weak' } else { 'good' })))
$null = $h.Append((& $tile $metrics.ProdSysAdminsEveryday 'Production System Admins (everyday)' $(if ($metrics.ProdSysAdminsEveryday) { 'weak' } else { 'good' })))
$null = $h.Append((& $tile $metrics.GlobalAdmins 'Global Admins (can self-elevate)' 'part'))
$null = $h.Append((& $tile $metrics.FlowsOn 'Active flows' ''))
$null = $h.Append((& $tile $metrics.FlowsAtRiskHigh 'Flows likely to break' $(if ($metrics.FlowsAtRiskHigh) { 'weak' } else { 'good' })))
$null = $h.Append((& $tile $metrics.Makers 'People who build' ''))
$null = $h.Append('</div>')
if ($metrics.EnvironmentsNotRead -gt 0) { $null = $h.Append("<p class=""note"">$($metrics.EnvironmentsNotRead) environment(s) could not be read in full, so role holders and flows there are missing (finding PP-14).</p>") }

$null = $h.Append('<h3>People by persona</h3>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($people | Group-Object Persona | Sort-Object @{ Expression = { $personaOrder[$_.Name] } } | ForEach-Object { [pscustomobject]@{ Persona = $_.Name; People = $_.Count } }) -Columns @('Persona', 'People')))

$null = $h.Append('<h2 id="findings">Findings</h2><p class="lede">Open findings first. Each lists who or what is affected; the full lists are in the CSV files.</p>')
foreach ($f in @($findings | Sort-Object @{ Expression = { if ($_.Status -eq 'Good') { 9 } else { $sevOrder[$_.Severity] } } }, Id)) {
    if ($f.Status -eq 'Good') { continue }
    $cls = switch ($f.Severity) { 'High' { '' } 'Medium' { 'med' } default { 'low' } }
    $bcls = switch ($f.Severity) { 'High' { 'high' } 'Medium' { 'med' } default { 'low' } }
    $null = $h.Append("<div class=""card $cls""><div><span class=""b $bcls"">$($f.Severity)</span> <span class=""title"">$($f.Id) $(& $enc $f.Finding)</span> ($($f.Count))</div><dl><dt>Why it matters</dt><dd>$(& $enc $f.Detail)</dd><dt>Recommendation</dt><dd>$(& $enc $f.Recommendation)</dd><dt>Affected</dt><dd>$(& $enc $f.Affected)</dd></dl></div>")
}
$passed = @($findings | Where-Object Status -eq 'Good')
if ($passed.Count) { $null = $h.Append("<p class=""passes""><span class=""b good"">Good</span> No issues found for: $(& $enc ((@($passed | ForEach-Object { "$($_.Id) $($_.Finding)" })) -join '; ')).</p>") }

$null = $h.Append('<h2 id="people">Who does what</h2><p class="lede">One row per person found with a Power Platform role or owning flows or apps. Makers with no admin rights are in pp-people-register.csv.</p>')
$adminPeople = @($people | Where-Object { $_.Persona -ne 'Maker' })
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $adminPeople -Columns @('DisplayName', 'UserPrincipalName', 'AccountType', 'Persona', 'TenantRoles', 'SysAdminProductionEnvironments', 'FlowsOn', 'AppsOwned', 'PremiumLicence', 'RecommendedAction') -MaxRows 150 -CsvName 'pp-people-register.csv'))

$null = $h.Append('<h2 id="risk">Flows at risk</h2><p class="lede">Flows whose owner holds admin rights or is disabled. High means likely to break when the owner''s admin role is removed; check these with the owner first.</p>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($risk | Where-Object { $_.Severity -ne 'Low' }) -Columns @('Severity', 'Environment', 'FlowName', 'State', 'Owner', 'OwnerPersona', 'Connectors', 'Reason') -MaxRows 200 -CsvName 'pp-flows-at-risk.csv'))
$low = @($risk | Where-Object Severity -eq 'Low').Count
if ($low) { $null = $h.Append("<p class=""more"">$low further low-risk flow(s) in pp-flows-at-risk.csv.</p>") }

$null = $h.Append('<h2 id="envs">Environments</h2>')
$envView = @($envs | ForEach-Object {
    $eid = $_.EnvironmentId
    [pscustomobject]@{
        DisplayName = $_.DisplayName; Type = $_.Type; Default = (ConvertTo-Bool $_.IsDefault); Dataverse = (ConvertTo-Bool $_.HasDataverse)
        SecurityGroup = $_.SecurityGroupName; Managed = (ConvertTo-Bool $_.Managed)
        SystemAdmins = @($envRoles | Where-Object { $_.EnvironmentId -eq $eid -and $_.RoleName -in $EnvAdminRoleNames -and $_.PrincipalType -eq 'User' } | ForEach-Object UserId | Sort-Object -Unique).Count
        Flows = @($flows | Where-Object EnvironmentId -eq $eid).Count
        RolesRead = $_.RolesCollection
    } })
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $envView -Columns @('DisplayName', 'Type', 'Default', 'Dataverse', 'SecurityGroup', 'Managed', 'SystemAdmins', 'Flows', 'RolesRead') -MaxRows 300 -CsvName 'pp-environments.csv'))

$null = $h.Append('<h2 id="method">How to read this report</h2><div class="note">')
$null = $h.Append('<p><strong>Two layers.</strong> Tenant admin roles (Power Platform Administrator, Dynamics 365 Administrator, Global Administrator) are Entra roles that PIM governs. Dataverse roles such as System Administrator are assigned inside each environment; PIM does not see them. Tenant admins no longer get System Administrator automatically and must self-elevate per environment.</p>')
$null = $h.Append('<p><strong>Personas.</strong> CLAD accounts are matched by the naming prefix in the tool config. Everything else is treated as an everyday account. The target model is: the CLAD administers (no licence, eligible roles), the everyday account builds (licence, scoped environment roles, no tenant admin role).</p>')
$null = $h.Append('<p><strong>Flows at risk</strong> are estimated from the flow owner''s roles and the connectors in the flow definition. A Dataverse action can target another environment, so check with the owner before acting.</p>')
$null = $h.Append('<p><strong>Coverage.</strong> Environments where the run account could not read Dataverse are listed under PP-14. Evidence files: pp-*.csv in the run folder; collection log in pp-collection-log.csv.</p></div>')
$null = $h.Append('</main></body></html>')

$reportPath = Join-Path $RunFolder (Get-SafeFileName -Name ("PowerPlatform_Review_{0}_{1}.html" -f $label, (Get-Date -Format 'yyyyMMdd')))
$h.ToString() | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Power Platform assessment: $reportPath" -ForegroundColor Green
[pscustomobject]@{ ReportPath = $reportPath; RunFolder = $RunFolder; Summary = $summary }
#endregion
