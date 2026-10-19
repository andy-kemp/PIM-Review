<#
.SYNOPSIS
PIM Phase 2 tenant assessment: turns the Entra PIM review and Azure RBAC review exports into the registers
the PIM Phase 2 HLD and implementation runbook need.

.DESCRIPTION
Works entirely offline from the Raw CSV evidence of a tenant's runs, so it can be re-run every time the role
catalogue changes (HLD OD-02) without collecting again. Inputs:
- an Entra run folder (Run-YYYYMMDD-HHMMSS from Invoke-FullPimReview.ps1)
- optionally an Azure run folder (AzureRun-... from Get-AzureRbacReview.ps1, or the Azure subfolder of a full run)
- Config/pim-phase2.catalogue.local.json if present, else Config/pim-phase2.catalogue.json (trust levels, role
  catalogue, identity and organisation rules)

Outputs (in <run>/Phase2 or -OutputFolder):
- P2_PrivilegedIdentities.csv   every privileged identity: account type, organisation, linked person, highest TL
- P2_AccessPaths.csv            every path from an identity to a privileged role (Entra and Azure) with TL
- P2_RoleCatalogue.csv          every role in use with its trust level, classification source and holders (runbook 1.2)
- P2_SelfApproval.csv           person-level self-approval routes, including linked CLAD/everyday identities (F01)
- P2_ApproverGroups.csv         approver population against HLD 7.6.3
- P2_GroupBundles.csv           groups that bundle roles, and whether TL1 sits inside a bundle (F03, 7.6.1)
- P2_TL1Paths.csv               every route to a TL1 role
- P2_StandingAccess.csv         permanent active privileged access (SEC-PIM-03, SEC-PIM-21)
- P2_PolicyGaps.csv             PIM role settings against the trust-level baseline (runbook 4.3)
- P2_MigrationWorksheet.csv     current path, trust level and proposed action per path (runbook 1.2 / 5.1)
- P2_ExceptionCandidates.csv    access that will need an exception record (HLD 8.4, runbook 5.8)
- P2_HldFindings.csv            status of HLD findings F01-F15 in this tenant
- P2_Maturity.csv               measured indicators for the HLD 6.7 maturity baseline
- P2_Metrics.csv                headline numbers for the partnership roll-up
- PIM_Phase2_Assessment_<tenant>.html

.EXAMPLE
./Invoke-PimPhase2Assessment.ps1 -TenantFolder .\Output\Contoso -TenantShortName CON

.EXAMPLE
./Invoke-PimPhase2Assessment.ps1 -EntraRunFolder .\Output\Contoso\Run-20261020-090000 -AzureRunFolder .\Output\Contoso\Run-20261020-090000\Azure
#>
[CmdletBinding()]
param(
    [string]$TenantFolder,
    [string]$EntraRunFolder,
    [string]$AzureRunFolder,
    [string]$TenantName,
    [string]$TenantShortName,
    [string]$CataloguePath,
    [string]$IdentityMapCsv,
    [string]$OutputFolder
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}
. (Join-Path -Path $PSScriptRoot -ChildPath 'New-PimPhase2Report.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimAuditControls.ps1')

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

function Get-P2Prop {
    param([object]$InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { if ($InputObject.Contains($Name)) { return $InputObject[$Name] }; return $null }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Import-P2Csv {
    param([string]$Folder, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Folder)) { return @() }
    $path = Join-Path -Path $Folder -ChildPath $Name
    if (-not (Test-Path -Path $path)) { return @() }
    if ((Get-Item -Path $path).Length -lt 5) { return @() }
    return @(Import-Csv -Path $path -Encoding UTF8)
}

function Test-P2True {
    param([object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    return ([string]$Value -match '^(?i)(true|yes|1)$')
}

function ConvertTo-P2Hours {
    param([string]$Duration)
    if ([string]::IsNullOrWhiteSpace($Duration)) { return $null }
    if ($Duration -notmatch '^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$') { return $null }
    $d = if ($Matches[1]) { [double]$Matches[1] } else { 0 }
    $h = if ($Matches[2]) { [double]$Matches[2] } else { 0 }
    $m = if ($Matches[3]) { [double]$Matches[3] } else { 0 }
    return [Math]::Round(($d * 24) + $h + ($m / 60), 2)
}

function Get-P2TlRank {
    param([string]$Level)
    switch ($Level) { 'TL1' { 4 } 'TL2' { 3 } 'TL3' { 2 } 'TL4' { 1 } default { 0 } }
}

function Get-P2HighestTl {
    param([object[]]$Levels)
    $best = $null
    foreach ($l in $Levels) { if ((Get-P2TlRank -Level $l) -gt (Get-P2TlRank -Level $best)) { $best = $l } }
    return $best
}

function Get-P2NameKey {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $n = $Name -replace '\[[^\]]*\]', ''
    if ($n -match '^\s*([^,]+),\s*(.+)$') { $n = "$($Matches[2]) $($Matches[1])" }
    $n = $n.ToLowerInvariant()
    $n = $n -replace ("[" + [char]0x2019 + "']"), ''
    $n = $n -replace '[^a-z ]', ' '
    $tokens = @($n.Split(' ') | Where-Object { $_.Length -gt 0 })
    if ($tokens.Count -lt 2) { return $null }
    return "$($tokens[0]) $($tokens[$tokens.Count - 1])"
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

function Invoke-PimPhase2Assessment {
    [CmdletBinding()]
    param(
        [string]$TenantFolder,
        [string]$EntraRunFolder,
        [string]$AzureRunFolder,
        [string]$TenantName,
        [string]$TenantShortName,
        [string]$CataloguePath,
        [string]$IdentityMapCsv,
        [string]$OutputFolder
    )

    # ---- Locate inputs ----------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($CataloguePath)) {
        # A local (git-ignored) catalogue holds programme-specific roles, domains and branding.
        $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'Config\pim-phase2.catalogue.local.json'
        if (-not (Test-Path -Path $CataloguePath)) { $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'Config\pim-phase2.catalogue.json' }
    }
    if (-not (Test-Path -Path $CataloguePath)) { throw "Catalogue not found: $CataloguePath" }
    $cat = Get-Content -Path $CataloguePath -Raw | ConvertFrom-Json

    if ([string]::IsNullOrWhiteSpace($EntraRunFolder) -and $TenantFolder) {
        $entraCandidate = @(Get-ChildItem -Path $TenantFolder -Directory -Filter 'Run-*' | Where-Object { Test-Path (Join-Path $_.FullName 'Raw\RoleAssignments.csv') } | Sort-Object -Property Name -Descending | Select-Object -First 1)
        if ($entraCandidate.Count -gt 0) { $EntraRunFolder = $entraCandidate[0].FullName }
    }
    if ([string]::IsNullOrWhiteSpace($AzureRunFolder)) {
        $azCandidates = @()
        if ($EntraRunFolder -and (Test-Path (Join-Path $EntraRunFolder 'Azure\Raw\AzureRoleAssignments.csv'))) { $azCandidates += Get-Item (Join-Path $EntraRunFolder 'Azure') }
        if ($TenantFolder) { $azCandidates += @(Get-ChildItem -Path $TenantFolder -Directory -Filter 'AzureRun-*' | Where-Object { Test-Path (Join-Path $_.FullName 'Raw\AzureRoleAssignments.csv') }) }
        $latest = @($azCandidates | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1)
        if ($latest.Count -gt 0) { $AzureRunFolder = $latest[0].FullName }
    }
    if ([string]::IsNullOrWhiteSpace($EntraRunFolder) -and [string]::IsNullOrWhiteSpace($AzureRunFolder)) {
        throw 'No Entra or Azure run found. Pass -TenantFolder, -EntraRunFolder or -AzureRunFolder.'
    }

    $entraRaw = if ($EntraRunFolder) { Join-Path $EntraRunFolder 'Raw' } else { $null }
    $azureRaw = if ($AzureRunFolder) { Join-Path $AzureRunFolder 'Raw' } else { $null }

    $tenantDetails = @(Import-P2Csv -Folder $entraRaw -Name 'TenantDetails.csv') | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($TenantName)) {
        $TenantName = if ($tenantDetails -and $tenantDetails.TenantDisplayName) { $tenantDetails.TenantDisplayName } elseif ($TenantFolder) { Split-Path -Path $TenantFolder -Leaf } else { 'Tenant' }
    }
    if ([string]::IsNullOrWhiteSpace($TenantShortName)) { $TenantShortName = $TenantName }

    if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
        $base = if ($EntraRunFolder) { $EntraRunFolder } else { $AzureRunFolder }
        $OutputFolder = Join-Path -Path $base -ChildPath 'Phase2'
    }
    $OutputFolder = Ensure-Directory -Path $OutputFolder

    Write-PimLog -Message "Phase 2 assessment for $TenantName. Entra run: $EntraRunFolder. Azure run: $AzureRunFolder."

    # ---- Load evidence ----------------------------------------------------------------------
    $roleAssignments = @(Import-P2Csv -Folder $entraRaw -Name 'RoleAssignments.csv')
    $pimGroups = @(Import-P2Csv -Folder $entraRaw -Name 'PimForGroups.Assignments.csv')
    $groupMembers = @(Import-P2Csv -Folder $entraRaw -Name 'GroupMembers.All.csv')
    $nestedPaths = @(Import-P2Csv -Folder $entraRaw -Name 'NestedGroupPrivilegePaths.csv')
    $userAccessPaths = @(Import-P2Csv -Folder $entraRaw -Name 'UserAccessPaths.csv')
    $policyFlat = @(Import-P2Csv -Folder $entraRaw -Name 'RolePolicySettings.flat.csv')
    $groupPolicyFlat = @(Import-P2Csv -Folder $entraRaw -Name 'PimGroupPolicySettings.flat.csv')
    $approverProfiles = @(Import-P2Csv -Folder $entraRaw -Name 'ApproverProfiles.csv')
    $assurance = @(Import-P2Csv -Folder $entraRaw -Name 'IdentityAssuranceProfiles.csv')
    $licences = @(Import-P2Csv -Folder $entraRaw -Name 'UserLicenses.csv')
    $caPolicies = @(Import-P2Csv -Folder $entraRaw -Name 'ConditionalAccessPolicies.csv')
    $identityContext = @(Import-P2Csv -Folder $entraRaw -Name 'PrivilegedIdentityContext.csv')
    $authMethods = @(Import-P2Csv -Folder $entraRaw -Name 'AuthMethodRegistration.csv')
    $accessReviews = @(Import-P2Csv -Folder $entraRaw -Name 'AccessReviews.beta.csv')

    $azAccess = @(Import-P2Csv -Folder $azureRaw -Name 'AzureUserAccess.csv')
    $azAssignments = @(Import-P2Csv -Folder $azureRaw -Name 'AzureRoleAssignments.csv')
    $azRgTypes = @(Import-P2Csv -Folder $azureRaw -Name 'AzureResourceGroupTypes.csv')
    $azPolicies = @(Import-P2Csv -Folder $azureRaw -Name 'AzurePimPolicies.csv')
    $azLighthouse = @(Import-P2Csv -Folder $azureRaw -Name 'AzureLighthouseDelegations.csv')
    $azCoverageGaps = @(Import-P2Csv -Folder $azureRaw -Name 'AzureCoverageGaps.csv')

    $hasEntra = $roleAssignments.Count -gt 0
    $hasAzure = $azAccess.Count -gt 0

    # ---- Identity registry and classification ------------------------------------------------
    $ident = @{}
    $touch = {
        param($Id, $DisplayName, $Upn, $ObjectType, $UserType, $Enabled)
        if ([string]::IsNullOrWhiteSpace($Id)) { return }
        $k = ([string]$Id).ToLowerInvariant()
        if (-not $ident.ContainsKey($k)) {
            $ident[$k] = [ordered]@{ Id = $k; DisplayName = $null; Upn = $null; ObjectType = $null; UserType = $null; AccountEnabled = $null }
        }
        $e = $ident[$k]
        if (-not $e.DisplayName -and $DisplayName) { $e.DisplayName = [string]$DisplayName }
        if (-not $e.Upn -and $Upn) { $e.Upn = [string]$Upn }
        if (-not $e.ObjectType -and $ObjectType) { $e.ObjectType = [string]$ObjectType }
        if (-not $e.UserType -and $UserType) { $e.UserType = [string]$UserType }
        if ($null -eq $e.AccountEnabled -and $null -ne $Enabled -and [string]$Enabled -ne '') { $e.AccountEnabled = Test-P2True -Value $Enabled }
    }

    foreach ($r in $roleAssignments) { & $touch $r.PrincipalId $r.PrincipalDisplayName $r.PrincipalUserPrincipalName $r.PrincipalType $r.PrincipalUserType $null }
    foreach ($r in $pimGroups) { & $touch $r.PrincipalId $r.PrincipalDisplayName $null $r.PrincipalType $null $null }
    foreach ($r in $groupMembers) { & $touch $r.MemberId $r.MemberDisplayName $r.MemberUserPrincipalName $r.MemberType $r.MemberUserType $r.AccountEnabled }
    foreach ($r in $nestedPaths) { & $touch $r.UserId $r.UserDisplayName $r.UserPrincipalName 'User' $r.UserType $null }
    foreach ($r in $userAccessPaths) { & $touch $r.UserId $r.UserDisplayName $r.UserPrincipalName 'User' $(if ($r.UserCategory -eq 'Guest') { 'Guest' } else { $null }) $null }
    foreach ($r in $approverProfiles) { if ($r.UserId) { & $touch $r.UserId $r.DisplayName $r.UserPrincipalName 'User' $r.UserType $null } }
    foreach ($r in $identityContext) { & $touch $r.Id $r.DisplayName $r.UserPrincipalName $r.ObjectType $r.UserType $r.AccountEnabled }
    foreach ($r in $azAccess) {
        $ot = switch -Regex ([string]$r.PrincipalCategory) { '^(Member|Guest)$' { 'User' } 'ServicePrincipal|ManagedIdentity|MicrosoftPlatform|ExternalApp' { 'ServicePrincipal' } 'Group' { 'Group' } '^Deleted$' { 'Deleted' } '^ForeignPrincipal$' { 'Foreign' } 'Unresolved|LookupFailed|Unknown' { 'Unresolved' } default { $null } }
        & $touch $r.PrincipalId $r.DisplayName $r.UserPrincipalName $ot $(if ($r.PrincipalCategory -eq 'Guest') { 'Guest' } else { $null }) $r.AccountEnabled
    }

    $assuranceById = @{}
    foreach ($a in $assurance) { if ($a.UserId) { $assuranceById[$a.UserId.ToLowerInvariant()] = $a } }
    $licenceById = @{}
    foreach ($l in $licences) { if ($l.UserId) { $licenceById[$l.UserId.ToLowerInvariant()] = $l } }
    $contextById = @{}
    foreach ($c in $identityContext) { if ($c.Id) { $contextById[$c.Id.ToLowerInvariant()] = $c } }
    $authById = @{}
    foreach ($m in $authMethods) { if ($m.UserId) { $authById[$m.UserId.ToLowerInvariant()] = $m } }

    $idRules = $cat.Identity
    $orgDomains = @{}
    foreach ($p in $cat.Organisations.Domains.PSObject.Properties) { $orgDomains[$p.Name.ToLowerInvariant()] = $p.Value }
    $tenantDomains = @()
    if ($tenantDetails -and $tenantDetails.VerifiedDomains) { $tenantDomains = @(([string]$tenantDetails.VerifiedDomains).Split(';') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ }) }

    $resolveOrg = {
        param($Domain)
        if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }
        $d = $Domain.ToLowerInvariant()
        while ($d) {
            if ($orgDomains.ContainsKey($d)) { return $orgDomains[$d] }
            $i = $d.IndexOf('.')
            if ($i -lt 0) { break }
            $d = $d.Substring($i + 1)
            if ($d -notmatch '\.') { break }
        }
        if ($tenantDomains -contains $Domain.ToLowerInvariant() -or $Domain -match '\.onmicrosoft\.com$') { return [pscustomobject]@{ Name = $TenantName; Type = 'Tenant' } }
        return [pscustomobject]@{ Name = $Domain; Type = 'Unknown' }
    }

    $mapping = @{}
    $mapPath = if ($IdentityMapCsv) { $IdentityMapCsv } elseif ($idRules.IdentityMapCsv) { [string]$idRules.IdentityMapCsv } else { $null }
    if ($mapPath -and (Test-Path -Path $mapPath)) {
        foreach ($m in @(Import-Csv -Path $mapPath)) {
            $priv = [string](Get-P2Prop $m 'PrivilegedUpn'); $person = [string](Get-P2Prop $m 'Person'); $everyday = [string](Get-P2Prop $m 'EverydayUpn')
            if ($priv) { $mapping[$priv.ToLowerInvariant()] = [pscustomobject]@{ Person = $person; Everyday = $everyday } }
            if ($everyday) { $mapping[$everyday.ToLowerInvariant()] = [pscustomobject]@{ Person = $person; Everyday = $everyday } }
        }
        Write-PimLog -Message "Loaded identity map with $($mapping.Count) entries from $mapPath."
    }

    $matchAny = {
        param($Value, $Patterns)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        foreach ($p in @($Patterns)) { if ($p -and $Value -match $p) { return $true } }
        return $false
    }

    $breakGlassUpns = @($idRules.BreakGlassUpns | ForEach-Object { ([string]$_).ToLowerInvariant() })
    foreach ($k in @($ident.Keys)) {
        $e = $ident[$k]
        $upn = [string]$e.Upn
        $dn = [string]$e.DisplayName
        $upnLower = $upn.ToLowerInvariant()
        $local = if ($upnLower -match '^([^@]+)@') { $Matches[1] } else { $upnLower }
        $isGuest = ($e.UserType -eq 'Guest') -or ($upnLower -match '#ext#')
        $homeDomain = $null
        if ($upnLower -match '_([a-z0-9.-]+)#ext#') { $homeDomain = $Matches[1] }
        elseif ($upnLower -match '@([a-z0-9.-]+)$') { $homeDomain = $Matches[1] }

        $type = 'Unknown'
        $objType = [string]$e.ObjectType
        if ($objType -eq 'Deleted') { $type = 'Deleted identity' }
        elseif ($objType -eq 'Foreign') { $type = 'Other tenant principal' }
        elseif ($objType -eq 'Unresolved' -or $dn -match '^Unresolved \(') { $type = 'Unresolved' }
        elseif ($objType -match 'Group') { $type = 'Group' }
        elseif ($objType -match 'ServicePrincipal') { $type = 'WorkloadIdentity' }
        elseif ($breakGlassUpns -contains $upnLower -or (& $matchAny $dn $idRules.BreakGlassPatterns) -or (& $matchAny $local $idRules.BreakGlassPatterns)) { $type = 'BreakGlass' }
        elseif (($idRules.CladUpnPrefixes | Where-Object { $_ -and $local.StartsWith(([string]$_).ToLowerInvariant()) }) -or (& $matchAny $dn $idRules.CladDisplayNamePatterns)) { $type = 'CLAD' }
        elseif ((& $matchAny $dn $idRules.GenericPatterns) -or (& $matchAny $local $idRules.GenericPatterns)) { $type = 'Generic/Service' }
        elseif ((& $matchAny $dn $idRules.OtherAdminPatterns) -or (& $matchAny $local $idRules.OtherAdminPatterns)) { $type = 'Other admin account' }
        elseif ($isGuest) { $type = 'Guest' }
        elseif ($upn -or $dn) { $type = 'Everyday' }

        $org = & $resolveOrg $homeDomain
        $orgName = if ($org) { $org.Name } else { $null }
        $orgType = if ($org) { $org.Type } else { $null }
        if ($type -eq 'WorkloadIdentity' -or $type -eq 'Group') { $orgName = $TenantName; $orgType = 'Tenant' }
        elseif (-not $homeDomain -and $type -in @('CLAD', 'Other admin account', 'Generic/Service', 'BreakGlass')) { $orgName = $TenantName; $orgType = 'Tenant' }
        elseif ($type -in @('Unresolved', 'Deleted identity')) { $orgName = 'Unresolved'; $orgType = 'Unknown' }
        elseif ($type -eq 'Other tenant principal') { $orgName = 'Other tenant'; $orgType = 'Unknown' }
        elseif (-not $homeDomain) { $orgName = 'Not known'; $orgType = 'Unknown' }

        # Person key: cleaned display name, or the guest UPN local part.
        $cleanName = $dn
        foreach ($p in @($idRules.CladDisplayNamePatterns) + @($idRules.OtherAdminPatterns)) { if ($p) { $cleanName = $cleanName -replace $p, '' } }
        $cleanName = ($cleanName -replace '\s+-\s+.*$', '' -replace '\([^)]*\)', '').Trim()
        $nameKey = $null
        if ($type -in @('CLAD', 'Everyday', 'Guest', 'Other admin account')) {
            $nameKey = Get-P2NameKey -Name $cleanName
            if (-not $nameKey -and $upnLower -match '^([a-z]+)\.([a-z]+)_') { $nameKey = "$($Matches[1]) $($Matches[2])" }
            if (-not $nameKey -and $local -match '^([a-z]+)\.([a-z]+)$') { $nameKey = "$($Matches[1]) $($Matches[2])" }
        }
        $surnameInitial = $null
        if ($type -eq 'CLAD' -and $local -match '^(?:clad_)?([a-z]+?)([a-z])$') { $surnameInitial = "$($Matches[1])|$($Matches[2])" }

        $e['AccountType'] = $type
        $e['IsGuest'] = $isGuest
        $e['HomeDomain'] = $homeDomain
        $e['Organisation'] = $orgName
        $e['OrganisationType'] = $orgType
        $e['NameKey'] = $nameKey
        $e['SurnameInitial'] = $surnameInitial
        $e['PersonKey'] = $null
        $e['LinkedEveryday'] = $null
        $e['LinkConfidence'] = $null
    }

    # Link privileged identities (CLAD / other admin) to the everyday identity of the same person.
    $byName = @{}
    $bySurnameInitial = @{}
    foreach ($e in $ident.Values) {
        if ($e.AccountType -in @('Everyday', 'Guest') -and $e.NameKey) {
            if (-not $byName.ContainsKey($e.NameKey)) { $byName[$e.NameKey] = New-Object System.Collections.ArrayList }
            $null = $byName[$e.NameKey].Add($e)
            $parts = $e.NameKey.Split(' ')
            $si = "$($parts[$parts.Count - 1])|$($parts[0].Substring(0, 1))"
            if (-not $bySurnameInitial.ContainsKey($si)) { $bySurnameInitial[$si] = New-Object System.Collections.ArrayList }
            $null = $bySurnameInitial[$si].Add($e)
        }
    }

    foreach ($e in $ident.Values) {
        if ($e.AccountType -notin @('CLAD', 'Other admin account', 'Everyday', 'Guest')) { continue }
        $upnLower = ([string]$e.Upn).ToLowerInvariant()
        if ($upnLower -and $mapping.ContainsKey($upnLower)) {
            $m = $mapping[$upnLower]
            $e.PersonKey = if ($m.Person) { $m.Person.ToLowerInvariant() } else { $e.NameKey }
            if ($e.AccountType -in @('CLAD', 'Other admin account')) { $e.LinkedEveryday = $m.Everyday; $e.LinkConfidence = 'Identity map' }
            continue
        }
        if ($e.AccountType -in @('Everyday', 'Guest')) { $e.PersonKey = $e.NameKey; continue }

        $e.PersonKey = $e.NameKey
        $candidates = @()
        if ($e.NameKey -and $byName.ContainsKey($e.NameKey)) { $candidates = @($byName[$e.NameKey]); $e.LinkConfidence = 'Name match' }
        elseif ($e.SurnameInitial -and $bySurnameInitial.ContainsKey($e.SurnameInitial) -and @($bySurnameInitial[$e.SurnameInitial]).Count -eq 1) {
            $candidates = @($bySurnameInitial[$e.SurnameInitial]); $e.LinkConfidence = 'Surname and initial'
            $e.PersonKey = $candidates[0].NameKey
        }
        if ($candidates.Count -gt 0) {
            $e.LinkedEveryday = (@($candidates | ForEach-Object { if ($_.Upn) { $_.Upn } else { $_.DisplayName } }) -join '; ')
            if ($candidates.Count -gt 1) { $e.LinkConfidence = "$($e.LinkConfidence) (ambiguous)" }
        }
        else {
            $e.LinkConfidence = 'No everyday identity in evidence'
        }
    }

    # The organisation a person works for: a shared operator's CLAD sits in the partner's domain,
    # so prefer the organisation of any linked home identity (Supplier, then Operator, then Partner).
    $personOrg = @{}
    $orgRank = @{ Supplier = 4; Operator = 3; Partner = 2; Tenant = 1 }
    foreach ($e in $ident.Values) {
        if (-not $e.PersonKey -or -not $e.OrganisationType -or -not $orgRank.ContainsKey([string]$e.OrganisationType)) { continue }
        $cur = if ($personOrg.ContainsKey($e.PersonKey)) { $personOrg[$e.PersonKey] } else { $null }
        if (-not $cur -or $orgRank[[string]$e.OrganisationType] -gt $orgRank[[string]$cur.Type]) { $personOrg[$e.PersonKey] = [pscustomobject]@{ Name = $e.Organisation; Type = $e.OrganisationType } }
    }

    $titleCase = (New-Object System.Globalization.CultureInfo('en-GB')).TextInfo
    $personOf = {
        param($Id)
        if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
        $k = ([string]$Id).ToLowerInvariant()
        if ($ident.ContainsKey($k) -and $ident[$k].PersonKey) { return $titleCase.ToTitleCase([string]$ident[$k].PersonKey) }
        return "id:$k"
    }

    # ---- Trust level classification ----------------------------------------------------------
    $entraCat = @{}
    foreach ($p in $cat.EntraRoles.PSObject.Properties) { $entraCat[$p.Name.ToLowerInvariant()] = $p.Value }
    $entraLevel = {
        param($RoleName)
        $k = ([string]$RoleName).ToLowerInvariant()
        if ($entraCat.ContainsKey($k)) { return $entraCat[$k] }
        return $cat.EntraDefaultLevel
    }

    $azFamilyOf = @{}
    foreach ($fam in $cat.AzureRoleFamilies.PSObject.Properties) { foreach ($r in @($fam.Value)) { $azFamilyOf[([string]$r).ToLowerInvariant()] = $fam.Name } }
    $sensitiveNamePatterns = @($cat.AzureSensitiveScopes.NamePatterns)
    $sensitiveTypes = @($cat.AzureSensitiveScopes.ResourceTypes | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $rgTypes = @{}
    foreach ($t in $azRgTypes) {
        $k = "$(([string]$t.SubscriptionId).ToLowerInvariant())|$(([string]$t.ResourceGroup).ToLowerInvariant())"
        if (-not $rgTypes.ContainsKey($k)) { $rgTypes[$k] = New-Object System.Collections.ArrayList }
        $null = $rgTypes[$k].Add(([string]$t.ResourceType).ToLowerInvariant())
    }

    $azLevel = {
        param($Row)
        $roleKey = ([string]$Row.RoleName).ToLowerInvariant()
        $family = $null
        if ($azFamilyOf.ContainsKey($roleKey)) { $family = $azFamilyOf[$roleKey] }
        elseif ($roleKey -match 'reader$' -and $roleKey -notmatch 'data') { $family = 'Reader' }
        else {
            $tier = [string]$Row.PrivilegeTier
            $family = [string](Get-P2Prop $cat.AzureFamilyByTier $tier)
            if (-not $family) { $family = 'Workload' }
        }
        $scopeLevel = [string]$Row.ScopeLevel
        if ($scopeLevel -notin @('Root', 'ManagementGroup', 'Subscription', 'ResourceGroup', 'Resource')) { $scopeLevel = 'Resource' }
        $level = [string](Get-P2Prop (Get-P2Prop $cat.AzureLevelMatrix $family) $scopeLevel)
        $reason = "$family at $scopeLevel scope (HLD 7.11.2)"

        if ($family -notin @('Reader', 'DataRead')) {
            $sensitive = $false
            foreach ($candidate in @($Row.ScopeName, $Row.ResourceGroup, $Row.SubscriptionName)) {
                if (& $matchAny ([string]$candidate) $sensitiveNamePatterns) { $sensitive = $true; break }
            }
            $rgKey = "$(([string]$Row.SubscriptionId).ToLowerInvariant())|$(([string]$Row.ResourceGroup).ToLowerInvariant())"
            if (-not $sensitive -and $Row.ResourceGroup -and $rgTypes.ContainsKey($rgKey)) {
                foreach ($t in $rgTypes[$rgKey]) { foreach ($st in $sensitiveTypes) { if ($t.StartsWith($st)) { $sensitive = $true } } }
            }
            if ($sensitive -and (Get-P2TlRank -Level $level) -lt 4) {
                $level = 'TL1'
                $reason = "$reason; raised to TL1 because the scope holds identity, key, security, logging or automation services"
            }
        }
        return [pscustomobject]@{ Level = $level; Family = $family; Reason = $reason }
    }

    # ---- Entra effective access paths --------------------------------------------------------
    $paths = New-Object System.Collections.ArrayList
    $addPath = {
        param($IdentityId, $Plane, $Role, $Scope, $ScopeLevel, $PathType, $ViaGroup, $ViaGroupId, $MembershipState, $RoleState, $Permanent, $End, $TlInfo, $Extra)
        if ([string]::IsNullOrWhiteSpace($IdentityId)) { return }
        $k = ([string]$IdentityId).ToLowerInvariant()
        $e = if ($ident.ContainsKey($k)) { $ident[$k] } else { $null }
        $effective = if ($MembershipState -eq 'Eligible' -or $RoleState -eq 'Eligible') { 'Eligible' } else { 'Active' }
        $standing = ($effective -eq 'Active') -and $Permanent
        $row = [ordered]@{
            Tenant          = $TenantShortName
            Person          = & $personOf $IdentityId
            Identity        = if ($e) { $e.DisplayName } else { $IdentityId }
            Upn             = if ($e) { $e.Upn } else { $null }
            AccountType     = if ($e) { $e.AccountType } else { 'Unknown' }
            Organisation    = if ($e) { $e.Organisation } else { $null }
            OrganisationType = if ($e) { $e.OrganisationType } else { $null }
            PersonOrganisation = if ($e -and $e.PersonKey -and $personOrg.ContainsKey($e.PersonKey)) { $personOrg[$e.PersonKey].Name } elseif ($e) { $e.Organisation } else { $null }
            PersonOrganisationType = if ($e -and $e.PersonKey -and $personOrg.ContainsKey($e.PersonKey)) { $personOrg[$e.PersonKey].Type } elseif ($e) { $e.OrganisationType } else { $null }
            Plane           = $Plane
            Role            = $Role
            Scope           = $Scope
            ScopeLevel      = $ScopeLevel
            TrustLevel      = $TlInfo.Level
            TrustLevelSource = $TlInfo.Source
            PathType        = $PathType
            ViaGroup        = $ViaGroup
            MembershipState = $MembershipState
            RoleState       = $RoleState
            EffectiveState  = $effective
            Standing        = $standing
            EndDateTime     = $End
            IdentityId      = $k
            ViaGroupId      = $ViaGroupId
            AzureScope      = $null
            AzureFamily     = $null
            AssignmentType  = $null
            SubscriptionName = $null
        }
        if ($Extra) { foreach ($x in $Extra.Keys) { $row[$x] = $Extra[$x] } }
        $null = $paths.Add([pscustomobject]$row)
    }

    $groupRoles = @{}
    $entraSeen = @{}
    foreach ($ra in $roleAssignments) {
        $tl = & $entraLevel $ra.RoleDisplayName
        $tlInfo = [pscustomobject]@{ Level = $tl.Level; Source = $tl.Source }
        $permanent = [string]::IsNullOrWhiteSpace($ra.EndDateTimeUtc)
        $ptype = [string]$ra.PrincipalType
        if ($ptype -eq 'Group') {
            $gk = $ra.PrincipalId.ToLowerInvariant()
            if (-not $groupRoles.ContainsKey($gk)) { $groupRoles[$gk] = New-Object System.Collections.ArrayList }
            $null = $groupRoles[$gk].Add([pscustomobject]@{ Role = $ra.RoleDisplayName; State = $ra.AssignmentState; Permanent = $permanent; End = $ra.EndDateTimeUtc; Tl = $tlInfo; GroupName = $ra.PrincipalDisplayName })
            continue
        }
        $key = "$($ra.PrincipalId)|$($ra.RoleDisplayName)|direct|$($ra.AssignmentState)".ToLowerInvariant()
        if ($entraSeen.ContainsKey($key)) { continue }
        $entraSeen[$key] = $true
        & $addPath $ra.PrincipalId 'Entra' $ra.RoleDisplayName 'Directory' 'Directory' 'Direct' $null $null $null $ra.AssignmentState $permanent $ra.EndDateTimeUtc $tlInfo $null
    }

    # Group membership: PIM for Groups (eligible and active), plain members, nested members.
    $memberships = New-Object System.Collections.ArrayList
    foreach ($m in $pimGroups) {
        if ($m.AccessId -and $m.AccessId -ne 'member') { continue }
        if ([string]$m.PrincipalType -eq 'Group') { continue }
        $null = $memberships.Add([pscustomobject]@{ GroupId = $m.GroupId.ToLowerInvariant(); MemberId = $m.PrincipalId; State = $m.AssignmentState; Permanent = (Test-P2True $m.IsPermanent) -or [string]::IsNullOrWhiteSpace($m.EndDateTimeUtc); End = $m.EndDateTimeUtc; PathType = $(if ($m.AssignmentState -eq 'Eligible') { 'PIM for Groups (eligible member)' } else { 'PIM for Groups (active member)' }) })
    }
    foreach ($m in $groupMembers) {
        if ([string]$m.MemberType -eq 'Group' -or (Test-P2True $m.IsNestedGroup)) { continue }
        $null = $memberships.Add([pscustomobject]@{ GroupId = $m.SourceGroupId.ToLowerInvariant(); MemberId = $m.MemberId; State = 'Active'; Permanent = $true; PathType = 'Group member' })
    }
    foreach ($n in $nestedPaths) {
        $null = $memberships.Add([pscustomobject]@{ GroupId = $n.RootGroupId.ToLowerInvariant(); MemberId = $n.UserId; State = 'Active'; Permanent = $true; PathType = 'Nested group member' })
    }

    $membershipSeen = @{}
    foreach ($m in $memberships) {
        if (-not $groupRoles.ContainsKey($m.GroupId)) { continue }
        foreach ($gr in $groupRoles[$m.GroupId]) {
            $key = "$($m.MemberId)|$($gr.Role)|$($m.GroupId)".ToLowerInvariant()
            if ($membershipSeen.ContainsKey($key)) {
                # Prefer the stronger (active) membership record if both an eligible and active exist.
                continue
            }
            $membershipSeen[$key] = $true
            $permanent = $m.Permanent -and $gr.Permanent
            $pathEnd = if ($m.PSObject.Properties['End'] -and $m.End) { $m.End } else { $gr.End }
            & $addPath $m.MemberId 'Entra' $gr.Role 'Directory' 'Directory' $m.PathType $gr.GroupName $m.GroupId $m.State $gr.State $permanent $pathEnd $gr.Tl $null
        }
    }

    # Fallback: the original tool's UserAccessPaths covers members we could not otherwise see.
    foreach ($u in $userAccessPaths) {
        if ($u.AccessPathType -eq 'Direct') { continue }
        $key = "$($u.UserId)|$($u.RoleName)|$($u.SourceGroupId)".ToLowerInvariant()
        if ($membershipSeen.ContainsKey($key)) { continue }
        $membershipSeen[$key] = $true
        $tl = & $entraLevel $u.RoleName
        & $addPath $u.UserId 'Entra' $u.RoleName 'Directory' 'Directory' 'Group member' $u.SourceGroupDisplayName $u.SourceGroupId 'Active' $u.AssignmentState (Test-P2True $u.IsPermanent) $null ([pscustomobject]@{ Level = $tl.Level; Source = $tl.Source }) $null
    }

    # ---- Azure paths -------------------------------------------------------------------------
    foreach ($a in $azAccess) {
        if ([string]$a.PrincipalCategory -eq 'Group') { continue }
        $info = & $azLevel $a
        $state = if ($a.EffectiveState) { $a.EffectiveState } else { $a.AssignmentState }
        $isStanding = Test-P2True $a.IsStanding
        $membershipState = if ([string]$a.MembershipType -like 'Eligible*') { 'Eligible' } elseif ($a.AccessPath -eq 'Group') { 'Active' } else { $null }
        $pathType = if ($a.AccessPath -eq 'Group') { if ($membershipState -eq 'Eligible') { 'PIM for Groups (eligible member)' } else { 'Group member' } } else { 'Direct' }
        $scopeText = if ($a.ScopeLevel -in @('Root', 'ManagementGroup')) { "$($a.ScopeLevel): $($a.ScopeName)" } elseif ($a.ScopeLevel -eq 'Subscription') { "Subscription: $($a.ScopeName)" } else { "$($a.ScopeLevel): $($a.ScopeName) ($($a.SubscriptionName))" }
        & $addPath $a.PrincipalId 'Azure' $a.RoleName $scopeText $a.ScopeLevel $pathType $a.ViaGroupName $a.ViaGroupId $membershipState $a.AssignmentState $isStanding $a.EndDateTime ([pscustomobject]@{ Level = $info.Level; Source = $info.Reason }) @{ AzureScope = $a.Scope; AzureFamily = $info.Family; AssignmentType = $a.AssignmentType; SubscriptionName = $a.SubscriptionName }
        # Azure standing comes from the export's own calculation (permanent active, not PIM-activated).
        # Read-only roles may stay standing (HLD 7.11.3), so they are not counted as standing privilege.
        if ($paths.Count -gt 0 -and $paths[$paths.Count - 1].IdentityId -eq ([string]$a.PrincipalId).ToLowerInvariant()) {
            $paths[$paths.Count - 1].Standing = $isStanding -and $state -ne 'Eligible' -and $info.Family -ne 'Reader'
        }
    }

    $privPaths = @($paths | Where-Object { (Get-P2TlRank -Level $_.TrustLevel) -ge 2 })
    Write-PimLog -Message "Built $($paths.Count) access paths ($(@($paths | Where-Object Plane -eq 'Entra').Count) Entra, $(@($paths | Where-Object Plane -eq 'Azure').Count) Azure); $($privPaths.Count) at TL1-TL3."

    # ---- Policy settings (Entra roles and PIM for Groups) --------------------------------------
    $policyByRole = @{}
    $parsePolicy = {
        param($Rows, $NameColumn)
        $result = @{}
        foreach ($grp in @($Rows | Group-Object -Property $NameColumn)) {
            $rs = @($grp.Group)
            $get = { param($RuleId) @($rs | Where-Object { $_.RuleId -eq $RuleId }) | Select-Object -First 1 }
            $exp = & $get 'Expiration_EndUser_Assignment'
            $enable = & $get 'Enablement_EndUser_Assignment'
            $appr = & $get 'Approval_EndUser_Assignment'
            $ctx = & $get 'AuthenticationContext_EndUser_Assignment'
            $eligExp = & $get 'Expiration_Admin_Eligibility'
            $actExp = & $get 'Expiration_Admin_Assignment'
            $ctxEnabled = $false
            if ($ctx) {
                foreach ($col in @('IsEnabled', 'AuthContextEnabled', 'ClaimValue', 'AuthenticationContextClaim')) {
                    $v = Get-P2Prop $ctx $col
                    if ($v -and [string]$v -notmatch '^(?i)(false|0)$') { $ctxEnabled = $true }
                }
            }
            $result[([string]$grp.Name).ToLowerInvariant()] = [pscustomobject]@{
                MaxActivationHours = if ($exp) { ConvertTo-P2Hours -Duration $exp.MaxActivationDuration } else { $null }
                ApprovalRequired   = if ($appr) { Test-P2True $appr.IsApprovalRequired } else { $null }
                Approvers          = if ($appr) { $appr.ApproverDisplayNames } else { $null }
                ApproverIds        = if ($appr) { $appr.ApproverIds } else { $null }
                MfaRequired        = if ($enable) { Test-P2True $enable.RequiresMfa } else { $null }
                AuthContext        = $ctxEnabled
                Justification      = if ($enable) { Test-P2True $enable.RequiresJustification } else { $null }
                Ticket             = if ($enable) { Test-P2True $enable.RequiresTicketInfo } else { $null }
                PermanentEligible  = if ($eligExp) { -not (Test-P2True $eligExp.ExpirationRequirement) } else { $null }
                MaxEligibleDays    = if ($eligExp) { [Math]::Round(((ConvertTo-P2Hours -Duration $eligExp.MaxActivationDuration) / 24), 0) } else { $null }
                PermanentActive    = if ($actExp) { -not (Test-P2True $actExp.ExpirationRequirement) } else { $null }
            }
        }
        return $result
    }
    if ($policyFlat.Count -gt 0) { $policyByRole = & $parsePolicy $policyFlat 'RoleName' }
    $policyByGroup = @{}
    if ($groupPolicyFlat.Count -gt 0) { $policyByGroup = & $parsePolicy $groupPolicyFlat 'GroupName' }

    $baselineOf = { param($Level) Get-P2Prop $cat.TrustLevelBaselines $Level }
    $policyGaps = New-Object System.Collections.ArrayList
    $policyCompliance = @{}
    $checkPolicy = {
        param($Plane, $Subject, $Level, $Pol, $Holders)
        $b = & $baselineOf $Level
        if (-not $b -or -not $Pol) { return }
        $gaps = New-Object System.Collections.ArrayList
        $add = { param($Setting, $Current, $Target) $null = $gaps.Add([pscustomobject]@{ Tenant = $TenantShortName; Plane = $Plane; Subject = $Subject; TrustLevel = $Level; Setting = $Setting; Current = $Current; Target = $Target; PeopleAffected = $Holders }) }
        if ($b.MaxActivationHours -and $Pol.MaxActivationHours -and $Pol.MaxActivationHours -gt $b.MaxActivationHours) { & $add 'Maximum activation' "$($Pol.MaxActivationHours)h" "$($b.MaxActivationHours)h" }
        if ($b.ApprovalRequired -eq $true -and $Pol.ApprovalRequired -eq $false) { & $add 'Approval' 'Not required' 'Required (independent approver group)' }
        if ($b.ApprovalRequired -eq $false -and $Pol.ApprovalRequired -eq $true) { & $add 'Approval' 'Required' 'Not required at this level (HLD 7.6.3)' }
        if ($b.MfaOrAuthContextRequired -and -not $Pol.MfaRequired -and -not $Pol.AuthContext) { & $add 'MFA / authentication context on activation' 'Neither' 'Authentication context (MFA interim)' }
        if ($b.AuthContextTarget -and -not $Pol.AuthContext) { & $add 'Authentication context bound' 'No' "Yes (c$($Level.Substring(2)) for $Level, runbook 6.3)" }
        if ($b.JustificationRequired -and $Pol.Justification -eq $false) { & $add 'Justification' 'Not required' 'Required' }
        if ($b.PermanentActiveAllowed -eq $false -and $Pol.PermanentActive -eq $true) { & $add 'Permanent active assignment' 'Allowed' 'Not allowed' }
        if ($b.PermanentEligibleAllowed -eq $false -and $Pol.PermanentEligible -eq $true) { & $add 'Permanent eligible assignment' 'Allowed' 'Expiry required' }
        foreach ($g in $gaps) { $null = $policyGaps.Add($g) }
        $policyCompliance["$Plane|$Subject".ToLowerInvariant()] = $gaps.Count
    }

    $holdersByRole = @{}
    foreach ($grp in @($privPaths | Where-Object Plane -eq 'Entra' | Group-Object -Property Role)) { $holdersByRole[([string]$grp.Name).ToLowerInvariant()] = @($grp.Group | Select-Object -ExpandProperty Person -Unique).Count }
    foreach ($rk in @($policyByRole.Keys)) {
        $roleName = @($roleAssignments | Where-Object { $_.RoleDisplayName -and $_.RoleDisplayName.ToLowerInvariant() -eq $rk } | Select-Object -First 1 -ExpandProperty RoleDisplayName)
        if ($roleName.Count -eq 0) { continue }
        $tl = & $entraLevel $roleName[0]
        $holders = if ($holdersByRole.ContainsKey($rk)) { $holdersByRole[$rk] } else { 0 }
        & $checkPolicy 'Entra role' $roleName[0] $tl.Level $policyByRole[$rk] $holders
    }

    # PIM for Groups: the group's activation policy carries the level of the highest role the group holds.
    $groupTl = @{}
    foreach ($gk in @($groupRoles.Keys)) { $groupTl[$gk] = Get-P2HighestTl -Levels @($groupRoles[$gk] | ForEach-Object { $_.Tl.Level }) }
    foreach ($gk in @($policyByGroup.Keys)) {
        $gid = @($groupRoles.GetEnumerator() | Where-Object { ([string]$_.Value[0].GroupName).ToLowerInvariant() -eq $gk } | Select-Object -First 1)
        $level = if ($gid.Count -gt 0) { $groupTl[$gid[0].Key] } else { $null }
        if (-not $level) { continue }
        & $checkPolicy 'PIM for Groups' $gk $level $policyByGroup[$gk] $null
    }

    # Azure PIM policies (when collected).
    foreach ($ap in $azPolicies) {
        $roleRow = [pscustomobject]@{ RoleName = $ap.RoleName; ScopeLevel = $ap.ScopeLevel; ScopeName = $ap.ScopeName; ResourceGroup = $null; SubscriptionName = $ap.SubscriptionName; SubscriptionId = $null; PrivilegeTier = $ap.PrivilegeTier }
        $info = & $azLevel $roleRow
        $pol = [pscustomobject]@{
            MaxActivationHours = ConvertTo-P2Hours -Duration $ap.MaxActivationDuration
            ApprovalRequired = Test-P2True $ap.ApprovalRequired
            MfaRequired = Test-P2True $ap.MfaRequired
            AuthContext = Test-P2True $ap.AuthContextEnabled
            Justification = Test-P2True $ap.JustificationRequired
            PermanentEligible = Test-P2True $ap.PermanentEligibleAllowed
            PermanentActive = Test-P2True $ap.PermanentActiveAllowed
        }
        & $checkPolicy 'Azure role' "$($ap.RoleName) @ $($ap.ScopeName)" $info.Level $pol $null
    }

    # ---- Approvers and self-approval -----------------------------------------------------------
    $selfApproval = New-Object System.Collections.ArrayList
    $approverGroups = New-Object System.Collections.ArrayList
    $approversByRole = @{}
    foreach ($ap in $approverProfiles) {
        if (-not $ap.UserId) { continue }
        $rk = ([string]$ap.RoleName).ToLowerInvariant()
        if (-not $approversByRole.ContainsKey($rk)) { $approversByRole[$rk] = New-Object System.Collections.ArrayList }
        $null = $approversByRole[$rk].Add($ap)
    }

    $eligibleByRole = @{}
    foreach ($p in @($paths | Where-Object { $_.Plane -eq 'Entra' -and $_.RoleState -eq 'Eligible' })) {
        $rk = ([string]$p.Role).ToLowerInvariant()
        if (-not $eligibleByRole.ContainsKey($rk)) { $eligibleByRole[$rk] = New-Object System.Collections.ArrayList }
        $null = $eligibleByRole[$rk].Add($p)
    }

    foreach ($rk in @($approversByRole.Keys)) {
        $approvers = @($approversByRole[$rk])
        $roleName = $approvers[0].RoleName
        $tl = (& $entraLevel $roleName).Level
        $requesters = if ($eligibleByRole.ContainsKey($rk)) { @($eligibleByRole[$rk]) } else { @() }
        foreach ($req in $requesters) {
            foreach ($ap in $approvers) {
                $apId = ([string]$ap.UserId).ToLowerInvariant()
                $apPerson = & $personOf $apId
                if ($apPerson -ne $req.Person) { continue }
                $sameObject = $apId -eq $req.IdentityId
                $apIdent = if ($ident.ContainsKey($apId)) { $ident[$apId] } else { $null }
                $null = $selfApproval.Add([pscustomobject]@{
                    Tenant          = $TenantShortName
                    Plane           = 'Entra'
                    Role            = $roleName
                    TrustLevel      = $tl
                    Person          = $req.Person
                    RequesterAccount = if ($req.Upn) { $req.Upn } else { $req.Identity }
                    RequesterType   = $req.AccountType
                    RequestPath     = if ($req.ViaGroup) { "$($req.PathType) via $($req.ViaGroup)" } else { $req.PathType }
                    ApproverAccount = if ($ap.UserPrincipalName) { $ap.UserPrincipalName } else { $ap.DisplayName }
                    ApproverType    = if ($apIdent) { $apIdent.AccountType } else { $null }
                    ApproverVia     = if ($ap.SourceGroup) { $ap.SourceGroup } elseif ($ap.GroupName) { $ap.GroupName } else { 'Direct approver' }
                    Route           = if ($sameObject) { 'Same account (PIM blocks approving your own request, but approver and eligible populations overlap)' } else { 'Linked identity: requests as one account, approves as another (HLD F01)' }
                    Severity        = if ($sameObject) { if ($tl -eq 'TL1') { 'Medium' } else { 'Low' } } else { if ($tl -eq 'TL1') { 'Critical' } else { 'High' } }
                    LinkConfidence  = if ($ident.ContainsKey($req.IdentityId)) { $ident[$req.IdentityId].LinkConfidence } else { $null }
                })
            }
        }
    }

    foreach ($grp in @($approverProfiles | Where-Object { $_.UserId } | Group-Object -Property { if ($_.SourceGroup) { $_.SourceGroup } elseif ($_.GroupName) { $_.GroupName } else { 'Direct approvers' } })) {
        $members = @($grp.Group | Group-Object -Property UserId | ForEach-Object { $_.Group[0] })
        $roles = @($grp.Group | Select-Object -ExpandProperty RoleName -Unique)
        $roleTls = @($roles | ForEach-Object { (& $entraLevel $_).Level })
        $types = @($members | ForEach-Object { $k = ([string]$_.UserId).ToLowerInvariant(); if ($ident.ContainsKey($k)) { $ident[$k].AccountType } else { 'Unknown' } })
        $eligiblePeople = @{}
        foreach ($r in $roles) { $rk = ([string]$r).ToLowerInvariant(); if ($eligibleByRole.ContainsKey($rk)) { foreach ($p in $eligibleByRole[$rk]) { if ($p.Person) { $eligiblePeople[$p.Person] = $true } } } }
        $approverPeople = @($members | ForEach-Object { & $personOf $_.UserId } | Select-Object -Unique)
        $overlap = @($approverPeople | Where-Object { $eligiblePeople.ContainsKey($_) })
        $everydayCount = @($types | Where-Object { $_ -in @('Everyday', 'Guest') }).Count
        $issues = @()
        if ($everydayCount -gt 0) { $issues += "$everydayCount everyday/guest identities (HLD 7.6.3: CLAD only)" }
        if ($overlap.Count -gt 0) { $issues += "$($overlap.Count) of $($approverPeople.Count) approvers are themselves eligible for the roles they approve" }
        $null = $approverGroups.Add([pscustomobject]@{
            Tenant               = $TenantShortName
            ApproverGroup        = $grp.Name
            HighestTrustLevel    = Get-P2HighestTl -Levels $roleTls
            RolesApproved        = $roles.Count
            Roles                = ($roles -join '; ')
            Members              = $members.Count
            CladMembers          = @($types | Where-Object { $_ -eq 'CLAD' }).Count
            EverydayOrGuestMembers = $everydayCount
            OtherMembers         = @($types | Where-Object { $_ -notin @('CLAD', 'Everyday', 'Guest') }).Count
            ApproversAlsoEligible = $overlap.Count
            SelfApprovalPeople   = @($selfApproval | Where-Object { $_.ApproverVia -eq $grp.Name -and $_.Route -like 'Linked*' } | Select-Object -ExpandProperty Person -Unique).Count
            MeetsHld763          = ($everydayCount -eq 0 -and $overlap.Count -eq 0)
            Issues               = ($issues -join '; ')
        })
    }

    # ---- Group bundles ------------------------------------------------------------------------
    $groupBundles = New-Object System.Collections.ArrayList
    foreach ($gk in @($groupRoles.Keys)) {
        $roles = @($groupRoles[$gk])
        $tls = @($roles | ForEach-Object { $_.Tl.Level })
        $hasTl1 = $tls -contains 'TL1'
        $members = @($paths | Where-Object { $_.ViaGroupId -eq $gk } | Select-Object -ExpandProperty Person -Unique)
        $eligibleMembers = @($paths | Where-Object { $_.ViaGroupId -eq $gk -and $_.MembershipState -eq 'Eligible' } | Select-Object -ExpandProperty Person -Unique)
        $distinctLevels = @($tls | Select-Object -Unique)
        $isBundle = $roles.Count -gt 1
        $rec = 'Retain - validate with role owner'
        if (@($roles | Where-Object { $_.Role -eq 'Global Administrator' }).Count -gt 0) { $rec = 'Remove Global Administrator (assign it directly to named CLADs only)' + $(if ($isBundle) { '; split the other TL1 roles out to direct eligible or single-purpose groups (HLD 7.6.1)' } else { '' }) }
        elseif ($hasTl1 -and $isBundle) { $rec = 'Split: move TL1 roles to direct eligible assignment or a single-purpose TL1 group (HLD 7.6.1)' }
        elseif ($isBundle -and $distinctLevels.Count -gt 1) { $rec = 'Rebuild bundle so it holds one trust level only (runbook 4.2)' }
        elseif ($hasTl1) { $rec = 'Single-purpose TL1 group: keep only if membership is small and owned' }
        $null = $groupBundles.Add([pscustomobject]@{
            Tenant          = $TenantShortName
            Group           = $roles[0].GroupName
            Roles           = $roles.Count
            HighestTrustLevel = Get-P2HighestTl -Levels $tls
            TL1Roles        = (@($roles | Where-Object { $_.Tl.Level -eq 'TL1' } | Select-Object -ExpandProperty Role -Unique) -join '; ')
            TL2Roles        = @($roles | Where-Object { $_.Tl.Level -eq 'TL2' }).Count
            TL3Roles        = @($roles | Where-Object { $_.Tl.Level -eq 'TL3' }).Count
            ActiveRoles     = @($roles | Where-Object { $_.State -eq 'Active' }).Count
            EligibleRoles   = @($roles | Where-Object { $_.State -eq 'Eligible' }).Count
            People          = $members.Count
            EligibleMembers = $eligibleMembers.Count
            Recommendation  = $rec
            AllRoles        = (@($roles | ForEach-Object { "$($_.Role) [$($_.Tl.Level), $($_.State)]" } | Select-Object -Unique) -join '; ')
            GroupId         = $gk
        })
    }
    $groupBundles = @($groupBundles | Sort-Object -Property @{ Expression = { Get-P2TlRank -Level $_.HighestTrustLevel }; Descending = $true }, @{ Expression = 'People'; Descending = $true })

    # ---- Registers ----------------------------------------------------------------------------
    $tl1Paths = @($privPaths | Where-Object { $_.TrustLevel -eq 'TL1' } | Sort-Object Plane, Role, Person)
    $standing = @($privPaths | Where-Object { $_.Standing } | Sort-Object @{ Expression = { Get-P2TlRank -Level $_.TrustLevel }; Descending = $true }, Plane, Role)

    # Identity register.
    $identityRows = New-Object System.Collections.ArrayList
    foreach ($grp in @($privPaths | Group-Object -Property IdentityId)) {
        $k = $grp.Name
        $e = if ($ident.ContainsKey($k)) { $ident[$k] } else { $null }
        $rows = @($grp.Group)
        $a = if ($assuranceById.ContainsKey($k)) { $assuranceById[$k] } else { $null }
        $lic = if ($licenceById.ContainsKey($k)) { $licenceById[$k] } else { $null }
        $ctx = if ($contextById.ContainsKey($k)) { $contextById[$k] } else { $null }
        $auth = if ($authById.ContainsKey($k)) { $authById[$k] } else { $null }
        $skus = [string](Get-P2Prop $lic 'SkuPartNumbers')
        $hasP2 = $skus -match 'AAD_PREMIUM_P2|EMSPREMIUM|SPE_E5|IDENTITY_GOVERNANCE|M365_E5|ENTERPRISEPREMIUM|Microsoft_Entra_ID_Governance|SPE_E7|M365_E7'
        $productivity = $skus -match 'ENTERPRISEPACK|SPE_E3|SPE_E5|STANDARDPACK|EXCHANGESTANDARD|EXCHANGEENTERPRISE|O365_BUSINESS|SPB|M365_E|SPE_F|TEAMS'
        $phishingResistant = $null
        if ($auth) { $phishingResistant = Test-P2True (Get-P2Prop $auth 'HasPhishingResistant') }
        elseif ($a) { $phishingResistant = Test-P2True $a.HasPhishingResistantMfa }
        $hasFido2 = if ($auth) { Test-P2True (Get-P2Prop $auth 'HasFido2') } else { $null }

        $issues = New-Object System.Collections.ArrayList
        $type = if ($e) { $e.AccountType } else { 'Unknown' }
        $highest = Get-P2HighestTl -Levels @($rows | ForEach-Object { $_.TrustLevel })
        if ($type -eq 'Everyday') { $null = $issues.Add('Everyday identity holds privilege (SEC-PIM-08)') }
        if ($type -eq 'Guest') { $null = $issues.Add('Guest identity holds privilege') }
        if ($type -eq 'Generic/Service') { $null = $issues.Add('Generic or service user account holds privilege (HLD 7.9)') }
        if ($type -eq 'CLAD' -and $e.LinkConfidence -eq 'No everyday identity in evidence') { $null = $issues.Add('Everyday identity not found in the evidence; confirm the link (runbook 2.2)') }
        if ($type -in @('CLAD', 'Other admin account') -and $productivity) { $null = $issues.Add('Admin identity has a productivity licence (HLD DP02)') }
        if ($type -in @('CLAD', 'Other admin account', 'Everyday', 'Guest') -and $lic -and -not $hasP2) { $null = $issues.Add('No Entra ID P2 licence seen (OD-14)') }
        if ($highest -eq 'TL1' -and $phishingResistant -eq $false) { $null = $issues.Add('TL1 without phishing-resistant method (SEC-PIM-06)') }
        if ($e -and $e.AccountEnabled -eq $false) { $null = $issues.Add('Disabled account still holds access') }
        $synced = Get-P2Prop $ctx 'OnPremisesSyncEnabled'
        if ($type -in @('CLAD', 'Other admin account') -and (Test-P2True $synced)) { $null = $issues.Add('Admin identity synchronised from on-premises AD') }

        $null = $identityRows.Add([pscustomobject]@{
            Tenant            = $TenantShortName
            Identity          = if ($e) { $e.DisplayName } else { $k }
            Upn               = if ($e) { $e.Upn } else { $null }
            AccountType       = $type
            Organisation      = if ($e) { $e.Organisation } else { $null }
            OrganisationType  = if ($e) { $e.OrganisationType } else { $null }
            PersonOrganisation = $rows[0].PersonOrganisation
            Person            = & $personOf $k
            LinkedEveryday    = if ($e) { $e.LinkedEveryday } else { $null }
            LinkConfidence    = if ($e) { $e.LinkConfidence } else { $null }
            HighestTrustLevel = $highest
            TL1Paths          = @($rows | Where-Object TrustLevel -eq 'TL1').Count
            TL2Paths          = @($rows | Where-Object TrustLevel -eq 'TL2').Count
            TL3Paths          = @($rows | Where-Object TrustLevel -eq 'TL3').Count
            StandingPaths     = @($rows | Where-Object Standing).Count
            EntraRoles        = @($rows | Where-Object Plane -eq 'Entra' | Select-Object -ExpandProperty Role -Unique).Count
            AzurePaths        = @($rows | Where-Object Plane -eq 'Azure').Count
            TL1Roles          = (@($rows | Where-Object TrustLevel -eq 'TL1' | ForEach-Object { if ($_.Plane -eq 'Azure') { "$($_.Role) @ $($_.Scope)" } else { $_.Role } } | Select-Object -Unique | Select-Object -First 8) -join '; ')
            PhishingResistant = $phishingResistant
            HasFido2          = $hasFido2
            AuthStrength      = Get-P2Prop $a 'AuthStrength'
            HasP2Licence      = if ($lic) { [bool]$hasP2 } else { $null }
            Licences          = $skus
            AccountEnabled    = if ($e) { $e.AccountEnabled } else { $null }
            LastSignIn        = Get-P2Prop $ctx 'LastSignIn'
            Issues            = ($issues -join '; ')
            IdentityId        = $k
        })
    }
    $identityRows = @($identityRows | Sort-Object @{ Expression = { Get-P2TlRank -Level $_.HighestTrustLevel }; Descending = $true }, AccountType, Identity)

    # Role catalogue extract (runbook 1.2).
    $catalogueRows = New-Object System.Collections.ArrayList
    foreach ($grp in @($paths | Group-Object -Property Plane, Role, ScopeLevel)) {
        $rows = @($grp.Group)
        $first = $rows[0]
        $levels = @($rows | Select-Object -ExpandProperty TrustLevel -Unique)
        $null = $catalogueRows.Add([pscustomobject]@{
            Tenant          = $TenantShortName
            Plane           = $first.Plane
            Role            = $first.Role
            ScopeLevel      = $first.ScopeLevel
            TrustLevel      = Get-P2HighestTl -Levels $levels
            Classification  = if ($first.Plane -eq 'Entra') { $first.TrustLevelSource } else { 'HLD 7.11.2 matrix' }
            Rationale       = if ($first.Plane -eq 'Entra') { (& $entraLevel $first.Role).Rationale } else { (@($rows | Select-Object -ExpandProperty TrustLevelSource -Unique | Select-Object -First 2) -join ' / ') }
            People          = @($rows | Select-Object -ExpandProperty Person -Unique).Count
            DirectPaths     = @($rows | Where-Object PathType -eq 'Direct').Count
            GroupPaths      = @($rows | Where-Object PathType -ne 'Direct').Count
            EligiblePaths   = @($rows | Where-Object EffectiveState -eq 'Eligible').Count
            StandingPaths   = @($rows | Where-Object Standing).Count
            PolicyGaps      = if ($first.Plane -eq 'Entra' -and $policyCompliance.ContainsKey("entra role|$(([string]$first.Role).ToLowerInvariant())")) { $policyCompliance["entra role|$(([string]$first.Role).ToLowerInvariant())"] } else { $null }
            RoleOwner       = 'TBC'
        })
    }
    $catalogueRows = @($catalogueRows | Sort-Object @{ Expression = { Get-P2TlRank -Level $_.TrustLevel }; Descending = $true }, Plane, Role, ScopeLevel)

    # ---- CLAD provisioning: every person doing admin work from an everyday or guest account needs a CLAD ----
    $cladUpnPrefix = if ($idRules.CladUpnPrefixes) { [string]@($idRules.CladUpnPrefixes)[0] } else { 'clad_' }
    $cladFormat = if ($idRules.CladDisplayNameFormat) { [string]$idRules.CladDisplayNameFormat } else { '(Cloud Admin) {First} {Last}' }
    $existingClads = @($ident.Values | Where-Object { $_.AccountType -eq 'CLAD' -and $_.Upn })
    $cladDomain = if ($idRules.CladUpnDomain) { [string]$idRules.CladUpnDomain } else {
        $d = @($existingClads | ForEach-Object { ([string]$_.Upn).Split('@')[-1].ToLowerInvariant() } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1)
        if ($d.Count -gt 0) { $d[0].Name } elseif ($tenantDetails -and $tenantDetails.PrimaryDomain) { [string]$tenantDetails.PrimaryDomain } else { 'tenant.onmicrosoft.com' }
    }
    $takenLocal = @{}
    foreach ($c in $existingClads) { $takenLocal[(([string]$c.Upn).Split('@')[0]).ToLowerInvariant()] = $c }
    $cladByPerson = @{}
    foreach ($c in $existingClads + @($ident.Values | Where-Object { $_.AccountType -eq 'CLAD' -and -not $_.Upn })) { if ($c.PersonKey -and -not $cladByPerson.ContainsKey($c.PersonKey)) { $cladByPerson[$c.PersonKey] = $c } }
    $approverIds = @{}
    foreach ($ap in $approverProfiles) { if ($ap.UserId) { $approverIds[([string]$ap.UserId).ToLowerInvariant()] = $true } }

    $splitName = {
        param($Entry)
        $first = $null; $last = $null
        $dn = ([string]$Entry.DisplayName) -replace '\[[^\]]*\]', '' -replace '\([^)]*\)', ''
        if ($dn -match '^\s*([^,]+),\s*(.+)$') { $last = $Matches[1]; $first = $Matches[2] }
        else {
            $tok = @($dn.Trim() -split '\s+' | Where-Object { $_ })
            if ($tok.Count -ge 2) { $first = $tok[0]; $last = $tok[$tok.Count - 1] }
        }
        if ((-not $first -or -not $last) -and ([string]$Entry.Upn) -match '^([A-Za-z]+)\.([A-Za-z''-]+)[_@]') { $first = $Matches[1]; $last = $Matches[2] }
        if (-not $first -or -not $last) { return $null }
        $first = ($first.Trim() -split '\s+')[0]
        $tc = (New-Object System.Globalization.CultureInfo('en-GB')).TextInfo
        return [pscustomobject]@{
            First = $first.Trim(); Last = $last.Trim()
            FirstKey = ($first.ToLowerInvariant() -replace '[^a-z]', ''); LastKey = ($last.ToLowerInvariant() -replace '[^a-z]', '')
            Display = ($cladFormat -replace '\{First\}', $first.Trim() -replace '\{Last\}', $last.Trim())
        }
    }

    $cladRows = New-Object System.Collections.ArrayList
    $candidates = @{}
    foreach ($e in $ident.Values) {
        if ($e.AccountType -notin @('Everyday', 'Guest')) { continue }
        $routes = @($privPaths | Where-Object IdentityId -eq $e.Id)
        $isApprover = $approverIds.ContainsKey($e.Id)
        if ($routes.Count -eq 0 -and -not $isApprover) { continue }
        $candidates[$e.Id] = [pscustomobject]@{ Entry = $e; Routes = $routes; IsApprover = $isApprover }
    }
    foreach ($cand in @($candidates.Values | Sort-Object { $_.Entry.DisplayName })) {
        $e = $cand.Entry
        $routes = @($cand.Routes)
        $nm = & $splitName $e
        $existing = $null; $match = 'None'
        if ($e.PersonKey -and $cladByPerson.ContainsKey($e.PersonKey)) { $existing = $cladByPerson[$e.PersonKey]; $match = 'Same person' }
        elseif ($nm -and $nm.LastKey) {
            # Older CLADs sometimes shorten the surname (clad_braitd); treat a shared 5-letter surname stem plus the first initial as a probable match.
            $stem = $nm.LastKey.Substring(0, [Math]::Min(5, $nm.LastKey.Length))
            $hit = @($existingClads | Where-Object { $l = (([string]$_.Upn).Split('@')[0]).ToLowerInvariant(); $l.StartsWith($cladUpnPrefix.ToLowerInvariant() + $stem) -and $l.EndsWith($nm.FirstKey.Substring(0, 1)) })
            if ($hit.Count -eq 1) { $existing = $hit[0]; $match = 'Naming pattern - confirm' }
        }
        $proposed = $null
        if (-not $existing -and $nm -and $nm.LastKey -and $nm.FirstKey) {
            for ($n = 1; $n -le $nm.FirstKey.Length; $n++) {
                $local = ($cladUpnPrefix + $nm.LastKey + $nm.FirstKey.Substring(0, $n)).ToLowerInvariant()
                if (-not $takenLocal.ContainsKey($local)) { $proposed = "$local@$cladDomain"; $takenLocal[$local] = $e; break }
            }
        }
        $highest = Get-P2HighestTl -Levels @($routes | ForEach-Object { $_.TrustLevel })
        $roleList = @($routes | ForEach-Object { if ($_.Plane -eq 'Azure') { "$($_.Role) @ $($_.Scope)" } else { $_.Role } } | Select-Object -Unique)
        $orgType = if ($e.PersonKey -and $personOrg.ContainsKey($e.PersonKey)) { $personOrg[$e.PersonKey].Type } else { $e.OrganisationType }
        $orgName = if ($e.PersonKey -and $personOrg.ContainsKey($e.PersonKey)) { $personOrg[$e.PersonKey].Name } else { $e.Organisation }
        $notes = New-Object System.Collections.ArrayList
        if ($cand.IsApprover) { $null = $notes.Add('Everyday account is a PIM approver: replace it in the approver group with an admin account (HLD 7.6.3)') }
        if ($orgType -eq 'Supplier') { $null = $notes.Add('Supplier: CLAD only if agreed under OD-09, with sponsor and contract end date') }
        if ($e.AccountType -eq 'Guest' -and $orgType -ne 'Supplier') { $null = $notes.Add('Guest everyday account: tenant CLAD per the agreed pattern (OD-09)') }
        if (-not $existing -and -not $proposed) { $null = $notes.Add('Name could not be parsed: choose the CLAD name manually') }
        if ($proposed) { $null = $notes.Add('Check the directory for an existing account of this name before creating') }
        $action = if ($routes.Count -eq 0) { if ($existing) { 'Approver only: replace everyday account with existing CLAD' } else { 'Approver only: create CLAD' } }
                  elseif ($existing) { 'Move rights to existing CLAD' } else { 'Create CLAD and move rights' }
        $null = $cladRows.Add([pscustomobject]@{
            Tenant              = $TenantShortName
            Person              = & $personOf $e.Id
            Organisation        = $orgName
            OrganisationType    = $orgType
            EverydayAccount     = if ($e.Upn) { $e.Upn } else { $e.DisplayName }
            AccountType         = $e.AccountType
            HighestTrustLevel   = $highest
            Action              = $action
            ExistingClad        = if ($existing) { if ($existing.Upn) { $existing.Upn } else { $existing.DisplayName } } else { $null }
            ExistingCladMatch   = $match
            ProposedCladUpn     = $proposed
            ProposedDisplayName = if ($proposed -and $nm) { $nm.Display } else { $null }
            RoutesToMove        = $routes.Count
            TL1Routes           = @($routes | Where-Object TrustLevel -eq 'TL1').Count
            PermanentRoutes     = @($routes | Where-Object Standing).Count
            IsApprover          = $cand.IsApprover
            RolesToMove         = (($roleList | Select-Object -First 25) -join '; ')
            Notes               = ($notes -join ' | ')
            EverydayObjectId    = $e.Id
        })
    }
    $cladRows = @($cladRows | Sort-Object @{ Expression = { Get-P2TlRank -Level $_.HighestTrustLevel }; Descending = $true }, Action, Person)

    # ---- Access review plan: every privileged role, PIM group and Azure subscription is reviewed on a trust-level cycle ----
    $reviewCycle = @{ TL1 = 'Quarterly'; TL2 = 'Six-monthly'; TL3 = 'Annually' }
    $reviewDays = @{ TL1 = 7; TL2 = 14; TL3 = 14 }
    $reviewer = @{
        TL1 = 'Named security reviewer who does not hold the role (not self-review); second stage: role owner'
        TL2 = 'Service or role owner (not self-review)'
        TL3 = 'Team lead or line manager'
    }
    $reviewSettings = 'Auto-apply results; remove access if not reviewed; justification required; reviewer recommendations on (inactive 30 days)'
    $existingReviewText = @($accessReviews | ForEach-Object { "$($_.DisplayName) $($_.Description)" })
    $findExisting = {
        param($Name)
        if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
        $hit = @($accessReviews | Where-Object { ([string]$_.DisplayName + ' ' + [string]$_.Description) -like "*$Name*" } | Select-Object -ExpandProperty DisplayName)
        if ($hit.Count -gt 0) { return ($hit -join '; ') }
        return $null
    }
    $reviewPlan = New-Object System.Collections.ArrayList
    $addReview = {
        param($Tl, $Target, $Type, $Scope, $People, $Notes)
        if (-not $reviewCycle.ContainsKey([string]$Tl)) { return }
        $null = $reviewPlan.Add([pscustomobject]@{
            Tenant = $TenantShortName; TrustLevel = $Tl; Target = $Target; ReviewType = $Type; Scope = $Scope
            People = $People; Frequency = $reviewCycle[$Tl]; DurationDays = $reviewDays[$Tl]; Reviewers = $reviewer[$Tl]
            Settings = $reviewSettings; ExistingReview = & $findExisting ($Target -replace '^[^:]+:\s*', ''); Notes = $Notes
        })
    }
    # Entra roles held directly (role reviews in PIM).
    foreach ($g in @($privPaths | Where-Object { $_.Plane -eq 'Entra' -and $_.PathType -eq 'Direct' -and $_.AccountType -notin @('WorkloadIdentity', 'BreakGlass') } | Group-Object Role)) {
        $tl = Get-P2HighestTl -Levels @($g.Group | ForEach-Object { $_.TrustLevel })
        & $addReview $tl "Entra role: $($g.Name)" 'PIM access review of the Entra role (eligible and active assignments)' 'Direct assignments' @($g.Group | Select-Object -ExpandProperty Person -Unique).Count $(if ($g.Name -eq 'Global Administrator') { 'Break-glass accounts excluded and reviewed separately' } else { $null })
    }
    # Groups that hold roles (PIM for Groups membership reviews), at the level of the highest role they grant.
    foreach ($b in $groupBundles) {
        & $addReview $b.HighestTrustLevel "Group: $($b.Group)" 'Access review of group membership (PIM for Groups eligible and active members)' "Members; grants $($b.Roles) role(s)" $b.People $(if ([int]$b.Roles -gt 1) { 'Review again once the group is rebuilt to a single trust level' } else { $null })
    }
    # Azure subscriptions with privileged human access.
    foreach ($g in @($privPaths | Where-Object { $_.Plane -eq 'Azure' -and $_.AccountType -in @('CLAD', 'Other admin account', 'Everyday', 'Guest', 'Generic/Service') -and $_.TrustLevel -in @('TL1', 'TL2') -and $_.SubscriptionName } | Group-Object SubscriptionName)) {
        $tl = Get-P2HighestTl -Levels @($g.Group | ForEach-Object { $_.TrustLevel })
        & $addReview $tl "Azure subscription: $($g.Name)" 'PIM access review of Azure resource roles' 'Owner, User Access Administrator, Contributor and data-plane roles at subscription and below' @($g.Group | Select-Object -ExpandProperty Person -Unique).Count 'Needs PIM for Azure resources enabled on the subscription'
    }
    # Cross-cutting reviews.
    $guestPeople = @($privPaths | Where-Object { $_.AccountType -eq 'Guest' -or $_.PersonOrganisationType -eq 'Supplier' } | Select-Object -ExpandProperty Person -Unique).Count
    if ($guestPeople -gt 0) { & $addReview 'TL1' 'Guest and supplier accounts with admin rights' 'Access review of guest users in privileged groups and roles' 'All guest and supplier identities with any admin route' $guestPeople 'Reviewer: the named sponsor for each supplier; tie expiry to the contract' }
    $cladCount = @($ident.Values | Where-Object AccountType -eq 'CLAD').Count
    if ($cladCount -gt 0) { & $addReview 'TL2' 'All CLAD accounts' 'Access review of the CLAD account population (a dynamic group of admin accounts)' 'Every CLAD; flag CLADs whose everyday account is disabled or that have not signed in for 90 days' $cladCount 'Supports leaver removal (HLD F07)' }
    $apprCount = @($approverProfiles | Where-Object UserId | Select-Object -ExpandProperty UserId -Unique).Count
    if ($apprCount -gt 0) { & $addReview 'TL1' 'PIM approver groups' 'Access review of approver group membership' 'Approver groups for TL1 and TL2 roles' $apprCount 'Confirm approvers are admin accounts and not eligible for the roles they approve (HLD 7.6.3)' }
    $reviewPlan = @($reviewPlan | Sort-Object @{ Expression = { Get-P2TlRank -Level $_.TrustLevel }; Descending = $true }, Target)

    # ---- Migration worksheet -------------------------------------------------------------------
    $bundleByGroup = @{}
    foreach ($b in $groupBundles) { $bundleByGroup[$b.GroupId] = $b }
    $migration = New-Object System.Collections.ArrayList
    foreach ($p in $privPaths) {
        $actions = New-Object System.Collections.ArrayList
        $e = if ($ident.ContainsKey($p.IdentityId)) { $ident[$p.IdentityId] } else { $null }
        $tlb = & $baselineOf $p.TrustLevel
        switch ($p.AccountType) {
            'BreakGlass' { $null = $actions.Add('Retain: break-glass exception (HLD 7.13)') }
            'WorkloadIdentity' { $null = $actions.Add('Inventory only: non-human identity, out of Phase 2 scope (R15)') }
            'Generic/Service' { $null = $actions.Add('Replace with a named identity or workload identity, or record an exception (HLD 7.9, runbook 5.6)') }
            'Everyday' { $null = $actions.Add("Move to the person's CLAD account (see P2_CladProvisioning.csv; SEC-PIM-08)") }
            'Guest' { $null = $actions.Add('Confirm sponsor, organisation and expiry; decide guest vs tenant CLAD pattern (OD-09, runbook 5.6)') }
            'Unknown' { $null = $actions.Add('Identify the principal; remove if orphaned') }
            'Unresolved' { $null = $actions.Add('Principal could not be read: check the reviewing account can read directory objects, then re-run') }
            'Deleted identity' { $null = $actions.Add('Remove: the identity has been deleted') }
            'Other tenant principal' { $null = $actions.Add('Identify the external organisation and confirm the access is still needed') }
        }
        if ($e -and $e.AccountEnabled -eq $false) { $null = $actions.Add('Remove: account disabled') }
        if ($p.AccountType -notin @('BreakGlass', 'WorkloadIdentity')) {
            if ($p.Plane -eq 'Entra' -and $p.Role -eq 'Global Administrator' -and $p.PathType -ne 'Direct') {
                $null = $actions.Add('Global Administrator is never group-assigned: assign it directly as eligible to the named CLAD (if in the agreed population) and remove it from the group')
            }
            if ($p.Standing -and $tlb -and $tlb.PermanentActiveAllowed -eq $false) {
                if ($p.Plane -eq 'Azure') { $null = $actions.Add('Convert to eligible through PIM for Azure resources at the narrowest scope (HLD 7.11.4)') }
                else { $null = $actions.Add('Convert standing access to eligible (SEC-PIM-03)') }
            }
            if ($p.TrustLevel -eq 'TL1' -and $p.ViaGroupId -and $bundleByGroup.ContainsKey($p.ViaGroupId) -and $bundleByGroup[$p.ViaGroupId].Roles -gt 1) {
                $null = $actions.Add('Move TL1 out of the operational bundle to direct eligible or a single-purpose group (HLD 7.6.1)')
            }
            if ($p.Plane -eq 'Azure' -and $p.TrustLevel -eq 'TL1' -and $p.ScopeLevel -in @('Root', 'ManagementGroup')) {
                $null = $actions.Add('Confirm Azure platform team ownership; root and MG scope limited to platform team (HLD 7.11.4)')
            }
            if ($p.EffectiveState -eq 'Eligible' -and [string]::IsNullOrWhiteSpace($p.EndDateTime) -and $tlb -and $tlb.PermanentEligibleAllowed -eq $false) {
                $null = $actions.Add("Set eligibility expiry ($($p.TrustLevel) review every $($tlb.ReviewMonths) months)")
            }
            if ($p.PersonOrganisationType -eq 'Supplier') { $null = $actions.Add('Supplier: named sponsor, contract expiry as eligibility end date (runbook 5.6)') }
        }
        if ($actions.Count -eq 0) { $null = $actions.Add('Retain: validate need with role owner during rebaseline (SEC-PIM-19)') }

        $null = $migration.Add([pscustomobject]@{
            Tenant         = $TenantShortName
            Person         = $p.Person
            Identity       = $p.Identity
            Upn            = $p.Upn
            AccountType    = $p.AccountType
            Organisation   = $p.PersonOrganisation
            Plane          = $p.Plane
            Role           = $p.Role
            Scope          = $p.Scope
            TrustLevel     = $p.TrustLevel
            CurrentPath    = if ($p.ViaGroup) { "$($p.PathType) - $($p.ViaGroup)" } else { $p.PathType }
            CurrentState   = if ($p.Standing) { 'Standing (permanent active)' } elseif ($p.EffectiveState -eq 'Eligible') { 'Eligible' } else { 'Active (time-bound)' }
            ProposedActions = ($actions -join ' | ')
            TargetPath     = ''
            Wave           = ''
            RoleOwner      = 'TBC'
            Decision       = ''
        })
    }
    $migration = @($migration | Sort-Object Person, @{ Expression = { Get-P2TlRank -Level $_.TrustLevel }; Descending = $true }, Plane, Role)

    # ---- Exception candidates ------------------------------------------------------------------
    $exceptions = New-Object System.Collections.ArrayList
    foreach ($grp in @($privPaths | Where-Object { $_.AccountType -eq 'BreakGlass' } | Group-Object IdentityId)) {
        $f = $grp.Group[0]
        $null = $exceptions.Add([pscustomobject]@{ Tenant = $TenantShortName; Category = 'Break-glass'; Subject = $f.Identity; Detail = "$($grp.Count) path(s): $(@($grp.Group | Select-Object -ExpandProperty Role -Unique) -join ', ')"; HldReference = 'HLD 7.13, SEC-PIM-16'; RequiredEvidence = 'Two accounts, tested, alerted, excluded from CA only where necessary' })
    }
    foreach ($grp in @($privPaths | Where-Object { $_.AccountType -eq 'Generic/Service' } | Group-Object IdentityId)) {
        $f = $grp.Group[0]
        $null = $exceptions.Add([pscustomobject]@{ Tenant = $TenantShortName; Category = 'Generic / service user account'; Subject = $f.Identity; Detail = "$(Get-P2HighestTl -Levels @($grp.Group | ForEach-Object { $_.TrustLevel })) access: $(@($grp.Group | Select-Object -ExpandProperty Role -Unique | Select-Object -First 6) -join ', ')"; HldReference = 'HLD 7.9 shared/generic accounts, SEC-PIM-17'; RequiredEvidence = 'Platform cannot support named access; vaulting, check-out, logging, expiry' })
    }
    foreach ($grp in @($standing | Where-Object { $_.TrustLevel -in @('TL1', 'TL2') -and $_.AccountType -in @('CLAD', 'Other admin account', 'Everyday', 'Guest') } | Group-Object Person)) {
        $null = $exceptions.Add([pscustomobject]@{ Tenant = $TenantShortName; Category = 'Standing TL1/TL2 access'; Subject = $grp.Name; Detail = (@($grp.Group | ForEach-Object { "$($_.Role) ($($_.Plane) $($_.Scope))" } | Select-Object -Unique | Select-Object -First 6) -join '; '); HldReference = 'SEC-PIM-03, SEC-PIM-21'; RequiredEvidence = 'Convert to eligible, or risk owner, compensating control, expiry' })
    }
    foreach ($grp in @($privPaths | Where-Object { $_.AccountType -eq 'WorkloadIdentity' -and $_.TrustLevel -eq 'TL1' } | Group-Object IdentityId)) {
        $f = $grp.Group[0]
        $null = $exceptions.Add([pscustomobject]@{ Tenant = $TenantShortName; Category = 'Non-human TL1 (R15)'; Subject = $f.Identity; Detail = (@($grp.Group | ForEach-Object { "$($_.Role) @ $($_.Scope)" } | Select-Object -Unique | Select-Object -First 5) -join '; '); HldReference = 'R15'; RequiredEvidence = 'Named owner accepts exclusion; inventory recorded' })
    }

    # ---- HLD findings --------------------------------------------------------------------------
    $people = @($privPaths | Where-Object { $_.AccountType -notin @('WorkloadIdentity', 'BreakGlass', 'Group', 'Unknown', 'Unresolved', 'Deleted identity', 'Other tenant principal') } | Select-Object -ExpandProperty Person -Unique)
    $gaPeople = @($privPaths | Where-Object { $_.Plane -eq 'Entra' -and $_.Role -eq 'Global Administrator' -and $_.AccountType -notin @('BreakGlass', 'WorkloadIdentity') } | Select-Object -ExpandProperty Person -Unique)
    $tl1People = @($tl1Paths | Where-Object { $_.AccountType -notin @('BreakGlass', 'WorkloadIdentity', 'Unresolved', 'Deleted identity', 'Other tenant principal') } | Select-Object -ExpandProperty Person -Unique)
    $selfApprovalPeople = @($selfApproval | Where-Object { $_.Route -like 'Linked*' } | Select-Object -ExpandProperty Person -Unique)
    $selfApprovalTl1People = @($selfApproval | Where-Object { $_.Route -like 'Linked*' -and $_.TrustLevel -eq 'TL1' } | Select-Object -ExpandProperty Person -Unique)
    $approverEveryday = @($approverGroups | Where-Object { $_.EverydayOrGuestMembers -gt 0 })
    $tl1InBundles = @($groupBundles | Where-Object { $_.TL1Roles -and $_.Roles -gt 1 })
    $standingHuman = @($standing | Where-Object { $_.AccountType -in @('CLAD', 'Other admin account', 'Everyday', 'Guest', 'Generic/Service') })
    $tl1NoPr = @($identityRows | Where-Object { $_.HighestTrustLevel -eq 'TL1' -and $_.PhishingResistant -eq $false -and $_.AccountType -notin @('BreakGlass', 'WorkloadIdentity') })
    $cladUnlinked = @($identityRows | Where-Object { $_.AccountType -eq 'CLAD' -and $_.LinkConfidence -eq 'No everyday identity in evidence' })
    $disabled = @($identityRows | Where-Object { $_.AccountEnabled -eq $false })
    $suppliers = @($identityRows | Where-Object { $_.OrganisationType -eq 'Supplier' })
    $generic = @($identityRows | Where-Object { $_.AccountType -eq 'Generic/Service' })
    $everydayPriv = @($identityRows | Where-Object { $_.AccountType -eq 'Everyday' })
    $purviewRoles = @($privPaths | Where-Object { $_.Plane -eq 'Entra' -and $_.Role -match 'Purview|eDiscovery|Compliance' })
    $noP2 = @($identityRows | Where-Object { $_.HasP2Licence -eq $false -and $_.AccountType -in @('CLAD', 'Other admin account', 'Everyday', 'Guest') })
    $caDevice = @($caPolicies | Where-Object { $_.State -eq 'enabled' -and [string]$_.GrantControls -match 'compliantDevice|domainJoinedDevice' -and ($_.IncludeRoleIds -or [string]$_.PolicyName -match '(?i)admin|privileg') })
    $tl1PolicyGaps = @($policyGaps | Where-Object TrustLevel -eq 'TL1')
    $azStandingTl1 = @($standingHuman | Where-Object { $_.Plane -eq 'Azure' -and $_.TrustLevel -eq 'TL1' -and $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') })
    $azRoot = @($privPaths | Where-Object { $_.Plane -eq 'Azure' -and $_.ScopeLevel -eq 'Root' -and $_.AccountType -ne 'WorkloadIdentity' })
    $breakGlass = @($identityRows | Where-Object AccountType -eq 'BreakGlass')

    $finding = {
        param($Id, $Title, $Status, $Measure, $Evidence)
        [pscustomobject]@{ Tenant = $TenantShortName; Finding = $Id; Title = $Title; Status = $Status; Measure = $Measure; Evidence = $Evidence }
    }
    $hld = @(
        (& $finding 'F01' 'Self-approval' $(if (-not $hasEntra) { 'Not assessed' } elseif ($selfApprovalPeople.Count -gt 0 -or $approverEveryday.Count -gt 0) { 'Confirmed' } else { 'Not observed' }) "$($selfApprovalPeople.Count) people can approve their own elevation through a linked identity ($($selfApprovalTl1People.Count) for TL1); $($approverEveryday.Count) approver group(s) contain everyday/guest identities" 'P2_SelfApproval.csv, P2_ApproverGroups.csv'),
        (& $finding 'F02' 'Broad high-impact eligibility' $(if ($gaPeople.Count -gt 5) { 'Confirmed' } elseif ($gaPeople.Count -gt 0) { 'Partially' } else { 'Not observed' }) "$($gaPeople.Count) people can reach Global Administrator; $($tl1People.Count) people can reach a TL1 role" 'P2_TL1Paths.csv'),
        (& $finding 'F03' 'Role aggregation' $(if ($tl1InBundles.Count -gt 0) { 'Confirmed' } else { 'Not observed' }) "$($tl1InBundles.Count) group(s) bundle TL1 roles with other roles; largest bundle $((@($groupBundles | Sort-Object Roles -Descending | Select-Object -First 1 | ForEach-Object { "$($_.Group) ($($_.Roles) roles)" })) -join '')" 'P2_GroupBundles.csv'),
        (& $finding 'F04' 'Standing privilege outside PIM' $(if ($standingHuman.Count -gt 0) { 'Confirmed' } else { 'Not observed' }) "$($standingHuman.Count) standing privileged paths held by people ($(@($standingHuman | Where-Object Plane -eq 'Entra').Count) Entra, $(@($standingHuman | Where-Object Plane -eq 'Azure').Count) Azure)" 'P2_StandingAccess.csv'),
        (& $finding 'F05' 'Authentication assurance' $(if ($assurance.Count -eq 0 -and $authMethods.Count -eq 0) { 'Not assessed' } elseif ($tl1NoPr.Count -gt 0) { 'Confirmed' } else { 'Not observed' }) "$($tl1NoPr.Count) TL1 identities without a phishing-resistant method registered" 'P2_PrivilegedIdentities.csv'),
        (& $finding 'F06' 'Unmanaged device access' 'Test required' "$($caDevice.Count) enabled CA policies require a compliant or joined device for admin roles. Configuration alone cannot prove the block; run AT-03." 'ConditionalAccessPolicies.csv'),
        (& $finding 'F07' 'Lifecycle gap' $(if ($disabled.Count -gt 0) { 'Confirmed' } elseif ($cladUnlinked.Count -gt 0) { 'Indicated' } else { 'Not observed' }) "$($cladUnlinked.Count) CLAD accounts whose everyday identity is not in the evidence (the export only holds identities with roles or approver duties); $($disabled.Count) disabled identities still hold access" 'P2_PrivilegedIdentities.csv'),
        (& $finding 'F08' 'Supplier and generic accounts' $(if ($suppliers.Count -gt 0 -or $generic.Count -gt 0) { 'Confirmed' } else { 'Not observed' }) "$($suppliers.Count) supplier identities and $($generic.Count) generic/service user accounts hold privilege; $($everydayPriv.Count) everyday identities hold privilege directly" 'P2_PrivilegedIdentities.csv, P2_ExceptionCandidates.csv'),
        (& $finding 'F09' 'Workload scope (Purview / eDiscovery)' $(if ($purviewRoles.Count -gt 0) { 'Confirmed' } else { 'Not observed' }) "$(@($purviewRoles | Select-Object -ExpandProperty Person -Unique).Count) people hold Purview / eDiscovery / Compliance roles ($(@($purviewRoles | Where-Object Standing).Count) standing). Purview role groups outside Entra are not collected." 'P2_AccessPaths.csv'),
        (& $finding 'F10' 'Monitoring evidence' 'Not assessed' 'Needs SIEM and alert evidence (runbook 1.4).' ''),
        (& $finding 'F11' 'Operational drift' $(if ($tl1PolicyGaps.Count -gt 0) { 'Indicated' } else { 'Not observed' }) "$($tl1PolicyGaps.Count) TL1 PIM settings differ from the baseline. Compare runs (Compare-PimPhase2Assessment.ps1) to measure drift over time." 'P2_PolicyGaps.csv'),
        (& $finding 'F12' 'Password / recovery position' 'Not assessed' 'Needs SSPR and password policy review (OD-13).' ''),
        (& $finding 'F13' 'Out-of-hours approval' $(if ($approverGroups.Count -gt 0) { 'Indicated' } else { 'Not assessed' }) "$($approverGroups.Count) approver group(s); coverage and rota cannot be read from configuration (OD-05)." 'P2_ApproverGroups.csv'),
        (& $finding 'F14' 'Licensing uncertainty' $(if ($licences.Count -eq 0) { 'Not assessed' } elseif ($noP2.Count -gt 0) { 'Confirmed' } else { 'Not observed' }) "$($noP2.Count) privileged human identities with no Entra ID P2 (or suite including it) seen" 'P2_PrivilegedIdentities.csv'),
        (& $finding 'F15' 'Azure not baselined' $(if ($hasAzure) { 'Addressed' } else { 'Open' }) $(if ($hasAzure) { "$(@($privPaths | Where-Object Plane -eq 'Azure').Count) Azure privileged paths assessed; $($azStandingTl1.Count) standing TL1 paths at subscription scope or above; $($azRoot.Count) root-scope paths; $($azLighthouse.Count) Lighthouse authorisations" } else { 'Run Get-AzureRbacReview.ps1 for this tenant.' }) 'P2_AccessPaths.csv (Plane = Azure)')
    )

    # ---- Maturity baseline indicators (HLD 6.7) --------------------------------------------------
    $eligibleShare = if ($privPaths.Count -gt 0) { [Math]::Round((@($privPaths | Where-Object { $_.EffectiveState -eq 'Eligible' }).Count / $privPaths.Count) * 100, 0) } else { $null }
    $maturity = @(
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Eligible role assignment'; HldBaseline = 'Established'; Phase2Target = 'Extended to all material privilege'; Indicator = "$eligibleShare% of privileged paths are eligible" },
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Dedicated administrative identities'; HldBaseline = 'Established'; Phase2Target = 'Naming and productivity restrictions applied'; Indicator = "$(@($identityRows | Where-Object AccountType -eq 'CLAD').Count) CLADs; $($everydayPriv.Count) everyday and $(@($identityRows | Where-Object AccountType -eq 'Guest').Count) guest identities hold privilege directly" },
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Approval governance independence'; HldBaseline = 'Partially mature'; Phase2Target = 'Approver population separated from eligible population'; Indicator = "$($selfApprovalPeople.Count) people with linked-identity self-approval; $($approverEveryday.Count) approver groups with everyday identities" },
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Privilege segmentation'; HldBaseline = 'Partially mature'; Phase2Target = 'TL1 separated from operational bundles'; Indicator = "$($tl1InBundles.Count) bundles contain TL1 roles" },
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Global Administrator governance'; HldBaseline = 'Partially mature'; Phase2Target = 'Justified population (OD-03)'; Indicator = "$($gaPeople.Count) people can reach Global Administrator; $($breakGlass.Count) break-glass identities detected" },
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Phishing-resistant authentication'; HldBaseline = 'Limited adoption'; Phase2Target = 'FIDO2 for TL1'; Indicator = $(if ($assurance.Count -or $authMethods.Count) { "$($tl1NoPr.Count) of $(@($identityRows | Where-Object { $_.HighestTrustLevel -eq 'TL1' -and $_.AccountType -notin @('BreakGlass', 'WorkloadIdentity') }).Count) TL1 identities lack a phishing-resistant method" } else { 'Not collected' }) },
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Access reviews and lifecycle governance'; HldBaseline = 'Emerging'; Phase2Target = 'Owned reviews, JML triggers, removal SLA'; Indicator = "$($cladUnlinked.Count) unlinked CLADs; $($disabled.Count) disabled identities with access" },
        [pscustomobject]@{ Tenant = $TenantShortName; Capability = 'Service principal and non-human privilege'; HldBaseline = 'Emerging'; Phase2Target = 'Out of scope (R15)'; Indicator = "$(@($identityRows | Where-Object { $_.AccountType -eq 'WorkloadIdentity' -and $_.HighestTrustLevel -eq 'TL1' }).Count) workload identities hold TL1 roles" }
    )

    # ---- Headline metrics --------------------------------------------------------------------
    $metrics = [pscustomobject]@{
        Tenant                        = $TenantShortName
        TenantName                    = $TenantName
        EntraRun                      = if ($EntraRunFolder) { Split-Path $EntraRunFolder -Leaf } else { $null }
        AzureRun                      = if ($AzureRunFolder) { $leaf = Split-Path $AzureRunFolder -Leaf; if ($leaf -eq 'Azure') { "$(Split-Path (Split-Path $AzureRunFolder -Parent) -Leaf) (Azure)" } else { $leaf } } else { $null }
        PeopleWithPrivilege           = $people.Count
        PeopleWithTL1                 = $tl1People.Count
        PeopleReachingGlobalAdmin     = $gaPeople.Count
        SelfApprovalPeople            = $selfApprovalPeople.Count
        SelfApprovalTL1People         = $selfApprovalTl1People.Count
        ApproverGroupsWithEveryday    = $approverEveryday.Count
        TL1InBundles                  = $tl1InBundles.Count
        StandingPrivilegedPaths       = $standingHuman.Count
        StandingTL1Paths              = @($standingHuman | Where-Object TrustLevel -eq 'TL1').Count
        AzureStandingTL1AtSubOrAbove  = $azStandingTl1.Count
        TL1WithoutPhishingResistant   = $tl1NoPr.Count
        CladAccounts                  = @($identityRows | Where-Object AccountType -eq 'CLAD').Count
        CladNotLinked                 = $cladUnlinked.Count
        EverydayIdentitiesWithPrivilege = $everydayPriv.Count
        GuestIdentitiesWithPrivilege  = @($identityRows | Where-Object AccountType -eq 'Guest').Count
        SupplierIdentities            = $suppliers.Count
        GenericAccounts               = $generic.Count
        BreakGlassAccounts            = $breakGlass.Count
        DisabledWithAccess            = $disabled.Count
        UnresolvedPrincipals          = @($identityRows | Where-Object AccountType -eq 'Unresolved').Count
        DeletedIdentitiesWithAccess   = @($identityRows | Where-Object AccountType -eq 'Deleted identity').Count
        AccessReviewsConfigured       = $accessReviews.Count
        AccessReviewsPlanned          = $reviewPlan.Count
        CladsToCreate                 = @($cladRows | Where-Object { $_.Action -like '*create CLAD*' }).Count
        CladsExistingRightsToMove     = @($cladRows | Where-Object { $_.Action -like '*existing CLAD*' }).Count
        GaPeopleViaGroup              = @($privPaths | Where-Object { $_.Plane -eq 'Entra' -and $_.Role -eq 'Global Administrator' -and $_.PathType -ne 'Direct' -and $_.AccountType -notin @('BreakGlass', 'WorkloadIdentity') } | Select-Object -ExpandProperty Person -Unique).Count
        OtherTenantPrincipals         = @($identityRows | Where-Object AccountType -eq 'Other tenant principal').Count
        WithoutP2                     = $noP2.Count
        TL1PolicyGaps                 = $tl1PolicyGaps.Count
        PolicyGaps                    = $policyGaps.Count
        AzureRootScopePaths           = $azRoot.Count
        LighthouseAuthorisations      = $azLighthouse.Count
        EligibleSharePercent          = $eligibleShare
    }

    # ---- Control checks and NCSC CAF benchmark -------------------------------------------------
    $audit = Get-PimAuditControls -Ctx @{
        PrivPaths = $privPaths; Identities = $identityRows; PolicyByRole = $policyByRole; Catalogue = $cat
        Catalogue_InUse = $catalogueRows; HasEntra = $hasEntra; HasAzure = $hasAzure
        GaPeople = $gaPeople; Tl1InBundles = $tl1InBundles; SelfApprovalPeople = $selfApprovalPeople
        SelfApprovalTl1People = $selfApprovalTl1People; ApproverEveryday = $approverEveryday
        CaPolicies = $caPolicies; AccessReviews = $accessReviews; NoP2 = $noP2; HasLicences = ($licences.Count -gt 0)
        AzureAccess = $azAccess; AzStandingTl1 = $azStandingTl1; AzRoot = $azRoot
        AzLighthouse = $azLighthouse; AzCoverageGaps = $azCoverageGaps; CladRows = @($cladRows); ReviewPlan = @($reviewPlan)
    }
    foreach ($row in @($audit.Controls) + @($audit.Caf) + @($audit.Ssa) + @($audit.CoverageEntra) + @($audit.CoverageAzure) + @($audit.Oversubscribed)) {
        if ($row) { Add-Member -InputObject $row -NotePropertyName Tenant -NotePropertyValue $TenantShortName -Force }
    }
    Add-Member -InputObject $metrics -NotePropertyName ControlsGood -NotePropertyValue @($audit.Controls | Where-Object Result -eq 'Good').Count
    Add-Member -InputObject $metrics -NotePropertyName ControlsPartial -NotePropertyValue @($audit.Controls | Where-Object Result -eq 'Partial').Count
    Add-Member -InputObject $metrics -NotePropertyName ControlsWeak -NotePropertyValue @($audit.Controls | Where-Object Result -eq 'Weak').Count
    foreach ($c in $audit.Caf) { Add-Member -InputObject $metrics -NotePropertyName ("Caf_" + ($c.Outcome -replace '\.', '')) -NotePropertyValue $c.Rating }

    # ---- Export ------------------------------------------------------------------------------
    Export-PimData -Data $audit.Controls -CsvPath (Join-Path $OutputFolder 'P2_Controls.csv')
    Export-PimData -Data $audit.Caf -CsvPath (Join-Path $OutputFolder 'P2_NcscCafBenchmark.csv')
    Export-PimData -Data @($audit.CoverageEntra + $audit.CoverageAzure) -CsvPath (Join-Path $OutputFolder 'P2_PimCoverage.csv')
    Export-PimData -Data $audit.Oversubscribed -CsvPath (Join-Path $OutputFolder 'P2_OversubscribedRoles.csv')
    Export-PimData -Data $identityRows -CsvPath (Join-Path $OutputFolder 'P2_PrivilegedIdentities.csv')
    Export-PimData -Data @($paths | Sort-Object Person, Plane, Role) -CsvPath (Join-Path $OutputFolder 'P2_AccessPaths.csv')
    Export-PimData -Data $catalogueRows -CsvPath (Join-Path $OutputFolder 'P2_RoleCatalogue.csv')
    Export-PimData -Data @($selfApproval | Sort-Object Severity, Person, Role) -CsvPath (Join-Path $OutputFolder 'P2_SelfApproval.csv')
    Export-PimData -Data @($approverGroups) -CsvPath (Join-Path $OutputFolder 'P2_ApproverGroups.csv')
    Export-PimData -Data $groupBundles -CsvPath (Join-Path $OutputFolder 'P2_GroupBundles.csv')
    Export-PimData -Data $tl1Paths -CsvPath (Join-Path $OutputFolder 'P2_TL1Paths.csv')
    Export-PimData -Data $standing -CsvPath (Join-Path $OutputFolder 'P2_StandingAccess.csv')
    Export-PimData -Data @($policyGaps) -CsvPath (Join-Path $OutputFolder 'P2_PolicyGaps.csv')
    Export-PimData -Data $migration -CsvPath (Join-Path $OutputFolder 'P2_MigrationWorksheet.csv')
    Export-PimData -Data @($cladRows) -CsvPath (Join-Path $OutputFolder 'P2_CladProvisioning.csv')
    Export-PimData -Data @($reviewPlan) -CsvPath (Join-Path $OutputFolder 'P2_AccessReviewPlan.csv')
    Export-PimData -Data @($exceptions) -CsvPath (Join-Path $OutputFolder 'P2_ExceptionCandidates.csv')
    Export-PimData -Data $hld -CsvPath (Join-Path $OutputFolder 'P2_HldFindings.csv')
    Export-PimData -Data $maturity -CsvPath (Join-Path $OutputFolder 'P2_Maturity.csv')
    Export-PimData -Data @($metrics) -CsvPath (Join-Path $OutputFolder 'P2_Metrics.csv') -JsonPath (Join-Path $OutputFolder 'P2_Metrics.json')

    $report = New-PimPhase2Report -OutputFolder $OutputFolder -Data @{
        TenantName      = $TenantName
        TenantShortName = $TenantShortName
        Branding        = $cat.Branding
        Metrics         = $metrics
        Hld             = $hld
        Maturity        = $maturity
        Identities      = $identityRows
        SelfApproval    = @($selfApproval)
        ApproverGroups  = @($approverGroups)
        Bundles         = $groupBundles
        Tl1Paths        = $tl1Paths
        Standing        = $standing
        PolicyGaps      = @($policyGaps)
        Catalogue       = $catalogueRows
        Exceptions      = @($exceptions)
        Migration       = $migration
        Audit           = $audit
        CladRows        = @($cladRows)
        ReviewPlan      = @($reviewPlan)
        AccessReviews   = @($accessReviews)
        PrivPathsHuman  = @($privPaths | Where-Object { $_.AccountType -in @('CLAD', 'Other admin account', 'Everyday', 'Guest', 'Generic/Service') })
        Identity        = $ident
        HasEntra        = $hasEntra
        HasAzure        = $hasAzure
        EntraRun        = $metrics.EntraRun
        AzureRun        = $metrics.AzureRun
        AzCoverageGaps  = $azCoverageGaps
        Collected       = @{
            GroupPolicies = $groupPolicyFlat.Count -gt 0
            AuthMethods   = $authMethods.Count -gt 0
            IdentityContext = $identityContext.Count -gt 0
            AzurePolicies = $azPolicies.Count -gt 0
        }
    }

    Write-PimLog -Message "Phase 2 assessment written to $OutputFolder"
    return [pscustomobject]@{
        OutputFolder = $OutputFolder
        ReportPath   = $report
        Metrics      = $metrics
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-PimPhase2Assessment @PSBoundParameters
}
