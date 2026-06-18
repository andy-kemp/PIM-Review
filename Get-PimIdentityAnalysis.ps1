<#
.SYNOPSIS
Collects per-user authentication strength and Conditional Access coverage data for privileged users.

.DESCRIPTION
Provides two analyses:

1. Authentication Registration Details — queries the Graph authentication methods report
   endpoint to classify each privileged user as PhishingResistant / StandardMFA / WeakOrNone.
   Endpoint: GET /v1.0/reports/authenticationMethods/userRegistrationDetails
   Required scope: Reports.Read.All (or UserAuthenticationMethod.Read.All)
   Returns @() gracefully when the scope is not consented.

2. Conditional Access Coverage — maps each assigned privileged role to the set of enabled
   CA policies that target it, detects whether MFA is enforced, and produces a risk rating
   per role (NotCovered, Covered-NoMFA, Covered-StrongMFA).
   Uses data already collected by Get-PimAdvancedRiskData — no additional Graph calls.

This script is read-only. It does not modify tenant configuration.

Required scopes (in addition to standard PIM review scopes):
- Reports.Read.All             — authentication registration details
#>
[CmdletBinding()]
param(
    [object[]]$PrivilegedUserIds,

    [object[]]$ConditionalAccessPolicies,

    [object[]]$RoleAssignments,

    [string[]]$HighImpactRoles,

    [string]$OutputFolder,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

function Get-AuthRegistrationDetails {
    <#
    .SYNOPSIS
    Fetches authentication method registration details for privileged users from the Graph report API.
    Classifies each user as PhishingResistant, StandardMFA, WeakOrNone, or Unknown.
    Returns an empty array when the Reports.Read.All scope is not available.
    #>
    [CmdletBinding()]
    param(
        [object[]]$PrivilegedUserIds
    )

    Write-PimLog -Message 'Fetching authentication method registration details from Graph report API.'

    $allDetails = @()
    $uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999&$select=id,userPrincipalName,userDisplayName,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered'
    try {
        $allDetails = @(Get-GraphPagedResults -Uri $uri)
        Write-PimLog -Message "Retrieved $($allDetails.Count) user authentication registration record(s)."
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve authentication registration details: $($_.Exception.Message). Ensure Reports.Read.All scope is consented. Authentication strength analysis will be skipped."
        return @()
    }

    # Build lookup set for faster membership test
    $privilegedSet = @{}
    foreach ($id in @($PrivilegedUserIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $privilegedSet[$id] = $true
    }

    $rows = @()
    foreach ($detail in $allDetails) {
        if ([string]::IsNullOrWhiteSpace($detail.id)) { continue }
        if ($privilegedSet.Count -gt 0 -and -not $privilegedSet.ContainsKey($detail.id)) { continue }

        $methodsArr = @()
        if ($detail.methodsRegistered) {
            $methodsArr = @($detail.methodsRegistered)
        }

        $hasPhishingResistant = $false
        $hasStandardMfa = $false
        $hasWeakMethod = $false
        $methodLabels = @()

        foreach ($m in $methodsArr) {
            $mStr = [string]$m
            $methodLabels += $mStr
            if ($mStr -match 'fido2|windowsHelloForBusiness|passkey') {
                $hasPhishingResistant = $true
            }
            elseif ($mStr -match 'microsoftAuthenticatorApp|softwareOneTimePasscode|temporaryAccessPass|hardwareOathToken') {
                $hasStandardMfa = $true
            }
            else {
                $hasWeakMethod = $true
            }
        }

        if ($hasPhishingResistant) {
            $authStrength = 'PhishingResistant'
        }
        elseif ($hasStandardMfa) {
            $authStrength = 'StandardMFA'
        }
        elseif ($detail.isMfaRegistered -eq $true) {
            $authStrength = 'StandardMFA'
        }
        elseif ($hasWeakMethod) {
            $authStrength = 'WeakOrNone'
        }
        elseif ($methodsArr.Count -gt 0) {
            $authStrength = 'WeakOrNone'
        }
        else {
            $authStrength = 'Unknown'
        }

        if ($authStrength -eq 'WeakOrNone') {
            $authRisk = 'High'
        }
        elseif ($authStrength -eq 'StandardMFA') {
            $authRisk = 'Medium'
        }
        elseif ($authStrength -eq 'PhishingResistant') {
            $authRisk = 'Low'
        }
        else {
            $authRisk = 'Medium'
        }

        $isMfaReg    = if ($null -ne $detail.isMfaRegistered)       { [bool]$detail.isMfaRegistered }       else { $false }
        $isMfaCap    = if ($null -ne $detail.isMfaCapable)           { [bool]$detail.isMfaCapable }           else { $false }
        $isPassless  = if ($null -ne $detail.isPasswordlessCapable)  { [bool]$detail.isPasswordlessCapable }  else { $false }

        $rows += [pscustomobject]@{
            UserId                     = $detail.id
            UserPrincipalName          = $detail.userPrincipalName
            UserDisplayName            = $detail.userDisplayName
            AuthStrength               = $authStrength
            HasPhishingResistantMethod = $hasPhishingResistant
            HasStandardMfaMethod       = $hasStandardMfa
            IsMfaRegistered            = $isMfaReg
            IsMfaCapable               = $isMfaCap
            IsPasswordlessCapable      = $isPassless
            MethodCount                = $methodsArr.Count
            MethodsRegistered          = ($methodLabels -join '; ')
            AuthRiskRating             = $authRisk
        }
    }

    return @($rows | Sort-Object -Property AuthStrength, UserDisplayName)
}

function Get-CACoverageForPrivilegedRoles {
    <#
    .SYNOPSIS
    Evaluates Conditional Access policy coverage for each privileged role and classifies
    coverage as NotCovered / Covered-NoMFA / Covered-StrongMFA with a risk rating per role.
    No additional Graph calls — uses already-collected CA policy and role assignment data.
    #>
    [CmdletBinding()]
    param(
        [object[]]$ConditionalAccessPolicies,
        [object[]]$RoleAssignments,
        [string[]]$HighImpactRoles
    )

    # Build role name -> role definition ID mapping from assignment data
    $roleNameToId = @{}
    foreach ($ra in @($RoleAssignments)) {
        $rdn = [string]$ra.RoleDefinitionId
        $rn  = [string]$ra.RoleDisplayName
        if (-not [string]::IsNullOrWhiteSpace($rdn) -and -not [string]::IsNullOrWhiteSpace($rn)) {
            $roleNameToId[$rn] = $rdn
        }
    }

    $enabledPolicies = @($ConditionalAccessPolicies | Where-Object { $_.State -eq 'enabled' })

    # Analyse all distinct roles present in assignments
    $allRoleNames = @($RoleAssignments | Select-Object -ExpandProperty RoleDisplayName -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    $rows = @()
    foreach ($roleName in $allRoleNames) {
        $roleId = $roleNameToId[$roleName]
        $isHighImpact = $roleName -in $HighImpactRoles

        $coveringPolicies = New-Object System.Collections.Generic.List[string]
        $mfaEnforced = $false
        $deviceComplianceEnforced = $false
        $coveredByAllUsers = $false

        foreach ($policy in $enabledPolicies) {
            $coversRole = $false

            # All-user policies cover every role by definition
            if ($policy.IncludeUserTargets -match '\bAll\b') {
                $coversRole = $true
                $coveredByAllUsers = $true
            }

            # Explicit role-ID inclusion
            if (-not $coversRole -and -not [string]::IsNullOrWhiteSpace($roleId)) {
                if ($policy.IncludeRoleIds -match [regex]::Escape($roleId)) {
                    $coversRole = $true
                }
            }

            # Honour explicit role exclusions even when covered by All
            if ($coversRole -and -not [string]::IsNullOrWhiteSpace($roleId)) {
                if ($policy.ExcludeRoleIds -match [regex]::Escape($roleId)) {
                    $coversRole = $false
                }
            }

            if ($coversRole) {
                $coveringPolicies.Add($policy.PolicyName)
                if ($policy.RequiresMfaControl -eq $true) { $mfaEnforced = $true }
                if ($policy.GrantControls -match 'compliantDevice|domainJoinedDevice') { $deviceComplianceEnforced = $true }
            }
        }

        if ($mfaEnforced) {
            $coverageStatus = 'Covered-StrongMFA'
        }
        elseif ($coveringPolicies.Count -gt 0) {
            $coverageStatus = 'Covered-NoMFA'
        }
        else {
            $coverageStatus = 'NotCovered'
        }

        if ($coverageStatus -eq 'NotCovered' -and $isHighImpact) {
            $riskRating = 'High'
        }
        elseif ($coverageStatus -eq 'NotCovered') {
            $riskRating = 'Medium'
        }
        elseif ($coverageStatus -eq 'Covered-NoMFA' -and $isHighImpact) {
            $riskRating = 'High'
        }
        elseif ($coverageStatus -eq 'Covered-NoMFA') {
            $riskRating = 'Medium'
        }
        else {
            $riskRating = 'Low'
        }

        $rows += [pscustomobject]@{
            RoleName                     = $roleName
            RoleDefinitionId             = $roleId
            IsHighImpact                 = $isHighImpact
            CoverageStatus               = $coverageStatus
            IsMfaEnforced                = $mfaEnforced
            IsDeviceComplianceEnforced   = $deviceComplianceEnforced
            IsCoveredByAllUsersPolicy    = $coveredByAllUsers
            CoveringPolicyCount          = $coveringPolicies.Count
            CoveringPolicies             = ($coveringPolicies -join '; ')
            RiskRating                   = $riskRating
        }
    }

    return @($rows | Sort-Object -Property IsHighImpact, RiskRating, RoleName -Descending)
}

function Get-PimIdentityAnalysis {
    <#
    .SYNOPSIS
    Orchestrator — runs authentication strength and CA coverage analysis, exports CSVs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$PrivilegedUserIds,

        [Parameter(Mandatory)]
        [object[]]$ConditionalAccessPolicies,

        [Parameter(Mandatory)]
        [object[]]$RoleAssignments,

        [string[]]$HighImpactRoles,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$ReturnObjectsOnly
    )

    $rawFolder = Ensure-Directory -Path (Join-Path -Path $OutputFolder -ChildPath 'Raw')

    Write-PimLog -Message 'Running identity analysis: authentication strength.'
    $authStrength = Get-AuthRegistrationDetails -PrivilegedUserIds $PrivilegedUserIds

    Write-PimLog -Message 'Running identity analysis: Conditional Access coverage by role.'
    $caCoverage = Get-CACoverageForPrivilegedRoles `
        -ConditionalAccessPolicies $ConditionalAccessPolicies `
        -RoleAssignments $RoleAssignments `
        -HighImpactRoles $HighImpactRoles

    if (-not $ReturnObjectsOnly) {
        Export-PimData -Data $authStrength -CsvPath (Join-Path -Path $rawFolder -ChildPath 'AuthStrength.csv')
        Export-PimData -Data $caCoverage   -CsvPath (Join-Path -Path $rawFolder -ChildPath 'CACoverage.csv')
    }

    return [pscustomobject]@{
        AuthStrength = @($authStrength)
        CACoverage   = @($caCoverage)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimIdentityAnalysis @PSBoundParameters
}
