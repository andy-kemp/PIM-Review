<#
.SYNOPSIS
Exports advanced risk datasets for comprehensive PIM assessment.

.DESCRIPTION
Collects additional governance and telemetry context:
- Role activation request activity (beta)
- Activation anomalies (frequency and out-of-hours)
- Conditional Access policy posture
- Access review definitions and status
- Privileged workload identity credential hygiene
- Nested group-to-user privilege paths via recursive traversal

Required delegated scopes (recommended):
- RoleManagement.Read.Directory
- Policy.Read.All
- AccessReview.Read.All
- Application.Read.All
- Group.Read.All
#>
[CmdletBinding()]
param(
    [object[]]$RoleAssignments,

    [object[]]$PrivilegedGroups,

    [string]$OutputFolder,

    [int]$MaxNestedTraversalDepth = 4,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
Import-Module -Name $commonModulePath -DisableNameChecking

function Get-ActivationRequests {
    [CmdletBinding()]
    param()

    $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleRequests?`$filter=action eq 'selfActivate'&`$expand=principal,roleDefinition"
    try {
        return @(Get-GraphPagedResults -Uri $uri)
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve activation requests: $($_.Exception.Message)"
        return @()
    }
}

function Convert-ActivationRequestRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Request
    )

    $principalName = $null
    $principalUpn = $null
    $principalUserType = $null

    if ($Request.principal) {
        if ($Request.principal.displayName) {
            $principalName = $Request.principal.displayName
        }
        if ($Request.principal.userPrincipalName) {
            $principalUpn = $Request.principal.userPrincipalName
            if (-not $principalName) {
                $principalName = $principalUpn
            }
        }
        if ($Request.principal.userType) {
            $principalUserType = $Request.principal.userType
        }
    }

    $createdUtc = $null
    if ($Request.createdDateTime) {
        try {
            $createdUtc = [datetime]$Request.createdDateTime
        }
        catch {
            $createdUtc = $null
        }
    }

    $hourUtc = if ($createdUtc) { $createdUtc.Hour } else { $null }
    $isOutOfHours = $false
    if ($hourUtc -ne $null) {
        $isOutOfHours = ($hourUtc -lt 7 -or $hourUtc -ge 19)
    }

    $startUtc = $null
    $endUtc = $null
    if ($Request.scheduleInfo -and $Request.scheduleInfo.startDateTime) {
        $startUtc = $Request.scheduleInfo.startDateTime
    }
    if ($Request.scheduleInfo -and $Request.scheduleInfo.expiration -and $Request.scheduleInfo.expiration.endDateTime) {
        $endUtc = $Request.scheduleInfo.expiration.endDateTime
    }

    $justification = $null
    if ($Request.justification) {
        $justification = $Request.justification
    }

    return [pscustomobject]@{
        RequestId            = $Request.id
        PrincipalId          = $Request.principalId
        PrincipalDisplayName = $principalName
        PrincipalUpn         = $principalUpn
        PrincipalUserType    = $principalUserType
        RoleName             = if ($Request.roleDefinition) { $Request.roleDefinition.displayName } else { $null }
        Action               = $Request.action
        Status               = $Request.status
        CreatedDateUtc       = $Request.createdDateTime
        StartDateUtc         = $startUtc
        EndDateUtc           = $endUtc
        IsOutOfHoursUtc      = $isOutOfHours
        Justification        = $justification
        TicketNumber         = if ($Request.ticketInfo) { $Request.ticketInfo.ticketNumber } else { $null }
        TicketSystem         = if ($Request.ticketInfo) { $Request.ticketInfo.ticketSystem } else { $null }
        IsBetaDerived        = $true
    }
}

function New-ActivationAnomalies {
    [CmdletBinding()]
    param(
        [object[]]$ActivationRows
    )

    $rows = @()
    $byPrincipalRole = @($ActivationRows | Group-Object -Property PrincipalId, RoleName)

    foreach ($group in $byPrincipalRole) {
        $records = @($group.Group)
        if ($records.Count -eq 0) {
            continue
        }

        $first = $records[0]
        $outOfHoursCount = @($records | Where-Object { $_.IsOutOfHoursUtc -eq $true }).Count
        $highFrequency = $records.Count -ge 5

        $risk = if ($highFrequency -or $outOfHoursCount -gt 0) { 'Medium' } else { 'Low' }
        if ($records.Count -ge 10 -or $outOfHoursCount -ge 3) {
            $risk = 'High'
        }

        $riskReasons = @()
        if ($highFrequency) {
            $riskReasons += 'High activation frequency for role'
        }
        if ($outOfHoursCount -gt 0) {
            $riskReasons += 'Out-of-hours activation requests'
        }

        $rows += [pscustomobject]@{
            PrincipalId          = $first.PrincipalId
            PrincipalDisplayName = $first.PrincipalDisplayName
            PrincipalUpn         = $first.PrincipalUpn
            PrincipalUserType    = $first.PrincipalUserType
            RoleName             = $first.RoleName
            ActivationRequestCount = $records.Count
            OutOfHoursCount      = $outOfHoursCount
            MaxRiskRating        = $risk
            RiskWhy              = ($riskReasons -join '; ')
        }
    }

    return @($rows | Sort-Object -Property MaxRiskRating, ActivationRequestCount -Descending)
}

function Get-ConditionalAccessPolicies {
    [CmdletBinding()]
    param()

    $uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    try {
        $policies = @(Get-GraphPagedResults -Uri $uri)
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve Conditional Access policies: $($_.Exception.Message)"
        return @()
    }

    $rows = @()
    foreach ($policy in $policies) {
        $includeRoles = @()
        $excludeRoles = @()
        $includeUsers = @()
        $excludeUsers = @()
        $grantControls = @()

        if ($policy.conditions) {
            if ($policy.conditions.users) {
                $includeRoles = @($policy.conditions.users.includeRoles)
                $excludeRoles = @($policy.conditions.users.excludeRoles)
                $includeUsers = @($policy.conditions.users.includeUsers)
                $excludeUsers = @($policy.conditions.users.excludeUsers)
            }
        }

        if ($policy.grantControls -and $policy.grantControls.builtInControls) {
            $grantControls = @($policy.grantControls.builtInControls)
        }

        $rows += [pscustomobject]@{
            PolicyId              = $policy.id
            PolicyName            = $policy.displayName
            State                 = $policy.state
            IncludeRoleIds        = ($includeRoles -join '; ')
            ExcludeRoleIds        = ($excludeRoles -join '; ')
            IncludeUserTargets    = ($includeUsers -join '; ')
            ExcludeUserTargets    = ($excludeUsers -join '; ')
            GrantControls         = ($grantControls -join '; ')
            RequiresMfaControl    = ($grantControls -contains 'mfa')
            IncludesAllApps       = if ($policy.conditions -and $policy.conditions.applications) { @($policy.conditions.applications.includeApplications) -contains 'All' } else { $false }
        }
    }

    return @($rows | Sort-Object -Property PolicyName)
}

function Get-AccessReviewOverview {
    [CmdletBinding()]
    param()

    $uri = 'https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions'
    try {
        $definitions = @(Get-GraphPagedResults -Uri $uri)
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve access review definitions: $($_.Exception.Message)"
        return @()
    }

    $rows = @()
    foreach ($def in $definitions) {
        $rows += [pscustomobject]@{
            ReviewDefinitionId     = $def.id
            DisplayName            = $def.displayName
            Description            = $def.descriptionForAdmins
            Status                 = $def.status
            CreatedDateTime        = $def.createdDateTime
            ReviewerType           = if ($def.settings) { $def.settings.reviewerType } else { $null }
            DefaultDecisionEnabled = if ($def.settings) { $def.settings.defaultDecisionEnabled } else { $null }
            DefaultDecision        = if ($def.settings) { $def.settings.defaultDecision } else { $null }
            JustificationRequired  = if ($def.settings) { $def.settings.justificationRequiredOnApproval } else { $null }
            RecommendationsEnabled = if ($def.settings) { $def.settings.recommendationsEnabled } else { $null }
            IsBetaDerived          = $true
        }
    }

    return @($rows | Sort-Object -Property DisplayName)
}

function Get-ServicePrincipalRiskRows {
    [CmdletBinding()]
    param(
        [object[]]$RoleAssignments,
        [string[]]$HighImpactRoles
    )

    $spAssignments = @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' -and $_.PrincipalId })
    $spIds = @($spAssignments | Select-Object -ExpandProperty PrincipalId -Unique)

    $rows = @()

    foreach ($spId in $spIds) {
        $roles = @($spAssignments | Where-Object { $_.PrincipalId -eq $spId } | Select-Object -ExpandProperty RoleDisplayName -Unique)
        $highImpact = @($roles | Where-Object { $_ -in $HighImpactRoles })

        $sp = $null
        try {
            $sp = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId?`$select=id,displayName,appId,accountEnabled,passwordCredentials,keyCredentials"
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read service principal ${spId}: $($_.Exception.Message)"
        }

        $ownerCount = 0
        try {
            $owners = @(Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/owners?`$select=id")
            $ownerCount = $owners.Count
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read owners for service principal ${spId}: $($_.Exception.Message)"
        }

        $expiredCredCount = 0
        $nextExpiryDays = $null
        $allExpiryDates = @()

        if ($sp) {
            foreach ($cred in @($sp.passwordCredentials)) {
                if ($cred.endDateTime) {
                    try {
                        $dt = [datetime]$cred.endDateTime
                        $allExpiryDates += $dt
                        if ($dt -lt (Get-Date).ToUniversalTime()) {
                            $expiredCredCount++
                        }
                    }
                    catch {}
                }
            }

            foreach ($cred in @($sp.keyCredentials)) {
                if ($cred.endDateTime) {
                    try {
                        $dt = [datetime]$cred.endDateTime
                        $allExpiryDates += $dt
                        if ($dt -lt (Get-Date).ToUniversalTime()) {
                            $expiredCredCount++
                        }
                    }
                    catch {}
                }
            }
        }

        if ($allExpiryDates.Count -gt 0) {
            $next = ($allExpiryDates | Sort-Object | Select-Object -First 1)
            $nextExpiryDays = [math]::Round(($next - (Get-Date).ToUniversalTime()).TotalDays, 1)
        }

        $riskReasons = @()
        if ($highImpact.Count -gt 0) { $riskReasons += 'Privileged workload identity has high-impact role(s)' }
        if ($ownerCount -eq 0) { $riskReasons += 'No owners assigned' }
        if ($expiredCredCount -gt 0) { $riskReasons += 'Expired credential(s) present' }
        if ($nextExpiryDays -ne $null -and $nextExpiryDays -le 30) { $riskReasons += 'Credential expiry within 30 days' }

        $risk = 'Low'
        if ($riskReasons.Count -ge 2) { $risk = 'Medium' }
        if ($highImpact.Count -gt 0 -and ($ownerCount -eq 0 -or $expiredCredCount -gt 0)) { $risk = 'High' }

        $rows += [pscustomobject]@{
            ServicePrincipalId      = $spId
            ServicePrincipalName    = if ($sp) { $sp.displayName } else { ($spAssignments | Where-Object { $_.PrincipalId -eq $spId } | Select-Object -First 1 -ExpandProperty PrincipalDisplayName) }
            AppId                   = if ($sp) { $sp.appId } else { $null }
            AccountEnabled          = if ($sp) { $sp.accountEnabled } else { $null }
            PrivilegedRoles         = ($roles -join '; ')
            HighImpactRoles         = ($highImpact -join '; ')
            OwnerCount              = $ownerCount
            ExpiredCredentialCount  = $expiredCredCount
            NextCredentialExpiryDays = $nextExpiryDays
            WorkloadRiskRating      = $risk
            WorkloadRiskWhy         = ($riskReasons -join '; ')
        }
    }

    return @($rows | Sort-Object -Property WorkloadRiskRating, ServicePrincipalName -Descending)
}

function Get-NestedGroupPrivilegePaths {
    [CmdletBinding()]
    param(
        [object[]]$PrivilegedGroups,
        [object[]]$RoleAssignments,
        [int]$MaxDepth = 4
    )

    $rows = @()
    $groupAssignments = @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' -and $_.PrincipalId })
    $privGroups = @($PrivilegedGroups | Select-Object -ExpandProperty GroupId -Unique)

    foreach ($rootGroupId in $privGroups) {
        $rootGroup = Resolve-Group -GroupId $rootGroupId
        $rootGroupName = if ($rootGroup -and $rootGroup.displayName) { $rootGroup.displayName } else { $rootGroupId }

        $queue = New-Object System.Collections.Generic.Queue[object]
        $visited = New-Object System.Collections.Generic.HashSet[string]

        $queue.Enqueue([pscustomobject]@{ GroupId = $rootGroupId; Path = @($rootGroupId); Depth = 0 })

        while ($queue.Count -gt 0) {
            $node = $queue.Dequeue()
            $groupId = [string]$node.GroupId
            $depth = [int]$node.Depth

            if ($depth -gt $MaxDepth) {
                continue
            }

            $visitKey = "${rootGroupId}::${groupId}::${depth}"
            if (-not $visited.Add($visitKey)) {
                continue
            }

            $members = @()
            try {
                $members = @(Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,displayName,userPrincipalName,userType")
            }
            catch {
                Write-PimLog -Level WARN -Message "Unable to retrieve members for group $groupId during nested path traversal: $($_.Exception.Message)"
                continue
            }

            foreach ($member in $members) {
                $memberType = Get-PrincipalType -Principal $member
                if ($memberType -eq 'Group') {
                    if ($depth + 1 -le $MaxDepth) {
                        $queue.Enqueue([pscustomobject]@{ GroupId = $member.id; Path = @($node.Path + $member.id); Depth = $depth + 1 })
                    }
                    continue
                }

                if ($memberType -ne 'User') {
                    continue
                }

                $roles = @($groupAssignments | Where-Object { $_.PrincipalId -eq $rootGroupId } | Select-Object -ExpandProperty RoleDisplayName -Unique)
                $rows += [pscustomobject]@{
                    RootGroupId            = $rootGroupId
                    RootGroupDisplayName   = $rootGroupName
                    UserId                 = $member.id
                    UserDisplayName        = if ($member.displayName) { $member.displayName } else { $member.userPrincipalName }
                    UserPrincipalName      = $member.userPrincipalName
                    UserType               = $member.userType
                    PathDepth              = $depth
                    GroupPathIds           = ($node.Path -join ' -> ')
                    InheritedRoles         = ($roles -join '; ')
                }
            }
        }
    }

    return @($rows | Sort-Object -Property RootGroupDisplayName, PathDepth, UserDisplayName -Unique)
}

function Get-PimAdvancedRiskData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$RoleAssignments,

        [Parameter(Mandatory)]
        [object[]]$PrivilegedGroups,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [int]$MaxNestedTraversalDepth = 4,

        [string[]]$HighImpactRoles,

        [switch]$ReturnObjectsOnly
    )

    $rawFolder = Ensure-Directory -Path (Join-Path -Path $OutputFolder -ChildPath 'Raw')

    $activationRequestsRaw = Get-ActivationRequests
    $activationRows = @(
        foreach ($req in $activationRequestsRaw) {
            if ($req) {
                Convert-ActivationRequestRow -Request $req
            }
        }
    )

    $activationAnomalies = New-ActivationAnomalies -ActivationRows $activationRows
    $caPolicies = Get-ConditionalAccessPolicies
    $accessReviews = Get-AccessReviewOverview
    $workloadRisk = Get-ServicePrincipalRiskRows -RoleAssignments $RoleAssignments -HighImpactRoles $HighImpactRoles
    $nestedPaths = Get-NestedGroupPrivilegePaths -PrivilegedGroups $PrivilegedGroups -RoleAssignments $RoleAssignments -MaxDepth $MaxNestedTraversalDepth

    if (-not $ReturnObjectsOnly) {
        Export-PimData -Data $activationRows -CsvPath (Join-Path -Path $rawFolder -ChildPath 'ActivationRequests.beta.csv')
        Export-PimData -Data $activationAnomalies -CsvPath (Join-Path -Path $rawFolder -ChildPath 'ActivationAnomalies.csv')
        Export-PimData -Data $caPolicies -CsvPath (Join-Path -Path $rawFolder -ChildPath 'ConditionalAccessPolicies.csv')
        Export-PimData -Data $accessReviews -CsvPath (Join-Path -Path $rawFolder -ChildPath 'AccessReviews.beta.csv')
        Export-PimData -Data $workloadRisk -CsvPath (Join-Path -Path $rawFolder -ChildPath 'WorkloadIdentityRisk.csv')
        Export-PimData -Data $nestedPaths -CsvPath (Join-Path -Path $rawFolder -ChildPath 'NestedGroupPrivilegePaths.csv')
    }

    return [pscustomobject]@{
        ActivationRequests = @($activationRows)
        ActivationAnomalies = @($activationAnomalies)
        ConditionalAccessPolicies = @($caPolicies)
        AccessReviews = @($accessReviews)
        WorkloadIdentityRisk = @($workloadRisk)
        NestedGroupPaths = @($nestedPaths)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimAdvancedRiskData @PSBoundParameters
}
