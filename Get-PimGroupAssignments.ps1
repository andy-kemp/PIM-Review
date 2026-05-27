<#
.SYNOPSIS
Exports Microsoft Entra PIM for Groups assignment and eligibility schedule instances.

.DESCRIPTION
Retrieves Active and Eligible PIM for Groups schedule instances and exports a flattened
assignment view. The script tries Microsoft Graph v1.0 endpoints first and falls back to
beta endpoints when necessary.

Recommended delegated scopes:
- PrivilegedAssignmentSchedule.Read.AzureADGroup
- PrivilegedEligibilitySchedule.Read.AzureADGroup
- Group.Read.All

.EXAMPLE
./Get-PimGroupAssignments.ps1 -OutputFolder .\Output -Verbose
#>
[CmdletBinding()]
param(
    [string]$OutputFolder,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
Import-Module -Name $commonModulePath -DisableNameChecking

function Get-GroupPimScheduleInstances {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Active', 'Eligible')]
        [string]$AssignmentState,

        [Parameter(Mandatory)]
        [string[]]$GroupIds
    )

    $path = if ($AssignmentState -eq 'Active') {
        'assignmentScheduleInstances'
    }
    else {
        'eligibilityScheduleInstances'
    }

    $allItems = @()
    $versions = @()

    foreach ($groupId in @($GroupIds | Where-Object { $_ } | Select-Object -Unique)) {
        $filter = [uri]::EscapeDataString("groupId eq '$groupId'")
        $query = "?`$filter=$filter&`$select=id,groupId,principalId,accessId,memberType,startDateTime,endDateTime"
        $v1Uri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/${path}${query}"
        $betaUri = "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/${path}${query}"

        try {
            $allItems += @(Get-GraphPagedResults -Uri $v1Uri)
            $versions += 'v1.0'
            continue
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read $path for group $groupId from v1.0 endpoint: $($_.Exception.Message). Retrying with beta endpoint."
        }

        try {
            $allItems += @(Get-GraphPagedResults -Uri $betaUri)
            $versions += 'beta'
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read $path for group $groupId from beta endpoint: $($_.Exception.Message)"
        }
    }

    $distinctVersions = @($versions | Select-Object -Unique)
    $apiVersion = if ($distinctVersions.Count -eq 0) { 'none' } elseif ($distinctVersions.Count -eq 1) { $distinctVersions[0] } else { 'mixed' }

    return [pscustomobject]@{
        ApiVersion = $apiVersion
        Items      = @($allItems)
    }
}

function Convert-GroupPimScheduleRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [ValidateSet('Active', 'Eligible')]
        [string]$AssignmentState,

        [Parameter(Mandatory)]
        [string]$ApiVersion
    )

    $principal = $null
    if ($Item.principal) {
        $principal = $Item.principal
    }
    elseif ($Item.principalId) {
        $principal = Resolve-DirectoryObject -ObjectId $Item.principalId
    }

    $group = $null
    if ($Item.group) {
        $group = $Item.group
    }
    elseif ($Item.groupId) {
        $group = Resolve-Group -GroupId $Item.groupId
    }

    $principalType = if ($principal) { Get-PrincipalType -Principal $principal } else { 'Unknown' }
    $principalDisplayName = $null
    if ($principal) {
        if ($principal.displayName) {
            $principalDisplayName = $principal.displayName
        }
        elseif ($principal.userPrincipalName) {
            $principalDisplayName = $principal.userPrincipalName
        }
    }

    $groupDisplayName = $null
    if ($group -and $group.displayName) {
        $groupDisplayName = $group.displayName
    }

    $isPermanent = [string]::IsNullOrWhiteSpace([string]$Item.endDateTime)

    return [pscustomobject]@{
        AssignmentState      = $AssignmentState
        AssignmentId         = $Item.id
        ApiVersion           = $ApiVersion
        GroupId              = $Item.groupId
        GroupDisplayName     = $groupDisplayName
        PrincipalId          = $Item.principalId
        PrincipalDisplayName = $principalDisplayName
        PrincipalType        = $principalType
        AccessId             = $Item.accessId
        MemberType           = $Item.memberType
        StartDateTimeUtc     = $Item.startDateTime
        EndDateTimeUtc       = $Item.endDateTime
        IsPermanent          = $isPermanent
    }
}

function Get-PimGroupAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string[]]$GroupIds,

        [switch]$ReturnObjectsOnly
    )

    $null = Ensure-Directory -Path $OutputFolder

    $targetGroupIds = @($GroupIds | Where-Object { $_ } | Select-Object -Unique)
    if ($targetGroupIds.Count -eq 0) {
        Write-PimLog -Level WARN -Message 'No target group IDs supplied for PIM for Groups retrieval; skipping group PIM API calls.'
        return @()
    }

    Write-PimLog -Message 'Retrieving Active PIM for Groups schedule instances.'
    $active = Get-GroupPimScheduleInstances -AssignmentState Active -GroupIds $targetGroupIds

    Write-PimLog -Message 'Retrieving Eligible PIM for Groups schedule instances.'
    $eligible = Get-GroupPimScheduleInstances -AssignmentState Eligible -GroupIds $targetGroupIds

    $rows = @(
        foreach ($item in @($active.Items)) {
            if ($item) {
                Convert-GroupPimScheduleRow -Item $item -AssignmentState Active -ApiVersion $active.ApiVersion
            }
        }

        foreach ($item in @($eligible.Items)) {
            if ($item) {
                Convert-GroupPimScheduleRow -Item $item -AssignmentState Eligible -ApiVersion $eligible.ApiVersion
            }
        }
    )

    if (-not $ReturnObjectsOnly) {
        if (@($rows).Count -gt 0) {
            $csvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\PimForGroups.Assignments.csv'
            Export-PimData -Data $rows -CsvPath $csvPath
            Write-PimLog -Message "Exported PIM for Groups assignments: $csvPath"
        }
        else {
            Write-PimLog -Level WARN -Message 'No PIM for Groups assignment rows returned; skipping PimForGroups.Assignments.csv export.'
        }
    }

    return @($rows)
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimGroupAssignments @PSBoundParameters
}


