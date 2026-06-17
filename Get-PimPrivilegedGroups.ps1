<#
.SYNOPSIS
Builds a distinct list of group principals holding privileged role assignments.

.DESCRIPTION
Consumes role assignment exports and returns one row per group principal with assignment counts,
role counts, and role-assignable indicator when retrievable.

Required delegated scope:
- Group.Read.All

.EXAMPLE
./Get-PimPrivilegedGroups.ps1 -RoleAssignments $roleAssignments -OutputFolder .\Output -Verbose
#>
[CmdletBinding()]
param(
    [object[]]$RoleAssignments,

    [string]$OutputFolder,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

function Get-PimPrivilegedGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$RoleAssignments,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$ReturnObjectsOnly
    )

    $groupAssignments = @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' -and $_.PrincipalId })
    $groupIds = @($groupAssignments.PrincipalId | Select-Object -Unique)

    Write-PimLog -Message "Detected $($groupIds.Count) distinct group principals in role assignments."

    $rows = @()

    foreach ($groupId in $groupIds) {
        $rowsForGroup = @($groupAssignments | Where-Object { $_.PrincipalId -eq $groupId })
        $group = Resolve-Group -GroupId $groupId

        $activeCount = @($rowsForGroup | Where-Object { $_.AssignmentState -eq 'Active' }).Count
        $eligibleCount = @($rowsForGroup | Where-Object { $_.AssignmentState -eq 'Eligible' }).Count
        $distinctRoles = @($rowsForGroup.RoleDisplayName | Where-Object { $_ } | Select-Object -Unique)

        $groupDisplayName = $null
        if ($group -and ($null -ne $group.PSObject.Properties['displayName']) -and $group.displayName) {
            $groupDisplayName = $group.displayName
        }
        elseif (@($rowsForGroup).Count -gt 0) {
            $groupDisplayName = $rowsForGroup[0].PrincipalDisplayName
        }

        $rows += [pscustomobject]@{
            GroupId                 = $groupId
            GroupDisplayName        = $groupDisplayName
            IsRoleAssignable        = if ($group) { $group.isAssignableToRole } else { $null }
            RoleAssignmentCount     = $rowsForGroup.Count
            DistinctRoleCount       = $distinctRoles.Count
            DistinctRolesHeld       = ($distinctRoles -join '; ')
            ActiveCount             = $activeCount
            EligibleCount           = $eligibleCount
        }
    }

    $result = @($rows | Sort-Object -Property GroupDisplayName)

    if (-not $ReturnObjectsOnly) {
        $csvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\PrivilegedGroupPrincipals.csv'
        Export-PimData -Data $result -CsvPath $csvPath
        Write-PimLog -Message "Exported privileged group principals: $csvPath"
    }

    return $result
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimPrivilegedGroups @PSBoundParameters
}


