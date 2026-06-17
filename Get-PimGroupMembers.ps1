<#
.SYNOPSIS
Exports membership for privileged groups used in privileged role assignments.

.DESCRIPTION
Exports direct members for each privileged group and can optionally include transitive members.
Each group export is saved as an individual CSV and a combined dataset is returned.

Required delegated scope:
- Group.Read.All

.EXAMPLE
./Get-PimGroupMembers.ps1 -PrivilegedGroups $groups -OutputFolder .\Output -IncludeTransitiveMembers -Verbose
#>
[CmdletBinding()]
param(
    [object[]]$PrivilegedGroups,

    [string]$OutputFolder,

    [switch]$IncludeTransitiveMembers,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
Import-Module -Name $commonModulePath -DisableNameChecking

function Convert-GroupMemberRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$SourceGroup,

        [Parameter(Mandatory)]
        [object]$Member
    )

    $memberType = Get-PrincipalType -Principal $Member
    $isNested = $memberType -eq 'Group'
    $memberDisplayName = $null
    $memberUpn = $null
    $memberUserType = $null
    $memberAccountEnabled = $null

    if ($Member -and ($null -ne $Member.PSObject.Properties['displayName']) -and $Member.displayName) {
        $memberDisplayName = $Member.displayName
    }

    if ($Member -and ($null -ne $Member.PSObject.Properties['userPrincipalName']) -and $Member.userPrincipalName) {
        $memberUpn = $Member.userPrincipalName
    }

    if ($Member -and ($null -ne $Member.PSObject.Properties['userType']) -and $Member.userType) {
        $memberUserType = $Member.userType
    }

    if (-not $memberDisplayName) {
        $memberDisplayName = $memberUpn
    }

    if ($Member -and ($null -ne $Member.PSObject.Properties['accountEnabled'])) {
        $memberAccountEnabled = $Member.accountEnabled
    }

    return [pscustomobject]@{
        SourceGroupId           = $SourceGroup.GroupId
        SourceGroupDisplayName  = $SourceGroup.GroupDisplayName
        MemberId                = $Member.id
        MemberDisplayName       = $memberDisplayName
        MemberUserPrincipalName = $memberUpn
        MemberUserType          = $memberUserType
        MemberType              = $memberType
        AccountEnabled          = $memberAccountEnabled
        IsNestedGroup           = $isNested
    }
}

function Get-PimGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$PrivilegedGroups,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$IncludeTransitiveMembers,

        [switch]$ReturnObjectsOnly
    )

    $groupMembersFolder = Join-Path -Path $OutputFolder -ChildPath 'Raw\GroupMembers'
    $null = Ensure-Directory -Path $groupMembersFolder

    $combinedRows = @()

    foreach ($group in $PrivilegedGroups) {
        $groupId = $group.GroupId
        $groupName = if ($group.GroupDisplayName) { $group.GroupDisplayName } else { $groupId }
        $memberPath = if ($IncludeTransitiveMembers) { 'transitiveMembers' } else { 'members' }
        $uri = "https://graph.microsoft.com/v1.0/groups/${groupId}/${memberPath}?`$select=id,displayName,userPrincipalName,userType,accountEnabled"

        Write-PimLog -Message "Retrieving $memberPath for group $groupName ($groupId)."

        $members = @(Get-GraphPagedResults -Uri $uri)
        $rows = @()

        foreach ($member in @($members)) {
            if (-not $member) {
                continue
            }

            $row = Convert-GroupMemberRow -SourceGroup $group -Member $member
            $rows += $row
            $combinedRows += $row
        }

        if (-not $ReturnObjectsOnly) {
            $safeName = Get-SafeFileName -Name $groupName
            $fileName = "GroupMembers_${safeName}_$groupId.csv"
            $csvPath = Join-Path -Path $groupMembersFolder -ChildPath $fileName
            Export-PimData -Data @($rows) -CsvPath $csvPath
        }
    }

    $result = @($combinedRows)

    if (-not $ReturnObjectsOnly) {
        $combinedCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\GroupMembers.All.csv'
        Export-PimData -Data $result -CsvPath $combinedCsvPath
        Write-PimLog -Message "Exported combined group membership: $combinedCsvPath"
    }

    return $result
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimGroupMembers @PSBoundParameters
}


