<#
.SYNOPSIS
Exports Microsoft Entra role assignment schedule instances (Active and Eligible) for PIM review.

.DESCRIPTION
Retrieves Active and Eligible role assignments from Microsoft Graph v1.0 schedule instance endpoints,
resolves role/principal details, and exports read-only evidence files.

Required delegated scope:
- RoleManagement.Read.Directory

.EXAMPLE
./Get-PimRoleAssignments.ps1 -OutputFolder .\Output -Verbose

.EXAMPLE
Get-PimRoleAssignments -OutputFolder .\Output -ReturnObjectsOnly
#>
[CmdletBinding()]
param(
    [string]$OutputFolder,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

function Convert-AssignmentInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [ValidateSet('Active', 'Eligible')]
        [string]$AssignmentState
    )

    $principal = $null
    if ($Item.principal) {
        $principal = $Item.principal
    }
    elseif ($Item.principalId) {
        $principal = Resolve-DirectoryObject -ObjectId $Item.principalId
    }

    $role = $null
    if ($Item.roleDefinition) {
        $role = $Item.roleDefinition
    }

    $principalType = if ($principal) { Get-PrincipalType -Principal $principal } else { 'Unknown' }
    $principalUpn = $null
    $principalUserType = $null

    if ($principal -and ($null -ne $principal.PSObject.Properties['userPrincipalName']) -and $principal.userPrincipalName) {
        $principalUpn = $principal.userPrincipalName
    }

    if ($principal -and ($null -ne $principal.PSObject.Properties['userType']) -and $principal.userType) {
        $principalUserType = $principal.userType
    }

    $isPermanent = [string]::IsNullOrWhiteSpace([string]$Item.endDateTime)
    $principalDisplayName = $null
    if ($principal) {
        if ($principal.displayName) {
            $principalDisplayName = $principal.displayName
        }
        elseif ($principal.userPrincipalName) {
            $principalDisplayName = $principal.userPrincipalName
        }
    }

    return [pscustomobject]@{
        AssignmentState      = $AssignmentState
        AssignmentId         = $Item.id
        RoleDisplayName      = $role.displayName
        RoleDefinitionId     = $Item.roleDefinitionId
        PrincipalId          = $Item.principalId
        PrincipalDisplayName = $principalDisplayName
        PrincipalUserPrincipalName = $principalUpn
        PrincipalUserType    = $principalUserType
        PrincipalType        = $principalType
        MemberType           = $Item.memberType
        StartDateTimeUtc     = $Item.startDateTime
        EndDateTimeUtc       = $Item.endDateTime
        IsPermanent          = $isPermanent
        DirectoryScopeId     = $Item.directoryScopeId
        AppScopeId           = $Item.appScopeId
    }
}

function Get-PimRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$ReturnObjectsOnly
    )

    $null = Ensure-Directory -Path $OutputFolder

    $activeUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal,roleDefinition'
    $eligibleUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal,roleDefinition'

    Write-PimLog -Message 'Retrieving Active role assignments from roleAssignmentScheduleInstances.'
    $activeItems = Get-GraphPagedResults -Uri $activeUri

    Write-PimLog -Message 'Retrieving Eligible role assignments from roleEligibilityScheduleInstances.'
    $eligibleItems = Get-GraphPagedResults -Uri $eligibleUri

    $activeRows = @(
        foreach ($item in @($activeItems)) {
            if ($item) {
                Convert-AssignmentInstance -Item $item -AssignmentState Active
            }
        }
    )

    $eligibleRows = @(
        foreach ($item in @($eligibleItems)) {
            if ($item) {
                Convert-AssignmentInstance -Item $item -AssignmentState Eligible
            }
        }
    )

    $result = @($activeRows + $eligibleRows)

    if (-not $ReturnObjectsOnly) {
        $csvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\RoleAssignments.csv'
        Export-PimData -Data $result -CsvPath $csvPath
        Write-PimLog -Message "Exported role assignments: $csvPath"
    }

    return $result
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimRoleAssignments @PSBoundParameters
}


