<#
.SYNOPSIS
Exports PIM role policy assignments and rules for assigned Microsoft Entra roles.

.DESCRIPTION
For each role definition with at least one assignment, retrieves roleManagementPolicyAssignment and
linked roleManagementPolicy rules, then flattens policy rules for reporting.

Required delegated scopes:
- RoleManagementPolicy.Read.Directory
- RoleManagement.Read.Directory

.EXAMPLE
./Get-PimRolePolicySettings.ps1 -RoleAssignments $assignments -OutputFolder .\Output -Verbose
#>
[CmdletBinding()]
param(
    [object[]]$RoleAssignments,

    [string]$OutputFolder,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
Import-Module -Name $commonModulePath -DisableNameChecking

function Get-ApproverIdsFromRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Rule
    )

    $ids = @()

    if ($Rule.setting -and $Rule.setting.approvalStages) {
        foreach ($stage in $Rule.setting.approvalStages) {
            foreach ($collectionName in @('primaryApprovers', 'escalationApprovers')) {
                if ($stage.$collectionName) {
                    foreach ($approver in $stage.$collectionName) {
                        if ($approver.id) {
                            $ids += [string]$approver.id
                        }
                    }
                }
            }
        }
    }

    return @($ids | Where-Object { $_ } | Select-Object -Unique)
}

function Resolve-ApproverDisplayNames {
    [CmdletBinding()]
    param(
        [object[]]$ApproverIds
    )

    $names = @()

    foreach ($id in @($ApproverIds | Where-Object { $_ })) {
        $resolved = Resolve-DirectoryObject -ObjectId $id
        if ($resolved) {
            $name = if ($resolved.displayName) { $resolved.displayName } else { $resolved.userPrincipalName }
            if ($name) {
                $names += [string]$name
            }
        }
    }

    return @($names | Select-Object -Unique)
}

function Convert-PolicyRuleToFlatRow {
    [CmdletBinding()]
    param(
        [string]$RoleName,

        [object]$PolicyAssignmentId,

        [object]$PolicyId,

        [object]$Rule
    )

    $ruleType = ($Rule.'@odata.type' -replace '^#microsoft.graph\.', '')
    $approverIds = Get-ApproverIdsFromRule -Rule $Rule
    $approverDisplayNames = Resolve-ApproverDisplayNames -ApproverIds $approverIds

    $operations = $null
    if ($Rule.operations) {
        $operations = ($Rule.operations -join '; ')
    }

    $isApprovalRequired = $false
    $approvalMode = $null
    $approverCount = 0

    if ($Rule.setting) {
        if ($Rule.setting.isApprovalRequired -ne $null) {
            $isApprovalRequired = [bool]$Rule.setting.isApprovalRequired
        }
        if ($Rule.setting.approvalMode) {
            $approvalMode = $Rule.setting.approvalMode
        }
        if ($Rule.setting.approvalStages) {
            $approverCount = @($approverIds).Count
        }
    }

    $requiresMfa = $null
    $requiresJustification = $null
    $requiresTicketInfo = $null

    if ($Rule.enabledRules) {
        $enabledRules = @($Rule.enabledRules)
        $requiresMfa = [bool]($enabledRules -contains 'MultiFactorAuthentication')
        $requiresJustification = [bool]($enabledRules -contains 'Justification')
        $requiresTicketInfo = [bool]($enabledRules -contains 'Ticketing')
    }

    $maxActivationDuration = $null
    $expirationRequired = $null
    if ($Rule.maximumDuration) {
        $maxActivationDuration = [string]$Rule.maximumDuration
    }
    if ($Rule.isExpirationRequired -ne $null) {
        $expirationRequired = [bool]$Rule.isExpirationRequired
    }

    $permanentActiveAllowed = $null
    $permanentEligibleAllowed = $null
    if ($Rule.allowPermanentAssignment -ne $null) {
        if (($Rule.id -match 'Expiration_Admin_Assignment') -or ($Rule.id -match 'Expiration_EndUser_Assignment')) {
            $permanentActiveAllowed = [bool]$Rule.allowPermanentAssignment
        }
        elseif (($Rule.id -match 'Expiration_Admin_Eligibility') -or ($Rule.id -match 'Expiration_EndUser_Eligibility')) {
            $permanentEligibleAllowed = [bool]$Rule.allowPermanentAssignment
        }
    }

    $notificationRecipientType = $null
    $notificationLevel = $null
    $notificationType = $null
    if ($Rule.recipientType) { $notificationRecipientType = [string]$Rule.recipientType }
    if ($Rule.notificationLevel) { $notificationLevel = [string]$Rule.notificationLevel }
    if ($Rule.notificationType) { $notificationType = [string]$Rule.notificationType }

    return [pscustomobject]@{
        RoleName                   = $RoleName
        PolicyAssignmentId         = if ($null -ne $PolicyAssignmentId) { [string]$PolicyAssignmentId } else { $null }
        PolicyId                   = if ($null -ne $PolicyId) { [string]$PolicyId } else { $null }
        RuleId                     = $Rule.id
        RuleType                   = $ruleType
        Caller                     = $Rule.caller
        Level                      = $Rule.level
        Operations                 = $operations
        IsApprovalRequired         = $isApprovalRequired
        ApprovalMode               = $approvalMode
        ApproverCount              = $approverCount
        ApproverIds                = (Get-UniqueJoinedValue -Values $approverIds)
        ApproverDisplayNames       = (Get-UniqueJoinedValue -Values $approverDisplayNames)
        MaxActivationDuration      = $maxActivationDuration
        RequiresMfa                = $requiresMfa
        RequiresJustification      = $requiresJustification
        RequiresTicketInfo         = $requiresTicketInfo
        PermanentActiveAllowed     = $permanentActiveAllowed
        PermanentEligibleAllowed   = $permanentEligibleAllowed
        ExpirationRequirement      = $expirationRequired
        NotificationRecipientType  = $notificationRecipientType
        NotificationLevel          = $notificationLevel
        NotificationType           = $notificationType
    }
}

function Get-PimRolePolicySettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$RoleAssignments,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$ReturnObjectsOnly
    )

    $roleIds = @(
        $RoleAssignments |
        ForEach-Object { [string]$_.RoleDefinitionId } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    )
    Write-PimLog -Message "Retrieving role policy settings for $($roleIds.Count) assigned roles."

    $rawPolicies = @()
    $flatRows = @()

    foreach ($roleId in $roleIds) {
        $roleName = ($RoleAssignments | Where-Object { $_.RoleDefinitionId -eq $roleId } | Select-Object -First 1 -ExpandProperty RoleDisplayName)
        $filter = [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$roleId'")
        $uri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=$filter&`$expand=policy(`$expand=rules)"

        $assignments = @(Get-GraphPagedResults -Uri $uri)

        foreach ($assignment in $assignments) {
            if (-not $assignment) {
                continue
            }

            $rawPolicies += $assignment

            $policy = $assignment.policy
            if (-not $policy -or -not $policy.rules) {
                continue
            }

            foreach ($rule in @($policy.rules)) {
                if ($rule) {
                    $flatRows += (Convert-PolicyRuleToFlatRow -RoleName $roleName -PolicyAssignmentId $assignment.id -PolicyId $policy.id -Rule $rule)
                }
            }
        }
    }

    $flat = @($flatRows)
    $raw = @($rawPolicies)

    if (-not $ReturnObjectsOnly) {
        $rawJsonPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\RolePolicySettings.raw.json'
        $flatCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\RolePolicySettings.flat.csv'

        Export-PimData -Data $raw -JsonPath $rawJsonPath
        Export-PimData -Data $flat -CsvPath $flatCsvPath

        Write-PimLog -Message "Exported role policy settings raw JSON: $rawJsonPath"
        Write-PimLog -Message "Exported role policy settings flat CSV: $flatCsvPath"
    }

    return [pscustomobject]@{
        RawPolicies = $raw
        FlatRules   = $flat
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimRolePolicySettings @PSBoundParameters
}


