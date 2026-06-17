<#
.SYNOPSIS
Exports PIM approval configuration and approval history data.

.DESCRIPTION
Builds approval settings from policy rules and, optionally, retrieves approval history / approval steps
for role activation requests from beta endpoints. Approval history output is clearly marked beta-derived.

Required delegated scopes:
- RoleManagementPolicy.Read.Directory (approval settings in rules)
- RoleManagement.Read.Directory (role activation requests)

Beta endpoints used only for approval history:
- /beta/roleManagement/directory/roleAssignmentScheduleRequests
- /beta/roleManagement/directory/roleAssignmentApprovals/{id}/steps

.EXAMPLE
./Get-PimApprovalData.ps1 -PolicyFlatRules $policy.FlatRules -IncludeApprovalHistory -OutputFolder .\Output -Verbose
#>
[CmdletBinding()]
param(
    [object[]]$PolicyFlatRules,

    [string]$OutputFolder,

    [switch]$IncludeApprovalHistory,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

function Get-PimApprovalData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$PolicyFlatRules,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$IncludeApprovalHistory,

        [switch]$ReturnObjectsOnly
    )

    $approvalSettings = @(
        $PolicyFlatRules |
        Where-Object { $_.IsApprovalRequired -eq $true } |
        Select-Object RoleName, PolicyAssignmentId, PolicyId, RuleId, ApprovalMode, ApproverCount, ApproverIds, ApproverDisplayNames
    )

    $approvalHistoryRows = @()

    if ($IncludeApprovalHistory) {
        Write-PimLog -Message 'Retrieving approval history (beta-derived) for role activation requests.'

        $requestUri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleRequests?$filter=action eq ''selfActivate''&$expand=principal,roleDefinition'
        $requests = @()

        try {
            $requests = Get-GraphPagedResults -Uri $requestUri
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read role activation requests from beta endpoint: $($_.Exception.Message)"
        }

        foreach ($request in $requests) {
            if (-not $request.approvalId) {
                continue
            }

            $steps = @()
            $stepsUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentApprovals/$($request.approvalId)/steps"

            try {
                $steps = Get-GraphPagedResults -Uri $stepsUri
            }
            catch {
                Write-PimLog -Level WARN -Message "Unable to read approval steps for approvalId $($request.approvalId): $($_.Exception.Message)"
                continue
            }

            foreach ($step in $steps) {
                $approverId = $null
                $approverDisplayName = $null

                if ($step.reviewedBy -and $step.reviewedBy.id) {
                    $approverId = $step.reviewedBy.id
                    $approverDisplayName = $step.reviewedBy.displayName
                }
                elseif ($step.assignedToMe -and $step.assignedToMe.id) {
                    $approverId = $step.assignedToMe.id
                    $approverDisplayName = $step.assignedToMe.displayName
                }

                if (-not $approverDisplayName -and $approverId) {
                    $obj = Resolve-DirectoryObject -ObjectId $approverId
                    if ($obj) {
                        $approverDisplayName = if ($obj.displayName) { $obj.displayName } else { $obj.userPrincipalName }
                    }
                }

                $principalName = $null
                if ($request.principal) {
                    $principalName = if ($request.principal.displayName) { $request.principal.displayName } else { $request.principal.userPrincipalName }
                }

                $approvalHistoryRows += [pscustomobject]@{
                    ApprovalObjectId      = $request.approvalId
                    RequestId             = $request.id
                    RoleName              = $request.roleDefinition.displayName
                    PrincipalName         = $principalName
                    PrincipalId           = $request.principalId
                    RequestCreatedDate    = $request.createdDateTime
                    StepId                = $step.id
                    StepStatus            = $step.status
                    ReviewResult          = $step.reviewResult
                    ApproverDisplayName   = $approverDisplayName
                    ApproverId            = $approverId
                    Justification         = $step.justification
                    LastModifiedDate      = $step.lastModifiedDateTime
                    IsBetaDerived         = $true
                }
            }
        }
    }

    $history = @($approvalHistoryRows)

    if (-not $ReturnObjectsOnly) {
        $settingsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\ApprovalSettings.csv'
        $historyCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\ApprovalHistory.beta.csv'

        Export-PimData -Data $approvalSettings -CsvPath $settingsCsvPath
        Export-PimData -Data $history -CsvPath $historyCsvPath

        Write-PimLog -Message "Exported approval settings: $settingsCsvPath"
        Write-PimLog -Message "Exported approval history (beta-derived): $historyCsvPath"
    }

    return [pscustomobject]@{
        ApprovalSettings = $approvalSettings
        ApprovalHistory  = $history
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimApprovalData @PSBoundParameters
}


