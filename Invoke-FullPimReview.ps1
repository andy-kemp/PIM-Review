<#
.SYNOPSIS
Runs a full Microsoft Entra PIM review export and workbook build.

.DESCRIPTION
Orchestrates all reporting scripts for:
- Entra role assignments (active and eligible)
- Role policy settings/rules
- Privileged group principals and members
- User licensing details with fallback mapping
- Approval settings and optional beta-derived approval history
- Derived findings and review workbook generation

This script is read-only. It does not modify tenant configuration.

.EXAMPLE
./Invoke-FullPimReview.ps1 -ConfigPath .\Config\pim-review.config.json -Verbose

.EXAMPLE
./Invoke-FullPimReview.ps1 -ConfigPath .\Config\pim-review.config.json -OutputFolder .\Output\Run-Manual -IncludeTransitiveMembers
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Config\pim-review.config.json'),
    [string]$OutputFolder,
    [switch]$IncludeTransitiveMembers,
    [switch]$IncludeApprovalHistory,
    [switch]$IncludeLicenseDetails,
    [switch]$IncludePimForGroups,
    [switch]$InstallImportExcelIfMissing,
    [switch]$PromptToInstallImportExcel,
    [switch]$DisableTranscript
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
Import-Module -Name $commonModulePath -DisableNameChecking

. (Join-Path -Path $PSScriptRoot -ChildPath 'Connect-GraphForPimReview.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimRoleAssignments.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimRolePolicySettings.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimPrivilegedGroups.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimGroupMembers.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimGroupAssignments.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimUserLicenses.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimApprovalData.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Build-PimReviewWorkbook.ps1')

function Get-PimConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    if (-not (Test-Path -Path $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $rawConfig = Get-Content -Path $ConfigPath -Raw
    try {
        $cfg = $rawConfig | ConvertFrom-Json -Depth 20
    }
    catch {
        # Windows PowerShell 5.1 does not support -Depth on ConvertFrom-Json.
        $cfg = $rawConfig | ConvertFrom-Json
    }

    return @{
        OutputFolder                  = $cfg.OutputFolder
        IncludeTransitiveMembers      = [bool]$cfg.IncludeTransitiveMembers
        IncludeApprovalHistory        = [bool]$cfg.IncludeApprovalHistory
        IncludeLicenseDetails         = [bool]$cfg.IncludeLicenseDetails
        IncludePimForGroups           = if ($null -ne $cfg.IncludePimForGroups) { [bool]$cfg.IncludePimForGroups } else { $false }
        InstallImportExcelIfMissing   = if ($null -ne $cfg.InstallImportExcelIfMissing) { [bool]$cfg.InstallImportExcelIfMissing } else { $false }
        PromptToInstallImportExcel    = if ($null -ne $cfg.PromptToInstallImportExcel) { [bool]$cfg.PromptToInstallImportExcel } else { $false }
        LongActivationThresholdHours  = [double]$cfg.LongActivationThresholdHours
        HighImpactRoles               = @($cfg.HighImpactRoles)
        ExpectedLicenseSkuPartNumbers = @($cfg.ExpectedLicenseSkuPartNumbers)
    }
}

function Invoke-FullPimReview {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [string]$OutputFolder,
        [switch]$IncludeTransitiveMembers,
        [switch]$IncludeApprovalHistory,
        [switch]$IncludeLicenseDetails,
        [switch]$IncludePimForGroups,
        [switch]$InstallImportExcelIfMissing,
        [switch]$PromptToInstallImportExcel,
        [switch]$DisableTranscript
    )

    $config = Get-PimConfig -ConfigPath $ConfigPath

    if ($PSBoundParameters.ContainsKey('OutputFolder')) {
        $config.OutputFolder = $OutputFolder
    }

    if ($IncludeTransitiveMembers.IsPresent) {
        $config.IncludeTransitiveMembers = $true
    }

    if ($IncludeApprovalHistory.IsPresent) {
        $config.IncludeApprovalHistory = $true
    }

    if ($IncludeLicenseDetails.IsPresent) {
        $config.IncludeLicenseDetails = $true
    }

    if ($IncludePimForGroups.IsPresent) {
        $config.IncludePimForGroups = $true
    }

    if ($InstallImportExcelIfMissing.IsPresent) {
        $config.InstallImportExcelIfMissing = $true
    }

    if ($PromptToInstallImportExcel.IsPresent) {
        $config.PromptToInstallImportExcel = $true
    }

    $runFolderName = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $targetRoot = Ensure-Directory -Path $config.OutputFolder
    $runOutputFolder = Ensure-Directory -Path (Join-Path -Path $targetRoot -ChildPath "Run-$runFolderName")
    $rawFolder = Ensure-Directory -Path (Join-Path -Path $runOutputFolder -ChildPath 'Raw')

    $transcriptPath = Join-Path -Path $runOutputFolder -ChildPath 'Transcript.log'
    $transcriptStarted = $false

    if (-not $DisableTranscript) {
        $transcriptStarted = Start-PimTranscriptSafe -TranscriptPath $transcriptPath
    }

    try {
        Initialize-PimCache

        $null = Connect-GraphForPimReview `
            -IncludeLicenseDetails:$config.IncludeLicenseDetails `
            -IncludeApprovalHistory:$config.IncludeApprovalHistory `
            -IncludePimForGroups:$config.IncludePimForGroups

        $roleAssignments = Get-PimRoleAssignments -OutputFolder $runOutputFolder

        $policyData = Get-PimRolePolicySettings -RoleAssignments $roleAssignments -OutputFolder $runOutputFolder
        $policyRules = @($policyData.FlatRules)

        $privilegedGroups = Get-PimPrivilegedGroups -RoleAssignments $roleAssignments -OutputFolder $runOutputFolder

        $groupMembers = @()
        if ($privilegedGroups.Count -gt 0) {
            $groupMembers = Get-PimGroupMembers -PrivilegedGroups $privilegedGroups -OutputFolder $runOutputFolder -IncludeTransitiveMembers:$config.IncludeTransitiveMembers
        }

        $pimGroupAssignments = @()
        if ($config.IncludePimForGroups) {
            $pimGroupIds = @($privilegedGroups | Select-Object -ExpandProperty GroupId -Unique)
            $pimGroupAssignments = Get-PimGroupAssignments -OutputFolder $runOutputFolder -GroupIds $pimGroupIds
        }

        $directUserIds = @($roleAssignments | Where-Object { $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty PrincipalId -Unique)
        $groupUserIds = @($groupMembers | Where-Object { $_.MemberType -eq 'User' } | Select-Object -ExpandProperty MemberId -Unique)
        $allUserIds = @($directUserIds + $groupUserIds | Where-Object { $_ } | Select-Object -Unique)

        $userLicenses = @()
        if ($allUserIds.Count -gt 0) {
            $userLicenses = Get-PimUserLicenses -UserIds $allUserIds -OutputFolder $runOutputFolder -IncludeLicenseDetails:$config.IncludeLicenseDetails
        }

        $approvalData = Get-PimApprovalData -PolicyFlatRules $policyRules -OutputFolder $runOutputFolder -IncludeApprovalHistory:$config.IncludeApprovalHistory

        $data = @{
            RoleAssignments = $roleAssignments
            RolePolicyRules = $policyRules
            PrivilegedGroups = $privilegedGroups
            GroupMembers = $groupMembers
            PimGroupAssignments = $pimGroupAssignments
            UserLicenses = $userLicenses
            ApprovalSettings = @($approvalData.ApprovalSettings)
            ApprovalHistory = @($approvalData.ApprovalHistory)
        }

        $workbookResult = Build-PimReviewWorkbook -Data $data -Config $config -OutputFolder $runOutputFolder `
            -InstallImportExcelIfMissing:$config.InstallImportExcelIfMissing `
            -PromptToInstallImportExcel:$config.PromptToInstallImportExcel

        $runMeta = [pscustomobject]@{
            RunUtc                  = (Get-Date).ToUniversalTime().ToString('o')
            OutputFolder            = $runOutputFolder
            IncludeTransitiveMembers = $config.IncludeTransitiveMembers
            IncludeApprovalHistory   = $config.IncludeApprovalHistory
            IncludeLicenseDetails    = $config.IncludeLicenseDetails
            IncludePimForGroups      = $config.IncludePimForGroups
            InstallImportExcelIfMissing = $config.InstallImportExcelIfMissing
            PromptToInstallImportExcel = $config.PromptToInstallImportExcel
            WorkbookCreated          = $workbookResult.WorkbookCreated
            WorkbookPath             = $workbookResult.WorkbookPath
            Counts = [pscustomobject]@{
                RoleAssignments = @($roleAssignments).Count
                PolicyRules     = @($policyRules).Count
                PrivilegedGroups = @($privilegedGroups).Count
                GroupMembers    = @($groupMembers).Count
                PimGroupAssignments = @($pimGroupAssignments).Count
                UserLicenses    = @($userLicenses).Count
                ApprovalSettings = @($approvalData.ApprovalSettings).Count
                ApprovalHistory = @($approvalData.ApprovalHistory).Count
                Findings        = @($workbookResult.Findings).Count
            }
        }

        $metaPath = Join-Path -Path $rawFolder -ChildPath 'RunMetadata.json'
        $runMeta | ConvertTo-Json -Depth 10 | Out-File -FilePath $metaPath -Encoding UTF8

        Write-PimLog -Message "Full PIM review completed. Output folder: $runOutputFolder"
        return $runMeta
    }
    finally {
        if ($transcriptStarted) {
            Stop-PimTranscriptSafe
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-FullPimReview @PSBoundParameters
}


