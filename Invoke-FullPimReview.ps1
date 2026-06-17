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
    [string]$TenantId,
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
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimAdvancedRiskData.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Build-PimReviewWorkbook.ps1')

function Get-PimConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath
    )

    $resolvedConfigPath = $ConfigPath

    if (-not (Test-Path -Path $resolvedConfigPath)) {
        $candidatePaths = @(
            (Join-Path -Path $PSScriptRoot -ChildPath $ConfigPath),
            (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Config') -ChildPath $ConfigPath)
        )

        foreach ($candidate in $candidatePaths) {
            if (Test-Path -Path $candidate) {
                $resolvedConfigPath = $candidate
                break
            }
        }
    }

    if (-not (Test-Path -Path $resolvedConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $rawConfig = Get-Content -Path $resolvedConfigPath -Raw
    try {
        $cfg = $rawConfig | ConvertFrom-Json -Depth 20
    }
    catch {
        # Windows PowerShell 5.1 does not support -Depth on ConvertFrom-Json.
        $cfg = $rawConfig | ConvertFrom-Json
    }

    return @{
        OutputFolder                  = $cfg.OutputFolder
        TenantId                      = if ($null -ne $cfg.TenantId) { [string]$cfg.TenantId } else { $null }
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

function Get-TenantProfile {
    [CmdletBinding()]
    param()

    $org = $null
    try {
        $orgItems = @(
            Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/organization?`$select=id,displayName,verifiedDomains,tenantType,countryLetterCode,onPremisesSyncEnabled'
        )
        if ($orgItems.Count -gt 0) {
            $org = $orgItems[0]
        }
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve organization profile: $($_.Exception.Message)"
    }

    $context = Get-MgContext -ErrorAction SilentlyContinue
    $tenantId = if ($context -and $context.TenantId) { [string]$context.TenantId } else { $null }
    if ([string]::IsNullOrWhiteSpace($tenantId) -and $org -and $org.id) {
        $tenantId = [string]$org.id
    }

    $verifiedDomains = @()
    if ($org -and $org.verifiedDomains) {
        $verifiedDomains = @($org.verifiedDomains)
    }

    $initialDomain = $null
    if ($verifiedDomains.Count -gt 0) {
        $initialDomain = @($verifiedDomains | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1 -ExpandProperty name)
        if (-not $initialDomain) {
            $initialDomain = @($verifiedDomains | Where-Object { $_.name -like '*.onmicrosoft.com' } | Select-Object -First 1 -ExpandProperty name)
        }
    }

    $initialDomainName = if ($initialDomain) { [string]$initialDomain[0] } else { $null }
    $prefix = $null
    if (-not [string]::IsNullOrWhiteSpace($initialDomainName) -and $initialDomainName -match '^(?<prefix>.+?)\.onmicrosoft\.com$') {
        $prefix = $Matches['prefix']
    }

    $displayName = if ($org -and $org.displayName) { [string]$org.displayName } else { $null }
    $labelSource = if (-not [string]::IsNullOrWhiteSpace($prefix)) { $prefix } elseif (-not [string]::IsNullOrWhiteSpace($displayName)) { $displayName } elseif (-not [string]::IsNullOrWhiteSpace($tenantId)) { $tenantId } else { 'Tenant' }
    $tenantLabel = Get-SafeFileName -Name $labelSource

    if ([string]::IsNullOrWhiteSpace($tenantLabel)) {
        $tenantLabel = 'Tenant'
    }

    return [pscustomobject]@{
        TenantId               = $tenantId
        TenantDisplayName      = $displayName
        TenantType             = if ($org) { $org.tenantType } else { $null }
        CountryLetterCode      = if ($org) { $org.countryLetterCode } else { $null }
        OnPremisesSyncEnabled  = if ($org) { $org.onPremisesSyncEnabled } else { $null }
        InitialOnMicrosoftDomain = $initialDomainName
        TenantPrefix           = $prefix
        TenantLabel            = $tenantLabel
        VerifiedDomains        = $verifiedDomains
    }
}

function New-PimSummaryReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [Parameter(Mandatory)]
        [object]$TenantProfile,

        [Parameter(Mandatory)]
        [object]$RunMeta,

        [object[]]$Findings,

        [object[]]$UserAccessPaths,

        [object[]]$ActivationAnomalies,

        [object[]]$ConditionalAccessPolicies,

        [object[]]$AccessReviews,

        [object[]]$WorkloadIdentityRisk,

        [object[]]$NestedGroupPaths,

        [object[]]$SodConflicts
    )

    $highCount = @($Findings | Where-Object { $_.RiskRating -eq 'High' }).Count
    $mediumCount = @($Findings | Where-Object { $_.RiskRating -eq 'Medium' }).Count
    $lowCount = @($Findings | Where-Object { $_.RiskRating -eq 'Low' }).Count

    $guestPathCount = @($UserAccessPaths | Where-Object { $_.UserCategory -eq 'Guest' }).Count
    $guestInheritedCount = @($UserAccessPaths | Where-Object { $_.UserCategory -eq 'Guest' -and $_.AccessPathType -eq 'GroupInherited' }).Count
    $highActivationAnomalies = @($ActivationAnomalies | Where-Object { $_.MaxRiskRating -eq 'High' }).Count
    $caPoliciesNoMfa = @($ConditionalAccessPolicies | Where-Object { $_.State -eq 'enabled' -and $_.RequiresMfaControl -eq $false }).Count
    $accessReviewActive = @($AccessReviews | Where-Object { $_.Status -match 'InProgress|Starting|Ready' }).Count
    $workloadHigh = @($WorkloadIdentityRisk | Where-Object { $_.WorkloadRiskRating -eq 'High' }).Count
    $deepNestedPaths = @($NestedGroupPaths | Where-Object { $_.PathDepth -ge 2 }).Count
    $sodHigh = @($SodConflicts | Where-Object { $_.ConflictRisk -eq 'High' }).Count

    $topFindingTypes = @(
        $Findings |
        Group-Object -Property FindingType |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10
    )

    $topRoles = @(
        $UserAccessPaths |
        Group-Object -Property RoleName |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10
    )

    $summaryPath = Join-Path -Path $OutputFolder -ChildPath 'Summary.md'
    $summaryHtmlPath = Join-Path -Path $OutputFolder -ChildPath 'Summary.html'

    $lines = @()
    $lines += '# PIM Review Summary'
    $lines += ''
    $lines += "- Run UTC: $($RunMeta.RunUtc)"
    $lines += "- Tenant Display Name: $($TenantProfile.TenantDisplayName)"
    $lines += "- Tenant ID: $($TenantProfile.TenantId)"
    $lines += "- Initial .onmicrosoft.com Domain: $($TenantProfile.InitialOnMicrosoftDomain)"
    $lines += "- Output Folder: $($RunMeta.OutputFolder)"
    $lines += "- Workbook: $($RunMeta.WorkbookPath)"
    $lines += ''
    $lines += '## Findings Overview'
    $lines += ''
    $lines += "- Total Findings: $(@($Findings).Count)"
    $lines += "- High: $highCount"
    $lines += "- Medium: $mediumCount"
    $lines += "- Low: $lowCount"
    $lines += ''
    $lines += '## Access Path Overview'
    $lines += ''
    $lines += "- Total User Access Paths: $(@($UserAccessPaths).Count)"
    $lines += "- Guest Access Paths: $guestPathCount"
    $lines += "- Guest Group-Inherited Paths: $guestInheritedCount"
    $lines += ''
    $lines += '## Governance And Control Posture'
    $lines += ''
    $lines += "- High Activation Anomalies: $highActivationAnomalies"
    $lines += "- Enabled CA Policies Without MFA Control: $caPoliciesNoMfa"
    $lines += "- Active Access Reviews: $accessReviewActive"
    $lines += "- High-Risk Workload Identities: $workloadHigh"
    $lines += "- Deep Nested Group Paths (depth >= 2): $deepNestedPaths"
    $lines += "- High-Risk SoD Conflicts: $sodHigh"
    $lines += ''
    $lines += '## Top Finding Types'
    $lines += ''
    foreach ($row in $topFindingTypes) {
        $lines += "- $($row.Name): $($row.Count)"
    }
    $lines += ''
    $lines += '## Top Roles By Access Paths'
    $lines += ''
    foreach ($row in $topRoles) {
        $lines += "- $($row.Name): $($row.Count)"
    }

    $lines | Out-File -FilePath $summaryPath -Encoding UTF8

    $html = @()
    $html += '<!doctype html>'
    $html += '<html>'
    $html += '<head>'
    $html += '<meta charset="utf-8" />'
    $html += '<title>PIM Review Summary</title>'
    $html += '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;line-height:1.4}h1,h2{margin-bottom:8px}ul{margin-top:0}table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:6px 10px}</style>'
    $html += '</head>'
    $html += '<body>'
    $html += '<h1>PIM Review Summary</h1>'
    $html += '<h2>Run Details</h2>'
    $html += '<ul>'
    $html += "<li>Run UTC: $($RunMeta.RunUtc)</li>"
    $html += "<li>Tenant Display Name: $($TenantProfile.TenantDisplayName)</li>"
    $html += "<li>Tenant ID: $($TenantProfile.TenantId)</li>"
    $html += "<li>Initial .onmicrosoft.com Domain: $($TenantProfile.InitialOnMicrosoftDomain)</li>"
    $html += "<li>Output Folder: $($RunMeta.OutputFolder)</li>"
    $html += "<li>Workbook: $($RunMeta.WorkbookPath)</li>"
    $html += '</ul>'
    $html += '<h2>Findings Overview</h2>'
    $html += '<ul>'
    $html += "<li>Total Findings: $(@($Findings).Count)</li>"
    $html += "<li>High: $highCount</li>"
    $html += "<li>Medium: $mediumCount</li>"
    $html += "<li>Low: $lowCount</li>"
    $html += '</ul>'
    $html += '<h2>Access Path Overview</h2>'
    $html += '<ul>'
    $html += "<li>Total User Access Paths: $(@($UserAccessPaths).Count)</li>"
    $html += "<li>Guest Access Paths: $guestPathCount</li>"
    $html += "<li>Guest Group-Inherited Paths: $guestInheritedCount</li>"
    $html += '</ul>'
    $html += '<h2>Governance And Control Posture</h2>'
    $html += '<ul>'
    $html += "<li>High Activation Anomalies: $highActivationAnomalies</li>"
    $html += "<li>Enabled CA Policies Without MFA Control: $caPoliciesNoMfa</li>"
    $html += "<li>Active Access Reviews: $accessReviewActive</li>"
    $html += "<li>High-Risk Workload Identities: $workloadHigh</li>"
    $html += "<li>Deep Nested Group Paths (depth >= 2): $deepNestedPaths</li>"
    $html += "<li>High-Risk SoD Conflicts: $sodHigh</li>"
    $html += '</ul>'
    $html += '<h2>Top Finding Types</h2>'
    $html += '<ul>'
    foreach ($row in $topFindingTypes) {
        $html += "<li>$($row.Name): $($row.Count)</li>"
    }
    $html += '</ul>'
    $html += '<h2>Top Roles By Access Paths</h2>'
    $html += '<ul>'
    foreach ($row in $topRoles) {
        $html += "<li>$($row.Name): $($row.Count)</li>"
    }
    $html += '</ul>'
    $html += '</body>'
    $html += '</html>'
    $html | Out-File -FilePath $summaryHtmlPath -Encoding UTF8

    return [pscustomobject]@{
        MarkdownPath = $summaryPath
        HtmlPath     = $summaryHtmlPath
    }
}

function Convert-SummaryToPdf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MarkdownPath,

        [Parameter(Mandatory)]
        [string]$PdfPath
    )

    try {
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
    }
    catch {
        Write-PimLog -Level WARN -Message 'Microsoft Word COM automation unavailable. Skipping automatic PDF generation.'
        return $null
    }

    try {
        $word.Visible = $false
        $doc = $word.Documents.Add()
        $markdownText = Get-Content -Path $MarkdownPath -Raw
        $doc.Content.Text = $markdownText
        $wdFormatPDF = 17
        $doc.SaveAs([ref]$PdfPath, [ref]$wdFormatPDF)
        $doc.Close()
        return $PdfPath
    }
    catch {
        Write-PimLog -Level WARN -Message "Automatic PDF generation failed: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($word) {
            $word.Quit()
        }
    }
}

function Invoke-FullPimReview {
    [CmdletBinding()]
    param(
        [string]$ConfigPath,
        [string]$OutputFolder,
        [string]$TenantId,
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

    if ($PSBoundParameters.ContainsKey('TenantId')) {
        $config.TenantId = $TenantId
    }

    if ([string]::IsNullOrWhiteSpace([string]$config.TenantId)) {
        $enteredTenant = Read-Host 'Enter tenant ID or tenant domain (for example contoso.onmicrosoft.com). Press Enter to use current/default context'
        if (-not [string]::IsNullOrWhiteSpace($enteredTenant)) {
            $config.TenantId = $enteredTenant.Trim()
        }
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

    $transcriptStarted = $false
    $runOutputFolder = $null
    $rawFolder = $null

    try {
        Initialize-PimCache

        $null = Connect-GraphForPimReview `
            -TenantId $config.TenantId `
            -IncludeLicenseDetails:$config.IncludeLicenseDetails `
            -IncludeApprovalHistory:$config.IncludeApprovalHistory `
            -IncludePimForGroups:$config.IncludePimForGroups

        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        $tenantProfile = Get-TenantProfile

        $tenantIdForFolder = if (-not [string]::IsNullOrWhiteSpace($tenantProfile.TenantId)) { $tenantProfile.TenantId } elseif ($graphContext) { $graphContext.TenantId } else { 'unknown-tenant' }
        $tenantRootName = Get-SafeFileName -Name ("{0}_{1}" -f $tenantProfile.TenantLabel, $tenantIdForFolder)
        $tenantRootFolder = Ensure-Directory -Path (Join-Path -Path $targetRoot -ChildPath $tenantRootName)
        $runOutputFolder = Ensure-Directory -Path (Join-Path -Path $tenantRootFolder -ChildPath "Run-$runFolderName")
        $rawFolder = Ensure-Directory -Path (Join-Path -Path $runOutputFolder -ChildPath 'Raw')

        $tenantDetailsJsonPath = Join-Path -Path $rawFolder -ChildPath 'TenantDetails.json'
        $tenantDetailsCsvPath = Join-Path -Path $rawFolder -ChildPath 'TenantDetails.csv'
        $tenantDetailsRow = [pscustomobject]@{
            TenantId                 = $tenantProfile.TenantId
            TenantDisplayName        = $tenantProfile.TenantDisplayName
            TenantType               = $tenantProfile.TenantType
            CountryLetterCode        = $tenantProfile.CountryLetterCode
            OnPremisesSyncEnabled    = $tenantProfile.OnPremisesSyncEnabled
            InitialOnMicrosoftDomain = $tenantProfile.InitialOnMicrosoftDomain
            TenantPrefix             = $tenantProfile.TenantPrefix
            TenantLabel              = $tenantProfile.TenantLabel
            VerifiedDomains          = (@($tenantProfile.VerifiedDomains | ForEach-Object { $_.name }) -join '; ')
        }
        Export-PimData -Data @($tenantDetailsRow) -CsvPath $tenantDetailsCsvPath -JsonPath $tenantDetailsJsonPath

        $transcriptPath = Join-Path -Path $runOutputFolder -ChildPath 'Transcript.log'
        if (-not $DisableTranscript) {
            $transcriptStarted = Start-PimTranscriptSafe -TranscriptPath $transcriptPath
        }

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

        $advancedRisk = Get-PimAdvancedRiskData `
            -RoleAssignments $roleAssignments `
            -PrivilegedGroups $privilegedGroups `
            -OutputFolder $runOutputFolder `
            -HighImpactRoles @($config.HighImpactRoles)

        $data = @{
            RoleAssignments = $roleAssignments
            RolePolicyRules = $policyRules
            PrivilegedGroups = $privilegedGroups
            GroupMembers = $groupMembers
            PimGroupAssignments = $pimGroupAssignments
            UserLicenses = $userLicenses
            ApprovalSettings = @($approvalData.ApprovalSettings)
            ApprovalHistory = @($approvalData.ApprovalHistory)
            ActivationRequests = @($advancedRisk.ActivationRequests)
            ActivationAnomalies = @($advancedRisk.ActivationAnomalies)
            ConditionalAccessPolicies = @($advancedRisk.ConditionalAccessPolicies)
            AccessReviews = @($advancedRisk.AccessReviews)
            WorkloadIdentityRisk = @($advancedRisk.WorkloadIdentityRisk)
            NestedGroupPaths = @($advancedRisk.NestedGroupPaths)
        }

        $workbookFileName = Get-SafeFileName -Name ("PIM_Review_{0}_{1}.xlsx" -f $tenantProfile.TenantLabel, $runFolderName)

        $workbookResult = Build-PimReviewWorkbook -Data $data -Config $config -OutputFolder $runOutputFolder `
            -WorkbookFileName $workbookFileName `
            -InstallImportExcelIfMissing:$config.InstallImportExcelIfMissing `
            -PromptToInstallImportExcel:$config.PromptToInstallImportExcel

        $runMeta = [pscustomobject]@{
            RunUtc                  = (Get-Date).ToUniversalTime().ToString('o')
            OutputFolder            = $runOutputFolder
            TenantId                = if (-not [string]::IsNullOrWhiteSpace($tenantProfile.TenantId)) { $tenantProfile.TenantId } elseif ($graphContext) { $graphContext.TenantId } else { $config.TenantId }
            TenantDisplayName       = $tenantProfile.TenantDisplayName
            TenantPrefix            = $tenantProfile.TenantPrefix
            InitialOnMicrosoftDomain = $tenantProfile.InitialOnMicrosoftDomain
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
                ActivationRequests = @($advancedRisk.ActivationRequests).Count
                ActivationAnomalies = @($advancedRisk.ActivationAnomalies).Count
                ConditionalAccessPolicies = @($advancedRisk.ConditionalAccessPolicies).Count
                AccessReviews = @($advancedRisk.AccessReviews).Count
                WorkloadIdentityRisk = @($advancedRisk.WorkloadIdentityRisk).Count
                NestedGroupPaths = @($advancedRisk.NestedGroupPaths).Count
                UserAccessPaths = @($workbookResult.UserAccessPaths).Count
                UserRoleSummary = @($workbookResult.UserRoleSummary).Count
                GroupRoleSummary = @($workbookResult.GroupRoleSummary).Count
                Findings        = @($workbookResult.Findings).Count
            }
        }

        $summaryInfo = New-PimSummaryReport `
            -OutputFolder $runOutputFolder `
            -TenantProfile $tenantProfile `
            -RunMeta $runMeta `
            -Findings $workbookResult.Findings `
            -UserAccessPaths $workbookResult.UserAccessPaths `
            -ActivationAnomalies $advancedRisk.ActivationAnomalies `
            -ConditionalAccessPolicies $advancedRisk.ConditionalAccessPolicies `
            -AccessReviews $advancedRisk.AccessReviews `
            -WorkloadIdentityRisk $advancedRisk.WorkloadIdentityRisk `
            -NestedGroupPaths $advancedRisk.NestedGroupPaths `
            -SodConflicts $workbookResult.SoDConflicts

        $summaryPdfPath = Join-Path -Path $runOutputFolder -ChildPath 'Summary.pdf'
        $pdfPath = Convert-SummaryToPdf -MarkdownPath $summaryInfo.MarkdownPath -PdfPath $summaryPdfPath
        Add-Member -InputObject $runMeta -NotePropertyName SummaryPath -NotePropertyValue $summaryInfo.MarkdownPath -Force
        Add-Member -InputObject $runMeta -NotePropertyName SummaryHtmlPath -NotePropertyValue $summaryInfo.HtmlPath -Force
        Add-Member -InputObject $runMeta -NotePropertyName SummaryPdfPath -NotePropertyValue $pdfPath -Force

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


