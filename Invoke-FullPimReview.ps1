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
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

. (Join-Path -Path $PSScriptRoot -ChildPath 'Connect-GraphForPimReview.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimRoleAssignments.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimRolePolicySettings.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimPrivilegedGroups.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimGroupMembers.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimGroupAssignments.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimUserLicenses.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimApprovalData.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimAdvancedRiskData.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimRoleElevationMatrix.ps1')
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
        TenantLabelOverride           = if ($null -ne $cfg.TenantLabelOverride) { [string]$cfg.TenantLabelOverride } else { $null }
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
    param(
        [string]$TenantLabelOverride
    )

    $org = $null
    try {
        $orgItems = @(
            Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains,countryLetterCode,onPremisesSyncEnabled'
        )
        if ($orgItems.Count -gt 0) {
            $org = $orgItems[0]
        }
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve organization profile: $($_.Exception.Message)"
    }

    $domains = @()
    try {
        $domains = @(
            Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isDefault,isInitial,isVerified'
        )
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve domains profile: $($_.Exception.Message)"
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

    if ($verifiedDomains.Count -eq 0 -and $domains.Count -gt 0) {
        $verifiedDomains = @(
            foreach ($d in $domains) {
                [pscustomobject]@{
                    name      = $d.id
                    isInitial = $d.isInitial
                    isDefault = $d.isDefault
                    isVerified = $d.isVerified
                }
            }
        )
    }

    $primaryDomainName = $null
    if ($verifiedDomains.Count -gt 0) {
        $primaryDomainName = @($verifiedDomains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1 -ExpandProperty name)
        if (-not $primaryDomainName) {
            $primaryDomainName = @($verifiedDomains | Where-Object { $_.name -notlike '*.onmicrosoft.com' -and ($_.isVerified -ne $false) } | Select-Object -First 1 -ExpandProperty name)
        }
    }

    $initialDomain = $null
    if ($verifiedDomains.Count -gt 0) {
        $initialDomain = @($verifiedDomains | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1 -ExpandProperty name)
        if (-not $initialDomain) {
            $initialDomain = @($verifiedDomains | Where-Object { $_.name -like '*.onmicrosoft.com' } | Select-Object -First 1 -ExpandProperty name)
        }
    }

    $initialDomainName = if ($initialDomain) { [string]$initialDomain[0] } else { $null }
    $primaryDomain = if ($primaryDomainName) { [string]$primaryDomainName[0] } else { $null }

    if ([string]::IsNullOrWhiteSpace($primaryDomain) -and $context -and $context.Account -and ($context.Account -match '@')) {
        $primaryDomain = ($context.Account -split '@')[-1]
    }

    $primaryPrefix = $null
    if (-not [string]::IsNullOrWhiteSpace($primaryDomain) -and $primaryDomain -match '^(?<prefix>[^\.]+)\.') {
        $primaryPrefix = $Matches['prefix']
    }

    $prefix = $null
    if (-not [string]::IsNullOrWhiteSpace($initialDomainName) -and $initialDomainName -match '^(?<prefix>.+?)\.onmicrosoft\.com$') {
        $prefix = $Matches['prefix']
    }

    $displayName = if ($org -and $org.displayName) { [string]$org.displayName } else { $null }
    if ([string]::IsNullOrWhiteSpace($displayName) -and -not [string]::IsNullOrWhiteSpace($primaryPrefix)) {
        $displayName = $primaryPrefix
    }

    $labelSource = if (-not [string]::IsNullOrWhiteSpace($TenantLabelOverride)) { $TenantLabelOverride } elseif (-not [string]::IsNullOrWhiteSpace($displayName)) { $displayName } elseif (-not [string]::IsNullOrWhiteSpace($primaryPrefix)) { $primaryPrefix } elseif (-not [string]::IsNullOrWhiteSpace($prefix)) { $prefix } elseif (-not [string]::IsNullOrWhiteSpace($tenantId)) { $tenantId } else { 'Tenant' }
    $tenantLabel = Get-SafeFileName -Name $labelSource
    $tenantLabel = $tenantLabel -replace '\s+', '_'

    if ([string]::IsNullOrWhiteSpace($tenantLabel)) {
        $tenantLabel = 'Tenant'
    }

    # Keep report/display text aligned with tenant metadata from Graph; overrides are for file/folder labels only.
    $effectiveDisplayName = if (-not [string]::IsNullOrWhiteSpace($displayName)) { $displayName } elseif (-not [string]::IsNullOrWhiteSpace($primaryPrefix)) { $primaryPrefix } elseif (-not [string]::IsNullOrWhiteSpace($prefix)) { $prefix } elseif (-not [string]::IsNullOrWhiteSpace($TenantLabelOverride)) { $TenantLabelOverride } else { $tenantId }

    return [pscustomobject]@{
        TenantId               = $tenantId
        TenantDisplayName      = $displayName
        TenantDisplayNameEffective = $effectiveDisplayName
        TenantType             = if ($org) { $org.tenantType } else { $null }
        CountryLetterCode      = if ($org) { $org.countryLetterCode } else { $null }
        OnPremisesSyncEnabled  = if ($org) { $org.onPremisesSyncEnabled } else { $null }
        PrimaryDomain          = $primaryDomain
        PrimaryDomainPrefix    = $primaryPrefix
        InitialOnMicrosoftDomain = $initialDomainName
        TenantPrefix           = $prefix
        TenantLabel            = $tenantLabel
        VerifiedDomains        = $verifiedDomains
    }
}

function ConvertTo-MarkdownTable {
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        [string[]]$Columns
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        return @('- No rows')
    }

    $lines = @()
    $header = '| ' + (($Columns | ForEach-Object { $_ -replace '\|', '/' }) -join ' | ') + ' |'
    $separator = '| ' + (($Columns | ForEach-Object { '---' }) -join ' | ') + ' |'
    $lines += $header
    $lines += $separator

    foreach ($row in $Rows) {
        $values = @()
        foreach ($col in $Columns) {
            $value = $null
            if ($row -and ($null -ne $row.PSObject.Properties[$col])) {
                $value = $row.$col
            }

            if ($null -eq $value) {
                $values += ''
            }
            else {
                $values += ([string]$value -replace '\|', '/' -replace '[\r\n]+', ' ')
            }
        }

        $lines += ('| ' + ($values -join ' | ') + ' |')
    }

    return $lines
}

function ConvertTo-HtmlTable {
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        [string[]]$Columns
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        return '<p>No rows</p>'
    }

    $html = @()
    $html += '<table>'
    $html += '<thead><tr>'
    foreach ($col in $Columns) {
        $html += "<th>$col</th>"
    }
    $html += '</tr></thead>'
    $html += '<tbody>'

    foreach ($row in $Rows) {
        $html += '<tr>'
        foreach ($col in $Columns) {
            $value = $null
            if ($row -and ($null -ne $row.PSObject.Properties[$col])) {
                $value = $row.$col
            }

            $safe = if ($null -eq $value) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$value) }
            $html += "<td>$safe</td>"
        }
        $html += '</tr>'
    }

    $html += '</tbody></table>'
    return ($html -join '')
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

        [object[]]$RoleAssignments,

        [object[]]$Findings,

        [object[]]$UserAccessPaths,

        [object[]]$ActivationAnomalies,

        [object[]]$ConditionalAccessPolicies,

        [object[]]$AccessReviews,

        [object[]]$WorkloadIdentityRisk,

        [object[]]$NestedGroupPaths,

        [object[]]$SodConflicts,

        [object[]]$ExecutiveScorecard
    )

    param([object[]]$RoleElevationMatrix)


    $highCount = @($Findings | Where-Object { $_.RiskRating -eq 'High' }).Count

    $matrixRows = if ($null -ne $RoleElevationMatrix) { @($RoleElevationMatrix) } else { @() }

    $matrixCritical = @($matrixRows | Where-Object { $_.RiskRating -eq 'Critical' }).Count
    $matrixHigh     = @($matrixRows | Where-Object { $_.RiskRating -eq 'High'     }).Count
    $matrixMedium   = @($matrixRows | Where-Object { $_.RiskRating -eq 'Medium'   }).Count
    $matrixLow      = @($matrixRows | Where-Object { $_.RiskRating -eq 'Low'      }).Count
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

    $scoreRow = @($ExecutiveScorecard | Where-Object { $_.Metric -eq 'OverallRiskScore' } | Select-Object -First 1)
    $gaRow = @($ExecutiveScorecard | Where-Object { $_.Metric -eq 'GlobalAdminReachableUsers' } | Select-Object -First 1)
    $bgRow = @($ExecutiveScorecard | Where-Object { $_.Metric -eq 'BreakGlassAccountsDetected' } | Select-Object -First 1)
    $overallScore = if ($scoreRow) { [int]$scoreRow[0].Value } else { 0 }
    $overallTrafficLight = if ($scoreRow) { [string]$scoreRow[0].Status } else { 'Red' }
    $overallTrafficLight = if ([string]::IsNullOrWhiteSpace($overallTrafficLight)) { 'Red' } else { $overallTrafficLight }
    $overallTrafficLight = ("$overallTrafficLight").Trim()
    $trafficLightClass = switch -Regex ($overallTrafficLight.ToLowerInvariant()) {
        '^green$' { 'tl-green' }
        '^amber$|^yellow$' { 'tl-amber' }
        default { 'tl-red' }
    }
    $trafficLightColourName = switch ($trafficLightClass) {
        'tl-green' { 'Green' }
        'tl-amber' { 'Amber' }
        default { 'Red' }
    }
    $trafficLightHex = switch ($trafficLightClass) {
        'tl-green' { '#2e7d32' }
        'tl-amber' { '#ff8f00' }
        default { '#c62828' }
    }
    $executiveSummaryStatement = switch ($trafficLightClass) {
        'tl-green' { 'Overall assurance position is Green: core PIM controls are operating effectively, with targeted optimisations recommended.' }
        'tl-amber' { 'Overall assurance position is Amber: baseline controls exist, but notable weaknesses should be remediated in the near term.' }
        default { 'Overall assurance position is Red: significant control gaps present immediate risk and require urgent remediation.' }
    }
    $gaValue = if ($gaRow) { [int]$gaRow[0].Value } else { 0 }
    $bgValue = if ($bgRow) { [int]$bgRow[0].Value } else { 0 }
    $gaExposureClass = if ($gaValue -le 5) {
        'tl-green'
    }
    elseif ($gaValue -le 9) {
        'tl-amber'
    }
    else {
        'tl-red'
    }
    $gaExposureLabel = switch ($gaExposureClass) {
        'tl-green' { 'Green' }
        'tl-amber' { 'Amber' }
        default { 'Red' }
    }
    $gaExposureHex = switch ($gaExposureClass) {
        'tl-green' { '#2e7d32' }
        'tl-amber' { '#ff8f00' }
        default { '#c62828' }
    }
    $gaBandClass = 'band-' + ($gaExposureClass -replace '^tl-','')
    $trafficTextClass = 'status-text-' + ($trafficLightClass -replace '^tl-','')

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

    $explicitAssignmentRows = @(
        $RoleAssignments |
        Where-Object { $_.PrincipalType -in @('User', 'Group') } |
        Select-Object PrincipalType, PrincipalDisplayName, PrincipalUserPrincipalName, AssignmentState, RoleDisplayName, IsPermanent |
        Sort-Object -Property PrincipalType, PrincipalDisplayName, RoleDisplayName, AssignmentState
    )

    $groupElevationRows = @(
        $UserAccessPaths |
        Where-Object { $_.AccessPathType -eq 'GroupInherited' -and $_.UserId } |
        Group-Object -Property UserId |
        ForEach-Object {
            $rows = @($_.Group)
            $first = $rows[0]
            $roles = @($rows | Select-Object -ExpandProperty RoleName -Unique | Sort-Object)
            $groups = @($rows | Select-Object -ExpandProperty SourceGroupDisplayName -Unique | Sort-Object)
               [object[]]$ExecutiveScorecard,
               [object[]]$RoleElevationMatrix
            $eligibleCount = @($rows | Where-Object { $_.AssignmentState -eq 'Eligible' }).Count

            [pscustomobject]@{
                UserDisplayName          = $first.UserDisplayName
                UserPrincipalName        = $first.UserPrincipalName
                UserCategory             = $first.UserCategory
                RolesViaGroupMembership  = ($roles -join '; ')
                RoleCount                = $roles.Count
                ActivePathCount          = $activeCount
                EligiblePathCount        = $eligibleCount
                SourceGroups             = ($groups -join '; ')
            }
        } |
        Sort-Object -Property UserDisplayName
    )

    $scorecardTableRows = @(
        $ExecutiveScorecard |
        Select-Object Metric, Value, Status, Target, Commentary
    )

    $findingsDetailRows = @(
        $Findings |
        Select-Object RiskRating, FindingType, Subject, RoleName, Details, EvidenceId |
        Sort-Object -Property RiskRating, FindingType, Subject
    )

    $strengths = @()
    $improvements = @()

    if ($overallTrafficLight -eq 'Green') {
        $strengths += 'Overall control posture is strong based on the current composite risk score.'
    }
    elseif ($overallTrafficLight -eq 'Amber') {
        $strengths += 'Baseline controls are present, but several risk concentrations require remediation.'
    }

    if ($gaValue -le 5) {
        $strengths += "Global Administrator reachable user count is within target (current: $gaValue, target: <= 5)."
    }
    else {
        $improvements += "Reduce Global Administrator reachable users from $gaValue to 5 or fewer by shifting excess users to eligible access."
    }

    if ($bgValue -eq 2) {
        $strengths += 'Break-glass account count aligns with target control baseline (2 accounts).'
    }
    else {
        $improvements += "Align break-glass account population to exactly 2 accounts (current: $bgValue)."
    }

    if ($caPoliciesNoMfa -eq 0) {
        $strengths += 'All enabled Conditional Access policies in scope include MFA controls.'
    }
    else {
        $improvements += "Remediate $caPoliciesNoMfa enabled Conditional Access policy/policies that do not enforce MFA controls."
    }

    if ($sodHigh -eq 0) {
        $strengths += 'No high-risk segregation-of-duties conflicts were detected.'
    }
    else {
        $improvements += "Resolve $sodHigh high-risk segregation-of-duties conflicts by redistributing conflicting roles."
    }

    if ($highCount -eq 0) {
        $strengths += 'No high-risk findings were detected in the current evidence set.'
    }
    else {
        $improvements += "Close $highCount high-risk findings as immediate remediation priority."
    }

    if ($strengths.Count -eq 0) {
        $strengths += 'Control maturity indicators are mixed and require focused remediation to establish a stable baseline.'
    }

    if ($improvements.Count -eq 0) {
        $improvements += 'Continue periodic assurance testing and maintain current control posture.'
    }

    $summaryPath = Join-Path -Path $OutputFolder -ChildPath 'Summary.md'
    $summaryHtmlPath = Join-Path -Path $OutputFolder -ChildPath 'Summary.html'
    $assessmentDate = (Get-Date $RunMeta.RunUtc).ToString('yyyy-MM-dd')

    $lines = @()
    $lines += '# Privileged Identity Management Assessment Report'
    $lines += ''
    $lines += '## Cover Page'
    $lines += ''
    $lines += "- Client: $($TenantProfile.TenantDisplayNameEffective)"
    $lines += '- Assessment Type: Microsoft Entra PIM Infrastructure Review'
    $lines += "- Assessment Date: $assessmentDate"
    $lines += '- Prepared By: Identity Security Advisory'
    $lines += "- Report Identifier: PIM-$($TenantProfile.TenantLabel)-$assessmentDate"
    $lines += ''
    $lines += '## Executive Summary'
    $lines += ''
    $lines += "- Overall assurance colour rating: $trafficLightColourName"
    $lines += "- Summary statement: $executiveSummaryStatement"
    $lines += "- Overall score (0-100): $overallScore"
    $lines += ''
    $lines += '## Section Index'
    $lines += ''
    $lines += '- 1.0 Engagement Context'
    $lines += '- 2.0 Executive Findings Overview'
    $lines += '- 3.0 Access Path Overview'
    $lines += '- 4.0 Governance And Control Posture'
    $lines += '- 5.0 Top Finding Categories'
    $lines += '- 6.0 Top Roles By Exposure'
    $lines += '- 7.0 Risk Posture Narrative'
    $lines += '- 8.0 Control Strengths And Exposure Indicators'
    $lines += '- 9.0 Improvement Priorities'
    $lines += '- 10.0 Executive Scorecard'
    $lines += '- 11.0 Explicit Role Assignments (Users And Groups)'
    $lines += '- 12.0 User Elevation Paths Via Group Membership'
    $lines += '- 13.0 Detailed Findings Register'
    $lines += '- 14.0 Traffic Light Position'
    $lines += '- 15.0 Consultative Recommendations'
    $lines += '- 16.0 Privileged Role Elevation Control Matrix'
    $lines += ''
    $lines += '## 1.0 Engagement Context'
    $lines += ''
    $lines += "- Run UTC: $($RunMeta.RunUtc)"
    $lines += "- Tenant Display Name: $($TenantProfile.TenantDisplayNameEffective)"
    $lines += "- Tenant ID: $($TenantProfile.TenantId)"
    $lines += "- Primary Domain: $($TenantProfile.PrimaryDomain)"
    $lines += "- Initial .onmicrosoft.com Domain: $($TenantProfile.InitialOnMicrosoftDomain)"
    $lines += "- Tenant Label: $($TenantProfile.TenantLabel)"
    $lines += "- Output Folder: $($RunMeta.OutputFolder)"
    $lines += "- Workbook: $($RunMeta.WorkbookPath)"
    $lines += ''
    $lines += '## 2.0 Executive Findings Overview'
    $lines += ''
    $lines += "- Total Findings: $(@($Findings).Count)"
    $lines += "- High: $highCount"
    $lines += "- Medium: $mediumCount"
    $lines += "- Low: $lowCount"
    $lines += ''
    $lines += '## 3.0 Access Path Overview'
    $lines += ''
    $lines += "- Total User Access Paths: $(@($UserAccessPaths).Count)"
    $lines += "- Guest Access Paths: $guestPathCount"
    $lines += "- Guest Group-Inherited Paths: $guestInheritedCount"
    $lines += ''
    $lines += '## 4.0 Governance And Control Posture'
    $lines += ''
    $lines += "- High Activation Anomalies: $highActivationAnomalies"
    $lines += "- Enabled CA Policies Without MFA Control: $caPoliciesNoMfa"
    $lines += "- Active Access Reviews: $accessReviewActive"
    $lines += "- High-Risk Workload Identities: $workloadHigh"
    $lines += "- Deep Nested Group Paths (depth >= 2): $deepNestedPaths"
    $lines += "- High-Risk SoD Conflicts: $sodHigh"
    $lines += ''
    $lines += '## 5.0 Top Finding Categories'
    $lines += ''
    foreach ($row in $topFindingTypes) {
        $lines += "- $($row.Name): $($row.Count)"
    }
    $lines += ''
    $lines += '## 6.0 Top Roles By Exposure'
    $lines += ''
    foreach ($row in $topRoles) {
        $lines += "- $($row.Name): $($row.Count)"
    }

    $lines += ''
    $lines += '## 7.0 Risk Posture Narrative'
    $lines += ''
    $lines += 'Context: This section explains the overall assurance position and what it means for privileged identity governance.'
    $lines += "The current PIM operating model is assessed as <span style='color:$trafficLightHex;font-weight:700'>$trafficLightColourName</span> based on role exposure, control coverage, and governance indicators."
    $lines += "This assessment combines direct and inherited privilege paths, role policy controls, CA posture, workload identity hygiene, and segregation-of-duties analysis."

    $lines += ''
    $lines += '## 8.0 Control Strengths And Exposure Indicators'
    $lines += ''
    $lines += 'Context: This section highlights controls that are performing well, while showing key exposure indicators against defined thresholds.'
    $lines += "- GA Exposure Indicator: <span style='color:$gaExposureHex;font-weight:700'>$gaExposureLabel</span> ($gaValue reachable users)"
    $lines += '- GA Thresholds: Green = 0-5, Amber = 6-9, Red = 10+'
    foreach ($item in $strengths) {
        $lines += "- $item"
    }

    $lines += ''
    $lines += '## 9.0 Improvement Priorities'
    $lines += ''
    foreach ($item in $improvements) {
        $lines += "- $item"
    }

    $lines += ''
    $lines += '## 10.0 Executive Scorecard'
    $lines += ''
    $lines += (ConvertTo-MarkdownTable -Rows $scorecardTableRows -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary'))

    $lines += ''
    $lines += '## 11.0 Explicit Role Assignments (Users And Groups)'
    $lines += ''
    $lines += (ConvertTo-MarkdownTable -Rows $explicitAssignmentRows -Columns @('PrincipalType', 'PrincipalDisplayName', 'PrincipalUserPrincipalName', 'AssignmentState', 'RoleDisplayName', 'IsPermanent'))

    $lines += ''
    $lines += '## 12.0 User Elevation Paths Via Group Membership'
    $lines += ''
    $lines += 'Context: This section shows each user''s inherited privilege routes through groups, including how many unique roles they can reach.'
    $lines += '- Role Count: Number of unique privileged roles reachable by the user via group membership.'
    $lines += '- Active Path Count: Number of currently active inherited role paths via group membership.'
    $lines += '- Eligible Path Count: Number of inherited role paths that are eligible (activatable) but not currently active.'
    $lines += (ConvertTo-MarkdownTable -Rows $groupElevationRows -Columns @('UserDisplayName', 'UserPrincipalName', 'UserCategory', 'RoleCount', 'RolesViaGroupMembership', 'ActivePathCount', 'EligiblePathCount', 'SourceGroups'))

    $lines += ''
    $lines += '## 13.0 Detailed Findings Register'
    $lines += ''
    $lines += (ConvertTo-MarkdownTable -Rows $findingsDetailRows -Columns @('RiskRating', 'FindingType', 'Subject', 'RoleName', 'Details', 'EvidenceId'))

    $lines += ''
    $lines += '## 14.0 Traffic Light Position'
    $lines += ''
    $lines += "- Overall Score (0-100): $overallScore"
    $lines += "- Overall Status: $overallTrafficLight"
    $lines += "- Global Administrator Reachable Users: $gaValue (target <= 5)"
    $lines += "- Break Glass Accounts Detected: $bgValue (target = 2)"

    $lines += ''
    $lines += '## 15.0 Consultative Recommendations'
    $lines += ''

    if ($gaValue -gt 5) {
        $lines += "- Priority 1: Reduce active Global Administrator exposure from $gaValue to 5 or fewer by moving excess users to eligible JIT and scoped admin roles."
    }
    else {
        $lines += '- Priority 1: Maintain Global Administrator population within the five-user maximum and validate emergency-only usage.'
    }

    if ($bgValue -ne 2) {
        $lines += "- Priority 1: Align break-glass account count to exactly 2 (currently $bgValue), ensure excluded CA controls are documented, and test sign-in quarterly."
    }
    else {
        $lines += '- Priority 1: Keep break-glass account controls as-is and confirm quarterly validation evidence is retained.'
    }

    if ($caPoliciesNoMfa -gt 0) {
        $lines += "- Priority 2: Remediate $caPoliciesNoMfa enabled Conditional Access policy/policies without MFA grant control."
    }

    if ($sodHigh -gt 0) {
        $lines += "- Priority 2: Resolve $sodHigh high-risk segregation-of-duties conflict(s) by splitting conflicting role combinations across separate operators."
    }

    if ($highCount -gt 0) {
        $lines += "- Priority 3: Triage and close $highCount high-risk findings first, then tackle medium findings in a 30/60/90-day plan."
    }

    $lines | Out-File -FilePath $summaryPath -Encoding UTF8

    $html = @()
    $html += '<!doctype html>'
    $html += '<html>'
    $html += '<head>'
    $html += '<meta charset="utf-8" />'
    $html += '<title>Privileged Identity Management Assessment Report</title>'
    $html += '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:28px;line-height:1.45;color:#222}h1{font-size:32px;margin-bottom:8px}h2{font-size:22px;margin-top:26px;margin-bottom:10px;border-bottom:1px solid #e3e3e3;padding-bottom:4px}h3{font-size:18px;margin-top:18px;margin-bottom:8px}.cover{border:2px solid #1f4e78;padding:20px;border-radius:8px;background:#f7fbff;margin-bottom:18px}.meta{margin:6px 0}.summary-card{border:2px solid #cfd8e3;padding:16px 18px;border-radius:8px;background:#fcfdff;margin-bottom:24px}.summary-title{font-size:20px;font-weight:700;margin-bottom:8px}.summary-line{margin:4px 0}.section-context{margin:8px 0 10px 0;color:#3f4f61;font-style:italic}.tl-dot{display:inline-block;width:14px;height:14px;border-radius:50%;margin-right:8px;vertical-align:middle;border:1px solid rgba(0,0,0,.2)}.tl-green{background:#2e7d32}.tl-amber{background:#ff8f00}.tl-red{background:#c62828}.status-pill{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:700;font-size:12px;color:#fff}.status-text-green{color:#2e7d32;font-weight:700}.status-text-amber{color:#ff8f00;font-weight:700}.status-text-red{color:#c62828;font-weight:700}.section-band{border-radius:8px;padding:12px 16px;margin:22px 0 12px 0;border:1px solid transparent}.section-band h2{margin:0;border-bottom:none;padding-bottom:0;color:#fff}.band-green{background:#2e7d32;border-color:#1b5e20}.band-amber{background:#ff8f00;border-color:#ef6c00}.band-red{background:#c62828;border-color:#8e0000}.section-break{page-break-before:always}ul{margin-top:0}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ddd;padding:6px 8px;vertical-align:top}th{background:#f4f6f8;text-align:left}.toc li{margin:4px 0}</style>'
    $html += '</head>'
    $html += '<body>'
    $html += '<div class="cover">'
    $html += '<h1>Privileged Identity Management Assessment Report</h1>'
    $html += "<div class=""meta""><strong>Client:</strong> $($TenantProfile.TenantDisplayNameEffective)</div>"
    $html += '<div class="meta"><strong>Assessment Type:</strong> Microsoft Entra PIM Infrastructure Review</div>'
    $html += "<div class=""meta""><strong>Assessment Date:</strong> $assessmentDate</div>"
    $html += '<div class="meta"><strong>Prepared By:</strong> Identity Security Advisory</div>'
    $html += "<div class=""meta""><strong>Report Identifier:</strong> PIM-$($TenantProfile.TenantLabel)-$assessmentDate</div>"
    $html += '</div>'

    $html += '<div class="summary-card">'
    $html += '<div class="summary-title">Executive Summary</div>'
    $html += "<div class=""summary-line""><span class=""tl-dot $trafficLightClass""></span><strong>Overall assurance colour rating:</strong> <span class=""status-pill $trafficLightClass"">$trafficLightColourName</span></div>"
    $html += "<div class=""summary-line""><strong>Summary statement:</strong> $([System.Net.WebUtility]::HtmlEncode($executiveSummaryStatement))</div>"
    $html += "<div class=""summary-line""><strong>Overall score (0-100):</strong> $overallScore</div>"
    $html += '</div>'

    $html += '<h2>Section Index</h2>'
    $html += '<ul class="toc">'
    $html += '<li>1.0 Engagement Context</li>'
    $html += '<li>2.0 Executive Findings Overview</li>'
    $html += '<li>3.0 Access Path Overview</li>'
    $html += '<li>4.0 Governance And Control Posture</li>'
    $html += '<li>5.0 Top Finding Categories</li>'
    $html += '<li>6.0 Top Roles By Exposure</li>'
    $html += '<li>7.0 Risk Posture Narrative</li>'
    $html += '<li>8.0 Control Strengths And Exposure Indicators</li>'
    $html += '<li>9.0 Improvement Priorities</li>'
    $html += '<li>10.0 Executive Scorecard</li>'
    $html += '<li>11.0 Explicit Role Assignments (Users And Groups)</li>'
    $html += '<li>12.0 User Elevation Paths Via Group Membership</li>'
    $html += '<li>13.0 Detailed Findings Register</li>'
    $html += '<li>14.0 Traffic Light Position</li>'
    $html += '<li>15.0 Consultative Recommendations</li>'
    $html += '<li>16.0 Privileged Role Elevation Control Matrix</li>'
    $html += '</ul>'

    $html += '<h2>1.0 Engagement Context</h2>'
    $html += '<ul>'
    $html += "<li>Run UTC: $($RunMeta.RunUtc)</li>"
    $html += "<li>Tenant Display Name: $($TenantProfile.TenantDisplayNameEffective)</li>"
    $html += "<li>Tenant ID: $($TenantProfile.TenantId)</li>"
    $html += "<li>Primary Domain: $($TenantProfile.PrimaryDomain)</li>"
    $html += "<li>Initial .onmicrosoft.com Domain: $($TenantProfile.InitialOnMicrosoftDomain)</li>"
    $html += "<li>Tenant Label: $($TenantProfile.TenantLabel)</li>"
    $html += "<li>Output Folder: $($RunMeta.OutputFolder)</li>"
    $html += "<li>Workbook: $($RunMeta.WorkbookPath)</li>"
    $html += '</ul>'
    $html += '<h2>2.0 Executive Findings Overview</h2>'
    $html += '<ul>'
    $html += "<li>Total Findings: $(@($Findings).Count)</li>"
    $html += "<li>High: $highCount</li>"
    $html += "<li>Medium: $mediumCount</li>"
    $html += "<li>Low: $lowCount</li>"
    $html += '</ul>'
    $html += '<h2>3.0 Access Path Overview</h2>'
    $html += '<ul>'
    $html += "<li>Total User Access Paths: $(@($UserAccessPaths).Count)</li>"
    $html += "<li>Guest Access Paths: $guestPathCount</li>"
    $html += "<li>Guest Group-Inherited Paths: $guestInheritedCount</li>"
    $html += '</ul>'
    $html += '<h2>4.0 Governance And Control Posture</h2>'
    $html += '<ul>'
    $html += "<li>High Activation Anomalies: $highActivationAnomalies</li>"
    $html += "<li>Enabled CA Policies Without MFA Control: $caPoliciesNoMfa</li>"
    $html += "<li>Active Access Reviews: $accessReviewActive</li>"
    $html += "<li>High-Risk Workload Identities: $workloadHigh</li>"
    $html += "<li>Deep Nested Group Paths (depth >= 2): $deepNestedPaths</li>"
    $html += "<li>High-Risk SoD Conflicts: $sodHigh</li>"
    $html += '</ul>'
    $html += '<h2>5.0 Top Finding Categories</h2>'
    $html += '<ul>'
    foreach ($row in $topFindingTypes) {
        $html += "<li>$($row.Name): $($row.Count)</li>"
    }
    $html += '</ul>'
    $html += '<h2>6.0 Top Roles By Exposure</h2>'
    $html += '<ul>'
    foreach ($row in $topRoles) {
        $html += "<li>$($row.Name): $($row.Count)</li>"
    }
    $html += '</ul>'

    $html += '<h2>7.0 Risk Posture Narrative</h2>'
    $html += '<p class="section-context">Context: this section explains the overall assurance position and what it means for privileged identity governance.</p>'
    $html += "<p>The current PIM operating model is assessed as <span class=""$trafficTextClass""><strong>$trafficLightColourName</strong></span> based on role exposure, control coverage, and governance indicators.</p>"
    $html += '<p>This assessment combines direct and inherited privilege paths, role policy controls, Conditional Access posture, workload identity hygiene, and segregation-of-duties analysis.</p>'

    $html += "<div class=""section-band $gaBandClass""><h2>8.0 Control Strengths And Exposure Indicators</h2></div>"
    $html += '<p class="section-context">Context: this section highlights controls that are performing well, while showing key exposure indicators against defined thresholds.</p>'
    $html += "<p><strong>GA Exposure Indicator:</strong> <span class=""status-pill $gaExposureClass"">$gaExposureLabel</span> ($gaValue reachable users)</p>"
    $html += '<p><strong>GA Thresholds:</strong> Green = 0-5, Amber = 6-9, Red = 10+</p>'
    $html += '<ul>'
    foreach ($item in $strengths) {
        $safeItem = [System.Net.WebUtility]::HtmlEncode($item)
        $html += "<li>$safeItem</li>"
    }
    $html += '</ul>'

    $html += '<h2>9.0 Improvement Priorities</h2>'
    $html += '<ul>'
    foreach ($item in $improvements) {
        $safeItem = [System.Net.WebUtility]::HtmlEncode($item)
        $html += "<li>$safeItem</li>"
    }
    $html += '</ul>'

    $html += '<h2>10.0 Executive Scorecard</h2>'
    $html += (ConvertTo-HtmlTable -Rows $scorecardTableRows -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary'))

    $html += '<h2 class="section-break">11.0 Explicit Role Assignments (Users And Groups)</h2>'
    $html += (ConvertTo-HtmlTable -Rows $explicitAssignmentRows -Columns @('PrincipalType', 'PrincipalDisplayName', 'PrincipalUserPrincipalName', 'AssignmentState', 'RoleDisplayName', 'IsPermanent'))

    $html += '<h2>12.0 User Elevation Paths Via Group Membership</h2>'
    $html += '<p class="section-context">Context: this section shows each user''s inherited privilege routes through groups, including how many unique roles they can reach.</p>'
    $html += '<ul>'
    $html += '<li><strong>Role Count:</strong> Number of unique privileged roles reachable by the user via group membership.</li>'
    $html += '<li><strong>Active Path Count:</strong> Number of currently active inherited role paths via group membership.</li>'
    $html += '<li><strong>Eligible Path Count:</strong> Number of inherited role paths that are eligible (activatable) but not currently active.</li>'
    $html += '</ul>'
    $html += (ConvertTo-HtmlTable -Rows $groupElevationRows -Columns @('UserDisplayName', 'UserPrincipalName', 'UserCategory', 'RoleCount', 'RolesViaGroupMembership', 'ActivePathCount', 'EligiblePathCount', 'SourceGroups'))

    $html += '<h2 class="section-break">13.0 Detailed Findings Register</h2>'
    $html += (ConvertTo-HtmlTable -Rows $findingsDetailRows -Columns @('RiskRating', 'FindingType', 'Subject', 'RoleName', 'Details', 'EvidenceId'))

    $html += '<h2>14.0 Traffic Light Position</h2>'
    $html += '<ul>'
    $html += "<li>Overall Score (0-100): $overallScore</li>"
    $html += "<li>Overall Colour Rating: <span class=""tl-dot $trafficLightClass""></span><span class=""status-pill $trafficLightClass"">$trafficLightColourName</span></li>"
    $html += "<li>Summary Statement: $([System.Net.WebUtility]::HtmlEncode($executiveSummaryStatement))</li>"
    $html += "<li>Global Administrator Reachable Users: $gaValue (target <= 5)</li>"
    $html += "<li>Break Glass Accounts Detected: $bgValue (target = 2)</li>"
    $html += '</ul>'

    $html += '<h2>15.0 Consultative Recommendations</h2>'
    $html += '<ul>'
    if ($gaValue -gt 5) {
        $html += "<li>Priority 1: Reduce active Global Administrator exposure from $gaValue to 5 or fewer by moving excess users to eligible JIT and scoped admin roles.</li>"
    }
    else {
        $html += '<li>Priority 1: Maintain Global Administrator population within the five-user maximum and validate emergency-only usage.</li>'
    }

    if ($bgValue -ne 2) {
        $html += "<li>Priority 1: Align break-glass account count to exactly 2 (currently $bgValue), ensure excluded CA controls are documented, and test sign-in quarterly.</li>"
    }
    else {
        $html += '<li>Priority 1: Keep break-glass account controls as-is and confirm quarterly validation evidence is retained.</li>'
    }

    if ($caPoliciesNoMfa -gt 0) {
        $html += "<li>Priority 2: Remediate $caPoliciesNoMfa enabled Conditional Access policy/policies without MFA grant control.</li>"
    }

    if ($sodHigh -gt 0) {
        $html += "<li>Priority 2: Resolve $sodHigh high-risk segregation-of-duties conflict(s) by splitting conflicting role combinations across separate operators.</li>"
    }

    if ($highCount -gt 0) {
        $html += "<li>Priority 3: Triage and close $highCount high-risk findings first, then tackle medium findings in a 30/60/90-day plan.</li>"
    }
    $html += '</ul>'
    $html += '</body>'
    $html += '</html>'

    # ── Section 16.0 — Privileged Role Elevation Control Matrix ──────────────────
    $html += '<h2 class="section-break">16.0 Privileged Role Elevation Control Matrix</h2>'
    $html += '<p class="section-context">Context: this technical appendix maps every assigned privileged role to its activation control settings and derived risk posture. Use this section to identify where PIM is deployed but ineffectively controlled.</p>'
    $html += '<ul>'
    $html += '<li><strong>Elevation Friction Score (0-100):</strong> +40 MFA required, +30 Approval with approvers configured, +20 Max duration &lt;= 8 hours, +10 Justification required. Higher = stronger JIT governance.</li>'
    $html += '<li><strong>Control Maturity:</strong> Well-Controlled (80-100), Partially Controlled (50-79), Weakly Controlled (20-49), Critical Gap (0-19).</li>'
    $html += '<li><strong>Risk Rating:</strong> Critical = high-impact with no MFA and no approval. High = high-impact with a major gap or permanent active assignment. Medium = notable control weakness. Low = controls in place.</li>'
    $html += '</ul>'
    $html += "<p><strong>Matrix summary:</strong> $($matrixRows.Count) roles analysed."
    $html += " <span class=""status-pill tl-red"">Critical: $matrixCritical</span>&nbsp;"
    $html += " <span class=""status-pill tl-red"">High: $matrixHigh</span>&nbsp;"
    $html += " <span class=""status-pill tl-amber"">Medium: $matrixMedium</span>&nbsp;"
    $html += " <span class=""status-pill tl-green"">Low: $matrixLow</span></p>"

    if ($matrixRows.Count -gt 0) {
        $html += '<table>'
        $html += '<thead><tr><th>Role Name</th><th>High Impact</th><th>Assignment Type</th><th>MFA</th><th>Approval</th><th>Approvers</th><th>Max Duration (h)</th><th>Justification</th><th>Friction Score</th><th>Maturity</th><th>Risk Rating</th><th>Control Gaps</th><th>Access Reviews</th></tr></thead>'
        $html += '<tbody>'
        foreach ($m in $matrixRows) {
            $rowBg = switch ($m.RiskRating) {
                'Critical' { '#ffcdd2' }
                'High'     { '#ffebee' }
                'Medium'   { '#fff8e1' }
                'Low'      { '#f1f8e9' }
                default    { '#ffffff' }
            }
            $ratingStyle = switch ($m.RiskRating) {
                'Critical' { 'color:#b71c1c;font-weight:700' }
                'High'     { 'color:#c62828;font-weight:700' }
                'Medium'   { 'color:#e65100;font-weight:700' }
                'Low'      { 'color:#2e7d32;font-weight:700' }
                default    { '' }
            }
            $hiLabel    = if ($m.IsHighImpact)          { 'Yes' } else { 'No' }
            $mfaLabel   = if ($null -eq $m.MfaRequired)          { '?' } elseif ($m.MfaRequired)          { 'Yes' } else { 'No' }
            $apprLabel  = if ($null -eq $m.ApprovalRequired)     { '?' } elseif ($m.ApprovalRequired)     { 'Yes' } else { 'No' }
            $justLabel  = if ($null -eq $m.JustificationRequired){ '?' } elseif ($m.JustificationRequired){ 'Yes' } else { 'No' }
            $durLabel   = if ($null -eq $m.MaxActivationDurationHours) { '?' } else { "$([Math]::Round($m.MaxActivationDurationHours,1))" }
            $revLabel   = if ($m.AccessReviewsEnabled)  { 'Yes' } else { 'No' }
            $approverEnc = if ($m.ApproverDisplayNames) { [System.Net.WebUtility]::HtmlEncode([string]$m.ApproverDisplayNames) } else { '&mdash;' }
            $gapsEnc    = if ($m.ControlGaps) { [System.Net.WebUtility]::HtmlEncode([string]$m.ControlGaps) } else { 'None' }
            $html += "<tr style=""background:$rowBg"">"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($m.RoleName))</strong></td>"
            $html += "<td>$hiLabel</td><td>$([System.Net.WebUtility]::HtmlEncode($m.AssignmentTypes))</td>"
            $html += "<td>$mfaLabel</td><td>$apprLabel</td><td style=""font-size:12px"">$approverEnc</td>"
            $html += "<td>$durLabel</td><td>$justLabel</td>"
            $html += "<td><strong>$($m.ElevationFrictionScore)</strong></td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode($m.ControlMaturityLabel))</td>"
            $html += "<td style=""$ratingStyle"">$([System.Net.WebUtility]::HtmlEncode($m.RiskRating))</td>"
            $html += "<td style=""font-size:12px"">$gapsEnc</td><td>$revLabel</td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p>No role elevation policy data is available for this run.</p>'
    }

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
        [string]$HtmlPath,

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
        $doc = $word.Documents.Open($HtmlPath)
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
        $tenantProfile = Get-TenantProfile -TenantLabelOverride $config.TenantLabelOverride

        $tenantRootName = Get-SafeFileName -Name $tenantProfile.TenantLabel
        $tenantRootFolder = Ensure-Directory -Path (Join-Path -Path $targetRoot -ChildPath $tenantRootName)
        $runOutputFolder = Ensure-Directory -Path (Join-Path -Path $tenantRootFolder -ChildPath "Run-$runFolderName")
        $rawFolder = Ensure-Directory -Path (Join-Path -Path $runOutputFolder -ChildPath 'Raw')

        $tenantDetailsJsonPath = Join-Path -Path $rawFolder -ChildPath 'TenantDetails.json'
        $tenantDetailsCsvPath = Join-Path -Path $rawFolder -ChildPath 'TenantDetails.csv'
        $tenantDetailsRow = [pscustomobject]@{
            TenantId                 = $tenantProfile.TenantId
            TenantDisplayName        = $tenantProfile.TenantDisplayName
            TenantDisplayNameEffective = $tenantProfile.TenantDisplayNameEffective
            TenantType               = $tenantProfile.TenantType
            CountryLetterCode        = $tenantProfile.CountryLetterCode
            OnPremisesSyncEnabled    = $tenantProfile.OnPremisesSyncEnabled
            PrimaryDomain            = $tenantProfile.PrimaryDomain
            PrimaryDomainPrefix      = $tenantProfile.PrimaryDomainPrefix
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

        # Build the Privileged Role Elevation Control Matrix from already-collected data.
        # No additional Graph API calls are made — analysis runs against the flat policy rules.
        Write-PimLog -Message 'Building Privileged Role Elevation Control Matrix.'
        $roleElevationMatrix = @(Get-PimRoleElevationMatrix `
            -PolicyRules      $policyRules `
            -RoleAssignments  $roleAssignments `
            -AccessReviews    @($advancedRisk.AccessReviews) `
            -Config           $config `
            -OutputFolder     $rawFolder `
            -ReturnObjectsOnly)
        $data['RoleElevationMatrix'] = $roleElevationMatrix

        $workbookResult = Build-PimReviewWorkbook -Data $data -Config $config -OutputFolder $runOutputFolder `
            -WorkbookFileName $workbookFileName `
            -InstallImportExcelIfMissing:$config.InstallImportExcelIfMissing `
            -PromptToInstallImportExcel:$config.PromptToInstallImportExcel

        $runMeta = [pscustomobject]@{
            RunUtc                  = (Get-Date).ToUniversalTime().ToString('o')
            OutputFolder            = $runOutputFolder
            TenantId                = if (-not [string]::IsNullOrWhiteSpace($tenantProfile.TenantId)) { $tenantProfile.TenantId } elseif ($graphContext) { $graphContext.TenantId } else { $config.TenantId }
            TenantDisplayName       = $tenantProfile.TenantDisplayName
            TenantDisplayNameEffective = $tenantProfile.TenantDisplayNameEffective
            PrimaryDomain           = $tenantProfile.PrimaryDomain
            PrimaryDomainPrefix     = $tenantProfile.PrimaryDomainPrefix
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
                UserElevationPaths = @($workbookResult.UserElevationPaths).Count
                UserRoleSummary = @($workbookResult.UserRoleSummary).Count
                GroupRoleSummary = @($workbookResult.GroupRoleSummary).Count
                ExecutiveScorecard = @($workbookResult.ExecutiveScorecard).Count
                Findings        = @($workbookResult.Findings).Count
            }
        }

        Add-Member -InputObject $runMeta.Counts -NotePropertyName RoleElevationMatrix -NotePropertyValue @($roleElevationMatrix).Count -Force

        $summaryInfo = New-PimSummaryReport `
            -OutputFolder $runOutputFolder `
            -TenantProfile $tenantProfile `
            -RunMeta $runMeta `
            -RoleAssignments $roleAssignments `
            -Findings $workbookResult.Findings `
            -UserAccessPaths $workbookResult.UserAccessPaths `
            -ActivationAnomalies $advancedRisk.ActivationAnomalies `
            -ConditionalAccessPolicies $advancedRisk.ConditionalAccessPolicies `
            -AccessReviews $advancedRisk.AccessReviews `
            -WorkloadIdentityRisk $advancedRisk.WorkloadIdentityRisk `
            -NestedGroupPaths $advancedRisk.NestedGroupPaths `
            -SodConflicts $workbookResult.SoDConflicts `
            -ExecutiveScorecard $workbookResult.ExecutiveScorecard

        $summaryInfo = New-PimSummaryReport `
            -OutputFolder      $runOutputFolder `
            -TenantProfile     $tenantProfile `
            -RunMeta           $runMeta `
            -RoleAssignments   $roleAssignments `
            -Findings          $workbookResult.Findings `
            -UserAccessPaths   $workbookResult.UserAccessPaths `
            -ActivationAnomalies       $advancedRisk.ActivationAnomalies `
            -ConditionalAccessPolicies $advancedRisk.ConditionalAccessPolicies `
            -AccessReviews             $advancedRisk.AccessReviews `
            -WorkloadIdentityRisk      $advancedRisk.WorkloadIdentityRisk `
            -NestedGroupPaths          $advancedRisk.NestedGroupPaths `
            -SodConflicts              $workbookResult.SoDConflicts `
            -ExecutiveScorecard        $workbookResult.ExecutiveScorecard `
            -RoleElevationMatrix       $roleElevationMatrix

        Add-Member -InputObject $runMeta -NotePropertyName RoleElevationMatrixPath -NotePropertyValue (Join-Path -Path $rawFolder -ChildPath 'RoleElevationMatrix.csv') -Force

        $summaryPdfPath = Join-Path -Path $runOutputFolder -ChildPath 'Summary.pdf'
    $pdfPath = Convert-SummaryToPdf -MarkdownPath $summaryInfo.MarkdownPath -HtmlPath $summaryInfo.HtmlPath -PdfPath $summaryPdfPath
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


