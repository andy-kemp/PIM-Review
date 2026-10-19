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
    [switch]$IncludeAuthStrength,
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
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimIdentityAnalysis.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-PimApproverAnalysis.ps1')
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
        NamingCompliancePrefix        = if ($null -ne $cfg.NamingCompliancePrefix -and -not [string]::IsNullOrWhiteSpace($cfg.NamingCompliancePrefix)) { [string]$cfg.NamingCompliancePrefix } else { 'CLAD_' }
        IncludeAuthStrength           = if ($null -ne $cfg.IncludeAuthStrength) { [bool]$cfg.IncludeAuthStrength } else { $false }
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

    $labelSource = if (-not [string]::IsNullOrWhiteSpace($displayName)) { $displayName } elseif (-not [string]::IsNullOrWhiteSpace($primaryPrefix)) { $primaryPrefix } elseif (-not [string]::IsNullOrWhiteSpace($prefix)) { $prefix } elseif (-not [string]::IsNullOrWhiteSpace($TenantLabelOverride)) { $TenantLabelOverride } elseif (-not [string]::IsNullOrWhiteSpace($tenantId)) { $tenantId } else { 'Tenant' }
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

        [object[]]$ExecutiveScorecard,

        [object[]]$RoleElevationMatrix,

        [object[]]$PrivilegeConcentration,

        [object[]]$GroupRiskProfiles,

        [object]$JitEffectiveness,

        [string[]]$KeyInsights,

        [object[]]$GuestPrivilegedAccounts,

        [object[]]$NamingCompliance,

        [object[]]$LicensedPrivilegedAccounts,

        [object[]]$IdentityAssuranceProfiles,

        [object[]]$AuthStrengthData,

        [object[]]$CACoverage,

        [object[]]$ApprovalAnalysis,

        [object[]]$ApproverProfiles,

        [object[]]$ApproverGroupRoleMap
    )


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
            $activeCount = @($rows | Where-Object { $_.AssignmentState -eq 'Active' }).Count
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

    $userPrivilegedAccessRows = @(
        $UserAccessPaths |
        Where-Object { $_.UserId } |
        Group-Object -Property UserId |
        ForEach-Object {
            $rows = @($_.Group)
            $first = $rows[0]
            $directRoles = @(
                $rows |
                Where-Object { $_.AccessPathType -ne 'GroupInherited' } |
                Select-Object -ExpandProperty RoleName -Unique |
                Sort-Object
            )
            $inheritedRoles = @(
                $rows |
                Where-Object { $_.AccessPathType -eq 'GroupInherited' } |
                Select-Object -ExpandProperty RoleName -Unique |
                Sort-Object
            )
            $allRoles = @(($directRoles + $inheritedRoles) | Select-Object -Unique | Sort-Object)

            if ($allRoles.Count -eq 0) {
                return
            }

            [pscustomobject]@{
                UserDisplayName     = $first.UserDisplayName
                UserPrincipalName   = $first.UserPrincipalName
                UserCategory        = $first.UserCategory
                TotalRoleCount      = $allRoles.Count
                DirectRoleCount     = $directRoles.Count
                InheritedRoleCount  = $inheritedRoles.Count
                RolesDirect         = ($directRoles -join '; ')
                RolesInherited      = ($inheritedRoles -join '; ')
                AllPrivilegedRoles  = ($allRoles -join '; ')
            }
        } |
        Sort-Object -Property @{Expression='TotalRoleCount';Descending=$true}, UserDisplayName
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

    $summaryFileStem = "Summary_$($TenantProfile.TenantLabel)"
    $summaryPath = Join-Path -Path $OutputFolder -ChildPath ("{0}.md" -f $summaryFileStem)
    $summaryHtmlPath = Join-Path -Path $OutputFolder -ChildPath ("{0}.html" -f $summaryFileStem)
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
    $lines += '- 1.0 Assessment Engagement Context'
    $lines += '- 2.0 Privileged Risk Register - Findings Summary by Severity'
    $lines += '- 3.0 Privilege Exposure Surface - Direct and Group-Inherited Access Paths'
    $lines += '- 4.0 Governance Control Indicators - Approval, MFA, Conditional Access and Reviews'
    $lines += '- 5.0 Most Prevalent Risk Finding Categories'
    $lines += '- 6.0 Highest Exposure Privileged Roles - Ranked by Assignment Count'
    $lines += '- 7.0 Overall Risk Posture - Composite Assurance Assessment Narrative'
    $lines += '- 8.0 Control Effectiveness - Verified Strengths and Threshold Indicators'
    $lines += '- 9.0 Priority Remediation Actions'
    $lines += '- 10.0 Key Governance Metrics - Executive Assurance Scorecard'
    $lines += '- 11.0 Direct Privileged Role Assignments - Users and Groups Register'
    $lines += '- 12.0 Group-Inherited Privilege Paths - Elevation via Group Membership'
    $lines += '- 12.1 Consolidated Privileged Access by User - Direct and Group-Inherited Roles'
    $lines += '- 13.0 Technical Risk Findings Register - Full Evidence Set'
    $lines += '- 14.0 RAG Status Indicators - Governance Traffic Light Position'
    $lines += '- 15.0 Governance Improvement Roadmap - Prioritised Recommendations'
    $lines += '- 16.0 Key Security Insights'
    $lines += '- 17.0 Privilege Concentration Analysis'
    $lines += '- 18.0 Group Risk Classification'
    $lines += '- 19.0 JIT Effectiveness Summary'
    $lines += '- 20.0 Privileged Role Elevation Control Matrix - Per-Role Activation Control Assessment'
    $lines += '- 21.0 Guest Privileged Accounts'
    $lines += '- 22.0 Naming Convention Compliance'
    $lines += '- 23.0 Licensed Privileged Accounts'
    $lines += '- 24.0 Identity Assurance Profile'
    $lines += '- 25.0 Authentication Strength Analysis'
    $lines += '- 26.0 Conditional Access Coverage by Role'
    $lines += '- 27.0 Approval Model Analysis'
    $lines += ''
    $lines += '## 1.0 Assessment Engagement Context'
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
    $lines += '## 2.0 Privileged Risk Register - Findings Summary by Severity'
    $lines += ''
    $lines += "- Total Findings: $(@($Findings).Count)"
    $lines += "- High: $highCount"
    $lines += "- Medium: $mediumCount"
    $lines += "- Low: $lowCount"
    $lines += ''
    $lines += '## 3.0 Privilege Exposure Surface - Direct and Group-Inherited Access Paths'
    $lines += ''
    $lines += "- Total User Access Paths: $(@($UserAccessPaths).Count)"
    $lines += "- Guest Access Paths: $guestPathCount"
    $lines += "- Guest Group-Inherited Paths: $guestInheritedCount"
    $lines += ''
    $lines += '## 4.0 Governance Control Indicators - Approval, MFA, Conditional Access and Reviews'
    $lines += ''
    $lines += "- High Activation Anomalies: $highActivationAnomalies"
    $lines += "- Enabled CA Policies Without MFA Control: $caPoliciesNoMfa"
    $lines += "- Active Access Reviews: $accessReviewActive"
    $lines += "- High-Risk Workload Identities: $workloadHigh"
    $lines += "- Deep Nested Group Paths (depth >= 2): $deepNestedPaths"
    $lines += "- High-Risk SoD Conflicts: $sodHigh"
    $lines += ''
    $lines += '## 5.0 Most Prevalent Risk Finding Categories'
    $lines += ''
    foreach ($row in $topFindingTypes) {
        $lines += "- $($row.Name): $($row.Count)"
    }
    $lines += ''
    $lines += '## 6.0 Highest Exposure Privileged Roles - Ranked by Assignment Count'
    $lines += ''
    foreach ($row in $topRoles) {
        $lines += "- $($row.Name): $($row.Count)"
    }

    $lines += ''
    $lines += '## 7.0 Overall Risk Posture - Composite Assurance Assessment Narrative'
    $lines += ''
    $lines += 'This rating is determined by combining role assignment exposure, activation policy controls, Conditional Access coverage, workload identity hygiene, and segregation-of-duties indicators. It represents the assessor''s objective view of how well privileged access is governed across the tenant at the time of assessment.'
    $lines += "The current PIM operating model is assessed as <span style='color:$trafficLightHex;font-weight:700'>$trafficLightColourName</span> based on role exposure, control coverage, and governance indicators."
    $lines += "This assessment combines direct and inherited privilege paths, role policy controls, CA posture, workload identity hygiene, and segregation-of-duties analysis."

    $lines += ''
    $lines += '## 8.0 Control Effectiveness - Verified Strengths and Threshold Indicators'
    $lines += ''
    $lines += 'Controls are evaluated against best-practice thresholds for Microsoft Entra PIM deployments. Verified strengths confirm areas where governance is operating within expected bounds. Exposure indicators highlight areas where current measured values fall short of the defined target and require management attention.'
    $lines += "- GA Exposure Indicator: <span style='color:$gaExposureHex;font-weight:700'>$gaExposureLabel</span> ($gaValue reachable users)"
    $lines += '- GA Thresholds: Green = 0-5, Amber = 6-9, Red = 10+'
    foreach ($item in $strengths) {
        $lines += "- $item"
    }

    $lines += ''
    $lines += '## 9.0 Priority Remediation Actions'
    $lines += ''
    foreach ($item in $improvements) {
        $lines += "- $item"
    }

    $lines += ''
    $lines += '## 10.0 Key Governance Metrics - Executive Assurance Scorecard'
    $lines += ''
    $lines += (ConvertTo-MarkdownTable -Rows $scorecardTableRows -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary'))

    $lines += ''
    $lines += '## 11.0 Direct Privileged Role Assignments - Users and Groups Register'
    $lines += ''
    $lines += (ConvertTo-MarkdownTable -Rows $explicitAssignmentRows -Columns @('PrincipalType', 'PrincipalDisplayName', 'PrincipalUserPrincipalName', 'AssignmentState', 'RoleDisplayName', 'IsPermanent'))

    $lines += ''
    $lines += '## 12.0 Group-Inherited Privilege Paths - Elevation via Group Membership'
    $lines += ''
    $lines += 'Each user in this section reaches one or more privileged roles exclusively through group membership rather than through a direct role assignment. Group-inherited access is typically less visible in standard reports, may bypass direct-assignment approval gates, and can grant unintended standing access if group membership is not regularly reviewed.'
    $lines += '- Role Count: Number of unique privileged roles reachable by the user via group membership.'
    $lines += '- Active Path Count: Number of currently active inherited role paths via group membership.'
    $lines += '- Eligible Path Count: Number of inherited role paths that are eligible (activatable) but not currently active.'
    $lines += (ConvertTo-MarkdownTable -Rows $groupElevationRows -Columns @('UserDisplayName', 'UserPrincipalName', 'UserCategory', 'RoleCount', 'RolesViaGroupMembership', 'ActivePathCount', 'EligiblePathCount', 'SourceGroups'))

    $lines += ''
    $lines += '## 12.1 Consolidated Privileged Access by User - Direct and Group-Inherited Roles'
    $lines += ''
    $lines += 'This section consolidates every user with privileged access from any path and lists the complete role set they can reach (direct assignments and group-inherited assignments combined).'
    $lines += (ConvertTo-MarkdownTable -Rows $userPrivilegedAccessRows -Columns @('UserDisplayName', 'UserPrincipalName', 'UserCategory', 'TotalRoleCount', 'DirectRoleCount', 'InheritedRoleCount', 'RolesDirect', 'RolesInherited', 'AllPrivilegedRoles'))

    $lines += ''
    $lines += '## 13.0 Technical Risk Findings Register - Full Evidence Set'
    $lines += ''
    $lines += (ConvertTo-MarkdownTable -Rows $findingsDetailRows -Columns @('RiskRating', 'FindingType', 'Subject', 'RoleName', 'Details', 'EvidenceId'))

    $lines += ''
    $lines += '## 14.0 RAG Status Indicators - Governance Traffic Light Position'
    $lines += ''
    $lines += "- Overall Score (0-100): $overallScore"
    $lines += "- Overall Status: $overallTrafficLight"
    $lines += "- Global Administrator Reachable Users: $gaValue (target <= 5)"
    $lines += "- Break Glass Accounts Detected: $bgValue (target = 2)"

    $lines += ''
    $lines += '## 15.0 Governance Improvement Roadmap - Prioritised Recommendations'
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

    $lines += ''
    $lines += '## 27.0 Approval Model Analysis'
    $lines += ''
    $approvalRowsMd = if ($null -ne $ApprovalAnalysis) { @($ApprovalAnalysis) } else { @() }
    $approvalGroupBasedMd = @($approvalRowsMd | Where-Object { $_.ApproverType -in 'Group', 'Mixed' }).Count
    $approvalGuestMd      = @($approvalRowsMd | Where-Object { $_.GuestMembers -gt 0 }).Count
    $approvalWeakMd       = @($approvalRowsMd | Where-Object { $_.ApprovalIntegrity -in 'Weak', 'Broken' }).Count
    $lines += "- Roles with approval configured: $($approvalRowsMd.Count)"
    $lines += "- Roles with group-based approvers: $approvalGroupBasedMd"
    $lines += "- Roles with guest approvers: $approvalGuestMd"
    $lines += "- Roles with Weak or Broken integrity: $approvalWeakMd"
    if ($approvalRowsMd.Count -gt 0) {
        $lines += ''
        $lines += (ConvertTo-MarkdownTable -Rows $approvalRowsMd -Columns @('RoleName', 'ApproverType', 'GroupName', 'GroupType', 'MemberCount', 'GuestMembers', 'PrivilegedMembers', 'ApprovalIntegrity', 'RiskRating'))
    }

    $lines | Out-File -FilePath $summaryPath -Encoding UTF8

    $html = @()
    $html += '<!doctype html>'
    $html += '<html>'
    $html += '<head>'
    $html += '<meta charset="utf-8" />'
    $html += '<title>Privileged Identity Management Assessment Report</title>'
    $html += '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:28px;line-height:1.45;color:#222}h1{font-size:32px;margin-bottom:8px}h2{font-size:22px;margin-top:26px;margin-bottom:10px;border-bottom:1px solid #e3e3e3;padding-bottom:4px}h3{font-size:18px;margin-top:18px;margin-bottom:8px}.cover{border:2px solid #1f4e78;padding:20px;border-radius:8px;background:#f7fbff;margin-bottom:18px}.meta{margin:6px 0}.summary-card{border:2px solid #cfd8e3;padding:16px 18px;border-radius:8px;background:#fcfdff;margin-bottom:24px}.summary-title{font-size:20px;font-weight:700;margin-bottom:8px}.summary-line{margin:4px 0}.section-context{margin:8px 0 10px 0;color:#3f4f61;font-style:italic}.section-intro{margin:8px 0 12px 0;color:#2c3e50;font-size:13px;line-height:1.6}.tl-dot{display:inline-block;width:14px;height:14px;border-radius:50%;margin-right:8px;vertical-align:middle;border:1px solid rgba(0,0,0,.2)}.tl-green{background:#2e7d32}.tl-amber{background:#ff8f00}.tl-red{background:#c62828}.status-pill{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:700;font-size:12px;color:#fff}.status-text-green{color:#2e7d32;font-weight:700}.status-text-amber{color:#ff8f00;font-weight:700}.status-text-red{color:#c62828;font-weight:700}.section-band{border-radius:8px;padding:12px 16px;margin:22px 0 12px 0;border:1px solid transparent}.section-band h2{margin:0;border-bottom:none;padding-bottom:0;color:#fff}.band-green{background:#2e7d32;border-color:#1b5e20}.band-amber{background:#ff8f00;border-color:#ef6c00}.band-red{background:#c62828;border-color:#8e0000}.section-break{page-break-before:always}ul{margin-top:0}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ddd;padding:6px 8px;vertical-align:top}th{background:#f4f6f8;text-align:left}.toc li{margin:4px 0}.pillar-header{background:#1f4e78;color:#fff;padding:10px 16px;border-radius:6px;font-size:15px;font-weight:700;margin:30px 0 14px 0;letter-spacing:.4px}.insight-item{background:#f0f7ff;border-left:4px solid #1f4e78;padding:10px 16px;margin:6px 0;border-radius:0 6px 6px 0;font-size:13px;line-height:1.55}.cs-strong{color:#2e7d32;font-weight:700}.cs-moderate{color:#e65100;font-weight:700}.cs-weak{color:#b71c1c;font-weight:700}.cs-unknown{color:#555}.badge-critical{background:#b71c1c;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}.badge-high{background:#c62828;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}.badge-medium{background:#e65100;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}.badge-low{background:#2e7d32;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}</style>'
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

    # ── Executive Summary card ────────────────────────────────────────────────────
    $html += '<div class="summary-card">'
    $html += '<div class="summary-title">Executive Summary</div>'
    $html += "<div class=""summary-line""><span class=""tl-dot $trafficLightClass""></span><strong>Overall assurance colour rating:</strong> <span class=""status-pill $trafficLightClass"">$trafficLightColourName</span>&nbsp;&nbsp;<strong>Score:</strong> $overallScore / 100</div>"
    $html += "<div class=""summary-line"" style=""margin:8px 0 12px 0;"">$([System.Net.WebUtility]::HtmlEncode($executiveSummaryStatement))</div>"
    $html += '<table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:14px">'
    $html += '<thead><tr style="background:#f4f6f8"><th style="padding:6px 10px;border:1px solid #ddd;text-align:left">Area</th><th style="padding:6px 10px;border:1px solid #ddd;text-align:left">Finding</th><th style="padding:6px 10px;border:1px solid #ddd;text-align:left">Status</th></tr></thead><tbody>'
    $findingStatusClass = if ($highCount -gt 0) { 'tl-red' } elseif ($mediumCount -gt 0) { 'tl-amber' } else { 'tl-green' }
    $findingStatusLabel = if ($highCount -gt 0) { 'Requires action' } elseif ($mediumCount -gt 0) { 'Monitor' } else { 'On track' }
    $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Risk Findings</td><td style='padding:5px 10px;border:1px solid #ddd'>$highCount High, $mediumCount Medium, $lowCount Low findings identified</td><td style='padding:5px 10px;border:1px solid #ddd'><span class='status-pill $findingStatusClass'>$findingStatusLabel</span></td></tr>"
    $matrixStatusClass = if ($matrixCritical -gt 0) { 'tl-red' } elseif ($matrixHigh -gt 0) { 'tl-amber' } else { 'tl-green' }
    $matrixStatusLabel = if ($matrixCritical -gt 0) { 'Critical gaps' } elseif ($matrixHigh -gt 0) { 'Gaps present' } else { 'Controlled' }
    $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Elevation Control Matrix</td><td style='padding:5px 10px;border:1px solid #ddd'>$($matrixRows.Count) roles: $matrixCritical Critical, $matrixHigh High, $matrixMedium Medium, $matrixLow Low</td><td style='padding:5px 10px;border:1px solid #ddd'><span class='status-pill $matrixStatusClass'>$matrixStatusLabel</span></td></tr>"
    $gaExStatusClass = if ($gaValue -le 5) { 'tl-green' } elseif ($gaValue -le 9) { 'tl-amber' } else { 'tl-red' }
    $gaExStatusLabel = if ($gaValue -le 5) { 'Within target' } elseif ($gaValue -le 9) { 'Near threshold' } else { 'Exceeds target' }
    $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Global Administrator Exposure</td><td style='padding:5px 10px;border:1px solid #ddd'>$gaValue reachable users (target: &le;5)</td><td style='padding:5px 10px;border:1px solid #ddd'><span class='status-pill $gaExStatusClass'>$gaExStatusLabel</span></td></tr>"
    $bgExStatusClass = if ($bgValue -eq 2) { 'tl-green' } else { 'tl-amber' }
    $bgExStatusLabel = if ($bgValue -eq 2) { 'On target' } else { 'Review required' }
    $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Break-Glass Accounts</td><td style='padding:5px 10px;border:1px solid #ddd'>$bgValue detected (target: 2)</td><td style='padding:5px 10px;border:1px solid #ddd'><span class='status-pill $bgExStatusClass'>$bgExStatusLabel</span></td></tr>"
    $caExStatusClass = if ($caPoliciesNoMfa -eq 0) { 'tl-green' } elseif ($caPoliciesNoMfa -le 3) { 'tl-amber' } else { 'tl-red' }
    $caExStatusLabel = if ($caPoliciesNoMfa -eq 0) { 'No gaps' } else { 'Gaps present' }
    $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Conditional Access (MFA)</td><td style='padding:5px 10px;border:1px solid #ddd'>$caPoliciesNoMfa enabled policies without MFA grant control</td><td style='padding:5px 10px;border:1px solid #ddd'><span class='status-pill $caExStatusClass'>$caExStatusLabel</span></td></tr>"
    $sodExStatusClass = if ($sodHigh -eq 0) { 'tl-green' } elseif ($sodHigh -le 5) { 'tl-amber' } else { 'tl-red' }
    $sodExStatusLabel = if ($sodHigh -eq 0) { 'No conflicts' } elseif ($sodHigh -le 5) { 'Review required' } else { 'Urgent action' }
    $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Segregation of Duties</td><td style='padding:5px 10px;border:1px solid #ddd'>$sodHigh high-risk role conflicts detected</td><td style='padding:5px 10px;border:1px solid #ddd'><span class='status-pill $sodExStatusClass'>$sodExStatusLabel</span></td></tr>"
    $html += '</tbody></table>'
    $topHighFindings = @($Findings | Where-Object { $_.RiskRating -eq 'High' } | Group-Object -Property FindingType | Sort-Object -Property Count -Descending | Select-Object -First 3)
    if ($topHighFindings.Count -gt 0) {
        $html += '<p style="margin:4px 0 2px 0"><strong>Most prevalent high-risk finding types:</strong></p>'
        $html += '<ul style="margin:0 0 8px 22px">'
        foreach ($tf in $topHighFindings) {
            $sfLabel = [System.Net.WebUtility]::HtmlEncode($tf.Name)
            $sfCount = $tf.Count
            $sfS     = if ($sfCount -ne 1) { 's' } else { '' }
            $html += "<li>$sfLabel ($sfCount instance$sfS)</li>"
        }
        $html += '</ul>'
    }
    $html += '</div>'

    $html += '<h2>Section Index</h2>'
    $html += '<ul class="toc">'
    $html += '<li>1.0 Assessment Engagement Context</li>'
    $html += '<li>2.0 Privileged Risk Register - Findings Summary by Severity</li>'
    $html += '<li>3.0 Privilege Exposure Surface - Direct and Group-Inherited Access Paths</li>'
    $html += '<li>4.0 Governance Control Indicators - Approval, MFA, Conditional Access and Reviews</li>'
    $html += '<li>5.0 Most Prevalent Risk Finding Categories</li>'
    $html += '<li>6.0 Highest Exposure Privileged Roles - Ranked by Assignment Count</li>'
    $html += '<li>7.0 Overall Risk Posture - Composite Assurance Assessment Narrative</li>'
    $html += '<li>8.0 Control Effectiveness - Verified Strengths and Threshold Indicators</li>'
    $html += '<li>9.0 Priority Remediation Actions</li>'
    $html += '<li>10.0 Key Governance Metrics - Executive Assurance Scorecard</li>'
    $html += '<li>11.0 Direct Privileged Role Assignments - Users and Groups Register</li>'
    $html += '<li>12.0 Group-Inherited Privilege Paths - Elevation via Group Membership</li>'
    $html += '<li>12.1 Consolidated Privileged Access by User - Direct and Group-Inherited Roles</li>'
    $html += '<li>13.0 Technical Risk Findings Register - Full Evidence Set</li>'
    $html += '<li>14.0 RAG Status Indicators - Governance Traffic Light Position</li>'
    $html += '<li>15.0 Governance Improvement Roadmap - Prioritised Recommendations</li>'
    $html += '<li>16.0 Key Security Insights</li>'
    $html += '<li>17.0 Privilege Concentration Analysis</li>'
    $html += '<li>18.0 Group Risk Classification</li>'
    $html += '<li>19.0 JIT Effectiveness Summary</li>'
    $html += '<li>20.0 Privileged Role Elevation Control Matrix &#8212; Per-Role Activation Control Assessment</li>'
    $html += '<li>21.0 Guest Privileged Accounts</li>'
    $html += '<li>22.0 Naming Convention Compliance</li>'
    $html += '<li>23.0 Licensed Privileged Accounts</li>'
    $html += '<li>24.0 Identity Assurance Profile</li>'
    $html += '<li>25.0 Authentication Strength Analysis</li>'
    $html += '<li>26.0 Conditional Access Coverage by Role</li>'
    $html += '<li>27.0 Approval Model Analysis</li>'
    $html += '<li>27.1 Per-Role Approval Breakdown</li>'
    $html += '<li>27.2 Approver Group &#8212; Role Mapping</li>'
    $html += '<li>27.3 Approver Group Member Directory</li>'
    $html += '</ul>'

    $html += '<h2>1.0 Assessment Engagement Context</h2>'
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
    $html += '<h2>2.0 Privileged Risk Register &#8212; Findings Summary by Severity</h2>'
    $html += '<ul>'
    $html += "<li>Total Findings: $(@($Findings).Count)</li>"
    $html += "<li>High: $highCount</li>"
    $html += "<li>Medium: $mediumCount</li>"
    $html += "<li>Low: $lowCount</li>"
    $html += '</ul>'
    $html += '<h2>3.0 Privilege Exposure Surface &#8212; Direct and Group-Inherited Access Paths</h2>'
    $html += '<ul>'
    $html += "<li>Total User Access Paths: $(@($UserAccessPaths).Count)</li>"
    $html += "<li>Guest Access Paths: $guestPathCount</li>"
    $html += "<li>Guest Group-Inherited Paths: $guestInheritedCount</li>"
    $html += '</ul>'
    $html += '<h2>4.0 Governance Control Indicators &#8212; Approval, MFA, Conditional Access and Reviews</h2>'
    $html += '<ul>'
    $html += "<li>High Activation Anomalies: $highActivationAnomalies</li>"
    $html += "<li>Enabled CA Policies Without MFA Control: $caPoliciesNoMfa</li>"
    $html += "<li>Active Access Reviews: $accessReviewActive</li>"
    $html += "<li>High-Risk Workload Identities: $workloadHigh</li>"
    $html += "<li>Deep Nested Group Paths (depth >= 2): $deepNestedPaths</li>"
    $html += "<li>High-Risk SoD Conflicts: $sodHigh</li>"
    $html += '</ul>'
    $html += '<h2>5.0 Most Prevalent Risk Finding Categories</h2>'
    $html += '<ul>'
    foreach ($row in $topFindingTypes) {
        $html += "<li>$($row.Name): $($row.Count)</li>"
    }
    $html += '</ul>'
    $html += '<h2>6.0 Highest Exposure Privileged Roles &#8212; Ranked by Assignment Count</h2>'
    $html += '<ul>'
    foreach ($row in $topRoles) {
        $html += "<li>$($row.Name): $($row.Count)</li>"
    }
    $html += '</ul>'

    $html += '<h2>7.0 Overall Risk Posture &#8212; Composite Assurance Assessment Narrative</h2>'
    $html += '<p class="section-intro">This rating is determined by combining role assignment exposure, activation policy controls, Conditional Access coverage, workload identity hygiene, and segregation-of-duties indicators. It represents the assessor&rsquo;s objective view of how well privileged access is governed across the tenant at the time of this assessment.</p>'
    $html += "<p>The current PIM operating model is assessed as <span class=""$trafficTextClass""><strong>$trafficLightColourName</strong></span> based on role exposure, control coverage, and governance indicators.</p>"
    $html += '<p>This assessment combines direct and inherited privilege paths, role policy controls, Conditional Access posture, workload identity hygiene, and segregation-of-duties analysis.</p>'

    $html += "<div class=""section-band $gaBandClass""><h2>8.0 Control Effectiveness &#8212; Verified Strengths and Threshold Indicators</h2></div>"
    $html += '<p class="section-intro">Controls are evaluated against best-practice thresholds for Microsoft Entra PIM deployments. Verified strengths confirm areas where governance is operating within expected bounds. Exposure indicators highlight areas where current measured values fall short of the defined target and require management attention.</p>'
    $html += "<p><strong>GA Exposure Indicator:</strong> <span class=""status-pill $gaExposureClass"">$gaExposureLabel</span> ($gaValue reachable users)</p>"
    $html += '<p><strong>GA Thresholds:</strong> Green = 0-5, Amber = 6-9, Red = 10+</p>'
    $html += '<ul>'
    foreach ($item in $strengths) {
        $safeItem = [System.Net.WebUtility]::HtmlEncode($item)
        $html += "<li>$safeItem</li>"
    }
    $html += '</ul>'

    $html += '<h2>9.0 Priority Remediation Actions</h2>'
    $html += '<ul>'
    foreach ($item in $improvements) {
        $safeItem = [System.Net.WebUtility]::HtmlEncode($item)
        $html += "<li>$safeItem</li>"
    }
    $html += '</ul>'

    $html += '<h2>10.0 Key Governance Metrics &#8212; Executive Assurance Scorecard</h2>'
    $html += (ConvertTo-HtmlTable -Rows $scorecardTableRows -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary'))

    $html += '<h2 class="section-break">11.0 Direct Privileged Role Assignments &#8212; Users and Groups Register</h2>'
    $html += (ConvertTo-HtmlTable -Rows $explicitAssignmentRows -Columns @('PrincipalType', 'PrincipalDisplayName', 'PrincipalUserPrincipalName', 'AssignmentState', 'RoleDisplayName', 'IsPermanent'))

    $html += '<h2>12.0 Group-Inherited Privilege Paths &#8212; Elevation via Group Membership</h2>'
    $html += '<p class="section-intro">Each user in this section reaches one or more privileged roles exclusively through group membership rather than through a direct role assignment. Group-inherited access is typically less visible in standard reporting, may bypass direct-assignment approval gates, and can grant unintended standing access if group membership is not regularly reviewed. The role and path counts below indicate the breadth of each user&rsquo;s inherited privilege footprint.</p>'
    $html += '<ul>'
    $html += '<li><strong>Role Count:</strong> Number of unique privileged roles reachable by the user via group membership.</li>'
    $html += '<li><strong>Active Path Count:</strong> Number of currently active inherited role paths via group membership.</li>'
    $html += '<li><strong>Eligible Path Count:</strong> Number of inherited role paths that are eligible (activatable) but not currently active.</li>'
    $html += '</ul>'
    $html += (ConvertTo-HtmlTable -Rows $groupElevationRows -Columns @('UserDisplayName', 'UserPrincipalName', 'UserCategory', 'RoleCount', 'RolesViaGroupMembership', 'ActivePathCount', 'EligiblePathCount', 'SourceGroups'))

    $html += '<h2>12.1 Consolidated Privileged Access by User &#8212; Direct and Group-Inherited Roles</h2>'
    $html += '<p class="section-intro">This section consolidates every user with privileged access from any path and lists the complete role set they can reach (direct assignments and group-inherited assignments combined).</p>'
    $html += (ConvertTo-HtmlTable -Rows $userPrivilegedAccessRows -Columns @('UserDisplayName', 'UserPrincipalName', 'UserCategory', 'TotalRoleCount', 'DirectRoleCount', 'InheritedRoleCount', 'RolesDirect', 'RolesInherited', 'AllPrivilegedRoles'))

    $html += '<h2 class="section-break">13.0 Technical Risk Findings Register &#8212; Full Evidence Set</h2>'
    $html += (ConvertTo-HtmlTable -Rows $findingsDetailRows -Columns @('RiskRating', 'FindingType', 'Subject', 'RoleName', 'Details', 'EvidenceId'))

    $html += '<h2>14.0 RAG Status Indicators &#8212; Governance Traffic Light Position</h2>'
    $html += '<ul>'
    $html += "<li>Overall Score (0-100): $overallScore</li>"
    $html += "<li>Overall Colour Rating: <span class=""tl-dot $trafficLightClass""></span><span class=""status-pill $trafficLightClass"">$trafficLightColourName</span></li>"
    $html += "<li>Summary Statement: $([System.Net.WebUtility]::HtmlEncode($executiveSummaryStatement))</li>"
    $html += "<li>Global Administrator Reachable Users: $gaValue (target <= 5)</li>"
    $html += "<li>Break Glass Accounts Detected: $bgValue (target = 2)</li>"
    $html += '</ul>'

    $html += '<h2>15.0 Governance Improvement Roadmap &#8212; Prioritised Recommendations</h2>'
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

    # ── Section 16.0 — Key Security Insights ─────────────────────────────────────
    $html += '<h2>16.0 Key Security Insights</h2>'
    $html += '<p class="section-intro">The following insights are automatically derived from patterns in the collected data. Each insight identifies a systemic governance condition that warrants management attention beyond a single isolated finding.</p>'
    $insightList = if ($null -ne $KeyInsights -and @($KeyInsights).Count -gt 0) { @($KeyInsights) } else { @() }
    if ($insightList.Count -gt 0) {
        foreach ($insight in $insightList) {
            $safeInsight = [System.Net.WebUtility]::HtmlEncode([string]$insight)
            $html += "<div class='insight-item'>$safeInsight</div>"
        }
    }
    else {
        $html += '<p>No key insights were generated for this run. Ensure role elevation matrix data is available.</p>'
    }

    # ── Section 17.0 — Privilege Concentration Analysis ──────────────────────────
    $html += '<h2>17.0 Privilege Concentration Analysis</h2>'
    $html += '<p class="section-intro">This section profiles the privilege breadth of each user across both direct and group-inherited access paths. Users exceeding 10 roles are flagged as high-privilege; users meeting Tier-0 role combination thresholds are flagged as approaching super-administrator equivalence. A super-admin equivalent user represents a critical single point of compromise.</p>'
    $concRows = if ($null -ne $PrivilegeConcentration -and @($PrivilegeConcentration).Count -gt 0) { @($PrivilegeConcentration) } else { @() }
    if ($concRows.Count -gt 0) {
        $superCount = @($concRows | Where-Object { $_.IsSuperAdminEquivalent -eq $true }).Count
        $heavyCount = @($concRows | Where-Object { $_.TotalDistinctRoles -gt 10 }).Count
        $maxRoleVal = ($concRows | Measure-Object -Property TotalDistinctRoles -Maximum).Maximum
        $html += "<p><strong>Total privileged users analysed:</strong> $($concRows.Count) &nbsp; <strong>Super-admin equivalent:</strong> $superCount &nbsp; <strong>Heavy-privilege (&gt;10 roles):</strong> $heavyCount &nbsp; <strong>Max roles (single user):</strong> $maxRoleVal</p>"
        $html += '<table>'
        $html += '<thead><tr><th>User</th><th>UPN</th><th>Category</th><th>Total Roles</th><th>Direct</th><th>Inherited</th><th>High-Impact</th><th>Tier-0</th><th>Global Admin</th><th>Super-Admin Equiv</th><th>Concentration Risk</th></tr></thead>'
        $html += '<tbody>'
        foreach ($cr in @($concRows | Select-Object -First 50)) {
            if ($cr.ConcentrationRisk -eq 'Critical') { $crBg = '#ffcdd2' } elseif ($cr.ConcentrationRisk -eq 'High') { $crBg = '#ffebee' } elseif ($cr.ConcentrationRisk -eq 'Medium') { $crBg = '#fff8e1' } else { $crBg = '#f1f8e9' }
            $gaLabel  = if ($cr.IsGlobalAdmin)          { 'Yes' } else { 'No' }
            $saLabel  = if ($cr.IsSuperAdminEquivalent) { '<strong>Yes</strong>' } else { 'No' }
            if ($cr.ConcentrationRisk -eq 'Critical') { $crClass = 'badge-critical' } elseif ($cr.ConcentrationRisk -eq 'High') { $crClass = 'badge-high' } elseif ($cr.ConcentrationRisk -eq 'Medium') { $crClass = 'badge-medium' } else { $crClass = 'badge-low' }
            $html += "<tr style='background:$crBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($cr.UserDisplayName))</strong></td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$cr.UserPrincipalName))</td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$cr.UserCategory))</td>"
            $html += "<td><strong>$($cr.TotalDistinctRoles)</strong></td>"
            $html += "<td>$($cr.DirectRoleCount)</td><td>$($cr.InheritedRoleCount)</td><td>$($cr.HighImpactRoleCount)</td><td>$($cr.Tier0RoleCount)</td>"
            $html += "<td>$gaLabel</td><td>$saLabel</td>"
            $html += "<td><span class='$crClass'>$([System.Net.WebUtility]::HtmlEncode($cr.ConcentrationRisk))</span></td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
        if ($concRows.Count -gt 50) { $html += "<p style='font-size:12px;color:#555'>Showing top 50 of $($concRows.Count) users. Full data available in the Excel workbook (sheet 23_Privilege_Concentration).</p>" }
    }
    else {
        $html += '<p>No privilege concentration data is available for this run.</p>'
    }

    # ── Section 18.0 — Group Risk Classification ─────────────────────────────────
    $html += '<h2>18.0 Group Risk Classification</h2>'
    $html += '<p class="section-intro">Each role-assignable group is assessed for the risk it introduces into the privilege surface. Groups rated Critical combine high-impact roles with embedded Segregation of Duties conflicts: any member simultaneously inherits mutually exclusive privileges. Groups rated High hold high-impact roles or include guest members. Risk ratings are derived automatically from the group role set and membership composition.</p>'
    $grpRows = if ($null -ne $GroupRiskProfiles -and @($GroupRiskProfiles).Count -gt 0) { @($GroupRiskProfiles) } else { @() }
    if ($grpRows.Count -gt 0) {
        $grpCritCount = @($grpRows | Where-Object { $_.GroupRiskRating -eq 'Critical' }).Count
        $grpHighCount = @($grpRows | Where-Object { $_.GroupRiskRating -eq 'High'     }).Count
        $grpSodCount  = @($grpRows | Where-Object { $_.HasSoDConflict  -eq $true      }).Count
        $html += "<p><strong>Total groups:</strong> $($grpRows.Count) &nbsp; <strong>Critical:</strong> $grpCritCount &nbsp; <strong>High:</strong> $grpHighCount &nbsp; <strong>Embedded SoD conflicts:</strong> $grpSodCount</p>"
        $html += '<table>'
        $html += '<thead><tr><th>Group</th><th>Total Roles</th><th>High-Impact</th><th>SoD Conflict</th><th>User Members</th><th>Guests</th><th>Nested Groups</th><th>Risk Rating</th><th>Risk Rationale</th></tr></thead>'
        $html += '<tbody>'
        foreach ($gr in $grpRows) {
            if ($gr.GroupRiskRating -eq 'Critical') { $grBg = '#ffcdd2' } elseif ($gr.GroupRiskRating -eq 'High') { $grBg = '#ffebee' } elseif ($gr.GroupRiskRating -eq 'Medium') { $grBg = '#fff8e1' } else { $grBg = '#f1f8e9' }
            if ($gr.GroupRiskRating -eq 'Critical') { $grClass = 'badge-critical' } elseif ($gr.GroupRiskRating -eq 'High') { $grClass = 'badge-high' } elseif ($gr.GroupRiskRating -eq 'Medium') { $grClass = 'badge-medium' } else { $grClass = 'badge-low' }
            $sodLabel = if ($gr.HasSoDConflict -eq $true) { '<strong style="color:#b71c1c">Yes</strong>' } else { 'No' }
            $html += "<tr style='background:$grBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($gr.GroupDisplayName))</strong></td>"
            $html += "<td>$($gr.DistinctRoleCount)</td><td>$($gr.HighImpactRoleCount)</td><td>$sodLabel</td>"
            $html += "<td>$($gr.DirectUserMemberCount)</td><td>$($gr.GuestMemberCount)</td><td>$($gr.NestedGroupMemberCount)</td>"
            $html += "<td><span class='$grClass'>$([System.Net.WebUtility]::HtmlEncode($gr.GroupRiskRating))</span></td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$gr.GroupRiskWhy))</td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p>No group risk profile data is available for this run.</p>'
    }

    # ── Section 19.0 — JIT Effectiveness Summary ─────────────────────────────────
    $html += '<h2>19.0 JIT Effectiveness Summary</h2>'
    $html += '<p class="section-intro">The JIT Effectiveness Score (0-100) measures how consistently Just-In-Time access controls are applied across all analysed privileged roles. Score weights: MFA 35%, Approval 30%, Duration &le;8h 20%, Permanent eligibility penalty 15%. A score below 60 indicates the JIT model requires structural improvement.</p>'
    if ($null -ne $JitEffectiveness) {
        $jitScore  = $JitEffectiveness.JITEffectivenessScore
        $jitRating = $JitEffectiveness.JITEffectivenessRating
        if ($jitRating -eq 'Strong') { $jitClass = 'tl-green' } elseif ($jitRating -eq 'Moderate') { $jitClass = 'tl-amber' } else { $jitClass = 'tl-red' }
        $html += "<p><strong>JIT Effectiveness Score: $jitScore / 100</strong> &nbsp; <span class='status-pill $jitClass'>$jitRating</span></p>"
        $html += '<table style="width:62%;margin-bottom:12px">'
        $html += '<thead><tr style="background:#f4f6f8"><th style="padding:5px 10px;border:1px solid #ddd">Control</th><th style="padding:5px 10px;border:1px solid #ddd">Roles</th><th style="padding:5px 10px;border:1px solid #ddd">Coverage (%)</th></tr></thead>'
        $html += '<tbody>'
        $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>MFA Required</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.RolesWithMfa) of $($JitEffectiveness.TotalRolesAnalysed)</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.PctMfaRequired)%</td></tr>"
        $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Approval Required (with approvers)</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.RolesWithApproval) of $($JitEffectiveness.TotalRolesAnalysed)</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.PctApprovalRequired)%</td></tr>"
        $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Duration &le;8h</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.RolesWithShortDuration) of $($JitEffectiveness.TotalRolesAnalysed)</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.PctShortDuration)%</td></tr>"
        $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Permanent Eligible Assignments</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.RolesWithPermanentEligible) of $($JitEffectiveness.TotalRolesAnalysed)</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.PctPermanentEligible)%</td></tr>"
        $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Strong Control Posture</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.RolesWithStrongControl) of $($JitEffectiveness.TotalRolesAnalysed)</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.PctStrongControl)%</td></tr>"
        $html += "<tr><td style='padding:5px 10px;border:1px solid #ddd'>Weak Control Posture</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.RolesWithWeakControl) of $($JitEffectiveness.TotalRolesAnalysed)</td><td style='padding:5px 10px;border:1px solid #ddd'>$($JitEffectiveness.PctWeakControl)%</td></tr>"
        $html += '</tbody></table>'
        $html += "<p class='section-intro'>$([System.Net.WebUtility]::HtmlEncode([string]$JitEffectiveness.Insight))</p>"
    }
    else {
        $html += '<p>JIT effectiveness data is not available for this run. Ensure the Role Elevation Matrix was collected successfully.</p>'
    }

    # ── Section 20.0 — Privileged Role Elevation Control Matrix ──────────────────
    $html += '<h2>20.0 Privileged Role Elevation Control Matrix &#8212; Per-Role Activation Control Assessment</h2>'
    $html += '<p class="section-intro">This appendix maps every assigned privileged role to its PIM activation policy settings and derives an objective risk posture for each one. The <strong>Elevation Friction Score</strong> (0&#8211;100) measures how many JIT controls a user must pass before activating the role. The <strong>Risk Rating</strong> combines role criticality tier with the specific control gaps identified. Roles rated Critical or High should be prioritised for immediate policy remediation.</p>'
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
        $html += '<thead><tr><th>Role Name</th><th>Criticality</th><th>High Impact</th><th>Assignment Type</th><th>MFA</th><th>Approval</th><th>Approver Type</th><th>Approvers</th><th>Approver Details</th><th>Max Duration (h)</th><th>Justification</th><th>Ticketing</th><th>Friction Score</th><th>Maturity</th><th>Control Strength</th><th>Approval Model</th><th>Risk Rating</th><th>Control Gaps</th><th>Access Reviews</th></tr></thead>'
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
            $ticketLabel = if ($null -eq $m.TicketingRequired) { '?' } elseif ($m.TicketingRequired) { 'Yes' } else { 'No' }
            $durLabel   = if ($null -eq $m.MaxActivationDurationHours) { '?' } else { "$([Math]::Round($m.MaxActivationDurationHours,1))" }
            $revLabel   = if ($m.AccessReviewsEnabled)  { 'Yes' } else { 'No' }
            $approverEnc = if ($m.ApproverDisplayNames) { [System.Net.WebUtility]::HtmlEncode([string]$m.ApproverDisplayNames) } else { '&mdash;' }
            $approverDetailEnc = if ($m.ApproverDetails) { [System.Net.WebUtility]::HtmlEncode([string]$m.ApproverDetails) } else { '&mdash;' }
            $gapsEnc    = if ($m.ControlGaps) { [System.Net.WebUtility]::HtmlEncode([string]$m.ControlGaps) } else { 'None' }
            $html += "<tr style=""background:$rowBg"">"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($m.RoleName))</strong></td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$m.RoleCriticalityTier))</td>"
            $html += "<td>$hiLabel</td><td>$([System.Net.WebUtility]::HtmlEncode($m.AssignmentTypes))</td>"
            $html += "<td>$mfaLabel</td><td>$apprLabel</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$m.ApproverType))</td><td style=""font-size:12px"">$approverEnc</td><td style=""font-size:12px"">$approverDetailEnc</td>"
            $html += "<td>$durLabel</td><td>$justLabel</td><td>$ticketLabel</td>"
            $html += "<td><strong>$($m.ElevationFrictionScore)</strong></td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode($m.ControlMaturityLabel))</td>"
            $html += "<td style=""$ratingStyle"">$([System.Net.WebUtility]::HtmlEncode($m.RiskRating))</td>"
            $html += "<td style=""font-size:12px"">$gapsEnc</td><td>$revLabel</td>"
            $csStrLabel = if ($m.ControlStrength)       { [System.Net.WebUtility]::HtmlEncode([string]$m.ControlStrength)       } else { '?' }
            $amStrLabel = if ($m.ApprovalModelStrength) { [System.Net.WebUtility]::HtmlEncode([string]$m.ApprovalModelStrength) } else { '?' }
            if ($m.ControlStrength -eq 'Strong') { $csStrClass = 'cs-strong' } elseif ($m.ControlStrength -eq 'Moderate') { $csStrClass = 'cs-moderate' } else { $csStrClass = 'cs-weak' }
            if ($m.ApprovalModelStrength -eq 'Strong') { $amStrClass = 'cs-strong' } elseif ($m.ApprovalModelStrength -eq 'Moderate') { $amStrClass = 'cs-moderate' } elseif ($m.ApprovalModelStrength -eq 'Weak') { $amStrClass = 'cs-weak' } else { $amStrClass = 'cs-unknown' }
            $html += "<td><span class='$csStrClass'>$csStrLabel</span></td><td><span class='$amStrClass'>$amStrLabel</span></td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p>No role elevation policy data is available for this run.</p>'
    }

    # ── Section 21.0 — Guest Privileged Accounts ──────────────────────────────────
    $html += '<h2>21.0 Guest Privileged Accounts</h2>'
    $html += '<p class="section-intro">Guest (external) identities with privileged role assignments represent a significantly elevated risk. External accounts are not managed through the organisation''s identity lifecycle controls, may not be subject to the same MFA or naming policies, and their access is frequently invisible in standard privilege reviews. Each guest access path should have a documented business justification, a defined expiry date, and be covered by a periodic access review.</p>'
    $guestRows = if ($null -ne $GuestPrivilegedAccounts -and @($GuestPrivilegedAccounts).Count -gt 0) { @($GuestPrivilegedAccounts) } else { @() }
    if ($guestRows.Count -gt 0) {
        $guestCritical = @($guestRows | Where-Object { $_.GuestRiskRating -eq 'Critical' }).Count
        $guestHigh     = @($guestRows | Where-Object { $_.GuestRiskRating -eq 'High'     }).Count
        $html += "<p><strong>Total privileged guest accounts:</strong> $($guestRows.Count) &nbsp; <strong>Critical:</strong> $guestCritical &nbsp; <strong>High:</strong> $guestHigh</p>"
        $html += '<table>'
        $html += '<thead><tr><th>User</th><th>UPN</th><th>Total Roles</th><th>High-Impact</th><th>Direct Assign</th><th>Group Assign</th><th>Permanent Path</th><th>Source Groups</th><th>Risk Rating</th><th>Risk Rationale</th></tr></thead>'
        $html += '<tbody>'
        foreach ($gr in $guestRows) {
            if ($gr.GuestRiskRating -eq 'Critical') { $grBg = '#ffcdd2'; $grCls = 'badge-critical' }
            elseif ($gr.GuestRiskRating -eq 'High') { $grBg = '#ffebee'; $grCls = 'badge-high' }
            else                                    { $grBg = '#fff8e1'; $grCls = 'badge-medium' }
            $directLabel = if ($gr.HasDirectAssignment)  { '<strong style="color:#b71c1c">Yes</strong>' } else { 'No' }
            $permLabel   = if ($gr.HasPermanentPath)     { '<strong style="color:#b71c1c">Yes</strong>' } else { 'No' }
            $html += "<tr style='background:$grBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($gr.UserDisplayName))</strong></td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$gr.UserPrincipalName))</td>"
            $html += "<td>$($gr.TotalRoleCount)</td><td>$($gr.HighImpactRoleCount)</td>"
            $html += "<td>$directLabel</td><td>$(if ($gr.HasGroupAssignment) { 'Yes' } else { 'No' })</td><td>$permLabel</td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$gr.SourceGroups))</td>"
            $html += "<td><span class='$grCls'>$([System.Net.WebUtility]::HtmlEncode($gr.GuestRiskRating))</span></td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$gr.GuestRiskWhy))</td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p style="color:#2e7d32"><strong>No guest accounts with privileged roles were detected.</strong> This is a positive control indicator.</p>'
    }

    # ── Section 22.0 — Naming Convention Compliance ────────────────────────────────
    $html += '<h2>22.0 Naming Convention Compliance</h2>'
    $html += "<p class='section-intro'>Dedicated privileged admin accounts should follow a defined naming convention (prefix: <strong>CLAD_</strong>) to distinguish them from everyday user accounts. Using a personal or shared account for privileged operations increases the risk of credential reuse, makes it harder to enforce account-specific controls, and reduces visibility in privilege reviews. Accounts failing this check may represent everyday accounts used for administrative access.</p>"
    $namingRows = if ($null -ne $NamingCompliance -and @($NamingCompliance).Count -gt 0) { @($NamingCompliance) } else { @() }
    if ($namingRows.Count -gt 0) {
        $nonCompliantCount = @($namingRows | Where-Object { $_.IsNamingCompliant -eq $false }).Count
        $compliantCount    = @($namingRows | Where-Object { $_.IsNamingCompliant -eq $true  }).Count
        $html += "<p><strong>Total member accounts assessed:</strong> $($namingRows.Count) &nbsp; <strong>Compliant:</strong> $compliantCount &nbsp; <span style='color:#c62828'><strong>Non-Compliant:</strong> $nonCompliantCount</span></p>"
        $nonCompliant = @($namingRows | Where-Object { $_.IsNamingCompliant -eq $false })
        if ($nonCompliant.Count -gt 0) {
            $html += '<table>'
            $html += '<thead><tr><th>User</th><th>UPN</th><th>Category</th><th>Total Roles</th><th>Compliance Status</th><th>Risk Rating</th><th>Reason</th></tr></thead>'
            $html += '<tbody>'
            foreach ($nr in $nonCompliant) {
                $html += "<tr style='background:#ffebee'>"
                $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($nr.UserDisplayName))</strong></td>"
                $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$nr.UserPrincipalName))</td>"
                $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$nr.UserCategory))</td>"
                $html += "<td>$($nr.TotalDistinctRoles)</td>"
                $html += "<td><span class='badge-high'>Non-Compliant</span></td>"
                $html += "<td><span class='badge-high'>$([System.Net.WebUtility]::HtmlEncode($nr.ComplianceRiskRating))</span></td>"
                $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$nr.ComplianceReason))</td>"
                $html += '</tr>'
            }
            $html += '</tbody></table>'
        }
        else {
            $html += '<p style="color:#2e7d32"><strong>All privileged member accounts meet the naming convention requirement.</strong></p>'
        }
    }
    else {
        $html += '<p>Naming compliance data is not available for this run.</p>'
    }

    # ── Section 23.0 — Licensed Privileged Accounts ────────────────────────────────
    $html += '<h2>23.0 Licensed Privileged Accounts</h2>'
    $html += '<p class="section-intro">Privileged accounts that also hold product licenses (e.g. Microsoft 365 E5, Exchange Online) combine administrative authority with access to organisational data. A credential compromise of such an account simultaneously exposes both privileged administrative control and licensed data (mail, files, Teams, etc.). Best practice is to use dedicated, unlicensed admin accounts for privileged operations — with all licensing assigned to the user''s everyday account.</p>'
    $licensedRows = if ($null -ne $LicensedPrivilegedAccounts -and @($LicensedPrivilegedAccounts).Count -gt 0) { @($LicensedPrivilegedAccounts) } else { @() }
    if ($licensedRows.Count -gt 0) {
        $licensedHighCount = @($licensedRows | Where-Object { $_.LicensedAdminRiskRating -eq 'High' }).Count
        $html += "<p><strong>Licensed privileged accounts detected:</strong> $($licensedRows.Count) &nbsp; <strong>High risk:</strong> $licensedHighCount</p>"
        $html += '<table>'
        $html += '<thead><tr><th>User</th><th>UPN</th><th>Category</th><th>Total Roles</th><th>High-Impact</th><th>Licenses</th><th>License SKUs</th><th>Risk Rating</th><th>Rationale</th></tr></thead>'
        $html += '<tbody>'
        foreach ($lr in $licensedRows) {
            if ($lr.LicensedAdminRiskRating -eq 'High') { $lrBg = '#ffebee'; $lrCls = 'badge-high' }
            elseif ($lr.LicensedAdminRiskRating -eq 'Medium') { $lrBg = '#fff8e1'; $lrCls = 'badge-medium' }
            else { $lrBg = '#f1f8e9'; $lrCls = 'badge-low' }
            $html += "<tr style='background:$lrBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($lr.UserDisplayName))</strong></td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$lr.UserPrincipalName))</td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$lr.UserCategory))</td>"
            $html += "<td>$($lr.TotalDistinctRoles)</td><td>$($lr.HighImpactRoleCount)</td>"
            $html += "<td>$($lr.LicenseCount)</td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$lr.FriendlyLicenseNames))</td>"
            $html += "<td><span class='$lrCls'>$([System.Net.WebUtility]::HtmlEncode($lr.LicensedAdminRiskRating))</span></td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$lr.LicensedAdminRiskWhy))</td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p style="color:#2e7d32"><strong>No privileged accounts with active product licenses were detected.</strong> This indicates dedicated admin account hygiene is maintained.</p>'
    }

    # ── Section 24.0 — Identity Assurance Profile ─────────────────────────────────
    $html += '<h2>24.0 Identity Assurance Profile</h2>'
    $html += '<p class="section-intro">The Identity Assurance Profile provides a consolidated risk view for each privileged user, combining privilege breadth, account type (guest/member), naming compliance, license status, and authentication strength. The IdentityRiskRating is derived from a composite score across all risk dimensions. Users rated Critical or High should be prioritised for immediate remediation of the specific risk factors identified.</p>'
    $iapRows = if ($null -ne $IdentityAssuranceProfiles -and @($IdentityAssuranceProfiles).Count -gt 0) { @($IdentityAssuranceProfiles) } else { @() }
    if ($iapRows.Count -gt 0) {
        $iapCritical = @($iapRows | Where-Object { $_.IdentityRiskRating -eq 'Critical' }).Count
        $iapHigh     = @($iapRows | Where-Object { $_.IdentityRiskRating -eq 'High'     }).Count
        $iapPhish    = @($iapRows | Where-Object { $_.HasPhishingResistantMfa -eq $true  }).Count
        $html += "<p><strong>Profiles:</strong> $($iapRows.Count) &nbsp; <strong>Critical:</strong> $iapCritical &nbsp; <strong>High:</strong> $iapHigh &nbsp; <strong>Phishing-Resistant MFA:</strong> $iapPhish</p>"
        $html += '<table>'
        $html += '<thead><tr><th>User</th><th>UPN</th><th>Guest</th><th>Licensed</th><th>Naming OK</th><th>Auth Strength</th><th>Total Roles</th><th>High-Impact</th><th>Conc. Risk</th><th>Super-Admin</th><th>Score</th><th>Risk Rating</th></tr></thead>'
        $html += '<tbody>'
        foreach ($ip in @($iapRows | Select-Object -First 100)) {
            if ($ip.IdentityRiskRating -eq 'Critical') { $ipBg = '#ffcdd2'; $ipCls = 'badge-critical' }
            elseif ($ip.IdentityRiskRating -eq 'High')  { $ipBg = '#ffebee'; $ipCls = 'badge-high' }
            elseif ($ip.IdentityRiskRating -eq 'Medium') { $ipBg = '#fff8e1'; $ipCls = 'badge-medium' }
            else { $ipBg = '#f1f8e9'; $ipCls = 'badge-low' }
            $guestLabel = if ($ip.IsGuest) { '<strong style="color:#e65100">Guest</strong>' } else { 'No' }
            $licLabel   = if ($ip.IsLicensed) { '<strong>Yes</strong>' } else { 'No' }
            $namingLabel = if ($ip.IsNamingCompliant) { '<span style="color:#2e7d32">OK</span>' } else { '<strong style="color:#c62828">FAIL</strong>' }
            $saLabel    = if ($ip.IsSuperAdminEquivalent) { '<strong style="color:#b71c1c">Yes</strong>' } else { 'No' }
            if ($ip.AuthStrength -eq 'PhishingResistant') { $authCls = 'cs-strong' }
            elseif ($ip.AuthStrength -eq 'StandardMFA')   { $authCls = 'cs-moderate' }
            elseif ($ip.AuthStrength -eq 'WeakOrNone')    { $authCls = 'cs-weak' }
            else                                          { $authCls = 'cs-unknown' }
            $html += "<tr style='background:$ipBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($ip.UserDisplayName))</strong></td>"
            $html += "<td style='font-size:11px'>$([System.Net.WebUtility]::HtmlEncode([string]$ip.UserPrincipalName))</td>"
            $html += "<td>$guestLabel</td><td>$licLabel</td><td>$namingLabel</td>"
            $html += "<td><span class='$authCls'>$([System.Net.WebUtility]::HtmlEncode([string]$ip.AuthStrength))</span></td>"
            $html += "<td>$($ip.TotalRoleCount)</td><td>$($ip.HighImpactRoleCount)</td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$ip.ConcentrationRisk))</td>"
            $html += "<td>$saLabel</td><td>$($ip.IdentityRiskScore)</td>"
            $html += "<td><span class='$ipCls'>$([System.Net.WebUtility]::HtmlEncode($ip.IdentityRiskRating))</span></td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
        if ($iapRows.Count -gt 100) { $html += "<p style='font-size:12px;color:#555'>Showing top 100 of $($iapRows.Count) profiles. Full data in workbook sheet 28_Identity_Assurance.</p>" }
    }
    else {
        $html += '<p>Identity assurance profile data is not available for this run.</p>'
    }

    # ── Section 25.0 — Authentication Strength Analysis ───────────────────────────
    $html += '<h2>25.0 Authentication Strength Analysis</h2>'
    $html += '<p class="section-intro">This section analyses the authentication method registrations of privileged users to classify their effective MFA posture. Phishing-resistant methods (FIDO2 security keys, Windows Hello for Business) provide the strongest protection against credential attacks targeting privileged accounts. Standard MFA (Microsoft Authenticator app, OATH TOTP) provides acceptable protection but remains vulnerable to some advanced phishing techniques. Accounts with weak or no MFA registered are at critical risk of credential-based compromise.</p>'
    $authRows = if ($null -ne $AuthStrengthData -and @($AuthStrengthData).Count -gt 0) { @($AuthStrengthData) } else { @() }
    if ($authRows.Count -gt 0) {
        $phishCount   = @($authRows | Where-Object { $_.AuthStrength -eq 'PhishingResistant' }).Count
        $standardCount = @($authRows | Where-Object { $_.AuthStrength -eq 'StandardMFA'      }).Count
        $weakCount    = @($authRows | Where-Object { $_.AuthStrength -eq 'WeakOrNone'        }).Count
        $unknownCount = @($authRows | Where-Object { $_.AuthStrength -eq 'Unknown'           }).Count
        $html += "<p><strong>Total privileged users analysed:</strong> $($authRows.Count) &nbsp; "
        $html += "<span class='cs-strong'>Phishing-Resistant: $phishCount</span>&nbsp; "
        $html += "<span class='cs-moderate'>Standard MFA: $standardCount</span>&nbsp; "
        $html += "<span class='cs-weak'>Weak or None: $weakCount</span>&nbsp; "
        $html += "<span class='cs-unknown'>Unknown: $unknownCount</span></p>"
        if ($weakCount -gt 0) {
            $html += "<div class='insight-item' style='border-left-color:#c62828'>$weakCount privileged user(s) have weak or no MFA registered. Phishing-resistant MFA should be enforced for all privileged accounts via Conditional Access Authentication Strength policies.</div>"
        }
        $html += '<table>'
        $html += '<thead><tr><th>User</th><th>UPN</th><th>Auth Strength</th><th>Phishing-Resistant</th><th>Standard MFA</th><th>MFA Registered</th><th>Passwordless</th><th>Method Count</th><th>Methods</th><th>Auth Risk</th></tr></thead>'
        $html += '<tbody>'
        foreach ($ar in $authRows) {
            if ($ar.AuthStrength -eq 'PhishingResistant') { $arBg = '#f1f8e9'; $arCls = 'cs-strong' }
            elseif ($ar.AuthStrength -eq 'StandardMFA')   { $arBg = '#fff8e1'; $arCls = 'cs-moderate' }
            elseif ($ar.AuthStrength -eq 'WeakOrNone')    { $arBg = '#ffebee'; $arCls = 'cs-weak' }
            else                                          { $arBg = '#f5f5f5'; $arCls = 'cs-unknown' }
            $html += "<tr style='background:$arBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode([string]$ar.UserDisplayName))</strong></td>"
            $html += "<td style='font-size:11px'>$([System.Net.WebUtility]::HtmlEncode([string]$ar.UserPrincipalName))</td>"
            $html += "<td><span class='$arCls'>$([System.Net.WebUtility]::HtmlEncode($ar.AuthStrength))</span></td>"
            $html += "<td>$(if ($ar.HasPhishingResistantMethod) { '<span style="color:#2e7d32"><strong>Yes</strong></span>' } else { 'No' })</td>"
            $html += "<td>$(if ($ar.HasStandardMfaMethod) { 'Yes' } else { 'No' })</td>"
            $html += "<td>$(if ($ar.IsMfaRegistered) { 'Yes' } else { 'No' })</td>"
            $html += "<td>$(if ($ar.IsPasswordlessCapable) { '<span style="color:#2e7d32">Yes</span>' } else { 'No' })</td>"
            $html += "<td>$($ar.MethodCount)</td>"
            $html += "<td style='font-size:11px'>$([System.Net.WebUtility]::HtmlEncode([string]$ar.MethodsRegistered))</td>"
            if ($ar.AuthRiskRating -eq 'High') { $authRiskCls = 'badge-high' } elseif ($ar.AuthRiskRating -eq 'Medium') { $authRiskCls = 'badge-medium' } else { $authRiskCls = 'badge-low' }
            $html += "<td><span class='$authRiskCls'>$([System.Net.WebUtility]::HtmlEncode($ar.AuthRiskRating))</span></td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p>Authentication strength data is not available. To enable this analysis, ensure the <strong>Reports.Read.All</strong> scope is consented and re-run with the <code>-IncludeAuthStrength</code> switch or set <code>IncludeAuthStrength: true</code> in the config file.</p>'
    }

    # ── Section 26.0 — Conditional Access Coverage by Role ────────────────────────
    $html += '<h2>26.0 Conditional Access Coverage by Role</h2>'
    $html += '<p class="section-intro">This section maps each privileged role to the set of enabled Conditional Access policies that apply to it. Roles not covered by any enabled CA policy, or covered only by policies without an MFA grant control, represent the highest-risk exposure surface. All high-impact roles should be explicitly targeted by strong CA policies enforcing at minimum MFA — ideally phishing-resistant MFA via an Authentication Strength control.</p>'
    $caRows = if ($null -ne $CACoverage -and @($CACoverage).Count -gt 0) { @($CACoverage) } else { @() }
    if ($caRows.Count -gt 0) {
        $notCoveredHigh = @($caRows | Where-Object { $_.CoverageStatus -eq 'NotCovered' -and $_.IsHighImpact -eq $true }).Count
        $noMfaHigh      = @($caRows | Where-Object { $_.CoverageStatus -eq 'Covered-NoMFA' -and $_.IsHighImpact -eq $true }).Count
        $strongMfaCount = @($caRows | Where-Object { $_.CoverageStatus -eq 'Covered-StrongMFA' }).Count
        $html += "<p><strong>Total roles analysed:</strong> $($caRows.Count) &nbsp; <strong>High-impact roles with no CA coverage:</strong> $notCoveredHigh &nbsp; <strong>High-impact roles covered but without MFA:</strong> $noMfaHigh &nbsp; <strong>Covered with strong MFA:</strong> $strongMfaCount</p>"
        if ($notCoveredHigh -gt 0 -or $noMfaHigh -gt 0) {
            $html += "<div class='insight-item' style='border-left-color:#c62828'>$notCoveredHigh high-impact role(s) have no Conditional Access coverage, and $noMfaHigh high-impact role(s) are covered but without MFA enforcement. These roles can be activated without Conditional Access controls applying.</div>"
        }
        $html += '<table>'
        $html += '<thead><tr><th>Role</th><th>High Impact</th><th>Coverage Status</th><th>MFA Enforced</th><th>Device Compliance</th><th>All-Users Policy</th><th>Covering Policies</th><th>Risk Rating</th></tr></thead>'
        $html += '<tbody>'
        foreach ($cr in $caRows) {
            if ($cr.RiskRating -eq 'High') { $crBg = '#ffebee'; $crCls = 'badge-high' }
            elseif ($cr.RiskRating -eq 'Medium') { $crBg = '#fff8e1'; $crCls = 'badge-medium' }
            else { $crBg = '#f1f8e9'; $crCls = 'badge-low' }
            $hiLabel = if ($cr.IsHighImpact) { '<strong>Yes</strong>' } else { 'No' }
            $mfaLabel = if ($cr.IsMfaEnforced) { '<span style="color:#2e7d32"><strong>Yes</strong></span>' } else { '<span style="color:#c62828">No</span>' }
            $dcLabel  = if ($cr.IsDeviceComplianceEnforced) { 'Yes' } else { 'No' }
            $allLabel = if ($cr.IsCoveredByAllUsersPolicy)  { 'Yes' } else { 'No' }
            if ($cr.CoverageStatus -eq 'NotCovered') { $covStyle = 'color:#c62828;font-weight:700' }
            elseif ($cr.CoverageStatus -eq 'Covered-NoMFA') { $covStyle = 'color:#e65100;font-weight:700' }
            else { $covStyle = 'color:#2e7d32' }
            $html += "<tr style='background:$crBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($cr.RoleName))</strong></td>"
            $html += "<td>$hiLabel</td>"
            $html += "<td style='$covStyle'>$([System.Net.WebUtility]::HtmlEncode($cr.CoverageStatus))</td>"
            $html += "<td>$mfaLabel</td><td>$dcLabel</td><td>$allLabel</td>"
            $html += "<td style='font-size:11px'>$([System.Net.WebUtility]::HtmlEncode([string]$cr.CoveringPolicies))</td>"
            $html += "<td><span class='$crCls'>$([System.Net.WebUtility]::HtmlEncode($cr.RiskRating))</span></td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p>Conditional Access coverage data is not available. Ensure the CA policies data was collected successfully (requires Policy.Read.All scope).</p>'
    }

    # ── Section 27.0 — Approval Model Analysis ────────────────────────────────────
    $approvalRows       = if ($null -ne $ApprovalAnalysis) { @($ApprovalAnalysis) } else { @() }
    $approvalGroupBased = @($approvalRows | Where-Object { $_.ApproverType -in 'Group', 'Mixed' }).Count
    $approvalGuestRoles = @($approvalRows | Where-Object { $_.GuestMembers -gt 0 }).Count
    $approvalWeakBroken = @($approvalRows | Where-Object { $_.ApprovalIntegrity -in 'Weak', 'Broken' }).Count
    $approvalStrong     = @($approvalRows | Where-Object { $_.ApprovalIntegrity -eq 'Strong' }).Count

    $html += '<h2>27.0 Approval Model Analysis</h2>'
    $html += '<p class="section-intro">This section analyses the approval model for every role that requires approval. Approver groups are expanded to member level and evaluated for guest composition, privileged user overlap, and self-approval risk. The <strong>ApprovalIntegrity</strong> classification objectively rates how robust the approval gate is against circumvention.</p>'
    $html += '<ul>'
    $html += '<li><strong>Strong:</strong> No overlap between approvers and role holders. All approvers are clean, identified internal accounts.</li>'
    $html += '<li><strong>Moderate:</strong> Guest approvers present, external tenant identities, or unclear approver type mapping.</li>'
    $html += '<li><strong>Weak:</strong> Approvers themselves hold privileged roles &mdash; separation of duties is reduced.</li>'
    $html += '<li><strong>Broken:</strong> Effective self-approval possible (same identity or heuristic alias match between approver and role holder), or approver group resolves to zero members.</li>'
    $html += '</ul>'
    if ($approvalRows.Count -gt 0) {
        $html += "<p><strong>Roles with approval configured:</strong> $($approvalRows.Count) &nbsp; <strong>Group-based:</strong> $approvalGroupBased &nbsp; <strong>With guest approvers:</strong> $approvalGuestRoles &nbsp; <strong>Weak or Broken integrity:</strong> $approvalWeakBroken &nbsp; <strong>Strong integrity:</strong> $approvalStrong</p>"
        if ($approvalWeakBroken -gt 0) {
            $html += "<div class='insight-item' style='border-left-color:#c62828'>$approvalWeakBroken role(s) have Weak or Broken approval integrity. Review the approval group composition and ensure approvers are separated from role holders to maintain a meaningful approval gate.</div>"
        }
        if ($approvalGuestRoles -gt 0) {
            $html += "<div class='insight-item' style='border-left-color:#e65100'>$approvalGuestRoles role(s) rely on guest (external) identities as approvers. Guest accounts operate outside this organisation's identity lifecycle and should not be approval authorities for privileged access.</div>"
        }
        $html += '<table>'
        $html += '<thead><tr><th>Role</th><th>Approver Type</th><th>Group Name</th><th>Group Type</th><th>Member Count</th><th>Guest Approvers</th><th>Privileged Approvers</th><th>Approval Integrity</th><th>Risk Rating</th></tr></thead>'
        $html += '<tbody>'
        foreach ($ar in $approvalRows) {
            $integ = [string]$ar.ApprovalIntegrity
            if     ($integ -eq 'Broken')   { $arBg = '#ffcdd2'; $arCls = 'badge-critical' }
            elseif ($integ -eq 'Weak')     { $arBg = '#ffebee'; $arCls = 'badge-high'     }
            elseif ($integ -eq 'Moderate') { $arBg = '#fff8e1'; $arCls = 'badge-medium'   }
            else                           { $arBg = '#f1f8e9'; $arCls = 'badge-low'      }
            $guestStyle = if ([int]$ar.GuestMembers -gt 0) { 'color:#e65100;font-weight:700' } else { '' }
            $privStyle  = if ([int]$ar.PrivilegedMembers -gt 0) { 'color:#c62828;font-weight:700' } else { '' }
            $html += "<tr style='background:$arBg'>"
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode($ar.RoleName))</strong></td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$ar.ApproverType))</td>"
            $html += "<td style='font-size:12px'>$([System.Net.WebUtility]::HtmlEncode([string]$ar.GroupName))</td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$ar.GroupType))</td>"
            $html += "<td>$($ar.MemberCount)</td>"
            $html += "<td style='$guestStyle'>$($ar.GuestMembers)</td>"
            $html += "<td style='$privStyle'>$($ar.PrivilegedMembers)</td>"
            $html += "<td><span class='$arCls'>$([System.Net.WebUtility]::HtmlEncode($integ))</span></td>"
            if ($ar.RiskRating -eq 'High') { $rrCls = 'badge-high' } elseif ($ar.RiskRating -eq 'Medium') { $rrCls = 'badge-medium' } else { $rrCls = 'badge-low' }
            $html += "<td><span class='$rrCls'>$([System.Net.WebUtility]::HtmlEncode([string]$ar.RiskRating))</span></td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }
    else {
        $html += '<p>Approval model analysis data is not available for this run. Ensure the role policy settings were collected successfully.</p>'
    }

    # ── Section 27.1 — Per-Role Approval Breakdown ────────────────────────────────
    $profileRowsAll = if ($null -ne $ApproverProfiles) { @($ApproverProfiles) } else { @() }
    if ($profileRowsAll.Count -gt 0) {
        $html += '<h3 id="s27-1">27.1 Per-Role Approval Breakdown</h3>'
        $html += '<p>Each role block below lists every effective approver with their identity flags. Where approver groups were configured, members are shown individually. A role-level summary and integrity verdict is shown at the bottom of each block.</p>'

        # Build a lookup of integrity/risk from the analysis summary rows
        $integrityLookup = @{}
        foreach ($ar in $approvalRows) {
            if ($ar.RoleName) { $integrityLookup[[string]$ar.RoleName] = $ar }
        }

        # Group profiles by RoleName, preserving order from analysis rows
        $orderedRoleNames = [System.Collections.Generic.List[string]]::new()
        $profilesByRole   = @{}
        # First add roles from analysis rows (preserves integrity-ordered output)
        foreach ($ar in $approvalRows) {
            if ($ar.RoleName -and -not $profilesByRole.ContainsKey([string]$ar.RoleName)) {
                [void]$orderedRoleNames.Add([string]$ar.RoleName)
                $profilesByRole[[string]$ar.RoleName] = [System.Collections.Generic.List[object]]::new()
            }
        }
        foreach ($p in $profileRowsAll) {
            $rn = if ($p.RoleName) { [string]$p.RoleName } else { '' }
            if (-not $profilesByRole.ContainsKey($rn)) {
                [void]$orderedRoleNames.Add($rn)
                $profilesByRole[$rn] = [System.Collections.Generic.List[object]]::new()
            }
            $profilesByRole[$rn].Add($p)
        }

        foreach ($roleName27 in $orderedRoleNames) {
            $roleProfiles27 = @($profilesByRole[$roleName27])
            $summary27      = if ($integrityLookup.ContainsKey($roleName27)) { $integrityLookup[$roleName27] } else { $null }
            $integrity27    = if ($summary27) { [string]$summary27.ApprovalIntegrity } else { 'Unknown' }

            switch ($integrity27) {
                'Broken'   { $cardBorder = '#c62828'; $cardBg = '#fff5f5' }
                'Weak'     { $cardBorder = '#e65100'; $cardBg = '#fff8f0' }
                'Moderate' { $cardBorder = '#f9a825'; $cardBg = '#fffde7' }
                'Strong'   { $cardBorder = '#2e7d32'; $cardBg = '#f1f8f1' }
                default    { $cardBorder = '#9e9e9e'; $cardBg = '#fafafa' }
            }

            $html += "<div style='border-left:4px solid $cardBorder;background:$cardBg;padding:12px 16px;margin:18px 0;border-radius:4px'>"
            $html += "<h4 style='margin:0 0 8px 0'>$([System.Net.WebUtility]::HtmlEncode($roleName27))</h4>"

            # Group names / group types summary line
            $roleGroups27 = @($roleProfiles27 | Where-Object { $_.ApproverObjectType -eq 'Group' -and $_.GroupName } | Select-Object -Property GroupName, GroupType -Unique)
            if ($roleGroups27.Count -gt 0) {
                $html += '<p style="margin:4px 0"><strong>Approver Groups:</strong>'
                $html += '<ul style="margin:4px 0 8px 24px">'
                foreach ($rg in $roleGroups27) {
                    $html += "<li>$([System.Net.WebUtility]::HtmlEncode([string]$rg.GroupName)) <em style='color:#666'>($([System.Net.WebUtility]::HtmlEncode([string]$rg.GroupType)))</em></li>"
                }
                $html += '</ul></p>'
            }
            else {
                # Individual user approvers — list directly
                $directUsers27 = @($roleProfiles27 | Where-Object { $_.ApproverObjectType -eq 'User' })
                if ($directUsers27.Count -gt 0) {
                    $html += '<p style="margin:4px 0"><strong>Direct Approvers:</strong>'
                    $html += '<ul style="margin:4px 0 8px 24px">'
                    foreach ($du in $directUsers27) {
                        $duFlags = @()
                        if ($du.IsGuest)            { $duFlags += "<span class='badge-medium' style='font-size:10px'>Guest</span>" }
                        if ($du.IsPrivileged)       { $duFlags += "<span class='badge-high' style='font-size:10px'>Privileged</span>" }
                        if ($du.NamingCompliant -eq $false) { $duFlags += "<span class='badge-medium' style='font-size:10px'>Naming</span>" }
                        $duFlagsStr = if ($duFlags) { ' ' + ($duFlags -join ' ') } else { '' }
                        $html += "<li>$([System.Net.WebUtility]::HtmlEncode([string]$du.DisplayName)) &mdash; $([System.Net.WebUtility]::HtmlEncode([string]$du.UserPrincipalName))$duFlagsStr</li>"
                    }
                    $html += '</ul></p>'
                }
            }

            # Member table (effective members — may include group members or direct user approvers)
            $effectiveMembers27 = @($roleProfiles27 | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserId) })
            if ($effectiveMembers27.Count -gt 0) {
                $html += '<p style="margin:8px 0 4px 0"><strong>Members:</strong></p>'
                $html += '<table style="font-size:12px;margin-bottom:8px">'
                $html += '<thead><tr><th>Display Name</th><th>UPN</th><th>Type</th><th>Guest</th><th>Privileged</th><th>Naming OK</th><th>Licensed</th><th>Source</th></tr></thead>'
                $html += '<tbody>'
                foreach ($em in $effectiveMembers27) {
                    $emGuest  = if ($em.IsGuest)            { "<span style='color:#e65100;font-weight:700'>Yes</span>" } else { 'No' }
                    $emPriv   = if ($em.IsPrivileged)       { "<span style='color:#c62828;font-weight:700'>Yes</span>" } else { 'No' }
                    $emName   = if ($em.NamingCompliant -eq $false) { "<span style='color:#f9a825;font-weight:700'>No</span>" } else { 'Yes' }
                    $emLic    = if ($em.IsLicensed)         { 'Yes' } else { 'No' }
                    $emSource = if ($em.MemberSource)       { [string]$em.MemberSource } else { 'Direct' }
                    $emRowBg  = if ($em.IsGuest) { '#fff8e1' } elseif ($em.IsPrivileged) { '#ffebee' } else { '' }
                    $emRowStyle = if ($emRowBg) { " style='background:$emRowBg'" } else { '' }
                    $html += "<tr$emRowStyle>"
                    $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$em.DisplayName))</td>"
                    $html += "<td style='font-size:11px'>$([System.Net.WebUtility]::HtmlEncode([string]$em.UserPrincipalName))</td>"
                    $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$em.UserType))</td>"
                    $html += "<td>$emGuest</td><td>$emPriv</td><td>$emName</td><td>$emLic</td>"
                    $html += "<td>$([System.Net.WebUtility]::HtmlEncode($emSource))</td>"
                    $html += '</tr>'
                }
                $html += '</tbody></table>'
            }
            else {
                $html += '<p style="color:#c62828"><em>No effective approver members could be resolved for this role.</em></p>'
            }

            # Per-role summary footer
            $roleTotal27  = $effectiveMembers27.Count
            $roleGuest27  = @($effectiveMembers27 | Where-Object { $_.IsGuest }).Count
            $rolePriv27   = @($effectiveMembers27 | Where-Object { $_.IsPrivileged }).Count
            $roleNaming27 = @($effectiveMembers27 | Where-Object { $_.NamingCompliant -eq $false }).Count
            if ($integrity27 -eq 'Broken')   { $integCls27 = 'badge-critical' }
            elseif ($integrity27 -eq 'Weak') { $integCls27 = 'badge-high' }
            elseif ($integrity27 -eq 'Moderate') { $integCls27 = 'badge-medium' }
            else                             { $integCls27 = 'badge-low' }
            $html += "<p style='margin:6px 0 0 0;font-size:12px'>"
            $html += "<strong>Total Members:</strong> $roleTotal27 &nbsp; "
            $html += "<strong>Guest:</strong> $roleGuest27 &nbsp; "
            $html += "<strong>Privileged:</strong> $rolePriv27 &nbsp; "
            $html += "<strong>Naming Issues:</strong> $roleNaming27 &nbsp; "
            $html += "<strong>Approval Integrity:</strong> <span class='$integCls27'>$([System.Net.WebUtility]::HtmlEncode($integrity27))</span>"
            $html += '</p>'
            $html += '</div>'
        }
    }

    # ── Section 27.2 — Approver Group → Role Mapping ─────────────────────────────
    $groupRoleRows = if ($null -ne $ApproverGroupRoleMap) { @($ApproverGroupRoleMap) } else { @() }
    if ($groupRoleRows.Count -gt 0) {
        $html += '<h3 id="s27-2">27.2 Approver Group &#8212; Role Mapping</h3>'
        $html += '<p>This table shows every approver group that is configured across all PIM role policies, and which roles each group is responsible for approving. Use this view to assess whether an approver group has an inappropriate breadth of approval authority, or whether critical roles rely on the same approver pool.</p>'
        $html += '<table>'
        $html += '<thead><tr><th>Approver Group</th><th>Group Type</th><th>Roles Approved</th><th>Role Count</th><th>Members</th><th>Guest Members</th><th>Privileged Members</th></tr></thead>'
        $html += '<tbody>'
        foreach ($gr in $groupRoleRows) {
            $grGuest = if ([int]$gr.GuestMembers -gt 0) { "<span style='color:#e65100;font-weight:700'>$($gr.GuestMembers)</span>" } else { '0' }
            $grPriv  = if ([int]$gr.PrivilegedMembers -gt 0) { "<span style='color:#c62828;font-weight:700'>$($gr.PrivilegedMembers)</span>" } else { '0' }
            $html += '<tr>'
            $html += "<td><strong>$([System.Net.WebUtility]::HtmlEncode([string]$gr.ApproverGroupName))</strong></td>"
            $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$gr.GroupType))</td>"
            $html += "<td style='font-size:11px'>$([System.Net.WebUtility]::HtmlEncode([string]$gr.RolesApproved))</td>"
            $html += "<td>$($gr.RoleCount)</td>"
            $html += "<td>$($gr.MemberCount)</td>"
            $html += "<td>$grGuest</td>"
            $html += "<td>$grPriv</td>"
            $html += '</tr>'
        }
        $html += '</tbody></table>'
    }

    # ── Section 27.3 — Approver Group Member Directory ───────────────────────────
    $profileRowsFor273 = if ($null -ne $ApproverProfiles) { @($ApproverProfiles) } else { @() }
    if ($profileRowsFor273.Count -gt 0) {
        $html += '<h3 id="s27-3">27.3 Approver Group Member Directory</h3>'
        $html += '<p>For each approver group, the table below lists every resolved member with their identity flags. This provides the complete answer to <em>&ldquo;who can approve activation for the roles in each approver group?&rdquo;</em></p>'

        # Build group-keyed member lookup
        $g273Map     = @{}
        $g273Order   = [System.Collections.Generic.List[string]]::new()
        $g273Meta    = @{}

        foreach ($p in $profileRowsFor273) {
            if ($p.ApproverObjectType -ne 'Group' -or [string]::IsNullOrWhiteSpace($p.ApproverObjectId)) { continue }
            $gid273 = [string]$p.ApproverObjectId
            if (-not $g273Map.ContainsKey($gid273)) {
                [void]$g273Order.Add($gid273)
                $g273Map[$gid273]  = [System.Collections.Generic.List[object]]::new()
                $g273Meta[$gid273] = @{ Name = [string]$p.GroupName; Type = [string]$p.GroupType }
            }
            if (-not [string]::IsNullOrWhiteSpace($p.UserId)) {
                $g273Map[$gid273].Add($p)
            }
        }

        # Build role-per-group lookup from groupRoleRows
        $g273RoleMap = @{}
        foreach ($gr in $groupRoleRows) {
            if ($gr.ApproverGroupId) { $g273RoleMap[[string]$gr.ApproverGroupId] = [string]$gr.RolesApproved }
        }

        foreach ($gid273 in $g273Order) {
            $meta273    = $g273Meta[$gid273]
            $members273 = @($g273Map[$gid273] | Sort-Object UserPrincipalName -Unique)
            $roles273   = if ($g273RoleMap.ContainsKey($gid273)) { $g273RoleMap[$gid273] } else { '' }
            $guestCnt   = @($members273 | Where-Object { $_.IsGuest }).Count
            $privCnt    = @($members273 | Where-Object { $_.IsPrivileged }).Count

            if     ($guestCnt -gt 0 -or $privCnt -gt 0) { $g273Border = '#e65100'; $g273Bg = '#fff8f0' }
            else                                          { $g273Border = '#1f4e78'; $g273Bg = '#f7fbff' }

            $html += "<div style='border-left:4px solid $g273Border;background:$g273Bg;padding:12px 16px;margin:18px 0;border-radius:4px'>"
            $html += "<h4 style='margin:0 0 6px 0'>$([System.Net.WebUtility]::HtmlEncode($meta273.Name)) <span style='font-weight:400;font-size:13px;color:#555'>($([System.Net.WebUtility]::HtmlEncode($meta273.Type)))</span></h4>"
            if ($roles273) {
                $html += "<p style='margin:0 0 8px 0;font-size:12px;color:#3f4f61'><strong>Approves for:</strong> $([System.Net.WebUtility]::HtmlEncode($roles273))</p>"
            }
            $html += "<p style='margin:0 0 4px 0;font-size:12px'><strong>Members: $($members273.Count)</strong> &nbsp; "
            if ($guestCnt -gt 0) { $html += "<span style='color:#e65100;font-weight:700'>Guest: $guestCnt</span> &nbsp; " }
            if ($privCnt  -gt 0) { $html += "<span style='color:#c62828;font-weight:700'>Privileged: $privCnt</span> &nbsp; " }
            $html += '</p>'

            if ($members273.Count -gt 0) {
                $html += '<table style="font-size:12px;margin-top:6px">'
                $html += '<thead><tr><th>Display Name</th><th>UPN</th><th>Type</th><th>Guest</th><th>Privileged</th><th>Naming OK</th><th>Licensed</th><th>Source</th></tr></thead>'
                $html += '<tbody>'
                foreach ($m273 in $members273) {
                    $m273Guest  = if ($m273.IsGuest)            { "<span style='color:#e65100;font-weight:700'>Yes</span>" } else { 'No' }
                    $m273Priv   = if ($m273.IsPrivileged)       { "<span style='color:#c62828;font-weight:700'>Yes</span>" } else { 'No' }
                    $m273Name   = if ($m273.NamingCompliant -eq $false) { "<span style='color:#f9a825;font-weight:700'>No</span>" } else { 'Yes' }
                    $m273Lic    = if ($m273.IsLicensed)         { 'Yes' } else { 'No' }
                    $m273Source = if ($m273.MemberSource)       { [string]$m273.MemberSource } else { 'Direct' }
                    $m273RowBg  = if ($m273.IsGuest) { " style='background:#fff8e1'" } elseif ($m273.IsPrivileged) { " style='background:#ffebee'" } else { '' }
                    $html += "<tr$m273RowBg>"
                    $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$m273.DisplayName))</td>"
                    $html += "<td style='font-size:11px'>$([System.Net.WebUtility]::HtmlEncode([string]$m273.UserPrincipalName))</td>"
                    $html += "<td>$([System.Net.WebUtility]::HtmlEncode([string]$m273.UserType))</td>"
                    $html += "<td>$m273Guest</td><td>$m273Priv</td><td>$m273Name</td><td>$m273Lic</td>"
                    $html += "<td>$([System.Net.WebUtility]::HtmlEncode($m273Source))</td>"
                    $html += '</tr>'
                }
                $html += '</tbody></table>'
            }
            else {
                $html += '<p style="color:#c62828;font-size:12px"><em>No members could be resolved for this group.</em></p>'
            }
            $html += '</div>'
        }
    }

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

    # Build a Word-friendly version of the HTML that strips CSS classes Word cannot
    # render (coloured pills, border-radius, background-color on table cells) and
    # replaces them with inline styles that the Word HTML engine honours.
    $printHtmlPath = [System.IO.Path]::ChangeExtension($HtmlPath, '.print.html')
    try {
        $raw = [System.IO.File]::ReadAllText($HtmlPath, [System.Text.Encoding]::UTF8)

        # Replace coloured status pill spans with plain bold bracketed text
        $raw = $raw -replace '<span[^>]+class="[^"]*status-pill tl-red[^"]*"[^>]*>(.*?)</span>', '<strong>[$1]</strong>'
        $raw = $raw -replace '<span[^>]+class="[^"]*status-pill tl-amber[^"]*"[^>]*>(.*?)</span>', '<strong>[$1]</strong>'
        $raw = $raw -replace '<span[^>]+class="[^"]*status-pill tl-green[^"]*"[^>]*>(.*?)</span>', '<strong>[$1]</strong>'
        $raw = $raw -replace '<span[^>]+class="[^"]*status-pill[^"]*"[^>]*>(.*?)</span>', '<strong>[$1]</strong>'

        # Replace tl-dot divs with plain text indicators
        $raw = $raw -replace '<div[^>]+class="[^"]*tl-dot tl-green[^"]*"[^>]*></div>', '<strong>[GREEN]</strong>&nbsp;'
        $raw = $raw -replace '<div[^>]+class="[^"]*tl-dot tl-amber[^"]*"[^>]*></div>', '<strong>[AMBER]</strong>&nbsp;'
        $raw = $raw -replace '<div[^>]+class="[^"]*tl-dot tl-red[^"]*"[^>]*></div>', '<strong>[RED]</strong>&nbsp;'

        # Strip section-band coloured divs — keep inner content only
        $raw = $raw -replace '<div[^>]+class="[^"]*section-band[^"]*"[^>]*>(.*?)</div>', '$1'

        # Replace coloured background on table cells with a border
        $raw = $raw -replace '(<td[^>]+)style="[^"]*background[^"]*"', '$1style="border:1px solid #999;"'
        $raw = $raw -replace '(<th[^>]+)style="[^"]*background[^"]*"', '$1style="border:1px solid #999;font-weight:bold;"'

        # Inject a minimal Word-compatible style block before </head>
        $wordStyle = @'
<style>
body{font-family:Calibri,Arial,sans-serif;font-size:11pt;color:#000;margin:0}
h1{font-size:18pt;font-weight:bold;margin-top:16pt;margin-bottom:8pt}
h2{font-size:14pt;font-weight:bold;margin-top:14pt;margin-bottom:6pt;border-bottom:1px solid #999;padding-bottom:3pt}
h3{font-size:12pt;font-weight:bold;margin-top:10pt;margin-bottom:4pt}
table{border-collapse:collapse;width:100%;font-size:9pt}
th,td{border:1px solid #888;padding:4pt 6pt;vertical-align:top}
th{font-weight:bold;background:#e8e8e8}
ul,ol{margin:4pt 0 4pt 18pt}
li{margin-bottom:3pt}
p{margin:4pt 0}
</style>
'@
        $raw = $raw -replace '(?i)</head>', "$wordStyle`n</head>"
        [System.IO.File]::WriteAllText($printHtmlPath, $raw, [System.Text.Encoding]::UTF8)
    }
    catch {
        Write-PimLog -Level WARN -Message "Could not build print-friendly HTML; will use source HTML for PDF. Error: $($_.Exception.Message)"
        $printHtmlPath = $HtmlPath
    }

    try {
        $word.Visible = $false
        $doc = $word.Documents.Open($printHtmlPath)

        # Set generous margins so table columns do not overflow
        $doc.PageSetup.TopMargin    = $word.InchesToPoints(0.75)
        $doc.PageSetup.BottomMargin = $word.InchesToPoints(0.75)
        $doc.PageSetup.LeftMargin   = $word.InchesToPoints(0.75)
        $doc.PageSetup.RightMargin  = $word.InchesToPoints(0.75)

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
        # Clean up the temporary print HTML
        if ($printHtmlPath -ne $HtmlPath -and (Test-Path $printHtmlPath)) {
            Remove-Item -Path $printHtmlPath -Force -ErrorAction SilentlyContinue
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
        [switch]$DisableTranscript,
        [switch]$ForceReConnect
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
            -IncludePimForGroups:$config.IncludePimForGroups `
            -IncludeAuthStrength:($IncludeAuthStrength.IsPresent -or $config.IncludeAuthStrength) `
            -ForceReConnect:$ForceReConnect

        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        $tenantProfile = Get-TenantProfile -TenantLabelOverride $config.TenantLabelOverride

        $tenantRootName = $tenantProfile.TenantLabel
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

        $transcriptPath = Join-Path -Path $runOutputFolder -ChildPath ("Transcript_{0}.log" -f $tenantProfile.TenantLabel)
        if (-not $DisableTranscript) {
            $transcriptStarted = Start-PimTranscriptSafe -TranscriptPath $transcriptPath
        }

        $roleAssignments = @(Get-PimRoleAssignments -OutputFolder $runOutputFolder)

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

        # Pre-initialise identity analysis keys so they always exist in $data even if the
        # analysis step fails for any reason (e.g. missing Graph scope, type coercion, network error).
        $data['AuthStrengthData'] = @()
        $data['CACoverage']       = @()

        # Pre-initialise approver analysis keys
        $data['ApprovalAnalysis']    = @()
        $data['ApproverProfiles']    = @()
        $data['ApproverGroupRoleMap'] = @()
        $data['ApprovalFindings']    = @()

        # Pin a direct object reference to the data hashtable before the try/catch block.
        # In PS5.1 (WMF 5.1), when Build-PimReviewWorkbook.ps1 is dot-sourced its script-level
        # param([hashtable]$Data) creates $Data=$null in script scope. After a nested try/catch,
        # PS5.1 variable lookup can incorrectly resolve $data to that script-scope $null instead of
        # the function-local hashtable. $pimData is a separate reference to the same object that
        # avoids this name collision entirely.
        $pimData = $data

        # Identity analysis: authentication strength + CA coverage per role
        Write-PimLog -Message 'Running identity analysis (authentication strength + CA coverage).'
        try {
            $privUserIdStrings = [string[]]@($allUserIds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            $identityAnalysis = Get-PimIdentityAnalysis `
                -PrivilegedUserIds        $privUserIdStrings `
                -ConditionalAccessPolicies @($advancedRisk.ConditionalAccessPolicies) `
                -RoleAssignments          $roleAssignments `
                -HighImpactRoles          @($config.HighImpactRoles) `
                -OutputFolder             $runOutputFolder `
                -ReturnObjectsOnly

            if ($null -ne $identityAnalysis) {
                $authStrengthResult = $identityAnalysis.AuthStrength
                $caCoverageResult   = $identityAnalysis.CACoverage
                if ($null -ne $authStrengthResult) { $pimData['AuthStrengthData'] = @($authStrengthResult) }
                if ($null -ne $caCoverageResult)   { $pimData['CACoverage']       = @($caCoverageResult) }
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Identity analysis (auth strength / CA coverage) failed and will be skipped. Error: $($_.Exception.Message)"
        }

        # ── Approver analysis: expand groups, evaluate integrity, generate findings ──────
        Write-PimLog -Message 'Running deep approver analysis (group expansion and integrity evaluation).'
        try {
            $approverAnalysisResult = Get-PimApproverAnalysis `
                -PolicyFlatRules  $policyRules `
                -RoleAssignments  $roleAssignments `
                -Config           $config `
                -OutputFolder     $runOutputFolder

            if ($null -ne $approverAnalysisResult) {
                # Patch every elevation matrix policy object with ApprovalIntegrity and GroupType
                $integrityByRole = @{}
                $groupTypeByRole = @{}
                foreach ($row in @($approverAnalysisResult.ApprovalAnalysis)) {
                    if (-not [string]::IsNullOrWhiteSpace($row.RoleName)) {
                        $integrityByRole[$row.RoleName] = $row.ApprovalIntegrity
                        if ($row.GroupType) { $groupTypeByRole[$row.RoleName] = $row.GroupType }
                    }
                }
                foreach ($policy in $roleElevationMatrix) {
                    if ($policy -and -not [string]::IsNullOrWhiteSpace($policy.RoleName)) {
                        $ai = if ($integrityByRole.ContainsKey($policy.RoleName)) { $integrityByRole[$policy.RoleName] } else { 'Unknown' }
                        $gt = if ($groupTypeByRole.ContainsKey($policy.RoleName)) { $groupTypeByRole[$policy.RoleName] } else { $null }
                        $policy | Add-Member -NotePropertyName ApprovalIntegrity -NotePropertyValue $ai -Force
                        $policy | Add-Member -NotePropertyName GroupType         -NotePropertyValue $gt -Force
                    }
                }
                $pimData['ApprovalAnalysis']    = @($approverAnalysisResult.ApprovalAnalysis)
                $pimData['ApproverProfiles']    = @($approverAnalysisResult.ApproverProfiles)
                $pimData['ApproverGroupRoleMap'] = @($approverAnalysisResult.ApproverGroupRoleMap)
                $pimData['ApprovalFindings']    = @($approverAnalysisResult.ApprovalFindings)
                Write-PimLog -Message "Approver analysis complete: $(@($approverAnalysisResult.ApprovalAnalysis).Count) role(s) analysed, $(@($approverAnalysisResult.ApproverProfiles).Count) approver profile row(s), $(@($approverAnalysisResult.ApproverGroupRoleMap).Count) approver group(s)."
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Approver analysis failed and will be skipped. Error: $($_.Exception.Message)"
        }

        Write-PimLog -Message "Building PIM review workbook (data keys: $($pimData.Count), auth-strength records: $(@($pimData.AuthStrengthData).Count), CA-coverage records: $(@($pimData.CACoverage).Count))."

        # Use splatting to pre-evaluate all argument values into a hashtable before the call.
        # Calling Build-PimReviewWorkbook with named parameters (-Data $pimData) triggers a PS5.1
        # scope-resolution bug: dot-sourcing Build-PimReviewWorkbook.ps1 creates $Data=$null and
        # $Config=$null in script scope; PS5.1 Mandatory validation then resolves those names against
        # script scope (null) instead of the supplied argument. Splatting bypasses this because the
        # values are captured into $wbSplat at construction time using function-local scope lookup,
        # and passed to the function as pre-resolved object references.
        $wbSplat = @{
            Data                        = $pimData
            Config                      = $config
            OutputFolder                = $runOutputFolder
            WorkbookFileName            = $workbookFileName
            InstallImportExcelIfMissing = [bool]$config.InstallImportExcelIfMissing
            PromptToInstallImportExcel  = [bool]$config.PromptToInstallImportExcel
        }
        $workbookResult = Build-PimReviewWorkbook @wbSplat

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

        Add-Member -InputObject $runMeta.Counts -NotePropertyName RoleElevationMatrix  -NotePropertyValue @($roleElevationMatrix).Count -Force
        Add-Member -InputObject $runMeta.Counts -NotePropertyName ApprovalAnalysis     -NotePropertyValue @($pimData.ApprovalAnalysis).Count  -Force
        Add-Member -InputObject $runMeta.Counts -NotePropertyName ApproverGroups       -NotePropertyValue @($pimData.ApproverGroupRoleMap).Count  -Force

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
            -RoleElevationMatrix       $roleElevationMatrix `
            -PrivilegeConcentration    $workbookResult.PrivilegeConcentration `
            -GroupRiskProfiles         $workbookResult.GroupRoleSummary `
            -JitEffectiveness          $workbookResult.JitEffectiveness `
            -KeyInsights               @($workbookResult.KeyInsights) `
            -GuestPrivilegedAccounts   $workbookResult.GuestPrivilegedAccounts `
            -NamingCompliance          $workbookResult.NamingCompliance `
            -LicensedPrivilegedAccounts $workbookResult.LicensedPrivilegedAccounts `
            -IdentityAssuranceProfiles $workbookResult.IdentityAssuranceProfiles `
            -AuthStrengthData          @($pimData.AuthStrengthData) `
            -CACoverage                @($pimData.CACoverage) `
            -ApprovalAnalysis          @($pimData.ApprovalAnalysis) `
            -ApproverProfiles          @($pimData.ApproverProfiles) `
            -ApproverGroupRoleMap      @($pimData.ApproverGroupRoleMap)

        Add-Member -InputObject $runMeta -NotePropertyName RoleElevationMatrixPath -NotePropertyValue (Join-Path -Path $rawFolder -ChildPath 'RoleElevationMatrix.csv') -Force

        $summaryPdfPath = Join-Path -Path $runOutputFolder -ChildPath ("Summary_{0}.pdf" -f $tenantProfile.TenantLabel)
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


