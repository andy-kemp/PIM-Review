<#
.SYNOPSIS
Builds the Privileged Role Elevation Control Matrix for a PIM review.

.DESCRIPTION
Derives structured RoleElevationPolicy objects from existing flat policy rules,
role assignment data, and access review coverage information.

This script introduces the following structured analysis outputs:

  RoleElevationPolicy object
  - RoleName / IsHighImpact / AssignmentTypes
  - MaxActivationDurationHours / MfaRequired / ApprovalRequired
  - ApproverCount / ApproverType / ApproverDisplayNames
  - JustificationRequired / TicketingRequired
  - PermanentActiveAllowed / PermanentEligibleAllowed
  - AccessReviewsEnabled
  - ElevationFrictionScore (0-100, higher = better JIT control)
  - ControlMaturityLabel (Well-Controlled / Partially Controlled / Weakly Controlled / Critical Gap)
  - ControlGaps (list of detected control weaknesses)
  - GovernanceWeaknesses (list of approval design concerns)
  - RiskRating (Critical / High / Medium / Low)
  - RiskRationale (plain-language summary)

  Add-RoleControlFindings
  - Generates correlated findings combining exposure and control weakness signals
  - Designed for integration with the main New-PimFindings findings engine

No additional Microsoft Graph API calls are made. All analysis runs against data
already collected by Get-PimRolePolicySettings.ps1 and Get-PimAdvancedRiskData.ps1.

Required inputs:
  - PolicyRules     : flat rules from Get-PimRolePolicySettings (FlatRules property)
  - RoleAssignments : role assignment rows from Get-PimRoleAssignments
  - AccessReviews   : access review rows from Get-PimAdvancedRiskData
  - Config          : hashtable with HighImpactRoles list

.EXAMPLE
$matrix = Get-PimRoleElevationMatrix `
    -PolicyRules     $policyData.FlatRules `
    -RoleAssignments $roleAssignments `
    -AccessReviews   $advancedRisk.AccessReviews `
    -Config          $config `
    -OutputFolder    $rawFolder
#>
[CmdletBinding()]
param(
    [object[]]$PolicyRules,
    [object[]]$RoleAssignments,
    [object[]]$AccessReviews,
    [hashtable]$Config,
    [string]$OutputFolder,
    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

# ─── Helper functions ──────────────────────────────────────────────────────────

function Get-NormalizedRoleName {
    [CmdletBinding()]
    param([string]$RoleName)

    if ([string]::IsNullOrWhiteSpace($RoleName)) { return '' }
    return $RoleName.Trim().ToLowerInvariant()
}

function Get-RoleCriticalityTier {
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [string[]]$HighImpactRoles
    )

    $normalizedRole = Get-NormalizedRoleName -RoleName $RoleName
    $normalizedHighImpact = @($HighImpactRoles | ForEach-Object { Get-NormalizedRoleName -RoleName $_ } | Where-Object { $_ })

    if ($normalizedRole -notin $normalizedHighImpact) {
        return 'Standard'
    }

    switch ($normalizedRole) {
        'global administrator' { return 'Tier0-GlobalAdministrator' }
        'privileged role administrator' { return 'Tier0-PrivilegedRoleAdministrator' }
        'conditional access administrator' { return 'Tier0-ConditionalAccessAdministrator' }
        'security administrator' { return 'Tier0-SecurityAdministrator' }
        'privileged authentication administrator' { return 'Tier0-PrivilegedAuthenticationAdministrator' }
        'authentication policy administrator' { return 'Tier0-PrivilegedAuthenticationAdministrator' }
        default { return 'HighImpact' }
    }
}

function Get-RolePriorityWeight {
    [CmdletBinding()]
    param([string]$RoleCriticalityTier)

    switch ($RoleCriticalityTier) {
        'Tier0-GlobalAdministrator' { return 4 }
        'Tier0-PrivilegedRoleAdministrator' { return 4 }
        'Tier0-ConditionalAccessAdministrator' { return 3 }
        'Tier0-SecurityAdministrator' { return 3 }
        'Tier0-PrivilegedAuthenticationAdministrator' { return 3 }
        'HighImpact' { return 2 }
        default { return 1 }
    }
}

function Get-ApproverInsights {
    [CmdletBinding()]
    param(
        [string]$ApproverIds,
        [string]$ApproverDisplayNames,
        [hashtable]$PrincipalTypeById
    )

    $ids = @(($ApproverIds -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $names = @(($ApproverDisplayNames -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $details = New-Object System.Collections.Generic.List[string]
    $userCount = 0
    $groupCount = 0
    $spCount = 0
    $unknownCount = 0

    for ($i = 0; $i -lt $ids.Count; $i++) {
        $id = $ids[$i]
        $name = if ($i -lt $names.Count) { $names[$i] } else { $id }

        $type = 'Unknown'
        if ($PrincipalTypeById -and $PrincipalTypeById.ContainsKey($id) -and -not [string]::IsNullOrWhiteSpace($PrincipalTypeById[$id])) {
            $type = [string]$PrincipalTypeById[$id]
        }

        switch ($type) {
            'User' { $userCount++ }
            'Group' { $groupCount++ }
            'ServicePrincipal' { $spCount++ }
            default { $unknownCount++ }
        }

        $details.Add("$name ($type)")
    }

    $approverTypeBreakdown = "Users=$userCount; Groups=$groupCount; ServicePrincipals=$spCount; Unknown=$unknownCount"

    return [pscustomobject]@{
        ApproverIds           = ($ids -join '; ')
        ApproverDisplayNames  = (($details | ForEach-Object { ($_ -replace ' \([^)]+\)$', '') }) -join '; ')
        ApproverDetails       = ($details -join '; ')
        ApproverCount         = $ids.Count
        ApproverTypeBreakdown = $approverTypeBreakdown
        HasUnknownApproverType = ($unknownCount -gt 0)
    }
}

# ─── Pure scoring functions ────────────────────────────────────────────────────

function Get-ElevationFrictionScore {
    <#
    .SYNOPSIS
    Computes a 0-100 score representing how much friction a user faces when activating
    a privileged role. Higher scores indicate stronger JIT controls.

    Scoring model:
      +40  MFA is required for activation
      +30  Approval is required and at least one approver is configured
      +20  Maximum activation window is 8 hours or less
      +10  Business justification is required for activation
    #>
    [CmdletBinding()]
    param(
        [bool]$MfaRequired,
        [bool]$ApprovalRequired,
        [int]$ApproverCount,
        [AllowNull()][object]$MaxActivationDurationHours,
        [bool]$JustificationRequired
    )

    $score = 0

    if ($MfaRequired) { $score += 40 }
    if ($ApprovalRequired -and $ApproverCount -gt 0) { $score += 30 }
    if ($null -ne $MaxActivationDurationHours -and [double]$MaxActivationDurationHours -gt 0 -and [double]$MaxActivationDurationHours -le 8) { $score += 20 }
    if ($JustificationRequired) { $score += 10 }

    return [Math]::Min(100, $score)
}

function Get-ControlMaturityLabel {
    <#
    .SYNOPSIS Maps an ElevationFrictionScore to a descriptive control maturity label.#>
    [CmdletBinding()]
    param([int]$FrictionScore)

    if ($FrictionScore -ge 80) { return 'Well-Controlled' }
    if ($FrictionScore -ge 50) { return 'Partially Controlled' }
    if ($FrictionScore -ge 20) { return 'Weakly Controlled' }
    return 'Critical Gap'
}

function Get-ControlStrength {
    <#
    .SYNOPSIS
    Classifies the overall control strength for a role as Strong, Moderate, or Weak.

    Strong   : MFA required, effective approval (>= 1 approver), duration <= 8h, no permanent active assignment.
    Moderate : Core controls present but with a residual gap (e.g. long duration, permanent eligible assignment).
    Weak     : Missing MFA, missing effective approval, duration > 24h, or permanent active assignment exists.
    #>
    [CmdletBinding()]
    param(
        [bool]$MfaRequired,
        [bool]$ApprovalRequired,
        [int]$ApproverCount,
        [AllowNull()][object]$MaxActivationDurationHours,
        [bool]$HasPermanentEligibleAssignment,
        [bool]$HasPermanentActiveAssignment,
        [string]$RoleCriticalityTier
    )

    $effectiveApproval = $ApprovalRequired -and $ApproverCount -gt 0
    $shortDuration     = $null -ne $MaxActivationDurationHours -and [double]$MaxActivationDurationHours -le 8
    $veryLongDuration  = $null -ne $MaxActivationDurationHours -and [double]$MaxActivationDurationHours -gt 24
    $isTier0           = $RoleCriticalityTier -like 'Tier0-*'

    if (-not $MfaRequired)                              { return 'Weak' }
    if (-not $effectiveApproval)                        { return 'Weak' }
    if ($veryLongDuration)                              { return 'Weak' }
    if ($HasPermanentActiveAssignment)                  { return 'Weak' }
    if ($isTier0 -and $HasPermanentEligibleAssignment)  { return 'Weak' }
    if ($shortDuration -and -not $HasPermanentEligibleAssignment) { return 'Strong' }
    return 'Moderate'
}

function Get-ApprovalModelStrength {
    <#
    .SYNOPSIS
    Assesses the quality of the approval model configured for a role.

    Strong   : Approval configured, 2+ approvers, no unknown types, no self-approval risk.
    Moderate : 1 approver, unknown approver types, or Tier-0 role with fewer than 2 approvers.
    Weak     : Approval required but 0 approvers, or self-approval risk detected.
    Unknown  : Approval not required - approval model quality cannot be assessed.
    #>
    [CmdletBinding()]
    param(
        [bool]$ApprovalRequired,
        [int]$ApproverCount,
        [bool]$HasUnknownApproverType,
        [string[]]$GovernanceWeaknesses,
        [string]$RoleCriticalityTier
    )

    if (-not $ApprovalRequired) { return 'Unknown' }
    if ($ApproverCount -eq 0)   { return 'Weak' }

    $hasSelfApprovalRisk = @($GovernanceWeaknesses | Where-Object { $_ -match 'self-approval' }).Count -gt 0
    if ($hasSelfApprovalRisk) { return 'Weak' }

    $isTier0 = $RoleCriticalityTier -like 'Tier0-*'
    if ($isTier0 -and $ApproverCount -lt 2) { return 'Moderate' }
    if ($HasUnknownApproverType)            { return 'Moderate' }
    if ($ApproverCount -eq 1)               { return 'Moderate' }
    return 'Strong'
}

function Get-RoleControlRiskRating {
    <#
    .SYNOPSIS
    Derives a risk rating (Critical/High/Medium/Low) from role criticality and detected control gaps.

    Rating logic (evaluated in order):
    - Critical : High-impact role with neither MFA nor effective approval
    - High     : High-impact role missing MFA or approval, or has a permanent active assignment
    - High     : High-impact role with permanent eligible assignment
    - Medium   : Any role with no MFA, no approval, or a very long activation window (>24h)
    - Low      : All key controls are present
    #>
    [CmdletBinding()]
    param(
        [string]$RoleCriticalityTier,
        [bool]$MfaRequired,
        [bool]$ApprovalRequired,
        [int]$ApproverCount,
        [bool]$HasPermanentActiveAssignment,
        [bool]$HasPermanentEligibleAssignment,
        [AllowNull()][object]$MaxActivationDurationHours,
        [bool]$AccessReviewsEnabled,
        [int]$GovernanceWeaknessCount,
        [bool]$TicketingRequired
    )

    $roleWeight           = Get-RolePriorityWeight -RoleCriticalityTier $RoleCriticalityTier
    $isTier0              = $roleWeight -ge 3
    $isHighImpact         = $roleWeight -ge 2
    $hasEffectiveApproval = $ApprovalRequired -and $ApproverCount -gt 0
    $noMfa                = -not $MfaRequired
    $noApproval           = -not $hasEffectiveApproval
    $veryLongDuration     = $null -ne $MaxActivationDurationHours -and [double]$MaxActivationDurationHours -gt 24
    $longDuration         = $null -ne $MaxActivationDurationHours -and [double]$MaxActivationDurationHours -gt 8
    $noTicketing          = -not $TicketingRequired

    if ($isTier0 -and $HasPermanentActiveAssignment) { return 'Critical' }
    if ($isTier0 -and $noMfa -and $noApproval) { return 'Critical' }

    if ($isTier0 -and ($noMfa -or $noApproval -or $HasPermanentEligibleAssignment -or $longDuration -or -not $AccessReviewsEnabled)) { return 'High' }
    if ($isHighImpact -and ($noMfa -and $noApproval)) { return 'High' }
    if ($isHighImpact -and ($HasPermanentActiveAssignment -or $HasPermanentEligibleAssignment)) { return 'High' }
    if ($isHighImpact -and $GovernanceWeaknessCount -ge 2) { return 'High' }

    if ($noMfa -or $noApproval -or $veryLongDuration -or $GovernanceWeaknessCount -gt 0 -or $noTicketing) { return 'Medium' }

    return 'Low'
}

# ─── Approval governance weakness detection ─────────────────────────────────────

function Test-ApprovalGovernanceWeakness {
    <#
    .SYNOPSIS
    Returns a list of governance weakness descriptions for a role's approval configuration.
    Where self-approval cannot be definitively confirmed, findings are labelled as potential.
    #>
    [CmdletBinding()]
    param(
        [bool]$ApprovalRequired,
        [int]$ApproverCount,
        [string]$ApproverDisplayNames,
        [string]$ApproverIds,
        [string[]]$RoleUserIds,
        [bool]$HasUnknownApproverType,
        [string]$RoleCriticalityTier
    )

    $weaknesses = New-Object System.Collections.Generic.List[string]

    if (-not $ApprovalRequired) {
        # No approval configured — control gap handled in Get-RoleElevationPolicy; not a governance weakness here
        return @()
    }

    # Approval required but no approvers are defined
    if ($ApproverCount -eq 0) {
        $weaknesses.Add('Approval is required but no approvers are defined. Activation may be permanently blocked or may silently bypass the approval gate depending on policy evaluation behaviour.')
        return @($weaknesses)
    }

    $idList   = @(($ApproverIds          -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $nameList = @(($ApproverDisplayNames -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    # Detect potential self-approval: approver IDs overlap with principals assigned to this role
    # This is flagged as "potential" because group membership of approvers cannot be evaluated without extra API calls
    $roleUserIdSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($userId in @($RoleUserIds | Where-Object { $_ })) {
        [void]$roleUserIdSet.Add([string]$userId)
    }

    $overlapCount = @($idList | Where-Object { $roleUserIdSet.Contains($_) }).Count
    if ($overlapCount -gt 0) {
        $weaknesses.Add("Potential self-approval risk: $overlapCount approver identity(s) also hold this role directly. This cannot be confirmed definitively without group membership evaluation but warrants governance review.")
    }

    # Single approver creates an availability dependency and concentration risk
    if ($ApproverCount -eq 1) {
        $approverLabel = if ($nameList.Count -gt 0) { $nameList[0] } else { 'unknown approver' }
        $weaknesses.Add("Single approver configured ($approverLabel). This creates an availability dependency and may not provide adequate separation of duty for sensitive role activation.")
    }

    if ($HasUnknownApproverType) {
        $weaknesses.Add('One or more approvers could not be classified as User or Group from collected evidence. Validate approver object types to confirm accountable approval design.')
    }

    if ($RoleCriticalityTier -like 'Tier0-*' -and $ApproverCount -lt 2) {
        $weaknesses.Add('Tier-0 role has fewer than two approvers configured. Introduce at least two independent approvers for resilience and separation of duty.')
    }

    return @($weaknesses)
}

# ─── RoleElevationPolicy object builder ─────────────────────────────────────────

function Get-RoleElevationPolicy {
    <#
    .SYNOPSIS
    Builds a structured RoleElevationPolicy object from flat policy rules and contextual data.

    Rule ID patterns (from the Microsoft Graph roleManagementPolicy API):
      Enablement_EndUser_Assignment  → MFA, justification, ticketing requirements
      Approval_EndUser_Assignment    → approval and approver configuration
      Expiration_EndUser_Assignment  → maximum activation duration
      Expiration_Admin_Assignment    → whether permanent active assignments are permitted
      Expiration_Admin_Eligibility   → whether permanent eligible assignments are permitted
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RoleName,

        [Parameter(Mandatory)]
        [object[]]$RoleRules,

        [object[]]$RoleAssignmentsForRole,
        [string[]]$RoleUserIds,
        [hashtable]$PrincipalTypeById,
        [string[]]$HighImpactRoles,
        $AccessReviewRoleSet
    )

    # ── Derive assignment context from actual assignment data ─────────────────────
    $roleAsgn             = @($RoleAssignmentsForRole)
    $hasActive            = @($roleAsgn | Where-Object { $_.AssignmentState -eq 'Active'   }).Count -gt 0
    $hasEligible          = @($roleAsgn | Where-Object { $_.AssignmentState -eq 'Eligible' }).Count -gt 0
    $hasPermanentActive   = @($roleAsgn | Where-Object { $_.AssignmentState -eq 'Active'   -and $_.IsPermanent }).Count -gt 0
    $hasPermanentEligible = @($roleAsgn | Where-Object { $_.AssignmentState -eq 'Eligible' -and $_.IsPermanent }).Count -gt 0
    $criticalityTier      = Get-RoleCriticalityTier -RoleName $RoleName -HighImpactRoles $HighImpactRoles
    $isHighImpact         = $criticalityTier -ne 'Standard'

    if ($hasActive -and $hasEligible) { $assignmentTypeLabel = 'Active and Eligible' }
    elseif ($hasActive)               { $assignmentTypeLabel = 'Active only' }
    elseif ($hasEligible)             { $assignmentTypeLabel = 'Eligible only' }
    else                              { $assignmentTypeLabel = 'Unknown' }

    # ── Extract activation control settings from specific rule IDs ────────────────

    $enableRule           = @($RoleRules | Where-Object { $_.RuleId -match 'Enablement_EndUser_Assignment' }) | Select-Object -First 1
    $mfaRequired          = if ($enableRule -and $null -ne $enableRule.RequiresMfa)          { [bool]$enableRule.RequiresMfa }          else { $null }
    $justificationRequired = if ($enableRule -and $null -ne $enableRule.RequiresJustification) { [bool]$enableRule.RequiresJustification } else { $null }
    $ticketingRequired    = if ($enableRule -and $null -ne $enableRule.RequiresTicketInfo)   { [bool]$enableRule.RequiresTicketInfo }   else { $null }

    $approvalRule         = @($RoleRules | Where-Object { $_.RuleId -match 'Approval_EndUser_Assignment' }) | Select-Object -First 1
    $approvalRequired     = if ($approvalRule -and $null -ne $approvalRule.IsApprovalRequired) { [bool]$approvalRule.IsApprovalRequired } else { $false }
    $approverCount        = if ($approvalRule) { [int]$approvalRule.ApproverCount }            else { 0 }
    $approverIds          = if ($approvalRule -and $approvalRule.ApproverIds)          { [string]$approvalRule.ApproverIds }          else { $null }
    $approverDisplayNames = if ($approvalRule -and $approvalRule.ApproverDisplayNames) { [string]$approvalRule.ApproverDisplayNames } else { $null }

    $approverInsights = Get-ApproverInsights `
        -ApproverIds $approverIds `
        -ApproverDisplayNames $approverDisplayNames `
        -PrincipalTypeById $PrincipalTypeById

    $expRule              = @($RoleRules | Where-Object { $_.RuleId -match 'Expiration_EndUser_Assignment' }) | Select-Object -First 1
    $maxDurationIso       = if ($expRule -and $expRule.MaxActivationDuration) { [string]$expRule.MaxActivationDuration } else { $null }
    $maxDurationHours     = if ($maxDurationIso) { Convert-Iso8601DurationToHours -Duration $maxDurationIso } else { $null }

    $adminActiveRule         = @($RoleRules | Where-Object { $_.RuleId -match 'Expiration_Admin_Assignment'  }) | Select-Object -First 1
    $adminEligRule           = @($RoleRules | Where-Object { $_.RuleId -match 'Expiration_Admin_Eligibility' }) | Select-Object -First 1
    $permanentActiveAllowed  = if ($adminActiveRule -and $null -ne $adminActiveRule.PermanentActiveAllowed)  { [bool]$adminActiveRule.PermanentActiveAllowed  } else { $null }
    $permanentEligibleAllowed = if ($adminEligRule  -and $null -ne $adminEligRule.PermanentEligibleAllowed) { [bool]$adminEligRule.PermanentEligibleAllowed } else { $null }

    $approverCount = if ($approvalRequired) { $approverInsights.ApproverCount } else { 0 }
    if (-not $approvalRequired -or $approverCount -eq 0) {
        $approverType = 'None'
    } elseif ($approverInsights.ApproverTypeBreakdown -match 'Groups=0' -and $approverInsights.ApproverTypeBreakdown -match 'Unknown=0') {
        $approverType = 'User'
    } elseif ($approverInsights.ApproverTypeBreakdown -match 'Users=0' -and $approverInsights.ApproverTypeBreakdown -match 'Unknown=0') {
        $approverType = 'Group'
    } else {
        $approverType = 'Mixed'
    }

    # ── Control gap analysis ──────────────────────────────────────────────────────
    $controlGaps = New-Object System.Collections.Generic.List[string]

    if ($null -eq $mfaRequired -or $mfaRequired -eq $false) {
        $controlGaps.Add('MFA not required for activation')
    }
    if (-not $approvalRequired) {
        $controlGaps.Add('No approval required for activation')
    }
    elseif ($approverCount -eq 0) {
        $controlGaps.Add('Approval required but no approvers are configured')
    }
    if ($null -ne $maxDurationHours) {
        if ([double]$maxDurationHours -gt 24) {
            $controlGaps.Add("Activation window is $([Math]::Round($maxDurationHours,1))h - major control weakness (recommend <= 8h for high-impact roles)")
        }
        elseif ([double]$maxDurationHours -gt 8) {
            $controlGaps.Add("Activation window is $([Math]::Round($maxDurationHours,1))h - exceeds recommended 8h threshold")
        }
    }
    if ($null -eq $justificationRequired -or $justificationRequired -eq $false) {
        $controlGaps.Add('Business justification not required for activation')
    }
    if ($hasPermanentActive -and $isHighImpact) {
        $controlGaps.Add('Permanent active assignment exists for this high-impact role (no JIT benefit)')
    }
    if ($hasPermanentEligible -and $isHighImpact) {
        $controlGaps.Add('Permanent eligible assignment exists for this high-impact role (no expiry enforcement)')
    }
    if ($permanentActiveAllowed -eq $true) {
        $controlGaps.Add('Role policy permits permanent active assignments (no enforced expiry)')
    }
    if ($permanentEligibleAllowed -eq $true) {
        $controlGaps.Add('Role policy permits permanent eligible assignments (no enforced expiry)')
    }

    $normalizedRoleName = Get-NormalizedRoleName -RoleName $RoleName
    $reviewsEnabled = ($null -ne $AccessReviewRoleSet) -and $AccessReviewRoleSet.Contains($normalizedRoleName)
    if ($isHighImpact -and -not $reviewsEnabled) {
        $controlGaps.Add('No active access review coverage detected for this high-impact role')
    }

    if ($isHighImpact -and ($null -eq $ticketingRequired -or $ticketingRequired -eq $false)) {
        $controlGaps.Add('Ticketing/case reference is not required for high-impact role activation')
    }

    # ── Governance weakness detection ─────────────────────────────────────────────
    $govWeaknesses = Test-ApprovalGovernanceWeakness `
        -ApprovalRequired     $approvalRequired `
        -ApproverCount        $approverCount `
        -ApproverDisplayNames ([string]$approverInsights.ApproverDisplayNames) `
        -ApproverIds          ([string]$approverInsights.ApproverIds) `
        -RoleUserIds          $RoleUserIds `
        -HasUnknownApproverType $approverInsights.HasUnknownApproverType `
        -RoleCriticalityTier  $criticalityTier

    # ── Derived scores and labels ─────────────────────────────────────────────────
    $frictionScore = Get-ElevationFrictionScore `
        -MfaRequired               ([bool]$mfaRequired) `
        -ApprovalRequired          $approvalRequired `
        -ApproverCount             $approverCount `
        -MaxActivationDurationHours $maxDurationHours `
        -JustificationRequired     ([bool]$justificationRequired)

    $maturityLabel = Get-ControlMaturityLabel -FrictionScore $frictionScore

    $riskRating = Get-RoleControlRiskRating `
        -RoleCriticalityTier          $criticalityTier `
        -MfaRequired                  ([bool]$mfaRequired) `
        -ApprovalRequired             $approvalRequired `
        -ApproverCount                $approverCount `
        -HasPermanentActiveAssignment $hasPermanentActive `
        -HasPermanentEligibleAssignment $hasPermanentEligible `
        -MaxActivationDurationHours   $maxDurationHours `
        -AccessReviewsEnabled         $reviewsEnabled `
        -GovernanceWeaknessCount      @($govWeaknesses).Count `
        -TicketingRequired            ([bool]$ticketingRequired)

    # Compact risk rationale from the first three detected gaps
    $controlStrength = Get-ControlStrength `
        -MfaRequired                    ([bool]$mfaRequired) `
        -ApprovalRequired               $approvalRequired `
        -ApproverCount                  $approverCount `
        -MaxActivationDurationHours     $maxDurationHours `
        -HasPermanentEligibleAssignment $hasPermanentEligible `
        -HasPermanentActiveAssignment   $hasPermanentActive `
        -RoleCriticalityTier            $criticalityTier

    $approvalModelStrength = Get-ApprovalModelStrength `
        -ApprovalRequired       $approvalRequired `
        -ApproverCount          $approverCount `
        -HasUnknownApproverType $approverInsights.HasUnknownApproverType `
        -GovernanceWeaknesses   @($govWeaknesses) `
        -RoleCriticalityTier    $criticalityTier

    $rationaleItems = @($controlGaps | Select-Object -First 3)
    $riskRationale  = if ($rationaleItems.Count -gt 0) { $rationaleItems -join '. ' } else { 'No significant control gaps detected.' }

    return [pscustomobject]@{
        RoleName                       = $RoleName
        IsHighImpact                   = $isHighImpact
        RoleCriticalityTier            = $criticalityTier
        AssignmentTypes                = $assignmentTypeLabel
        HasPermanentActiveAssignment   = $hasPermanentActive
        HasPermanentEligibleAssignment = $hasPermanentEligible
        MaxActivationDurationHours     = $maxDurationHours
        MfaRequired                    = $mfaRequired
        ApprovalRequired               = $approvalRequired
        ApproverCount                  = $approverCount
        ApproverType                   = $approverType
        ApproverTypeBreakdown          = $approverInsights.ApproverTypeBreakdown
        ApproverDisplayNames           = $approverInsights.ApproverDisplayNames
        ApproverDetails                = $approverInsights.ApproverDetails
        JustificationRequired          = $justificationRequired
        TicketingRequired              = $ticketingRequired
        PermanentActiveAllowed         = $permanentActiveAllowed
        PermanentEligibleAllowed       = $permanentEligibleAllowed
        AccessReviewsEnabled           = $reviewsEnabled
        ElevationFrictionScore         = $frictionScore
        ControlMaturityLabel           = $maturityLabel
        ControlStrength                = $controlStrength
        ApprovalModelStrength          = $approvalModelStrength
        ControlGaps                    = ($controlGaps -join '; ')
        GovernanceWeaknesses           = ($govWeaknesses -join '; ')
        RiskRating                     = $riskRating
        RiskRationale                  = $riskRationale
        ApprovalIntegrity              = 'Unknown'
        GroupType                      = $null
    }
}

# ─── Matrix builder ─────────────────────────────────────────────────────────────

function New-RoleElevationMatrix {
    [CmdletBinding()]
    param(
        [object[]]$PolicyRules,
        [object[]]$RoleAssignments,
        [object[]]$AccessReviews,
        [string[]]$HighImpactRoles
    )

    Write-PimLog -Message 'Building Privileged Role Elevation Control Matrix.'

    $accessReviewRoleSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($review in @($AccessReviews)) {
        $candidate = if ($review.ReviewedRoleName) { [string]$review.ReviewedRoleName } elseif ($review.RoleName) { [string]$review.RoleName } else { $null }
        $normalized = Get-NormalizedRoleName -RoleName $candidate
        if (-not [string]::IsNullOrWhiteSpace($normalized)) {
            [void]$accessReviewRoleSet.Add($normalized)
        }
    }

    $assignmentsByRole = @{}
    $roleUserIdsByRole = @{}
    $principalTypeById = @{}

    foreach ($assignment in @($RoleAssignments)) {
        if (-not $assignment) { continue }
        $roleName = if ($assignment.RoleDisplayName) { [string]$assignment.RoleDisplayName } else { '' }
        if ([string]::IsNullOrWhiteSpace($roleName)) { continue }

        if (-not $assignmentsByRole.ContainsKey($roleName)) {
            $assignmentsByRole[$roleName] = [System.Collections.Generic.List[object]]::new()
        }
        $assignmentsByRole[$roleName].Add($assignment)

        if ($assignment.PrincipalId -and $assignment.PrincipalType) {
            $principalTypeById[[string]$assignment.PrincipalId] = [string]$assignment.PrincipalType
        }

        if ($assignment.PrincipalType -eq 'User' -and $assignment.PrincipalId) {
            if (-not $roleUserIdsByRole.ContainsKey($roleName)) {
                $roleUserIdsByRole[$roleName] = [System.Collections.Generic.List[string]]::new()
            }
            $roleUserIdsByRole[$roleName].Add([string]$assignment.PrincipalId)
        }
    }

    $rulesByRole = @($PolicyRules | Group-Object -Property RoleName)
    $matrix      = New-Object System.Collections.Generic.List[object]

    foreach ($roleGroup in $rulesByRole) {
        $roleName = $roleGroup.Name
        if ([string]::IsNullOrWhiteSpace($roleName)) { continue }

        try {
            $roleAsgnForRole    = @(if ($assignmentsByRole.ContainsKey($roleName))    { $assignmentsByRole[$roleName] })
            $roleUserIdsForRole = @(if ($roleUserIdsByRole.ContainsKey($roleName))    { $roleUserIdsByRole[$roleName] })
            $policy = Get-RoleElevationPolicy `
                -RoleName               $roleName `
                -RoleRules              @($roleGroup.Group) `
                -RoleAssignmentsForRole $roleAsgnForRole `
                -RoleUserIds            $roleUserIdsForRole `
                -PrincipalTypeById      $principalTypeById `
                -HighImpactRoles        $HighImpactRoles `
                -AccessReviewRoleSet    $accessReviewRoleSet

            $matrix.Add($policy)
        }
        catch {
            Write-PimLog -Level WARN -Message "Failed to build elevation policy for role '$roleName': $($_.Exception.Message) | Stack: $($_.ScriptStackTrace)"
        }
    }

    # Sort: Critical → High → Medium → Low, then alphabetically within each band
    $sortOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $sorted    = @(
        $matrix |
        Sort-Object -Property @{
            Expression = { if ($sortOrder.ContainsKey($_.RiskRating)) { $sortOrder[$_.RiskRating] } else { 99 } }
            Ascending  = $true
        }, RoleName
    )

    Write-PimLog -Message "Role Elevation Matrix built: $($sorted.Count) roles analysed."
    return $sorted
}

# ─── Correlated findings integration ────────────────────────────────────────────

function Add-RoleControlFindings {
    <#
    .SYNOPSIS
    Derives structured findings from the elevation control matrix and appends them
    to the provided FindingsList. Cross-references access path data to produce
    correlated exposure + control weakness findings.

    Designed to be called from Build-PimReviewWorkbook so that matrix-derived signals
    are included in the consolidated findings set alongside standard assignment findings.
    #>
    [CmdletBinding()]
    param(
        [object[]]$RoleElevationMatrix,
        [object[]]$UserAccessPaths,
        [string[]]$HighImpactRoles,
        [System.Collections.Generic.List[object]]$FindingsList
    )

    foreach ($policy in @($RoleElevationMatrix)) {
        $rating = $policy.RiskRating

        # ── Critical elevation control gap ────────────────────────────────────────
        if ($rating -eq 'Critical') {
            $FindingsList.Add([pscustomobject]@{
                FindingType = 'Critical Elevation Control Gap'
                RiskRating  = 'High'
                Subject     = $policy.RoleName
                RoleName    = $policy.RoleName
                Details     = "High-impact role '$($policy.RoleName)' has an elevation friction score of $($policy.ElevationFrictionScore)/100 ($($policy.ControlMaturityLabel)). Neither MFA nor approval is required for activation. PIM is deployed but provides no effective access governance for this role."
                EvidenceId  = "ElevationMatrix_$($policy.RoleName)"
            })
        }

        # ── Correlated: group-path exposure combined with activation control weakness
        if ($policy.IsHighImpact -and $rating -in 'Critical', 'High' -and -not [string]::IsNullOrWhiteSpace($policy.ControlGaps)) {
            $groupUserCount = @(
                $UserAccessPaths |
                Where-Object { $_.RoleName -eq $policy.RoleName -and $_.AccessPathType -eq 'GroupInherited' } |
                Select-Object -ExpandProperty UserId -Unique
            ).Count

            if ($groupUserCount -gt 0) {
                $gapPreview = ($policy.ControlGaps -split '; ' | Select-Object -First 2) -join '; '
                $FindingsList.Add([pscustomobject]@{
                    FindingType = 'Correlated: Group Exposure With Elevation Control Weakness'
                    RiskRating  = 'High'
                    Subject     = $policy.RoleName
                    RoleName    = $policy.RoleName
                    Details     = "$($policy.RoleName) is reachable by $groupUserCount user(s) via group membership. Elevation policy has gaps: $gapPreview. Group-inherited access bypasses direct-assignment approval gates, amplifying the control weakness."
                    EvidenceId  = "ElevationMatrix_$($policy.RoleName)"
                })
            }
        }

        # ── Approval configured but no approvers defined ──────────────────────────
        if ($policy.ApprovalRequired -eq $true -and $policy.ApproverCount -eq 0) {
            $FindingsList.Add([pscustomobject]@{
                FindingType = 'Approval Configured Without Approvers'
                RiskRating  = 'High'
                Subject     = $policy.RoleName
                RoleName    = $policy.RoleName
                Details     = "Role '$($policy.RoleName)' requires approval for activation but no approvers are defined. Activations may be permanently blocked or silently granted depending on Entra ID evaluation behaviour."
                EvidenceId  = "ElevationMatrix_$($policy.RoleName)"
            })
        }

        if ($policy.IsHighImpact -and -not $policy.AccessReviewsEnabled) {
            $FindingsList.Add([pscustomobject]@{
                FindingType = 'High-Impact Role Missing Access Review Coverage'
                RiskRating  = if ($policy.RoleCriticalityTier -like 'Tier0-*') { 'High' } else { 'Medium' }
                Subject     = $policy.RoleName
                RoleName    = $policy.RoleName
                Details     = "High-impact role '$($policy.RoleName)' has no active access review evidence in scope. Introduce periodic review campaigns for all standing and eligible assignments to this role."
                EvidenceId  = "ElevationMatrix_$($policy.RoleName)"
            })
        }

        if ($policy.RoleCriticalityTier -like 'Tier0-*' -and $policy.ApprovalRequired -and $policy.ApproverCount -eq 1) {
            $FindingsList.Add([pscustomobject]@{
                FindingType = 'Tier-0 Role Has Single Approver'
                RiskRating  = 'High'
                Subject     = $policy.RoleName
                RoleName    = $policy.RoleName
                Details     = "Tier-0 role '$($policy.RoleName)' is configured with a single approver. This creates a governance bottleneck and weakens resilience and separation of duties."
                EvidenceId  = "ElevationMatrix_$($policy.RoleName)"
            })
        }

        # ── Governance weaknesses flagged ─────────────────────────────────────────
        if (-not [string]::IsNullOrWhiteSpace($policy.GovernanceWeaknesses)) {
            $FindingsList.Add([pscustomobject]@{
                FindingType = 'Approval Governance Weakness'
                RiskRating  = 'Medium'
                Subject     = $policy.RoleName
                RoleName    = $policy.RoleName
                Details     = "Approval governance concern for '$($policy.RoleName)': $($policy.GovernanceWeaknesses)"
                EvidenceId  = "ElevationMatrix_$($policy.RoleName)"
            })
        }

        # ── Role is effectively uncontrolled despite being in PIM ─────────────────
        if ($policy.ElevationFrictionScore -lt 20 -and ($policy.HasPermanentActiveAssignment -or $policy.HasPermanentEligibleAssignment)) {
            $FindingsList.Add([pscustomobject]@{
                FindingType = 'Role Is Effectively Uncontrolled In PIM'
                RiskRating  = if ($policy.IsHighImpact) { 'High' } else { 'Medium' }
                Subject     = $policy.RoleName
                RoleName    = $policy.RoleName
                Details     = "Role '$($policy.RoleName)' has a friction score of $($policy.ElevationFrictionScore)/100 ($($policy.ControlMaturityLabel)) with permanent assignments in place. Inclusion in PIM provides minimal access governance benefit in its current configuration."
                EvidenceId  = "ElevationMatrix_$($policy.RoleName)"
            })
        }
    }
}

function ConvertTo-RoleElevationMatrixExportRows {
    [CmdletBinding()]
    param([object[]]$RoleElevationMatrix)

    return @(
        foreach ($row in @($RoleElevationMatrix)) {
            [pscustomobject]@{
                RoleName                       = $row.RoleName
                RoleCriticalityTier            = $row.RoleCriticalityTier
                RiskRating                     = $row.RiskRating
                ControlMaturityLabel           = $row.ControlMaturityLabel
                ControlStrength                = $row.ControlStrength
                ApprovalModelStrength          = $row.ApprovalModelStrength
                ElevationFrictionScore         = $row.ElevationFrictionScore
                AssignmentTypes                = $row.AssignmentTypes
                MaxActivationDurationHours     = $row.MaxActivationDurationHours
                MfaRequired                    = $row.MfaRequired
                ApprovalRequired               = $row.ApprovalRequired
                ApproverCount                  = $row.ApproverCount
                ApproverType                   = $row.ApproverType
                ApproverTypeBreakdown          = $row.ApproverTypeBreakdown
                ApproverDisplayNames           = $row.ApproverDisplayNames
                ApproverDetails                = $row.ApproverDetails
                JustificationRequired          = $row.JustificationRequired
                TicketingRequired              = $row.TicketingRequired
                AccessReviewsEnabled           = $row.AccessReviewsEnabled
                HasPermanentActiveAssignment   = $row.HasPermanentActiveAssignment
                HasPermanentEligibleAssignment = $row.HasPermanentEligibleAssignment
                PermanentActiveAllowed         = $row.PermanentActiveAllowed
                PermanentEligibleAllowed       = $row.PermanentEligibleAllowed
                ControlGaps                    = $row.ControlGaps
                GovernanceWeaknesses           = $row.GovernanceWeaknesses
                RiskRationale                  = $row.RiskRationale
                ApprovalIntegrity              = if ($null -ne $row.PSObject.Properties['ApprovalIntegrity']) { $row.ApprovalIntegrity } else { 'Unknown' }
                GroupType                      = if ($null -ne $row.PSObject.Properties['GroupType'])         { $row.GroupType }         else { $null }
            }
        }
    )
}

# ─── Main exported function ─────────────────────────────────────────────────────

function Get-PimRoleElevationMatrix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$PolicyRules,

        [Parameter(Mandatory)]
        [object[]]$RoleAssignments,

        [Parameter(Mandatory)]
        [object[]]$AccessReviews,

        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$ReturnObjectsOnly
    )

    $highImpactRoles = @($Config.HighImpactRoles)

    $matrix = New-RoleElevationMatrix `
        -PolicyRules     $PolicyRules `
        -RoleAssignments $RoleAssignments `
        -AccessReviews   $AccessReviews `
        -HighImpactRoles $highImpactRoles

    if (-not $ReturnObjectsOnly -and -not [string]::IsNullOrWhiteSpace($OutputFolder)) {
        $csvPath = Join-Path -Path $OutputFolder -ChildPath 'RoleElevationMatrix.csv'
        Export-PimData -Data $matrix -CsvPath $csvPath
        Write-PimLog -Message "Exported Role Elevation Matrix: $csvPath"
    }

    return $matrix
}

# ─── Script entry point ─────────────────────────────────────────────────────────

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimRoleElevationMatrix @PSBoundParameters
}
