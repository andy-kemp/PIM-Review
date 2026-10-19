<#
.SYNOPSIS
Builds the PIM review workbook and derived findings from exported datasets.

.DESCRIPTION
Creates a single Excel workbook with multiple review sheets using ImportExcel when available.
If ImportExcel is unavailable, leaves CSV outputs in place and logs a warning.
This script is intended to be dot-sourced by Invoke-FullPimReview.ps1.

.EXAMPLE
./Build-PimReviewWorkbook.ps1 -Data $data -Config $config -OutputFolder .\Output -Verbose
#>

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

function New-PimFindings {
    [CmdletBinding()]
    param(
        [object[]]$RoleAssignments,
        [object[]]$PolicyRules,
        [object[]]$PrivilegedGroups,
        [object[]]$GroupMembers,
        [object[]]$UserLicenses,
        [hashtable]$Config
    )

    $findings = New-Object System.Collections.Generic.List[object]

    $durationThresholdHours = [double]$Config.LongActivationThresholdHours
    $highImpactRoles = @($Config.HighImpactRoles)
    $expectedLicenseSkuPartNumbers = @($Config.ExpectedLicenseSkuPartNumbers)

    foreach ($row in @($RoleAssignments | Where-Object { $_.AssignmentState -eq 'Active' -and $_.IsPermanent })) {
        $risk = if ($row.RoleDisplayName -in $highImpactRoles) { 'High' } else { 'Medium' }
        $findings.Add([pscustomobject]@{
            FindingType    = 'Permanently Active Assignment'
            RiskRating     = $risk
            Subject        = $row.PrincipalDisplayName
            RoleName       = $row.RoleDisplayName
            Details        = 'Active privileged role assignment has no end date.'
            EvidenceId     = $row.AssignmentId
        })
    }

    foreach ($row in @($RoleAssignments | Where-Object { $_.AssignmentState -eq 'Eligible' -and $_.IsPermanent })) {
        $risk = if ($row.RoleDisplayName -in $highImpactRoles) { 'High' } else { 'Medium' }
        $findings.Add([pscustomobject]@{
            FindingType    = 'Permanently Eligible Assignment'
            RiskRating     = $risk
            Subject        = $row.PrincipalDisplayName
            RoleName       = $row.RoleDisplayName
            Details        = 'Eligible privileged role assignment has no end date.'
            EvidenceId     = $row.AssignmentId
        })
    }

    $rolePolicyGroups = $PolicyRules | Group-Object -Property RoleName
    foreach ($group in $rolePolicyGroups) {
        $roleName = $group.Name
        $rules = @($group.Group)

        $approvalRequired = ($rules | Where-Object { $_.IsApprovalRequired -eq $true }).Count -gt 0
        if (-not $approvalRequired) {
            $risk = if ($roleName -in $highImpactRoles) { 'High' } else { 'Medium' }
            $findings.Add([pscustomobject]@{
                FindingType = 'Role Has No Approval Requirement'
                RiskRating  = $risk
                Subject     = $roleName
                RoleName    = $roleName
                Details     = 'No approval requirement identified in role policy rules.'
                EvidenceId  = ($rules[0].PolicyId)
            })
        }

        $maxDurations = @($rules | Where-Object { $_.MaxActivationDuration } | ForEach-Object { Convert-Iso8601DurationToHours -Duration $_.MaxActivationDuration } | Where-Object { $_ -ne $null })
        if ($maxDurations.Count -gt 0) {
            $maxHours = ($maxDurations | Measure-Object -Maximum).Maximum
            if ($maxHours -gt $durationThresholdHours) {
                $findings.Add([pscustomobject]@{
                    FindingType = 'Role Has Long Activation Duration'
                    RiskRating  = 'Medium'
                    Subject     = $roleName
                    RoleName    = $roleName
                    Details     = "Max activation duration is ${maxHours}h, above threshold ${durationThresholdHours}h."
                    EvidenceId  = ($rules[0].PolicyId)
                })
            }
        }

        $noMfa = ($rules | Where-Object { $_.RequiresMfa -eq $false }).Count -gt 0
        if ($noMfa) {
            $risk = if ($roleName -in $highImpactRoles) { 'High' } else { 'Medium' }
            $findings.Add([pscustomobject]@{
                FindingType = 'Role Policy Does Not Require MFA'
                RiskRating  = $risk
                Subject     = $roleName
                RoleName    = $roleName
                Details     = 'At least one role policy rule indicates MFA is not required.'
                EvidenceId  = ($rules[0].PolicyId)
            })
        }

        $noJustification = ($rules | Where-Object { $_.RequiresJustification -eq $false }).Count -gt 0
        if ($noJustification) {
            $findings.Add([pscustomobject]@{
                FindingType = 'Role Policy Does Not Require Justification'
                RiskRating  = 'Medium'
                Subject     = $roleName
                RoleName    = $roleName
                Details     = 'At least one role policy rule indicates justification is not required.'
                EvidenceId  = ($rules[0].PolicyId)
            })
        }
    }

    foreach ($group in $PrivilegedGroups) {
        $roles = @(($group.DistinctRolesHeld -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $intersect = @($roles | Where-Object { $_ -in $highImpactRoles })
        if ($intersect.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                FindingType = 'Group Holds High-Impact Roles'
                RiskRating  = 'High'
                Subject     = $group.GroupDisplayName
                RoleName    = ($intersect -join '; ')
                Details     = 'Privileged group is assigned one or more high-impact roles.'
                EvidenceId  = $group.GroupId
            })
        }
    }

    $highImpactGroupIds = @(
        $PrivilegedGroups |
        Where-Object {
            @((($_.DistinctRolesHeld -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -in $highImpactRoles })).Count -gt 0
        } |
        Select-Object -ExpandProperty GroupId
    )

    foreach ($member in @($GroupMembers | Where-Object { $_.MemberType -eq 'User' -and $_.SourceGroupId -in $highImpactGroupIds })) {
        $findings.Add([pscustomobject]@{
            FindingType = 'User Has High-Impact Access Through Group'
            RiskRating  = 'High'
            Subject     = $member.MemberDisplayName
            RoleName    = 'Inherited via group'
            Details     = "User receives privileged access through group $($member.SourceGroupDisplayName)."
            EvidenceId  = $member.MemberId
        })
    }

    foreach ($sp in @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'ServicePrincipal' })) {
        $risk = if ($sp.RoleDisplayName -in $highImpactRoles) { 'High' } else { 'Medium' }
        $findings.Add([pscustomobject]@{
            FindingType = 'Service Principal Has Privileged Role'
            RiskRating  = $risk
            Subject     = $sp.PrincipalDisplayName
            RoleName    = $sp.RoleDisplayName
            Details     = 'Service principal has privileged role assignment.'
            EvidenceId  = $sp.AssignmentId
        })
    }

    foreach ($acct in @($RoleAssignments | Where-Object { ($_.PrincipalDisplayName -match 'break\s*glass') -or ($_.PrincipalDisplayName -match 'emergency') })) {
        $findings.Add([pscustomobject]@{
            FindingType = 'Break Glass Account Detected'
            RiskRating  = 'High'
            Subject     = $acct.PrincipalDisplayName
            RoleName    = $acct.RoleDisplayName
            Details     = 'Break glass or emergency account detected in privileged assignment path.'
            EvidenceId  = $acct.AssignmentId
        })
    }

    if ($expectedLicenseSkuPartNumbers.Count -gt 0) {
        foreach ($user in @($UserLicenses | Where-Object { $_.UserId })) {
            $skuParts = @(($user.SkuPartNumbers -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $matchesExpected = @($skuParts | Where-Object { $_ -in $expectedLicenseSkuPartNumbers }).Count -gt 0
            if (-not $matchesExpected) {
                $findings.Add([pscustomobject]@{
                    FindingType = 'User Missing Expected License'
                    RiskRating  = 'Low'
                    Subject     = $user.DisplayName
                    RoleName    = 'N/A'
                    Details     = 'User does not have expected license SKUs from configured baseline.'
                    EvidenceId  = $user.UserId
                })
            }
        }
    }

    return @($findings | Sort-Object -Property RiskRating, FindingType, Subject -Unique)
}

function New-SummaryRows {
    [CmdletBinding()]
    param(
        [object]$RoleAssignments,
        [object]$PolicyRules,
        [object]$PrivilegedGroups,
        [object]$GroupMembers
    )

    $RoleAssignments = @($RoleAssignments)
    $PolicyRules = @($PolicyRules)
    $PrivilegedGroups = @($PrivilegedGroups)
    $GroupMembers = @($GroupMembers)

    $activeAssignments = @($RoleAssignments | Where-Object { $_.AssignmentState -eq 'Active' })
    $eligibleAssignments = @($RoleAssignments | Where-Object { $_.AssignmentState -eq 'Eligible' })

    $distinctRoles = @($RoleAssignments.RoleDisplayName | Where-Object { $_ } | Select-Object -Unique)
    $distinctGroups = @($PrivilegedGroups.GroupId | Where-Object { $_ } | Select-Object -Unique)
    $directUsers = @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty PrincipalId -Unique)
    $groupIndirectUsers = @($GroupMembers | Where-Object { $_.MemberType -eq 'User' } | Select-Object -ExpandProperty MemberId -Unique)

    $permActiveCount = @($activeAssignments | Where-Object { $_.IsPermanent }).Count
    $permEligibleCount = @($eligibleAssignments | Where-Object { $_.IsPermanent }).Count

    $rolesRequiringApproval = @($PolicyRules | Where-Object { $_.IsApprovalRequired -eq $true } | Select-Object -ExpandProperty RoleName -Unique)
    $rolesNoApproval = @($distinctRoles | Where-Object { $_ -notin $rolesRequiringApproval })

    $topRoles = @(
        $RoleAssignments |
        Group-Object -Property RoleDisplayName |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10
    )

    $topGroups = @(
        $PrivilegedGroups |
        Sort-Object -Property DistinctRoleCount -Descending |
        Select-Object -First 10
    )

    $rows = @()
    $rows += [pscustomobject]@{ Metric = 'Total active assignments'; Value = $activeAssignments.Count }
    $rows += [pscustomobject]@{ Metric = 'Total eligible assignments'; Value = $eligibleAssignments.Count }
    $rows += [pscustomobject]@{ Metric = 'Count of distinct roles'; Value = $distinctRoles.Count }
    $rows += [pscustomobject]@{ Metric = 'Count of distinct privileged groups'; Value = $distinctGroups.Count }
    $rows += [pscustomobject]@{ Metric = 'Count of direct user assignments'; Value = $directUsers.Count }
    $rows += [pscustomobject]@{ Metric = 'Count of group-based indirect paths'; Value = $groupIndirectUsers.Count }
    $rows += [pscustomobject]@{ Metric = 'Count of permanently active assignments'; Value = $permActiveCount }
    $rows += [pscustomobject]@{ Metric = 'Count of permanently eligible assignments'; Value = $permEligibleCount }
    $rows += [pscustomobject]@{ Metric = 'Count of roles requiring approval'; Value = $rolesRequiringApproval.Count }
    $rows += [pscustomobject]@{ Metric = 'Count of roles not requiring approval'; Value = $rolesNoApproval.Count }

    foreach ($role in $topRoles) {
        $rows += [pscustomobject]@{ Metric = "Top role by principals: $($role.Name)"; Value = $role.Count }
    }

    foreach ($group in $topGroups) {
        $rows += [pscustomobject]@{ Metric = "Top group by privileged roles: $($group.GroupDisplayName)"; Value = $group.DistinctRoleCount }
    }

    return @($rows)
}

function Get-PrincipalCategory {
    [CmdletBinding()]
    param(
        [string]$UserType,
        [string]$UserPrincipalName
    )

    if (-not [string]::IsNullOrWhiteSpace($UserType)) {
        if ($UserType -ieq 'Guest') {
            return 'Guest'
        }

        if ($UserType -ieq 'Member') {
            return 'Member'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName) -and $UserPrincipalName -match '#EXT#') {
        return 'Guest'
    }

    return 'Unknown'
}

function Get-AccessPathRisk {
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [string]$AssignmentState,
        [bool]$IsPermanent,
        [string]$UserCategory,
        [string]$AccessPathType,
        [string[]]$HighImpactRoles
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $riskScore = 0

    if ($RoleName -in $HighImpactRoles) {
        $riskScore += 3
        $reasons.Add('High-impact privileged role')
    }

    if ($AssignmentState -eq 'Active') {
        $riskScore += 2
        $reasons.Add('Role is currently Active')
    }
    elseif ($AssignmentState -eq 'Eligible') {
        $riskScore += 1
        $reasons.Add('Role is Eligible (can be activated)')
    }

    if ($IsPermanent) {
        $riskScore += 2
        $reasons.Add('No assignment end date (permanent)')
    }

    if ($UserCategory -eq 'Guest') {
        $riskScore += 2
        $reasons.Add('External guest identity')
    }

    if ($AccessPathType -eq 'GroupInherited') {
        $riskScore += 1
        $reasons.Add('Inherited through group membership')
    }

    $riskRating = if ($riskScore -ge 6) {
        'High'
    }
    elseif ($riskScore -ge 3) {
        'Medium'
    }
    else {
        'Low'
    }

    return [pscustomobject]@{
        RiskRating = $riskRating
        RiskReason = ($reasons -join '; ')
    }
}

function New-UserAccessPaths {
    [CmdletBinding()]
    param(
        [object[]]$RoleAssignments,
        [object[]]$GroupMembers,
        [string[]]$HighImpactRoles
    )

    $rows = @()
    $groupAssignments = @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' -and $_.PrincipalId })

    foreach ($assignment in @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'User' -and $_.PrincipalId })) {
        $principalCategory = Get-PrincipalCategory -UserType $assignment.PrincipalUserType -UserPrincipalName $assignment.PrincipalUserPrincipalName
        $risk = Get-AccessPathRisk `
            -RoleName $assignment.RoleDisplayName `
            -AssignmentState $assignment.AssignmentState `
            -IsPermanent $assignment.IsPermanent `
            -UserCategory $principalCategory `
            -AccessPathType 'Direct' `
            -HighImpactRoles $HighImpactRoles

        $rows += [pscustomobject]@{
            UserId                 = $assignment.PrincipalId
            UserDisplayName        = $assignment.PrincipalDisplayName
            UserPrincipalName      = $assignment.PrincipalUserPrincipalName
            UserCategory           = $principalCategory
            AccessPathType         = 'Direct'
            SourceGroupId          = $null
            SourceGroupDisplayName = $null
            RoleName               = $assignment.RoleDisplayName
            AssignmentState        = $assignment.AssignmentState
            IsPermanent            = $assignment.IsPermanent
            RoleAssignmentId       = $assignment.AssignmentId
            AccessRiskRating       = $risk.RiskRating
            AccessRiskReason       = $risk.RiskReason
            EvidencePath           = "Direct assignment to role $($assignment.RoleDisplayName)."
        }
    }

    foreach ($member in @($GroupMembers | Where-Object { $_.MemberType -eq 'User' -and $_.SourceGroupId })) {
        $assignmentsForGroup = @($groupAssignments | Where-Object { $_.PrincipalId -eq $member.SourceGroupId })
        if ($assignmentsForGroup.Count -eq 0) {
            continue
        }

        $principalCategory = Get-PrincipalCategory -UserType $member.MemberUserType -UserPrincipalName $member.MemberUserPrincipalName
        foreach ($assignment in $assignmentsForGroup) {
            $risk = Get-AccessPathRisk `
                -RoleName $assignment.RoleDisplayName `
                -AssignmentState $assignment.AssignmentState `
                -IsPermanent $assignment.IsPermanent `
                -UserCategory $principalCategory `
                -AccessPathType 'GroupInherited' `
                -HighImpactRoles $HighImpactRoles

            $rows += [pscustomobject]@{
                UserId                 = $member.MemberId
                UserDisplayName        = $member.MemberDisplayName
                UserPrincipalName      = $member.MemberUserPrincipalName
                UserCategory           = $principalCategory
                AccessPathType         = 'GroupInherited'
                SourceGroupId          = $member.SourceGroupId
                SourceGroupDisplayName = $member.SourceGroupDisplayName
                RoleName               = $assignment.RoleDisplayName
                AssignmentState        = $assignment.AssignmentState
                IsPermanent            = $assignment.IsPermanent
                RoleAssignmentId       = $assignment.AssignmentId
                AccessRiskRating       = $risk.RiskRating
                AccessRiskReason       = $risk.RiskReason
                EvidencePath           = "Member of group $($member.SourceGroupDisplayName), group assigned to role $($assignment.RoleDisplayName)."
            }
        }
    }

    return @($rows | Sort-Object -Property UserDisplayName, RoleName, AccessPathType, SourceGroupDisplayName -Unique)
}

function New-UserRoleSummary {
    [CmdletBinding()]
    param(
        [object[]]$UserAccessPaths
    )

    $rows = @()
    $byUser = @($UserAccessPaths | Group-Object -Property UserId)

    foreach ($grp in $byUser) {
        $userRows = @($grp.Group)
        if ($userRows.Count -eq 0) {
            continue
        }

        $first = $userRows[0]
        $directRoles = @($userRows | Where-Object { $_.AccessPathType -eq 'Direct' } | Select-Object -ExpandProperty RoleName -Unique)
        $inheritedRoles = @($userRows | Where-Object { $_.AccessPathType -eq 'GroupInherited' } | Select-Object -ExpandProperty RoleName -Unique)
        $sourceGroups = @($userRows | Where-Object { $_.SourceGroupDisplayName } | Select-Object -ExpandProperty SourceGroupDisplayName -Unique)
        $allRoles = @($userRows | Select-Object -ExpandProperty RoleName -Unique)

        $maxRisk = 'Low'
        if (@($userRows | Where-Object { $_.AccessRiskRating -eq 'High' }).Count -gt 0) {
            $maxRisk = 'High'
        }
        elseif (@($userRows | Where-Object { $_.AccessRiskRating -eq 'Medium' }).Count -gt 0) {
            $maxRisk = 'Medium'
        }

        $riskReasons = @($userRows | Select-Object -ExpandProperty AccessRiskReason -Unique)

        $rows += [pscustomobject]@{
            UserId                    = $first.UserId
            UserDisplayName           = $first.UserDisplayName
            UserPrincipalName         = $first.UserPrincipalName
            UserCategory              = $first.UserCategory
            TotalDistinctRoles        = $allRoles.Count
            DirectRoleCount           = $directRoles.Count
            GroupInheritedRoleCount   = $inheritedRoles.Count
            SourceGroupCount          = $sourceGroups.Count
            DirectRoles               = ($directRoles -join '; ')
            GroupInheritedRoles       = ($inheritedRoles -join '; ')
            SourceGroups              = ($sourceGroups -join '; ')
            MaxRiskRating             = $maxRisk
            RiskWhy                   = ($riskReasons -join '; ')
        }
    }

    return @($rows | Sort-Object -Property MaxRiskRating, TotalDistinctRoles, UserDisplayName -Descending)
}

function New-GroupRoleSummary {
    [CmdletBinding()]
    param(
        [object[]]$PrivilegedGroups,
        [object[]]$RoleAssignments,
        [object[]]$GroupMembers,
        [string[]]$HighImpactRoles
    )

    $rows = @()
    $groupAssignments = @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'Group' -and $_.PrincipalId })

    foreach ($group in @($PrivilegedGroups)) {
        $groupId = $group.GroupId
        $roles = @($groupAssignments | Where-Object { $_.PrincipalId -eq $groupId } | Select-Object -ExpandProperty RoleDisplayName -Unique)
        $highImpact = @($roles | Where-Object { $_ -in $HighImpactRoles })
        $memberUsers = @($GroupMembers | Where-Object { $_.SourceGroupId -eq $groupId -and $_.MemberType -eq 'User' } | Select-Object -ExpandProperty MemberId -Unique)
        $memberGuests = @($GroupMembers | Where-Object { $_.SourceGroupId -eq $groupId -and $_.MemberType -eq 'User' -and $_.MemberUserType -eq 'Guest' } | Select-Object -ExpandProperty MemberId -Unique)
        $memberNestedGroups = @($GroupMembers | Where-Object { $_.SourceGroupId -eq $groupId -and $_.MemberType -eq 'Group' } | Select-Object -ExpandProperty MemberId -Unique)

        # Check if this group's role set contains any SoD conflict pairs (SoD embedded in group design)
        $groupSodPairs = @(
            @{ A = 'Privileged Role Administrator';         B = 'Conditional Access Administrator' },
            @{ A = 'Global Administrator';                  B = 'Privileged Role Administrator' },
            @{ A = 'Global Administrator';                  B = 'Security Administrator' },
            @{ A = 'Privileged Role Administrator';         B = 'Security Administrator' },
            @{ A = 'Privileged Authentication Administrator'; B = 'Authentication Administrator' },
            @{ A = 'Billing Administrator';                 B = 'Global Administrator' },
            @{ A = 'Security Administrator';                B = 'Exchange Administrator' },
            @{ A = 'Authentication Administrator';          B = 'User Administrator' },
            @{ A = 'User Administrator';                    B = 'Groups Administrator' },
            @{ A = 'SharePoint Administrator';              B = 'Exchange Administrator' },
            @{ A = 'Application Administrator';             B = 'Cloud Application Administrator' },
            @{ A = 'Intune Administrator';                  B = 'Security Administrator' }
        )
        $hasSodConflict = $false
        foreach ($pair in $groupSodPairs) {
            if (($pair.A -in $roles) -and ($pair.B -in $roles)) { $hasSodConflict = $true; break }
        }

        $riskReasons = New-Object System.Collections.Generic.List[string]
        if ($highImpact.Count -gt 0)         { $riskReasons.Add('Group holds high-impact roles') }
        if ($hasSodConflict)                 { $riskReasons.Add('Group role set contains conflicting role pairs - SoD conflict embedded in group design') }
        if ($memberGuests.Count -gt 0)       { $riskReasons.Add('Group includes guest members') }
        if ($memberNestedGroups.Count -gt 0) { $riskReasons.Add('Group includes nested groups (indirect path complexity)') }
        if ($roles.Count -ge 5)              { $riskReasons.Add("Group holds $($roles.Count) distinct roles - potential admin bundle overload") }

        if ($highImpact.Count -gt 0 -and $hasSodConflict) { $risk = 'Critical' }
        elseif ($highImpact.Count -gt 0 -or ($memberGuests.Count -gt 0 -and $roles.Count -gt 0)) { $risk = 'High' }
        elseif ($roles.Count -gt 0) { $risk = 'Medium' }
        else { $risk = 'Low' }

        $rows += [pscustomobject]@{
            GroupId                    = $groupId
            GroupDisplayName           = $group.GroupDisplayName
            IsRoleAssignable           = $group.IsRoleAssignable
            DistinctRoleCount          = $roles.Count
            HighImpactRoleCount        = $highImpact.Count
            HasSoDConflict             = $hasSodConflict
            Roles                      = ($roles -join '; ')
            HighImpactRoles            = ($highImpact -join '; ')
            DirectUserMemberCount      = $memberUsers.Count
            GuestMemberCount           = $memberGuests.Count
            NestedGroupMemberCount     = $memberNestedGroups.Count
            GroupRiskRating            = $risk
            GroupRiskWhy               = ($riskReasons -join '; ')
        }
    }

    return @($rows | Sort-Object -Property GroupRiskRating, DistinctRoleCount, GroupDisplayName -Descending)
}

function New-SodConflicts {
    [CmdletBinding()]
    param(
        [object[]]$UserAccessPaths
    )

    $conflictPairs = @(
        @{ A = 'Privileged Role Administrator';         B = 'Conditional Access Administrator';        Risk = 'High';   Why = 'Can assign privileged roles and alter Conditional Access protection controls simultaneously.' },
        @{ A = 'Global Administrator';                  B = 'Privileged Role Administrator';            Risk = 'High';   Why = 'Broad tenant control combined with role governance authority creates unchecked administrative power.' },
        @{ A = 'Global Administrator';                  B = 'Security Administrator';                   Risk = 'High';   Why = 'Overlapping Tier-0 roles create excessive privileged authority concentration.' },
        @{ A = 'Privileged Role Administrator';         B = 'Security Administrator';                   Risk = 'High';   Why = 'Role assignment power combined with security policy control undermines identity governance.' },
        @{ A = 'Privileged Authentication Administrator'; B = 'Authentication Administrator';            Risk = 'High';   Why = 'Combined privileged and standard authentication administration removes separation of duty.' },
        @{ A = 'Billing Administrator';                 B = 'Global Administrator';                     Risk = 'High';   Why = 'Financial control combined with full tenant authority creates unchecked spend and access risk.' },
        @{ A = 'Security Administrator';                B = 'Exchange Administrator';                   Risk = 'Medium'; Why = 'Cross-domain administrative control weakens operational segregation of duties.' },
        @{ A = 'Authentication Administrator';          B = 'User Administrator';                       Risk = 'Medium'; Why = 'Identity lifecycle control combined with authentication factor management reduces accountability separation.' },
        @{ A = 'User Administrator';                    B = 'Groups Administrator';                     Risk = 'Medium'; Why = 'Combined identity and group lifecycle control reduces accountability separation.' },
        @{ A = 'SharePoint Administrator';              B = 'Exchange Administrator';                   Risk = 'Medium'; Why = 'Combined content and messaging platform control reduces operational boundary.' },
        @{ A = 'Application Administrator';             B = 'Cloud Application Administrator';          Risk = 'Medium'; Why = 'Overlapping application registration scopes reduce segregation of platform control.' },
        @{ A = 'Intune Administrator';                  B = 'Security Administrator';                   Risk = 'Medium'; Why = 'Device management combined with security policy control may weaken endpoint governance.' }
    )

    $rows = @()
    $byUser = @($UserAccessPaths | Group-Object -Property UserId)

    foreach ($group in $byUser) {
        $records = @($group.Group)
        if ($records.Count -eq 0) {
            continue
        }

        $roles = @($records | Select-Object -ExpandProperty RoleName -Unique)
        $first = $records[0]

        foreach ($pair in $conflictPairs) {
            if (($pair.A -in $roles) -and ($pair.B -in $roles)) {
                $rows += [pscustomobject]@{
                    UserId            = $first.UserId
                    UserDisplayName   = $first.UserDisplayName
                    UserPrincipalName = $first.UserPrincipalName
                    UserCategory      = $first.UserCategory
                    ConflictRoleA     = $pair.A
                    ConflictRoleB     = $pair.B
                    ConflictRisk      = $pair.Risk
                    ConflictWhy       = $pair.Why
                }
            }
        }
    }

    return @($rows | Sort-Object -Property ConflictRisk, UserDisplayName -Descending)
}

function New-UserElevationPaths {
    [CmdletBinding()]
    param(
        [object[]]$UserAccessPaths
    )

    $rows = @()
    $eligibleInherited = @(
        $UserAccessPaths |
        Where-Object { $_.AccessPathType -eq 'GroupInherited' -and $_.AssignmentState -eq 'Eligible' }
    )

    $grouped = @($eligibleInherited | Group-Object -Property UserId)
    foreach ($grp in $grouped) {
        $items = @($grp.Group)
        if ($items.Count -eq 0) {
            continue
        }

        $first = $items[0]
        $roles = @($items | Select-Object -ExpandProperty RoleName -Unique)
        $sourceGroups = @($items | Select-Object -ExpandProperty SourceGroupDisplayName -Unique)

        $rows += [pscustomobject]@{
            UserId                     = $first.UserId
            UserDisplayName            = $first.UserDisplayName
            UserPrincipalName          = $first.UserPrincipalName
            UserCategory               = $first.UserCategory
            EligibleElevationRoleCount = $roles.Count
            EligibleElevationRoles     = ($roles -join '; ')
            SourceGroups               = ($sourceGroups -join '; ')
        }
    }

    return @($rows | Sort-Object -Property EligibleElevationRoleCount, UserDisplayName -Descending)
}

function New-ExecutiveScorecard {
    [CmdletBinding()]
    param(
        [object[]]$RoleAssignments,
        [object[]]$UserAccessPaths,
        [object[]]$Findings,
        [object[]]$ConditionalAccessPolicies,
        [object[]]$SodConflicts
    )

    $highFindings = @($Findings | Where-Object { $_.RiskRating -eq 'High' }).Count
    $mediumFindings = @($Findings | Where-Object { $_.RiskRating -eq 'Medium' }).Count

    $gaReachableUsers = @(
        $UserAccessPaths |
        Where-Object {
            $_.RoleName -eq 'Global Administrator' -and
            ($_.AssignmentState -eq 'Active' -or $_.AssignmentState -eq 'Eligible')
        } |
        Select-Object -ExpandProperty UserId -Unique
    )

    $gaActiveUsers = @(
        $UserAccessPaths |
        Where-Object { $_.RoleName -eq 'Global Administrator' -and $_.AssignmentState -eq 'Active' } |
        Select-Object -ExpandProperty UserId -Unique
    )

    $bgAccounts = @(
        $RoleAssignments |
        Where-Object {
            $_.PrincipalType -eq 'User' -and
            $_.PrincipalId -and
            (($_.PrincipalDisplayName -match 'break\s*glass') -or ($_.PrincipalDisplayName -match 'emergency') -or ($_.PrincipalUserPrincipalName -match 'break\s*glass|emergency'))
        } |
        Select-Object -ExpandProperty PrincipalId -Unique
    )

    $enabledCaWithoutMfa = @($ConditionalAccessPolicies | Where-Object { $_.State -eq 'enabled' -and $_.RequiresMfaControl -eq $false }).Count
    $highSod = @($SodConflicts | Where-Object { $_.ConflictRisk -eq 'High' }).Count

    $score = 100
    $score -= [Math]::Min(40, $highFindings)
    $score -= [Math]::Min(20, [Math]::Max(0, ($gaReachableUsers.Count - 5)) * 5)
    $score -= if ($bgAccounts.Count -eq 2) { 0 } else { 15 }
    $score -= [Math]::Min(15, $enabledCaWithoutMfa)
    $score -= [Math]::Min(10, $highSod)
    $score -= [Math]::Min(10, [int]($mediumFindings / 25))

    if ($score -lt 0) {
        $score = 0
    }

    $trafficLight = if ($score -ge 80) {
        'Green'
    }
    elseif ($score -ge 60) {
        'Amber'
    }
    else {
        'Red'
    }

    $rows = @()
    $rows += [pscustomobject]@{ Metric = 'OverallRiskScore'; Value = $score; Status = $trafficLight; Target = '>= 80'; Commentary = 'Composite score across identity, policy, and governance controls.' }
    $rows += [pscustomobject]@{ Metric = 'GlobalAdminReachableUsers'; Value = $gaReachableUsers.Count; Status = if ($gaReachableUsers.Count -le 5) { 'Green' } else { 'Red' }; Target = '<= 5'; Commentary = 'Maximum of five users should have Global Administrator access paths (Active or Eligible).' }
    $rows += [pscustomobject]@{ Metric = 'GlobalAdminActiveUsers'; Value = $gaActiveUsers.Count; Status = if ($gaActiveUsers.Count -le 5) { 'Green' } else { 'Amber' }; Target = '<= 5'; Commentary = 'Users with currently Active Global Administrator access paths.' }
    $rows += [pscustomobject]@{ Metric = 'BreakGlassAccountsDetected'; Value = $bgAccounts.Count; Status = if ($bgAccounts.Count -eq 2) { 'Green' } elseif ($bgAccounts.Count -lt 2) { 'Red' } else { 'Amber' }; Target = '= 2'; Commentary = 'Maintain exactly two monitored break-glass accounts.' }
    $rows += [pscustomobject]@{ Metric = 'HighRiskFindings'; Value = $highFindings; Status = if ($highFindings -eq 0) { 'Green' } elseif ($highFindings -le 10) { 'Amber' } else { 'Red' }; Target = '0'; Commentary = 'High-risk findings requiring immediate remediation.' }
    $rows += [pscustomobject]@{ Metric = 'EnabledCAPoliciesWithoutMFA'; Value = $enabledCaWithoutMfa; Status = if ($enabledCaWithoutMfa -eq 0) { 'Green' } elseif ($enabledCaWithoutMfa -le 2) { 'Amber' } else { 'Red' }; Target = '0'; Commentary = 'Enabled Conditional Access policies that do not enforce MFA control.' }
    $rows += [pscustomobject]@{ Metric = 'HighRiskSoDConflicts'; Value = $highSod; Status = if ($highSod -eq 0) { 'Green' } elseif ($highSod -le 3) { 'Amber' } else { 'Red' }; Target = '0'; Commentary = 'Users with high-risk toxic role combinations.' }

    return @($rows)
}

# ─── Privilege Concentration Analysis ───────────────────────────────────────────

function New-PrivilegeConcentrationAnalysis {
    <#
    .SYNOPSIS
    Calculates per-user privilege breadth and flags users with excessive role concentration.
    Super-admin equivalence is flagged when a user holds 3+ Tier-0 roles or GA + 15+ total roles.
    #>
    [CmdletBinding()]
    param(
        [object[]]$UserRoleSummary,
        [string[]]$HighImpactRoles
    )

    $tier0Roles = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Conditional Access Administrator',
        'Security Administrator',
        'Privileged Authentication Administrator',
        'Authentication Policy Administrator'
    )

    $rows = @()
    foreach ($user in @($UserRoleSummary)) {
        if (-not $user -or -not $user.UserId) { continue }

        $total = [int]$user.TotalDistinctRoles

        $directList   = @(($user.DirectRoles        -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $inheritedList = @(($user.GroupInheritedRoles -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $allRoles     = @($directList + $inheritedList | Where-Object { $_ } | Select-Object -Unique)

        $highImpactCount = @($allRoles | Where-Object { $_ -in $HighImpactRoles }).Count
        $tier0Count      = @($allRoles | Where-Object { $_ -in $tier0Roles }).Count
        $isGlobalAdmin   = 'Global Administrator' -in $allRoles

        $isSuperAdminEquiv = ($tier0Count -ge 3) -or ($isGlobalAdmin -and $total -gt 15)

        if ($total -gt 20 -or ($isSuperAdminEquiv -and $highImpactCount -ge 3)) { $concentrationRisk = 'Critical' }
        elseif ($total -gt 10 -or $highImpactCount -ge 3)                        { $concentrationRisk = 'High' }
        elseif ($total -gt 5)                                                     { $concentrationRisk = 'Medium' }
        else                                                                      { $concentrationRisk = 'Low' }

        $rows += [pscustomobject]@{
            UserId                 = $user.UserId
            UserDisplayName        = $user.UserDisplayName
            UserPrincipalName      = $user.UserPrincipalName
            UserCategory           = $user.UserCategory
            TotalDistinctRoles     = $total
            DirectRoleCount        = $user.DirectRoleCount
            InheritedRoleCount     = $user.GroupInheritedRoleCount
            HighImpactRoleCount    = $highImpactCount
            Tier0RoleCount         = $tier0Count
            IsGlobalAdmin          = $isGlobalAdmin
            IsSuperAdminEquivalent = $isSuperAdminEquiv
            ConcentrationRisk      = $concentrationRisk
            AllRoles               = (($allRoles | Sort-Object) -join '; ')
        }
    }

    return @($rows | Sort-Object -Property TotalDistinctRoles -Descending)
}

# ─── JIT Effectiveness Score ─────────────────────────────────────────────────────

function Get-JitEffectivenessScore {
    <#
    .SYNOPSIS
    Computes a tenant-wide JIT effectiveness score (0-100) and breakdown across all analysed roles.
    Score weights: MFA 35%, Approval 30%, Short duration 20%, Permanent-eligible penalty 15%.
    #>
    [CmdletBinding()]
    param([object[]]$RoleElevationMatrix)

    $matrix = @($RoleElevationMatrix)
    $total  = $matrix.Count
    if ($total -eq 0) { return $null }

    $mfaCount      = @($matrix | Where-Object { $_.MfaRequired      -eq $true }).Count
    $approvalCount = @($matrix | Where-Object { $_.ApprovalRequired -eq $true -and $_.ApproverCount -gt 0 }).Count
    $shortDurCount = @($matrix | Where-Object { $null -ne $_.MaxActivationDurationHours -and [double]$_.MaxActivationDurationHours -le 8 }).Count
    $permEligCount = @($matrix | Where-Object { $_.HasPermanentEligibleAssignment -eq $true }).Count
    $strongCount   = @($matrix | Where-Object { $_.ControlStrength  -eq 'Strong' }).Count
    $weakCount     = @($matrix | Where-Object { $_.ControlStrength  -eq 'Weak'   }).Count

    $pctMfa      = [Math]::Round(($mfaCount      / $total) * 100, 1)
    $pctApproval = [Math]::Round(($approvalCount / $total) * 100, 1)
    $pctShortDur = [Math]::Round(($shortDurCount / $total) * 100, 1)
    $pctPermElig = [Math]::Round(($permEligCount / $total) * 100, 1)
    $pctStrong   = [Math]::Round(($strongCount   / $total) * 100, 1)
    $pctWeak     = [Math]::Round(($weakCount     / $total) * 100, 1)

    $rawScore = ($pctMfa * 0.35) + ($pctApproval * 0.30) + ($pctShortDur * 0.20) + ((100 - $pctPermElig) * 0.15)
    $score    = [Math]::Min(100, [Math]::Max(0, [Math]::Round($rawScore, 1)))

    if ($score -ge 80) { $rating = 'Strong' } elseif ($score -ge 60) { $rating = 'Moderate' } else { $rating = 'Weak' }

    return [pscustomobject]@{
        TotalRolesAnalysed         = $total
        RolesWithMfa               = $mfaCount
        RolesWithApproval          = $approvalCount
        RolesWithShortDuration     = $shortDurCount
        RolesWithPermanentEligible = $permEligCount
        RolesWithStrongControl     = $strongCount
        RolesWithWeakControl       = $weakCount
        PctMfaRequired             = $pctMfa
        PctApprovalRequired        = $pctApproval
        PctShortDuration           = $pctShortDur
        PctPermanentEligible       = $pctPermElig
        PctStrongControl           = $pctStrong
        PctWeakControl             = $pctWeak
        JITEffectivenessScore      = $score
        JITEffectivenessRating     = $rating
        Insight                    = "Across $total roles: $pctMfa% require MFA, $pctApproval% require approval, $pctShortDur% enforce max 8h duration. $pctPermElig% have permanent eligible assignments. $pctStrong% carry Strong control posture, $pctWeak% are Weak."
    }
}

# ─── Key Security Insights ────────────────────────────────────────────────────────

function Generate-KeyInsights {
    <#
    .SYNOPSIS
    Derives 3-5 high-value narrative security insights from patterns in the collected data.
    All insights are data-driven; none are hardcoded.
    #>
    [CmdletBinding()]
    param(
        [object[]]$RoleElevationMatrix,
        [object[]]$UserRoleSummary,
        [object[]]$GroupRiskProfiles,
        [object[]]$Findings,
        [object]$JitEffectiveness,
        [object[]]$PrivilegeConcentration,
        [string[]]$HighImpactRoles
    )

    $insights      = New-Object System.Collections.Generic.List[string]
    $matrix        = @($RoleElevationMatrix)
    $concentration = @($PrivilegeConcentration)
    $groupProfiles = @($GroupRiskProfiles)

    # ── Insight 1: JIT effectiveness posture ─────────────────────────────────────
    if ($null -ne $JitEffectiveness -and $JitEffectiveness.TotalRolesAnalysed -gt 0) {
        $pctMfa      = $JitEffectiveness.PctMfaRequired
        $pctApproval = $JitEffectiveness.PctApprovalRequired
        $pctPerm     = $JitEffectiveness.PctPermanentEligible
        if ($pctMfa -lt 50 -or $pctApproval -lt 50) {
            $insights.Add("PIM is deployed but is not consistently enforcing Just-In-Time controls: only $pctMfa% of roles require MFA and $pctApproval% require approval. The JIT model is providing limited access governance in its current configuration and requires structural remediation.")
        }
        elseif ($pctPerm -gt 20) {
            $insights.Add("JIT control coverage across MFA ($pctMfa%) and approval ($pctApproval%) is reasonable, however $pctPerm% of roles carry permanent eligible assignments with no expiry enforcement. Permanent eligibility undermines the time-bound access model and should be replaced with defined eligibility windows.")
        }
        else {
            $insights.Add("JIT controls are broadly applied: $pctMfa% of roles enforce MFA and $pctApproval% require approval. Residual risk is concentrated in the minority of unprotected high-impact roles identified in the elevation control matrix - these should be prioritised for immediate remediation.")
        }
    }

    # ── Insight 2: Privilege concentration ────────────────────────────────────────
    if ($concentration.Count -gt 0) {
        $superAdmins = @($concentration | Where-Object { $_.IsSuperAdminEquivalent -eq $true }).Count
        $heavyPriv   = @($concentration | Where-Object { $_.TotalDistinctRoles -gt 10 }).Count
        $maxRoles    = ($concentration | Measure-Object -Property TotalDistinctRoles -Maximum).Maximum
        if ($superAdmins -gt 0) {
            $insights.Add("$superAdmins user(s) hold a combination of Tier-0 roles that approaches super-administrator equivalence, with a single account carrying up to $maxRoles distinct privileged roles. This level of privilege concentration creates a high-impact single point of compromise.")
        }
        elseif ($heavyPriv -gt 0) {
            $insights.Add("Privilege breadth is concentrated in $heavyPriv user(s) who each hold more than 10 distinct privileged roles (maximum: $maxRoles). Role rationalisation for these accounts would materially reduce the blast radius of a credential compromise.")
        }
    }

    # ── Insight 3: Group-embedded risk ────────────────────────────────────────────
    $criticalGroups = @($groupProfiles | Where-Object { $_.GroupRiskRating -eq 'Critical' }).Count
    $sodGroupCount  = @($groupProfiles | Where-Object { $_.HasSoDConflict  -eq $true }).Count
    $highRiskGroups = @($groupProfiles | Where-Object { $_.GroupRiskRating -in 'Critical', 'High' }).Count
    if ($criticalGroups -gt 0) {
        $insights.Add("$criticalGroups privileged group(s) are rated Critical because they combine high-impact roles with embedded SoD conflicts in their role design. Members simultaneously inherit mutually exclusive privileges, and these conflicts are invisible in standard direct-assignment reporting.")
    }
    elseif ($sodGroupCount -gt 0) {
        $insights.Add("$sodGroupCount privileged group(s) contain conflicting role pairs embedded in their design. Any user who joins these groups immediately inherits mutually exclusive privileges without the SoD conflict appearing in direct-assignment views.")
    }
    elseif ($highRiskGroups -gt 0) {
        $insights.Add("$highRiskGroups privileged group(s) are rated High or Critical risk. Group-based privilege grants are typically less visible in standard access reporting and may bypass direct-assignment approval gates, amplifying the effective control gap.")
    }

    # ── Insight 4: High-impact roles with weak controls ───────────────────────────
    $critHighImpact    = @($matrix | Where-Object { $_.IsHighImpact -eq $true -and $_.RiskRating -in 'Critical', 'High' }).Count
    if ($critHighImpact -gt 0) {
        $noMfaHigh      = @($matrix | Where-Object { $_.IsHighImpact -eq $true -and $_.MfaRequired -ne $true }).Count
        $noApprovalHigh = @($matrix | Where-Object { $_.IsHighImpact -eq $true -and ($_.ApprovalRequired -ne $true -or $_.ApproverCount -eq 0) }).Count
        $insights.Add("$critHighImpact high-impact role(s) carry a Critical or High elevation risk rating: $noMfaHigh lack MFA enforcement and $noApprovalHigh lack effective approval controls. These roles represent the highest-priority remediation targets for reducing privilege exploitation risk.")
    }

    # ── Insight 5: Top high-risk finding pattern ──────────────────────────────────
    $highFindings = @($Findings | Where-Object { $_.RiskRating -eq 'High' })
    if ($highFindings.Count -gt 0) {
        $topType = @($highFindings | Group-Object -Property FindingType | Sort-Object -Property Count -Descending | Select-Object -First 1)
        if ($topType.Count -gt 0) {
            $topTypeName  = [System.Net.WebUtility]::HtmlDecode($topType[0].Name)
            $topTypeCount = $topType[0].Count
            $totalHigh    = $highFindings.Count
            $insights.Add("The most prevalent high-risk finding type is '$topTypeName' ($topTypeCount instance(s) of $totalHigh total high-risk findings). Systematic remediation of this category will deliver the greatest single reduction in overall risk posture.")
        }
    }

    return @($insights | Select-Object -First 5)
}

# ─── Guest Privileged Accounts ──────────────────────────────────────────────────

function New-GuestPrivilegedAccounts {
    <#
    .SYNOPSIS
    Extracts guest users with privileged access paths and produces a per-user risk profile.
    Input is the UserAccessPaths table — no additional Graph calls.
    #>
    [CmdletBinding()]
    param(
        [object[]]$UserAccessPaths,
        [string[]]$HighImpactRoles
    )

    $rows = @()
    $guestPaths = @($UserAccessPaths | Where-Object { $_.UserCategory -eq 'Guest' -and $_.UserId })
    if ($guestPaths.Count -eq 0) { return @() }

    $byUser = @($guestPaths | Group-Object -Property UserId)
    foreach ($grp in $byUser) {
        $items = @($grp.Group)
        if ($items.Count -eq 0) { continue }
        $first = $items[0]

        $allRoles       = @($items | Select-Object -ExpandProperty RoleName -Unique)
        $highImpact     = @($allRoles | Where-Object { $_ -in $HighImpactRoles })
        $directPaths    = @($items | Where-Object { $_.AccessPathType -eq 'Direct' })
        $inheritedPaths = @($items | Where-Object { $_.AccessPathType -eq 'GroupInherited' })
        $permanentPaths = @($items | Where-Object { $_.IsPermanent -eq $true })
        $sourceGroups   = @($items | Where-Object { $_.SourceGroupDisplayName } | Select-Object -ExpandProperty SourceGroupDisplayName -Unique)

        $riskReasons = New-Object System.Collections.Generic.List[string]
        $riskReasons.Add('External guest identity holds privileged access')
        if ($highImpact.Count -gt 0)     { $riskReasons.Add("Holds $($highImpact.Count) high-impact role(s)") }
        if ($directPaths.Count -gt 0)    { $riskReasons.Add('Has direct role assignment(s) in addition to or instead of group-based paths') }
        if ($permanentPaths.Count -gt 0) { $riskReasons.Add("$($permanentPaths.Count) path(s) with no expiry (permanent assignment)") }
        if ($sourceGroups.Count -gt 0)   { $riskReasons.Add("Inherits access via $($sourceGroups.Count) privileged group(s)") }

        if ($highImpact.Count -gt 0 -and $directPaths.Count -gt 0) { $risk = 'Critical' }
        elseif ($highImpact.Count -gt 0)                           { $risk = 'High' }
        elseif ($directPaths.Count -gt 0)                          { $risk = 'High' }
        else                                                        { $risk = 'Medium' }

        $rows += [pscustomobject]@{
            UserId                   = $first.UserId
            UserDisplayName          = $first.UserDisplayName
            UserPrincipalName        = $first.UserPrincipalName
            TotalRoleCount           = $allRoles.Count
            HighImpactRoleCount      = $highImpact.Count
            HasDirectAssignment      = ($directPaths.Count -gt 0)
            HasGroupAssignment       = ($inheritedPaths.Count -gt 0)
            HasPermanentPath         = ($permanentPaths.Count -gt 0)
            DirectPathCount          = $directPaths.Count
            GroupInheritedPathCount  = $inheritedPaths.Count
            SourceGroupCount         = $sourceGroups.Count
            AllRoles                 = (($allRoles | Sort-Object) -join '; ')
            HighImpactRoles          = ($highImpact -join '; ')
            SourceGroups             = ($sourceGroups -join '; ')
            GuestRiskRating          = $risk
            GuestRiskWhy             = ($riskReasons -join '; ')
        }
    }

    return @($rows | Sort-Object -Property GuestRiskRating, HighImpactRoleCount, TotalRoleCount -Descending)
}

# ─── Naming Convention Compliance ────────────────────────────────────────────────

function Get-NamingCompliance {
    <#
    .SYNOPSIS
    Evaluates whether privileged user UPNs conform to a required naming convention prefix
    (e.g. CLAD_). Non-compliant accounts may be everyday personal or service accounts
    used for privileged operations — a control gap.
    No additional Graph calls.
    #>
    [CmdletBinding()]
    param(
        [object[]]$UserRoleSummary,
        [string]$NamingPrefix
    )

    if ([string]::IsNullOrWhiteSpace($NamingPrefix)) { $NamingPrefix = 'CLAD_' }
    $prefixPattern = '^' + [regex]::Escape($NamingPrefix)

    $rows = @()
    foreach ($user in @($UserRoleSummary)) {
        if (-not $user -or [string]::IsNullOrWhiteSpace($user.UserId)) { continue }

        $upn = [string]$user.UserPrincipalName
        # Guest accounts (#EXT#) are excluded — naming rule applies to member accounts only
        if ($upn -match '#EXT#') { continue }
        if ($user.UserCategory -eq 'Guest') { continue }

        $isCompliant = $upn -match $prefixPattern

        $riskReasons = @()
        if (-not $isCompliant) {
            $riskReasons += "UPN '$upn' does not start with required prefix '$NamingPrefix'"
            $riskReasons += 'Privileged account may be an everyday personal or shared account - dedicated admin account standard not met'
        }

        $riskRating = if ($isCompliant) { 'Low' } else { 'High' }

        $rows += [pscustomobject]@{
            UserId                 = $user.UserId
            UserDisplayName        = $user.UserDisplayName
            UserPrincipalName      = $upn
            UserCategory           = $user.UserCategory
            TotalDistinctRoles     = $user.TotalDistinctRoles
            NamingPrefix           = $NamingPrefix
            IsNamingCompliant      = $isCompliant
            NamingComplianceStatus = if ($isCompliant) { 'Compliant' } else { 'Non-Compliant' }
            ComplianceRiskRating   = $riskRating
            ComplianceReason       = if ($riskReasons.Count -gt 0) { ($riskReasons -join '; ') } else { "UPN matches required '$NamingPrefix' naming prefix - dedicated admin account standard met" }
        }
    }

    return @($rows | Sort-Object -Property IsNamingCompliant, TotalDistinctRoles -Descending)
}

# ─── Licensed Privileged Accounts ────────────────────────────────────────────────

function New-PrivilegedLicensedAccounts {
    <#
    .SYNOPSIS
    Cross-references the privileged user role summary with the user license data to identify
    users who hold both privileged roles and active product licenses.
    Licensed accounts with high-impact roles represent a risk: a credential compromise also
    exposes licensed data (mail, files, Teams) alongside privileged administrative access.
    No additional Graph calls.
    #>
    [CmdletBinding()]
    param(
        [object[]]$UserRoleSummary,
        [object[]]$UserLicenses,
        [string[]]$HighImpactRoles
    )

    # Build UserId -> license record lookup
    $licenseByUser = @{}
    foreach ($lic in @($UserLicenses | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserId) })) {
        $licenseByUser[[string]$lic.UserId] = $lic
    }

    $rows = @()
    foreach ($user in @($UserRoleSummary | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserId) })) {
        $licInfo = $licenseByUser[[string]$user.UserId]
        if (-not $licInfo) { continue }

        $skuParts = @(([string]$licInfo.SkuPartNumbers -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($skuParts.Count -eq 0) { continue }

        $allRoles    = @((([string]$user.DirectRoles + ';' + [string]$user.GroupInheritedRoles) -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
        $highImpact  = @($allRoles | Where-Object { $_ -in $HighImpactRoles })

        $riskReasons = New-Object System.Collections.Generic.List[string]
        $riskReasons.Add("Licensed account with $($skuParts.Count) assigned product SKU(s) also holds $($allRoles.Count) privileged role(s)")
        if ($highImpact.Count -gt 0) { $riskReasons.Add("$($highImpact.Count) of those role(s) are high-impact - credential compromise exposes both data and administrative authority") }
        if ($user.UserCategory -eq 'Guest') { $riskReasons.Add('External guest identity holds both a product license and privileged roles') }

        if ($highImpact.Count -gt 0) { $risk = 'High' }
        elseif ([int]$user.TotalDistinctRoles -gt 5) { $risk = 'Medium' }
        else { $risk = 'Low' }

        $friendlySkus = @($skuParts | ForEach-Object {
            switch ($_) {
                'AAD_PREMIUM_P2'   { 'Azure AD P2' }
                'AAD_PREMIUM'      { 'Azure AD P1' }
                'SPE_E5'           { 'Microsoft 365 E5' }
                'SPE_E3'           { 'Microsoft 365 E3' }
                'ENTERPRISEPREMIUM'{ 'Office 365 E5' }
                'ENTERPRISEPACK'   { 'Office 365 E3' }
                'EMS'              { 'EMS E3' }
                'EMSPREMIUM'       { 'EMS E5' }
                default            { $_ }
            }
        })

        $rows += [pscustomobject]@{
            UserId                    = $user.UserId
            UserDisplayName           = $user.UserDisplayName
            UserPrincipalName         = $user.UserPrincipalName
            UserCategory              = $user.UserCategory
            TotalDistinctRoles        = $user.TotalDistinctRoles
            HighImpactRoleCount       = $highImpact.Count
            DirectRoleCount           = $user.DirectRoleCount
            LicenseCount              = $skuParts.Count
            LicenseSkuPartNumbers     = ($skuParts -join '; ')
            FriendlyLicenseNames      = ($friendlySkus -join '; ')
            HighImpactRoles           = ($highImpact -join '; ')
            LicensedAdminRiskRating   = $risk
            LicensedAdminRiskWhy      = ($riskReasons -join '; ')
        }
    }

    return @($rows | Sort-Object -Property LicensedAdminRiskRating, HighImpactRoleCount, TotalDistinctRoles -Descending)
}

# ─── Identity Assurance Profile ───────────────────────────────────────────────────

function New-IdentityAssuranceProfiles {
    <#
    .SYNOPSIS
    Produces a unified per-user identity risk object combining:
    - Privilege concentration (role breadth)
    - Guest / external identity
    - Naming convention compliance
    - License assignment alongside privileged roles
    - Authentication strength (phishing-resistant / standard MFA / weak)
    
    IdentityRiskRating is derived from a composite score across all risk factors.
    #>
    [CmdletBinding()]
    param(
        [object[]]$UserRoleSummary,
        [object[]]$GuestAnalysis,
        [object[]]$NamingCompliance,
        [object[]]$LicensedAccounts,
        [object[]]$AuthStrength,
        [object[]]$PrivilegeConcentration,
        [string[]]$HighImpactRoles
    )

    # Build lookup tables indexed by UserId
    $guestById = @{}
    foreach ($g in @($GuestAnalysis   | Where-Object { $_.UserId })) { $guestById[$g.UserId]   = $g }

    $namingById = @{}
    foreach ($n in @($NamingCompliance | Where-Object { $_.UserId })) { $namingById[$n.UserId]  = $n }

    $licensedById = @{}
    foreach ($l in @($LicensedAccounts | Where-Object { $_.UserId })) { $licensedById[$l.UserId] = $l }

    $authById = @{}
    foreach ($a in @($AuthStrength     | Where-Object { $_.UserId })) { $authById[$a.UserId]    = $a }

    $concById = @{}
    foreach ($c in @($PrivilegeConcentration | Where-Object { $_.UserId })) { $concById[$c.UserId] = $c }

    $rows = @()
    foreach ($user in @($UserRoleSummary | Where-Object { $_.UserId })) {
        $uid      = [string]$user.UserId
        $upn      = [string]$user.UserPrincipalName
        $isGuest  = ($user.UserCategory -eq 'Guest') -or ($upn -match '#EXT#')
        $isLicensed = $licensedById.ContainsKey($uid)

        $namingRec = $namingById[$uid]
        $isNamingCompliant = if ($namingRec) { $namingRec.IsNamingCompliant } else { $true }

        $authRec = $authById[$uid]
        $authStrengthVal = if ($authRec) { [string]$authRec.AuthStrength } else { 'Unknown' }
        $hasPhishingMfa  = if ($authRec) { [bool]$authRec.HasPhishingResistantMethod } else { $false }

        $concRec = $concById[$uid]
        $concentrationRisk = if ($concRec) { [string]$concRec.ConcentrationRisk }    else { 'Low' }
        $isSuperAdmin      = if ($concRec) { [bool]$concRec.IsSuperAdminEquivalent } else { $false }

        $allRoles = @(
            (([string]$user.DirectRoles + ';' + [string]$user.GroupInheritedRoles) -split ';') |
            ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique
        )
        $highImpactCount = @($allRoles | Where-Object { $_ -in $HighImpactRoles }).Count
        $total = [int]$user.TotalDistinctRoles

        # Composite identity risk score (additive, capped at Critical = 7+)
        $score = 0
        if ($isGuest)                                      { $score += 3 }
        if (-not $isNamingCompliant)                       { $score += 2 }
        if ($isLicensed -and $highImpactCount -gt 0)      { $score += 2 }
        if ($authStrengthVal -eq 'WeakOrNone')             { $score += 3 }
        elseif ($authStrengthVal -eq 'StandardMFA')        { $score += 1 }
        if ($highImpactCount -gt 0)                        { $score += 2 }
        if ($total -gt 10)                                 { $score += 1 }
        if ($isSuperAdmin)                                 { $score += 2 }

        if ($score -ge 7)     { $identityRisk = 'Critical' }
        elseif ($score -ge 4) { $identityRisk = 'High' }
        elseif ($score -ge 2) { $identityRisk = 'Medium' }
        else                  { $identityRisk = 'Low' }

        $rows += [pscustomobject]@{
            UserId                   = $uid
            UserDisplayName          = $user.UserDisplayName
            UserPrincipalName        = $upn
            UserCategory             = $user.UserCategory
            IsGuest                  = $isGuest
            IsLicensed               = $isLicensed
            IsNamingCompliant        = $isNamingCompliant
            AuthStrength             = $authStrengthVal
            HasPhishingResistantMfa  = $hasPhishingMfa
            TotalRoleCount           = $total
            HighImpactRoleCount      = $highImpactCount
            DirectRoleCount          = [int]$user.DirectRoleCount
            InheritedRoleCount       = [int]$user.GroupInheritedRoleCount
            ConcentrationRisk        = $concentrationRisk
            IsSuperAdminEquivalent   = $isSuperAdmin
            IdentityRiskScore        = $score
            IdentityRiskRating       = $identityRisk
        }
    }

    return @($rows | Sort-Object -Property IdentityRiskRating, IdentityRiskScore, TotalRoleCount -Descending)
}

# ─── Workbook Builder ─────────────────────────────────────────────────────────────

function Build-PimReviewWorkbook {
    [CmdletBinding()]
    param(
        [hashtable]$Data,

        [hashtable]$Config,

        [string]$OutputFolder,

        [string]$WorkbookFileName,

        [switch]$InstallImportExcelIfMissing,

        [switch]$PromptToInstallImportExcel,

        [switch]$ReturnObjectsOnly
    )

    # Manual guards replacing [Parameter(Mandatory)] — the script-level param() block in this file
    # creates $Data=$null and $Config=$null in script scope when dot-sourced, which causes PS5.1's
    # Mandatory validation to wrongly reject valid arguments passed by the caller.
    if ($null -eq $Data)         { throw 'Build-PimReviewWorkbook: -Data is required.' }
    if ($null -eq $Config)       { throw 'Build-PimReviewWorkbook: -Config is required.' }
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) { throw 'Build-PimReviewWorkbook: -OutputFolder is required.' }

    $null = Ensure-Directory -Path $OutputFolder

    $findings = New-PimFindings `
        -RoleAssignments $Data.RoleAssignments `
        -PolicyRules $Data.RolePolicyRules `
        -PrivilegedGroups $Data.PrivilegedGroups `
        -GroupMembers $Data.GroupMembers `
        -UserLicenses $Data.UserLicenses `
        -Config $Config

    $summary = New-SummaryRows `
        -RoleAssignments $Data.RoleAssignments `
        -PolicyRules $Data.RolePolicyRules `
        -PrivilegedGroups $Data.PrivilegedGroups `
        -GroupMembers $Data.GroupMembers

    $userAccessPaths = New-UserAccessPaths `
        -RoleAssignments $Data.RoleAssignments `
        -GroupMembers $Data.GroupMembers `
        -HighImpactRoles @($Config.HighImpactRoles)

    # ── Elevation matrix integration ──────────────────────────────────────────────
    # Pull the pre-computed matrix from $Data when supplied by the orchestrator.
    # Correlated findings (exposure + control weakness) are merged into the main findings set.
    $roleElevationMatrix = if ($Data.ContainsKey('RoleElevationMatrix') -and $Data.RoleElevationMatrix) { @($Data.RoleElevationMatrix) } else { @() }
    if ($roleElevationMatrix.Count -gt 0 -and (Get-Command -Name Add-RoleControlFindings -ErrorAction SilentlyContinue)) {
        $findingsList = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $findings) { $findingsList.Add($f) }
        Add-RoleControlFindings `
            -RoleElevationMatrix $roleElevationMatrix `
            -UserAccessPaths     $userAccessPaths `
            -HighImpactRoles     @($Config.HighImpactRoles) `
            -FindingsList        $findingsList
        $findings = @($findingsList | Sort-Object -Property RiskRating, FindingType, Subject -Unique)
    }

    # ── Merge approval-model findings from approver analysis ──────────────────────
    if ($Data.ContainsKey('ApprovalFindings') -and $Data.ApprovalFindings -and @($Data.ApprovalFindings).Count -gt 0) {
        $approvalFindingsMerge = @($Data.ApprovalFindings)
        $mergedList = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $findings) { $mergedList.Add($f) }
        foreach ($f in $approvalFindingsMerge) { $mergedList.Add($f) }
        $findings = @($mergedList | Sort-Object -Property RiskRating, FindingType, Subject)
    }

    $userRoleSummary = New-UserRoleSummary -UserAccessPaths $userAccessPaths
    $groupRoleSummary = New-GroupRoleSummary `
        -PrivilegedGroups $Data.PrivilegedGroups `
        -RoleAssignments $Data.RoleAssignments `
        -GroupMembers $Data.GroupMembers `
        -HighImpactRoles @($Config.HighImpactRoles)

    $sodConflicts = New-SodConflicts -UserAccessPaths $userAccessPaths
    $userElevationPaths = New-UserElevationPaths -UserAccessPaths $userAccessPaths
    $executiveScorecard = New-ExecutiveScorecard `
        -RoleAssignments $Data.RoleAssignments `
        -UserAccessPaths $userAccessPaths `
        -Findings $findings `
        -ConditionalAccessPolicies $Data.ConditionalAccessPolicies `
        -SodConflicts $sodConflicts

    # ── Advanced risk analysis (privilege concentration, JIT, key insights) ────────
    $privilegeConcentration = New-PrivilegeConcentrationAnalysis `
        -UserRoleSummary $userRoleSummary `
        -HighImpactRoles @($Config.HighImpactRoles)

    $jitEffectiveness = Get-JitEffectivenessScore -RoleElevationMatrix $roleElevationMatrix

    $keyInsightsRaw = @(Generate-KeyInsights `
        -RoleElevationMatrix    $roleElevationMatrix `
        -UserRoleSummary        $userRoleSummary `
        -GroupRiskProfiles      $groupRoleSummary `
        -Findings               $findings `
        -JitEffectiveness       $jitEffectiveness `
        -PrivilegeConcentration $privilegeConcentration `
        -HighImpactRoles        @($Config.HighImpactRoles))
    $keyInsights = @($keyInsightsRaw)

    # ── Identity analysis functions ───────────────────────────────────────────────
    $guestPrivilegedAccounts = New-GuestPrivilegedAccounts `
        -UserAccessPaths $userAccessPaths `
        -HighImpactRoles @($Config.HighImpactRoles)

    $namingPrefix = 'CLAD_'
    if ($Config.ContainsKey('NamingCompliancePrefix') -and -not [string]::IsNullOrWhiteSpace($Config.NamingCompliancePrefix)) {
        $namingPrefix = $Config.NamingCompliancePrefix
    }
    $namingCompliance = Get-NamingCompliance `
        -UserRoleSummary $userRoleSummary `
        -NamingPrefix    $namingPrefix

    $licensedPrivilegedAccounts = New-PrivilegedLicensedAccounts `
        -UserRoleSummary $userRoleSummary `
        -UserLicenses    @($Data.UserLicenses) `
        -HighImpactRoles @($Config.HighImpactRoles)

    $authStrengthData = @()
    if ($Data.ContainsKey('AuthStrengthData') -and $Data.AuthStrengthData) {
        $authStrengthData = @($Data.AuthStrengthData)
    }

    $caCoverageData = @()
    if ($Data.ContainsKey('CACoverage') -and $Data.CACoverage) {
        $caCoverageData = @($Data.CACoverage)
    }

    $identityAssuranceProfiles = New-IdentityAssuranceProfiles `
        -UserRoleSummary      $userRoleSummary `
        -GuestAnalysis        $guestPrivilegedAccounts `
        -NamingCompliance     $namingCompliance `
        -LicensedAccounts     $licensedPrivilegedAccounts `
        -AuthStrength         $authStrengthData `
        -PrivilegeConcentration $privilegeConcentration `
        -HighImpactRoles      @($Config.HighImpactRoles)

    $findingsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\Findings.csv'
    Export-PimData -Data @($findings) -CsvPath $findingsCsvPath

    $accessPathsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\UserAccessPaths.csv'
    Export-PimData -Data @($userAccessPaths) -CsvPath $accessPathsCsvPath

    $userRoleSummaryCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\UserRoleAccessSummary.csv'
    Export-PimData -Data @($userRoleSummary) -CsvPath $userRoleSummaryCsvPath

    $groupRoleSummaryCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\GroupRoleAccessSummary.csv'
    Export-PimData -Data @($groupRoleSummary) -CsvPath $groupRoleSummaryCsvPath

    $sodConflictsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\SoDConflicts.csv'
    Export-PimData -Data @($sodConflicts) -CsvPath $sodConflictsCsvPath

    $userElevationCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\UserElevationPaths.csv'
    Export-PimData -Data @($userElevationPaths) -CsvPath $userElevationCsvPath

    $scorecardCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\ExecutiveScorecard.csv'
    Export-PimData -Data @($executiveScorecard) -CsvPath $scorecardCsvPath

    $roleElevationMatrixExport = if (Get-Command -Name ConvertTo-RoleElevationMatrixExportRows -ErrorAction SilentlyContinue) {
        @(ConvertTo-RoleElevationMatrixExportRows -RoleElevationMatrix $roleElevationMatrix)
    }
    else {
        @($roleElevationMatrix)
    }

    if ($roleElevationMatrixExport.Count -gt 0) {
        $elevationMatrixCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\RoleElevationMatrix.csv'
        Export-PimData -Data @($roleElevationMatrixExport) -CsvPath $elevationMatrixCsvPath
    }

    $privConcCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\PrivilegeConcentration.csv'
    Export-PimData -Data @($privilegeConcentration) -CsvPath $privConcCsvPath

    if ($null -ne $jitEffectiveness) {
        $jitCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\JITEffectiveness.csv'
        Export-PimData -Data @($jitEffectiveness) -CsvPath $jitCsvPath
    }

    $keyInsightRows = @($keyInsights | ForEach-Object { [pscustomobject]@{ Insight = $_ } })
    if ($keyInsightRows.Count -gt 0) {
        $insightsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\KeyInsights.csv'
        Export-PimData -Data $keyInsightRows -CsvPath $insightsCsvPath
    }

    Export-PimData -Data @($guestPrivilegedAccounts)    -CsvPath (Join-Path -Path $OutputFolder -ChildPath 'Raw\GuestPrivilegedAccounts.csv')
    Export-PimData -Data @($namingCompliance)           -CsvPath (Join-Path -Path $OutputFolder -ChildPath 'Raw\NamingCompliance.csv')
    Export-PimData -Data @($licensedPrivilegedAccounts) -CsvPath (Join-Path -Path $OutputFolder -ChildPath 'Raw\LicensedPrivilegedAccounts.csv')
    Export-PimData -Data @($identityAssuranceProfiles)  -CsvPath (Join-Path -Path $OutputFolder -ChildPath 'Raw\IdentityAssuranceProfiles.csv')

    $excelAvailable = Test-ImportExcelAvailable

    $excelInstalled = [bool](Get-Module -ListAvailable -Name ImportExcel)
    if (-not $excelAvailable -and -not $excelInstalled) {
        $shouldInstall = $InstallImportExcelIfMissing.IsPresent

        if ((-not $shouldInstall) -and $PromptToInstallImportExcel.IsPresent) {
            try {
                $prompt = Read-Host 'ImportExcel is not installed. Install now and build workbook? (Y/N)'
                if ($prompt -match '^(y|yes)$') {
                    $shouldInstall = $true
                }
            }
            catch {
                Write-PimLog -Level WARN -Message "Unable to prompt for ImportExcel installation: $($_.Exception.Message)"
            }
        }

        if ($shouldInstall) {
            try {
                Write-PimLog -Message 'Installing ImportExcel module for current user.'
                Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                $excelAvailable = Test-ImportExcelAvailable -Refresh
            }
            catch {
                Write-PimLog -Level WARN -Message "ImportExcel installation failed: $($_.Exception.Message)"
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($WorkbookFileName)) {
        $WorkbookFileName = 'PIM_Review_Workbook.xlsx'
    }

    $workbookPath = Join-Path -Path $OutputFolder -ChildPath $WorkbookFileName

    if (-not $excelAvailable) {
        Write-PimLog -Level WARN -Message 'Excel workbook skipped (ImportExcel is not installed or cannot be loaded on this device). CSV evidence and HTML reports are still produced.'
        return [pscustomobject]@{
            WorkbookCreated = $false
            WorkbookPath    = $null
            Findings        = $findings
            Summary         = $summary
            UserAccessPaths = $userAccessPaths
            UserRoleSummary = $userRoleSummary
            GroupRoleSummary = $groupRoleSummary
            SoDConflicts    = $sodConflicts
            UserElevationPaths = $userElevationPaths
            ExecutiveScorecard = $executiveScorecard
            PrivilegeConcentration = $privilegeConcentration
            JitEffectiveness = $jitEffectiveness
            KeyInsights      = $keyInsights
            GuestPrivilegedAccounts    = $guestPrivilegedAccounts
            NamingCompliance           = $namingCompliance
            LicensedPrivilegedAccounts = $licensedPrivilegedAccounts
            IdentityAssuranceProfiles  = $identityAssuranceProfiles
        }
        # Note: RoleElevationMatrix is intentionally omitted here because this path is
        # reached before the matrix integration block executes; it was set to @() earlier.
    }

    Import-Module ImportExcel -ErrorAction Stop -Verbose:$false
    if (Test-Path -Path $workbookPath) {
        Remove-Item -Path $workbookPath -Force
    }

    $sheetMap = @(
        @{ Name = '00_Executive_Scorecard'; Data = $executiveScorecard },
        @{ Name = '01_Summary';            Data = $summary },
        @{ Name = '02_Role_Assignments';   Data = $Data.RoleAssignments },
        @{ Name = '03_Role_Policy_Settings'; Data = $Data.RolePolicyRules },
        @{ Name = '04_Group_Principals';   Data = $Data.PrivilegedGroups },
        @{ Name = '05_Group_Members';      Data = $Data.GroupMembers },
        @{ Name = '06_PIM_Group_Assignments'; Data = $Data.PimGroupAssignments },
        @{ Name = '07_User_Licenses';      Data = $Data.UserLicenses },
        @{ Name = '08_Approval_Settings';  Data = $Data.ApprovalSettings },
        @{ Name = '09_Approval_History';   Data = $Data.ApprovalHistory },
        @{ Name = '10_User_Access_Paths';  Data = $userAccessPaths },
        @{ Name = '11_User_Role_Summary';  Data = $userRoleSummary },
        @{ Name = '12_Group_Role_Summary'; Data = $groupRoleSummary },
        @{ Name = '13_Activation_Requests'; Data = $Data.ActivationRequests },
        @{ Name = '14_Activation_Anomalies'; Data = $Data.ActivationAnomalies },
        @{ Name = '15_Conditional_Access'; Data = $Data.ConditionalAccessPolicies },
        @{ Name = '16_Access_Reviews';     Data = $Data.AccessReviews },
        @{ Name = '17_Workload_Risk';      Data = $Data.WorkloadIdentityRisk },
        @{ Name = '18_Nested_Group_Paths'; Data = $Data.NestedGroupPaths },
        @{ Name = '19_SoD_Conflicts';      Data = $sodConflicts },
        @{ Name = '20_Findings';           Data = $findings },
        @{ Name = '21_User_Elevation_Paths'; Data = $userElevationPaths },
        @{ Name = '22_Role_Elevation_Matrix';     Data = $roleElevationMatrixExport },
        @{ Name = '23_Privilege_Concentration';    Data = $privilegeConcentration },
        @{ Name = '24_JIT_Effectiveness';          Data = if ($null -ne $jitEffectiveness) { @($jitEffectiveness) } else { @() } },
        @{ Name = '25_Guest_Privileged';           Data = $guestPrivilegedAccounts },
        @{ Name = '26_Naming_Compliance';          Data = $namingCompliance },
        @{ Name = '27_Licensed_Admins';            Data = $licensedPrivilegedAccounts },
        @{ Name = '28_Identity_Assurance';         Data = $identityAssuranceProfiles },
        @{ Name = '29_Auth_Strength';              Data = $authStrengthData },
        @{ Name = '30_CA_Coverage';                Data = $caCoverageData },
        @{ Name = '31_Approval_Analysis';          Data = if ($Data.ContainsKey('ApprovalAnalysis') -and $Data.ApprovalAnalysis) { @($Data.ApprovalAnalysis) } else { @() } },
        @{ Name = '32_Approver_Profiles';          Data = if ($Data.ContainsKey('ApproverProfiles') -and $Data.ApproverProfiles) { @($Data.ApproverProfiles) } else { @() } },
        @{ Name = '33_Approver_Group_Role_Map';    Data = if ($Data.ContainsKey('ApproverGroupRoleMap') -and $Data.ApproverGroupRoleMap) { @($Data.ApproverGroupRoleMap) } else { @() } }
    )

    foreach ($sheet in $sheetMap) {
        $rows = @($sheet.Data)
        if ($rows.Count -eq 0) {
            $rows = @([pscustomobject]@{ Info = 'No data returned for this sheet.' })
        }

        $tableName = ($sheet.Name -replace '[^A-Za-z0-9_]', '_')
        if ($tableName -notmatch '^[A-Za-z]') {
            $tableName = "T_$tableName"
        }

        $rows | Export-Excel -Path $workbookPath -WorksheetName $sheet.Name -TableName $tableName -AutoSize -FreezeTopRow -AutoFilter -Append
    }

    try {
        $cfCmd = Get-Command Add-ConditionalFormatting -ErrorAction SilentlyContinue
        if ($cfCmd -and $cfCmd.Parameters.ContainsKey('Path')) {
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '10_User_Access_Paths' -Address 'L:L' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '10_User_Access_Paths' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '10_User_Access_Paths' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Low' -BackgroundColor 'LightGreen'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '00_Executive_Scorecard' -Address 'C:C' -RuleType ContainsText -ConditionValue 'Red' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '00_Executive_Scorecard' -Address 'C:C' -RuleType ContainsText -ConditionValue 'Amber' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '00_Executive_Scorecard' -Address 'C:C' -RuleType ContainsText -ConditionValue 'Green' -BackgroundColor 'LightGreen'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '19_SoD_Conflicts' -Address 'G:G' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '19_SoD_Conflicts' -Address 'G:G' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '20_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '20_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '20_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'Low' -BackgroundColor 'LightGreen'
            # Sheet 22 — Role Elevation Matrix: colour-code RiskRating column (column C in export projection)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '22_Role_Elevation_Matrix' -Address 'C:C' -RuleType ContainsText -ConditionValue 'Critical' -BackgroundColor 'LightCoral'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '22_Role_Elevation_Matrix' -Address 'C:C' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '22_Role_Elevation_Matrix' -Address 'C:C' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '22_Role_Elevation_Matrix' -Address 'C:C' -RuleType ContainsText -ConditionValue 'Low' -BackgroundColor 'LightGreen'

            # Friction score column E: quickly identify low-friction high-risk roles.
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '22_Role_Elevation_Matrix' -Address 'E:E' -RuleType LessThan -ConditionValue 20 -BackgroundColor 'LightCoral'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '22_Role_Elevation_Matrix' -Address 'E:E' -RuleType Between -ConditionValue '20,49' -BackgroundColor 'Khaki'
            # Sheet 23 -- Privilege Concentration: colour-code ConcentrationRisk column (column L)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '23_Privilege_Concentration' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Critical' -BackgroundColor 'LightCoral'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '23_Privilege_Concentration' -Address 'L:L' -RuleType ContainsText -ConditionValue 'High'     -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '23_Privilege_Concentration' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Medium'   -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '23_Privilege_Concentration' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Low'      -BackgroundColor 'LightGreen'
            # Sheet 25 -- Guest Privileged: GuestRiskRating (column O)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '25_Guest_Privileged' -Address 'O:O' -RuleType ContainsText -ConditionValue 'Critical' -BackgroundColor 'LightCoral'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '25_Guest_Privileged' -Address 'O:O' -RuleType ContainsText -ConditionValue 'High'     -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '25_Guest_Privileged' -Address 'O:O' -RuleType ContainsText -ConditionValue 'Medium'   -BackgroundColor 'Khaki'
            # Sheet 26 -- Naming Compliance: ComplianceRiskRating (column I)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '26_Naming_Compliance' -Address 'I:I' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '26_Naming_Compliance' -Address 'I:I' -RuleType ContainsText -ConditionValue 'Low'  -BackgroundColor 'LightGreen'
            # Sheet 27 -- Licensed Admins: LicensedAdminRiskRating (column L)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '27_Licensed_Admins' -Address 'L:L' -RuleType ContainsText -ConditionValue 'High'   -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '27_Licensed_Admins' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '27_Licensed_Admins' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Low'    -BackgroundColor 'LightGreen'
            # Sheet 28 -- Identity Assurance: IdentityRiskRating (column Q)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '28_Identity_Assurance' -Address 'Q:Q' -RuleType ContainsText -ConditionValue 'Critical' -BackgroundColor 'LightCoral'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '28_Identity_Assurance' -Address 'Q:Q' -RuleType ContainsText -ConditionValue 'High'     -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '28_Identity_Assurance' -Address 'Q:Q' -RuleType ContainsText -ConditionValue 'Medium'   -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '28_Identity_Assurance' -Address 'Q:Q' -RuleType ContainsText -ConditionValue 'Low'      -BackgroundColor 'LightGreen'
            # Sheet 29 -- Auth Strength: AuthStrength (col D), AuthRiskRating (col L)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '29_Auth_Strength' -Address 'D:D' -RuleType ContainsText -ConditionValue 'PhishingResistant' -BackgroundColor 'LightGreen'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '29_Auth_Strength' -Address 'D:D' -RuleType ContainsText -ConditionValue 'WeakOrNone'        -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '29_Auth_Strength' -Address 'L:L' -RuleType ContainsText -ConditionValue 'High'              -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '29_Auth_Strength' -Address 'L:L' -RuleType ContainsText -ConditionValue 'Low'               -BackgroundColor 'LightGreen'
            # Sheet 30 -- CA Coverage: RiskRating (column J)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '30_CA_Coverage' -Address 'J:J' -RuleType ContainsText -ConditionValue 'High'   -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '30_CA_Coverage' -Address 'J:J' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '30_CA_Coverage' -Address 'J:J' -RuleType ContainsText -ConditionValue 'Low'    -BackgroundColor 'LightGreen'
            # Sheet 31 -- Approval Analysis: ApprovalIntegrity (col H), RiskRating (col I)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '31_Approval_Analysis' -Address 'H:H' -RuleType ContainsText -ConditionValue 'Broken'   -BackgroundColor 'LightCoral'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '31_Approval_Analysis' -Address 'H:H' -RuleType ContainsText -ConditionValue 'Weak'     -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '31_Approval_Analysis' -Address 'H:H' -RuleType ContainsText -ConditionValue 'Moderate' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '31_Approval_Analysis' -Address 'H:H' -RuleType ContainsText -ConditionValue 'Strong'   -BackgroundColor 'LightGreen'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '31_Approval_Analysis' -Address 'I:I' -RuleType ContainsText -ConditionValue 'High'     -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '31_Approval_Analysis' -Address 'I:I' -RuleType ContainsText -ConditionValue 'Medium'   -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '31_Approval_Analysis' -Address 'I:I' -RuleType ContainsText -ConditionValue 'Low'      -BackgroundColor 'LightGreen'
            # Sheet 32 -- Approver Profiles: IsGuest (col K), IsPrivileged (col M)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '32_Approver_Profiles' -Address 'K:K' -RuleType ContainsText -ConditionValue 'True'  -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '32_Approver_Profiles' -Address 'M:M' -RuleType ContainsText -ConditionValue 'True'  -BackgroundColor 'LightSalmon'
            # Sheet 33 -- Approver Group Role Map: GuestMembers (col G), PrivilegedMembers (col H)
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '33_Approver_Group_Role_Map' -Address 'G:G' -RuleType GreaterThan -ConditionValue '0' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '33_Approver_Group_Role_Map' -Address 'H:H' -RuleType GreaterThan -ConditionValue '0' -BackgroundColor 'LightSalmon'
        }
        else {
            Write-PimLog -Level WARN -Message 'Conditional formatting skipped for this ImportExcel version (no Path parameter support).'
        }
    }
    catch {
        Write-PimLog -Level WARN -Message "Conditional formatting could not be fully applied: $($_.Exception.Message)"
    }

    Write-PimLog -Message "Workbook generated: $workbookPath"

    return [pscustomobject]@{
        WorkbookCreated = $true
        WorkbookPath    = $workbookPath
        Findings        = $findings
        Summary         = $summary
        UserAccessPaths = $userAccessPaths
        UserRoleSummary = $userRoleSummary
        GroupRoleSummary = $groupRoleSummary
        SoDConflicts    = $sodConflicts
        UserElevationPaths = $userElevationPaths
        ExecutiveScorecard = $executiveScorecard
        RoleElevationMatrix = $roleElevationMatrix
        PrivilegeConcentration = $privilegeConcentration
        JitEffectiveness = $jitEffectiveness
        KeyInsights      = $keyInsights
        GuestPrivilegedAccounts    = $guestPrivilegedAccounts
        NamingCompliance           = $namingCompliance
        LicensedPrivilegedAccounts = $licensedPrivilegedAccounts
        IdentityAssuranceProfiles  = $identityAssuranceProfiles
        ApprovalAnalysis           = if ($Data.ContainsKey('ApprovalAnalysis') -and $Data.ApprovalAnalysis) { @($Data.ApprovalAnalysis) } else { @() }
        ApproverGroupRoleMap       = if ($Data.ContainsKey('ApproverGroupRoleMap') -and $Data.ApproverGroupRoleMap) { @($Data.ApproverGroupRoleMap) } else { @() }
    }
}


if ($MyInvocation.InvocationName -ne '.') {
    Write-Warning 'Build-PimReviewWorkbook.ps1 is intended to be dot-sourced by Invoke-FullPimReview.ps1, not run directly. Use Invoke-FullPimReview.ps1 instead.'
}


