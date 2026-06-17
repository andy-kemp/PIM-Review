<#
.SYNOPSIS
Builds the PIM review workbook and derived findings from exported datasets.

.DESCRIPTION
Creates a single Excel workbook with multiple review sheets using ImportExcel when available.
If ImportExcel is unavailable, leaves CSV outputs in place and logs a warning.

.EXAMPLE
./Build-PimReviewWorkbook.ps1 -Data $data -Config $config -OutputFolder .\Output -Verbose
#>
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

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
Import-Module -Name $commonModulePath -DisableNameChecking

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

        $riskReasons = New-Object System.Collections.Generic.List[string]
        if ($highImpact.Count -gt 0) {
            $riskReasons.Add('Group holds high-impact roles')
        }
        if ($memberGuests.Count -gt 0) {
            $riskReasons.Add('Group includes guest members')
        }
        if ($memberNestedGroups.Count -gt 0) {
            $riskReasons.Add('Group includes nested groups (indirect path complexity)')
        }

        $risk = if ($highImpact.Count -gt 0 -or ($memberGuests.Count -gt 0 -and $roles.Count -gt 0)) {
            'High'
        }
        elseif ($roles.Count -gt 0) {
            'Medium'
        }
        else {
            'Low'
        }

        $rows += [pscustomobject]@{
            GroupId                    = $groupId
            GroupDisplayName           = $group.GroupDisplayName
            IsRoleAssignable           = $group.IsRoleAssignable
            DistinctRoleCount          = $roles.Count
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
        @{ A = 'Privileged Role Administrator'; B = 'Conditional Access Administrator'; Risk = 'High'; Why = 'Can assign privileged roles and alter protection controls.' },
        @{ A = 'Global Administrator'; B = 'Privileged Role Administrator'; Risk = 'High'; Why = 'Broad tenant control with role governance control concentration.' },
        @{ A = 'Security Administrator'; B = 'Exchange Administrator'; Risk = 'Medium'; Why = 'Cross-domain control may reduce segregation of duties.' },
        @{ A = 'Authentication Administrator'; B = 'User Administrator'; Risk = 'Medium'; Why = 'Identity lifecycle and authentication factor control combined.' }
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

function Build-PimReviewWorkbook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data,

        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [string]$WorkbookFileName,

        [switch]$InstallImportExcelIfMissing,

        [switch]$PromptToInstallImportExcel,

        [switch]$ReturnObjectsOnly
    )

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

    $userRoleSummary = New-UserRoleSummary -UserAccessPaths $userAccessPaths
    $groupRoleSummary = New-GroupRoleSummary `
        -PrivilegedGroups $Data.PrivilegedGroups `
        -RoleAssignments $Data.RoleAssignments `
        -GroupMembers $Data.GroupMembers `
        -HighImpactRoles @($Config.HighImpactRoles)

    $sodConflicts = New-SodConflicts -UserAccessPaths $userAccessPaths

    $findingsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\Findings.csv'
    Export-PimData -Data $findings -CsvPath $findingsCsvPath

    $accessPathsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\UserAccessPaths.csv'
    Export-PimData -Data $userAccessPaths -CsvPath $accessPathsCsvPath

    $userRoleSummaryCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\UserRoleAccessSummary.csv'
    Export-PimData -Data $userRoleSummary -CsvPath $userRoleSummaryCsvPath

    $groupRoleSummaryCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\GroupRoleAccessSummary.csv'
    Export-PimData -Data $groupRoleSummary -CsvPath $groupRoleSummaryCsvPath

    $sodConflictsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\SoDConflicts.csv'
    Export-PimData -Data $sodConflicts -CsvPath $sodConflictsCsvPath

    $excelAvailable = Test-ImportExcelAvailable

    if (-not $excelAvailable) {
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
                $excelAvailable = Test-ImportExcelAvailable
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
        Write-PimLog -Level WARN -Message 'ImportExcel module is not installed. Workbook generation skipped; CSV evidence is still available.'
        return [pscustomobject]@{
            WorkbookCreated = $false
            WorkbookPath    = $null
            Findings        = $findings
            Summary         = $summary
            UserAccessPaths = $userAccessPaths
            UserRoleSummary = $userRoleSummary
            GroupRoleSummary = $groupRoleSummary
            SoDConflicts    = $sodConflicts
        }
    }

    Import-Module ImportExcel -ErrorAction Stop
    if (Test-Path -Path $workbookPath) {
        Remove-Item -Path $workbookPath -Force
    }

    $sheetMap = @(
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
        @{ Name = '20_Findings';           Data = $findings }
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
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '19_SoD_Conflicts' -Address 'G:G' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '19_SoD_Conflicts' -Address 'G:G' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '20_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '20_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '20_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'Low' -BackgroundColor 'LightGreen'
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
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Build-PimReviewWorkbook @PSBoundParameters
}


