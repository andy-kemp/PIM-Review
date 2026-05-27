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

function Build-PimReviewWorkbook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data,

        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

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

    $findingsCsvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\Findings.csv'
    Export-PimData -Data $findings -CsvPath $findingsCsvPath

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

    $workbookPath = Join-Path -Path $OutputFolder -ChildPath 'PIM_Review_Workbook.xlsx'

    if (-not $excelAvailable) {
        Write-PimLog -Level WARN -Message 'ImportExcel module is not installed. Workbook generation skipped; CSV evidence is still available.'
        return [pscustomobject]@{
            WorkbookCreated = $false
            WorkbookPath    = $null
            Findings        = $findings
            Summary         = $summary
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
        @{ Name = '10_Findings';           Data = $findings }
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
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '10_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'High' -BackgroundColor 'LightSalmon'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '10_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'Medium' -BackgroundColor 'Khaki'
            Add-ConditionalFormatting -Path $workbookPath -WorksheetName '10_Findings' -Address 'B:B' -RuleType ContainsText -ConditionValue 'Low' -BackgroundColor 'LightGreen'
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
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Build-PimReviewWorkbook @PSBoundParameters
}


