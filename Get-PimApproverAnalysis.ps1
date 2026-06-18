<#
.SYNOPSIS
Performs deep approval model analysis for PIM-protected privileged roles.

.DESCRIPTION
For every role that has approval configured this script:
  - Identifies whether each configured approver is a User or a Group
  - Classifies group type (Security / Microsoft 365 / Distribution / Unknown)
  - Expands group-based approvers to their full membership (with one level of nested group resolution)
  - Enriches each effective approver with: IsGuest, NamingCompliant, IsLicensed, IsPrivileged
  - Tests approval integrity by comparing approver identities against role holders:
      Broken   - effective self-approval (exact match or heuristic alias match)
      Weak     - approvers are themselves privileged users
      Moderate - guest approvers, external tenant identities, or unclear type mapping
      Strong   - no overlap, all approvers identified and clean
  - Flags high-risk scenarios as structured findings
  - Produces:
      ApprovalAnalysis  - per-role summary rows (Excel sheet 31_Approval_Analysis)
      ApproverProfiles  - per-expanded-member rows (Excel sheet 32_Approver_Profiles)
      ApprovalFindings  - findings for inclusion in the main findings set

Graph scopes required (already collected by Connect-GraphForPimReview):
  - GroupMember.Read.All
  - User.Read.All

.EXAMPLE
$result = Get-PimApproverAnalysis -PolicyFlatRules $policyData.FlatRules -RoleAssignments $roleAssignments -Config $config -OutputFolder $runOutputFolder -ReturnObjectsOnly
#>
[CmdletBinding()]
param(
    [object[]]$PolicyFlatRules,
    [object[]]$RoleAssignments,
    [hashtable]$Config,
    [string]$OutputFolder,
    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

# ─── Group-type classification ────────────────────────────────────────────────

function Get-GroupType {
    <#
    .SYNOPSIS
    Classifies a group object returned from Microsoft Graph as:
      Microsoft365 - Unified group (groupTypes contains 'Unified')
      Distribution - Mail-enabled, not security-enabled
      Security     - Security-enabled group
      Unknown      - Cannot determine from available properties
    #>
    [CmdletBinding()]
    param([object]$GroupObj)

    if (-not $GroupObj) { return 'Unknown' }

    $groupTypes = @()
    if ($null -ne $GroupObj.PSObject.Properties['groupTypes'] -and $GroupObj.groupTypes) {
        $groupTypes = @($GroupObj.groupTypes)
    }

    if ('Unified' -in $groupTypes) { return 'Microsoft365' }

    $mailEnabled     = if ($null -ne $GroupObj.PSObject.Properties['mailEnabled'])     { $GroupObj.mailEnabled }     else { $null }
    $securityEnabled = if ($null -ne $GroupObj.PSObject.Properties['securityEnabled']) { $GroupObj.securityEnabled } else { $null }

    if ($mailEnabled -eq $true -and ($securityEnabled -eq $false -or $null -eq $securityEnabled)) { return 'Distribution' }
    if ($securityEnabled -eq $true) { return 'Security' }
    return 'Unknown'
}

# ─── Cached group detail fetch ────────────────────────────────────────────────

function Get-ApproverGroupDetails {
    <#
    .SYNOPSIS
    Fetches a group from Graph including securityEnabled/mailEnabled/groupTypes.
    Results are cached in the provided hashtable to avoid duplicate API calls.
    #>
    [CmdletBinding()]
    param(
        [string]$GroupId,
        [hashtable]$Cache
    )

    if ([string]::IsNullOrWhiteSpace($GroupId)) { return $null }
    if ($Cache.ContainsKey($GroupId)) { return $Cache[$GroupId] }

    $uri = "https://graph.microsoft.com/v1.0/groups/${GroupId}?`$select=id,displayName,mail,securityEnabled,mailEnabled,groupTypes,isAssignableToRole"
    try {
        $group = Invoke-GraphRequestWithRetry -Uri $uri
        $Cache[$GroupId] = $group
        return $group
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to fetch group details for $GroupId : $($_.Exception.Message)"
        $Cache[$GroupId] = $null
        return $null
    }
}

# ─── Group membership expansion ───────────────────────────────────────────────

function Get-GroupMembersExpanded {
    <#
    .SYNOPSIS
    Returns all user members of a group, expanding one level of nested groups.
    Each returned object includes: UserId, DisplayName, UserPrincipalName, UserType,
    IsLicensed, SourceGroup, NestedViaGroup, MemberSource (Direct / Nested).
    Results are cached in MemberCache keyed by GroupId.
    #>
    [CmdletBinding()]
    param(
        [string]$GroupId,
        [string]$GroupDisplayName,
        [hashtable]$MemberCache,
        [hashtable]$DetailCache
    )

    if ([string]::IsNullOrWhiteSpace($GroupId)) { return @() }
    if ($MemberCache.ContainsKey($GroupId)) { return $MemberCache[$GroupId] }

    $members = New-Object System.Collections.Generic.List[object]

    $uri = "https://graph.microsoft.com/v1.0/groups/${GroupId}/members?`$select=id,displayName,userPrincipalName,userType,mail,assignedLicenses"
    $rawMembers = @()
    try {
        $rawMembers = @(Get-GraphPagedResults -Uri $uri)
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve members for approver group '$GroupDisplayName' ($GroupId): $($_.Exception.Message)"
        $MemberCache[$GroupId] = @()
        return @()
    }

    # We also need @odata.type — use the directoryObjects endpoint fallback if needed
    foreach ($member in $rawMembers) {
        $odataType = if ($null -ne $member.PSObject.Properties['@odata.type']) { [string]$member.'@odata.type' } else { '' }
        $memberId  = if ($member.id) { [string]$member.id } else { '' }
        if ([string]::IsNullOrWhiteSpace($memberId)) { continue }

        # Determine object type
        $isGroupMember = $odataType -match 'group'
        $isUserMember  = ($odataType -match 'user') -or ($null -ne $member.PSObject.Properties['userPrincipalName'] -and $member.userPrincipalName)

        if ($isGroupMember) {
            # Nested group — resolve one level deeper
            $nestedId          = $memberId
            $nestedDisplayName = if ($member.displayName) { [string]$member.displayName } else { $nestedId }

            $nestedUri = "https://graph.microsoft.com/v1.0/groups/${nestedId}/members?`$select=id,displayName,userPrincipalName,userType,mail,assignedLicenses"
            $nestedRaw = @()
            try {
                if ($MemberCache.ContainsKey($nestedId)) {
                    $nestedRaw = @($MemberCache[$nestedId] | Where-Object { $_.UserId })
                }
                else {
                    $nestedRaw = @(Get-GraphPagedResults -Uri $nestedUri)
                }
            }
            catch {
                Write-PimLog -Level WARN -Message "Unable to retrieve nested group members for '$nestedDisplayName' ($nestedId): $($_.Exception.Message)"
            }

            foreach ($nm in $nestedRaw) {
                $nmOdataType = if ($null -ne $nm.PSObject.Properties['@odata.type']) { [string]$nm.'@odata.type' } else { '' }
                # Skip further nested groups at depth > 1
                if ($nmOdataType -match 'group') { continue }

                $nmUpn       = if ($null -ne $nm.PSObject.Properties['userPrincipalName'] -and $nm.userPrincipalName) { [string]$nm.userPrincipalName } else { $null }
                $nmUserType  = if ($null -ne $nm.PSObject.Properties['userType'] -and $nm.userType) { [string]$nm.userType } else { 'Member' }
                $nmLicensed  = $null -ne $nm.PSObject.Properties['assignedLicenses'] -and $nm.assignedLicenses -and @($nm.assignedLicenses).Count -gt 0

                $members.Add([pscustomobject]@{
                    UserId            = [string]$nm.id
                    DisplayName       = if ($nm.displayName) { [string]$nm.displayName } else { $null }
                    UserPrincipalName = $nmUpn
                    UserType          = $nmUserType
                    IsLicensed        = $nmLicensed
                    SourceGroup       = $GroupDisplayName
                    NestedViaGroup    = $nestedDisplayName
                    MemberSource      = 'Nested'
                })
            }
        }
        elseif ($isUserMember) {
            $upn      = if ($null -ne $member.PSObject.Properties['userPrincipalName'] -and $member.userPrincipalName) { [string]$member.userPrincipalName } else { $null }
            $userType = if ($null -ne $member.PSObject.Properties['userType'] -and $member.userType) { [string]$member.userType } else { 'Member' }
            $licensed = $null -ne $member.PSObject.Properties['assignedLicenses'] -and $member.assignedLicenses -and @($member.assignedLicenses).Count -gt 0

            $members.Add([pscustomobject]@{
                UserId            = $memberId
                DisplayName       = if ($member.displayName) { [string]$member.displayName } else { $null }
                UserPrincipalName = $upn
                UserType          = $userType
                IsLicensed        = $licensed
                SourceGroup       = $GroupDisplayName
                NestedViaGroup    = $null
                MemberSource      = 'Direct'
            })
        }
        # Service principals or unknown types in approver groups are silently skipped
    }

    $result = @($members)
    $MemberCache[$GroupId] = $result
    return $result
}

# ─── Approver profile builder ─────────────────────────────────────────────────

function Get-ApproverProfiles {
    <#
    .SYNOPSIS
    Resolves each approver ID (User or Group) and produces one enriched profile row per
    effective approver member. Groups are expanded via Get-GroupMembersExpanded.
    #>
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [string]$ApproverIds,
        [string]$ApproverDisplayNames,
        [string]$NamingPrefix,
        [hashtable]$PrivilegedUserHash,
        [hashtable]$GroupMemberCache,
        [hashtable]$GroupDetailCache
    )

    $profiles = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($ApproverIds)) { return @() }

    $prefixPattern = '^' + [regex]::Escape($NamingPrefix)
    $ids   = @(($ApproverIds          -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $names = @(($ApproverDisplayNames -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    for ($i = 0; $i -lt $ids.Count; $i++) {
        $approverId          = $ids[$i]
        $approverDisplayName = if ($i -lt $names.Count) { $names[$i] } else { $approverId }

        # Resolve object type from Graph
        $obj       = Resolve-DirectoryObject -ObjectId $approverId
        $odataType = if ($obj -and ($null -ne $obj.PSObject.Properties['@odata.type'])) { [string]$obj.'@odata.type' } else { '' }

        $objectType = 'Unknown'
        if     ($odataType -match 'user')  { $objectType = 'User' }
        elseif ($odataType -match 'group') { $objectType = 'Group' }
        elseif ($obj -and ($null -ne $obj.PSObject.Properties['userPrincipalName']) -and $obj.userPrincipalName) { $objectType = 'User' }
        elseif ($obj -and ($null -ne $obj.PSObject.Properties['isAssignableToRole'])) { $objectType = 'Group' }

        if ($objectType -eq 'User') {
            # Resolve user with license data
            $userObj    = Resolve-User -UserId $approverId
            $upn        = if ($userObj -and ($null -ne $userObj.PSObject.Properties['userPrincipalName'])) { [string]$userObj.userPrincipalName } else { $null }
            $displayName = if ($userObj -and $userObj.displayName) { [string]$userObj.displayName } else { $approverDisplayName }
            $userType   = if ($upn -match '#EXT#') { 'Guest' } else { 'Member' }
            $isGuest    = ($userType -eq 'Guest')
            $isNamingCompliant = if ($upn -and -not $isGuest) { $upn -match $prefixPattern } else { $true }
            $isLicensed = $userObj -and ($null -ne $userObj.PSObject.Properties['assignedLicenses']) -and $userObj.assignedLicenses -and @($userObj.assignedLicenses).Count -gt 0
            $isPrivileged = $PrivilegedUserHash.ContainsKey($approverId)

            $profiles.Add([pscustomobject]@{
                RoleName           = $RoleName
                ApproverObjectId   = $approverId
                ApproverObjectType = 'User'
                GroupName          = $null
                GroupType          = $null
                UserId             = $approverId
                UserPrincipalName  = $upn
                DisplayName        = $displayName
                UserType           = $userType
                IsGuest            = $isGuest
                NamingCompliant    = $isNamingCompliant
                IsLicensed         = $isLicensed
                AuthStrength       = 'Unknown'
                IsPrivileged       = $isPrivileged
                SourceGroup        = $null
                MemberSource       = 'Direct'
            })
        }
        elseif ($objectType -eq 'Group') {
            $groupObj         = Get-ApproverGroupDetails -GroupId $approverId -Cache $GroupDetailCache
            $groupDisplayName = if ($groupObj -and $groupObj.displayName) { [string]$groupObj.displayName } else { $approverDisplayName }
            $groupType        = Get-GroupType -GroupObj $groupObj

            $groupMembers = @(Get-GroupMembersExpanded `
                -GroupId          $approverId `
                -GroupDisplayName $groupDisplayName `
                -MemberCache      $GroupMemberCache `
                -DetailCache      $GroupDetailCache)

            if ($groupMembers.Count -eq 0) {
                # Empty group — still record a sentinel row so the analysis can flag it
                $profiles.Add([pscustomobject]@{
                    RoleName           = $RoleName
                    ApproverObjectId   = $approverId
                    ApproverObjectType = 'Group'
                    GroupName          = $groupDisplayName
                    GroupType          = $groupType
                    UserId             = $null
                    UserPrincipalName  = $null
                    DisplayName        = "(empty group: $groupDisplayName)"
                    UserType           = $null
                    IsGuest            = $false
                    NamingCompliant    = $false
                    IsLicensed         = $false
                    AuthStrength       = 'Unknown'
                    IsPrivileged       = $false
                    SourceGroup        = $groupDisplayName
                    MemberSource       = 'Direct'
                })
            }
            else {
                foreach ($member in $groupMembers) {
                    $upn              = if ($member.UserPrincipalName) { [string]$member.UserPrincipalName } else { $null }
                    $isGuest          = ($member.UserType -ieq 'Guest') -or ($upn -and $upn -match '#EXT#')
                    $isNamingCompliant = if ($upn -and -not $isGuest) { $upn -match $prefixPattern } else { $true }
                    $isPrivileged     = $member.UserId -and $PrivilegedUserHash.ContainsKey([string]$member.UserId)

                    $profiles.Add([pscustomobject]@{
                        RoleName           = $RoleName
                        ApproverObjectId   = $approverId
                        ApproverObjectType = 'Group'
                        GroupName          = $groupDisplayName
                        GroupType          = $groupType
                        UserId             = $member.UserId
                        UserPrincipalName  = $upn
                        DisplayName        = $member.DisplayName
                        UserType           = if ($isGuest) { 'Guest' } else { $member.UserType }
                        IsGuest            = $isGuest
                        NamingCompliant    = $isNamingCompliant
                        IsLicensed         = $member.IsLicensed
                        AuthStrength       = 'Unknown'
                        IsPrivileged       = $isPrivileged
                        SourceGroup        = $groupDisplayName
                        MemberSource       = $member.MemberSource
                    })
                }
            }
        }
        else {
            # Unresolvable approver — record Unknown sentinel
            $profiles.Add([pscustomobject]@{
                RoleName           = $RoleName
                ApproverObjectId   = $approverId
                ApproverObjectType = 'Unknown'
                GroupName          = $null
                GroupType          = $null
                UserId             = $approverId
                UserPrincipalName  = $null
                DisplayName        = $approverDisplayName
                UserType           = 'Unknown'
                IsGuest            = $false
                NamingCompliant    = $false
                IsLicensed         = $false
                AuthStrength       = 'Unknown'
                IsPrivileged       = $false
                SourceGroup        = $null
                MemberSource       = 'Direct'
            })
        }
    }

    return @($profiles)
}

# ─── Approval integrity classification ────────────────────────────────────────

function Test-ApprovalIntegrity {
    <#
    .SYNOPSIS
    Classifies the approval integrity for a role based on comparing approver profiles
    to role privileged user IDs and UPNs.

    Returns one of: Broken / Weak / Moderate / Strong

    Broken   : No effective approvers, OR exact user-ID overlap, OR heuristic alias match
               (same person via CLAD_ admin account and regular account)
    Weak     : Approvers hold any privileged role (general privilege, not necessarily this one)
    Moderate : Guest approvers present, or unknown approver types
    Strong   : Clean approver set, no overlap with role holders
    #>
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [object[]]$ApproverProfiles,
        [string[]]$RolePrivilegedUserIds,
        [string[]]$RolePrivilegedUpns,
        [string]$NamingPrefix
    )

    # No effective approvers at all
    $effectiveProfiles = @($ApproverProfiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserId) })
    if ($effectiveProfiles.Count -eq 0) { return 'Broken' }

    $prefixPattern = '^' + [regex]::Escape($NamingPrefix)

    # Build approver user ID set
    $approverIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $effectiveProfiles) {
        if ($p.UserId) { [void]$approverIds.Add([string]$p.UserId) }
    }

    # Build approver alias set (strip naming prefix for heuristic matching)
    $approverAliases = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $effectiveProfiles) {
        if ($p.UserPrincipalName) {
            $alias = ($p.UserPrincipalName -split '@')[0] -replace $prefixPattern, ''
            if ($alias.Length -gt 2) { [void]$approverAliases.Add($alias.ToLowerInvariant()) }
        }
    }

    # Build role user ID set
    $roleIdSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in @($RolePrivilegedUserIds | Where-Object { $_ })) { [void]$roleIdSet.Add([string]$id) }

    # Test 1: Exact user-ID overlap → Broken (same account is both approver and role holder)
    $directOverlap = @($approverIds | Where-Object { $roleIdSet.Contains($_) })
    if ($directOverlap.Count -gt 0) { return 'Broken' }

    # Test 2: Heuristic alias match → Broken (same person via alternate account)
    foreach ($upn in @($RolePrivilegedUpns | Where-Object { $_ })) {
        $roleAlias = ($upn -split '@')[0] -replace $prefixPattern, ''
        if ($roleAlias.Length -gt 2 -and $approverAliases.Contains($roleAlias.ToLowerInvariant())) {
            return 'Broken'
        }
    }

    # Test 3: Approver is itself a privileged user → Weak (separation of duty concern)
    $privilegedApprovers = @($effectiveProfiles | Where-Object { $_.IsPrivileged -eq $true })
    if ($privilegedApprovers.Count -gt 0) { return 'Weak' }

    # Test 4: Moderate conditions
    $guestApprovers   = @($effectiveProfiles | Where-Object { $_.IsGuest -eq $true })
    $unknownApprovers = @($ApproverProfiles  | Where-Object { $_.ApproverObjectType -eq 'Unknown' })
    if ($guestApprovers.Count -gt 0 -or $unknownApprovers.Count -gt 0) { return 'Moderate' }

    return 'Strong'
}

# ─── High-risk findings generator ────────────────────────────────────────────

function Add-ApprovalFindings {
    <#
    .SYNOPSIS
    Appends approval model risk findings to FindingsList based on the resolved
    approver profiles and computed integrity classification for a role.
    #>
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [object[]]$ApproverProfiles,
        [string]$ApprovalIntegrity,
        [System.Collections.Generic.List[object]]$FindingsList
    )

    $evidenceId = "ApprovalAnalysis_$RoleName"

    switch ($ApprovalIntegrity) {
        'Broken' {
            $effectiveCount = @($ApproverProfiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserId) }).Count
            if ($effectiveCount -eq 0) {
                $FindingsList.Add([pscustomobject]@{
                    FindingType = 'Approval Gate Broken - No Effective Approvers'
                    RiskRating  = 'High'
                    Subject     = $RoleName
                    RoleName    = $RoleName
                    Details     = "Role '$RoleName' requires approval, but all configured approver groups resolve to zero effective members. Activation requests may be permanently blocked or silently bypassed depending on Entra ID policy evaluation behaviour."
                    EvidenceId  = $evidenceId
                })
            }
            else {
                $FindingsList.Add([pscustomobject]@{
                    FindingType = 'Approval Model Allows Effective Self-Approval'
                    RiskRating  = 'High'
                    Subject     = $RoleName
                    RoleName    = $RoleName
                    Details     = "Approval model for '$RoleName' allows effective self-approval: the same identity (or an alternate admin account of the same person) appears in both the approver list and the role assignee list. This defeats the intent of the approval gate."
                    EvidenceId  = $evidenceId
                })
            }
        }
        'Weak' {
            $privApprovers = @($ApproverProfiles | Where-Object { $_.IsPrivileged -eq $true } | Select-Object -ExpandProperty DisplayName -Unique | Select-Object -First 3)
            $privLabel     = if ($privApprovers.Count -gt 0) { ($privApprovers -join ', ') } else { 'one or more approvers' }
            $FindingsList.Add([pscustomobject]@{
                FindingType = 'Approver Group Contains Privileged Users'
                RiskRating  = 'High'
                Subject     = $RoleName
                RoleName    = $RoleName
                Details     = "Approval for '$RoleName' relies on users who themselves hold privileged roles (e.g. $privLabel). Privileged users approving access for this role reduces separation of duties and creates a governance concentration risk."
                EvidenceId  = $evidenceId
            })
        }
    }

    # Guest approvers (regardless of integrity classification)
    $guestApprovers = @($ApproverProfiles | Where-Object { $_.IsGuest -eq $true })
    if ($guestApprovers.Count -gt 0) {
        $guestNames = ($guestApprovers | Select-Object -ExpandProperty DisplayName -Unique | Where-Object { $_ } | Select-Object -First 3) -join ', '
        $FindingsList.Add([pscustomobject]@{
            FindingType = 'Approver Group Contains Guest Users'
            RiskRating  = 'Medium'
            Subject     = $RoleName
            RoleName    = $RoleName
            Details     = "The approval group for '$RoleName' contains $($guestApprovers.Count) guest (external) identity/identities as effective approvers (e.g. $guestNames). Guest accounts are not managed through this organisation's identity lifecycle and may represent stale access from former staff or external parties."
            EvidenceId  = $evidenceId
        })
    }

    # External tenant (#EXT#) approvers
    $extApprovers = @($ApproverProfiles | Where-Object { $_.UserPrincipalName -and $_.UserPrincipalName -match '#EXT#' })
    if ($extApprovers.Count -gt 0) {
        $FindingsList.Add([pscustomobject]@{
            FindingType = 'Approval Relies on External Tenant Identities'
            RiskRating  = 'Medium'
            Subject     = $RoleName
            RoleName    = $RoleName
            Details     = "Approval for '$RoleName' is reliant on $($extApprovers.Count) external (#EXT#) tenant identities. External approvers operate outside this organisation's identity lifecycle, MFA policies, and account deprovisioning controls."
            EvidenceId  = $evidenceId
        })
    }

    # Unresolvable approver objects
    $unknownApprovers = @($ApproverProfiles | Where-Object { $_.ApproverObjectType -eq 'Unknown' })
    if ($unknownApprovers.Count -gt 0) {
        $FindingsList.Add([pscustomobject]@{
            FindingType = 'Approver Object Type Cannot Be Determined'
            RiskRating  = 'Medium'
            Subject     = $RoleName
            RoleName    = $RoleName
            Details     = "$($unknownApprovers.Count) approver(s) for '$RoleName' could not be resolved or classified as User or Group. Validate that all approver object IDs are correct, active, and accessible with the current Graph permissions."
            EvidenceId  = $evidenceId
        })
    }
}

# ─── Main exported function ───────────────────────────────────────────────────

function Get-PimApproverAnalysis {
    <#
    .SYNOPSIS
    Orchestrates full approver analysis across all approval-configured roles.
    Returns ApprovalAnalysis rows, ApproverProfiles rows, and ApprovalFindings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$PolicyFlatRules,

        [Parameter(Mandatory)]
        [object[]]$RoleAssignments,

        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$ReturnObjectsOnly
    )

    Write-PimLog -Message 'Starting approver analysis: expanding group-based approvers and evaluating approval integrity.'

    $namingPrefix = if ($Config.ContainsKey('NamingCompliancePrefix') -and -not [string]::IsNullOrWhiteSpace($Config.NamingCompliancePrefix)) { $Config.NamingCompliancePrefix } else { 'CLAD_' }

    # ── Per-run caches (keyed by GroupId, avoids duplicate Graph calls) ───────────
    $groupMemberCache = @{}
    $groupDetailCache = @{}

    # ── Global privileged-user lookup (any role, for IsPrivileged flag) ───────────
    $privilegedUserHash = @{}
    foreach ($a in @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'User' -and $_.PrincipalId })) {
        $privilegedUserHash[[string]$a.PrincipalId] = $true
    }

    # ── Per-role user IDs and UPNs (for self-approval overlap detection) ─────────
    $roleUserIdsMap = @{}
    $roleUpnsMap    = @{}
    foreach ($a in @($RoleAssignments | Where-Object { $_.PrincipalType -eq 'User' -and $_.PrincipalId -and $_.RoleDisplayName })) {
        $roleName = [string]$a.RoleDisplayName
        if (-not $roleUserIdsMap.ContainsKey($roleName)) {
            $roleUserIdsMap[$roleName] = New-Object 'System.Collections.Generic.List[string]'
            $roleUpnsMap[$roleName]    = New-Object 'System.Collections.Generic.List[string]'
        }
        $roleUserIdsMap[$roleName].Add([string]$a.PrincipalId)
        if ($a.PrincipalUserPrincipalName) {
            $roleUpnsMap[$roleName].Add([string]$a.PrincipalUserPrincipalName)
        }
    }

    # ── Filter to approval-required roles only ────────────────────────────────────
    $approvalRules = @($PolicyFlatRules | Where-Object { $_.IsApprovalRequired -eq $true })
    Write-PimLog -Message "Approver analysis: $($approvalRules.Count) role(s) with approval configured."

    $analysisRows = New-Object System.Collections.Generic.List[object]
    $profileRows  = New-Object System.Collections.Generic.List[object]
    $findingsList = New-Object System.Collections.Generic.List[object]

    foreach ($rule in $approvalRules) {
        $roleName             = if ($rule.RoleName) { [string]$rule.RoleName } else { '' }
        $approverIds          = if ($rule.ApproverIds)          { [string]$rule.ApproverIds }          else { '' }
        $approverDisplayNames = if ($rule.ApproverDisplayNames) { [string]$rule.ApproverDisplayNames } else { '' }

        if ([string]::IsNullOrWhiteSpace($roleName)) { continue }

        # Handle zero-approver case
        if ([string]::IsNullOrWhiteSpace($approverIds)) {
            $analysisRows.Add([pscustomobject]@{
                RoleName          = $roleName
                ApproverType      = 'None'
                GroupName         = $null
                GroupType         = $null
                MemberCount       = 0
                GuestMembers      = 0
                PrivilegedMembers = 0
                ApprovalIntegrity = 'Broken'
                RiskRating        = 'High'
            })
            $findingsList.Add([pscustomobject]@{
                FindingType = 'Approval Configured Without Approvers'
                RiskRating  = 'High'
                Subject     = $roleName
                RoleName    = $roleName
                Details     = "Role '$roleName' requires approval but no approver object IDs are configured in the policy. Activation requests may be permanently blocked or silently bypassed."
                EvidenceId  = "ApprovalAnalysis_$roleName"
            })
            continue
        }

        # Resolve profiles (expands groups)
        $profiles = @()
        try {
            $profiles = @(Get-ApproverProfiles `
                -RoleName             $roleName `
                -ApproverIds          $approverIds `
                -ApproverDisplayNames $approverDisplayNames `
                -NamingPrefix         $namingPrefix `
                -PrivilegedUserHash   $privilegedUserHash `
                -GroupMemberCache     $groupMemberCache `
                -GroupDetailCache     $groupDetailCache)
        }
        catch {
            Write-PimLog -Level WARN -Message "Failed to resolve approver profiles for role '$roleName': $($_.Exception.Message)"
        }

        foreach ($p in $profiles) { $profileRows.Add($p) }

        # Test integrity against role-specific user IDs
        $roleUserIds = if ($roleUserIdsMap.ContainsKey($roleName)) { @($roleUserIdsMap[$roleName]) } else { @() }
        $roleUpns    = if ($roleUpnsMap.ContainsKey($roleName))    { @($roleUpnsMap[$roleName])    } else { @() }

        $integrity = Test-ApprovalIntegrity `
            -RoleName               $roleName `
            -ApproverProfiles       $profiles `
            -RolePrivilegedUserIds  $roleUserIds `
            -RolePrivilegedUpns     $roleUpns `
            -NamingPrefix           $namingPrefix

        # Derive summary metrics
        $groupNames    = @($profiles | Where-Object { $_.ApproverObjectType -eq 'Group' -and $_.GroupName } | Select-Object -ExpandProperty GroupName -Unique | Where-Object { $_ })
        $groupTypes    = @($profiles | Where-Object { $_.GroupType } | Select-Object -ExpandProperty GroupType -Unique | Where-Object { $_ })
        $guestCount    = @($profiles | Where-Object { $_.IsGuest -eq $true }).Count
        $privCount     = @($profiles | Where-Object { $_.IsPrivileged -eq $true }).Count
        $memberCount   = @($profiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserId) }).Count

        $approverTypeSet = @($profiles | Select-Object -ExpandProperty ApproverObjectType -Unique | Where-Object { $_ -ne 'Unknown' })
        $approverType = if ('Group' -in $approverTypeSet -and 'User' -in $approverTypeSet) { 'Mixed' }
                        elseif ('Group' -in $approverTypeSet) { 'Group' }
                        elseif ('User'  -in $approverTypeSet) { 'User' }
                        else { 'Unknown' }

        $riskRating = switch ($integrity) {
            'Broken'   { 'High' }
            'Weak'     { 'High' }
            'Moderate' { 'Medium' }
            'Strong'   { 'Low' }
            default    { 'Medium' }
        }

        $analysisRows.Add([pscustomobject]@{
            RoleName          = $roleName
            ApproverType      = $approverType
            GroupName         = ($groupNames -join '; ')
            GroupType         = ($groupTypes -join '; ')
            MemberCount       = $memberCount
            GuestMembers      = $guestCount
            PrivilegedMembers = $privCount
            ApprovalIntegrity = $integrity
            RiskRating        = $riskRating
        })

        # Generate findings
        Add-ApprovalFindings `
            -RoleName          $roleName `
            -ApproverProfiles  $profiles `
            -ApprovalIntegrity $integrity `
            -FindingsList      $findingsList
    }

    $analysisArr = @($analysisRows)
    $profileArr  = @($profileRows)
    $findingsArr = @($findingsList)

    if (-not $ReturnObjectsOnly -and -not [string]::IsNullOrWhiteSpace($OutputFolder)) {
        $rawFolder = Join-Path -Path $OutputFolder -ChildPath 'Raw'
        Export-PimData -Data $analysisArr -CsvPath (Join-Path -Path $rawFolder -ChildPath 'ApprovalAnalysis.csv')
        Export-PimData -Data $profileArr  -CsvPath (Join-Path -Path $rawFolder -ChildPath 'ApproverProfiles.csv')
    }

    Write-PimLog -Message "Approver analysis complete: $($analysisArr.Count) roles analysed, $($profileArr.Count) approver profile rows, $($findingsArr.Count) findings generated."

    return [pscustomobject]@{
        ApprovalAnalysis = $analysisArr
        ApproverProfiles = $profileArr
        ApprovalFindings = $findingsArr
    }
}

# ─── Convenience wrappers (spec-named public surface) ─────────────────────────

function Get-RoleApprovers {
    <#
    .SYNOPSIS
    Returns the flat approver profile rows for a specific role (or all roles).
    Each row represents one effective approver member after group expansion.
    Wraps Get-ApproverProfiles for external call-site convenience.

    .PARAMETER RoleName
    Optional. Filter to a specific role. Omit to return all roles.

    .PARAMETER PolicyFlatRules
    The flat policy rules array produced by Get-PimRolePolicySettings.

    .PARAMETER RoleAssignments
    The role assignments array (used to build privileged-user lookup).

    .PARAMETER Config
    The PIM review configuration hashtable.

    .PARAMETER OutputFolder
    Run output folder (used when exporting CSVs).
    #>
    [CmdletBinding()]
    param(
        [string]$RoleName,
        [object[]]$PolicyFlatRules,
        [object[]]$RoleAssignments,
        [hashtable]$Config,
        [string]$OutputFolder
    )

    $result = Get-PimApproverAnalysis `
        -PolicyFlatRules  $PolicyFlatRules `
        -RoleAssignments  $RoleAssignments `
        -Config           $Config `
        -OutputFolder     $OutputFolder `
        -ReturnObjectsOnly

    $profiles = @($result.ApproverProfiles)
    if (-not [string]::IsNullOrWhiteSpace($RoleName)) {
        $profiles = @($profiles | Where-Object { $_.RoleName -ieq $RoleName })
    }
    return $profiles
}

function Get-ApprovalSummary {
    <#
    .SYNOPSIS
    Returns per-role approval summary rows (ApprovalAnalysis) from a completed
    Get-PimApproverAnalysis result, optionally filtered to a single role.

    Each row contains: RoleName, ApproverType, GroupName, GroupType, MemberCount,
    GuestMembers, PrivilegedMembers, ApprovalIntegrity, RiskRating.

    .PARAMETER AnalysisResult
    The object returned by Get-PimApproverAnalysis (must contain .ApprovalAnalysis).

    .PARAMETER RoleName
    Optional filter to a single role.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AnalysisResult,

        [string]$RoleName
    )

    $rows = @($AnalysisResult.ApprovalAnalysis)
    if (-not [string]::IsNullOrWhiteSpace($RoleName)) {
        $rows = @($rows | Where-Object { $_.RoleName -ieq $RoleName })
    }
    return $rows
}

# ─── Script entry point ───────────────────────────────────────────────────────

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimApproverAnalysis @PSBoundParameters
}
