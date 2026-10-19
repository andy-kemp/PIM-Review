<#
.SYNOPSIS
Builds the Azure RBAC review report (HTML and Markdown). Function definitions only; dot-sourced by
Get-AzureRbacReview.ps1.
#>

function ConvertTo-AzRbacHtmlTable {
    param(
        [object[]]$Rows,
        [string[]]$Columns,
        [int]$MaxRows = 0,
        [string]$CsvName
    )

    $all = @($Rows | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) {
        return '<p class="none">None found.</p>'
    }

    $shown = $all
    if ($MaxRows -gt 0 -and $all.Count -gt $MaxRows) { $shown = @($all | Select-Object -First $MaxRows) }

    $badgeColumns = @('RiskRating', 'Status', 'HighestTier', 'PrivilegeTier', 'HighestGroupTier')
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<table><thead><tr>')
    foreach ($col in $Columns) { $null = $sb.Append("<th>$(ConvertTo-AzRbacLabel -Name $col)</th>") }
    $null = $sb.Append('</tr></thead><tbody>')

    foreach ($row in $shown) {
        $null = $sb.Append('<tr>')
        foreach ($col in $Columns) {
            $value = Get-AzRbacProp -InputObject $row -Name $col
            if ($value -is [datetime]) { $value = $value.ToString('yyyy-MM-dd') }
            elseif ($value -is [bool]) { $value = if ($value) { 'Yes' } else { 'No' } }
            $text = if ($null -eq $value) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$value) }
            if ($badgeColumns -contains $col) {
                $cls = switch ([string]$value) { 'Critical' { 'badge-critical' } 'High' { 'badge-high' } 'Red' { 'badge-high' } 'Medium' { 'badge-medium' } 'Amber' { 'badge-medium' } 'Low' { 'badge-low' } 'Green' { 'badge-low' } default { '' } }
                if ($cls) { $text = "<span class=""$cls"">$text</span>" }
            }
            $null = $sb.Append("<td>$text</td>")
        }
        $null = $sb.Append('</tr>')
    }

    $null = $sb.Append('</tbody></table>')
    if ($shown.Count -lt $all.Count) {
        $where = if ($CsvName) { " Full list: Raw/$CsvName." } else { '' }
        $null = $sb.Append("<p class=""more"">Showing $($shown.Count) of $($all.Count).$where</p>")
    }
    return $sb.ToString()
}

function ConvertTo-AzRbacMarkdownTable {
    param(
        [object[]]$Rows,
        [string[]]$Columns,
        [int]$MaxRows = 0
    )

    $all = @($Rows | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) { return @('- None found.') }
    $shown = $all
    if ($MaxRows -gt 0 -and $all.Count -gt $MaxRows) { $shown = @($all | Select-Object -First $MaxRows) }

    $lines = @()
    $lines += '| ' + (($Columns | ForEach-Object { ConvertTo-AzRbacLabel -Name $_ }) -join ' | ') + ' |'
    $lines += '| ' + (($Columns | ForEach-Object { '---' }) -join ' | ') + ' |'
    foreach ($row in $shown) {
        $values = @()
        foreach ($col in $Columns) {
            $value = Get-AzRbacProp -InputObject $row -Name $col
            if ($value -is [datetime]) { $value = $value.ToString('yyyy-MM-dd') }
            if ($null -eq $value) { $values += '' }
            else { $values += ([string]$value -replace '\|', '/' -replace '[\r\n]+', ' ') }
        }
        $lines += '| ' + ($values -join ' | ') + ' |'
    }
    if ($shown.Count -lt $all.Count) { $lines += ''; $lines += "_Showing $($shown.Count) of $($all.Count)._" }
    return $lines
}

function ConvertTo-AzRbacLabel {
    param([string]$Name)

    $map = @{
        'DisplayName' = 'Name'; 'UserPrincipalName' = 'UPN'; 'PrincipalCategory' = 'Type'; 'HighestTier' = 'Highest tier'
        'StandingPrivilegedCount' = 'Standing privileged'; 'EligiblePrivilegedCount' = 'Eligible privileged'
        'SubscriptionsReachable' = 'Subscriptions'; 'ResourcesReachable' = 'Resources'; 'CriticalAccess' = 'Can grant access via'
        'LastSignIn' = 'Last sign-in'; 'DaysSinceSignIn' = 'Days since sign-in'; 'OnPremisesSynced' = 'Synced from AD'
        'AzureChangeEvents' = 'Azure changes'; 'KeyVaultPolicyAccess' = 'Key Vault policies'; 'ManagedIdentityHost' = 'Attached to'
        'SubscriptionName' = 'Subscription'; 'ManagementGroupPath' = 'Management group path'; 'EffectivePrincipals' = 'Principals with access'
        'EffectiveOwners' = 'Can grant access'; 'StandingOwners' = 'Standing'; 'EligibleOwners' = 'Eligible'; 'GuestsWithAccess' = 'Guests'
        'PrivilegedWorkloads' = 'Privileged workloads'; 'LighthouseAuthorizations' = 'Lighthouse'; 'PimEligiblePaths' = 'PIM-eligible paths'
        'RiskRating' = 'Risk'; 'FindingType' = 'Finding'; 'RoleName' = 'Role'; 'ScopeName' = 'Scope'; 'GroupName' = 'Group'
        'IsAssignableToRole' = 'Role-assignable'; 'GuestMembers' = 'Guests'; 'WorkloadMembers' = 'Workloads'; 'EligibleMembers' = 'Eligible members'
        'ActiveSecrets' = 'Secrets'; 'ActiveCertificates' = 'Certificates'; 'FederatedCredentials' = 'Federated'; 'LongLivedCredentials' = 'Long-lived'
        'LongestLifetimeDays' = 'Longest lifetime (days)'; 'ManagedByTenant' = 'Managing tenant'; 'OfferName' = 'Offer'
        'AuthorizationType' = 'Type'; 'PrincipalDisplayName' = 'Principal'; 'CanAssignRoles' = 'Can assign'; 'PermissionModel' = 'Permission model'
        'AccessPolicyCount' = 'Policies'; 'PublicNetworkAccess' = 'Public network'; 'SecretPermissions' = 'Secrets'; 'KeyPermissions' = 'Keys'
        'CertificatePermissions' = 'Certificates'; 'ChangedBy' = 'Changed by'; 'Timestamp' = 'When'; 'PrivilegeTier' = 'Tier'
        'AssignmentCount' = 'Assignments'; 'WildcardActions' = 'Wildcards'; 'AssignableScopes' = 'Assignable scopes'
        'HighestGroupTier' = 'Group tier'; 'OwnerDisplayName' = 'Owner'; 'OwnerUserPrincipalName' = 'Owner UPN'; 'StatusCode' = 'Status'
        'Standing' = 'Standing'; 'Roles' = 'Roles'; 'ChangeEvents' = 'Changes'; 'LastChange' = 'Last change'; 'TopOperations' = 'Most frequent operations'
    }
    if ($map.ContainsKey($Name)) { return $map[$Name] }
    return $Name
}

function New-AzureRbacReport {
    [CmdletBinding()]
    param(
        [string]$OutputFolder,
        [hashtable]$Data
    )

    $tierRank = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1 }
    $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    $assessmentDate = (Get-Date).ToString('yyyy-MM-dd')
    $label = [string]$Data.TenantLabel
    $fileStem = Get-SafeFileName -Name ("AzureRbac_Summary_{0}" -f $label)
    $mdPath = Join-Path -Path $OutputFolder -ChildPath "$fileStem.md"
    $htmlPath = Join-Path -Path $OutputFolder -ChildPath "$fileStem.html"

    $findings = @($Data.Findings)
    $users = @($Data.UserSummary)
    $workloads = @($Data.Workloads)
    $groups = @($Data.Groups)
    $subs = @($Data.Subscriptions)
    $userCats = @('Member', 'Guest')

    $critCount = @($findings | Where-Object { $_.RiskRating -eq 'Critical' }).Count
    $highCount = @($findings | Where-Object { $_.RiskRating -eq 'High' }).Count
    $medCount = @($findings | Where-Object { $_.RiskRating -eq 'Medium' }).Count
    $lowCount = @($findings | Where-Object { $_.RiskRating -eq 'Low' }).Count

    $findingTypeSummary = @(
        $findings |
        Group-Object -Property RiskRating, FindingType |
        ForEach-Object {
            $first = $_.Group[0]
            [pscustomobject]@{ RiskRating = $first.RiskRating; FindingType = $first.FindingType; Count = $_.Count; Recommendation = $first.Recommendation }
        } |
        Sort-Object -Property @{ Expression = { $severityOrder[$_.RiskRating] } }, @{ Expression = 'Count'; Descending = $true }
    )

    # ---- Datasets for sections ----------------------------------------------------------------
    $canGrant = @($users | Where-Object { $_.HighestTier -eq 'Critical' -and $_.PrincipalCategory -ne 'MicrosoftPlatform' } |
        Sort-Object -Property @{ Expression = { if ($_.PrincipalCategory -in $userCats) { 0 } else { 1 } } }, @{ Expression = 'StandingPrivilegedCount'; Descending = $true }, DisplayName)
    $privUsers = @($users | Where-Object { $_.PrincipalCategory -in $userCats -and $tierRank[[string]$_.HighestTier] -ge 3 } |
        Sort-Object -Property @{ Expression = { $tierRank[[string]$_.HighestTier] }; Descending = $true }, @{ Expression = 'StandingPrivilegedCount'; Descending = $true }, DisplayName)
    $guests = @($users | Where-Object { $_.PrincipalCategory -eq 'Guest' })
    $customerWorkloads = @($workloads | Where-Object { $_.PrincipalCategory -ne 'MicrosoftPlatform' })
    $msWorkloads = @($workloads | Where-Object { $_.PrincipalCategory -eq 'MicrosoftPlatform' })
    $privWorkloads = @($customerWorkloads | Where-Object { $tierRank[[string]$_.HighestTier] -ge 3 })
    $kvPolicyVaults = @($Data.KeyVaults | Where-Object { $_.PermissionModel -eq 'Access policies' })
    $kvSecretPolicies = @($Data.KeyVaultPolicies | Where-Object { $_.CanReadSecretsOrKeys })
    $aksLocal = @($Data.AksClusters | Where-Object { -not $_.LocalAccountsDisabled })
    $sqlLocal = @($Data.SqlServers | Where-Object { -not $_.EntraOnlyAuth })
    $storageShared = @($Data.StorageAccounts | Where-Object { $_.SharedKeyAccess -ne 'Disabled' })
    $localAuth = @($Data.LocalAuthResources | Where-Object { $_.LocalAuth -eq 'Enabled' })
    $notVisibleSubs = @($subs | Where-Object { $_.Resources -eq 'Not visible' })

    # ---- Key insights -------------------------------------------------------------------------
    $pl = { param($Count, $One, $Many) if ($Count -eq 1) { "1 $One" } else { "$Count $Many" } }
    $insights = New-Object System.Collections.ArrayList
    $standingCritUsers = @($canGrant | Where-Object { $_.PrincipalCategory -in $userCats -and $_.StandingPrivilegedCount -gt 0 })
    $grantWorkloads = @($canGrant | Where-Object { $_.PrincipalCategory -notin $userCats }).Count
    $null = $insights.Add("$(& $pl $canGrant.Count 'identity can' 'identities can') grant access in Azure (Owner, User Access Administrator or equivalent): $(& $pl $standingCritUsers.Count 'person holds' 'people hold') it permanently and $(& $pl $grantWorkloads 'is a service principal or managed identity' 'are service principals or managed identities').")

    $pimRow = @($Data.Scorecard | Where-Object { $_.Metric -eq 'Privileged access through PIM' }) | Select-Object -First 1
    $noPimSubs = @($subs | Where-Object { $_.StandingOwners -gt 0 -and $_.PimEligiblePaths -eq 0 })
    if ($pimRow) {
        $pimText = "$($pimRow.Value) of privileged user access is just-in-time through PIM; the rest is standing."
        if ($noPimSubs.Count -gt 0) { $pimText += " $($noPimSubs.Count) of $($subs.Count) subscriptions have no PIM-eligible access at all." }
        $null = $insights.Add($pimText)
    }

    $topSubs = @($subs | Sort-Object -Property StandingOwners -Descending | Select-Object -First 3 | Where-Object { $_.StandingOwners -gt 0 })
    if ($topSubs.Count -gt 0) {
        $null = $insights.Add("Most standing owners: " + ((@($topSubs | ForEach-Object { "$($_.SubscriptionName) ($($_.StandingOwners))" })) -join ', ') + ". Target is $($Data.MaxOwners) or fewer per subscription.")
    }

    if ($Data.SignInAvailable) {
        $dormant = @($findings | Where-Object { $_.FindingType -eq 'DormantPrivilegedAccount' })
        if ($dormant.Count -gt 0) { $null = $insights.Add("$(& $pl $dormant.Count 'account' 'accounts') with privileged Azure access $(if ($dormant.Count -eq 1) { 'has' } else { 'have' }) not signed in for $($Data.DormantDays) days or more.") }
    }
    if ($Data.ActivityDays) {
        $unused = @($findings | Where-Object { $_.FindingType -eq 'UnusedStandingAccess' })
        if ($unused.Count -gt 0) { $null = $insights.Add("$(& $pl $unused.Count 'person' 'people') with standing privileged access made no changes in Azure in the last $($Data.ActivityDays) days, so that write access is not being used.") }
    }

    $guestPriv = @($guests | Where-Object { $tierRank[[string]$_.HighestTier] -ge 3 })
    if ($guests.Count -gt 0) { $null = $insights.Add("$(& $pl $guests.Count 'guest account has' 'guest accounts have') Azure access; $($guestPriv.Count) with Critical or High tier roles.") }

    $orphaned = @($findings | Where-Object { $_.FindingType -eq 'OrphanedAssignment' })
    if ($orphaned.Count -gt 0) { $null = $insights.Add("$(& $pl $orphaned.Count 'role assignment points' 'role assignments point') at deleted identities.") }

    if ($privWorkloads.Count -gt 0) {
        $owned = @($privWorkloads | Where-Object { $_.Owners })
        $longLived = @($privWorkloads | Where-Object { $_.LongLivedCredentials -gt 0 })
        $null = $insights.Add("$(& $pl $privWorkloads.Count 'service principal or managed identity holds' 'service principals and managed identities hold') Critical or High roles: $($owned.Count) with owners who could add a credential and use that access, $($longLived.Count) with credentials valid for more than a year.")
    }

    $lhTenants = @($Data.Lighthouse | Select-Object -ExpandProperty ManagedByTenantId -Unique)
    if ($lhTenants.Count -gt 0) { $null = $insights.Add("$(& $pl $lhTenants.Count 'external organisation manages' 'external organisations manage') subscriptions through Azure Lighthouse ($(@($Data.Lighthouse).Count) authorisations). This access does not show in the subscriptions' role assignments.") }

    $outside = @()
    if ($kvPolicyVaults.Count -gt 0) { $outside += "$($kvPolicyVaults.Count) Key Vaults use access policies" }
    if ($aksLocal.Count -gt 0) { $outside += "$($aksLocal.Count) AKS clusters allow local admin accounts" }
    if ($sqlLocal.Count -gt 0) { $outside += "$($sqlLocal.Count) SQL servers allow SQL logins" }
    if ($storageShared.Count -gt 0) { $outside += "$($storageShared.Count) storage accounts allow shared keys" }
    if ($outside.Count -gt 0) { $null = $insights.Add('Access outside Azure RBAC: ' + ($outside -join '; ') + '. These paths are not visible in role assignments.') }

    if ($notVisibleSubs.Count -gt 0) {
        $null = $insights.Add("The review account could not read resources in $($notVisibleSubs.Count) subscription(s) ($((@($notVisibleSubs | Select-Object -ExpandProperty SubscriptionName) -join ', '))). Role assignments there are complete, but resource counts, data plane checks and managed identity mapping are not.")
    }

    # ---- Column sets --------------------------------------------------------------------------
    $subCols = @('SubscriptionName', 'ManagementGroupPath', 'Resources', 'EffectivePrincipals', 'EffectiveOwners', 'StandingOwners', 'EligibleOwners', 'GuestsWithAccess', 'PrivilegedWorkloads', 'LighthouseAuthorizations', 'PimEligiblePaths', 'RiskRating')
    $grantCols = @('DisplayName', 'UserPrincipalName', 'PrincipalCategory', 'StandingPrivilegedCount', 'EligiblePrivilegedCount', 'SubscriptionsReachable', 'LastSignIn', 'AzureChangeEvents', 'CriticalAccess')
    $userCols = @('DisplayName', 'UserPrincipalName', 'PrincipalCategory', 'HighestTier', 'StandingPrivilegedCount', 'EligiblePrivilegedCount', 'SubscriptionsReachable', 'ResourcesReachable', 'LastSignIn', 'DaysSinceSignIn', 'OnPremisesSynced', 'AzureChangeEvents', 'ViaGroups')
    $groupCols = @('GroupName', 'HighestTier', 'Roles', 'Members', 'GuestMembers', 'WorkloadMembers', 'EligibleMembers', 'IsAssignableToRole', 'Owners')
    $workloadCols = @('DisplayName', 'PrincipalCategory', 'Publisher', 'HighestTier', 'SubscriptionsReachable', 'LastSignIn', 'AzureChangeEvents', 'ActiveSecrets', 'ActiveCertificates', 'FederatedCredentials', 'LongestLifetimeDays', 'Owners', 'ManagedIdentityHost', 'CriticalAccess')
    $findingCols = @('RiskRating', 'FindingType', 'Subject', 'RoleName', 'ScopeName', 'Details')

    # ---- Markdown -----------------------------------------------------------------------------
    $md = @()
    $md += '# Azure RBAC Privileged Access Review'
    $md += ''
    $md += "- Client: $label"
    $md += "- Tenant ID: $($Data.TenantId)"
    $md += "- Assessment date: $assessmentDate"
    $md += "- Findings: $critCount Critical, $highCount High, $medCount Medium, $lowCount Low"
    $md += ''
    $md += '## Key insights'
    $md += ''
    foreach ($i in $insights) { $md += "- $i" }
    $md += ''
    $md += '## Scorecard'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $Data.Scorecard -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary'))
    $md += ''
    $md += '## Findings by type'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $findingTypeSummary -Columns @('RiskRating', 'FindingType', 'Count', 'Recommendation'))
    $md += ''
    $md += '## Who can grant access'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $canGrant -Columns $grantCols)
    $md += ''
    $md += '## Subscriptions'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $subs -Columns $subCols)
    $md += ''
    $md += '## People with privileged access'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $privUsers -Columns $userCols)
    $md += ''
    $md += '## Groups holding Azure roles'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $groups -Columns $groupCols)
    $md += ''
    $md += '## Workload identities'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $customerWorkloads -Columns $workloadCols)
    $md += ''
    $md += '## External access (Lighthouse)'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $Data.Lighthouse -Columns @('SubscriptionName', 'ManagedByTenant', 'OfferName', 'AuthorizationType', 'PrincipalDisplayName', 'RoleName', 'CanAssignRoles'))
    $md += ''
    $md += '## Detailed findings'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $findings -Columns $findingCols)
    $md += ''
    $md += '## Coverage gaps'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $Data.CoverageGaps -Columns @('Scope', 'Operation', 'StatusCode', 'Message'))
    $md | Out-File -FilePath $mdPath -Encoding UTF8

    # ---- HTML ---------------------------------------------------------------------------------
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;margin:28px;line-height:1.45;color:#222;max-width:1500px}
h1{font-size:30px;margin-bottom:8px}
h2{font-size:21px;margin-top:34px;margin-bottom:10px;border-bottom:2px solid #1f4e78;padding-bottom:4px;color:#1f4e78}
h3{font-size:16px;margin-top:22px;margin-bottom:6px}
.cover{border:2px solid #1f4e78;padding:20px;border-radius:8px;background:#f7fbff;margin-bottom:18px}
.meta{margin:6px 0}
.intro{margin:8px 0 12px 0;color:#2c3e50;font-size:13px;line-height:1.6;max-width:1100px}
.insights li{margin:6px 0;font-size:14px}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}
.stat{border:1px solid #cfd8e3;border-radius:6px;padding:8px 14px;background:#fff;min-width:120px}
.stat .n{font-size:22px;font-weight:700;color:#1f4e78}
.stat .l{font-size:12px;color:#555}
table{border-collapse:collapse;width:100%;font-size:12px;margin-bottom:6px}
td,th{border:1px solid #ddd;padding:5px 7px;vertical-align:top}
th{background:#f4f6f8;text-align:left;position:sticky;top:0}
tr:nth-child(even) td{background:#fafbfc}
.none{color:#2e7d32;font-style:italic}
.more{color:#555;font-size:12px;font-style:italic}
.toc{columns:2;font-size:13px}
.toc li{margin:3px 0}
details{margin:8px 0;border:1px solid #e3e3e3;border-radius:6px;padding:6px 10px}
summary{cursor:pointer;font-weight:600}
.badge-critical,.badge-high,.badge-medium,.badge-low{color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}
.badge-critical{background:#7f0000}.badge-high{background:#c62828}.badge-medium{background:#e65100}.badge-low{background:#2e7d32}
.counts span{margin-right:8px}
@media print{details{border:none}summary{display:none}th{position:static}}
'@
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

    $sections = @(
        @{ Id = 'insights'; Title = 'Key insights' },
        @{ Id = 'scorecard'; Title = 'Scorecard' },
        @{ Id = 'findings'; Title = 'Findings by type' },
        @{ Id = 'grant'; Title = 'Who can grant access' },
        @{ Id = 'subs'; Title = 'Subscriptions' },
        @{ Id = 'subdetail'; Title = 'Privileged access by subscription' },
        @{ Id = 'people'; Title = 'People with privileged access' },
        @{ Id = 'groups'; Title = 'Groups holding Azure roles' },
        @{ Id = 'workloads'; Title = 'Service principals and managed identities' },
        @{ Id = 'external'; Title = 'External access: guests and other organisations' },
        @{ Id = 'outside'; Title = 'Access outside Azure RBAC' },
        @{ Id = 'changes'; Title = 'Recent role assignment changes' },
        @{ Id = 'custom'; Title = 'Custom roles' },
        @{ Id = 'detail'; Title = 'All findings' },
        @{ Id = 'coverage'; Title = 'Coverage and method' }
    )
    $n = 0
    $num = @{}
    foreach ($s in $sections) { $n++; $num[$s.Id] = $n }
    $h2 = { param($Id) $s = $sections | Where-Object { $_.Id -eq $Id }; "<h2 id=""$Id"">$($num[$Id]). $($s.Title)</h2>" }

    $html = New-Object System.Text.StringBuilder
    $null = $html.Append('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Azure RBAC Review - ' + (& $enc $label) + '</title>')
    $null = $html.Append("<style>$css</style></head><body>")

    # Cover
    $null = $html.Append('<div class="cover"><h1>Azure RBAC Privileged Access Review</h1>')
    $null = $html.Append("<div class=""meta""><strong>Client:</strong> $(& $enc $label)</div>")
    $null = $html.Append("<div class=""meta""><strong>Tenant ID:</strong> $($Data.TenantId)</div>")
    $null = $html.Append('<div class="meta"><strong>Scope:</strong> every Azure role assignment, active and PIM-eligible, from tenant root to individual resources; groups expanded to members; access paths outside RBAC</div>')
    $null = $html.Append("<div class=""meta""><strong>Assessment date:</strong> $assessmentDate</div>")
    $null = $html.Append("<div class=""meta counts""><strong>Findings:</strong> <span class=""badge-critical"">$critCount Critical</span><span class=""badge-high"">$highCount High</span><span class=""badge-medium"">$medCount Medium</span><span class=""badge-low"">$lowCount Low</span></div>")
    $null = $html.Append('<div class="stats">')
    foreach ($stat in @(
        @{ N = $Data.ManagementGroups; L = 'management groups' },
        @{ N = $subs.Count; L = 'subscriptions' },
        @{ N = $Data.TotalResources; L = 'resources visible' },
        @{ N = @($users | Where-Object { $_.PrincipalCategory -in $userCats }).Count; L = 'people with access' },
        @{ N = $canGrant.Count; L = 'can grant access' },
        @{ N = @($customerWorkloads).Count; L = 'workload identities' },
        @{ N = $groups.Count; L = 'groups holding roles' }
    )) {
        $null = $html.Append("<div class=""stat""><div class=""n"">$($stat.N)</div><div class=""l"">$($stat.L)</div></div>")
    }
    $null = $html.Append('</div></div>')

    # Contents
    $null = $html.Append('<h3>Contents</h3><ol class="toc">')
    foreach ($s in $sections) { $null = $html.Append("<li><a href=""#$($s.Id)"">$($s.Title)</a></li>") }
    $null = $html.Append('</ol>')

    # 1 Insights
    $null = $html.Append((& $h2 'insights'))
    $null = $html.Append('<ul class="insights">')
    foreach ($i in $insights) { $null = $html.Append("<li>$(& $enc $i)</li>") }
    $null = $html.Append('</ul>')

    # 2 Scorecard
    $null = $html.Append((& $h2 'scorecard'))
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $Data.Scorecard -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary')))

    # 3 Findings by type
    $null = $html.Append((& $h2 'findings'))
    $null = $html.Append('<p class="intro">Each finding type, how often it occurs and what to do about it. Standing-access findings are raised once per person and list every place the access applies. Every individual finding is in section ' + $num['detail'] + ' and in Raw/AzureFindings.csv.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $findingTypeSummary -Columns @('RiskRating', 'FindingType', 'Count', 'Recommendation')))

    # 4 Who can grant access
    $null = $html.Append((& $h2 'grant'))
    $null = $html.Append('<p class="intro">Every identity that can create role assignments somewhere in Azure (Owner, User Access Administrator, Role Based Access Control Administrator without a condition, or a custom role with the same rights), directly or through a group. Each of these can give itself or anyone else any access within that scope, so this is the list that matters most. Microsoft platform identities are shown separately in section ' + $num['workloads'] + '.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $canGrant -Columns $grantCols -MaxRows 300 -CsvName 'AzureUserSummary.csv'))

    # 5 Subscriptions
    $null = $html.Append((& $h2 'subs'))
    $null = $html.Append('<p class="intro">Counts include access inherited from management groups and the tenant root, and access through group membership. "Can grant access" counts people holding a Critical-tier role at or above the subscription; "Standing" are those without PIM. "Not visible" means the review account could not read resources there.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $subs -Columns $subCols))

    # 6 Per subscription
    $null = $html.Append((& $h2 'subdetail'))
    $null = $html.Append('<p class="intro">For each subscription, everyone holding a Critical or High tier role at or above it, with where the access comes from. Resource-group and resource-level access is in Raw/AzureUserAccess.csv and the full user-by-subscription grid in Raw/AzureAccessMatrix.csv.</p>')
    foreach ($s in $subs) {
        $detail = @()
        if ($Data.SubscriptionDetail -and $Data.SubscriptionDetail.ContainsKey($s.SubscriptionId)) { $detail = @($Data.SubscriptionDetail[$s.SubscriptionId]) }
        $title = "$(& $enc $s.SubscriptionName) - $($detail.Count) privileged principals, $($s.StandingOwners) standing owners"
        $null = $html.Append("<details open><summary>$title</summary>")
        $null = $html.Append("<p class=""intro"">Path: $(& $enc $s.ManagementGroupPath). Resources: $(& $enc $s.Resources). Principals with any access: $($s.EffectivePrincipals).</p>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $detail -Columns @('DisplayName', 'UserPrincipalName', 'PrincipalCategory', 'HighestTier', 'Standing', 'Roles') -MaxRows 150))
        $null = $html.Append('</details>')
    }

    # 7 People
    $null = $html.Append((& $h2 'people'))
    $signInNote = if ($Data.SignInAvailable) { "Last sign-in comes from Entra sign-in activity." } else { 'Last sign-in was not available (needs AuditLog.Read.All and Entra ID P1).' }
    $changeNote = if ($Data.ActivityDays) { " Azure changes counts write operations in the Activity Log over the last $($Data.ActivityDays) days; 0 means the person holds write access but did not use it." } else { '' }
    $null = $html.Append("<p class=""intro"">Members and guests whose highest Azure role is Critical or High, directly or through groups. $signInNote$changeNote Everyone with any access is in Raw/AzureUserSummary.csv.</p>")
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $privUsers -Columns $userCols -MaxRows 300 -CsvName 'AzureUserSummary.csv'))

    # 8 Groups
    $null = $html.Append((& $h2 'groups'))
    $null = $html.Append('<p class="intro">Every group that holds an Azure role, with member counts after nested groups are expanded. Owners can add members, and groups that are not role-assignable can be changed by several Entra admin roles, so both are routes to the access the group grants.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $groups -Columns $groupCols -MaxRows 200 -CsvName 'AzureGroupSummary.csv'))

    # 9 Workloads
    $null = $html.Append((& $h2 'workloads'))
    $null = $html.Append('<p class="intro">Service principals and managed identities with Azure roles. Owners and credentials control who can act as the identity; for managed identities, whoever can change or run code on the resource it is attached to can use it.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $customerWorkloads -Columns $workloadCols -MaxRows 300 -CsvName 'AzureWorkloadIdentities.csv'))
    $null = $html.Append('<h3>Microsoft platform identities</h3><p class="intro">Identities owned by Microsoft services (for example MS-PIM and Defender for Cloud scanners). Their roles are normally expected; they are listed for completeness and excluded from the findings.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $msWorkloads -Columns @('DisplayName', 'HighestTier', 'SubscriptionsReachable', 'CriticalAccess')))

    # 10 External
    $null = $html.Append((& $h2 'external'))
    $null = $html.Append('<h3>Guests</h3>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $guests -Columns @('DisplayName', 'UserPrincipalName', 'HighestTier', 'SubscriptionsReachable', 'LastSignIn', 'ViaGroups', 'CriticalAccess')))
    $null = $html.Append('<h3>Other organisations through Azure Lighthouse</h3><p class="intro">Lighthouse lets another tenant (usually a managed service provider) work in these subscriptions with its own accounts. These authorisations are not role assignments and do not appear anywhere else in Azure access control.</p>')
    if ($Data.ExtendedChecks) {
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $Data.Lighthouse -Columns @('SubscriptionName', 'ManagedByTenant', 'OfferName', 'AuthorizationType', 'PrincipalDisplayName', 'RoleName', 'PrivilegeTier', 'CanAssignRoles')))
    }
    else {
        $null = $html.Append('<p class="more">Not checked (run without -SkipExtendedChecks).</p>')
    }

    # 11 Outside RBAC
    $null = $html.Append((& $h2 'outside'))
    $null = $html.Append('<p class="intro">Ways to reach data or administer resources that do not go through Azure role assignments and so are invisible in the rest of this report. Only resources the review account can read are checked.</p>')
    if ($Data.ExtendedChecks) {
        $null = $html.Append("<h3>Key Vaults using access policies ($($kvPolicyVaults.Count) of $(@($Data.KeyVaults).Count))</h3>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $kvPolicyVaults -Columns @('SubscriptionName', 'ResourceGroup', 'VaultName', 'AccessPolicyCount', 'PublicNetworkAccess', 'PurgeProtection')))
        $null = $html.Append("<h3>Who can read secrets, keys or certificates through access policies ($($kvSecretPolicies.Count))</h3>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $kvSecretPolicies -Columns @('VaultName', 'PrincipalDisplayName', 'PrincipalCategory', 'SecretPermissions', 'KeyPermissions', 'CertificatePermissions') -MaxRows 200 -CsvName 'AzureKeyVaultAccessPolicies.csv'))
        $null = $html.Append("<h3>AKS clusters with local accounts enabled ($($aksLocal.Count) of $(@($Data.AksClusters).Count))</h3>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $aksLocal -Columns @('SubscriptionName', 'ClusterName', 'EntraIntegrated', 'AzureRbacForKubernetes', 'PrivateCluster')))
        $null = $html.Append("<h3>SQL servers allowing SQL authentication ($($sqlLocal.Count) of $(@($Data.SqlServers).Count))</h3>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $sqlLocal -Columns @('SubscriptionName', 'ServerName', 'SqlAdminLogin', 'EntraAdmin', 'PublicNetworkAccess')))
        $null = $html.Append("<h3>Storage accounts allowing shared key access ($($storageShared.Count) of $(@($Data.StorageAccounts).Count))</h3>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $storageShared -Columns @('SubscriptionName', 'ResourceGroup', 'AccountName', 'SharedKeyAccess', 'AnonymousBlobAccess', 'PublicNetworkAccess', 'NetworkDefaultAction') -MaxRows 100 -CsvName 'AzureStorageAccounts.csv'))
        $null = $html.Append("<h3>Other resources with key-based (local) authentication enabled ($($localAuth.Count))</h3>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $localAuth -Columns @('SubscriptionName', 'ResourceGroup', 'ResourceName', 'ResourceType') -MaxRows 100 -CsvName 'AzureLocalAuthResources.csv'))
    }
    else {
        $null = $html.Append('<p class="more">Not checked (run without -SkipExtendedChecks).</p>')
    }

    # 12 Changes
    $null = $html.Append((& $h2 'changes'))
    if ($Data.ActivityDays) {
        $null = $html.Append("<p class=""intro"">Role assignments granted or removed in the last $($Data.ActivityDays) days, from the Activity Log. Who made each change is shown so privileged grants can be checked against approvals.</p>")
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $Data.RbacChanges -Columns @('Timestamp', 'Change', 'ChangedBy', 'PrincipalDisplayName', 'RoleName', 'PrivilegeTier', 'SubscriptionName', 'Scope') -MaxRows 200 -CsvName 'AzureRoleAssignmentChanges.csv'))
        $null = $html.Append('<h3>Most active identities</h3>')
        $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $Data.ActivityByCaller -Columns @('Caller', 'SubscriptionName', 'ChangeEvents', 'LastChange', 'TopOperations') -MaxRows 50 -CsvName 'AzureActivityByCaller.csv'))
    }
    else {
        $null = $html.Append('<p class="more">Activity Log not read (run without -SkipActivityLog).</p>')
    }

    # 13 Custom roles
    $null = $html.Append((& $h2 'custom'))
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $Data.CustomRoles -Columns @('RoleName', 'PrivilegeTier', 'AssignmentCount', 'TierReason', 'WildcardActions', 'AssignableScopes')))

    # 14 All findings
    $null = $html.Append((& $h2 'detail'))
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $findings -Columns $findingCols -MaxRows 1500 -CsvName 'AzureFindings.csv'))

    # 15 Coverage and method
    $null = $html.Append((& $h2 'coverage'))
    $null = $html.Append('<p class="intro">What was read: role assignments at the tenant root, every management group and every subscription (which returns assignments at, above and below it); PIM eligible assignments and active schedules; role definitions; Microsoft Graph for identities, group membership (transitive), group and application owners, credentials and sign-in activity; Azure Resource Graph for the hierarchy, resource counts, Key Vault, storage, SQL, AKS and managed identity configuration; Azure Lighthouse registrations; deny assignments; and the Activity Log. Everything is read-only.</p>')
    $null = $html.Append('<p class="intro">Privilege tiers are worked out from each role''s permissions: Critical can create role assignments; High has full write or full data plane control, or role assignment rights limited by a condition; Medium has other write or data actions; Low is read-only.</p>')
    $null = $html.Append('<p class="intro">Not covered: classic subscription administrators (retired by Microsoft), Entra ID directory roles (covered by the Entra PIM review), database-level users, Kubernetes RoleBindings and VM local administrators.</p>')
    $null = $html.Append('<h3>Gaps in this run</h3>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $Data.CoverageGaps -Columns @('Scope', 'Operation', 'StatusCode', 'Message')))

    $null = $html.Append('</body></html>')
    [System.IO.File]::WriteAllText($htmlPath, $html.ToString(), [System.Text.Encoding]::UTF8)

    return [pscustomobject]@{
        MarkdownPath = $mdPath
        HtmlPath     = $htmlPath
    }
}
