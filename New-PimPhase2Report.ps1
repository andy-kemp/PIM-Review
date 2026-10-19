<#
.SYNOPSIS
Builds the PIM Phase 2 tenant assessment report (HTML). Function definitions only; dot-sourced by
Invoke-PimPhase2Assessment.ps1.
#>

function ConvertTo-P2Label {
    param([string]$Name)
    $map = @{
        Upn = 'UPN'; TL1Paths = 'TL1 paths'; TL2Paths = 'TL2 paths'; TL3Paths = 'TL3 paths'; TL1Roles = 'TL1 roles'; TL2Roles = 'TL2 roles'; TL3Roles = 'TL3 roles'
        HasP2Licence = 'P2 licence'; HasFido2 = 'FIDO2'; MeetsHld763 = 'Meets HLD 7.6.3'; HldBaseline = 'HLD baseline'; Phase2Target = 'Phase 2 target'
        HldReference = 'HLD reference'; ApproversAlsoEligible = 'Approvers also eligible'; SelfApprovalPeople = 'Self-approval people'
    }
    if ($map.ContainsKey($Name)) { return $map[$Name] }
    $Name = $Name -creplace 'TL([1-4])', ' TL$1 ' -creplace 'P2', ' P2 '
    $label = (($Name -creplace '([a-z])([A-Z])', '$1 $2') -creplace '([A-Z]+)([A-Z][a-z])', '$1 $2')
    return (($label -replace '\s+', ' ').Trim())
}

function ConvertTo-P2HtmlTable {
    param([object[]]$Rows, [string[]]$Columns, [int]$MaxRows = 0, [string]$CsvName)
    $all = @($Rows | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) { return '<p class="none">None found.</p>' }
    $shown = $all
    if ($MaxRows -gt 0 -and $all.Count -gt $MaxRows) { $shown = @($all | Select-Object -First $MaxRows) }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<div class="tw"><table><thead><tr>')
    foreach ($c in $Columns) { $null = $sb.Append("<th>$(ConvertTo-P2Label -Name $c)</th>") }
    $null = $sb.Append('</tr></thead><tbody>')
    foreach ($r in $shown) {
        $null = $sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = $null
            $p = $r.PSObject.Properties[$c]
            if ($p) { $v = $p.Value }
            if ($v -is [bool]) { $v = if ($v) { 'Yes' } else { 'No' } }
            $t = if ($null -eq $v) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$v) }
            $cls = switch -Regex ([string]$v) {
                '^TL1$' { 'b tl1' } '^TL2$' { 'b tl2' } '^TL3$' { 'b tl3' } '^TL4$' { 'b tl4' }
                '^Critical$' { 'b crit' } '^High$' { 'b high' } '^Medium$' { 'b med' } '^Low$' { 'b low' }
                '^Confirmed$' { 'b high' } '^(Partially|Indicated|Test required)$' { 'b med' } '^(Not observed|Addressed)$' { 'b low' } '^(Not assessed|Open)$' { 'b na' }
                default { '' }
            }
            if ($cls -and $c -in @('TrustLevel', 'HighestTrustLevel', 'Severity', 'Status')) { $t = "<span class=""$cls"">$t</span>" }
            $null = $sb.Append("<td>$t</td>")
        }
        $null = $sb.Append('</tr>')
    }
    $null = $sb.Append('</tbody></table></div>')
    if ($shown.Count -lt $all.Count) {
        $where = if ($CsvName) { " Full list in $CsvName." } else { '' }
        $null = $sb.Append("<p class=""more"">Showing $($shown.Count) of $($all.Count).$where</p>")
    }
    return $sb.ToString()
}

function New-PimPhase2Report {
    param([string]$OutputFolder, [hashtable]$Data)

    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $m = $Data.Metrics
    $pl = { param($n, $one, $many) if ([int]$n -eq 1) { "$n $one" } else { "$n $many" } }
    $brand = $Data.Branding
    $preparedBy = if ($brand -and $brand.PreparedBy) { $brand.PreparedBy } else { 'PIM review' }
    $programme = if ($brand -and $brand.Programme) { $brand.Programme } else { 'PIM Phase 2' }
    $classification = if ($brand -and $brand.Classification) { $brand.Classification } else { 'Client Confidential' }

    $css = @'
:root{--ink:#1d2733;--muted:#5b6673;--line:#dde3ea;--accent:#1f4e78;--bg:#ffffff;--soft:#f5f8fb}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;color:var(--ink);background:var(--bg);line-height:1.5}
main{max-width:1400px;margin:0 auto;padding:24px 16px 60px}
h1{font-size:28px;margin:0 0 6px}
h2{font-size:20px;margin:36px 0 10px;color:var(--accent);border-bottom:2px solid var(--accent);padding-bottom:4px}
h3{font-size:15px;margin:20px 0 6px}
.cover{border:1px solid var(--line);border-left:6px solid var(--accent);padding:18px 20px;background:var(--soft);border-radius:6px}
.meta{color:var(--muted);font-size:13px;margin:2px 0}
.intro{font-size:14px;max-width:1050px}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;margin:14px 0}
.stat{border:1px solid var(--line);border-radius:6px;padding:10px 12px;background:#fff}
.stat .n{font-size:24px;font-weight:700;color:var(--accent);font-variant-numeric:tabular-nums}
.stat .l{font-size:12px;color:var(--muted)}
.stat.bad .n{color:#b3261e}
ul.ins li{margin:6px 0;font-size:14px}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:12px;margin-bottom:6px}
td,th{border:1px solid var(--line);padding:5px 7px;vertical-align:top;text-align:left}
th{background:var(--soft);position:sticky;top:0}
tr:nth-child(even) td{background:#fbfcfd}
.none{color:#2e7d32;font-style:italic}
.more{color:var(--muted);font-size:12px;font-style:italic}
.toc{columns:2;font-size:13px}
details{margin:8px 0;border:1px solid var(--line);border-radius:6px;padding:6px 10px}
summary{cursor:pointer;font-weight:600}
.b{color:#fff;display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.tl1,.crit{background:#7f0000}.tl2,.high{background:#c62828}.tl3,.med{background:#e65100}.tl4,.low{background:#2e7d32}.na{background:#78909c}
.note{background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:8px 12px;font-size:13px}
@media (max-width:700px){.toc{columns:1}h1{font-size:22px}}
@media print{details{border:none}summary{display:none}th{position:static}}
'@

    $sections = @(
        @{ Id = 'summary'; Title = 'Summary' },
        @{ Id = 'hld'; Title = 'HLD findings in this tenant' },
        @{ Id = 'self'; Title = 'Self-approval (F01)' },
        @{ Id = 'approvers'; Title = 'Approver groups against HLD 7.6.3' },
        @{ Id = 'tl1'; Title = 'Routes to TL1 (F02)' },
        @{ Id = 'bundles'; Title = 'Group bundles (F03)' },
        @{ Id = 'standing'; Title = 'Standing access (F04)' },
        @{ Id = 'identities'; Title = 'Privileged identities' },
        @{ Id = 'policy'; Title = 'PIM settings against the trust-level baseline' },
        @{ Id = 'catalogue'; Title = 'Role catalogue extract (runbook 1.2)' },
        @{ Id = 'exceptions'; Title = 'Exception candidates' },
        @{ Id = 'maturity'; Title = 'Maturity baseline (HLD 6.7)' },
        @{ Id = 'migration'; Title = 'Migration worksheet' },
        @{ Id = 'method'; Title = 'Method, sources and limits' }
    )
    $num = @{}; $i = 0
    foreach ($s in $sections) { $i++; $num[$s.Id] = $i }
    $h2 = { param($Id) $s = $sections | Where-Object { $_.Id -eq $Id }; "<h2 id=""$Id"">$($num[$Id]). $($s.Title)</h2>" }

    $html = New-Object System.Text.StringBuilder
    $title = "PIM Phase 2 Assessment - $($Data.TenantName)"
    $null = $html.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>$(& $enc $title)</title><style>$css</style></head><body><main>")
    $null = $html.Append('<div class="cover">')
    $null = $html.Append("<h1>PIM Phase 2 Tenant Assessment</h1>")
    $null = $html.Append("<div class=""meta""><strong>Tenant:</strong> $(& $enc $Data.TenantName)</div>")
    $null = $html.Append("<div class=""meta""><strong>Programme:</strong> $(& $enc $programme)</div>")
    $null = $html.Append("<div class=""meta""><strong>Evidence:</strong> Entra run $(& $enc $(if ($Data.EntraRun) { $Data.EntraRun } else { 'not supplied' })); Azure run $(& $enc $(if ($Data.AzureRun) { $Data.AzureRun } else { 'not supplied' }))</div>")
    $null = $html.Append("<div class=""meta""><strong>Prepared by:</strong> $(& $enc $preparedBy) &middot; $(Get-Date -Format 'yyyy-MM-dd') &middot; $(& $enc $classification)</div>")
    $null = $html.Append('</div>')

    $null = $html.Append('<h3>Contents</h3><ol class="toc">')
    foreach ($s in $sections) { $null = $html.Append("<li><a href=""#$($s.Id)"">$(& $enc $s.Title)</a></li>") }
    $null = $html.Append('</ol>')

    # 1. Summary
    $null = $html.Append((& $h2 'summary'))
    $null = $html.Append('<p class="intro">This assessment measures the tenant against the PIM Phase 2 HLD. Each role is given a trust level (TL1 highest) from the role catalogue, every route a person has to that role is traced (direct, PIM for Groups, nested groups, Azure RBAC), and the result is compared with the HLD target model. Trust levels marked Proposed or Open in the catalogue still need agreement (OD-02).</p>')
    $stat = { param($n, $l, $bad) $cls = if ($bad -and [int]$n -gt 0) { 'stat bad' } else { 'stat' }; "<div class=""$cls""><div class=""n"">$n</div><div class=""l"">$(& $enc $l)</div></div>" }
    $null = $html.Append('<div class="stats">')
    $null = $html.Append((& $stat $m.PeopleWithPrivilege 'People with privileged access' $false))
    $null = $html.Append((& $stat $m.PeopleWithTL1 'People who can reach TL1' $false))
    $null = $html.Append((& $stat $m.PeopleReachingGlobalAdmin 'People who can reach Global Administrator' $true))
    $null = $html.Append((& $stat $m.SelfApprovalPeople 'People who can approve their own elevation' $true))
    $null = $html.Append((& $stat $m.TL1InBundles 'Groups bundling TL1 with other roles' $true))
    $null = $html.Append((& $stat $m.StandingPrivilegedPaths 'Standing privileged paths' $true))
    $null = $html.Append((& $stat $m.EverydayIdentitiesWithPrivilege 'Everyday identities with privilege' $true))
    $null = $html.Append((& $stat $m.TL1PolicyGaps 'TL1 settings off baseline' $true))
    $null = $html.Append('</div>')

    $ins = New-Object System.Collections.ArrayList
    if ($m.SelfApprovalPeople -gt 0) { $null = $ins.Add("$(& $pl $m.SelfApprovalPeople 'person' 'people') can request elevation with one account and approve it with another ($($m.SelfApprovalTL1People) of them for TL1 roles). PIM only blocks approval by the same account, so this is the F01 route the HLD describes.") }
    if ($m.ApproverGroupsWithEveryday -gt 0) { $null = $ins.Add("$(& $pl $m.ApproverGroupsWithEveryday 'approver group contains' 'approver groups contain') everyday or guest identities. HLD 7.6.3 requires approver groups to hold CLAD identities only.") }
    if ($m.PeopleReachingGlobalAdmin -gt 0) { $null = $ins.Add("$(& $pl $m.PeopleReachingGlobalAdmin 'person' 'people') can reach Global Administrator, excluding break-glass. OD-03 needs a justified population.") }
    if ($m.TL1InBundles -gt 0) { $null = $ins.Add("$(& $pl $m.TL1InBundles 'group' 'groups') hand out TL1 roles alongside other roles, so one group activation grants Tier 0 together with operational roles (HLD 7.6.1).") }
    if ($m.StandingPrivilegedPaths -gt 0) { $null = $ins.Add("$(& $pl $m.StandingPrivilegedPaths 'standing path is' 'standing paths are') held by people ($($m.StandingTL1Paths) at TL1, $($m.AzureStandingTL1AtSubOrAbove) of them Azure TL1 at subscription scope or above).") }
    if ($m.EverydayIdentitiesWithPrivilege -gt 0 -or $m.GuestIdentitiesWithPrivilege -gt 0) { $null = $ins.Add("$($m.EverydayIdentitiesWithPrivilege) everyday and $($m.GuestIdentitiesWithPrivilege) guest identities hold privilege directly rather than through a CLAD (SEC-PIM-08).") }
    if ($m.GenericAccounts -gt 0) { $null = $ins.Add("$(& $pl $m.GenericAccounts 'generic or service user account holds' 'generic or service user accounts hold') privilege and will need replacement or an exception (HLD 7.9).") }
    if ($m.CladNotLinked -gt 0) { $null = $ins.Add("$(& $pl $m.CladNotLinked 'CLAD account' 'CLAD accounts') have no everyday identity in this evidence, because the export only holds identities that have roles or approve. Self-approval checks are still complete (every approver is in the evidence), but an identity map or the updated collector is needed to confirm the CLAD-to-person link for lifecycle (F07).") }
    if ($m.TL1WithoutPhishingResistant -gt 0) { $null = $ins.Add("$(& $pl $m.TL1WithoutPhishingResistant 'TL1 identity has' 'TL1 identities have') no phishing-resistant method recorded (SEC-PIM-06).") }
    if ($m.TL1PolicyGaps -gt 0) { $null = $ins.Add("$(& $pl $m.TL1PolicyGaps 'TL1 PIM setting differs' 'TL1 PIM settings differ') from the HLD baseline, most often the missing authentication context.") }
    if ($ins.Count -gt 0) {
        $null = $html.Append('<ul class="ins">')
        foreach ($x in $ins) { $null = $html.Append("<li>$(& $enc $x)</li>") }
        $null = $html.Append('</ul>')
    }

    # 2. HLD findings
    $null = $html.Append((& $h2 'hld'))
    $null = $html.Append('<p class="intro">Status of each HLD current-state finding, measured from this tenant''s evidence. "Not assessed" means the export does not contain the evidence; it does not mean the finding is closed.</p>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $Data.Hld -Columns @('Finding', 'Title', 'Status', 'Measure', 'Evidence')))

    # 3. Self-approval
    $null = $html.Append((& $h2 'self'))
    $null = $html.Append('<p class="intro">A person is listed when one of their identities is eligible for a role that needs approval and another of their identities (normally the everyday account) is an approver for that role. Identities are linked by name, by the CLAD naming pattern, or by an identity map file when one is supplied. Check rows marked ambiguous.</p>')
    $selfLinked = @($Data.SelfApproval | Where-Object { $_.Route -like 'Linked*' })
    $bySelfPerson = @($selfLinked | Group-Object Person | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{
            Person = $_.Name
            RequesterAccount = (@($g | Select-Object -ExpandProperty RequesterAccount -Unique) -join '; ')
            ApproverAccount = (@($g | Select-Object -ExpandProperty ApproverAccount -Unique) -join '; ')
            ApproverVia = (@($g | Select-Object -ExpandProperty ApproverVia -Unique) -join '; ')
            Roles = @($g | Select-Object -ExpandProperty Role -Unique).Count
            TL1Roles = (@($g | Where-Object TrustLevel -eq 'TL1' | Select-Object -ExpandProperty Role -Unique) -join '; ')
            Severity = if (@($g | Where-Object Severity -eq 'Critical').Count -gt 0) { 'Critical' } else { 'High' }
            LinkConfidence = (@($g | Select-Object -ExpandProperty LinkConfidence -Unique) -join '; ')
        }
    } | Sort-Object @{ Expression = { if ($_.Severity -eq 'Critical') { 0 } else { 1 } } }, Person)
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $bySelfPerson -Columns @('Person', 'Severity', 'RequesterAccount', 'ApproverAccount', 'ApproverVia', 'Roles', 'TL1Roles', 'LinkConfidence') -MaxRows 60 -CsvName 'P2_SelfApproval.csv'))
    $sameObj = @($Data.SelfApproval | Where-Object { $_.Route -like 'Same account*' } | Select-Object -ExpandProperty Person -Unique)
    if ($sameObj.Count -gt 0) { $null = $html.Append("<p class=""more"">A further $($sameObj.Count) people are both eligible and approvers with the same account. PIM stops them approving their own request, but they can approve each other's, which still weakens independence.</p>") }

    # 4. Approver groups
    $null = $html.Append((& $h2 'approvers'))
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $Data.ApproverGroups -Columns @('ApproverGroup', 'HighestTrustLevel', 'RolesApproved', 'Members', 'CladMembers', 'EverydayOrGuestMembers', 'ApproversAlsoEligible', 'SelfApprovalPeople', 'MeetsHld763', 'Issues')))

    # 5. TL1
    $null = $html.Append((& $h2 'tl1'))
    $tl1ByRole = @($Data.Tl1Paths | Group-Object Plane, Role | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{
            Plane = $g[0].Plane; Role = $g[0].Role
            People = @($g | Where-Object { $_.AccountType -notin @('WorkloadIdentity', 'BreakGlass') } | Select-Object -ExpandProperty Person -Unique).Count
            Direct = @($g | Where-Object PathType -eq 'Direct').Count
            ViaGroup = @($g | Where-Object PathType -ne 'Direct').Count
            Eligible = @($g | Where-Object EffectiveState -eq 'Eligible').Count
            Standing = @($g | Where-Object Standing).Count
            Groups = (@($g | Where-Object ViaGroup | Select-Object -ExpandProperty ViaGroup -Unique | Select-Object -First 5) -join '; ')
            Workloads = @($g | Where-Object AccountType -eq 'WorkloadIdentity' | Select-Object -ExpandProperty IdentityId -Unique).Count
        }
    } | Sort-Object People -Descending)
    $null = $html.Append('<p class="intro">Each TL1 role and how many people can reach it, directly or through a group. HLD 7.6.1 expects TL1 to be assigned directly as eligible, or through a single-purpose group, and not through an operational bundle.</p>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $tl1ByRole -Columns @('Plane', 'Role', 'People', 'Direct', 'ViaGroup', 'Eligible', 'Standing', 'Workloads', 'Groups') -MaxRows 60 -CsvName 'P2_TL1Paths.csv'))

    # 6. Bundles
    $null = $html.Append((& $h2 'bundles'))
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $Data.Bundles -Columns @('Group', 'HighestTrustLevel', 'Roles', 'TL1Roles', 'TL2Roles', 'TL3Roles', 'People', 'EligibleMembers', 'Recommendation') -MaxRows 40 -CsvName 'P2_GroupBundles.csv'))

    # 7. Standing
    $null = $html.Append((& $h2 'standing'))
    $null = $html.Append('<p class="intro">Permanent active access at TL1 to TL3 held by people. The HLD does not allow permanent active assignment at these levels; each must be converted to eligible or recorded as an exception. Break-glass and workload identities are listed in the CSV but left out here.</p>')
    $standingPeople = @($Data.Standing | Where-Object { $_.AccountType -notin @('WorkloadIdentity', 'BreakGlass') })
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $standingPeople -Columns @('TrustLevel', 'Plane', 'Identity', 'AccountType', 'PersonOrganisation', 'Role', 'Scope', 'PathType', 'ViaGroup') -MaxRows 80 -CsvName 'P2_StandingAccess.csv'))

    # 8. Identities
    $null = $html.Append((& $h2 'identities'))
    $typeSummary = @($Data.Identities | Group-Object AccountType | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{ AccountType = $_.Name; Identities = $g.Count; WithTL1 = @($g | Where-Object HighestTrustLevel -eq 'TL1').Count; WithStanding = @($g | Where-Object { $_.StandingPaths -gt 0 }).Count; WithIssues = @($g | Where-Object Issues).Count }
    } | Sort-Object Identities -Descending)
    $orgSummary = @($Data.Identities | Where-Object { $_.AccountType -notin @('WorkloadIdentity', 'Group') } | Group-Object PersonOrganisation | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{ Organisation = $_.Name; Identities = $g.Count; WithTL1 = @($g | Where-Object HighestTrustLevel -eq 'TL1').Count }
    } | Sort-Object Identities -Descending)
    $null = $html.Append('<h3>By account type</h3>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $typeSummary -Columns @('AccountType', 'Identities', 'WithTL1', 'WithStanding', 'WithIssues')))
    $null = $html.Append('<h3>By organisation</h3>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $orgSummary -Columns @('Organisation', 'Identities', 'WithTL1')))
    $null = $html.Append('<h3>Identities with issues</h3>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows @($Data.Identities | Where-Object { $_.Issues -and $_.AccountType -ne 'WorkloadIdentity' }) -Columns @('HighestTrustLevel', 'Identity', 'AccountType', 'PersonOrganisation', 'LinkedEveryday', 'TL1Paths', 'StandingPaths', 'Issues') -MaxRows 80 -CsvName 'P2_PrivilegedIdentities.csv'))

    # 9. Policy
    $null = $html.Append((& $h2 'policy'))
    $null = $html.Append('<p class="intro">PIM role settings compared with the trust-level baselines in the catalogue (HLD 7.5, runbook 4.3). Approval at TL2 depends on role impact, so it is not flagged as a gap there.</p>')
    $gapSummary = @($Data.PolicyGaps | Group-Object TrustLevel, Setting | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{ TrustLevel = $g[0].TrustLevel; Setting = $g[0].Setting; Subjects = $g.Count; Target = $g[0].Target; Examples = (@($g | Select-Object -ExpandProperty Subject -First 6) -join '; ') }
    } | Sort-Object TrustLevel, Setting)
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $gapSummary -Columns @('TrustLevel', 'Setting', 'Subjects', 'Target', 'Examples')))
    if (-not $Data.Collected.GroupPolicies) { $null = $html.Append('<p class="note">PIM for Groups activation settings were not in this export. Where a role is reached by activating group membership, the group''s own settings control the activation; re-run with the current collector to include them.</p>') }

    # 10. Catalogue
    $null = $html.Append((& $h2 'catalogue'))
    $null = $html.Append('<p class="intro">Every role in use with its proposed trust level. Use this as the starting point for the role catalogue agreed with the partners. Role owners are blank until assigned.</p>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows @($Data.Catalogue | Where-Object { $_.TrustLevel -ne 'TL4' }) -Columns @('TrustLevel', 'Plane', 'Role', 'ScopeLevel', 'Classification', 'People', 'DirectPaths', 'GroupPaths', 'EligiblePaths', 'StandingPaths', 'PolicyGaps') -MaxRows 120 -CsvName 'P2_RoleCatalogue.csv'))

    # 11. Exceptions
    $null = $html.Append((& $h2 'exceptions'))
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $Data.Exceptions -Columns @('Category', 'Subject', 'Detail', 'HldReference', 'RequiredEvidence') -MaxRows 80 -CsvName 'P2_ExceptionCandidates.csv'))

    # 12. Maturity
    $null = $html.Append((& $h2 'maturity'))
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $Data.Maturity -Columns @('Capability', 'HldBaseline', 'Phase2Target', 'Indicator')))

    # 13. Migration
    $null = $html.Append((& $h2 'migration'))
    $null = $html.Append("<p class=""intro"">P2_MigrationWorksheet.csv has one row per privileged path ($($Data.Migration.Count) rows) with the proposed action and blank Target path, Wave, Role owner and Decision columns for the rebaseline workshops (runbook 1.2, 5.1). Summary of proposed actions:</p>")
    $actionSummary = @($Data.Migration | ForEach-Object { foreach ($a in ([string]$_.ProposedActions).Split('|')) { $a.Trim() } } | Group-Object | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ ProposedAction = $_.Name; Paths = $_.Count } })
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $actionSummary -Columns @('ProposedAction', 'Paths')))

    # 14. Method
    $null = $html.Append((& $h2 'method'))
    $null = $html.Append('<ul class="ins">')
    $null = $html.Append('<li>Trust levels come from Config/pim-phase2.catalogue.json. Entra roles are classified by name; Azure roles by role family and scope (HLD 7.11.2), raised to TL1 where the scope name or resource types match the sensitive-scope rules.</li>')
    $null = $html.Append('<li>Account types come from naming rules (CLAD prefix, display name patterns, generic and break-glass patterns) and the organisation from the home domain of the UPN.</li>')
    $null = $html.Append('<li>CLAD identities are linked to everyday identities by cleaned display name, falling back to surname and initial. An identity map CSV (PrivilegedUpn, EverydayUpn, Person) overrides this.</li>')
    $null = $html.Append('<li>Group paths combine PIM for Groups eligible and active membership, ordinary membership and nested membership with the roles assigned to the group. A path is standing when both membership and role assignment are permanent and active.</li>')
    $null = $html.Append('<li>Not measured from configuration: monitoring (F10), password and recovery (F12), approver rota (F13), device enforcement in practice (F06). These need the runbook tests.</li>')
    if (-not $Data.HasAzure) { $null = $html.Append('<li><strong>No Azure run supplied.</strong> Azure privilege is not included.</li>') }
    if (-not $Data.HasEntra) { $null = $html.Append('<li><strong>No Entra run supplied.</strong> Entra roles, approvals and policies are not included.</li>') }
    if (-not $Data.Collected.AuthMethods) { $null = $html.Append('<li>Authentication method registration was taken from the identity assurance summary; FIDO2 registration per identity was not collected in this run.</li>') }
    $null = $html.Append('</ul>')

    $null = $html.Append('</main></body></html>')

    $safe = ($Data.TenantShortName -replace '[^A-Za-z0-9_-]', '_')
    $path = Join-Path -Path $OutputFolder -ChildPath "PIM_Phase2_Assessment_$safe.html"
    [System.IO.File]::WriteAllText($path, $html.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $path
}
