<#
.SYNOPSIS
Builds the privileged access audit report (HTML) for one tenant. Function definitions only; dot-sourced by
Invoke-PimPhase2Assessment.ps1 (and, for the table helpers, by the roll-up and diff scripts).
#>

function ConvertTo-P2Label {
    param([string]$Name)
    $map = @{
        Upn = 'UPN'; TL1Paths = 'TL1 routes'; TL2Paths = 'TL2 routes'; TL3Paths = 'TL3 routes'; TL1Roles = 'TL1 roles'; TL2Roles = 'TL2 roles'; TL3Roles = 'TL3 roles'
        HasP2Licence = 'P2 licence'; HasFido2 = 'FIDO2'; MeetsHld763 = 'Meets HLD 7.6.3'; HldBaseline = 'HLD baseline'; Phase2Target = 'Phase 2 target'
        HldReference = 'HLD reference'; ApproversAlsoEligible = 'Approvers also eligible'; SelfApprovalPeople = 'Self-approval people'
        JustInTime = 'Just-in-time'; TimeBound = 'Time-bound active'; PimStatus = 'PIM status'; TimesGuide = 'x guide'; CafOutcome = 'CAF'; NcscPrinciple = 'NCSC SSA'
        PersonOrganisation = 'Organisation'
    }
    if ($map.ContainsKey($Name)) { return $map[$Name] }
    $Name = $Name -creplace 'TL([1-4])', ' TL$1 ' -creplace 'P2', ' P2 '
    $label = (($Name -creplace '([a-z])([A-Z])', '$1 $2') -creplace '([A-Z]+)([A-Z][a-z])', '$1 $2')
    return (($label -replace '\s+', ' ').Trim())
}

function Get-P2BadgeClass {
    param([string]$Value)
    switch -Regex ($Value) {
        '^TL1$' { return 'b tl1' } '^TL2$' { return 'b tl2' } '^TL3$' { return 'b tl3' } '^TL4$' { return 'b tl4' }
        '^Critical$' { return 'b crit' } '^High$' { return 'b high' } '^Medium$' { return 'b med' } '^Low$' { return 'b low' }
        '^(Good|Achieved|Strong|Within|Just-in-time \(PIM\)|Not observed|Addressed)$' { return 'b good' }
        '^(Partial|Partially achieved|Partly in place|Mixed|Time-bound active|Partially|Indicated|Test required)$' { return 'b part' }
        '^(Weak|Not achieved|Over|Permanent \(no PIM\)|Confirmed)$' { return 'b weak' }
        '^(Not assessed|Open)$' { return 'b na' }
        default { return '' }
    }
}

function ConvertTo-P2HtmlTable {
    param([object[]]$Rows, [string[]]$Columns, [int]$MaxRows = 0, [string]$CsvName)
    $all = @($Rows | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) { return '<p class="none">None found.</p>' }
    $shown = $all
    if ($MaxRows -gt 0 -and $all.Count -gt $MaxRows) { $shown = @($all | Select-Object -First $MaxRows) }
    $badgeCols = @('TrustLevel', 'HighestTrustLevel', 'Severity', 'Status', 'Result', 'Rating', 'PimStatus')
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
            if ($c -in $badgeCols) { $cls = Get-P2BadgeClass -Value ([string]$v); if ($cls) { $t = "<span class=""$cls"">$t</span>" } }
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
    $audit = $Data.Audit
    $pl = { param($n, $one, $many) if ([int]$n -eq 1) { "$n $one" } else { "$n $many" } }
    $brand = $Data.Branding
    $preparedBy = if ($brand -and $brand.PreparedBy) { $brand.PreparedBy } else { 'PIM review' }
    $programme = if ($brand -and $brand.Programme) { $brand.Programme } else { 'PIM review' }
    $classification = if ($brand -and $brand.Classification) { $brand.Classification } else { 'Confidential' }
    $humanTypes = @('CLAD', 'Other admin account', 'Everyday', 'Guest', 'Generic/Service')

    $css = @'
:root{--ink:#1b2430;--muted:#5d6878;--line:#e1e6ec;--soft:#f5f7fa;--accent:#1f4e78;--good:#1e7b45;--goodbg:#e8f5ee;--part:#a15c00;--partbg:#fff4e0;--weak:#b42318;--weakbg:#fdecea;--na:#6b7785;--nabg:#eef1f4}
*{box-sizing:border-box}
body{font-family:"Segoe UI",system-ui,-apple-system,Arial,sans-serif;margin:0;color:var(--ink);background:#fff;line-height:1.55;font-size:15px}
main{max-width:1180px;margin:0 auto;padding:28px 16px 80px}
h1{font-size:30px;line-height:1.2;margin:0 0 6px}
h2{font-size:22px;margin:48px 0 6px;color:var(--accent)}
h2+.lede{margin-top:0}
h3{font-size:16px;margin:24px 0 8px}
a{color:var(--accent)}
.cover{border-bottom:3px solid var(--accent);padding-bottom:18px;margin-bottom:8px}
.kicker{text-transform:uppercase;letter-spacing:.08em;font-size:12px;color:var(--muted);font-weight:600}
.meta{color:var(--muted);font-size:13px;margin-top:6px}
.lede{color:var(--muted);max-width:820px;margin:4px 0 16px}
.verdict{font-size:18px;line-height:1.5;margin:18px 0;max-width:900px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:16px 0}
.tile{border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:#fff}
.tile .n{font-size:28px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1.1}
.tile .l{font-size:13px;color:var(--muted);margin-top:4px}
.tile .g{font-size:12px;margin-top:6px;font-weight:600}
.tile.good .n,.tile.good .g{color:var(--good)} .tile.part .n,.tile.part .g{color:var(--part)} .tile.weak .n,.tile.weak .g{color:var(--weak)}
.caf{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px;margin:12px 0}
.cafc{border:1px solid var(--line);border-radius:8px;padding:12px 14px;border-top-width:4px}
.cafc.good{border-top-color:var(--good)} .cafc.part{border-top-color:var(--part)} .cafc.weak{border-top-color:var(--weak)} .cafc.na{border-top-color:var(--na)}
.cafc .id{font-weight:700} .cafc .t{font-size:13px;color:var(--muted);margin:2px 0 8px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.list{list-style:none;padding:0;margin:0}
.list li{border:1px solid var(--line);border-left:4px solid var(--good);border-radius:6px;padding:10px 12px;margin-bottom:8px;background:#fff}
.list li .h{font-weight:600}
.list li .d{color:var(--muted);font-size:14px}
.card{border:1px solid var(--line);border-left:5px solid var(--weak);border-radius:8px;padding:14px 16px;margin:12px 0;background:#fff;page-break-inside:avoid}
.card.part{border-left-color:var(--part)}
.card .top{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.card .title{font-weight:700;font-size:16px}
.card .found{margin:8px 0}
.card dl{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;margin:8px 0 0;font-size:14px}
.card dt{color:var(--muted)} .card dd{margin:0}
.ref{font-size:12px;color:var(--muted);margin-top:8px}
.b{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.b.good{background:var(--goodbg);color:var(--good)} .b.part{background:var(--partbg);color:var(--part)} .b.weak{background:var(--weakbg);color:var(--weak)} .b.na{background:var(--nabg);color:var(--na)}
.b.crit{background:#7a0e0e;color:#fff} .b.high{background:var(--weak);color:#fff} .b.med{background:#d27a00;color:#fff} .b.low{background:#55606e;color:#fff}
.b.tl1{background:#3d1a5b;color:#fff} .b.tl2{background:#6a3d9a;color:#fff} .b.tl3{background:#a58bc6;color:#fff} .b.tl4{background:#d9cfe7;color:#2c1d40}
.bars{margin:10px 0 18px}
.bar{display:grid;grid-template-columns:150px 1fr 70px;gap:10px;align-items:center;margin:6px 0;font-size:14px}
.track{display:flex;height:18px;border-radius:4px;overflow:hidden;background:var(--soft)}
.seg.j{background:var(--good)} .seg.t{background:#e0a243} .seg.p{background:var(--weak)}
.legend{font-size:13px;color:var(--muted);display:flex;gap:16px;flex-wrap:wrap}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:middle}
.meter{display:flex;align-items:center;gap:8px}
.meter .mt{flex:1;height:8px;background:var(--soft);border-radius:4px;position:relative;min-width:80px}
.meter .mf{height:8px;border-radius:4px}
.tw{overflow-x:auto;margin:8px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}
th{background:var(--soft);font-weight:600;position:sticky;top:0}
.none{color:var(--good);font-style:italic}
.more{color:var(--muted);font-size:12px;font-style:italic}
.note{background:var(--soft);border-radius:8px;padding:12px 14px;font-size:14px;color:var(--ink)}
.toc{columns:2;font-size:14px;padding-left:18px}
details{border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:10px 0}
details>summary{cursor:pointer;font-weight:600;padding:4px 0}
@media (max-width:760px){.cols{grid-template-columns:1fr}.toc{columns:1}.card dl{grid-template-columns:1fr}h1{font-size:24px}.bar{grid-template-columns:100px 1fr 50px}}
@media print{details{border:none}details>summary{display:none}details:not([open])>*{display:block}th{position:static}h2{page-break-after:avoid}}
'@

    $controls = @($audit.Controls)
    $good = @($audit.Strengths)
    $weak = @($audit.Weaknesses)
    $nGood = $good.Count
    $nPart = @($controls | Where-Object Result -eq 'Partial').Count
    $nWeak = @($controls | Where-Object Result -eq 'Weak').Count
    $resultClass = { param($r) switch ($r) { 'Good' { 'good' } 'Achieved' { 'good' } 'Strong' { 'good' } 'Partial' { 'part' } 'Partially achieved' { 'part' } 'Partly in place' { 'part' } 'Weak' { 'weak' } 'Not achieved' { 'weak' } default { 'na' } } }

    $html = New-Object System.Text.StringBuilder
    $title = "Privileged Access Audit - $($Data.TenantName)"
    $null = $html.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>$(& $enc $title)</title><style>$css</style></head><body><main>")

    # ---- Cover --------------------------------------------------------------------------------
    $null = $html.Append('<div class="cover">')
    $null = $html.Append("<div class=""kicker"">$(& $enc $programme)</div>")
    $null = $html.Append("<h1>Privileged Access Audit: $(& $enc $Data.TenantName)</h1>")
    $null = $html.Append('<div class="meta">Entra ID and Azure administrative access, PIM usage and controls, benchmarked against the NCSC Cyber Assessment Framework (CAF 4.0, Principle B2) and Microsoft guidance.</div>')
    $null = $html.Append("<div class=""meta"">Evidence: Entra run $(& $enc $(if ($Data.EntraRun) { $Data.EntraRun } else { 'not supplied' })) &middot; Azure run $(& $enc $(if ($Data.AzureRun) { $Data.AzureRun } else { 'not supplied' })) &middot; Prepared by $(& $enc $preparedBy) &middot; $(Get-Date -Format 'd MMMM yyyy') &middot; $(& $enc $classification)</div>")
    $null = $html.Append('</div>')

    $sections = @(
        @{ Id = 'glance'; Title = 'At a glance' },
        @{ Id = 'good'; Title = 'What is working well' },
        @{ Id = 'attention'; Title = 'What needs attention' },
        @{ Id = 'benchmark'; Title = 'NCSC benchmark' },
        @{ Id = 'pim'; Title = 'Where PIM is used, and where it is not' },
        @{ Id = 'over'; Title = 'Over-subscribed roles' },
        @{ Id = 'controls'; Title = 'All control checks' },
        @{ Id = 'evidence'; Title = 'Detailed evidence' },
        @{ Id = 'method'; Title = 'How to read this report' }
    )
    $null = $html.Append('<ol class="toc">')
    foreach ($s in $sections) { $null = $html.Append("<li><a href=""#$($s.Id)"">$(& $enc $s.Title)</a></li>") }
    $null = $html.Append('</ol>')

    # ---- 1. At a glance -----------------------------------------------------------------------
    $null = $html.Append('<h2 id="glance">At a glance</h2>')
    $top = @($weak | Where-Object { $_.Result -eq 'Weak' -and $_.Gap } | Select-Object -First 4 | ForEach-Object { $_.Gap })
    $topGood = @($good | Select-Object -First 3 | ForEach-Object { $t = [string]$_.Control; if ($t -match '^(Tier|Global|Azure|Entra|Conditional|PIM|Microsoft)\b') { $t } else { $t.Substring(0, 1).ToLower() + $t.Substring(1) } })
    $verdict = "Of $($controls.Count - @($controls | Where-Object Result -eq 'Not assessed').Count) controls checked, <strong>$nGood are in place</strong>, $nPart are partly in place and <strong>$nWeak are weak</strong>."
    if ($topGood.Count -gt 0) { $verdict += ' On the positive side: ' + (& $enc ($topGood -join '; ')) + '.' }
    if ($top.Count -gt 0) { $verdict += ' The most important gaps are that ' + (& $enc ($top -join '; ')) + '.' }
    $null = $html.Append("<p class=""verdict"">$verdict</p>")

    $peopleN = [int]$m.PeopleWithPrivilege
    $humanPaths = @($Data.PrivPathsHuman)
    $entraH = @($humanPaths | Where-Object Plane -eq 'Entra')
    $azH = @($humanPaths | Where-Object { $_.Plane -eq 'Azure' -and $_.AzureFamily -ne 'Reader' })
    $pctE = if ($entraH.Count) { [int][Math]::Round(100 * @($entraH | Where-Object EffectiveState -eq 'Eligible').Count / $entraH.Count) } else { $null }
    $pctA = if ($azH.Count) { [int][Math]::Round(100 * @($azH | Where-Object EffectiveState -eq 'Eligible').Count / $azH.Count) } else { $null }
    $tile = {
        param($n, $label, $cls, $guide)
        $g = if ($guide) { "<div class=""g"">$(& $enc $guide)</div>" } else { '' }
        "<div class=""tile $cls""><div class=""n"">$(& $enc $n)</div><div class=""l"">$(& $enc $label)</div>$g</div>"
    }
    $null = $html.Append('<div class="tiles">')
    $null = $html.Append((& $tile $peopleN 'People with admin access (Entra or Azure)' '' $null))
    $ga = [int]$m.PeopleReachingGlobalAdmin
    $null = $html.Append((& $tile $ga 'People who can become Global Administrator' $(if ($ga -lt 5) { 'good' } else { 'weak' }) 'Microsoft guide: fewer than 5'))
    $null = $html.Append((& $tile $m.PeopleWithTL1 'People who can reach Tier 0 (TL1)' '' $null))
    if ($null -ne $pctE) { $null = $html.Append((& $tile "$pctE%" 'Entra admin access that is just-in-time (PIM)' $(if ($pctE -ge 90) { 'good' } elseif ($pctE -ge 60) { 'part' } else { 'weak' }) 'Target: all, except break-glass')) }
    if ($null -ne $pctA) { $null = $html.Append((& $tile "$pctA%" 'Azure write access that is just-in-time (PIM)' $(if ($pctA -ge 90) { 'good' } elseif ($pctA -ge 50) { 'part' } else { 'weak' }) 'Target: all write access')) }
    $null = $html.Append((& $tile $m.SelfApprovalPeople 'People who can approve their own elevation' $(if ([int]$m.SelfApprovalPeople -eq 0) { 'good' } else { 'weak' }) 'Target: none'))
    $null = $html.Append((& $tile $m.StandingTL1Paths 'Permanent Tier 0 routes held by people' $(if ([int]$m.StandingTL1Paths -eq 0) { 'good' } else { 'weak' }) 'Target: none'))
    $null = $html.Append('</div>')

    $gaps = @($Data.AzCoverageGaps)
    if ($gaps.Count -gt 0) {
        $gapLines = @()
        $rootGap = @($gaps | Where-Object { $_.Scope -eq '/' })
        if ($rootGap.Count -gt 0) { $gapLines += 'role assignments at the tenant root could not be read (no access at root)' }
        $notVisible = @($gaps | Where-Object { $_.Operation -eq 'Resources not visible' })
        if ($notVisible.Count -gt 0) { $gapLines += "resources inside $(& $pl $notVisible.Count 'subscription' 'subscriptions') could not be listed, so resource-level checks (Key Vault, storage, sensitive resource groups) are incomplete" }
        $act = @($gaps | Where-Object { $_.Operation -match 'Activity' })
        if ($act.Count -gt 0) { $gapLines += "the Activity Log could not be read for $(& $pl $act.Count 'subscription' 'subscriptions')" }
        $other = $gaps.Count - $rootGap.Count - $notVisible.Count - $act.Count
        if ($other -gt 0) { $gapLines += "$other other collection gaps (see Azure\Raw\AzureCoverageGaps.csv)" }
        $null = $html.Append("<p class=""note""><strong>Coverage limits for Azure:</strong> $(& $enc ($gapLines -join '; ')). Reader at the tenant root management group closes these gaps.</p>")
    }
    $null = $html.Append('<h3>NCSC CAF Principle B2 (indicative)</h3><div class="caf">')
    foreach ($c in @($audit.Caf)) {
        $cls = & $resultClass $c.Rating
        $null = $html.Append("<div class=""cafc $cls""><div class=""id"">$(& $enc $c.Outcome) $(& $enc $c.Title)</div><div class=""t"">$(& $enc $c.WhatTheOutcomeMeans)</div><span class=""$(Get-P2BadgeClass -Value $c.Rating)"">$(& $enc $c.Rating)</span> <span class=""more"">$($c.Good) good, $($c.Partial) partial, $($c.Weak) weak</span></div>")
    }
    $null = $html.Append('</div>')

    # ---- 2. Strengths -------------------------------------------------------------------------
    $null = $html.Append('<h2 id="good">What is working well</h2><p class="lede">Controls that already meet the expected standard. These are worth keeping as the programme changes other things.</p>')
    if ($good.Count -eq 0) { $null = $html.Append('<p class="more">No control fully met the standard in this evidence.</p>') }
    else {
        $null = $html.Append('<ul class="list">')
        foreach ($c in $good) { $null = $html.Append("<li><div class=""h"">$(& $enc $c.Control)</div><div class=""d"">$(& $enc $c.Finding)</div></li>") }
        $null = $html.Append('</ul>')
    }
    $nPartial = @($controls | Where-Object Result -eq 'Partial').Count
    if ($nPartial -gt 0) { $null = $html.Append("<p class=""more"">A further $nPartial controls are partly in place; they are listed under What needs attention.</p>") }

    # ---- 3. Weaknesses ------------------------------------------------------------------------
    $null = $html.Append('<h2 id="attention">What needs attention</h2><p class="lede">In priority order: weak controls first, by severity, then controls that are partly in place.</p>')
    foreach ($c in $weak) {
        $cardCls = if ($c.Result -eq 'Partial') { 'card part' } else { 'card' }
        $null = $html.Append("<div class=""$cardCls""><div class=""top""><span class=""$(Get-P2BadgeClass -Value $c.Result)"">$(& $enc $c.Result)</span>")
        if ($c.Severity) { $null = $html.Append("<span class=""$(Get-P2BadgeClass -Value $c.Severity)"">$(& $enc $c.Severity)</span>") }
        $null = $html.Append("<span class=""title"">$(& $enc $c.Control)</span></div>")
        $null = $html.Append("<div class=""found"">$(& $enc $c.Finding)</div><dl>")
        if ($c.WhyItMatters) { $null = $html.Append("<dt>Why it matters</dt><dd>$(& $enc $c.WhyItMatters)</dd>") }
        if ($c.WhatGoodLooksLike) { $null = $html.Append("<dt>What good looks like</dt><dd>$(& $enc $c.WhatGoodLooksLike)</dd>") }
        if ($c.RecommendedAction) { $null = $html.Append("<dt>Recommended action</dt><dd>$(& $enc $c.RecommendedAction)</dd>") }
        $null = $html.Append('</dl>')
        $refs = @()
        if ($c.CafOutcome) { $refs += "NCSC CAF $($c.CafOutcome)" }
        if ($c.NcscPrinciple) { $refs += "NCSC secure system administration $($c.NcscPrinciple -replace 'SSA ', 'principle ')" }
        if ($c.Reference) { $refs += $c.Reference }
        if ($c.Evidence) { $refs += "Evidence: $($c.Evidence)" }
        $null = $html.Append("<div class=""ref"">$(& $enc ($refs -join ' | ')) &middot; $(& $enc $c.Id)</div></div>")
    }

    # ---- 4. Benchmark -------------------------------------------------------------------------
    $null = $html.Append('<h2 id="benchmark">NCSC benchmark</h2>')
    $null = $html.Append('<p class="lede">The NCSC Cyber Assessment Framework (CAF 4.0) is the benchmark for UK public sector organisations, including under GovAssure. Principle B2 covers identity and access control. Ratings here are indicative: they use configuration evidence only. A formal CAF assessment also needs process evidence such as joiners, movers and leavers records, review sign-offs and monitoring.</p>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $audit.Caf -Columns @('Outcome', 'Title', 'Rating', 'Good', 'Partial', 'Weak', 'Controls')))
    $null = $html.Append('<h3>NCSC secure system administration principles</h3>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $audit.Ssa -Columns @('Principle', 'Title', 'Rating', 'Good', 'Partial', 'Weak', 'Controls')))
    $null = $html.Append('<p class="more">Rating rule: Not achieved / Weak if any check is weak at High or Critical severity; Partially achieved if any check is weak or partial; Achieved if every assessed check is good. This mirrors the CAF approach, where a single Not achieved indicator prevents a higher rating.</p>')

    # ---- 5. PIM coverage ----------------------------------------------------------------------
    $null = $html.Append('<h2 id="pim">Where PIM is used, and where it is not</h2>')
    $null = $html.Append('<p class="lede">Every route a person has to an admin role, split by whether it is just-in-time (eligible in PIM, activated when needed), time-bound (active with an end date) or permanent. A route through a group counts as just-in-time if either the group membership or the group''s role is eligible.</p>')
    $null = $html.Append('<div class="legend"><span><i style="background:var(--good)"></i>Just-in-time (PIM)</span><span><i style="background:#e0a243"></i>Time-bound active</span><span><i style="background:var(--weak)"></i>Permanent</span></div><div class="bars">')
    foreach ($plane in @('Entra', 'Azure')) {
        foreach ($tl in @('TL1', 'TL2', 'TL3')) {
            $rs = @($humanPaths | Where-Object { $_.Plane -eq $plane -and $_.TrustLevel -eq $tl -and $_.AzureFamily -ne 'Reader' })
            if ($rs.Count -eq 0) { continue }
            $j = @($rs | Where-Object EffectiveState -eq 'Eligible').Count
            $p = @($rs | Where-Object Standing).Count
            $t = $rs.Count - $j - $p
            if ($t -lt 0) { $t = 0 }
            $w = { param($x) [Math]::Round(100.0 * $x / $rs.Count, 2) }
            $null = $html.Append("<div class=""bar""><div>$plane $tl</div><div class=""track"" title=""$j just-in-time, $t time-bound, $p permanent""><div class=""seg j"" style=""width:$(& $w $j)%""></div><div class=""seg t"" style=""width:$(& $w $t)%""></div><div class=""seg p"" style=""width:$(& $w $p)%""></div></div><div>$([int](& $w $j))% JIT</div></div>")
        }
    }
    $null = $html.Append('</div>')
    $null = $html.Append('<h3>Entra roles</h3>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $audit.CoverageEntra -Columns @('TrustLevel', 'Role', 'PimStatus', 'People', 'JustInTime', 'TimeBound', 'Permanent', 'ViaGroups') -MaxRows 80 -CsvName 'P2_PimCoverage.csv'))
    if ($Data.HasAzure) {
        $null = $html.Append('<h3>Azure roles (TL1 and TL2, by scope)</h3>')
        $null = $html.Append((ConvertTo-P2HtmlTable -Rows $audit.CoverageAzure -Columns @('TrustLevel', 'Role', 'ScopeLevel', 'PimStatus', 'People', 'JustInTime', 'TimeBound', 'Permanent', 'ViaGroups') -MaxRows 80 -CsvName 'P2_PimCoverage.csv'))
    }

    # ---- 6. Over-subscription ---------------------------------------------------------------
    $null = $html.Append('<h2 id="over">Over-subscribed roles</h2>')
    $null = $html.Append('<p class="lede">How many people can reach each high-impact role, against a guide number. Global Administrator and Azure subscription owners use Microsoft''s published guidance; other roles use the assessment guide in the catalogue (TL1: 5, TL2: 10), which the partners can change.</p>')
    $overRows = @($audit.Oversubscribed | Where-Object { $_.Status -eq 'Over' -or $_.TrustLevel -eq 'TL1' })
    if ($overRows.Count -eq 0) { $null = $html.Append('<p class="none">No role exceeds its guide.</p>') }
    else {
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.Append('<div class="tw"><table><thead><tr><th>Role</th><th>Scope</th><th>Level</th><th>People</th><th>Guide</th><th style="min-width:180px">Against guide</th><th>Source of guide</th></tr></thead><tbody>')
        foreach ($r in ($overRows | Select-Object -First 60)) {
            $ratio = if ($r.Guide -gt 0) { [double]$r.People / $r.Guide } else { 0 }
            $width = [Math]::Min(100, [Math]::Round(100 * $ratio / 4, 1))
            $col = if ($r.Status -eq 'Over') { 'var(--weak)' } else { 'var(--good)' }
            $null = $sb.Append("<tr><td>$(& $enc $r.Role)</td><td>$(& $enc $r.Scope)</td><td><span class=""$(Get-P2BadgeClass -Value $r.TrustLevel)"">$($r.TrustLevel)</span></td><td><strong>$($r.People)</strong></td><td>$($r.Guide)</td><td><div class=""meter""><div class=""mt""><div class=""mf"" style=""width:$width%;background:$col""></div></div><span class=""$(Get-P2BadgeClass -Value $r.Status)"">$(if ($r.Status -eq 'Over') { "$($r.TimesGuide)x" } else { 'Within' })</span></div></td><td class=""more"">$(& $enc $r.GuideSource)</td></tr>")
        }
        $null = $sb.Append('</tbody></table></div><p class="more">Bar scale: full width is four times the guide. Full list in P2_OversubscribedRoles.csv.</p>')
        $null = $html.Append($sb.ToString())
    }

    # ---- 7. All controls ----------------------------------------------------------------------
    $null = $html.Append('<h2 id="controls">All control checks</h2>')
    $null = $html.Append((ConvertTo-P2HtmlTable -Rows $controls -Columns @('Id', 'Area', 'Control', 'Result', 'Severity', 'Finding', 'CafOutcome', 'NcscPrinciple')))

    # ---- 8. Evidence --------------------------------------------------------------------------
    $null = $html.Append('<h2 id="evidence">Detailed evidence</h2><p class="lede">Expand a section for the underlying detail. Every table is also in the CSV files in this folder.</p>')
    $det = { param($Title, $Body, $Open) $o = if ($Open) { ' open' } else { '' }; "<details$o><summary>$(& $enc $Title)</summary>$Body</details>" }

    $selfLinked = @($Data.SelfApproval | Where-Object { $_.Route -like 'Linked*' })
    $bySelfPerson = @($selfLinked | Group-Object Person | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{
            Person = $_.Name
            Severity = if (@($g | Where-Object Severity -eq 'Critical').Count -gt 0) { 'Critical' } else { 'High' }
            RequesterAccount = (@($g | Select-Object -ExpandProperty RequesterAccount -Unique) -join '; ')
            ApproverAccount = (@($g | Select-Object -ExpandProperty ApproverAccount -Unique) -join '; ')
            ApproverVia = (@($g | Select-Object -ExpandProperty ApproverVia -Unique) -join '; ')
            Roles = @($g | Select-Object -ExpandProperty Role -Unique).Count
            TL1Roles = (@($g | Where-Object TrustLevel -eq 'TL1' | Select-Object -ExpandProperty Role -Unique) -join '; ')
            LinkConfidence = (@($g | Select-Object -ExpandProperty LinkConfidence -Unique) -join '; ')
        }
    } | Sort-Object Person)
    $null = $html.Append((& $det "Self-approval: $($bySelfPerson.Count) people" ('<p class="more">A person is listed when one of their accounts is eligible for a role that needs approval and another of their accounts approves that role. Accounts are linked by name and the admin-account naming pattern; check rows marked ambiguous.</p>' + (ConvertTo-P2HtmlTable -Rows $bySelfPerson -Columns @('Person', 'Severity', 'RequesterAccount', 'ApproverAccount', 'ApproverVia', 'Roles', 'TL1Roles', 'LinkConfidence') -MaxRows 80 -CsvName 'P2_SelfApproval.csv')) $false))
    $null = $html.Append((& $det "Approver groups: $(@($Data.ApproverGroups).Count)" (ConvertTo-P2HtmlTable -Rows $Data.ApproverGroups -Columns @('ApproverGroup', 'HighestTrustLevel', 'RolesApproved', 'Members', 'CladMembers', 'EverydayOrGuestMembers', 'ApproversAlsoEligible', 'SelfApprovalPeople', 'Issues')) $false))

    $tl1ByRole = @($Data.Tl1Paths | Group-Object Plane, Role | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{
            Plane = $g[0].Plane; Role = $g[0].Role
            People = @($g | Where-Object { $_.AccountType -in $humanTypes } | Select-Object -ExpandProperty Person -Unique).Count
            Direct = @($g | Where-Object PathType -eq 'Direct').Count
            ViaGroup = @($g | Where-Object PathType -ne 'Direct').Count
            Eligible = @($g | Where-Object EffectiveState -eq 'Eligible').Count
            Permanent = @($g | Where-Object Standing).Count
            Groups = (@($g | Where-Object ViaGroup | Select-Object -ExpandProperty ViaGroup -Unique | Select-Object -First 5) -join '; ')
        }
    } | Sort-Object People -Descending)
    $null = $html.Append((& $det "Routes to Tier 0 (TL1) roles: $($tl1ByRole.Count) roles" (ConvertTo-P2HtmlTable -Rows $tl1ByRole -Columns @('Plane', 'Role', 'People', 'Direct', 'ViaGroup', 'Eligible', 'Permanent', 'Groups') -MaxRows 80 -CsvName 'P2_TL1Paths.csv') $false))
    $null = $html.Append((& $det "Groups that bundle roles: $(@($Data.Bundles).Count)" (ConvertTo-P2HtmlTable -Rows $Data.Bundles -Columns @('Group', 'HighestTrustLevel', 'Roles', 'TL1Roles', 'TL2Roles', 'TL3Roles', 'People', 'Recommendation') -MaxRows 60 -CsvName 'P2_GroupBundles.csv') $false))
    $standingPeople = @($Data.Standing | Where-Object { $_.AccountType -in $humanTypes })
    $null = $html.Append((& $det "Permanent admin access held by people: $($standingPeople.Count) routes" (ConvertTo-P2HtmlTable -Rows $standingPeople -Columns @('TrustLevel', 'Plane', 'Identity', 'AccountType', 'PersonOrganisation', 'Role', 'Scope', 'PathType', 'ViaGroup') -MaxRows 120 -CsvName 'P2_StandingAccess.csv') $false))

    $typeSummary = @($Data.Identities | Group-Object AccountType | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{ AccountType = $_.Name; Identities = $g.Count; WithTL1 = @($g | Where-Object HighestTrustLevel -eq 'TL1').Count; WithPermanent = @($g | Where-Object { $_.StandingPaths -gt 0 }).Count; WithIssues = @($g | Where-Object Issues).Count }
    } | Sort-Object Identities -Descending)
    $orgSummary = @($Data.Identities | Where-Object { $_.AccountType -in $humanTypes } | Group-Object PersonOrganisation | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{ Organisation = $_.Name; Identities = $g.Count; WithTL1 = @($g | Where-Object HighestTrustLevel -eq 'TL1').Count }
    } | Sort-Object Identities -Descending)
    $idBody = '<h3>By account type</h3>' + (ConvertTo-P2HtmlTable -Rows $typeSummary -Columns @('AccountType', 'Identities', 'WithTL1', 'WithPermanent', 'WithIssues')) +
        '<h3>By organisation</h3>' + (ConvertTo-P2HtmlTable -Rows $orgSummary -Columns @('Organisation', 'Identities', 'WithTL1')) +
        '<h3>Identities with issues</h3>' + (ConvertTo-P2HtmlTable -Rows @($Data.Identities | Where-Object { $_.Issues -and $_.AccountType -ne 'WorkloadIdentity' }) -Columns @('HighestTrustLevel', 'Identity', 'AccountType', 'PersonOrganisation', 'LinkedEveryday', 'TL1Paths', 'StandingPaths', 'Issues') -MaxRows 100 -CsvName 'P2_PrivilegedIdentities.csv')
    $null = $html.Append((& $det "Admin identities: $(@($Data.Identities).Count)" $idBody $false))

    $gapSummary = @($Data.PolicyGaps | Group-Object TrustLevel, Setting | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{ TrustLevel = $g[0].TrustLevel; Setting = $g[0].Setting; Roles = $g.Count; Target = $g[0].Target; Examples = (@($g | Select-Object -ExpandProperty Subject -First 6) -join '; ') }
    } | Sort-Object TrustLevel, Setting)
    $policyNote = if (-not $Data.Collected.GroupPolicies) { '<p class="note">PIM for Groups activation settings were not in this export. Where a role is reached by activating a group, the group''s own settings control the activation.</p>' } else { '' }
    $null = $html.Append((& $det "PIM settings against the trust-level baseline: $(@($Data.PolicyGaps).Count) gaps" ((ConvertTo-P2HtmlTable -Rows $gapSummary -Columns @('TrustLevel', 'Setting', 'Roles', 'Target', 'Examples')) + $policyNote) $false))
    $null = $html.Append((& $det 'Role catalogue extract (every role in use, with trust level)' (ConvertTo-P2HtmlTable -Rows @($Data.Catalogue | Where-Object { $_.TrustLevel -ne 'TL4' }) -Columns @('TrustLevel', 'Plane', 'Role', 'ScopeLevel', 'Classification', 'People', 'DirectPaths', 'GroupPaths', 'EligiblePaths', 'StandingPaths', 'PolicyGaps') -MaxRows 150 -CsvName 'P2_RoleCatalogue.csv') $false))
    $null = $html.Append((& $det "Exception candidates: $(@($Data.Exceptions).Count)" (ConvertTo-P2HtmlTable -Rows $Data.Exceptions -Columns @('Category', 'Subject', 'Detail', 'HldReference', 'RequiredEvidence') -MaxRows 80 -CsvName 'P2_ExceptionCandidates.csv') $false))
    $null = $html.Append((& $det 'PIM Phase 2 HLD findings (F01-F15) and maturity indicators' ((ConvertTo-P2HtmlTable -Rows $Data.Hld -Columns @('Finding', 'Title', 'Status', 'Measure')) + '<h3>Maturity baseline</h3>' + (ConvertTo-P2HtmlTable -Rows $Data.Maturity -Columns @('Capability', 'HldBaseline', 'Phase2Target', 'Indicator'))) $false))
    $actionSummary = @($Data.Migration | ForEach-Object { foreach ($a in ([string]$_.ProposedActions).Split('|')) { $a.Trim() } } | Group-Object | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ ProposedAction = $_.Name; Routes = $_.Count } })
    $null = $html.Append((& $det "Migration worksheet summary ($(@($Data.Migration).Count) routes in P2_MigrationWorksheet.csv)" (ConvertTo-P2HtmlTable -Rows $actionSummary -Columns @('ProposedAction', 'Routes')) $false))

    # ---- 9. Method ----------------------------------------------------------------------------
    $null = $html.Append('<h2 id="method">How to read this report</h2>')
    $null = $html.Append('<h3>Trust levels</h3><div class="tw"><table><thead><tr><th>Level</th><th>Meaning</th><th>Examples</th><th>Expected controls</th></tr></thead><tbody>')
    $null = $html.Append('<tr><td><span class="b tl1">TL1</span></td><td>Tier 0: can take over the tenant or grant itself any access</td><td>Global Administrator, Privileged Role Administrator, Azure Owner at subscription or above</td><td>Eligible only, approval by independent approvers, 2 hours, phishing-resistant MFA, quarterly review</td></tr>')
    $null = $html.Append('<tr><td><span class="b tl2">TL2</span></td><td>High impact on a service or large amounts of data</td><td>Exchange, SharePoint, Intune Administrator, Azure Contributor at subscription</td><td>Eligible, MFA, 4 hours, approval by impact, six-monthly review</td></tr>')
    $null = $html.Append('<tr><td><span class="b tl3">TL3</span></td><td>Limited operational administration</td><td>Helpdesk, reports, resource-level contributor</td><td>Eligible, MFA, 8 hours, annual review</td></tr>')
    $null = $html.Append('<tr><td><span class="b tl4">TL4</span></td><td>Read only</td><td>Global Reader, Azure Reader</td><td>May be permanent</td></tr>')
    $null = $html.Append('</tbody></table></div>')
    $null = $html.Append('<h3>Terms</h3><ul>')
    $null = $html.Append('<li><strong>Route</strong>: one way a person reaches a role, for example directly, or by being a member (or eligible member) of a group that holds the role.</li>')
    $null = $html.Append('<li><strong>Just-in-time</strong>: the person is eligible and must activate in PIM (with MFA, justification and any approval) before the role works.</li>')
    $null = $html.Append('<li><strong>Permanent</strong>: the role is always active, with no end date and no activation step.</li>')
    $null = $html.Append('<li><strong>Admin account (CLAD)</strong>: a separate cloud-only account used only for administration.</li>')
    $null = $html.Append('</ul><h3>Limits</h3><ul>')
    $null = $html.Append('<li>The report uses configuration exported from Entra and Azure. It cannot see monitoring, review sign-offs or how processes work in practice; those CAF indicators are marked Not assessed.</li>')
    $null = $html.Append('<li>People are matched across accounts by name and naming patterns. Supply an identity map for exact matching.</li>')
    $null = $html.Append('<li>Trust levels come from the role catalogue. Entries marked Proposed or Open are drafts until agreed.</li>')
    if (-not $Data.HasAzure) { $null = $html.Append('<li><strong>No Azure evidence was supplied</strong>, so Azure is not included.</li>') }
    $null = $html.Append('</ul><h3>Sources</h3><ul>')
    $null = $html.Append('<li><a href="https://www.ncsc.gov.uk/collection/cyber-assessment-framework/caf-objective-b/principle-b2-identity-and-access-control">NCSC CAF 4.0, Principle B2: Identity and access control</a></li>')
    $null = $html.Append('<li><a href="https://www.ncsc.gov.uk/collection/secure-system-administration">NCSC: Secure system administration</a></li>')
    $null = $html.Append('<li><a href="https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices">Microsoft: Best practices for Microsoft Entra roles</a></li>')
    $null = $html.Append('<li><a href="https://learn.microsoft.com/azure/role-based-access-control/best-practices">Microsoft: Best practices for Azure RBAC</a></li>')
    $null = $html.Append('</ul>')

    $null = $html.Append('</main></body></html>')

    $safe = ($Data.TenantShortName -replace '[^A-Za-z0-9_-]', '_')
    $path = Join-Path -Path $OutputFolder -ChildPath "Privileged_Access_Audit_$safe.html"
    [System.IO.File]::WriteAllText($path, $html.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    return $path
}
