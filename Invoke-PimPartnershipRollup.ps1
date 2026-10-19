<#
.SYNOPSIS
Combines the PIM Phase 2 assessments of every partner tenant into one partnership view.

.DESCRIPTION
Finds the latest Phase2 folder for each tenant under -OutputRoot (or takes -Phase2Folders), then writes:
- PartnershipMetrics.csv        one row per tenant, headline numbers side by side
- PartnershipHldFindings.csv    F01-F15 status per tenant
- PartnershipPeople.csv         each person and the tenants where they hold privilege (shared operators)
- PartnershipSelfApproval.csv   self-approval routes across all tenants
- PartnershipApproverGroups.csv approver groups across all tenants
- PartnershipRoleCatalogue.csv  every role with its trust level and holders per tenant (for OD-02)
- PIM_Phase2_Partnership.html

.EXAMPLE
./Invoke-PimPartnershipRollup.ps1 -OutputRoot .\Output
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [string[]]$Phase2Folders,
    [string]$OutputFolder,
    [string]$CataloguePath
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) { Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false }
. (Join-Path -Path $PSScriptRoot -ChildPath 'New-PimPhase2Report.ps1')

function Invoke-PimPartnershipRollup {
    [CmdletBinding()]
    param([string]$OutputRoot, [string[]]$Phase2Folders, [string]$OutputFolder, [string]$CataloguePath)

    if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Output' }
    $folders = @()
    if ($Phase2Folders) { $folders = @($Phase2Folders) }
    else {
        # Latest Phase2 folder per tenant (tenant = first folder under the output root).
        $all = @(Get-ChildItem -Path $OutputRoot -Recurse -Filter 'P2_Metrics.csv' -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -notmatch '[\\/]Partnership' })
        $byTenant = @{}
        foreach ($f in $all) {
            $m = @(Import-Csv -Path $f.FullName) | Select-Object -First 1
            $t = [string]$m.Tenant
            if (-not $byTenant.ContainsKey($t) -or $f.LastWriteTime -gt $byTenant[$t].LastWriteTime) { $byTenant[$t] = $f }
        }
        $folders = @($byTenant.Values | ForEach-Object { $_.DirectoryName })
    }
    if ($folders.Count -eq 0) { throw "No Phase 2 assessments found under $OutputRoot. Run Invoke-PimPhase2Assessment.ps1 for each tenant first." }
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = Join-Path -Path $OutputRoot -ChildPath ("Partnership\Rollup-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    $OutputFolder = Ensure-Directory -Path $OutputFolder
    if ([string]::IsNullOrWhiteSpace($CataloguePath)) {
        # A local (git-ignored) catalogue holds programme-specific roles, domains and branding.
        $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'Config\pim-phase2.catalogue.local.json'
        if (-not (Test-Path -Path $CataloguePath)) { $CataloguePath = Join-Path -Path $PSScriptRoot -ChildPath 'Config\pim-phase2.catalogue.json' }
    }
    $cat = if (Test-Path $CataloguePath) { Get-Content -Path $CataloguePath -Raw | ConvertFrom-Json } else { $null }

    $load = { param($Name) $rows = New-Object System.Collections.ArrayList; foreach ($f in $folders) { $p = Join-Path $f $Name; if (Test-Path $p) { foreach ($r in @(Import-Csv -Path $p -Encoding UTF8)) { $null = $rows.Add($r) } } }; return @($rows) }
    $metrics = & $load 'P2_Metrics.csv'
    $hld = & $load 'P2_HldFindings.csv'
    $ctrl = & $load 'P2_Controls.csv'
    $cafRows = & $load 'P2_NcscCafBenchmark.csv'
    $paths = & $load 'P2_AccessPaths.csv'
    $selfApproval = & $load 'P2_SelfApproval.csv'
    $approvers = & $load 'P2_ApproverGroups.csv'
    $catalogue = & $load 'P2_RoleCatalogue.csv'
    $tenants = @($metrics | Select-Object -ExpandProperty Tenant -Unique | Sort-Object)
    Write-PimLog -Message "Partnership roll-up across $($tenants.Count) tenant(s): $($tenants -join ', ')"

    # HLD findings matrix.
    $hldMatrix = New-Object System.Collections.ArrayList
    foreach ($g in @($hld | Group-Object Finding | Sort-Object Name)) {
        $row = [ordered]@{ Finding = $g.Name; Title = $g.Group[0].Title }
        foreach ($t in $tenants) { $x = @($g.Group | Where-Object Tenant -eq $t) | Select-Object -First 1; $row[$t] = if ($x) { $x.Status } else { '' } }
        $null = $hldMatrix.Add([pscustomobject]$row)
    }

    # People across tenants.
    $humanTypes = @('CLAD', 'Other admin account', 'Everyday', 'Guest', 'Generic/Service')
    $people = New-Object System.Collections.ArrayList
    $rank = { param($l) switch ($l) { 'TL1' { 4 } 'TL2' { 3 } 'TL3' { 2 } 'TL4' { 1 } default { 0 } } }
    foreach ($g in @($paths | Where-Object { $_.AccountType -in $humanTypes -and $_.Person -and $_.Person -notlike 'id:*' } | Group-Object Person)) {
        $rows = @($g.Group)
        # A shared operator's CLAD sits in the partner's domain, so prefer the organisation of their home identity.
        $orgPick = $null
        foreach ($ot in @('Supplier', 'Operator', 'Partner', 'Tenant')) {
            $hit = @($rows | Where-Object { $_.PersonOrganisationType -eq $ot -and $_.PersonOrganisation } | Select-Object -ExpandProperty PersonOrganisation -Unique)
            if ($hit.Count -eq 0) { $hit = @($rows | Where-Object { $_.OrganisationType -eq $ot -and $_.Organisation } | Select-Object -ExpandProperty Organisation -Unique) }
            if ($hit.Count -gt 0) { $orgPick = $hit -join '; '; break }
        }
        $row = [ordered]@{ Person = $g.Name; Organisation = $orgPick }
        $tenantCount = 0; $best = 0
        foreach ($t in $tenants) {
            $tr = @($rows | Where-Object Tenant -eq $t)
            $hi = 0
            foreach ($r in $tr) { $v = & $rank $r.TrustLevel; if ($v -gt $hi) { $hi = $v } }
            if ($hi -gt $best) { $best = $hi }
            $row[$t] = switch ($hi) { 4 { 'TL1' } 3 { 'TL2' } 2 { 'TL3' } 1 { 'TL4' } default { '' } }
            if ($tr.Count -gt 0) { $tenantCount++ }
        }
        $row['Tenants'] = $tenantCount
        $row['HighestTrustLevel'] = switch ($best) { 4 { 'TL1' } 3 { 'TL2' } 2 { 'TL3' } 1 { 'TL4' } default { '' } }
        $row['SelfApprovalTenants'] = @($selfApproval | Where-Object { $_.Person -eq $g.Name -and $_.Route -like 'Linked*' } | Select-Object -ExpandProperty Tenant -Unique).Count
        $row['Accounts'] = (@($rows | ForEach-Object { if ($_.Upn) { $_.Upn } else { $_.Identity } } | Select-Object -Unique | Select-Object -First 8) -join '; ')
        $null = $people.Add([pscustomobject]$row)
    }
    $people = @($people | Sort-Object @{ Expression = 'Tenants'; Descending = $true }, @{ Expression = { & $rank $_.HighestTrustLevel }; Descending = $true }, Person)

    # Role catalogue across tenants.
    $roleRows = New-Object System.Collections.ArrayList
    foreach ($g in @($catalogue | Group-Object Plane, Role, ScopeLevel)) {
        $rows = @($g.Group)
        $row = [ordered]@{ Plane = $rows[0].Plane; Role = $rows[0].Role; ScopeLevel = $rows[0].ScopeLevel; TrustLevel = $rows[0].TrustLevel; Classification = $rows[0].Classification }
        foreach ($t in $tenants) { $x = @($rows | Where-Object Tenant -eq $t) | Select-Object -First 1; $row[$t] = if ($x) { [int]$x.People } else { $null } }
        $row['TotalPeople'] = (@($rows | ForEach-Object { [int]$_.People }) | Measure-Object -Sum).Sum
        $null = $roleRows.Add([pscustomobject]$row)
    }
    $roleRows = @($roleRows | Sort-Object @{ Expression = { & $rank $_.TrustLevel }; Descending = $true }, Plane, @{ Expression = 'TotalPeople'; Descending = $true })

    Export-PimData -Data $metrics -CsvPath (Join-Path $OutputFolder 'PartnershipMetrics.csv')
    # Control results and NCSC CAF ratings side by side.
    $ctrlMatrix = New-Object System.Collections.ArrayList
    foreach ($g in @($ctrl | Group-Object Id | Sort-Object Name)) {
        $row = [ordered]@{ Id = $g.Name; Control = $g.Group[0].Control }
        foreach ($t in $tenants) { $x = @($g.Group | Where-Object Tenant -eq $t) | Select-Object -First 1; $row[$t] = if ($x) { $x.Result } else { '' } }
        $null = $ctrlMatrix.Add([pscustomobject]$row)
    }
    $cafMatrix = New-Object System.Collections.ArrayList
    foreach ($g in @($cafRows | Group-Object Outcome | Sort-Object Name)) {
        $row = [ordered]@{ Outcome = $g.Name; Title = $g.Group[0].Title }
        foreach ($t in $tenants) { $x = @($g.Group | Where-Object Tenant -eq $t) | Select-Object -First 1; $row[$t] = if ($x) { $x.Rating } else { '' } }
        $null = $cafMatrix.Add([pscustomobject]$row)
    }
    Export-PimData -Data @($ctrlMatrix) -CsvPath (Join-Path $OutputFolder 'PartnershipControls.csv')
    Export-PimData -Data @($cafMatrix) -CsvPath (Join-Path $OutputFolder 'PartnershipNcscCaf.csv')
    Export-PimData -Data @($hldMatrix) -CsvPath (Join-Path $OutputFolder 'PartnershipHldFindings.csv')
    Export-PimData -Data $people -CsvPath (Join-Path $OutputFolder 'PartnershipPeople.csv')
    Export-PimData -Data $selfApproval -CsvPath (Join-Path $OutputFolder 'PartnershipSelfApproval.csv')
    Export-PimData -Data $approvers -CsvPath (Join-Path $OutputFolder 'PartnershipApproverGroups.csv')
    Export-PimData -Data $roleRows -CsvPath (Join-Path $OutputFolder 'PartnershipRoleCatalogue.csv')

    # Metrics transposed: one row per metric, one column per tenant.
    $metricNames = @('PeopleWithPrivilege', 'PeopleWithTL1', 'PeopleReachingGlobalAdmin', 'SelfApprovalPeople', 'SelfApprovalTL1People', 'ApproverGroupsWithEveryday', 'TL1InBundles', 'StandingPrivilegedPaths', 'StandingTL1Paths', 'AzureStandingTL1AtSubOrAbove', 'TL1WithoutPhishingResistant', 'CladAccounts', 'EverydayIdentitiesWithPrivilege', 'GuestIdentitiesWithPrivilege', 'SupplierIdentities', 'GenericAccounts', 'BreakGlassAccounts', 'WithoutP2', 'TL1PolicyGaps', 'EligibleSharePercent', 'ControlsGood', 'ControlsPartial', 'ControlsWeak')
    $metricRows = New-Object System.Collections.ArrayList
    foreach ($n in $metricNames) {
        $row = [ordered]@{ Metric = (ConvertTo-P2Label -Name $n) }
        foreach ($t in $tenants) { $x = @($metrics | Where-Object Tenant -eq $t) | Select-Object -First 1; $row[$t] = if ($x -and $x.PSObject.Properties[$n]) { $x.$n } else { '' } }
        $null = $metricRows.Add([pscustomobject]$row)
    }

    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $programme = if ($cat -and $cat.Branding.Programme) { $cat.Branding.Programme } else { 'PIM Phase 2' }
    $preparedBy = if ($cat -and $cat.Branding.PreparedBy) { $cat.Branding.PreparedBy } else { 'PIM review' }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>PIM Phase 2 Partnership</title>')
    $null = $sb.Append('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;color:#1d2733}main{max-width:1400px;margin:0 auto;padding:24px 16px 60px}h1{font-size:28px;margin:0 0 6px}h2{font-size:19px;color:#1f4e78;border-bottom:2px solid #1f4e78;padding-bottom:4px;margin-top:32px}.cover{border:1px solid #dde3ea;border-left:6px solid #1f4e78;padding:16px 20px;background:#f5f8fb;border-radius:6px}.meta{color:#5b6673;font-size:13px}.intro{font-size:14px;max-width:1050px}.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #dde3ea;padding:5px 7px;text-align:left;vertical-align:top}th{background:#f5f8fb}.none{color:#2e7d32;font-style:italic}.more{color:#5b6673;font-size:12px;font-style:italic}.b{color:#fff;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}.tl1,.crit{background:#7f0000}.tl2,.high{background:#c62828}.tl3,.med{background:#e65100}.tl4,.low{background:#2e7d32}.na{background:#78909c}</style></head><body><main>')
    $null = $sb.Append("<div class=""cover""><h1>PIM Phase 2 Partnership Assessment</h1><div class=""meta"">$(& $enc $programme) &middot; $($tenants.Count) tenant(s): $(& $enc ($tenants -join ', ')) &middot; Prepared by $(& $enc $preparedBy) &middot; $(Get-Date -Format 'yyyy-MM-dd')</div></div>")
    $null = $sb.Append('<h2>Headline numbers by tenant</h2>')
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows @($metricRows) -Columns (@('Metric') + $tenants)))
    $badgeIt = {
        param($Html)
        foreach ($s in @(@('Good', 'low'), @('Achieved', 'low'), @('Partial', 'med'), @('Partially achieved', 'med'), @('Weak', 'high'), @('Not achieved', 'high'), @('Not assessed', 'na'))) { $Html = $Html -replace ("<td>" + [regex]::Escape($s[0]) + "</td>"), "<td><span class=""b $($s[1])"">$($s[0])</span></td>" }
        return $Html
    }
    $null = $sb.Append('<h2>NCSC CAF Principle B2 by tenant (indicative)</h2>')
    $null = $sb.Append((& $badgeIt (ConvertTo-P2HtmlTable -Rows @($cafMatrix) -Columns (@('Outcome', 'Title') + $tenants))))
    $null = $sb.Append('<h2>Control results by tenant</h2>')
    $null = $sb.Append((& $badgeIt (ConvertTo-P2HtmlTable -Rows @($ctrlMatrix) -Columns (@('Id', 'Control') + $tenants))))
    $null = $sb.Append('<h2>HLD findings by tenant</h2>')
    $hldHtml = ConvertTo-P2HtmlTable -Rows @($hldMatrix) -Columns (@('Finding', 'Title') + $tenants)
    foreach ($s in @(@('Confirmed', 'high'), @('Partially', 'med'), @('Indicated', 'med'), @('Test required', 'med'), @('Not observed', 'low'), @('Addressed', 'low'), @('Not assessed', 'na'), @('Open', 'na'))) { $hldHtml = $hldHtml -replace ("<td>" + [regex]::Escape($s[0]) + "</td>"), "<td><span class=""b $($s[1])"">$($s[0])</span></td>" }
    $null = $sb.Append($hldHtml)
    $null = $sb.Append('<h2>People with privilege in more than one tenant</h2><p class="intro">Shared operators hold accounts in several partner tenants. Their highest trust level per tenant is shown; the shared approver model (F01) and the CLAD-per-tenant pattern apply to each of them.</p>')
    $multi = @($people | Where-Object { [int]$_.Tenants -gt 1 })
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows $multi -Columns (@('Person', 'Organisation') + $tenants + @('SelfApprovalTenants')) -MaxRows 150 -CsvName 'PartnershipPeople.csv'))
    $null = $sb.Append('<h2>Approver groups</h2>')
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows $approvers -Columns @('Tenant', 'ApproverGroup', 'HighestTrustLevel', 'RolesApproved', 'Members', 'CladMembers', 'EverydayOrGuestMembers', 'ApproversAlsoEligible', 'SelfApprovalPeople', 'MeetsHld763')))
    $null = $sb.Append('<h2>Role catalogue across tenants (OD-02)</h2><p class="intro">People holding each TL1 and TL2 role in each tenant. Use this to agree one catalogue for the partnership.</p>')
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows @($roleRows | Where-Object { $_.TrustLevel -in @('TL1', 'TL2') }) -Columns (@('TrustLevel', 'Plane', 'Role', 'ScopeLevel', 'Classification') + $tenants + @('TotalPeople')) -MaxRows 150 -CsvName 'PartnershipRoleCatalogue.csv'))
    $null = $sb.Append('</main></body></html>')
    $html = Join-Path $OutputFolder 'PIM_Phase2_Partnership.html'
    [System.IO.File]::WriteAllText($html, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    Write-PimLog -Message "Partnership roll-up written to $OutputFolder"
    return [pscustomobject]@{ OutputFolder = $OutputFolder; ReportPath = $html; Tenants = $tenants }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-PimPartnershipRollup @PSBoundParameters }
