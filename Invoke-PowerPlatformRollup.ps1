<#
.SYNOPSIS
Combines the latest Power Platform audit of each tenant into one partnership view.

.DESCRIPTION
Finds the latest PowerPlatform-* run per tenant under -OutputRoot (or takes -RunFolders) and writes to
<OutputRoot>\Partnership\PowerPlatform-<timestamp>:
- PP_Partnership_Metrics.csv     headline numbers per tenant
- PP_Partnership_Controls.csv    every control's result per tenant
- PP_Partnership_People.csv      every person across tenants, with a Tenant column
- PP_Partnership_CrossTenant.csv people with Power Platform admin rights in more than one tenant
- PP_Partnership_CladProvisioning.csv, PP_Partnership_PimImpact.csv, PP_Partnership_FlowsAtRisk.csv
- PowerPlatform_Partnership.html

.EXAMPLE
.\Invoke-PowerPlatformRollup.ps1 -OutputRoot .\Output
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [string[]]$RunFolders
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules\PimReview.Common.psm1') -Force -DisableNameChecking
. (Join-Path $PSScriptRoot 'New-PimPhase2Report.ps1')

if (-not $OutputRoot) { $OutputRoot = Join-Path $PSScriptRoot 'Output' }
if (-not $RunFolders) {
    $byTenant = @{}
    foreach ($f in @(Get-ChildItem -Path $OutputRoot -Recurse -Filter 'PP_Summary.json' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '[\\/]Partnership[\\/]' })) {
        $s = Get-Content $f.FullName -Raw | ConvertFrom-Json
        $t = [string]$s.TenantId
        if (-not $byTenant.ContainsKey($t) -or $f.LastWriteTime -gt $byTenant[$t].LastWriteTime) { $byTenant[$t] = $f }
    }
    $RunFolders = @($byTenant.Values | ForEach-Object { $_.DirectoryName })
}
if (@($RunFolders).Count -eq 0) { throw "No Power Platform audits found under $OutputRoot." }

$outFolder = Ensure-Directory -Path (Join-Path $OutputRoot ('Partnership\PowerPlatform-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
$metricsRows = New-Object System.Collections.ArrayList
$controlRows = New-Object System.Collections.ArrayList
$cafRows = New-Object System.Collections.ArrayList
$tables = @{ People = (New-Object System.Collections.ArrayList); CladProvisioning = (New-Object System.Collections.ArrayList); PimImpact = (New-Object System.Collections.ArrayList); FlowsAtRisk = (New-Object System.Collections.ArrayList) }
$titles = [ordered]@{}

foreach ($rf in $RunFolders) {
    $s = Get-Content (Join-Path $rf 'PP_Summary.json') -Raw | ConvertFrom-Json
    $t = [string]$s.TenantShortName
    $m = [ordered]@{ Tenant = $t }
    foreach ($p in $s.Metrics.PSObject.Properties) { if ($p.Name -ne 'TenantShortName') { $m[$p.Name] = $p.Value } }
    $null = $metricsRows.Add([pscustomobject]$m)
    foreach ($c in $s.Controls) { $titles[$c.Id] = $c.Control; $null = $controlRows.Add([pscustomobject]@{ Tenant = $t; Id = $c.Id; Area = $c.Area; Control = $c.Control; Result = $c.Result; Severity = $c.Severity }) }
    foreach ($c in $s.Caf) { $null = $cafRows.Add([pscustomobject]@{ Tenant = $t; Outcome = $c.Outcome; Title = $c.Title; Rating = $c.Rating }) }
    foreach ($k in @($tables.Keys)) {
        $p = Join-Path $rf "PP_$k.csv"
        if ((Test-Path $p) -and (Get-Item $p).Length -gt 2) { foreach ($r in Import-Csv $p) { $r | Add-Member -NotePropertyName Tenant -NotePropertyValue $t -Force; $null = $tables[$k].Add($r) } }
    }
}
$tenants = @($metricsRows | ForEach-Object Tenant)

$metricsRows | Export-Csv (Join-Path $outFolder 'PP_Partnership_Metrics.csv') -NoTypeInformation -Encoding UTF8
$controlRows | Export-Csv (Join-Path $outFolder 'PP_Partnership_Controls.csv') -NoTypeInformation -Encoding UTF8
foreach ($k in $tables.Keys) { if ($tables[$k].Count) { $tables[$k] | Select-Object Tenant, * -ExcludeProperty Tenant | Export-Csv (Join-Path $outFolder "PP_Partnership_$k.csv") -NoTypeInformation -Encoding UTF8 } }

# People with Power Platform admin rights in more than one tenant (matched by display name).
$cross = @($tables.People | Where-Object { $_.TenantAdminRoles -or $_.ProdSysAdminEnvironments } | Group-Object { ([string]$_.DisplayName -replace '^\(Cloud Admin\)\s*', '').ToLowerInvariant().Trim() } | Where-Object { @($_.Group | Select-Object -ExpandProperty Tenant -Unique).Count -gt 1 } | ForEach-Object {
        [pscustomobject]@{ Person = $_.Group[0].DisplayName; Tenants = (@($_.Group | Select-Object -ExpandProperty Tenant -Unique) -join ', '); Accounts = (@($_.Group | ForEach-Object { "$($_.Tenant): $($_.UserPrincipalName) ($($_.AccountType))" }) -join '; '); Roles = (@($_.Group | ForEach-Object { "$($_.Tenant): $($_.TenantAdminRoles)" } | Where-Object { $_ -notmatch ': $' }) -join '; ') }
    })
if ($cross.Count) { $cross | Export-Csv (Join-Path $outFolder 'PP_Partnership_CrossTenant.csv') -NoTypeInformation -Encoding UTF8 }

$matrix = foreach ($id in $titles.Keys) {
    $row = [ordered]@{ Id = $id; Control = $titles[$id] }
    foreach ($t in $tenants) { $hit = @($controlRows | Where-Object { $_.Tenant -eq $t -and $_.Id -eq $id }) | Select-Object -First 1; $row[$t] = if ($hit) { $hit.Result } else { 'n/a' } }
    [pscustomobject]$row
}
$cafMatrix = foreach ($o in @($cafRows | Select-Object -ExpandProperty Outcome -Unique)) {
    $row = [ordered]@{ Outcome = $o; Title = (@($cafRows | Where-Object Outcome -eq $o)[0].Title) }
    foreach ($t in $tenants) { $hit = @($cafRows | Where-Object { $_.Tenant -eq $t -and $_.Outcome -eq $o }) | Select-Object -First 1; $row[$t] = if ($hit) { $hit.Rating } else { 'n/a' } }
    [pscustomobject]$row
}
$metricView = foreach ($name in @('Environments', 'ProductionOrDefault', 'TenantAdmins', 'TenantAdminsEveryday', 'TenantAdminsPermanent', 'TenantAdminsViaGroups', 'GlobalAdmins', 'ProdSysAdminsEveryday', 'PeopleNeedingClad', 'CladsOwningResources', 'FlowsOn', 'FlowsAtRiskHigh', 'PimImpactHigh', 'AdminsPhishingResistantPct', 'Makers', 'EnvironmentsNotRead')) {
    $row = [ordered]@{ Measure = (ConvertTo-P2Label -Name $name) }
    foreach ($r in $metricsRows) { $row[$r.Tenant] = $r.$name }
    [pscustomobject]$row
}

# Same look as the tenant reports and the PIM partnership roll-up.
$css = ''
$src = Get-Content (Join-Path $PSScriptRoot 'New-PimPhase2Report.ps1') -Raw
if ($src -match "(?s)\`$css = @'\r?\n(.*?)\r?\n'@") { $css = $Matches[1] }
$brand = $null
foreach ($c in @('Config\pim-phase2.catalogue.local.json', 'Config\pim-phase2.catalogue.json')) { $p = Join-Path $PSScriptRoot $c; if (-not $brand -and (Test-Path $p)) { try { $brand = (Get-Content $p -Raw | ConvertFrom-Json).Branding } catch { } } }
$enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
$h = New-Object System.Text.StringBuilder
$null = $h.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>Power Platform Privileged Access Audit - Partnership</title><style>$css</style></head><body><main>")
$null = $h.Append("<div class=""cover""><div class=""kicker"">$(& $enc $(if ($brand -and $brand.Programme) { $brand.Programme } else { 'PIM review' }))</div><h1>Power Platform Privileged Access Audit: Partnership</h1><div class=""meta"">$($tenants.Count) tenants ($(& $enc ($tenants -join ', '))) &middot; $(Get-Date -Format 'd MMMM yyyy') &middot; $(& $enc $(if ($brand -and $brand.Classification) { $brand.Classification } else { 'Confidential' }))</div></div>")
$null = $h.Append('<h2>Headline numbers</h2>'); $null = $h.Append((ConvertTo-P2HtmlTable -Rows @($metricView) -Columns (@('Measure') + $tenants)))
$null = $h.Append('<h2>NCSC CAF Principle B2 (indicative)</h2>'); $null = $h.Append((ConvertTo-P2HtmlTable -Rows @($cafMatrix) -Columns (@('Outcome', 'Title') + $tenants)))
$null = $h.Append('<h2>Controls by tenant</h2>'); $null = $h.Append((ConvertTo-P2HtmlTable -Rows @($matrix) -Columns (@('Id', 'Control') + $tenants)))
$null = $h.Append('<h2>People who need a CLAD for Power Platform</h2>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($tables.CladProvisioning) -Columns @('Tenant', 'Person', 'EverydayUpn', 'ExistingClad', 'ProposedCladUpn', 'RightsToMove', 'FlowsToCheckFirst') -MaxRows 300 -CsvName 'PP_Partnership_CladProvisioning.csv'))
$null = $h.Append('<h2>What changes, and what breaks, with Power Platform admin in PIM</h2>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($tables.PimImpact | Where-Object { $_.Impact -ne 'Low' }) -Columns @('Tenant', 'Impact', 'DisplayName', 'Roles', 'HeldAs', 'WhatBreaks', 'BeforeTheChange') -MaxRows 300 -CsvName 'PP_Partnership_PimImpact.csv'))
$null = $h.Append('<h2>Flows likely to break</h2>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($tables.FlowsAtRisk | Where-Object Severity -eq 'High') -Columns @('Tenant', 'Environment', 'FlowName', 'Owner', 'OwnerAccountType', 'Reason') -MaxRows 300 -CsvName 'PP_Partnership_FlowsAtRisk.csv'))
$null = $h.Append('<h2>People with Power Platform admin rights in more than one tenant</h2>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $cross -Columns @('Person', 'Tenants', 'Accounts', 'Roles') -MaxRows 200 -CsvName 'PP_Partnership_CrossTenant.csv'))
$null = $h.Append('</main></body></html>')
$report = Join-Path $outFolder 'PowerPlatform_Partnership.html'
$h.ToString() | Out-File $report -Encoding UTF8
Write-Host "Partnership roll-up: $report" -ForegroundColor Green
[pscustomobject]@{ ReportPath = $report; OutputFolder = $outFolder }
