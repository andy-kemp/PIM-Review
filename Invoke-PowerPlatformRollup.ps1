<#
.SYNOPSIS
Combines the latest Power Platform review of each tenant into one partnership view.

.DESCRIPTION
Finds the latest PowerPlatform-* run folder per tenant under -OutputRoot (or takes -RunFolders) and writes:
- PP_Partnership_Metrics.csv    headline numbers per tenant
- PP_Partnership_Findings.csv   PP-01..PP-14 status and count per tenant
- PP_Partnership_People.csv     every person across tenants, with a Tenant column
- PP_Partnership_FlowsAtRisk.csv
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
    foreach ($f in @(Get-ChildItem -Path $OutputRoot -Recurse -Filter 'pp-summary.json' -ErrorAction SilentlyContinue)) {
        $s = Get-Content $f.FullName -Raw | ConvertFrom-Json
        $t = [string]$s.TenantId
        if (-not $byTenant.ContainsKey($t) -or $f.LastWriteTime -gt $byTenant[$t].LastWriteTime) { $byTenant[$t] = $f }
    }
    $RunFolders = @($byTenant.Values | ForEach-Object { $_.DirectoryName })
}
if (@($RunFolders).Count -eq 0) { throw "No Power Platform reviews found under $OutputRoot." }

$outFolder = Ensure-Directory -Path (Join-Path $OutputRoot ('Partnership\PowerPlatform-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
$metricsRows = New-Object System.Collections.ArrayList
$findingRows = New-Object System.Collections.ArrayList
$peopleRows = New-Object System.Collections.ArrayList
$riskRows = New-Object System.Collections.ArrayList
$findingTitles = [ordered]@{}

foreach ($rf in $RunFolders) {
    $s = Get-Content (Join-Path $rf 'pp-summary.json') -Raw | ConvertFrom-Json
    $t = $s.TenantShortName
    $m = [ordered]@{ Tenant = $t; TenantName = $s.TenantName; Run = $s.Run }
    foreach ($p in $s.Metrics.PSObject.Properties) { $m[$p.Name] = $p.Value }
    $null = $metricsRows.Add([pscustomobject]$m)
    foreach ($f in $s.Findings) {
        $findingTitles[$f.Id] = $f.Finding
        $null = $findingRows.Add([pscustomobject]@{ Tenant = $t; Id = $f.Id; Finding = $f.Finding; Severity = $f.Severity; Status = $f.Status; Count = $f.Count })
    }
    $pp = Join-Path $rf 'pp-people-register.csv'
    if ((Test-Path $pp) -and (Get-Item $pp).Length -gt 2) { foreach ($r in Import-Csv $pp) { $r | Add-Member -NotePropertyName Tenant -NotePropertyValue $t -Force; $null = $peopleRows.Add($r) } }
    $fr = Join-Path $rf 'pp-flows-at-risk.csv'
    if ((Test-Path $fr) -and (Get-Item $fr).Length -gt 2) { foreach ($r in Import-Csv $fr) { $r | Add-Member -NotePropertyName Tenant -NotePropertyValue $t -Force; $null = $riskRows.Add($r) } }
}

$metricsRows | Export-Csv (Join-Path $outFolder 'PP_Partnership_Metrics.csv') -NoTypeInformation -Encoding UTF8
$findingRows | Export-Csv (Join-Path $outFolder 'PP_Partnership_Findings.csv') -NoTypeInformation -Encoding UTF8
if ($peopleRows.Count) { $peopleRows | Select-Object Tenant, * -ExcludeProperty Tenant | Export-Csv (Join-Path $outFolder 'PP_Partnership_People.csv') -NoTypeInformation -Encoding UTF8 }
if ($riskRows.Count) { $riskRows | Select-Object Tenant, * -ExcludeProperty Tenant | Export-Csv (Join-Path $outFolder 'PP_Partnership_FlowsAtRisk.csv') -NoTypeInformation -Encoding UTF8 }

# Findings matrix: one row per finding, one column per tenant
$tenants = @($metricsRows | ForEach-Object Tenant)
$matrix = foreach ($id in $findingTitles.Keys) {
    $row = [ordered]@{ Id = $id; Finding = $findingTitles[$id] }
    foreach ($t in $tenants) {
        $hit = @($findingRows | Where-Object { $_.Tenant -eq $t -and $_.Id -eq $id }) | Select-Object -First 1
        $row[$t] = if ($hit) { if ($hit.Status -eq 'Good') { 'Good' } else { "$($hit.Severity) ($($hit.Count))" } } else { 'n/a' }
    }
    [pscustomobject]$row
}
$metricView = foreach ($name in @('Environments', 'ProductionOrDefault', 'TenantAdminsEveryday', 'PermanentTenantAdmins', 'GlobalAdmins', 'ProdSysAdminsEveryday', 'PeopleNeedingClad', 'FlowsOn', 'FlowsAtRiskHigh', 'Makers', 'EnvironmentsNotRead')) {
    $row = [ordered]@{ Measure = (ConvertTo-P2Label -Name $name) }
    foreach ($r in $metricsRows) { $row[$r.Tenant] = $r.$name }
    [pscustomobject]$row
}

$enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
$css = 'body{font-family:"Segoe UI",system-ui,Arial,sans-serif;color:#1b2430;margin:0;line-height:1.5;font-size:15px}main{max-width:1180px;margin:0 auto;padding:28px 16px 60px}h1{font-size:28px;margin:0 0 6px}h2{color:#1f4e78;margin-top:36px}.meta{color:#5d6878;font-size:13px}.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #e1e6ec;padding:7px 8px;text-align:left;vertical-align:top}th{background:#f5f7fa}.b{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600}.b.high{background:#b42318;color:#fff}.b.med{background:#d27a00;color:#fff}.b.low{background:#55606e;color:#fff}.b.good{background:#e8f5ee;color:#1e7b45}.more{color:#5d6878;font-size:12px;font-style:italic}.none{font-style:italic}'
$h = New-Object System.Text.StringBuilder
$null = $h.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><title>Power Platform Admin Review - Partnership</title><style>$css</style></head><body><main>")
$null = $h.Append("<h1>Power Platform Admin Review: Partnership</h1><div class=""meta"">$($tenants.Count) tenants &middot; $(Get-Date -Format 'd MMMM yyyy')</div>")
$null = $h.Append('<h2>Headline numbers</h2>'); $null = $h.Append((ConvertTo-P2HtmlTable -Rows @($metricView) -Columns (@('Measure') + $tenants)))
$null = $h.Append('<h2>Findings by tenant</h2>'); $null = $h.Append((ConvertTo-P2HtmlTable -Rows @($matrix) -Columns (@('Id', 'Finding') + $tenants)))
$null = $h.Append('<h2>People who need a CLAD</h2>')
$need = @($peopleRows | Where-Object { $_.Persona -like 'Tenant admin*' -or $_.Persona -like 'Production environment admin*' })
$null = $h.Append((ConvertTo-P2HtmlTable -Rows $need -Columns @('Tenant', 'DisplayName', 'UserPrincipalName', 'Persona', 'TenantRoles', 'FlowsOn', 'RecommendedAction') -MaxRows 300 -CsvName 'PP_Partnership_People.csv'))
$null = $h.Append('<h2>Flows likely to break</h2>')
$null = $h.Append((ConvertTo-P2HtmlTable -Rows @($riskRows | Where-Object Severity -eq 'High') -Columns @('Tenant', 'Environment', 'FlowName', 'Owner', 'Connectors', 'Reason') -MaxRows 300 -CsvName 'PP_Partnership_FlowsAtRisk.csv'))
$null = $h.Append('</main></body></html>')
$report = Join-Path $outFolder 'PowerPlatform_Partnership.html'
$h.ToString() | Out-File $report -Encoding UTF8
Write-Host "Partnership roll-up: $report" -ForegroundColor Green
[pscustomobject]@{ ReportPath = $report; OutputFolder = $outFolder }
