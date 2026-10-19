<#
.SYNOPSIS
Compares two PIM Phase 2 assessments of the same tenant (runbook 5.5 baseline diff, HLD F11 drift).

.DESCRIPTION
Reads the Phase2 folders written by Invoke-PimPhase2Assessment.ps1 and reports:
- access paths added, removed, or changed state (eligible / active / standing, trust level)
- PIM setting gaps opened or closed
- self-approval routes added or removed
- change in each headline metric
Writes P2Diff_*.csv files and PIM_Phase2_Diff_<tenant>.html to -OutputFolder (default: <Current>\Diff).

.EXAMPLE
./Compare-PimPhase2Assessment.ps1 -Baseline .\Output\Contoso\Run-20261020-090000\Phase2 -Current .\Output\Contoso\Run-20261201-090000\Phase2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Baseline,
    [Parameter(Mandatory = $true)][string]$Current,
    [string]$OutputFolder
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) { Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false }
. (Join-Path -Path $PSScriptRoot -ChildPath 'New-PimPhase2Report.ps1')

function Import-P2DiffCsv {
    param([string]$Folder, [string]$Name)
    $path = Join-Path -Path $Folder -ChildPath $Name
    if (-not (Test-Path -Path $path)) { return @() }
    return @(Import-Csv -Path $path -Encoding UTF8)
}

function Compare-PimPhase2Assessment {
    [CmdletBinding()]
    param([string]$Baseline, [string]$Current, [string]$OutputFolder)

    foreach ($f in @($Baseline, $Current)) {
        if (-not (Test-Path (Join-Path $f 'P2_AccessPaths.csv'))) { throw "Not a Phase 2 assessment folder (no P2_AccessPaths.csv): $f" }
    }
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = Join-Path -Path $Current -ChildPath 'Diff' }
    $OutputFolder = Ensure-Directory -Path $OutputFolder

    $pathKey = { param($r) ("$($r.Plane)|$($r.IdentityId)|$($r.Role)|$($r.Scope)|$($r.PathType)|$($r.ViaGroup)").ToLowerInvariant() }
    $index = {
        param($Rows, $KeyBlock)
        $h = @{}
        foreach ($r in $Rows) { $k = & $KeyBlock $r; if (-not $h.ContainsKey($k)) { $h[$k] = $r } }
        return $h
    }

    $bPaths = & $index (Import-P2DiffCsv $Baseline 'P2_AccessPaths.csv') $pathKey
    $cPaths = & $index (Import-P2DiffCsv $Current 'P2_AccessPaths.csv') $pathKey
    $pathDiff = New-Object System.Collections.ArrayList
    foreach ($k in $cPaths.Keys) {
        $c = $cPaths[$k]
        if (-not $bPaths.ContainsKey($k)) {
            $null = $pathDiff.Add([pscustomobject]@{ Change = 'Added'; TrustLevel = $c.TrustLevel; Plane = $c.Plane; Person = $c.Person; Identity = $c.Identity; AccountType = $c.AccountType; Role = $c.Role; Scope = $c.Scope; Path = $(if ($c.ViaGroup) { "$($c.PathType) - $($c.ViaGroup)" } else { $c.PathType }); Before = ''; After = $(if ($c.Standing -eq 'True') { 'Standing' } else { $c.EffectiveState }) })
            continue
        }
        $b = $bPaths[$k]
        $before = if ($b.Standing -eq 'True') { 'Standing' } else { $b.EffectiveState }
        $after = if ($c.Standing -eq 'True') { 'Standing' } else { $c.EffectiveState }
        if ($before -ne $after -or $b.TrustLevel -ne $c.TrustLevel) {
            $null = $pathDiff.Add([pscustomobject]@{ Change = 'Changed'; TrustLevel = $c.TrustLevel; Plane = $c.Plane; Person = $c.Person; Identity = $c.Identity; AccountType = $c.AccountType; Role = $c.Role; Scope = $c.Scope; Path = $(if ($c.ViaGroup) { "$($c.PathType) - $($c.ViaGroup)" } else { $c.PathType }); Before = "$before ($($b.TrustLevel))"; After = "$after ($($c.TrustLevel))" })
        }
    }
    foreach ($k in $bPaths.Keys) {
        if ($cPaths.ContainsKey($k)) { continue }
        $b = $bPaths[$k]
        $null = $pathDiff.Add([pscustomobject]@{ Change = 'Removed'; TrustLevel = $b.TrustLevel; Plane = $b.Plane; Person = $b.Person; Identity = $b.Identity; AccountType = $b.AccountType; Role = $b.Role; Scope = $b.Scope; Path = $(if ($b.ViaGroup) { "$($b.PathType) - $($b.ViaGroup)" } else { $b.PathType }); Before = $(if ($b.Standing -eq 'True') { 'Standing' } else { $b.EffectiveState }); After = '' })
    }
    $pathDiff = @($pathDiff | Sort-Object Change, TrustLevel, Plane, Person, Role)

    $gapKey = { param($r) ("$($r.Plane)|$($r.Subject)|$($r.Setting)").ToLowerInvariant() }
    $bGaps = & $index (Import-P2DiffCsv $Baseline 'P2_PolicyGaps.csv') $gapKey
    $cGaps = & $index (Import-P2DiffCsv $Current 'P2_PolicyGaps.csv') $gapKey
    $gapDiff = New-Object System.Collections.ArrayList
    foreach ($k in $cGaps.Keys) { if (-not $bGaps.ContainsKey($k)) { $g = $cGaps[$k]; $null = $gapDiff.Add([pscustomobject]@{ Change = 'Opened'; TrustLevel = $g.TrustLevel; Plane = $g.Plane; Subject = $g.Subject; Setting = $g.Setting; Current = $g.Current; Target = $g.Target }) } }
    foreach ($k in $bGaps.Keys) { if (-not $cGaps.ContainsKey($k)) { $g = $bGaps[$k]; $null = $gapDiff.Add([pscustomobject]@{ Change = 'Closed'; TrustLevel = $g.TrustLevel; Plane = $g.Plane; Subject = $g.Subject; Setting = $g.Setting; Current = $g.Current; Target = $g.Target }) } }

    $saKey = { param($r) ("$($r.Person)|$($r.Role)|$($r.ApproverAccount)").ToLowerInvariant() }
    $bSa = & $index (Import-P2DiffCsv $Baseline 'P2_SelfApproval.csv') $saKey
    $cSa = & $index (Import-P2DiffCsv $Current 'P2_SelfApproval.csv') $saKey
    $saDiff = New-Object System.Collections.ArrayList
    foreach ($k in $cSa.Keys) { if (-not $bSa.ContainsKey($k)) { $r = $cSa[$k]; $null = $saDiff.Add([pscustomobject]@{ Change = 'Added'; Person = $r.Person; Role = $r.Role; TrustLevel = $r.TrustLevel; ApproverAccount = $r.ApproverAccount; ApproverVia = $r.ApproverVia }) } }
    foreach ($k in $bSa.Keys) { if (-not $cSa.ContainsKey($k)) { $r = $bSa[$k]; $null = $saDiff.Add([pscustomobject]@{ Change = 'Removed'; Person = $r.Person; Role = $r.Role; TrustLevel = $r.TrustLevel; ApproverAccount = $r.ApproverAccount; ApproverVia = $r.ApproverVia }) } }

    $bm = @(Import-P2DiffCsv $Baseline 'P2_Metrics.csv') | Select-Object -First 1
    $cm = @(Import-P2DiffCsv $Current 'P2_Metrics.csv') | Select-Object -First 1
    $metricDiff = New-Object System.Collections.ArrayList
    if ($bm -and $cm) {
        foreach ($p in $cm.PSObject.Properties) {
            $bv = $bm.PSObject.Properties[$p.Name]
            $cv = 0.0; $b0 = 0.0
            if ($bv -and [double]::TryParse([string]$p.Value, [ref]$cv) -and [double]::TryParse([string]$bv.Value, [ref]$b0)) {
                $null = $metricDiff.Add([pscustomobject]@{ Metric = (ConvertTo-P2Label -Name $p.Name); Baseline = $b0; Current = $cv; Change = $cv - $b0 })
            }
        }
    }

    Export-PimData -Data $pathDiff -CsvPath (Join-Path $OutputFolder 'P2Diff_AccessPaths.csv')
    Export-PimData -Data @($gapDiff) -CsvPath (Join-Path $OutputFolder 'P2Diff_PolicyGaps.csv')
    Export-PimData -Data @($saDiff) -CsvPath (Join-Path $OutputFolder 'P2Diff_SelfApproval.csv')
    Export-PimData -Data @($metricDiff) -CsvPath (Join-Path $OutputFolder 'P2Diff_Metrics.csv')

    $tenant = if ($cm) { $cm.TenantName } else { 'Tenant' }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1""><title>PIM Phase 2 Diff - $(& $enc $tenant)</title>")
    $null = $sb.Append('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;color:#1d2733}main{max-width:1400px;margin:0 auto;padding:24px 16px}h1{font-size:26px}h2{font-size:19px;color:#1f4e78;border-bottom:2px solid #1f4e78;padding-bottom:4px;margin-top:30px}.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #dde3ea;padding:5px 7px;text-align:left;vertical-align:top}th{background:#f5f8fb}.none{color:#2e7d32;font-style:italic}.more{color:#5b6673;font-size:12px;font-style:italic}.b{color:#fff;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700}.tl1{background:#7f0000}.tl2{background:#c62828}.tl3{background:#e65100}.tl4{background:#2e7d32}.meta{color:#5b6673;font-size:13px}</style></head><body><main>')
    $null = $sb.Append("<h1>PIM Phase 2 change report</h1><div class=""meta"">$(& $enc $tenant): $(& $enc $bm.EntraRun) to $(& $enc $cm.EntraRun)</div>")
    $null = $sb.Append('<h2>Headline metrics</h2>')
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows @($metricDiff | Where-Object { $_.Change -ne 0 }) -Columns @('Metric', 'Baseline', 'Current', 'Change')))
    $null = $sb.Append("<h2>Access paths ($(@($pathDiff | Where-Object Change -eq 'Added').Count) added, $(@($pathDiff | Where-Object Change -eq 'Removed').Count) removed, $(@($pathDiff | Where-Object Change -eq 'Changed').Count) changed)</h2>")
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows @($pathDiff | Where-Object { $_.AccountType -ne 'WorkloadIdentity' }) -Columns @('Change', 'TrustLevel', 'Plane', 'Person', 'AccountType', 'Role', 'Scope', 'Path', 'Before', 'After') -MaxRows 300 -CsvName 'P2Diff_AccessPaths.csv'))
    $null = $sb.Append('<h2>PIM setting gaps</h2>')
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows @($gapDiff) -Columns @('Change', 'TrustLevel', 'Plane', 'Subject', 'Setting', 'Current', 'Target')))
    $null = $sb.Append('<h2>Self-approval routes</h2>')
    $null = $sb.Append((ConvertTo-P2HtmlTable -Rows @($saDiff) -Columns @('Change', 'Person', 'Role', 'TrustLevel', 'ApproverAccount', 'ApproverVia')))
    $null = $sb.Append('</main></body></html>')
    $safe = ([string]$cm.Tenant) -replace '[^A-Za-z0-9_-]', '_'
    $html = Join-Path $OutputFolder "PIM_Phase2_Diff_$safe.html"
    [System.IO.File]::WriteAllText($html, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    Write-PimLog -Message "Diff written to $OutputFolder ($($pathDiff.Count) path changes)."
    return [pscustomobject]@{ OutputFolder = $OutputFolder; ReportPath = $html; PathChanges = $pathDiff.Count; GapChanges = $gapDiff.Count; SelfApprovalChanges = $saDiff.Count }
}

if ($MyInvocation.InvocationName -ne '.') { Compare-PimPhase2Assessment @PSBoundParameters }
