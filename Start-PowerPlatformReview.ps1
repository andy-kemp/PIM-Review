<#
.SYNOPSIS
Power Platform admin review for one or more tenants, using the same tenant list as Start-PimAudit.ps1.

.DESCRIPTION
For each tenant runs Get-PowerPlatformReview.ps1 (collection and assessment); with more than one tenant it
also builds the partnership roll-up. You sign in twice per tenant (Microsoft Graph, then Azure for the Power
Platform tokens).

Before you run it: activate Power Platform Administrator in PIM for the account you will use, in each tenant.
For Dataverse role holders and flows you also need read access in each environment (for example by
self-elevating to System Administrator); environments without it are reported as a coverage gap.

.EXAMPLE
.\Start-PowerPlatformReview.ps1 -TenantId sds.co.uk, scotent.co.uk, hient.co.uk, sose.scot
.\Start-PowerPlatformReview.ps1            # asks for tenants (or shows the saved list from Start-PimAudit.ps1)
.\Start-PowerPlatformReview.ps1 -All
.\Start-PowerPlatformReview.ps1 -Tenant SE
.\Start-PowerPlatformReview.ps1 -TenantId contoso.onmicrosoft.com -TenantShortName CON
#>
[CmdletBinding()]
param(
    [string[]]$Tenant,
    [switch]$All,
    [string[]]$TenantId,
    [string[]]$TenantShortName,
    [string]$OutputFolder,
    [switch]$UseDeviceCode,
    [switch]$SkipDataverse,
    [switch]$SkipApps,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
Remove-Module -Name PimReview.Common -Force -ErrorAction SilentlyContinue

# Modules
$missing = @('Microsoft.Graph.Authentication', 'Az.Accounts' | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
if ($missing.Count) {
    Write-Host "Missing modules: $($missing -join ', ')" -ForegroundColor Yellow
    if ((Read-Host 'Install them now for the current user? (Y/N)') -notmatch '^(?i)y') { throw 'Required modules are missing.' }
    foreach ($m in $missing) { Install-Module -Name $m -Scope CurrentUser -Repository PSGallery -Force -AllowClobber }
}

# Tenants: -TenantId on the command line, -Tenant/-All from the saved list (Config\audit-tenants.local.json,
# shared with Start-PimAudit.ps1), or asked for here. Names and short names are worked out from each tenant.
if (-not $TenantId) {
    $listPath = Join-Path $PSScriptRoot 'Config\audit-tenants.local.json'
    $list = @()
    if (Test-Path $listPath) { $list = @((Get-Content $listPath -Raw | ConvertFrom-Json).Tenants | Where-Object { $_.TenantId -and $_.TenantId -notmatch '^<' }) }
    if (($Tenant -or $All) -and $list.Count -eq 0) { throw "-Tenant and -All need a tenant list at $listPath. Pass -TenantId instead." }
    $picked = @()
    if ($All) { $picked = $list }
    elseif ($Tenant) {
        foreach ($t in $Tenant) {
            $hit = @($list | Where-Object { $_.ShortName -eq $t -or $_.Name -eq $t })
            if (-not $hit) { throw "Tenant '$t' is not in $listPath." }
            $picked += $hit[0]
        }
    }
    elseif ($list.Count -gt 0) {
        for ($i = 0; $i -lt $list.Count; $i++) { Write-Host ("  {0}. {1} ({2})" -f ($i + 1), $list[$i].Name, $list[$i].ShortName) }
        $choice = Read-Host 'Which to review? Numbers separated by commas, A for all'
        if ($choice -match '^(?i)a') { $picked = $list }
        else { foreach ($n in ($choice -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })) { $picked += $list[[int]$n - 1] } }
    }
    if ($picked.Count -gt 0) {
        $TenantId = @($picked | ForEach-Object { [string]$_.TenantId })
        $TenantShortName = @($picked | ForEach-Object { [string]$_.ShortName })
    }
    else {
        $answer = Read-Host 'Tenants to review: tenant IDs or domains, separated by commas (for example sds.co.uk, scotent.co.uk)'
        $TenantId = @($answer -split '[,;\s]+' | Where-Object { $_ })
    }
}
if (-not $TenantId) { throw 'No tenant given.' }
if (-not $OutputFolder) { $OutputFolder = Join-Path $PSScriptRoot 'Output' }

$results = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $TenantId.Count; $i++) {
    $short = if ($TenantShortName -and $TenantShortName.Count -gt $i) { $TenantShortName[$i] } else { $null }
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host " Tenant $($i + 1) of $($TenantId.Count): $($TenantId[$i])" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    try {
        try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch { }
        $splat = @{ TenantId = $TenantId[$i]; OutputFolder = $OutputFolder }
        if ($short) { $splat.TenantShortName = $short }
        if ($UseDeviceCode) { $splat.UseDeviceCode = $true }
        if ($SkipDataverse) { $splat.SkipDataverse = $true }
        if ($SkipApps) { $splat.SkipApps = $true }
        $r = & (Join-Path $PSScriptRoot 'Get-PowerPlatformReview.ps1') @splat | Where-Object { $_ -and $_.PSObject.Properties['RunFolder'] } | Select-Object -Last 1
        $null = $results.Add([pscustomobject]@{ Tenant = $(if ($short) { $short } else { $TenantId[$i] }); Status = 'Completed'; Report = $r.ReportPath; RunFolder = $r.RunFolder; Error = $null })
    }
    catch {
        Write-Host "Tenant $($TenantId[$i]) failed: $($_.Exception.Message)" -ForegroundColor Red
        $null = $results.Add([pscustomobject]@{ Tenant = $(if ($short) { $short } else { $TenantId[$i] }); Status = 'Failed'; Report = $null; RunFolder = $null; Error = $_.Exception.Message })
    }
}

$rollup = $null
$done = @($results | Where-Object Status -eq 'Completed')
if ($done.Count -gt 1) {
    try { $rollup = & (Join-Path $PSScriptRoot 'Invoke-PowerPlatformRollup.ps1') -OutputRoot $OutputFolder -RunFolders @($done | ForEach-Object RunFolder) }
    catch { Write-Host "Roll-up failed: $($_.Exception.Message)" -ForegroundColor Red }
}

Write-Host ''
foreach ($r in $results) {
    Write-Host "$($r.Tenant): $($r.Status)" -ForegroundColor $(if ($r.Status -eq 'Completed') { 'Green' } else { 'Red' })
    if ($r.Report) { Write-Host "  $($r.Report)" }
    if ($r.Error) { Write-Host "  $($r.Error)" -ForegroundColor Red }
}
if ($rollup) { Write-Host "Partnership: $($rollup.ReportPath)" -ForegroundColor Green }
Write-Host "Output holds client data: keep it out of git." -ForegroundColor Yellow
if (-not $NoOpen) {
    $open = if ($rollup) { $rollup.ReportPath } else { @($done | Select-Object -First 1 -ExpandProperty Report) }
    foreach ($o in @($open)) { if ($o -and (Test-Path $o)) { try { Invoke-Item $o } catch { } } }
}
$results
