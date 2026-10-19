<#
.SYNOPSIS
One command for a full PIM audit: Entra PIM, Azure RBAC and the PIM Phase 2 assessment, for one tenant or several.

.DESCRIPTION
For each tenant this runs everything the tool can collect, with every option on:
- Entra roles (eligible and active), PIM role settings, approvers, approval history, PIM for Groups,
  group and nested membership, licences, authentication strength, Conditional Access, access reviews
- Azure RBAC across every management group and subscription the account can read (eligible and active,
  groups expanded, Key Vault / storage / SQL / AKS local access, Lighthouse, Activity Log)
- the PIM Phase 2 assessment (trust levels, self-approval, TL1 paths, standing access, policy gaps,
  migration worksheet, HLD findings)
When more than one tenant is audited, it also builds the partnership roll-up.

You sign in once per tenant (Microsoft Graph, then Azure). Use an account with Global Reader (or the read
roles listed in the README) in Entra and Reader at the tenant root management group in Azure.

.PARAMETER TenantId
One or more tenant IDs or domains (for example contoso.onmicrosoft.com). Prompted for if omitted.

.PARAMETER TenantShortName
Short names for the reports, in the same order as -TenantId (for example SE, HIE, SOSE, SDS).

.PARAMETER SkipAzure
Entra only.

.PARAMETER IncludeResourceLevelAccess
Also list access granted on individual resources, which can be slow in large estates.

.PARAMETER UseDeviceCode
Sign in to Azure with a device code (for sessions where a browser pop-up is not possible).

.EXAMPLE
./Start-PimAudit.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
./Start-PimAudit.ps1 -TenantId tenant1.onmicrosoft.com, tenant2.onmicrosoft.com -TenantShortName T1, T2
#>
[CmdletBinding()]
param(
    [string[]]$TenantId,
    [string[]]$TenantShortName,
    [string]$OutputFolder,
    [string]$ConfigPath,
    [switch]$SkipAzure,
    [switch]$IncludeResourceLevelAccess,
    [switch]$UseDeviceCode,
    [switch]$NoOpen
)



function Write-AuditStep {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

# ---- 1. Prerequisites ------------------------------------------------------------------------
Write-AuditStep 'Checking prerequisites'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "PowerShell $($PSVersionTable.PSVersion) detected. PowerShell 7 is recommended and much faster (winget install Microsoft.PowerShell)." -ForegroundColor Yellow
}

$required = @(
    @{ Name = 'Microsoft.Graph.Authentication'; Install = 'Microsoft.Graph.Authentication'; Why = 'Microsoft Graph sign-in' },
    @{ Name = 'ImportExcel'; Install = 'ImportExcel'; Why = 'Excel workbook' }
)
if (-not $SkipAzure.IsPresent) { $required += @{ Name = 'Az.Accounts'; Install = 'Az.Accounts'; Why = 'Azure sign-in' } }

$missing = @($required | Where-Object { -not (Get-Module -ListAvailable -Name $_.Name) })
if ($missing.Count -gt 0) {
    Write-Host 'These PowerShell modules are missing:' -ForegroundColor Yellow
    foreach ($m in $missing) { Write-Host "  - $($m.Name) ($($m.Why))" -ForegroundColor Yellow }
    $answer = Read-Host 'Install them now for the current user? (Y/N)'
    if ($answer -notmatch '^(?i)y') { throw 'Required modules are missing. Install them and run again.' }
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default }
    foreach ($m in $missing) {
        Write-Host "Installing $($m.Install)..."
        Install-Module -Name $m.Install -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
    }
}
Write-Host 'Modules OK.' -ForegroundColor Green

# ---- 2. Tenants ------------------------------------------------------------------------------
if (-not $TenantId -or $TenantId.Count -eq 0) {
    $entered = Read-Host 'Tenant ID or domain to audit (separate several with commas)'
    $TenantId = @($entered.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
if (-not $TenantId -or $TenantId.Count -eq 0) { throw 'No tenant given.' }
if ($TenantShortName -and $TenantShortName.Count -ne $TenantId.Count) {
    throw "-TenantShortName has $($TenantShortName.Count) value(s) but -TenantId has $($TenantId.Count). Give one short name per tenant, or none."
}

# ---- 3. Configuration with everything switched on --------------------------------------------
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot 'Config\pim-review.config.local.json'
    if (-not (Test-Path $ConfigPath)) { $ConfigPath = Join-Path $PSScriptRoot 'Config\pim-review.config.json' }
}
$cfg = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json
$set = {
    param($Name, $Value)
    if ($cfg.PSObject.Properties[$Name]) { $cfg.$Name = $Value } else { $cfg | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
}
& $set 'IncludeTransitiveMembers' $true
& $set 'IncludeApprovalHistory' $true
& $set 'IncludeLicenseDetails' $true
& $set 'IncludePimForGroups' $true
& $set 'IncludeAuthStrength' $true
& $set 'InstallImportExcelIfMissing' $true
& $set 'IncludeAzureRbac' (-not $SkipAzure.IsPresent)
& $set 'AzureIncludeResourceLevelAccess' ([bool]$IncludeResourceLevelAccess.IsPresent)
& $set 'AzureUseDeviceAuthentication' ([bool]$UseDeviceCode.IsPresent)
& $set 'AzureSkipExtendedChecks' $false
& $set 'TenantId' $null
& $set 'TenantLabelOverride' $null
if ($OutputFolder) { & $set 'OutputFolder' $OutputFolder }
if (-not $cfg.OutputFolder) { & $set 'OutputFolder' './Output' }

$outputRoot = [string]$cfg.OutputFolder
if (-not [System.IO.Path]::IsPathRooted($outputRoot)) { $outputRoot = Join-Path $PSScriptRoot ($outputRoot -replace '^\.[\\/]', '') }
if (-not (Test-Path $outputRoot)) { $null = New-Item -ItemType Directory -Path $outputRoot -Force }
& $set 'OutputFolder' $outputRoot

$runConfig = Join-Path $outputRoot ('audit-config-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
$cfg | ConvertTo-Json -Depth 10 | Out-File -FilePath $runConfig -Encoding UTF8

# ---- 4. Run each tenant ----------------------------------------------------------------------
$fullReview = Join-Path $PSScriptRoot 'Invoke-FullPimReview.ps1'
$results = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $TenantId.Count; $i++) {
    $t = $TenantId[$i]
    $short = if ($TenantShortName) { $TenantShortName[$i] } else { $null }
    Write-AuditStep "Tenant $($i + 1) of $($TenantId.Count): $t"
    Write-Host 'Sign in to Microsoft Graph, then to Azure, with an account in this tenant.'
    $started = Get-Date
    try {
        $splat = @{ ConfigPath = $runConfig; TenantId = $t; ForceReConnect = $true }
        if ($short) { $splat.TenantShortName = $short }
        $meta = & $fullReview @splat
        $meta = @($meta | Where-Object { $_ -and $_.PSObject.Properties['SummaryHtmlPath'] }) | Select-Object -Last 1
        $null = $results.Add([pscustomobject]@{
            Tenant        = if ($short) { $short } else { $t }
            Status        = 'Completed'
            Minutes       = [Math]::Round(((Get-Date) - $started).TotalMinutes, 1)
            Phase2Report  = if ($meta) { $meta.Phase2ReportPath } else { $null }
            EntraReport   = if ($meta) { $meta.SummaryHtmlPath } else { $null }
            AzureReport   = if ($meta) { $meta.AzureRbacSummaryHtmlPath } else { $null }
            Workbook      = if ($meta -and $meta.PSObject.Properties['WorkbookPath']) { $meta.WorkbookPath } else { $null }
            Error         = $null
        })
    }
    catch {
        Write-Host "Tenant $t failed: $($_.Exception.Message)" -ForegroundColor Red
        $null = $results.Add([pscustomobject]@{ Tenant = $(if ($short) { $short } else { $t }); Status = 'Failed'; Minutes = [Math]::Round(((Get-Date) - $started).TotalMinutes, 1); Phase2Report = $null; EntraReport = $null; AzureReport = $null; Workbook = $null; Error = $_.Exception.Message })
    }
}

# ---- 5. Partnership roll-up ------------------------------------------------------------------
$rollup = $null
if (@($results | Where-Object Status -eq 'Completed').Count -gt 1) {
    Write-AuditStep 'Building the partnership roll-up'
    try { $rollup = & (Join-Path $PSScriptRoot 'Invoke-PimPartnershipRollup.ps1') -OutputRoot $outputRoot }
    catch { Write-Host "Roll-up failed: $($_.Exception.Message)" -ForegroundColor Red }
}

Remove-Item -Path $runConfig -ErrorAction SilentlyContinue

# ---- 6. Summary ------------------------------------------------------------------------------
Write-AuditStep 'Audit finished'
foreach ($r in $results) {
    $colour = if ($r.Status -eq 'Completed') { 'Green' } else { 'Red' }
    Write-Host "$($r.Tenant): $($r.Status) in $($r.Minutes) min" -ForegroundColor $colour
    if ($r.Phase2Report) { Write-Host "  PIM Phase 2 assessment : $($r.Phase2Report)" }
    if ($r.EntraReport) { Write-Host "  Entra PIM review       : $($r.EntraReport)" }
    if ($r.AzureReport) { Write-Host "  Azure RBAC review      : $($r.AzureReport)" }
    if ($r.Error) { Write-Host "  Error: $($r.Error)" -ForegroundColor Red }
}
if ($rollup -and $rollup.ReportPath) { Write-Host ''; Write-Host "Partnership roll-up: $($rollup.ReportPath)" -ForegroundColor Green }
Write-Host ''
Write-Host "Everything is under $outputRoot. It holds client data: keep it out of git and share it only through approved channels." -ForegroundColor Yellow

if (-not $NoOpen.IsPresent) {
    $open = if ($rollup -and $rollup.ReportPath) { $rollup.ReportPath } else { @($results | Where-Object Phase2Report | Select-Object -First 1 -ExpandProperty Phase2Report) }
    foreach ($o in @($open)) { if ($o -and (Test-Path $o)) { try { Invoke-Item -Path $o } catch { } } }
}

$results
