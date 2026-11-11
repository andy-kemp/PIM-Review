<#
.SYNOPSIS
One command for a full Power Platform privileged access audit, for one tenant or several. The Power Platform
counterpart of Start-PimAudit.ps1, and run the same way.

.DESCRIPTION
For each tenant this collects everything the tool can see, with every option on:
- Entra roles that reach Power Platform (Power Platform Administrator, Dynamics 365 Administrator, Global
  Administrator, Fabric and Business Central Administrator): eligible and active, groups expanded, PIM role
  settings and 90 days of activations
- Conditional Access, authentication strengths and contexts, sign-in methods and licences of every person found
- every environment; System Administrator, System Customizer and Environment Maker in each (directly and
  through teams); Dataverse auditing settings
- cloud flows, canvas apps, connections, agents, model-driven apps and Power Pages sites with their owners
- Power Platform RBAC, management applications, tenant settings and DLP policies
- the assessment: everyday vs CLAD accounts, trust levels, PIM coverage and settings, what changes and what
  breaks when Power Platform admin is in PIM, flows and connections at risk, CLAD provisioning, migration
  worksheet, control checks and NCSC CAF benchmark
When more than one tenant is audited, it also builds the partnership roll-up.

Before you run it, in each tenant: activate Power Platform Administrator in PIM for the account you will use
(and have Global Reader). You sign in twice per tenant (Microsoft Graph, then Azure for the Power Platform
tokens). See README "Power Platform audit: permissions".

.PARAMETER TenantId
One or more tenant IDs or domains (for example contoso.onmicrosoft.com). Short names are worked out from each
tenant's name unless -TenantShortName is given.

.PARAMETER TenantShortName
Short names for the reports, in the same order as -TenantId (for example SE, HIE, SOSE, SDS).

.PARAMETER Tenant
Short names of tenants in Config\audit-tenants.local.json to audit (for example SE, HIE).

.PARAMETER All
Audit every tenant in Config\audit-tenants.local.json.

.PARAMETER ElevateForAudit
Where an environment's Dataverse cannot be read, self-elevate to System Administrator, read it, and remove the
role again at the end of the run (each elevation is logged by Microsoft Purview and in Raw\pp-elevations.csv).
Asked for if not given.

.PARAMETER NoElevation
Never elevate; environments that cannot be read are reported as a coverage gap.

.PARAMETER UseDeviceCode
Sign in with a device code (for sessions where a browser pop-up is not possible).

.EXAMPLE
./Start-PowerPlatformAudit.ps1
Shows a menu of the tenants in Config\audit-tenants.local.json (or asks for tenants if there is no list).

.EXAMPLE
./Start-PowerPlatformAudit.ps1 -All

.EXAMPLE
./Start-PowerPlatformAudit.ps1 -TenantId sds.co.uk, scotent.co.uk, hient.co.uk, sose.scot
#>
[CmdletBinding()]
param(
    [string[]]$Tenant,
    [switch]$All,
    [string]$TenantListPath,
    [string[]]$TenantId,
    [string[]]$TenantShortName,
    [string]$OutputFolder,
    [switch]$ElevateForAudit,
    [switch]$NoElevation,
    [switch]$SkipResources,
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

Remove-Module -Name PimReview.Common -Force -ErrorAction SilentlyContinue

# ---- 1. Prerequisites ------------------------------------------------------------------------
Write-AuditStep 'Checking prerequisites'
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "PowerShell $($PSVersionTable.PSVersion) detected. PowerShell 7 is recommended and much faster (winget install Microsoft.PowerShell)." -ForegroundColor Yellow
}
$required = @(
    @{ Name = 'Microsoft.Graph.Authentication'; Why = 'Microsoft Graph sign-in' },
    @{ Name = 'Az.Accounts'; Why = 'Power Platform and Dataverse tokens' }
)
$missing = @($required | Where-Object { -not (Get-Module -ListAvailable -Name $_.Name) })
if ($missing.Count -gt 0) {
    Write-Host 'These PowerShell modules are missing:' -ForegroundColor Yellow
    foreach ($m in $missing) { Write-Host "  - $($m.Name) ($($m.Why))" -ForegroundColor Yellow }
    $answer = Read-Host 'Install them now for the current user? (Y/N)'
    if ($answer -notmatch '^(?i)y') { throw 'Required modules are missing. Install them and run again.' }
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default }
    foreach ($m in $missing) { Write-Host "Installing $($m.Name)..."; Install-Module -Name $m.Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop }
}
Write-Host 'Modules OK.' -ForegroundColor Green

$excelNote = $null
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    $answer = Read-Host 'Optional: install ImportExcel for an Excel workbook as well as the HTML report? (Y/N)'
    if ($answer -match '^(?i)y') {
        try { Install-Module -Name ImportExcel -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop }
        catch { Write-Host "ImportExcel could not be installed: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
}
if (Get-Module -ListAvailable -Name ImportExcel) {
    try { Import-Module ImportExcel -ErrorAction Stop; $probe = New-Object -TypeName OfficeOpenXml.ExcelPackage; $probe.Dispose(); Write-Host 'Excel workbook: available.' -ForegroundColor Green }
    catch { $excelNote = 'Excel workbook not produced: this device blocks the ImportExcel library (usually Application Control). Open the CSV files in Excel instead.'; Write-Host $excelNote -ForegroundColor Yellow }
}
else { $excelNote = 'Excel workbook not produced: ImportExcel is not installed.' }

Write-Host ''
Write-Host 'Permissions for each tenant (see README "Power Platform audit: permissions"):' -ForegroundColor Cyan
Write-Host '  - Global Reader, and Power Platform Administrator ACTIVATED in PIM before you sign in.'
Write-Host '  - Global Administrator also works, but is not needed.'
Write-Host '  - Dataverse role holders need access inside each environment, which neither role gives automatically.'
if (-not $ElevateForAudit -and -not $NoElevation) {
    Write-Host ''
    Write-Host 'Environments you cannot read inside Dataverse can be read by self-elevating to System Administrator.' -ForegroundColor Yellow
    Write-Host 'The audit adds the role only where needed, reads the environment, and removes the role again at the end' -ForegroundColor Yellow
    Write-Host 'of the run. Each elevation is logged by Microsoft Purview. This is a change in those environments.' -ForegroundColor Yellow
    $ElevateForAudit = [switch]((Read-Host 'Elevate where needed? (Y/N, N reports those environments as a coverage gap)') -match '^(?i)y')
}

# ---- 2. Tenants ------------------------------------------------------------------------------
# Same list as Start-PimAudit.ps1 (Config\audit-tenants.local.json, git-ignored):
#   -All / -Tenant SE,HIE / (nothing) menu / -TenantId for tenants not in the list.
if ([string]::IsNullOrWhiteSpace($TenantListPath)) { $TenantListPath = Join-Path $PSScriptRoot 'Config\audit-tenants.local.json' }
$list = @()
if (Test-Path $TenantListPath) { $list = @((Get-Content -Path $TenantListPath -Raw | ConvertFrom-Json).Tenants | Where-Object { $_.TenantId -and $_.TenantId -notmatch '^<' }) }
if (-not $TenantId -or $TenantId.Count -eq 0) {
    if ($list.Count -eq 0) {
        Write-Host ''
        Write-Host 'No tenant list yet. Enter the tenants to audit, separated by commas (tenant IDs or domains).' -ForegroundColor Cyan
        Write-Host 'Names and short names are worked out from each tenant, and the list is saved for next time (shared with Start-PimAudit.ps1).'
        $answer = Read-Host 'Tenants (for example sds.co.uk, scotent.co.uk)'
        $TenantId = @($answer -split '[,;\s]+' | Where-Object { $_ })
        if ($TenantId.Count -eq 0) { throw 'No tenants entered.' }
    }
    else {
        $picked = @()
        if ($All.IsPresent) { $picked = $list }
        elseif ($Tenant) {
            foreach ($t in $Tenant) {
                $hit = @($list | Where-Object { $_.ShortName -eq $t -or $_.Name -eq $t })
                if ($hit.Count -eq 0) { throw "Tenant '$t' is not in $TenantListPath. Known: $(@($list | ForEach-Object { $_.ShortName }) -join ', ')" }
                $picked += $hit[0]
            }
        }
        else {
            Write-Host ''
            Write-Host 'Tenants in your list:' -ForegroundColor Cyan
            for ($i = 0; $i -lt $list.Count; $i++) { Write-Host ("  {0}. {1} ({2})  {3}" -f ($i + 1), $list[$i].Name, $list[$i].ShortName, $list[$i].TenantId) }
            $choice = Read-Host 'Which to audit? Numbers separated by commas, A for all'
            if ($choice -match '^(?i)a') { $picked = $list }
            else { foreach ($n in ($choice -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })) { $idx = [int]$n - 1; if ($idx -ge 0 -and $idx -lt $list.Count) { $picked += $list[$idx] } } }
        }
        $TenantId = @($picked | ForEach-Object { [string]$_.TenantId })
        $TenantShortName = @($picked | ForEach-Object { [string]$_.ShortName })
    }
}
if (-not $TenantId -or $TenantId.Count -eq 0) { throw 'No tenant given.' }
if ($TenantShortName -and @($TenantShortName | Where-Object { $_ }).Count -gt 0 -and $TenantShortName.Count -ne $TenantId.Count) {
    throw "-TenantShortName has $($TenantShortName.Count) value(s) but -TenantId has $($TenantId.Count). Give one short name per tenant, or none."
}

if (-not $OutputFolder) { $OutputFolder = Join-Path $PSScriptRoot 'Output' }
if (-not (Test-Path $OutputFolder)) { $null = New-Item -ItemType Directory -Path $OutputFolder -Force }

# ---- 3. Run each tenant ----------------------------------------------------------------------
$results = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $TenantId.Count; $i++) {
    $t = $TenantId[$i]
    $short = if ($TenantShortName -and $TenantShortName.Count -gt $i -and $TenantShortName[$i]) { $TenantShortName[$i] } else { $null }
    Write-AuditStep "Tenant $($i + 1) of $($TenantId.Count): $t"
    Write-Host 'Activate Power Platform Administrator in PIM for this tenant now if you have not already.'
    Write-Host 'Sign in to Microsoft Graph, then to Azure, with an account in this tenant.'
    $started = Get-Date
    try {
        try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch { }
        $splat = @{ TenantId = $t; OutputFolder = $OutputFolder }
        if ($short) { $splat.TenantShortName = $short }
        if ($UseDeviceCode) { $splat.UseDeviceCode = $true }
        if ($ElevateForAudit) { $splat.ElevateForAudit = $true; $splat.Unattended = $true }
        if ($SkipResources) { $splat.SkipResources = $true }
        $r = & (Join-Path $PSScriptRoot 'Get-PowerPlatformReview.ps1') @splat
        $r = @($r | Where-Object { $_ -and $_.PSObject.Properties['RunFolder'] -and $_.PSObject.Properties['TenantShortName'] }) | Select-Object -Last 1
        $null = $results.Add([pscustomobject]@{
            Tenant = $(if ($r) { $r.TenantShortName } elseif ($short) { $short } else { $t }); TenantName = $(if ($r) { $r.TenantName } else { $null }); TenantId = $t
            Status = 'Completed'; Minutes = [Math]::Round(((Get-Date) - $started).TotalMinutes, 1)
            Report = $(if ($r) { $r.ReportPath } else { $null }); Workbook = $(if ($r) { $r.WorkbookPath } else { $null }); RunFolder = $(if ($r) { $r.RunFolder } else { $null })
            ElevationsNotRemoved = $(if ($r) { $r.ElevationsNotRemoved } else { 0 }); Error = $null
        })
    }
    catch {
        Write-Host "Tenant $t failed: $($_.Exception.Message)" -ForegroundColor Red
        $null = $results.Add([pscustomobject]@{ Tenant = $(if ($short) { $short } else { $t }); TenantName = $null; TenantId = $t; Status = 'Failed'; Minutes = [Math]::Round(((Get-Date) - $started).TotalMinutes, 1); Report = $null; Workbook = $null; RunFolder = $null; ElevationsNotRemoved = 0; Error = $_.Exception.Message })
    }
}

# Save new tenants to the shared list, with the names worked out during the run.
try {
    $changed = $false
    $save = New-Object System.Collections.ArrayList
    foreach ($e in $list) { $null = $save.Add($e) }
    foreach ($r in @($results | Where-Object Status -eq 'Completed')) {
        if (@($save | Where-Object { [string]$_.TenantId -eq [string]$r.TenantId }).Count -eq 0) {
            $null = $save.Add([pscustomobject]@{ Name = $(if ($r.TenantName) { $r.TenantName } else { $r.TenantId }); ShortName = $r.Tenant; TenantId = $r.TenantId }); $changed = $true
        }
    }
    if ($changed) {
        $dir = Split-Path $TenantListPath -Parent; if (-not (Test-Path $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        [pscustomobject]@{ _about = 'Tenants for Start-PimAudit.ps1 and Start-PowerPlatformAudit.ps1. Local only (git-ignored). Edit freely.'; Tenants = @($save) } | ConvertTo-Json -Depth 5 | Out-File -FilePath $TenantListPath -Encoding UTF8
        Write-Host "Tenant list updated: $TenantListPath" -ForegroundColor Green
    }
}
catch { Write-Host "Tenant list not updated: $($_.Exception.Message)" -ForegroundColor Yellow }

# ---- 4. Partnership roll-up ------------------------------------------------------------------
$rollup = $null
if (@($results | Where-Object Status -eq 'Completed').Count -gt 1) {
    Write-AuditStep 'Building the partnership roll-up'
    try { $rollup = & (Join-Path $PSScriptRoot 'Invoke-PowerPlatformRollup.ps1') -OutputRoot $OutputFolder -RunFolders @($results | Where-Object Status -eq 'Completed' | ForEach-Object RunFolder) }
    catch { Write-Host "Roll-up failed: $($_.Exception.Message)" -ForegroundColor Red }
}

# ---- 5. Summary ------------------------------------------------------------------------------
Write-AuditStep 'Audit finished'
foreach ($r in $results) {
    Write-Host "$($r.Tenant): $($r.Status) in $($r.Minutes) min" -ForegroundColor $(if ($r.Status -eq 'Completed') { 'Green' } else { 'Red' })
    if ($r.Report) { Write-Host "  Power Platform audit: $($r.Report)" }
    if ($r.Workbook) { Write-Host "  Workbook            : $($r.Workbook)" }
    if ([int]$r.ElevationsNotRemoved -gt 0) { Write-Host "  ACTION: System Administrator could not be removed from the run account in $($r.ElevationsNotRemoved) environment(s). See Raw\pp-elevations.csv." -ForegroundColor Red }
    if ($r.Error) { Write-Host "  Error: $($r.Error)" -ForegroundColor Red }
}
if ($rollup -and $rollup.ReportPath) { Write-Host ''; Write-Host "Partnership roll-up: $($rollup.ReportPath)" -ForegroundColor Green }
if ($excelNote) { Write-Host ''; Write-Host $excelNote -ForegroundColor Yellow }
Write-Host ''
Write-Host "Everything is under $OutputFolder. It holds client data: keep it out of git and share it only through approved channels." -ForegroundColor Yellow
Write-Host 'Remember to deactivate Power Platform Administrator in PIM if you activated it for this audit.' -ForegroundColor Yellow

if (-not $NoOpen.IsPresent) {
    $open = if ($rollup -and $rollup.ReportPath) { $rollup.ReportPath } else { @($results | Where-Object Report | Select-Object -First 1 -ExpandProperty Report) }
    foreach ($o in @($open)) { if ($o -and (Test-Path $o)) { try { Invoke-Item -Path $o } catch { } } }
}
$results
