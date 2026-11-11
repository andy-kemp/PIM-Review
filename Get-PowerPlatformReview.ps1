<#
.SYNOPSIS
Collects everything about privileged access to Power Platform in one tenant: who holds the admin roles and how
(PIM settings, activations, Conditional Access, sign-in methods), who is System Administrator in each
environment, which accounts (everyday or CLAD) own flows, apps and connections, and the tenant guardrails.

.DESCRIPTION
Read-only unless -ElevateForAudit is used (see below). Writes the evidence to <OutputFolder>\<tenant>\
PowerPlatform-<timestamp>\Raw and then runs Invoke-PowerPlatformAssessment.ps1, which writes the registers,
control checks, HTML report and (if ImportExcel works on the device) the Excel workbook.

Collected:
- Entra roles that reach Power Platform (Power Platform Administrator, Dynamics 365 Administrator, Global
  Administrator, Fabric Administrator, Business Central Administrator): eligible and active, direct and through
  groups (groups expanded, PIM for Groups included), PIM role settings and 90 days of activations.
- Conditional Access policies, authentication contexts and authentication strengths.
- Every person found: licences, sign-in activity, registered sign-in methods, group membership (for
  Conditional Access), and every CLAD account in the tenant so everyday and CLAD accounts can be linked.
- Every environment: type, Dataverse, security group, managed environment, environment group.
- Dataverse per environment: System Administrator, System Customizer and Environment Maker holders (direct and
  through teams, Entra group teams expanded), application users, users by access mode, auditing settings.
  Environments without Dataverse: Environment Admin and Environment Maker.
- Cloud flows (state, owner, connectors, trigger), canvas apps, connections (owner, connector, status), and
  from the Power Platform inventory: agents, agent flows, model-driven apps and Power Pages sites.
- Power Platform RBAC role assignments, management applications (service principals registered as Power
  Platform admins), tenant settings and DLP policies.

Permissions (see README "Power Platform audit: permissions"):
- Global Reader in Entra (Graph reads, Conditional Access, PIM settings).
- Power Platform Administrator ACTIVE (activate in PIM before the run) for the Power Platform admin APIs.
  Global Administrator also works but is not needed.
- Dataverse role holders need access inside each environment, which neither role gives automatically. Without
  it the environment is a recorded coverage gap. With -ElevateForAudit the script self-elevates to System
  Administrator in those environments only (logged by Microsoft Purview), reads them, and removes the role
  again at the end of the run. Every elevation and removal is written to Raw\pp-elevations.csv.

Works in Windows PowerShell 5.1 and PowerShell 7. Needs Microsoft.Graph.Authentication and Az.Accounts.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,
    [string]$TenantShortName,
    [string]$OutputFolder,
    [switch]$UseDeviceCode,
    [switch]$SkipDataverse,
    [switch]$SkipResources,
    [switch]$ElevateForAudit,
    [switch]$Unattended,
    [int]$ActivationHistoryDays = 90,
    [string[]]$EnvironmentFilter,
    [switch]$NoAssessment
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules\PimReview.Common.psm1') -Force -DisableNameChecking

#region settings
$PpRoles = [ordered]@{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    '11648597-926c-4cf3-9c36-bcebb0ba8dcc' = 'Power Platform Administrator'
    '44367163-eba1-44c3-98af-f5787879f96a' = 'Dynamics 365 Administrator'
    'a9ea8996-122f-4c74-9520-8edcd192826c' = 'Fabric Administrator'
    '963797fb-eb3b-4cde-8ce3-5878b3f32a3f' = 'Dynamics 365 Business Central Administrator'
}
$DataverseRoles = @('System Administrator', 'System Customizer', 'Environment Maker')
$ResBap = 'https://service.powerapps.com/'
$ResFlow = 'https://service.flow.microsoft.com/'
$ResPpApi = 'https://api.powerplatform.com'
$BapBase = 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform'
#endregion

#region helpers
function Get-P {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] } return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-PPath {
    param($Obj, [string]$Path)
    $cur = $Obj
    foreach ($part in $Path.Split('.')) { $cur = Get-P $cur $part; if ($null -eq $cur) { return $null } }
    return $cur
}

$script:Log = New-Object System.Collections.ArrayList
function Add-RunLog {
    param([string]$Step, [string]$Target, [string]$Status, [string]$Message)
    $null = $script:Log.Add([pscustomobject]@{ Time = (Get-Date).ToString('s'); Step = $Step; Target = $Target; Status = $Status; Message = $Message })
    $colour = switch ($Status) { 'OK' { 'Green' } 'Warning' { 'Yellow' } 'Failed' { 'Red' } default { 'Gray' } }
    Write-Host ("  [{0}] {1} {2} {3}" -f $Status, $Step, $Target, $Message) -ForegroundColor $colour
}

function Write-Section { param([string]$Text) Write-Host ''; Write-Host $Text -ForegroundColor Cyan }

$script:Tokens = @{}
function Get-PpToken {
    param([string]$Resource)
    $cached = $script:Tokens[$Resource]
    if ($cached -and $cached.Expires -gt (Get-Date).AddMinutes(5)) { return $cached.Token }
    $t = Get-AzAccessToken -ResourceUrl $Resource -TenantId $script:TenantGuid -ErrorAction Stop -WarningAction SilentlyContinue
    $tok = $t.Token
    if ($tok -is [System.Security.SecureString]) { $tok = (New-Object System.Net.NetworkCredential('', $tok)).Password }
    $exp = (Get-Date).AddMinutes(45)
    try { if ($t.ExpiresOn) { $exp = $t.ExpiresOn.LocalDateTime } } catch { }
    $script:Tokens[$Resource] = @{ Token = $tok; Expires = $exp }
    return $tok
}

function Invoke-PpRequest {
    # GET/POST/DELETE to a Power Platform or Dataverse endpoint with retry. Returns the parsed body.
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Resource,
        [string]$Method = 'GET',
        [string]$Body,
        [hashtable]$ExtraHeaders,
        [int]$MaxRetries = 5
    )
    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        $headers = @{ Authorization = 'Bearer ' + (Get-PpToken -Resource $Resource); Accept = 'application/json' }
        if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] } }
        try {
            $params = @{ Uri = $Uri; Method = $Method; Headers = $headers; ErrorAction = 'Stop'; UseBasicParsing = $true }
            if ($Body) { $params.Body = $Body; $params.ContentType = 'application/json' }
            $resp = Invoke-WebRequest @params
            if ([string]::IsNullOrWhiteSpace($resp.Content)) { return $null }
            return ($resp.Content | ConvertFrom-Json)
        }
        catch {
            $code = 0
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($code -eq 0 -and $_.Exception.Message -match '\b(401|403|404)\b') { $code = [int]$Matches[1] }
            $retryable = ($code -eq 429) -or ($code -ge 500)
            if (-not $retryable -or $attempt -ge $MaxRetries) {
                $ex = New-Object System.Exception ("HTTP {0}: {1}" -f $code, $_.Exception.Message)
                $ex.Data['StatusCode'] = $code
                throw $ex
            }
            $delay = [Math]::Min(60, [Math]::Pow(2, $attempt) * 2)
            try { $ra = $_.Exception.Response.Headers['Retry-After']; if ($ra) { $delay = [int]$ra } } catch { }
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-PpPaged {
    param([string]$Uri, [string]$Resource, [hashtable]$ExtraHeaders)
    $out = New-Object System.Collections.ArrayList
    $next = $Uri
    while ($next) {
        $r = Invoke-PpRequest -Uri $next -Resource $Resource -ExtraHeaders $ExtraHeaders
        foreach ($i in @(Get-P $r 'value')) { if ($null -ne $i) { $null = $out.Add($i) } }
        $next = Get-P $r '@odata.nextLink'
        if (-not $next) { $next = Get-P $r 'nextLink' }
    }
    return , $out
}

function Get-StatusCode { param($ErrorRecord) try { return [int]$ErrorRecord.Exception.Data['StatusCode'] } catch { return 0 } }

$script:People = @{}
function Register-Person {
    param([string]$Id, [string]$Upn, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Id)) { return }
    $Id = $Id.ToLowerInvariant()
    if (-not $script:People.ContainsKey($Id)) { $script:People[$Id] = @{ Id = $Id; Upn = $Upn; Name = $Name } }
}

$script:GroupMemberCache = @{}
function Get-GroupUsers {
    # Transitive user members of an Entra group, plus PIM for Groups eligible members.
    param([string]$GroupId)
    if ($script:GroupMemberCache.ContainsKey($GroupId)) { return $script:GroupMemberCache[$GroupId] }
    $list = New-Object System.Collections.ArrayList
    try {
        $members = Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,displayName,accountEnabled&`$top=999"
        foreach ($m in $members) { $null = $list.Add([pscustomobject]@{ Id = $m.id; Upn = $m.userPrincipalName; Name = $m.displayName; Via = 'Member' }) }
    }
    catch { Add-RunLog 'GroupMembers' $GroupId 'Warning' $_.Exception.Message }
    try {
        $elig = Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$GroupId'&`$expand=principal"
        foreach ($e in $elig) {
            $pr = Get-P $e 'principal'
            if ((Get-P $pr '@odata.type') -match 'user') {
                $null = $list.Add([pscustomobject]@{ Id = $pr.id; Upn = (Get-P $pr 'userPrincipalName'); Name = (Get-P $pr 'displayName'); Via = 'PIM for Groups eligible' })
            }
        }
    }
    catch { Write-Verbose "PIM for Groups lookup skipped for $GroupId" }
    $script:GroupMemberCache[$GroupId] = $list
    return $list
}

function Get-ConnectorNames {
    # Connector names from flow connectionReferences, app connectionReferences or inventory powerPlatformConnectors.
    param($ConnRefs)
    $names = New-Object System.Collections.Generic.HashSet[string]
    if ($null -eq $ConnRefs) { return @() }
    $items = @()
    if ($ConnRefs -is [System.Array] -or $ConnRefs -is [System.Collections.IList]) { $items = @($ConnRefs | ForEach-Object { [pscustomobject]@{ Name = $null; Value = $_ } }) }
    else { $items = @($ConnRefs.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $items) {
        $v = $p.Value
        $n = Get-P $v 'connectorId'
        if (-not $n) { $n = Get-P $v 'apiName' }
        if (-not $n) { $n = Get-PPath $v 'api.name' }
        if (-not $n) { $id = Get-P $v 'id'; if (-not $id) { $id = Get-P $v 'apiId' }; if ($id) { $n = ($id -split '/')[-1] } }
        if (-not $n) { $n = $p.Name }
        if ($n) {
            $n = ([string]$n).ToLowerInvariant()
            if ($n -notlike 'shared_*' -and $n -notmatch '^[0-9a-f-]{36}$') { $n = 'shared_' + $n }
            $null = $names.Add($n)
        }
    }
    return @($names)
}

$AdminConnectors = @('shared_powerplatformforadmins', 'shared_powerplatformadminv2', 'shared_microsoftflowforadmins', 'shared_powerappsforadmins', 'shared_powerappsforappmakers', 'shared_dataverseadmin')
$DataverseConnectors = @('shared_commondataserviceforapps', 'shared_commondataservice', 'shared_dynamicscrmonline')
$HttpConnectors = @('shared_webcontents', 'shared_webcontentsv2', 'shared_http', 'shared_sendmail')
$PrivilegedConnectors = @('shared_azuread', 'shared_office365groups', 'shared_arm', 'shared_azureautomation', 'shared_keyvault', 'shared_azurekeyvault')
function Get-ConnectorFlags {
    param([string[]]$Names)
    $c = @($Names | Where-Object { $_ })
    return [ordered]@{
        Connectors = ($c -join '; '); ConnectorsKnown = ($c.Count -gt 0)
        UsesDataverse = [bool](@($c | Where-Object { $_ -in $DataverseConnectors }).Count)
        UsesAdminConnector = [bool](@($c | Where-Object { $_ -in $AdminConnectors }).Count)
        UsesHttp = [bool](@($c | Where-Object { $_ -in $HttpConnectors }).Count)
        UsesPrivilegedConnector = [bool](@($c | Where-Object { $_ -in $PrivilegedConnectors }).Count)
    }
}
#endregion

#region connect
$started = Get-Date
foreach ($m in 'Microsoft.Graph.Authentication', 'Az.Accounts') {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m is missing. Install-Module $m -Scope CurrentUser" }
}
$cfgPath = Join-Path $PSScriptRoot 'Config\pim-review.config.local.json'
if (-not (Test-Path $cfgPath)) { $cfgPath = Join-Path $PSScriptRoot 'Config\pim-review.config.json' }
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$catPath = Join-Path $PSScriptRoot 'Config\pim-phase2.catalogue.local.json'
if (-not (Test-Path $catPath)) { $catPath = Join-Path $PSScriptRoot 'Config\pim-phase2.catalogue.json' }
$catalogue = $null
try { $catalogue = Get-Content $catPath -Raw | ConvertFrom-Json } catch { }
$cladPrefixes = @(Get-PPath $catalogue 'Identity.CladUpnPrefixes' | Where-Object { $_ })
if ($cladPrefixes.Count -eq 0) { $p = Get-P $cfg 'NamingCompliancePrefix'; if (-not $p) { $p = 'clad_' }; $cladPrefixes = @($p) }

Write-Host ''
Write-Host "Power Platform audit: $TenantId" -ForegroundColor Cyan
Write-Host 'Sign-in 1 of 2: Microsoft Graph.'
$scopes = @('RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.Directory', 'User.Read.All', 'Group.Read.All', 'Organization.Read.All',
    'Domain.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.Read.All',
    'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAssignmentSchedule.Read.AzureADGroup')
$mgParams = @{ Scopes = $scopes; TenantId = $TenantId; NoWelcome = $true; ErrorAction = 'Stop' }
if ($UseDeviceCode) { $mgParams.UseDeviceCode = $true }
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
Connect-MgGraph @mgParams
$orgInfo = (Invoke-GraphRequestWithRetry -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains').value | Select-Object -First 1
$script:TenantGuid = $orgInfo.id
$tenantName = $orgInfo.displayName
if (-not $TenantShortName) {
    # Initials of the tenant name, ignoring "and"/"ltd": Skills Development Scotland -> SDS,
    # Highlands and Islands Enterprise -> HIE, South of Scotland Enterprise -> SOSE.
    $words = @($tenantName -split '[^A-Za-z0-9]+' | Where-Object { $_ -and $_ -notmatch '^(?i)(and|ltd|limited|plc)$' })
    $TenantShortName = (($words | ForEach-Object { $_.Substring(0, 1) }) -join '').ToUpperInvariant()
    if ($TenantShortName.Length -lt 2) { $TenantShortName = ($tenantName -replace '[^A-Za-z0-9]', '') }
}
Write-Host "Tenant: $tenantName ($TenantShortName)"

Write-Host 'Sign-in 2 of 2: Azure (used only to get Power Platform and Dataverse tokens; no subscription needed).'
try { $null = Update-AzConfig -LoginExperienceV2 Off -Scope Process -ErrorAction Stop -WarningAction SilentlyContinue } catch { }
$azParams = @{ Tenant = $script:TenantGuid; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
if ($UseDeviceCode) { $azParams.UseDeviceAuthentication = $true }
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx -or $ctx.Tenant.Id -ne $script:TenantGuid) { $null = Connect-AzAccount @azParams }
$ctx = Get-AzContext
$runAccount = $ctx.Account.Id

if (-not $OutputFolder) { $OutputFolder = Join-Path $PSScriptRoot 'Output' }
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$runFolder = Ensure-Directory -Path (Join-Path $OutputFolder (Join-Path (Get-SafeFileName -Name $TenantShortName) "PowerPlatform-$stamp"))
$rawFolder = Ensure-Directory -Path (Join-Path $runFolder 'Raw')
Write-Host "Output: $runFolder"

# The run account and which relevant roles it holds now (explains any coverage gaps).
$me = $null
try { $me = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($runAccount))?`$select=id,userPrincipalName,displayName" } catch { }
$runRoles = @()
if ($me) {
    try {
        $mine = Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$($me.id)'"
        $runRoles = @($mine | ForEach-Object { $rid = [string]$_.roleDefinitionId; if ($PpRoles.Contains($rid)) { $PpRoles[$rid] } elseif ($rid -eq 'f2ef992c-3afb-46b9-b7cf-a126ee74c451') { 'Global Reader' } } | Where-Object { $_ } | Sort-Object -Unique)
    }
    catch { }
}
Write-Host ("Run account {0} holds now: {1}" -f $runAccount, $(if ($runRoles) { $runRoles -join ', ' } else { 'none of the Power Platform admin roles or Global Reader' }))
if (-not ($runRoles | Where-Object { $_ -in @('Power Platform Administrator', 'Global Administrator', 'Dynamics 365 Administrator') })) {
    Write-Host 'Power Platform Administrator is not active for this account: environment, flow, app and connection detail will be missing. Activate it in PIM and run again for full coverage.' -ForegroundColor Yellow
}
#endregion

#region 1. tenant roles
Write-Section 'Entra roles that reach Power Platform'
$roleRows = New-Object System.Collections.ArrayList
foreach ($rid in $PpRoles.Keys) {
    $rname = $PpRoles[$rid]
    $sets = @(
        @{ State = 'Eligible'; Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=roleDefinitionId eq '$rid'&`$expand=principal" },
        @{ State = 'Active'; Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=roleDefinitionId eq '$rid'&`$expand=principal" }
    )
    foreach ($s in $sets) {
        try { $items = Get-GraphPagedResults -Uri $s.Uri }
        catch { Add-RunLog 'TenantRoles' "$rname/$($s.State)" 'Failed' $_.Exception.Message; continue }
        foreach ($i in $items) {
            $assignType = Get-P $i 'assignmentType'
            if ($s.State -eq 'Active' -and $assignType -eq 'Activated') { $state = 'Active (activated from eligible)' } else { $state = $s.State }
            $end = Get-P $i 'endDateTime'
            $pr = Get-P $i 'principal'
            if (-not $pr) { continue }
            $ptype = Get-PrincipalType -Principal $pr
            $base = @{
                RoleName = $rname; RoleId = $rid; State = $state; Permanent = [bool](-not $end)
                StartDateTime = Get-P $i 'startDateTime'; EndDateTime = $end; DirectoryScope = Get-P $i 'directoryScopeId'
            }
            if ($ptype -eq 'Group') {
                foreach ($u in (Get-GroupUsers -GroupId $pr.id)) {
                    Register-Person $u.Id $u.Upn $u.Name
                    $row = $base.Clone()
                    $row += @{ PrincipalType = 'User'; UserId = $u.Id; UserPrincipalName = $u.Upn; DisplayName = $u.Name; AssignedVia = 'Group'; GroupId = $pr.id; GroupName = (Get-P $pr 'displayName'); GroupMembership = $u.Via }
                    $null = $roleRows.Add([pscustomobject]$row)
                }
            }
            else {
                if ($ptype -eq 'User') { Register-Person $pr.id (Get-P $pr 'userPrincipalName') (Get-P $pr 'displayName') }
                $row = $base.Clone()
                $row += @{ PrincipalType = $ptype; UserId = (Get-P $pr 'id'); UserPrincipalName = (Get-P $pr 'userPrincipalName'); DisplayName = (Get-P $pr 'displayName'); AssignedVia = 'Direct'; GroupId = $null; GroupName = $null; GroupMembership = $null }
                $null = $roleRows.Add([pscustomobject]$row)
            }
        }
        Add-RunLog 'TenantRoles' "$rname/$($s.State)" 'OK' "$(@($items).Count) assignment(s)"
    }
}
#endregion

#region 2. PIM role settings and activation history
Write-Section 'PIM settings and activations for those roles'
$settingRows = New-Object System.Collections.ArrayList
foreach ($rid in $PpRoles.Keys) {
    $rname = $PpRoles[$rid]
    try {
        $pa = Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$rid'&`$expand=policy(`$expand=rules)"
        $pol = Get-P (@($pa) | Select-Object -First 1) 'policy'
        $rules = @{}
        foreach ($r in @(Get-P $pol 'rules')) { if ($r) { $rules[[string]$r.id] = $r } }
        $exp = $rules['Expiration_EndUser_Assignment']; $appr = $rules['Approval_EndUser_Assignment']
        $enab = $rules['Enablement_EndUser_Assignment']; $actx = $rules['AuthenticationContext_EndUser_Assignment']
        $eligExp = $rules['Expiration_Admin_Eligibility']; $actExp = $rules['Expiration_Admin_Assignment']
        $hours = $null
        $dur = Get-P $exp 'maximumDuration'
        if ($dur) { try { $hours = [Math]::Round([System.Xml.XmlConvert]::ToTimeSpan([string]$dur).TotalHours, 1) } catch { } }
        $enabled = @(Get-P $enab 'enabledRules')
        $setting = Get-P $appr 'setting'
        $approvers = @()
        foreach ($stage in @(Get-P $setting 'approvalStages')) {
            foreach ($a in @(Get-P $stage 'primaryApprovers')) {
                $d = Get-P $a 'description'; $gid = Get-P $a 'groupId'; $uid = Get-P $a 'userId'
                $approvers += $(if ($d) { $d } elseif ($gid) { "group $gid" } else { "user $uid" })
            }
        }
        $null = $settingRows.Add([pscustomobject]@{
            RoleName = $rname; RoleId = $rid; MaxActivationHours = $hours
            ApprovalRequired = [bool](Get-P $setting 'isApprovalRequired'); Approvers = ($approvers -join '; ')
            MfaRequired = ($enabled -contains 'MultiFactorAuthentication'); JustificationRequired = ($enabled -contains 'Justification'); TicketRequired = ($enabled -contains 'Ticketing')
            AuthContextRequired = [bool](Get-P $actx 'isEnabled'); AuthContextClaim = Get-P $actx 'claimValue'
            PermanentEligibleAllowed = -not [bool](Get-P $eligExp 'isExpirationRequired'); EligibleMaxDuration = Get-P $eligExp 'maximumDuration'
            PermanentActiveAllowed = -not [bool](Get-P $actExp 'isExpirationRequired'); ActiveMaxDuration = Get-P $actExp 'maximumDuration'
            PolicyId = Get-P $pol 'id'
        })
        Add-RunLog 'RoleSettings' $rname 'OK' ''
    }
    catch { Add-RunLog 'RoleSettings' $rname 'Warning' $_.Exception.Message }
}

$activationRows = New-Object System.Collections.ArrayList
$since = (Get-Date).ToUniversalTime().AddDays(-1 * $ActivationHistoryDays)
foreach ($rid in $PpRoles.Keys) {
    $rname = $PpRoles[$rid]
    try {
        $reqs = Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests?`$filter=roleDefinitionId eq '$rid'&`$expand=principal"
        $n = 0
        foreach ($q in $reqs) {
            if ((Get-P $q 'action') -ne 'selfActivate') { continue }
            $created = $null; try { $created = [datetime](Get-P $q 'createdDateTime') } catch { }
            if ($created -and $created.ToUniversalTime() -lt $since) { continue }
            $pr = Get-P $q 'principal'
            $just = [string](Get-P $q 'justification')
            if ($just.Length -gt 200) { $just = $just.Substring(0, 200) }
            $null = $activationRows.Add([pscustomobject]@{
                RoleName = $rname; UserId = Get-P $q 'principalId'; UserPrincipalName = Get-P $pr 'userPrincipalName'; DisplayName = Get-P $pr 'displayName'
                Created = Get-P $q 'createdDateTime'; Status = Get-P $q 'status'; Duration = Get-PPath $q 'scheduleInfo.expiration.duration'; Justification = $just
            })
            $n++
        }
        Add-RunLog 'Activations' $rname 'OK' "$n in $ActivationHistoryDays days"
    }
    catch { Add-RunLog 'Activations' $rname 'Warning' $_.Exception.Message }
}
#endregion

#region 3. Conditional Access
Write-Section 'Conditional Access'
$caRows = New-Object System.Collections.ArrayList
$caRaw = $null; $authStrengths = @(); $authContexts = @()
try {
    $caRaw = @(Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')
    try { $authStrengths = @(Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies') } catch { Add-RunLog 'AuthStrengths' 'tenant' 'Warning' $_.Exception.Message }
    try { $authContexts = @(Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences') } catch { }
    $strengthById = @{}
    foreach ($s in $authStrengths) { $strengthById[[string]$s.id] = $s }
    $phishCombos = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')
    foreach ($p in $caRaw) {
        $c = Get-P $p 'conditions'; $u = Get-P $c 'users'; $a = Get-P $c 'applications'; $g = Get-P $p 'grantControls'; $sc = Get-P $p 'sessionControls'
        $asId = [string](Get-PPath $g 'authenticationStrength.id')
        $as = $null; if ($asId -and $strengthById.ContainsKey($asId)) { $as = $strengthById[$asId] } elseif ($asId) { $as = Get-P $g 'authenticationStrength' }
        $combos = @(Get-P $as 'allowedCombinations')
        $phish = ($combos.Count -gt 0 -and @($combos | Where-Object { $_ -notin $phishCombos }).Count -eq 0)
        $null = $caRows.Add([pscustomobject]@{
            PolicyId = $p.id; PolicyName = $p.displayName; State = $p.state
            IncludeUsers = (@(Get-P $u 'includeUsers') -join '; '); ExcludeUsers = (@(Get-P $u 'excludeUsers') -join '; ')
            IncludeGroups = (@(Get-P $u 'includeGroups') -join '; '); ExcludeGroups = (@(Get-P $u 'excludeGroups') -join '; ')
            IncludeRoles = (@(Get-P $u 'includeRoles') -join '; '); ExcludeRoles = (@(Get-P $u 'excludeRoles') -join '; ')
            IncludeApps = (@(Get-P $a 'includeApplications') -join '; '); ExcludeApps = (@(Get-P $a 'excludeApplications') -join '; ')
            IncludeAuthContext = (@(Get-P $a 'includeAuthenticationContextClassReferences') -join '; ')
            UserActions = (@(Get-P $a 'includeUserActions') -join '; ')
            GrantOperator = Get-P $g 'operator'; BuiltInControls = (@(Get-P $g 'builtInControls') -join '; ')
            AuthStrength = Get-P $as 'displayName'; AuthStrengthCombinations = ($combos -join '; '); AuthStrengthPhishingResistant = $phish
            SignInFrequency = $(if (Get-PPath $sc 'signInFrequency.isEnabled') { "$(Get-PPath $sc 'signInFrequency.value') $(Get-PPath $sc 'signInFrequency.type')" } else { $null })
            HasLocations = [bool](Get-P $c 'locations'); HasPlatforms = [bool](Get-P $c 'platforms'); HasDeviceFilter = [bool](Get-P $c 'devices')
            ClientAppTypes = (@(Get-P $c 'clientAppTypes') -join '; ')
        })
    }
    Add-RunLog 'ConditionalAccess' 'tenant' 'OK' "$($caRaw.Count) polic(ies), $($authContexts.Count) authentication context(s)"
}
catch { Add-RunLog 'ConditionalAccess' 'tenant' 'Warning' "$($_.Exception.Message) (needs Policy.Read.All and Global Reader or Security Reader)" }
#endregion

#region 4. environments
Write-Section 'Power Platform environments'
$envRows = New-Object System.Collections.ArrayList
$ppAvailable = $true
try {
    $envs = Get-PpPaged -Uri "$BapBase/scopes/admin/environments?api-version=2021-04-01&`$expand=properties.governanceConfiguration" -Resource $ResBap
    Add-RunLog 'Environments' 'tenant' 'OK' "$($envs.Count) environment(s)"
}
catch {
    $ppAvailable = $false
    $envs = @()
    Add-RunLog 'Environments' 'tenant' 'Failed' "$($_.Exception.Message). Activate Power Platform Administrator for $runAccount and run again. Entra evidence is still reported."
}

$sgInfo = @{}
foreach ($e in $envs) {
    $p = Get-P $e 'properties'
    $disp = Get-P $p 'displayName'
    if ($EnvironmentFilter) {
        $hit = $false
        foreach ($f in $EnvironmentFilter) { if ($disp -like $f -or $e.name -like $f) { $hit = $true } }
        if (-not $hit) { continue }
    }
    $lem = Get-P $p 'linkedEnvironmentMetadata'
    $sg = Get-P $lem 'securityGroupId'
    if ($sg -and -not $sgInfo.ContainsKey($sg)) {
        $g = Resolve-Group -GroupId $sg
        $cnt = $null
        try { $cnt = @(Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/groups/$sg/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999").Count } catch { }
        $sgInfo[$sg] = @{ Name = $(if ($g) { $g.displayName } else { '(not found)' }); Members = $cnt }
    }
    $creator = Get-P $p 'createdBy'
    $null = $envRows.Add([pscustomobject]@{
        EnvironmentId = $e.name; DisplayName = $disp; Type = Get-P $p 'environmentSku'; IsDefault = [bool](Get-P $p 'isDefault')
        Region = Get-P $e 'location'; HasDataverse = [bool](Get-P $lem 'instanceUrl'); InstanceUrl = Get-P $lem 'instanceUrl'
        SecurityGroupId = $sg; SecurityGroupName = $(if ($sg) { $sgInfo[$sg].Name } else { $null }); SecurityGroupMembers = $(if ($sg) { $sgInfo[$sg].Members } else { $null })
        Managed = ((Get-PPath $p 'governanceConfiguration.protectionLevel') -eq 'Standard'); EnvironmentGroup = Get-PPath $p 'parentEnvironmentGroup.id'
        State = Get-PPath $p 'states.management.id'
        CreatedBy = $(if ($creator) { [string](Get-P $creator 'userPrincipalName') } else { $null }); CreatedByType = $(if ($creator) { Get-P $creator 'type' } else { $null })
        CreatedTime = Get-P $p 'createdTime'
        DataverseAccess = 'NotAttempted'; Elevated = $false
        AuditEnabled = $null; UserAccessAuditEnabled = $null; AuditRetentionDays = $null; DataverseUsers = $null; AdministrativeModeUsers = $null
        FlowsCollection = 'NotAttempted'; AppsCollection = 'NotAttempted'; ConnectionsCollection = 'NotAttempted'
    })
}
#endregion

#region 5. Dataverse role holders and audit settings (optional elevation)
Write-Section 'Environment role holders'
$envRoleRows = New-Object System.Collections.ArrayList
$elevRows = New-Object System.Collections.ArrayList

function Read-DataverseEnvironment {
    # Reads role holders, users by access mode and audit settings. Throws on access failure.
    param($EnvRow)
    $dv = $EnvRow.InstanceUrl.TrimEnd('/')
    $api = "$dv/api/data/v9.2"
    $rows = New-Object System.Collections.ArrayList
    $filter = ($DataverseRoles | ForEach-Object { "name eq '$_'" }) -join ' or '
    $roles = Get-PpPaged -Uri "$api/roles?`$select=name,roleid,_businessunitid_value&`$filter=$filter" -Resource $dv
    foreach ($r in $roles) {
        $users = Get-PpPaged -Uri "$api/roles($($r.roleid))/systemuserroles_association?`$select=fullname,domainname,azureactivedirectoryobjectid,isdisabled,accessmode,applicationid" -Resource $dv
        foreach ($u in $users) {
            $isApp = [bool](Get-P $u 'applicationid')
            if (-not $isApp) { Register-Person (Get-P $u 'azureactivedirectoryobjectid') $u.domainname $u.fullname }
            $null = $rows.Add([pscustomobject]@{
                EnvironmentId = $EnvRow.EnvironmentId; Environment = $EnvRow.DisplayName; EnvironmentType = $EnvRow.Type; IsDefault = $EnvRow.IsDefault
                RoleName = $r.name; Source = 'Dataverse'; AssignedVia = 'Direct'; TeamName = $null; TeamType = $null
                PrincipalType = $(if ($isApp) { 'Application user' } else { 'User' })
                UserId = Get-P $u 'azureactivedirectoryobjectid'; UserPrincipalName = $u.domainname; DisplayName = $u.fullname
                ApplicationId = Get-P $u 'applicationid'; AccessMode = Get-P $u 'accessmode'; Disabled = [bool](Get-P $u 'isdisabled')
            })
        }
        $teams = Get-PpPaged -Uri "$api/roles($($r.roleid))/teamroles_association?`$select=name,teamid,teamtype,azureactivedirectoryobjectid" -Resource $dv
        foreach ($t in $teams) {
            $ttype = switch ([int](Get-P $t 'teamtype')) { 0 { 'Owner' } 1 { 'Access' } 2 { 'Entra security group' } 3 { 'Entra Microsoft 365 group' } default { 'Other' } }
            $members = @()
            $aad = Get-P $t 'azureactivedirectoryobjectid'
            if ($aad -and $ttype -like 'Entra*') {
                $members = @(Get-GroupUsers -GroupId $aad | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Upn = $_.Upn; Name = $_.Name; Disabled = $false } })
            }
            else {
                $tm = Get-PpPaged -Uri "$api/teams($($t.teamid))/teammembership_association?`$select=fullname,domainname,azureactivedirectoryobjectid,isdisabled,applicationid" -Resource $dv
                $members = @($tm | Where-Object { -not (Get-P $_ 'applicationid') } | ForEach-Object { [pscustomobject]@{ Id = (Get-P $_ 'azureactivedirectoryobjectid'); Upn = $_.domainname; Name = $_.fullname; Disabled = [bool](Get-P $_ 'isdisabled') } })
            }
            foreach ($m in $members) {
                Register-Person $m.Id $m.Upn $m.Name
                $null = $rows.Add([pscustomobject]@{
                    EnvironmentId = $EnvRow.EnvironmentId; Environment = $EnvRow.DisplayName; EnvironmentType = $EnvRow.Type; IsDefault = $EnvRow.IsDefault
                    RoleName = $r.name; Source = 'Dataverse'; AssignedVia = 'Team'; TeamName = $t.name; TeamType = $ttype
                    PrincipalType = 'User'; UserId = $m.Id; UserPrincipalName = $m.Upn; DisplayName = $m.Name
                    ApplicationId = $null; AccessMode = $null; Disabled = $m.Disabled
                })
            }
        }
    }
    try {
        $o = @(Get-PpPaged -Uri "$api/organizations?`$select=isauditenabled,isuseraccessauditenabled,auditretentionperiodv2" -Resource $dv) | Select-Object -First 1
        $EnvRow.AuditEnabled = [bool](Get-P $o 'isauditenabled')
        $EnvRow.UserAccessAuditEnabled = [bool](Get-P $o 'isuseraccessauditenabled')
        $EnvRow.AuditRetentionDays = Get-P $o 'auditretentionperiodv2'
    }
    catch { }
    try {
        $all = Get-PpPaged -Uri "$api/systemusers?`$select=accessmode&`$filter=isdisabled eq false and applicationid eq null" -Resource $dv -ExtraHeaders @{ Prefer = 'odata.maxpagesize=5000' }
        $EnvRow.DataverseUsers = $all.Count
        $EnvRow.AdministrativeModeUsers = @($all | Where-Object { [int](Get-P $_ 'accessmode') -eq 1 }).Count
    }
    catch { }
    return , $rows
}

function Invoke-SelfElevate {
    param($EnvRow)
    $uri = "https://api.powerplatform.com/usermanagement/environments/$($EnvRow.EnvironmentId)/user/applyAdminRole?api-version=2022-03-01-preview"
    $null = Invoke-PpRequest -Uri $uri -Resource $ResPpApi -Method POST
}

function Remove-SelfElevation {
    # Removes System Administrator from the run account in an environment where this run added it.
    param($EnvRow)
    $dv = $EnvRow.InstanceUrl.TrimEnd('/')
    $api = "$dv/api/data/v9.2"
    $who = Invoke-PpRequest -Uri "$api/WhoAmI" -Resource $dv
    $uid = Get-P $who 'UserId'
    $roles = Get-PpPaged -Uri "$api/systemusers($uid)/systemuserroles_association?`$select=roleid,name" -Resource $dv
    foreach ($r in @($roles | Where-Object { $_.name -eq 'System Administrator' })) {
        $null = Invoke-PpRequest -Uri "$api/systemusers($uid)/systemuserroles_association($($r.roleid))/`$ref" -Resource $dv -Method DELETE
    }
}

$needElevation = New-Object System.Collections.ArrayList
foreach ($envRow in $envRows) {
    if ($envRow.HasDataverse) {
        if ($SkipDataverse) { $envRow.DataverseAccess = 'Skipped'; continue }
        try {
            $rows = Read-DataverseEnvironment -EnvRow $envRow
            foreach ($r in $rows) { $null = $envRoleRows.Add($r) }
            $envRow.DataverseAccess = 'OK'
            Add-RunLog 'Dataverse' $envRow.DisplayName 'OK' "$($rows.Count) role holder row(s)"
        }
        catch {
            $code = Get-StatusCode $_
            if ($code -in 401, 403) { $envRow.DataverseAccess = 'NoDataverseAccess'; $null = $needElevation.Add($envRow) } else { $envRow.DataverseAccess = 'Failed' }
            Add-RunLog 'Dataverse' $envRow.DisplayName 'Warning' $_.Exception.Message
        }
    }
    else {
        try {
            $ras = Get-PpPaged -Uri "$BapBase/scopes/admin/environments/$($envRow.EnvironmentId)/roleAssignments?api-version=2016-11-01" -Resource $ResBap
            foreach ($ra in $ras) {
                $p = Get-P $ra 'properties'
                $pr = Get-P $p 'principal'
                $ptype = Get-P $pr 'type'
                $role = Get-PPath $p 'roleDefinition.name'
                $base = @{ EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type; IsDefault = $envRow.IsDefault; RoleName = $role; Source = 'Environment'; ApplicationId = $null; AccessMode = $null; Disabled = $false }
                if ($ptype -eq 'Group') {
                    foreach ($u in (Get-GroupUsers -GroupId $pr.id)) {
                        Register-Person $u.Id $u.Upn $u.Name
                        $row = $base.Clone(); $row += @{ AssignedVia = 'Group'; TeamName = (Get-P $pr 'displayName'); TeamType = 'Entra group'; PrincipalType = 'User'; UserId = $u.Id; UserPrincipalName = $u.Upn; DisplayName = $u.Name }
                        $null = $envRoleRows.Add([pscustomobject]$row)
                    }
                }
                elseif ($ptype -eq 'Tenant') {
                    $row = $base.Clone(); $row += @{ AssignedVia = 'Everyone in tenant'; TeamName = $null; TeamType = $null; PrincipalType = 'Tenant'; UserId = $null; UserPrincipalName = '(everyone)'; DisplayName = '(everyone)' }
                    $null = $envRoleRows.Add([pscustomobject]$row)
                }
                else {
                    Register-Person (Get-P $pr 'id') (Get-P $pr 'email') (Get-P $pr 'displayName')
                    $row = $base.Clone(); $row += @{ AssignedVia = 'Direct'; TeamName = $null; TeamType = $null; PrincipalType = $ptype; UserId = (Get-P $pr 'id'); UserPrincipalName = (Get-P $pr 'email'); DisplayName = (Get-P $pr 'displayName') }
                    $null = $envRoleRows.Add([pscustomobject]$row)
                }
            }
            $envRow.DataverseAccess = 'NotApplicable'
            Add-RunLog 'EnvironmentRoles' $envRow.DisplayName 'OK' "$($ras.Count) assignment(s)"
        }
        catch { $envRow.DataverseAccess = 'Failed'; Add-RunLog 'EnvironmentRoles' $envRow.DisplayName 'Warning' $_.Exception.Message }
    }
}

if ($needElevation.Count -gt 0) {
    if ($ElevateForAudit) {
        $go = $true
        if (-not $Unattended) {
            Write-Host ''
            Write-Host "$($needElevation.Count) environment(s) could not be read. -ElevateForAudit will add $runAccount as System Administrator in each," -ForegroundColor Yellow
            Write-Host 'read them, and remove the role again at the end of this run. Each elevation is logged by Microsoft Purview.' -ForegroundColor Yellow
            $go = ((Read-Host 'Continue? (Y/N)') -match '^(?i)y')
        }
        if ($go) {
            foreach ($envRow in $needElevation) {
                $rec = [pscustomobject]@{ Environment = $envRow.DisplayName; EnvironmentId = $envRow.EnvironmentId; Account = $runAccount; Elevated = $null; ElevationResult = $null; Removed = $null; RemovalResult = $null }
                try {
                    Invoke-SelfElevate -EnvRow $envRow
                    $rec.Elevated = (Get-Date).ToString('s'); $rec.ElevationResult = 'OK'; $envRow.Elevated = $true
                    $read = $false
                    for ($try = 1; $try -le 4 -and -not $read; $try++) {
                        Start-Sleep -Seconds (10 * $try)
                        try {
                            $rows = Read-DataverseEnvironment -EnvRow $envRow
                            foreach ($r in $rows) { $null = $envRoleRows.Add($r) }
                            $envRow.DataverseAccess = 'OK (elevated)'
                            $read = $true
                            Add-RunLog 'Dataverse' $envRow.DisplayName 'OK' 'read after elevation'
                        }
                        catch { if ($try -eq 4) { Add-RunLog 'Dataverse' $envRow.DisplayName 'Warning' "elevated but still not readable: $($_.Exception.Message)" } }
                    }
                }
                catch {
                    $rec.ElevationResult = $_.Exception.Message
                    Add-RunLog 'Elevate' $envRow.DisplayName 'Warning' "$($_.Exception.Message). Self-elevate in the Power Platform admin center (Environment > Membership > Add me) and re-run, or accept the gap."
                }
                $null = $elevRows.Add($rec)
            }
        }
    }
    else {
        Write-Host "$($needElevation.Count) environment(s) could not be read (no Dataverse access). They are reported as a coverage gap. Re-run with -ElevateForAudit to read them." -ForegroundColor Yellow
    }
}
#endregion

#region 6. flows, apps, connections, inventory
$flowRows = New-Object System.Collections.ArrayList
$appRows = New-Object System.Collections.ArrayList
$connRows = New-Object System.Collections.ArrayList
$invRows = New-Object System.Collections.ArrayList

function Add-FlowRow {
    param($EnvRow, [string]$Id, [string]$Name, [string]$State, [string]$OwnerId, [string]$OwnerUpn, [string]$OwnerName, [string]$OwnerType, [bool]$OwnerDisabled, $Created, $Modified, $Managed, [string[]]$Connectors, [string]$Trigger, [string]$Source)
    if ($OwnerId -and $OwnerType -eq 'User') { Register-Person $OwnerId $OwnerUpn $OwnerName }
    $flags = Get-ConnectorFlags -Names $Connectors
    $row = [ordered]@{
        EnvironmentId = $EnvRow.EnvironmentId; Environment = $EnvRow.DisplayName; EnvironmentType = $EnvRow.Type
        FlowId = $Id; FlowName = $Name; State = $State
        OwnerType = $OwnerType; OwnerId = $OwnerId; OwnerUserPrincipalName = $OwnerUpn; OwnerDisplayName = $OwnerName; OwnerDisabled = $OwnerDisabled
        CreatedOn = $Created; ModifiedOn = $Modified; Managed = $Managed; Trigger = $Trigger
    }
    foreach ($k in $flags.Keys) { $row[$k] = $flags[$k] }
    $row['Source'] = $Source
    $null = $flowRows.Add([pscustomobject]$row)
}

if (-not $SkipResources -and $ppAvailable) {
    Write-Section 'Cloud flows'
    foreach ($envRow in $envRows) {
        $done = $false
        try {
            $fl = Get-PpPaged -Uri "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/$($envRow.EnvironmentId)/v2/flows?api-version=2016-11-01" -Resource $ResFlow
            foreach ($f in $fl) {
                $p = Get-P $f 'properties'
                $creator = Get-P $p 'creator'
                $oid = Get-P $creator 'userId'; if (-not $oid) { $oid = Get-P $creator 'objectId' }
                $conns = Get-ConnectorNames (Get-P $p 'connectionReferences')
                $state = switch ([string](Get-P $p 'state')) { 'Started' { 'On' } 'Stopped' { 'Off' } 'Suspended' { 'Suspended' } default { [string](Get-P $p 'state') } }
                $upn = $null; $nm = $null
                if ($oid) { $u = Resolve-User -UserId $oid; if ($u) { $upn = $u.userPrincipalName; $nm = $u.displayName } }
                $trig = $null
                $tr = Get-PPath $p 'definitionSummary.triggers'
                if ($tr) { $trig = (@($tr | ForEach-Object { (@((Get-P $_ 'type'), (Get-PPath $_ 'api.name')) | Where-Object { $_ }) -join ':' }) -join '; ') }
                Add-FlowRow $envRow $f.name (Get-P $p 'displayName') $state $oid $upn $nm 'User' $false (Get-P $p 'createdTime') (Get-P $p 'lastModifiedTime') $null $conns $trig 'FlowAdminApi'
            }
            $envRow.FlowsCollection = 'OK'; $done = $true
            Add-RunLog 'Flows' $envRow.DisplayName 'OK' "$($fl.Count) flow(s)"
        }
        catch { Add-RunLog 'Flows' $envRow.DisplayName 'Warning' "flow admin API: $($_.Exception.Message)" }
        if (-not $done -and $envRow.HasDataverse -and $envRow.DataverseAccess -like 'OK*') {
            $dv = $envRow.InstanceUrl.TrimEnd('/')
            try {
                $wf = Get-PpPaged -Uri "$dv/api/data/v9.2/workflows?`$select=name,workflowid,statecode,createdon,modifiedon,ismanaged,clientdata&`$filter=category eq 5&`$expand=owninguser(`$select=azureactivedirectoryobjectid,domainname,fullname,isdisabled),owningteam(`$select=name)" -Resource $dv -ExtraHeaders @{ Prefer = 'odata.maxpagesize=250' }
                foreach ($w in $wf) {
                    $conns = @()
                    $cd = Get-P $w 'clientdata'
                    if ($cd) { try { $conns = Get-ConnectorNames (Get-PPath ($cd | ConvertFrom-Json) 'properties.connectionReferences') } catch { } }
                    $ou = Get-P $w 'owninguser'; $ot = Get-P $w 'owningteam'
                    $state = switch ([int](Get-P $w 'statecode')) { 0 { 'Off' } 1 { 'On' } 2 { 'Suspended' } default { [string](Get-P $w 'statecode') } }
                    if ($ou) { Add-FlowRow $envRow $w.workflowid $w.name $state (Get-P $ou 'azureactivedirectoryobjectid') $ou.domainname $ou.fullname 'User' ([bool](Get-P $ou 'isdisabled')) $w.createdon $w.modifiedon (Get-P $w 'ismanaged') $conns $null 'Dataverse' }
                    else { Add-FlowRow $envRow $w.workflowid $w.name $state $null $null (Get-P $ot 'name') 'Team' $false $w.createdon $w.modifiedon (Get-P $w 'ismanaged') $conns $null 'Dataverse' }
                }
                $envRow.FlowsCollection = 'OK'
                Add-RunLog 'Flows' $envRow.DisplayName 'OK' "$($wf.Count) flow(s) from Dataverse"
            }
            catch { $envRow.FlowsCollection = 'Failed'; Add-RunLog 'Flows' $envRow.DisplayName 'Warning' "Dataverse: $($_.Exception.Message)" }
        }
        elseif (-not $done) { $envRow.FlowsCollection = 'Failed' }
    }

    Write-Section 'Canvas apps and connections'
    foreach ($envRow in $envRows) {
        try {
            $apps = Get-PpPaged -Uri "https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/$($envRow.EnvironmentId)/apps?api-version=2016-11-01" -Resource $ResBap
            foreach ($a in $apps) {
                $p = Get-P $a 'properties'
                $o = Get-P $p 'owner'
                $oid = Get-P $o 'id'
                Register-Person $oid (Get-P $o 'email') (Get-P $o 'displayName')
                $flags = Get-ConnectorFlags -Names (Get-ConnectorNames (Get-P $p 'connectionReferences'))
                $row = [ordered]@{
                    EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type
                    AppId = $a.name; AppName = Get-P $p 'displayName'; AppType = Get-P $p 'appType'
                    OwnerId = $oid; OwnerUserPrincipalName = Get-P $o 'email'; OwnerDisplayName = Get-P $o 'displayName'
                    CreatedTime = Get-P $p 'createdTime'; LastModifiedTime = Get-P $p 'lastModifiedTime'
                    SharedUsers = Get-P $p 'sharedUsersCount'; SharedGroups = Get-P $p 'sharedGroupsCount'
                }
                foreach ($k in $flags.Keys) { $row[$k] = $flags[$k] }
                $null = $appRows.Add([pscustomobject]$row)
            }
            $envRow.AppsCollection = 'OK'
            Add-RunLog 'Apps' $envRow.DisplayName 'OK' "$($apps.Count) app(s)"
        }
        catch { $envRow.AppsCollection = 'Failed'; Add-RunLog 'Apps' $envRow.DisplayName 'Warning' $_.Exception.Message }
        try {
            $conns = Get-PpPaged -Uri "https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/$($envRow.EnvironmentId)/connections?api-version=2016-11-01" -Resource $ResBap
            foreach ($c in $conns) {
                $p = Get-P $c 'properties'
                $cb = Get-P $p 'createdBy'
                $oid = Get-P $cb 'id'
                if ((Get-P $cb 'type') -ne 'ServicePrincipal') { Register-Person $oid (Get-P $cb 'email') (Get-P $cb 'displayName') }
                $api = ([string](Get-P $p 'apiId') -split '/')[-1].ToLowerInvariant()
                $statuses = @(Get-P $p 'statuses' | ForEach-Object { Get-P $_ 'status' })
                $null = $connRows.Add([pscustomobject]@{
                    EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type
                    ConnectionId = $c.name; Connector = $api; DisplayName = Get-P $p 'displayName'
                    OwnerId = $oid; OwnerUserPrincipalName = Get-P $cb 'email'; OwnerDisplayName = Get-P $cb 'displayName'; OwnerType = Get-P $cb 'type'
                    CreatedTime = Get-P $p 'createdTime'; LastModifiedTime = Get-P $p 'lastModifiedTime'
                    Status = ($statuses -join '; ')
                    IsAdminConnector = ($api -in $AdminConnectors); IsDataverse = ($api -in $DataverseConnectors); IsPrivilegedConnector = ($api -in $PrivilegedConnectors)
                })
            }
            $envRow.ConnectionsCollection = 'OK'
            Add-RunLog 'Connections' $envRow.DisplayName 'OK' "$($conns.Count) connection(s)"
        }
        catch { $envRow.ConnectionsCollection = 'Failed'; Add-RunLog 'Connections' $envRow.DisplayName 'Warning' $_.Exception.Message }
    }

    Write-Section 'Power Platform inventory (agents, agent flows, model-driven apps, Power Pages)'
    try {
        $types = @('microsoft.copilotstudio/agents', 'microsoft.powerautomate/agentflows', 'microsoft.powerautomate/m365agentflows', 'microsoft.powerapps/modeldrivenapps', 'microsoft.powerapps/codeapps', 'microsoft.powerapps/apps', 'microsoft.powerpages/sites')
        $envNames = @{}; foreach ($e in $envRows) { $envNames[[string]$e.EnvironmentId] = $e }
        $skip = $null
        do {
            $body = @{ TableName = 'PowerPlatformResources'; Clauses = @(@{ '$type' = 'where'; FieldName = 'type'; Operator = 'in~'; Values = $types }); Options = @{ Top = 1000 } }
            if ($skip) { $body.Options.SkipToken = $skip }
            $r = Invoke-PpRequest -Uri 'https://api.powerplatform.com/resourcequery/resources/query?api-version=2024-10-01' -Resource $ResPpApi -Method POST -Body ($body | ConvertTo-Json -Depth 8)
            foreach ($d in @(Get-P $r 'data')) {
                if (-not $d) { continue }
                $p = Get-P $d 'properties'
                $owner = Get-P $p 'ownerId'; if (-not $owner) { $owner = Get-P $p 'createdBy' }
                Register-Person $owner $null $null
                $eid = [string](Get-P $p 'environmentId')
                $flags = Get-ConnectorFlags -Names (Get-ConnectorNames (Get-P $p 'powerPlatformConnectors'))
                $row = [ordered]@{
                    ResourceType = ([string](Get-P $d 'type') -split '/')[-1]; ResourceId = Get-P $d 'name'; ResourceName = Get-P $p 'displayName'
                    EnvironmentId = $eid; Environment = $(if ($envNames.ContainsKey($eid)) { $envNames[$eid].DisplayName } else { $null })
                    EnvironmentType = $(if ($envNames.ContainsKey($eid)) { $envNames[$eid].Type } else { $null })
                    OwnerId = $owner; CreatedAt = Get-P $p 'createdAt'; LastModifiedAt = Get-P $p 'lastModifiedAt'
                    AnonymousAccess = Get-P $p 'anonymousAccessAllowed'; SiteVisibility = Get-P $p 'siteVisibility'
                }
                foreach ($k in $flags.Keys) { $row[$k] = $flags[$k] }
                $null = $invRows.Add([pscustomobject]$row)
            }
            $skip = Get-P $r 'skipToken'
        } while ($skip)
        Add-RunLog 'Inventory' 'tenant' 'OK' "$($invRows.Count) resource(s)"
    }
    catch { Add-RunLog 'Inventory' 'tenant' 'Warning' "Power Platform inventory API: $($_.Exception.Message). Agents, agent flows, model-driven apps and Pages sites are not in this run." }
}
#endregion

#region 7. Power Platform RBAC, management apps, tenant settings, DLP
Write-Section 'Tenant guardrails'
$ppRbacRows = New-Object System.Collections.ArrayList
try {
    $ras = Get-PpPaged -Uri 'https://api.powerplatform.com/authorization/roleAssignments?api-version=2022-03-01-preview' -Resource $ResPpApi
    foreach ($ra in $ras) {
        $prId = [string](Get-P $ra 'principalObjectId'); $ptype = Get-P $ra 'principalType'
        if ($ptype -eq 'User') { Register-Person $prId $null $null }
        $null = $ppRbacRows.Add([pscustomobject]@{ RoleDefinitionId = Get-P $ra 'roleDefinitionId'; RoleName = Get-P $ra 'roleDefinitionName'; Scope = Get-P $ra 'scope'; PrincipalType = $ptype; PrincipalId = $prId; CreatedOn = Get-P $ra 'createdOn' })
    }
    Add-RunLog 'PowerPlatformRbac' 'tenant' 'OK' "$($ppRbacRows.Count) assignment(s)"
}
catch { Add-RunLog 'PowerPlatformRbac' 'tenant' 'Warning' $_.Exception.Message }

$adminAppRows = New-Object System.Collections.ArrayList
$tenantSettings = $null
$dlpRows = New-Object System.Collections.ArrayList
if ($ppAvailable) {
    try {
        $apps = Get-PpPaged -Uri "$BapBase/adminApplications?api-version=2020-10-01" -Resource $ResBap
        foreach ($a in $apps) {
            $appId = [string](Get-P $a 'applicationId')
            $sp = $null
            try { $sp = (Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,displayName,appOwnerOrganizationId,accountEnabled").value | Select-Object -First 1 } catch { }
            $null = $adminAppRows.Add([pscustomobject]@{ ApplicationId = $appId; DisplayName = Get-P $sp 'displayName'; ServicePrincipalId = Get-P $sp 'id'; OwnerTenant = Get-P $sp 'appOwnerOrganizationId'; Enabled = Get-P $sp 'accountEnabled' })
        }
        Add-RunLog 'ManagementApps' 'tenant' 'OK' "$($adminAppRows.Count) registered"
    }
    catch { Add-RunLog 'ManagementApps' 'tenant' 'Warning' $_.Exception.Message }
    try {
        $tenantSettings = Invoke-PpRequest -Uri "$BapBase/listTenantSettings?api-version=2020-10-01" -Resource $ResBap -Method POST -Body '{}'
        Add-RunLog 'TenantSettings' 'tenant' 'OK' ''
    }
    catch { Add-RunLog 'TenantSettings' 'tenant' 'Warning' $_.Exception.Message }
    try {
        $pol = Get-PpPaged -Uri 'https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v2/policies' -Resource $ResBap
        foreach ($d in $pol) {
            $groups = @{}
            foreach ($cg in @(Get-P $d 'connectorGroups')) { if ($cg) { $groups[[string](Get-P $cg 'classification')] = @(Get-P $cg 'connectors' | ForEach-Object { ([string](Get-P $_ 'id') -split '/')[-1].ToLowerInvariant() }) } }
            $default = [string](Get-P $d 'defaultConnectorsClassification')
            $classOf = { param($c) foreach ($k in $groups.Keys) { if ($groups[$k] -contains $c) { return $k } }; return $default }
            $null = $dlpRows.Add([pscustomobject]@{
                PolicyName = Get-P $d 'displayName'; Scope = Get-P $d 'environmentType'
                Environments = (@(Get-P $d 'environments') | ForEach-Object { Get-P $_ 'name' }) -join '; '
                DefaultGroup = $default
                AdminConnectors = (@($AdminConnectors | ForEach-Object { "$($_ -replace '^shared_', '')=$(& $classOf $_)" }) -join '; ')
                HttpConnector = & $classOf 'shared_webcontents'
                BlockedCount = @($groups['Blocked']).Count; BusinessCount = @($groups['Confidential']).Count; NonBusinessCount = @($groups['General']).Count
                CreatedBy = Get-PPath $d 'createdBy.displayName'; LastModified = Get-P $d 'lastModifiedTime'
            })
        }
        Add-RunLog 'DlpPolicies' 'tenant' 'OK' "$($dlpRows.Count) polic(ies)"
    }
    catch { Add-RunLog 'DlpPolicies' 'tenant' 'Warning' $_.Exception.Message }
}
#endregion

#region 8. identities
Write-Section 'Identities'
$cladUsers = @{}
foreach ($pfx in $cladPrefixes) {
    try {
        foreach ($u in (Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/users?`$filter=startswith(userPrincipalName,'$pfx')&`$select=id,userPrincipalName,displayName,givenName,surname,accountEnabled&`$top=999")) { $cladUsers[$u.id] = $u }
    }
    catch { Add-RunLog 'CladAccounts' $pfx 'Warning' $_.Exception.Message }
}
try { foreach ($u in (Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/users?`$filter=startswith(displayName,'(Cloud Admin)')&`$select=id,userPrincipalName,displayName,givenName,surname,accountEnabled&`$top=999")) { $cladUsers[$u.id] = $u } } catch { }
$cladRows = @($cladUsers.Values | ForEach-Object { [pscustomobject]@{ UserId = $_.id; UserPrincipalName = $_.userPrincipalName; DisplayName = $_.displayName; GivenName = $_.givenName; Surname = $_.surname; AccountEnabled = $_.accountEnabled } })
Add-RunLog 'CladAccounts' 'tenant' 'OK' "$($cladRows.Count) CLAD account(s)"

$skuMap = @{}
try { foreach ($s in (Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber')) { $skuMap[[string]$s.skuId] = $s.skuPartNumber } }
catch { Add-RunLog 'Skus' 'tenant' 'Warning' $_.Exception.Message }

$premiumPattern = '(?i)POWERAPPS_PER|POWERAPPS_P[12]|POWERAPPS_DEV|FLOW_PER|FLOW_P[12]|POWERAUTOMATE|POWER_PAGES|DYN365|D365|CRMSTANDARD|CRMPLAN|PROJECT_P|POWERAPPS_INDIVIDUAL'
$officePattern = '(?i)ENTERPRISEPACK|ENTERPRISEPREMIUM|SPE_E|SPE_F|O365_|M365_|STANDARDPACK|EXCHANGESTANDARD|EXCHANGEENTERPRISE|SPB|OFFICESUBSCRIPTION'
$phishTypes = @('#microsoft.graph.fido2AuthenticationMethod', '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod', '#microsoft.graph.platformCredentialAuthenticationMethod', '#microsoft.graph.x509CertificateAuthenticationMethod')
$signInAvailable = $true
$methodsAvailable = $true
$peopleRows = New-Object System.Collections.ArrayList
$memberRows = New-Object System.Collections.ArrayList
$total = $script:People.Count; $i = 0
foreach ($id in @($script:People.Keys)) {
    $i++
    Write-Progress -Activity 'Resolving people' -Status "$i of $total" -PercentComplete ([int](100 * $i / [Math]::Max(1, $total)))
    $seed = $script:People[$id]
    $sel = 'id,userPrincipalName,displayName,givenName,surname,accountEnabled,userType,assignedLicenses,createdDateTime,onPremisesSyncEnabled,jobTitle,department,mail'
    $u = $null
    if ($signInAvailable) {
        try { $u = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/${id}?`$select=$sel,signInActivity" }
        catch { if ($_.Exception.Message -match '403|Forbidden|signInActivity|Premium') { $signInAvailable = $false } }
    }
    if (-not $u) {
        try { $u = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/${id}?`$select=$sel" }
        catch { Add-RunLog 'People' $id 'Warning' "Not resolved in Entra (deleted user or service principal): $($_.Exception.Message)" }
    }
    $skus = @()
    if ($u) { $skus = @(Get-P $u 'assignedLicenses' | ForEach-Object { $k = [string](Get-P $_ 'skuId'); if ($skuMap.ContainsKey($k)) { $skuMap[$k] } else { $k } }) }
    $methods = @(); $phish = $null
    if ($u -and $methodsAvailable) {
        try {
            $ms = Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/users/$id/authentication/methods"
            $methods = @($ms | ForEach-Object { ([string](Get-P $_ '@odata.type')) -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '' } | Sort-Object -Unique)
            $phish = [bool](@($ms | Where-Object { (Get-P $_ '@odata.type') -in $phishTypes }).Count)
        }
        catch { if ($_.Exception.Message -match '403|Forbidden') { $methodsAvailable = $false; Add-RunLog 'AuthMethods' 'tenant' 'Warning' 'Sign-in methods not readable (needs UserAuthenticationMethod.Read.All and Global Reader or an authentication admin role).' } }
    }
    if ($u) {
        try { foreach ($g in (Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/users/$id/transitiveMemberOf/microsoft.graph.group?`$select=id&`$top=999")) { $null = $memberRows.Add([pscustomobject]@{ UserId = $id; GroupId = $g.id }) } }
        catch { }
    }
    $upn = $(if ($u) { $u.userPrincipalName } else { $seed.Upn })
    $null = $peopleRows.Add([pscustomobject]@{
        UserId = $id; UserPrincipalName = $upn; DisplayName = $(if ($u) { $u.displayName } else { $seed.Name })
        GivenName = Get-P $u 'givenName'; Surname = Get-P $u 'surname'; JobTitle = Get-P $u 'jobTitle'; Department = Get-P $u 'department'
        Found = [bool]$u; AccountEnabled = $(if ($u) { [bool]$u.accountEnabled } else { $null }); UserType = Get-P $u 'userType'
        SyncedFromOnPrem = [bool](Get-P $u 'onPremisesSyncEnabled'); HasMailbox = [bool](Get-P $u 'mail')
        Licences = ($skus -join '; ')
        PremiumPowerPlatformLicence = [bool](@($skus | Where-Object { $_ -match $premiumPattern }).Count)
        OfficeLicence = [bool](@($skus | Where-Object { $_ -match $officePattern }).Count)
        AuthMethods = ($methods -join '; '); PhishingResistant = $phish
        LastSignIn = Get-PPath $u 'signInActivity.lastSuccessfulSignInDateTime'; Created = Get-P $u 'createdDateTime'
    })
}
Write-Progress -Activity 'Resolving people' -Completed
Add-RunLog 'People' 'tenant' 'OK' "$($peopleRows.Count) people"
#endregion

#region 9. remove audit elevation
foreach ($rec in $elevRows) {
    if ($rec.ElevationResult -ne 'OK') { continue }
    $envRow = @($envRows | Where-Object EnvironmentId -eq $rec.EnvironmentId) | Select-Object -First 1
    try {
        Remove-SelfElevation -EnvRow $envRow
        $rec.Removed = (Get-Date).ToString('s'); $rec.RemovalResult = 'OK'
        Add-RunLog 'RemoveElevation' $envRow.DisplayName 'OK' 'System Administrator removed from the run account'
    }
    catch {
        $rec.RemovalResult = $_.Exception.Message
        Add-RunLog 'RemoveElevation' $envRow.DisplayName 'Failed' "REMOVE MANUALLY: $runAccount is still System Administrator here. $($_.Exception.Message)"
    }
}
#endregion

#region output
Write-Section 'Writing evidence'
$exports = [ordered]@{
    'pp-tenant-roles.csv' = $roleRows; 'pp-role-settings.csv' = $settingRows; 'pp-activations.csv' = $activationRows
    'pp-conditional-access.csv' = $caRows; 'pp-environments.csv' = $envRows; 'pp-environment-roles.csv' = $envRoleRows
    'pp-flows.csv' = $flowRows; 'pp-apps.csv' = $appRows; 'pp-connections.csv' = $connRows; 'pp-inventory.csv' = $invRows
    'pp-rbac-assignments.csv' = $ppRbacRows; 'pp-management-apps.csv' = $adminAppRows; 'pp-dlp-policies.csv' = $dlpRows
    'pp-users.csv' = $peopleRows; 'pp-user-groups.csv' = $memberRows; 'pp-clad-accounts.csv' = $cladRows
    'pp-elevations.csv' = $elevRows; 'pp-collection-log.csv' = $script:Log
}
foreach ($k in $exports.Keys) { Export-PimData -Data @($exports[$k]) -CsvPath (Join-Path $rawFolder $k) }
if ($tenantSettings) { $tenantSettings | ConvertTo-Json -Depth 20 | Out-File (Join-Path $rawFolder 'pp-tenant-settings.json') -Encoding UTF8 }
if ($caRaw) { $caRaw | ConvertTo-Json -Depth 20 | Out-File (Join-Path $rawFolder 'pp-conditional-access.json') -Encoding UTF8 }
if ($authStrengths) { $authStrengths | ConvertTo-Json -Depth 10 | Out-File (Join-Path $rawFolder 'pp-auth-strengths.json') -Encoding UTF8 }
if ($authContexts) { $authContexts | ConvertTo-Json -Depth 10 | Out-File (Join-Path $rawFolder 'pp-auth-contexts.json') -Encoding UTF8 }

$meta = [ordered]@{
    tool = 'PIM-Review Power Platform audit'; version = '2.0'
    tenantId = $script:TenantGuid; tenantName = $tenantName; tenantShortName = $TenantShortName
    verifiedDomains = @($orgInfo.verifiedDomains | ForEach-Object { $_.name })
    runAccount = $runAccount; runAccountRoles = $runRoles; started = $started.ToString('s'); finished = (Get-Date).ToString('s')
    cladPrefixes = $cladPrefixes; skipDataverse = [bool]$SkipDataverse; skipResources = [bool]$SkipResources; elevateForAudit = [bool]$ElevateForAudit
    environmentFilter = $EnvironmentFilter; powerPlatformApiAvailable = $ppAvailable; signInActivityAvailable = $signInAvailable
    authMethodsAvailable = $methodsAvailable; conditionalAccessAvailable = [bool]$caRaw; activationHistoryDays = $ActivationHistoryDays
}
$meta | ConvertTo-Json -Depth 5 | Out-File (Join-Path $rawFolder 'pp-run.json') -Encoding UTF8
Write-Host "Collection finished in $([Math]::Round(((Get-Date) - $started).TotalMinutes, 1)) min." -ForegroundColor Green

$result = [pscustomobject]@{ TenantShortName = $TenantShortName; TenantName = $tenantName; RunFolder = $runFolder; ReportPath = $null; WorkbookPath = $null; Elevations = $elevRows.Count; ElevationsNotRemoved = @($elevRows | Where-Object { $_.ElevationResult -eq 'OK' -and $_.RemovalResult -ne 'OK' }).Count }
if (-not $NoAssessment) {
    $a = & (Join-Path $PSScriptRoot 'Invoke-PowerPlatformAssessment.ps1') -RunFolder $runFolder
    $a = @($a | Where-Object { $_ -and $_.PSObject.Properties['ReportPath'] }) | Select-Object -Last 1
    if ($a) { $result.ReportPath = $a.ReportPath; $result.WorkbookPath = $a.WorkbookPath }
}
$result
#endregion
