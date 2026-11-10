<#
.SYNOPSIS
Power Platform privileged access review for one tenant: who holds the admin roles, who is System Administrator
in each environment, and who owns the flows and apps that could break when admin rights move to CLAD accounts.

.DESCRIPTION
Read-only. Collects:
- Entra roles that reach Power Platform: Power Platform Administrator, Dynamics 365 Administrator,
  Global Administrator, Fabric (Power BI) Administrator, Dynamics 365 Business Central Administrator.
  Eligible and active, direct and through groups (groups expanded, including PIM for Groups eligible members).
- Every Power Platform environment (type, Dataverse, security group, managed environment).
- Dataverse role holders per environment: System Administrator, System Customizer, Environment Maker,
  directly and through teams (Entra group teams expanded). Environments without Dataverse: Environment Admin
  and Environment Maker role assignments.
- Cloud flows and canvas apps with their owner and connectors (Dataverse, admin connectors, HTTP).
- Licences and sign-in activity of every person found.
- Tenant settings and DLP policy summary (best effort).

Then runs Invoke-PowerPlatformAssessment.ps1 over the output to produce the people register (who does what),
flows at risk, findings and an HTML report.

Works in Windows PowerShell 5.1 and PowerShell 7. Needs Microsoft.Graph.Authentication and Az.Accounts.

Sign in with an account that has, in this tenant:
- Global Reader (Graph reads), and
- Power Platform Administrator ACTIVE (activate it in PIM first) to list environments, flows and apps, and
- for Dataverse role holders, read access in each environment's Dataverse (for example System Administrator
  after self-elevation). Without it the environment is listed with CollectionStatus 'NoDataverseAccess' and
  the report shows the gap; nothing is changed to get around it.

.PARAMETER TenantId
Tenant ID or domain.

.PARAMETER TenantShortName
Short name for folder and report names (for example SE).

.PARAMETER OutputFolder
Root output folder. Default: .\Output beside the script.

.PARAMETER UseDeviceCode
Device-code sign-in for Graph and Azure.

.PARAMETER SkipDataverse
Do not query Dataverse (tenant roles, environments, flows and apps only).

.PARAMETER SkipApps
Do not list canvas apps.

.PARAMETER EnvironmentFilter
Only these environments (display name or ID, wildcards allowed).

.EXAMPLE
.\Get-PowerPlatformReview.ps1 -TenantId contoso.onmicrosoft.com -TenantShortName CON
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,
    [string]$TenantShortName,
    [string]$OutputFolder,
    [switch]$UseDeviceCode,
    [switch]$SkipDataverse,
    [switch]$SkipApps,
    [string[]]$EnvironmentFilter,
    [switch]$NoAssessment
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules\PimReview.Common.psm1') -Force -DisableNameChecking

#region settings
$PpRoles = [ordered]@{
    '11648597-926c-4cf3-9c36-bcebb0ba8dcc' = 'Power Platform Administrator'
    '44367163-eba1-44c3-98af-f5787879f96a' = 'Dynamics 365 Administrator'
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'a9ea8996-122f-4c74-9520-8edcd192826c' = 'Fabric Administrator'
    '963797fb-eb3b-4cde-8ce3-5878b3f32a3f' = 'Dynamics 365 Business Central Administrator'
}
$DataverseRoles = @('System Administrator', 'System Customizer', 'Environment Maker')
$ResBap = 'https://service.powerapps.com/'
$ResFlow = 'https://service.flow.microsoft.com/'
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

$script:Tokens = @{}
function Get-PpToken {
    param([string]$Resource)
    $cached = $script:Tokens[$Resource]
    if ($cached -and $cached.Expires -gt (Get-Date).AddMinutes(5)) { return $cached.Token }
    $t = Get-AzAccessToken -ResourceUrl $Resource -TenantId $script:TenantGuid -ErrorAction Stop -WarningAction SilentlyContinue
    $tok = $t.Token
    if ($tok -is [System.Security.SecureString]) {
        $tok = (New-Object System.Net.NetworkCredential('', $tok)).Password
    }
    $exp = (Get-Date).AddMinutes(45)
    try { if ($t.ExpiresOn) { $exp = $t.ExpiresOn.LocalDateTime } } catch { }
    $script:Tokens[$Resource] = @{ Token = $tok; Expires = $exp }
    return $tok
}

function Invoke-PpRequest {
    # GET/POST to a Power Platform or Dataverse endpoint with retry. Returns the parsed body.
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
    # Follows nextLink / @odata.nextLink.
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

function Test-Clad {
    param([string]$Upn)
    if ([string]::IsNullOrWhiteSpace($Upn)) { return $false }
    return ($Upn -match $script:CladPattern)
}

# People cache: every user seen anywhere, resolved once through Graph.
$script:People = @{}
function Register-Person {
    param([string]$Id, [string]$Upn, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Id)) { return }
    $Id = $Id.ToLowerInvariant()
    if (-not $script:People.ContainsKey($Id)) {
        $script:People[$Id] = @{ Id = $Id; Upn = $Upn; Name = $Name }
    }
}

$script:GroupMemberCache = @{}
function Get-GroupUsers {
    # Transitive user members of an Entra group, plus PIM for Groups eligible members (Direct members only for those).
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
    # Connector API names from a flow definition or app connection references.
    param($ConnRefs)
    $names = New-Object System.Collections.Generic.HashSet[string]
    if ($null -eq $ConnRefs) { return @() }
    foreach ($p in $ConnRefs.PSObject.Properties) {
        $v = $p.Value
        $n = Get-P $v 'apiName'
        if (-not $n) { $n = Get-PPath $v 'api.name' }
        if (-not $n) { $id = Get-P $v 'id'; if (-not $id) { $id = Get-P $v 'apiId' }; if ($id) { $n = ($id -split '/')[-1] } }
        if (-not $n) { $n = $p.Name }
        if ($n) { $null = $names.Add(([string]$n).ToLowerInvariant()) }
    }
    return @($names)
}

$AdminConnectors = @('shared_powerplatformforadmins', 'shared_powerplatformadminv2', 'shared_microsoftflowforadmins', 'shared_powerappsforadmins', 'shared_powerappsforappmakers', 'shared_dataverseadmin')
$DataverseConnectors = @('shared_commondataserviceforapps', 'shared_commondataservice', 'shared_dynamicscrmonline')
$HttpConnectors = @('shared_webcontents', 'shared_webcontentsv2', 'shared_http', 'shared_sendmail')
#endregion

#region connect
$started = Get-Date
foreach ($m in 'Microsoft.Graph.Authentication', 'Az.Accounts') {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m is missing. Install-Module $m -Scope CurrentUser" }
}
$cfgPath = Join-Path $PSScriptRoot 'Config\pim-review.config.local.json'
if (-not (Test-Path $cfgPath)) { $cfgPath = Join-Path $PSScriptRoot 'Config\pim-review.config.json' }
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$prefix = Get-P $cfg 'NamingCompliancePrefix'
if (-not $prefix) { $prefix = 'CLAD_' }
$script:CladPattern = '^(?i)' + [regex]::Escape($prefix)

Write-Host ''
Write-Host "Power Platform review: $TenantId" -ForegroundColor Cyan
Write-Host 'Step 1 of 2: sign in to Microsoft Graph.'
$scopes = @('RoleManagement.Read.Directory', 'User.Read.All', 'Group.Read.All', 'Organization.Read.All', 'AuditLog.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
$mgParams = @{ Scopes = $scopes; TenantId = $TenantId; NoWelcome = $true; ErrorAction = 'Stop' }
if ($UseDeviceCode) { $mgParams.UseDeviceCode = $true }
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
Connect-MgGraph @mgParams
$orgInfo = (Invoke-GraphRequestWithRetry -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName').value | Select-Object -First 1
$script:TenantGuid = $orgInfo.id
$tenantName = $orgInfo.displayName
if (-not $TenantShortName) { $TenantShortName = ($tenantName -replace '[^A-Za-z0-9]', '') }

Write-Host 'Step 2 of 2: sign in to Azure (used only to get Power Platform tokens).'
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
Write-Host "Output: $runFolder"
#endregion

#region 1. tenant roles
Write-Host ''
Write-Host 'Entra roles that reach Power Platform' -ForegroundColor Cyan
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

#region 2. environments
Write-Host ''
Write-Host 'Power Platform environments' -ForegroundColor Cyan
$envRows = New-Object System.Collections.ArrayList
$ppAvailable = $true
try {
    $envs = Get-PpPaged -Uri "$BapBase/scopes/admin/environments?api-version=2021-04-01&`$expand=properties.governanceConfiguration" -Resource $ResBap
    Add-RunLog 'Environments' 'tenant' 'OK' "$($envs.Count) environment(s)"
}
catch {
    $ppAvailable = $false
    $envs = @()
    Add-RunLog 'Environments' 'tenant' 'Failed' "$($_.Exception.Message). Is Power Platform Administrator active for $runAccount? Tenant roles are still reported."
}

$sgNames = @{}
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
    $sgName = $null
    if ($sg) {
        if (-not $sgNames.ContainsKey($sg)) { $g = Resolve-Group -GroupId $sg; $sgNames[$sg] = $(if ($g) { $g.displayName } else { '(not found)' }) }
        $sgName = $sgNames[$sg]
    }
    $creator = Get-P $p 'createdBy'
    $null = $envRows.Add([pscustomobject]@{
        EnvironmentId     = $e.name
        DisplayName       = $disp
        Type              = Get-P $p 'environmentSku'
        IsDefault         = [bool](Get-P $p 'isDefault')
        Region            = Get-P $e 'location'
        HasDataverse      = [bool](Get-P $lem 'instanceUrl')
        InstanceUrl       = Get-P $lem 'instanceUrl'
        SecurityGroupId   = $sg
        SecurityGroupName = $sgName
        Managed           = ((Get-PPath $p 'governanceConfiguration.protectionLevel') -eq 'Standard')
        State             = Get-PPath $p 'states.management.id'
        CreatedBy         = $(if ($creator) { (Get-P $creator 'userPrincipalName') + (Get-P $creator 'displayName') } else { $null })
        CreatedTime       = Get-P $p 'createdTime'
        RolesCollection   = 'NotAttempted'
        FlowsCollection   = 'NotAttempted'
        AppsCollection    = 'NotAttempted'
    })
}
#endregion

#region 3. environment role holders
Write-Host ''
Write-Host 'Environment role holders' -ForegroundColor Cyan
$envRoleRows = New-Object System.Collections.ArrayList
foreach ($envRow in $envRows) {
    if ($envRow.HasDataverse) {
        if ($SkipDataverse) { $envRow.RolesCollection = 'Skipped'; continue }
        $dvUrl = $envRow.InstanceUrl.TrimEnd('/')
        $api = "$dvUrl/api/data/v9.2"
        try {
            $filter = ($DataverseRoles | ForEach-Object { "name eq '$_'" }) -join ' or '
            $roles = Get-PpPaged -Uri "$api/roles?`$select=name,roleid,_businessunitid_value&`$filter=$filter" -Resource $dvUrl
            foreach ($r in $roles) {
                $users = Get-PpPaged -Uri "$api/roles($($r.roleid))/systemuserroles_association?`$select=fullname,domainname,azureactivedirectoryobjectid,isdisabled,accessmode,applicationid" -Resource $dvUrl
                foreach ($u in $users) {
                    $isApp = [bool](Get-P $u 'applicationid')
                    if (-not $isApp) { Register-Person (Get-P $u 'azureactivedirectoryobjectid') $u.domainname $u.fullname }
                    $null = $envRoleRows.Add([pscustomobject]@{
                        EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type; IsDefault = $envRow.IsDefault
                        RoleName = $r.name; Source = 'Dataverse'; AssignedVia = 'Direct'; TeamName = $null; TeamType = $null
                        PrincipalType = $(if ($isApp) { 'Application user' } else { 'User' })
                        UserId = Get-P $u 'azureactivedirectoryobjectid'; UserPrincipalName = $u.domainname; DisplayName = $u.fullname
                        ApplicationId = Get-P $u 'applicationid'; AccessMode = Get-P $u 'accessmode'; Disabled = [bool](Get-P $u 'isdisabled')
                    })
                }
                $teams = Get-PpPaged -Uri "$api/roles($($r.roleid))/teamroles_association?`$select=name,teamid,teamtype,azureactivedirectoryobjectid" -Resource $dvUrl
                foreach ($t in $teams) {
                    $ttype = switch ([int](Get-P $t 'teamtype')) { 0 { 'Owner' } 1 { 'Access' } 2 { 'Entra security group' } 3 { 'Entra Microsoft 365 group' } default { 'Other' } }
                    $members = @()
                    $aad = Get-P $t 'azureactivedirectoryobjectid'
                    if ($aad -and $ttype -like 'Entra*') {
                        $members = @(Get-GroupUsers -GroupId $aad | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Upn = $_.Upn; Name = $_.Name; Disabled = $false } })
                    }
                    else {
                        $tm = Get-PpPaged -Uri "$api/teams($($t.teamid))/teammembership_association?`$select=fullname,domainname,azureactivedirectoryobjectid,isdisabled,applicationid" -Resource $dvUrl
                        $members = @($tm | Where-Object { -not (Get-P $_ 'applicationid') } | ForEach-Object { [pscustomobject]@{ Id = (Get-P $_ 'azureactivedirectoryobjectid'); Upn = $_.domainname; Name = $_.fullname; Disabled = [bool](Get-P $_ 'isdisabled') } })
                    }
                    foreach ($m in $members) {
                        Register-Person $m.Id $m.Upn $m.Name
                        $null = $envRoleRows.Add([pscustomobject]@{
                            EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type; IsDefault = $envRow.IsDefault
                            RoleName = $r.name; Source = 'Dataverse'; AssignedVia = 'Team'; TeamName = $t.name; TeamType = $ttype
                            PrincipalType = 'User'; UserId = $m.Id; UserPrincipalName = $m.Upn; DisplayName = $m.Name
                            ApplicationId = $null; AccessMode = $null; Disabled = $m.Disabled
                        })
                    }
                }
            }
            $envRow.RolesCollection = 'OK'
            Add-RunLog 'DataverseRoles' $envRow.DisplayName 'OK' ''
        }
        catch {
            $code = $_.Exception.Data['StatusCode']
            if ($code -in 401, 403) { $envRow.RolesCollection = 'NoDataverseAccess' } else { $envRow.RolesCollection = 'Failed' }
            Add-RunLog 'DataverseRoles' $envRow.DisplayName 'Warning' $_.Exception.Message
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
                if ($ptype -eq 'Group') {
                    foreach ($u in (Get-GroupUsers -GroupId $pr.id)) {
                        Register-Person $u.Id $u.Upn $u.Name
                        $null = $envRoleRows.Add([pscustomobject]@{ EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type; IsDefault = $envRow.IsDefault; RoleName = $role; Source = 'Environment'; AssignedVia = 'Group'; TeamName = (Get-P $pr 'displayName'); TeamType = 'Entra group'; PrincipalType = 'User'; UserId = $u.Id; UserPrincipalName = $u.Upn; DisplayName = $u.Name; ApplicationId = $null; AccessMode = $null; Disabled = $false })
                    }
                }
                elseif ($ptype -eq 'Tenant') {
                    $null = $envRoleRows.Add([pscustomobject]@{ EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type; IsDefault = $envRow.IsDefault; RoleName = $role; Source = 'Environment'; AssignedVia = 'Everyone in tenant'; TeamName = $null; TeamType = $null; PrincipalType = 'Tenant'; UserId = $null; UserPrincipalName = '(everyone)'; DisplayName = '(everyone)'; ApplicationId = $null; AccessMode = $null; Disabled = $false })
                }
                else {
                    Register-Person (Get-P $pr 'id') (Get-P $pr 'email') (Get-P $pr 'displayName')
                    $null = $envRoleRows.Add([pscustomobject]@{ EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type; IsDefault = $envRow.IsDefault; RoleName = $role; Source = 'Environment'; AssignedVia = 'Direct'; TeamName = $null; TeamType = $null; PrincipalType = $ptype; UserId = (Get-P $pr 'id'); UserPrincipalName = (Get-P $pr 'email'); DisplayName = (Get-P $pr 'displayName'); ApplicationId = $null; AccessMode = $null; Disabled = $false })
                }
            }
            $envRow.RolesCollection = 'OK'
            Add-RunLog 'EnvironmentRoles' $envRow.DisplayName 'OK' "$($ras.Count) assignment(s)"
        }
        catch { $envRow.RolesCollection = 'Failed'; Add-RunLog 'EnvironmentRoles' $envRow.DisplayName 'Warning' $_.Exception.Message }
    }
}
#endregion

#region 4. flows
Write-Host ''
Write-Host 'Cloud flows' -ForegroundColor Cyan
$flowRows = New-Object System.Collections.ArrayList
function Add-FlowRow {
    param($EnvRow, [string]$Id, [string]$Name, [string]$State, [string]$OwnerId, [string]$OwnerUpn, [string]$OwnerName, [string]$OwnerType, [bool]$OwnerDisabled, $Created, $Modified, $Managed, [string[]]$Connectors, [string]$Source)
    if ($OwnerId -and $OwnerType -eq 'User') { Register-Person $OwnerId $OwnerUpn $OwnerName }
    $c = @($Connectors | Where-Object { $_ })
    $null = $flowRows.Add([pscustomobject]@{
        EnvironmentId = $EnvRow.EnvironmentId; Environment = $EnvRow.DisplayName; EnvironmentType = $EnvRow.Type
        FlowId = $Id; FlowName = $Name; State = $State
        OwnerType = $OwnerType; OwnerId = $OwnerId; OwnerUserPrincipalName = $OwnerUpn; OwnerDisplayName = $OwnerName; OwnerDisabled = $OwnerDisabled
        CreatedOn = $Created; ModifiedOn = $Modified; Managed = $Managed
        Connectors = ($c -join '; ')
        ConnectorsKnown = ($c.Count -gt 0)
        UsesDataverse = [bool](@($c | Where-Object { $_ -in $DataverseConnectors }).Count)
        UsesAdminConnector = [bool](@($c | Where-Object { $_ -in $AdminConnectors }).Count)
        UsesHttp = [bool](@($c | Where-Object { $_ -in $HttpConnectors }).Count)
        Source = $Source
    })
}

foreach ($envRow in $envRows) {
    $done = $false
    if ($envRow.HasDataverse -and -not $SkipDataverse -and $envRow.RolesCollection -ne 'NoDataverseAccess') {
        $dvUrl = $envRow.InstanceUrl.TrimEnd('/')
        try {
            $wf = Get-PpPaged -Uri "$dvUrl/api/data/v9.2/workflows?`$select=name,workflowid,statecode,createdon,modifiedon,ismanaged,clientdata,_ownerid_value,solutionid&`$filter=category eq 5&`$expand=owninguser(`$select=azureactivedirectoryobjectid,domainname,fullname,isdisabled),owningteam(`$select=name)" -Resource $dvUrl -ExtraHeaders @{ Prefer = 'odata.maxpagesize=250' }
            foreach ($w in $wf) {
                $conns = @()
                $cd = Get-P $w 'clientdata'
                if ($cd) {
                    try { $conns = Get-ConnectorNames (Get-PPath ($cd | ConvertFrom-Json) 'properties.connectionReferences') } catch { }
                }
                $ou = Get-P $w 'owninguser'
                $ot = Get-P $w 'owningteam'
                $state = switch ([int](Get-P $w 'statecode')) { 0 { 'Draft (off)' } 1 { 'On' } 2 { 'Suspended' } default { [string](Get-P $w 'statecode') } }
                if ($ou) { Add-FlowRow $envRow $w.workflowid $w.name $state (Get-P $ou 'azureactivedirectoryobjectid') $ou.domainname $ou.fullname 'User' ([bool](Get-P $ou 'isdisabled')) $w.createdon $w.modifiedon (Get-P $w 'ismanaged') $conns 'Dataverse' }
                else { Add-FlowRow $envRow $w.workflowid $w.name $state $null $null (Get-P $ot 'name') 'Team' $false $w.createdon $w.modifiedon (Get-P $w 'ismanaged') $conns 'Dataverse' }
            }
            $envRow.FlowsCollection = 'OK'; $done = $true
            Add-RunLog 'Flows' $envRow.DisplayName 'OK' "$($wf.Count) flow(s) from Dataverse"
        }
        catch { Add-RunLog 'Flows' $envRow.DisplayName 'Warning' "Dataverse: $($_.Exception.Message); trying the flow admin API" }
    }
    if (-not $done -and $ppAvailable) {
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
                Add-FlowRow $envRow $f.name (Get-P $p 'displayName') $state $oid $upn $nm 'User' $false (Get-P $p 'createdTime') (Get-P $p 'lastModifiedTime') $null $conns 'FlowAdminApi'
            }
            $envRow.FlowsCollection = 'OK'
            Add-RunLog 'Flows' $envRow.DisplayName 'OK' "$($fl.Count) flow(s) from the flow admin API"
        }
        catch { $envRow.FlowsCollection = 'Failed'; Add-RunLog 'Flows' $envRow.DisplayName 'Warning' $_.Exception.Message }
    }
}
#endregion

#region 5. apps
$appRows = New-Object System.Collections.ArrayList
if (-not $SkipApps -and $ppAvailable) {
    Write-Host ''
    Write-Host 'Canvas apps' -ForegroundColor Cyan
    foreach ($envRow in $envRows) {
        try {
            $apps = Get-PpPaged -Uri "https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/$($envRow.EnvironmentId)/apps?api-version=2016-11-01" -Resource $ResBap
            foreach ($a in $apps) {
                $p = Get-P $a 'properties'
                $o = Get-P $p 'owner'
                $oid = Get-P $o 'id'
                Register-Person $oid (Get-P $o 'email') (Get-P $o 'displayName')
                $conns = Get-ConnectorNames (Get-P $p 'connectionReferences')
                $null = $appRows.Add([pscustomobject]@{
                    EnvironmentId = $envRow.EnvironmentId; Environment = $envRow.DisplayName; EnvironmentType = $envRow.Type
                    AppId = $a.name; AppName = Get-P $p 'displayName'; AppType = Get-P $p 'appType'
                    OwnerId = $oid; OwnerUserPrincipalName = Get-P $o 'email'; OwnerDisplayName = Get-P $o 'displayName'
                    CreatedTime = Get-P $p 'createdTime'; LastModifiedTime = Get-P $p 'lastModifiedTime'
                    SharedUsers = Get-P $p 'sharedUsersCount'; SharedGroups = Get-P $p 'sharedGroupsCount'
                    Connectors = ($conns -join '; ')
                    UsesDataverse = [bool](@($conns | Where-Object { $_ -in $DataverseConnectors }).Count)
                    UsesAdminConnector = [bool](@($conns | Where-Object { $_ -in $AdminConnectors }).Count)
                })
            }
            $envRow.AppsCollection = 'OK'
            Add-RunLog 'Apps' $envRow.DisplayName 'OK' "$($apps.Count) app(s)"
        }
        catch { $envRow.AppsCollection = 'Failed'; Add-RunLog 'Apps' $envRow.DisplayName 'Warning' $_.Exception.Message }
    }
}
#endregion

#region 6. tenant settings and DLP (best effort)
$tenantSettings = $null
$dlpRows = New-Object System.Collections.ArrayList
if ($ppAvailable) {
    try {
        $tenantSettings = Invoke-PpRequest -Uri "$BapBase/listTenantSettings?api-version=2020-10-01" -Resource $ResBap -Method POST -Body '{}'
        Add-RunLog 'TenantSettings' 'tenant' 'OK' ''
    }
    catch { Add-RunLog 'TenantSettings' 'tenant' 'Warning' $_.Exception.Message }
    try {
        $pol = Get-PpPaged -Uri 'https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v2/policies' -Resource $ResBap
        foreach ($d in $pol) {
            $null = $dlpRows.Add([pscustomobject]@{
                PolicyName = Get-P $d 'displayName'; Scope = Get-P $d 'environmentType'
                Environments = (@(Get-P $d 'environments') | ForEach-Object { Get-P $_ 'name' }) -join '; '
                DefaultGroup = Get-P $d 'defaultConnectorsClassification'
                CreatedBy = Get-PPath $d 'createdBy.displayName'; LastModified = Get-P $d 'lastModifiedTime'
            })
        }
        Add-RunLog 'DlpPolicies' 'tenant' 'OK' "$($dlpRows.Count) polic(ies)"
    }
    catch { Add-RunLog 'DlpPolicies' 'tenant' 'Warning' $_.Exception.Message }
}
#endregion

#region 7. people
Write-Host ''
Write-Host "Resolving $($script:People.Count) people (licences, sign-in)" -ForegroundColor Cyan
$skuMap = @{}
try {
    foreach ($s in (Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber')) { $skuMap[[string]$s.skuId] = $s.skuPartNumber }
}
catch { Add-RunLog 'Skus' 'tenant' 'Warning' $_.Exception.Message }

$premiumPattern = '(?i)POWERAPPS_PER|POWERAPPS_P[12]|POWERAPPS_DEV|FLOW_PER|FLOW_P[12]|POWERAUTOMATE|POWER_PAGES|DYN365|D365|CRMSTANDARD|CRMPLAN|PROJECT_P|POWERAPPS_INDIVIDUAL|PBI_PREMIUM'
$signInAvailable = $true
$peopleRows = New-Object System.Collections.ArrayList
foreach ($id in $script:People.Keys) {
    $seed = $script:People[$id]
    $u = $null
    if ($signInAvailable) {
        try { $u = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/${id}?`$select=id,userPrincipalName,displayName,accountEnabled,userType,assignedLicenses,signInActivity,createdDateTime" }
        catch { if ($_.Exception.Message -match '403|Forbidden|signInActivity|Premium') { $signInAvailable = $false } }
    }
    if (-not $u) {
        try { $u = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/${id}?`$select=id,userPrincipalName,displayName,accountEnabled,userType,assignedLicenses,createdDateTime" }
        catch { Add-RunLog 'People' $id 'Warning' "Not found in Entra: $($_.Exception.Message)" }
    }
    $skus = @()
    if ($u) { $skus = @(Get-P $u 'assignedLicenses' | ForEach-Object { $k = [string](Get-P $_ 'skuId'); if ($skuMap.ContainsKey($k)) { $skuMap[$k] } else { $k } }) }
    $upn = $(if ($u) { $u.userPrincipalName } else { $seed.Upn })
    $null = $peopleRows.Add([pscustomobject]@{
        UserId            = $id
        UserPrincipalName = $upn
        DisplayName       = $(if ($u) { $u.displayName } else { $seed.Name })
        Found             = [bool]$u
        AccountEnabled    = $(if ($u) { [bool]$u.accountEnabled } else { $null })
        UserType          = $(if ($u) { Get-P $u 'userType' } else { $null })
        IsClad            = Test-Clad $upn
        Licences          = ($skus -join '; ')
        PremiumPowerPlatformLicence = [bool](@($skus | Where-Object { $_ -match $premiumPattern }).Count)
        LastSignIn        = $(if ($u) { Get-PPath $u 'signInActivity.lastSuccessfulSignInDateTime' } else { $null })
        Created           = $(if ($u) { Get-P $u 'createdDateTime' } else { $null })
    })
}
#endregion

#region output
Export-PimData -Data @($roleRows) -CsvPath (Join-Path $runFolder 'pp-tenant-roles.csv')
Export-PimData -Data @($envRows) -CsvPath (Join-Path $runFolder 'pp-environments.csv')
Export-PimData -Data @($envRoleRows) -CsvPath (Join-Path $runFolder 'pp-environment-roles.csv')
Export-PimData -Data @($flowRows) -CsvPath (Join-Path $runFolder 'pp-flows.csv')
Export-PimData -Data @($appRows) -CsvPath (Join-Path $runFolder 'pp-apps.csv')
Export-PimData -Data @($dlpRows) -CsvPath (Join-Path $runFolder 'pp-dlp-policies.csv')
Export-PimData -Data @($peopleRows) -CsvPath (Join-Path $runFolder 'pp-users.csv')
Export-PimData -Data @($script:Log) -CsvPath (Join-Path $runFolder 'pp-collection-log.csv')
if ($tenantSettings) { $tenantSettings | ConvertTo-Json -Depth 20 | Out-File (Join-Path $runFolder 'pp-tenant-settings.json') -Encoding UTF8 }

$meta = [ordered]@{
    tool = 'PIM-Review Power Platform review'; version = '1.0'
    tenantId = $script:TenantGuid; tenantName = $tenantName; tenantShortName = $TenantShortName
    runAccount = $runAccount; started = $started.ToString('s'); finished = (Get-Date).ToString('s')
    cladPrefix = $prefix; skipDataverse = [bool]$SkipDataverse; skipApps = [bool]$SkipApps
    environmentFilter = $EnvironmentFilter; powerPlatformApiAvailable = $ppAvailable; signInActivityAvailable = $signInAvailable
}
$meta | ConvertTo-Json -Depth 5 | Out-File (Join-Path $runFolder 'pp-run.json') -Encoding UTF8
Write-Host ''
Write-Host "Collection finished in $([Math]::Round(((Get-Date) - $started).TotalMinutes, 1)) min. $runFolder" -ForegroundColor Green

$result = [pscustomobject]@{ TenantShortName = $TenantShortName; RunFolder = $runFolder; ReportPath = $null }
if (-not $NoAssessment) {
    $a = & (Join-Path $PSScriptRoot 'Invoke-PowerPlatformAssessment.ps1') -RunFolder $runFolder
    if ($a) { $result.ReportPath = $a.ReportPath }
}
$result
#endregion
