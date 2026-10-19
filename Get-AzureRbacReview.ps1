<#
.SYNOPSIS
Read-only Azure RBAC review: every role assignment (active and PIM-eligible) from the tenant root
down to individual resources, with groups expanded to users.

.DESCRIPTION
Enumerates management groups, subscriptions, resource groups and resources, then collects:
- Active Azure role assignments at every scope (root, management group, subscription, resource group, resource)
- PIM for Azure resources eligible assignments, and whether active assignments are permanent,
  time-bound or PIM-activated
- Role definitions (built-in and custom) with a privilege tier derived from the actual permissions
- Principal resolution through Microsoft Graph (users, guests, groups, service principals, managed identities)
- Transitive group membership, PIM for Groups eligible members, and group owners (escalation paths)
- Resource counts per scope (blast radius) via Azure Resource Graph

Outputs (CSV evidence, optional Excel sheets, HTML and Markdown summary):
- AzureRoleAssignments.csv      one row per assignment (active and eligible)
- AzureUserAccess.csv           one row per principal per assignment, groups expanded to members
- AzureUserSummary.csv          one row per user / service principal with reach and highest privilege
- AzureAccessMatrix.csv         principals down the side, subscriptions across the top
- AzureSubscriptionSummary.csv  one row per subscription
- AzureFindings.csv             risk findings with recommendations
- AzureResourceAccess.csv       (optional) one row per resource per principal

This script is read-only. It does not modify Azure or Entra configuration.

Required access:
- Azure: Reader (or any role with Microsoft.Authorization/*/read) at the Tenant Root Group for full coverage.
  Anything the account cannot see is recorded in AzureCoverageGaps.csv.
- Graph (delegated): User.Read.All, Group.Read.All, Application.Read.All.
  Optional: PrivilegedEligibilitySchedule.Read.AzureADGroup for PIM for Groups eligible members.

.EXAMPLE
./Get-AzureRbacReview.ps1 -TenantId contoso.onmicrosoft.com -OutputFolder .\Output -Verbose

.EXAMPLE
./Get-AzureRbacReview.ps1 -TenantId <guid> -SubscriptionId <sub1>,<sub2> -IncludeResourceLevelAccess
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputFolder,
    [string]$TenantLabel,
    [string[]]$SubscriptionId,
    [string]$WorkbookPath,
    [int]$MaxOwnersPerSubscription = 3,
    [switch]$IncludeResourceLevelAccess,
    [switch]$IncludePimForGroups,
    [switch]$UseDeviceAuthentication,
    [switch]$SkipGraphConnect,
    [switch]$ForceReConnect
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

# Dot-sourced at script scope (not inside a function) so its param block cannot reset the caller's
# function-local parameters.
if (-not (Get-Command -Name Connect-GraphForPimReview -ErrorAction SilentlyContinue)) {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Connect-GraphForPimReview.ps1')
}

$script:AzRbacArmBase = 'https://management.azure.com'
$script:AzRbacCoverageGaps = New-Object System.Collections.ArrayList
$script:AzRbacRbacWriteOperation = 'Microsoft.Authorization/roleAssignments/write'

# ---------------------------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------------------------

function Get-AzRbacProp {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-AzRbacLastSegment {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $parts = $Value.TrimEnd('/').Split('/')
    return $parts[$parts.Length - 1].ToLowerInvariant()
}

function Add-AzRbacCoverageGap {
    param(
        [string]$Scope,
        [string]$Operation,
        [string]$StatusCode,
        [string]$Message
    )

    $null = $script:AzRbacCoverageGaps.Add([pscustomobject]@{
        Scope      = $Scope
        Operation  = $Operation
        StatusCode = $StatusCode
        Message    = $Message
    })
}

# ---------------------------------------------------------------------------------------------
# Azure connection and ARM requests
# ---------------------------------------------------------------------------------------------

function Connect-AzureForRbacReview {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [switch]$UseDeviceAuthentication,
        [switch]$ForceReConnect
    )

    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        throw 'Az.Accounts module is not installed. Install-Module Az.Accounts -Scope CurrentUser'
    }

    Import-Module Az.Accounts -ErrorAction Stop -Verbose:$false

    $isGuid = $false
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $parsed = [guid]::Empty
        $isGuid = [guid]::TryParse($TenantId, [ref]$parsed)
    }

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($context -and $context.Tenant -and -not $ForceReConnect) {
        $reuse = $false
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            $reuse = $true
        }
        elseif ($isGuid -and $context.Tenant.Id -eq $TenantId) {
            $reuse = $true
        }

        if ($reuse) {
            Write-PimLog -Message "Reusing existing Azure context. Tenant=$($context.Tenant.Id) Account=$($context.Account.Id)"
            return $context
        }

        Write-PimLog -Level WARN -Message "Existing Azure context tenant ($($context.Tenant.Id)) does not match requested tenant ($TenantId). Reconnecting."
    }

    # Az 12+ shows an interactive subscription picker at sign-in. Turn it off for this process only.
    try {
        $null = Update-AzConfig -LoginExperienceV2 Off -Scope Process -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        Write-Verbose 'Update-AzConfig -LoginExperienceV2 not available on this Az.Accounts version.'
    }

    $connectParams = @{
        ErrorAction   = 'Stop'
        WarningAction = 'SilentlyContinue'
    }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams.Tenant = $TenantId
    }
    if ($UseDeviceAuthentication) {
        $connectParams.UseDeviceAuthentication = $true
    }

    Write-PimLog -Message "Connecting to Azure Resource Manager (tenant: $TenantId)."
    $null = Connect-AzAccount @connectParams

    $context = Get-AzContext
    if (-not $context) {
        throw 'Unable to establish Azure context.'
    }

    Write-PimLog -Message "Connected to Azure. Tenant=$($context.Tenant.Id) Account=$($context.Account.Id)"
    return $context
}

function Invoke-ArmRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        [string]$Payload,

        [int]$MaxRetries = 6
    )

    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        $invokeParams = @{
            Uri         = $Uri
            Method      = $Method
            ErrorAction = 'Stop'
        }
        if ($Method -eq 'POST' -and $Payload) {
            $invokeParams.Payload = $Payload
        }

        $statusCode = 0
        $content = $null
        $response = $null

        try {
            $response = Invoke-AzRestMethod @invokeParams
            $statusCode = [int]$response.StatusCode
            $content = $response.Content
        }
        catch {
            $statusCode = -1
            $content = $_.Exception.Message
        }

        if ($statusCode -ge 200 -and $statusCode -lt 300) {
            if ([string]::IsNullOrWhiteSpace($content)) {
                return $null
            }
            return ($content | ConvertFrom-Json)
        }

        $retryable = ($statusCode -eq 429) -or ($statusCode -ge 500) -or ($statusCode -eq -1)
        if (-not $retryable -or $attempt -ge $MaxRetries) {
            $errorMessage = $content
            try {
                $parsedError = $content | ConvertFrom-Json -ErrorAction Stop
                $errObj = Get-AzRbacProp -InputObject $parsedError -Name 'error'
                if ($errObj) {
                    $errorMessage = "{0}: {1}" -f (Get-AzRbacProp -InputObject $errObj -Name 'code'), (Get-AzRbacProp -InputObject $errObj -Name 'message')
                }
            }
            catch {
                Write-Verbose 'ARM error body was not JSON.'
            }

            $exception = New-Object System.Exception ("ARM request failed ({0}): {1}. Uri: {2}" -f $statusCode, $errorMessage, $Uri)
            $exception.Data['StatusCode'] = $statusCode
            throw $exception
        }

        $delay = [Math]::Min(60, [Math]::Pow(2, $attempt) * 2)
        try {
            if ($response -and $response.Headers -and $response.Headers.RetryAfter -and $response.Headers.RetryAfter.Delta) {
                $delay = [Math]::Max(1, [int][Math]::Ceiling($response.Headers.RetryAfter.Delta.TotalSeconds))
            }
        }
        catch {
            Write-Verbose 'No Retry-After header available.'
        }

        Write-PimLog -Level WARN -Message "Retryable ARM response ($statusCode). Waiting $delay seconds. Uri: $Uri"
        Start-Sleep -Seconds $delay
    }
}

function Get-ArmPagedResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$Operation = 'ARM list',

        [string]$Scope,

        [switch]$TolerateErrors
    )

    $results = New-Object System.Collections.ArrayList
    $nextUri = $Uri

    while ($nextUri) {
        try {
            $response = Invoke-ArmRequest -Uri $nextUri -Method GET
        }
        catch {
            if (-not $TolerateErrors) { throw }

            $code = $null
            try { $code = $_.Exception.Data['StatusCode'] } catch { $code = $null }
            Add-AzRbacCoverageGap -Scope $Scope -Operation $Operation -StatusCode ([string]$code) -Message $_.Exception.Message
            Write-PimLog -Level WARN -Message "$Operation not readable at scope '$Scope' ($code). Recorded as a coverage gap."
            break
        }

        $values = Get-AzRbacProp -InputObject $response -Name 'value'
        if ($null -ne $values) {
            foreach ($item in @($values)) {
                if ($null -ne $item) { $null = $results.Add($item) }
            }
        }

        $nextUri = Get-AzRbacProp -InputObject $response -Name 'nextLink'
    }

    return $results.ToArray()
}

function Invoke-AzRbacResourceGraphQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [string[]]$Subscriptions
    )

    $uri = "$($script:AzRbacArmBase)/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
    $rows = New-Object System.Collections.ArrayList

    $subChunks = @()
    $subList = @($Subscriptions | Where-Object { $_ })
    if ($subList.Count -eq 0) {
        $subChunks += ,@()
    }
    else {
        for ($i = 0; $i -lt $subList.Count; $i += 1000) {
            $end = [Math]::Min($i + 999, $subList.Count - 1)
            $subChunks += ,@($subList[$i..$end])
        }
    }

    foreach ($chunk in $subChunks) {
        $skipToken = $null
        do {
            $options = @{ resultFormat = 'objectArray'; '$top' = 1000 }
            if ($skipToken) { $options['$skipToken'] = $skipToken }

            $body = @{ query = $Query; options = $options }
            if (@($chunk).Count -gt 0) { $body.subscriptions = @($chunk) }

            $payload = $body | ConvertTo-Json -Depth 10 -Compress
            $response = Invoke-ArmRequest -Uri $uri -Method POST -Payload $payload

            $data = Get-AzRbacProp -InputObject $response -Name 'data'
            foreach ($row in @($data)) {
                if ($null -ne $row) { $null = $rows.Add($row) }
            }

            $skipToken = Get-AzRbacProp -InputObject $response -Name '$skipToken'
        } while ($skipToken)
    }

    return $rows.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Scope and role analysis
# ---------------------------------------------------------------------------------------------

function Get-AzRbacScopeInfo {
    [CmdletBinding()]
    param(
        [string]$Scope,
        [hashtable]$ManagementGroupNames,
        [hashtable]$SubscriptionNames
    )

    $normalized = if ([string]::IsNullOrWhiteSpace($Scope)) { '/' } else { $Scope.Trim() }
    if ($normalized.Length -gt 1) { $normalized = $normalized.TrimEnd('/') }

    $info = [ordered]@{
        Scope             = $normalized
        ScopeLevel        = 'Other'
        ScopeName         = $normalized
        ManagementGroupId = $null
        SubscriptionId    = $null
        SubscriptionName  = $null
        ResourceGroup     = $null
        ResourceType      = $null
        ResourceName      = $null
    }

    if ($normalized -eq '/') {
        $info.ScopeLevel = 'Root'
        $info.ScopeName = 'Tenant Root (/)'
    }
    elseif ($normalized -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)$') {
        $mgId = $Matches[1].ToLowerInvariant()
        $info.ScopeLevel = 'ManagementGroup'
        $info.ManagementGroupId = $mgId
        $info.ScopeName = $Matches[1]
        if ($ManagementGroupNames -and $ManagementGroupNames.ContainsKey($mgId)) {
            $info.ScopeName = $ManagementGroupNames[$mgId]
        }
    }
    elseif ($normalized -match '^/subscriptions/([^/]+)(.*)$') {
        $subId = $Matches[1].ToLowerInvariant()
        $remainder = $Matches[2]
        $info.SubscriptionId = $subId
        $subName = $subId
        if ($SubscriptionNames -and $SubscriptionNames.ContainsKey($subId)) {
            $subName = $SubscriptionNames[$subId]
        }
        $info.SubscriptionName = $subName

        if ([string]::IsNullOrEmpty($remainder)) {
            $info.ScopeLevel = 'Subscription'
            $info.ScopeName = $subName
        }
        elseif ($remainder -match '^/resourceGroups/([^/]+)$') {
            $info.ScopeLevel = 'ResourceGroup'
            $info.ResourceGroup = $Matches[1].ToLowerInvariant()
            $info.ScopeName = $Matches[1]
        }
        else {
            $info.ScopeLevel = 'Resource'
            if ($remainder -match '^/resourceGroups/([^/]+)/providers/(.+)$') {
                $info.ResourceGroup = $Matches[1].ToLowerInvariant()
                $providerPath = $Matches[2]
            }
            elseif ($remainder -match '^/providers/(.+)$') {
                $providerPath = $Matches[1]
            }
            else {
                $providerPath = $remainder.TrimStart('/')
            }

            $segments = @($providerPath.Split('/') | Where-Object { $_ -ne '' })
            if ($segments.Count -ge 3) {
                $typeParts = @($segments[0])
                for ($i = 1; $i -lt $segments.Count; $i += 2) {
                    $typeParts += $segments[$i]
                }
                $info.ResourceType = ($typeParts -join '/')
                $info.ResourceName = $segments[$segments.Count - 1]
                $info.ScopeName = $info.ResourceName
            }
            else {
                $info.ResourceType = $providerPath
                $info.ScopeName = $providerPath
            }
        }
    }

    return [pscustomobject]$info
}

function Test-ArmActionMatch {
    param(
        [string]$Pattern,
        [string]$Operation
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $false }
    $regex = '^' + ([Regex]::Escape($Pattern) -replace '\\\*', '.*') + '$'
    return ($Operation -match $regex)
}

function Get-AzRbacRoleTier {
    [CmdletBinding()]
    param(
        [object]$RoleDefinition
    )

    $props = Get-AzRbacProp -InputObject $RoleDefinition -Name 'properties'
    $permissions = @(Get-AzRbacProp -InputObject $props -Name 'permissions')

    $canManageRbac = $false
    $fullControl = $false
    $anyWrite = $false
    $dataFullControl = $false
    $anyDataAction = $false
    $wildcardActions = New-Object System.Collections.ArrayList

    foreach ($perm in $permissions) {
        if ($null -eq $perm) { continue }
        $actions = @(Get-AzRbacProp -InputObject $perm -Name 'actions')
        $notActions = @(Get-AzRbacProp -InputObject $perm -Name 'notActions')
        $dataActions = @(Get-AzRbacProp -InputObject $perm -Name 'dataActions')

        foreach ($action in $actions) {
            if ([string]::IsNullOrWhiteSpace($action)) { continue }

            if (Test-ArmActionMatch -Pattern $action -Operation $script:AzRbacRbacWriteOperation) {
                $excluded = $false
                foreach ($notAction in $notActions) {
                    if (Test-ArmActionMatch -Pattern $notAction -Operation $script:AzRbacRbacWriteOperation) {
                        $excluded = $true
                        break
                    }
                }
                if (-not $excluded) { $canManageRbac = $true }
            }

            if ($action -eq '*') { $fullControl = $true }
            if ($action -match '\*') { $null = $wildcardActions.Add($action) }
            if ($action -match '(\*|/write|/delete|/action)$') { $anyWrite = $true }
        }

        foreach ($dataAction in $dataActions) {
            if ([string]::IsNullOrWhiteSpace($dataAction)) { continue }
            $anyDataAction = $true
            if ($dataAction -match '\*$') { $dataFullControl = $true }
            if ($dataAction -match '(/write|/delete|/action)$') { $anyWrite = $true }
        }
    }

    $tier = 'Low'
    $reason = 'Read-only control plane permissions.'
    if ($canManageRbac) {
        $tier = 'Critical'
        $reason = 'Can create role assignments (Microsoft.Authorization/roleAssignments/write) and therefore grant itself or others any access.'
    }
    elseif ($fullControl) {
        $tier = 'High'
        $reason = 'Full control plane write (*) excluding role assignment management.'
    }
    elseif ($dataFullControl) {
        $tier = 'High'
        $reason = 'Full data plane control (wildcard data actions), for example secrets, keys or storage data.'
    }
    elseif ($anyWrite) {
        $tier = 'Medium'
        $reason = 'Can change resources or invoke actions on them.'
    }
    elseif ($anyDataAction) {
        $tier = 'Medium'
        $reason = 'Data plane read access (for example blob, queue, secret or key contents).'
    }

    return [pscustomobject]@{
        Tier            = $tier
        Reason          = $reason
        CanManageRbac   = $canManageRbac
        WildcardActions = (@($wildcardActions) -join '; ')
    }
}

function Get-AzRbacTierRank {
    param([string]$Tier)

    switch ($Tier) {
        'Critical' { return 4 }
        'High' { return 3 }
        'Medium' { return 2 }
        'Low' { return 1 }
        default { return 0 }
    }
}

# ---------------------------------------------------------------------------------------------
# Principal resolution (Microsoft Graph)
# ---------------------------------------------------------------------------------------------

function Resolve-AzRbacPrincipals {
    [CmdletBinding()]
    param(
        [string[]]$PrincipalIds,
        [hashtable]$ArmPrincipalTypes
    )

    $map = @{}
    $ids = @($PrincipalIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    if ($ids.Count -eq 0) { return $map }

    $graphAvailable = $null -ne (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) -and $null -ne (Get-MgContext -ErrorAction SilentlyContinue)

    $resolvedObjects = @{}
    if ($graphAvailable) {
        for ($i = 0; $i -lt $ids.Count; $i += 1000) {
            $end = [Math]::Min($i + 999, $ids.Count - 1)
            $batch = @($ids[$i..$end])
            $body = @{ ids = $batch; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Depth 5 -Compress
            try {
                $response = Invoke-GraphRequestWithRetry -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' -Method POST -Body $body
                foreach ($obj in @(Get-AzRbacProp -InputObject $response -Name 'value')) {
                    if ($null -eq $obj) { continue }
                    $objId = [string](Get-AzRbacProp -InputObject $obj -Name 'id')
                    if ($objId) { $resolvedObjects[$objId.ToLowerInvariant()] = $obj }
                }
            }
            catch {
                Write-PimLog -Level WARN -Message "Directory object lookup failed for a batch of $($batch.Count) principals: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-PimLog -Level WARN -Message 'No Microsoft Graph context. Principals will be reported by object ID only.'
    }

    foreach ($id in $ids) {
        $armType = $null
        if ($ArmPrincipalTypes -and $ArmPrincipalTypes.ContainsKey($id)) { $armType = $ArmPrincipalTypes[$id] }

        $obj = $null
        if ($resolvedObjects.ContainsKey($id)) { $obj = $resolvedObjects[$id] }

        $principal = [ordered]@{
            PrincipalId        = $id
            Resolved           = $null -ne $obj
            PrincipalType      = $armType
            Category           = 'Unknown'
            DisplayName        = $null
            UserPrincipalName  = $null
            UserType           = $null
            AccountEnabled     = $null
            AppId              = $null
            IsAssignableToRole = $null
        }

        if ($obj) {
            $odataType = [string](Get-AzRbacProp -InputObject $obj -Name '@odata.type')
            $principal.DisplayName = Get-AzRbacProp -InputObject $obj -Name 'displayName'

            if ($odataType -match 'user') {
                $principal.PrincipalType = 'User'
                $user = Resolve-User -UserId $id -Select 'id,displayName,userPrincipalName,userType,accountEnabled,mail'
                if (-not $user) { $user = $obj }
                $principal.DisplayName = Get-AzRbacProp -InputObject $user -Name 'displayName'
                $principal.UserPrincipalName = Get-AzRbacProp -InputObject $user -Name 'userPrincipalName'
                $principal.UserType = Get-AzRbacProp -InputObject $user -Name 'userType'
                $principal.AccountEnabled = Get-AzRbacProp -InputObject $user -Name 'accountEnabled'
                $isGuest = ($principal.UserType -eq 'Guest') -or ([string]$principal.UserPrincipalName -match '#EXT#')
                $principal.Category = if ($isGuest) { 'Guest' } else { 'Member' }
            }
            elseif ($odataType -match 'group') {
                $principal.PrincipalType = 'Group'
                $principal.Category = 'Group'
                $group = Resolve-Group -GroupId $id
                if ($group) {
                    $principal.IsAssignableToRole = Get-AzRbacProp -InputObject $group -Name 'isAssignableToRole'
                }
            }
            elseif ($odataType -match 'servicePrincipal') {
                $principal.PrincipalType = 'ServicePrincipal'
                $principal.AppId = Get-AzRbacProp -InputObject $obj -Name 'appId'
                $principal.AccountEnabled = Get-AzRbacProp -InputObject $obj -Name 'accountEnabled'
                $spType = [string](Get-AzRbacProp -InputObject $obj -Name 'servicePrincipalType')
                $principal.Category = if ($spType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
            }
        }
        else {
            if (-not $principal.PrincipalType) { $principal.PrincipalType = 'Unknown' }
            $principal.DisplayName = "Unresolved ($id)"
            $principal.Category = 'Unresolved'
        }

        $map[$id] = [pscustomobject]$principal
    }

    return $map
}

function Get-AzRbacGroupExpansion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupId,

        [string]$GroupDisplayName,

        [switch]$IncludePimForGroups
    )

    $members = New-Object System.Collections.ArrayList
    $owners = New-Object System.Collections.ArrayList
    $expansionFailed = $false

    $rawMembers = $null
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers?`$select=id,displayName,userPrincipalName,userType,accountEnabled,appId,servicePrincipalType"
    try {
        $rawMembers = @(Get-GraphPagedResults -Uri $uri)
    }
    catch {
        Write-PimLog -Level WARN -Message "Full member query failed for group $GroupDisplayName ($GroupId); retrying with basic properties. Error: $($_.Exception.Message)"
        try {
            $rawMembers = @(Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers")
        }
        catch {
            $expansionFailed = $true
            Write-PimLog -Level WARN -Message "Unable to expand members of group $GroupDisplayName ($GroupId): $($_.Exception.Message)"
        }
    }

    if (-not $expansionFailed) {
        foreach ($m in @($rawMembers)) {
            if ($null -eq $m) { continue }
            $type = Get-PrincipalType -Principal $m
            if ($type -ne 'User' -and $type -ne 'ServicePrincipal') { continue }

            $category = 'Member'
            if ($type -eq 'User') {
                $isGuest = ((Get-AzRbacProp -InputObject $m -Name 'userType') -eq 'Guest') -or ([string](Get-AzRbacProp -InputObject $m -Name 'userPrincipalName') -match '#EXT#')
                if ($isGuest) { $category = 'Guest' }
            }
            else {
                $category = if ((Get-AzRbacProp -InputObject $m -Name 'servicePrincipalType') -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
            }

            $null = $members.Add([pscustomobject]@{
                GroupId           = $GroupId
                GroupDisplayName  = $GroupDisplayName
                MemberId          = ([string](Get-AzRbacProp -InputObject $m -Name 'id')).ToLowerInvariant()
                DisplayName       = Get-AzRbacProp -InputObject $m -Name 'displayName'
                UserPrincipalName = Get-AzRbacProp -InputObject $m -Name 'userPrincipalName'
                PrincipalType     = $type
                Category          = $category
                AccountEnabled    = Get-AzRbacProp -InputObject $m -Name 'accountEnabled'
                MembershipType    = 'Member (transitive)'
                MembershipEnd     = $null
            })
        }
    }

    if ($IncludePimForGroups) {
        $pimUri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$GroupId'"
        try {
            foreach ($e in @(Get-GraphPagedResults -Uri $pimUri)) {
                if ($null -eq $e) { continue }
                if ([string](Get-AzRbacProp -InputObject $e -Name 'accessId') -ne 'member') { continue }

                $principalId = [string](Get-AzRbacProp -InputObject $e -Name 'principalId')
                if ([string]::IsNullOrWhiteSpace($principalId)) { continue }

                $user = Resolve-User -UserId $principalId -Select 'id,displayName,userPrincipalName,userType,accountEnabled,mail'
                $userType = Get-AzRbacProp -InputObject $user -Name 'userType'
                $upn = Get-AzRbacProp -InputObject $user -Name 'userPrincipalName'
                $category = if (($userType -eq 'Guest') -or ([string]$upn -match '#EXT#')) { 'Guest' } else { 'Member' }

                $null = $members.Add([pscustomobject]@{
                    GroupId           = $GroupId
                    GroupDisplayName  = $GroupDisplayName
                    MemberId          = $principalId.ToLowerInvariant()
                    DisplayName       = Get-AzRbacProp -InputObject $user -Name 'displayName'
                    UserPrincipalName = $upn
                    PrincipalType     = 'User'
                    Category          = $category
                    AccountEnabled    = Get-AzRbacProp -InputObject $user -Name 'accountEnabled'
                    MembershipType    = 'Eligible member (PIM for Groups)'
                    MembershipEnd     = Get-AzRbacProp -InputObject $e -Name 'endDateTime'
                })
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read PIM for Groups eligibility for $GroupDisplayName ($GroupId): $($_.Exception.Message)"
        }
    }

    $ownerUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/owners?`$select=id,displayName,userPrincipalName,userType,appId"
    try {
        foreach ($o in @(Get-GraphPagedResults -Uri $ownerUri)) {
            if ($null -eq $o) { continue }
            $null = $owners.Add([pscustomobject]@{
                GroupId                = $GroupId
                GroupDisplayName       = $GroupDisplayName
                OwnerId                = Get-AzRbacProp -InputObject $o -Name 'id'
                OwnerDisplayName       = Get-AzRbacProp -InputObject $o -Name 'displayName'
                OwnerUserPrincipalName = Get-AzRbacProp -InputObject $o -Name 'userPrincipalName'
                OwnerType              = Get-PrincipalType -Principal $o
            })
        }
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to read owners of group $GroupDisplayName ($GroupId): $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Members         = @($members)
        Owners          = @($owners)
        ExpansionFailed = $expansionFailed
    }
}

# ---------------------------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------------------------

function ConvertTo-AzRbacHtmlTable {
    param(
        [object[]]$Rows,
        [string[]]$Columns
    )

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return '<p>No rows</p>'
    }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('<table><thead><tr>')
    foreach ($col in $Columns) { $null = $sb.Append("<th>$col</th>") }
    $null = $sb.Append('</tr></thead><tbody>')

    foreach ($row in $Rows) {
        $null = $sb.Append('<tr>')
        foreach ($col in $Columns) {
            $value = Get-AzRbacProp -InputObject $row -Name $col
            $text = if ($null -eq $value) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$value) }
            if ($col -eq 'RiskRating' -or $col -eq 'Status' -or $col -eq 'HighestTier') {
                $cls = switch ([string]$value) { 'Critical' { 'badge-critical' } 'High' { 'badge-high' } 'Red' { 'badge-high' } 'Medium' { 'badge-medium' } 'Amber' { 'badge-medium' } 'Low' { 'badge-low' } 'Green' { 'badge-low' } default { '' } }
                if ($cls) { $text = "<span class=""$cls"">$text</span>" }
            }
            $null = $sb.Append("<td>$text</td>")
        }
        $null = $sb.Append('</tr>')
    }

    $null = $sb.Append('</tbody></table>')
    return $sb.ToString()
}

function ConvertTo-AzRbacMarkdownTable {
    param(
        [object[]]$Rows,
        [string[]]$Columns
    )

    if (-not $Rows -or @($Rows).Count -eq 0) {
        return @('- No rows')
    }

    $lines = @()
    $lines += '| ' + ($Columns -join ' | ') + ' |'
    $lines += '| ' + (($Columns | ForEach-Object { '---' }) -join ' | ') + ' |'
    foreach ($row in $Rows) {
        $values = @()
        foreach ($col in $Columns) {
            $value = Get-AzRbacProp -InputObject $row -Name $col
            if ($null -eq $value) { $values += '' }
            else { $values += ([string]$value -replace '\|', '/' -replace '[\r\n]+', ' ') }
        }
        $lines += '| ' + ($values -join ' | ') + ' |'
    }
    return $lines
}

function New-AzRbacSummaryReport {
    [CmdletBinding()]
    param(
        [string]$OutputFolder,
        [string]$TenantLabel,
        [string]$TenantIdValue,
        [object[]]$Scorecard,
        [object[]]$Findings,
        [object[]]$SubscriptionSummary,
        [object[]]$UserSummary,
        [object[]]$CustomRoles,
        [object[]]$GroupOwners,
        [object[]]$CoverageGaps
    )

    $assessmentDate = (Get-Date).ToString('yyyy-MM-dd')
    $fileStem = Get-SafeFileName -Name ("AzureRbac_Summary_{0}" -f $TenantLabel)
    $mdPath = Join-Path -Path $OutputFolder -ChildPath "$fileStem.md"
    $htmlPath = Join-Path -Path $OutputFolder -ChildPath "$fileStem.html"

    $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    $sortedFindings = @($Findings | Sort-Object -Property @{ Expression = { if ($severityOrder.ContainsKey($_.RiskRating)) { $severityOrder[$_.RiskRating] } else { 9 } } }, FindingType, Subject)

    $findingTypeSummary = @(
        $Findings |
        Group-Object -Property RiskRating, FindingType |
        ForEach-Object {
            $first = $_.Group[0]
            [pscustomobject]@{
                RiskRating     = $first.RiskRating
                FindingType    = $first.FindingType
                Count          = $_.Count
                Recommendation = $first.Recommendation
            }
        } |
        Sort-Object -Property @{ Expression = { if ($severityOrder.ContainsKey($_.RiskRating)) { $severityOrder[$_.RiskRating] } else { 9 } } }, @{ Expression = 'Count'; Descending = $true }
    )

    $topUsers = @(
        $UserSummary |
        Where-Object { $_.PrincipalCategory -in @('Member', 'Guest') -and (Get-AzRbacTierRank -Tier $_.HighestTier) -ge 3 } |
        Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, @{ Expression = 'StandingPrivilegedCount'; Descending = $true }, @{ Expression = 'SubscriptionsReachable'; Descending = $true } |
        Select-Object -First 100
    )

    $workloads = @(
        $UserSummary |
        Where-Object { $_.PrincipalCategory -in @('ServicePrincipal', 'ManagedIdentity') -and (Get-AzRbacTierRank -Tier $_.HighestTier) -ge 3 } |
        Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, @{ Expression = 'SubscriptionsReachable'; Descending = $true } |
        Select-Object -First 100
    )

    $critCount = @($Findings | Where-Object { $_.RiskRating -eq 'Critical' }).Count
    $highCount = @($Findings | Where-Object { $_.RiskRating -eq 'High' }).Count
    $medCount = @($Findings | Where-Object { $_.RiskRating -eq 'Medium' }).Count
    $lowCount = @($Findings | Where-Object { $_.RiskRating -eq 'Low' }).Count

    $subCols = @('SubscriptionName', 'State', 'ManagementGroupPath', 'Resources', 'EffectivePrincipals', 'EffectiveOwners', 'StandingOwners', 'EligibleOwners', 'GuestsWithAccess', 'PimEligibleAssignments', 'RiskRating')
    $userCols = @('DisplayName', 'UserPrincipalName', 'PrincipalCategory', 'HighestTier', 'StandingPrivilegedCount', 'EligiblePrivilegedCount', 'SubscriptionsReachable', 'ResourcesReachable', 'CriticalAccess')
    $workloadCols = @('DisplayName', 'PrincipalCategory', 'HighestTier', 'SubscriptionsReachable', 'ResourcesReachable', 'CriticalAccess')
    $findingCols = @('RiskRating', 'FindingType', 'Subject', 'RoleName', 'ScopeName', 'Details')

    # Markdown
    $md = @()
    $md += '# Azure RBAC Privileged Access Review'
    $md += ''
    $md += "- Client: $TenantLabel"
    $md += "- Tenant ID: $TenantIdValue"
    $md += "- Assessment date: $assessmentDate"
    $md += "- Findings: $critCount Critical, $highCount High, $medCount Medium, $lowCount Low"
    $md += ''
    $md += '## 1. Scorecard'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $Scorecard -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary'))
    $md += ''
    $md += '## 2. Findings by Type'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $findingTypeSummary -Columns @('RiskRating', 'FindingType', 'Count', 'Recommendation'))
    $md += ''
    $md += '## 3. Subscriptions'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $SubscriptionSummary -Columns $subCols)
    $md += ''
    $md += '## 4. Users with Critical or High Azure Access'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $topUsers -Columns $userCols)
    $md += ''
    $md += '## 5. Service Principals and Managed Identities with Critical or High Azure Access'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $workloads -Columns $workloadCols)
    $md += ''
    $md += '## 6. Custom Roles in Use'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $CustomRoles -Columns @('RoleName', 'PrivilegeTier', 'AssignmentCount', 'WildcardActions', 'AssignableScopes'))
    $md += ''
    $md += '## 7. Owners of Groups that Hold Azure Roles'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $GroupOwners -Columns @('GroupDisplayName', 'HighestGroupTier', 'IsAssignableToRole', 'OwnerDisplayName', 'OwnerUserPrincipalName', 'OwnerType'))
    $md += ''
    $md += '## 8. Detailed Findings'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $sortedFindings -Columns $findingCols)
    $md += ''
    $md += '## 9. Coverage Gaps'
    $md += ''
    $md += 'Scopes the review account could not read. Assignments at these scopes are missing from this report.'
    $md += ''
    $md += (ConvertTo-AzRbacMarkdownTable -Rows $CoverageGaps -Columns @('Scope', 'Operation', 'StatusCode'))
    $md | Out-File -FilePath $mdPath -Encoding UTF8

    # HTML
    $css = 'body{font-family:Segoe UI,Arial,sans-serif;margin:28px;line-height:1.45;color:#222}h1{font-size:30px;margin-bottom:8px}h2{font-size:21px;margin-top:28px;margin-bottom:10px;border-bottom:1px solid #e3e3e3;padding-bottom:4px}.cover{border:2px solid #1f4e78;padding:20px;border-radius:8px;background:#f7fbff;margin-bottom:18px}.meta{margin:6px 0}.section-intro{margin:8px 0 12px 0;color:#2c3e50;font-size:13px;line-height:1.6}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #ddd;padding:5px 7px;vertical-align:top}th{background:#f4f6f8;text-align:left}.badge-critical{background:#b71c1c;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}.badge-high{background:#c62828;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}.badge-medium{background:#e65100;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}.badge-low{background:#2e7d32;color:#fff;display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}.counts span{margin-right:10px}'
    $labelHtml = [System.Net.WebUtility]::HtmlEncode($TenantLabel)

    $html = New-Object System.Text.StringBuilder
    $null = $html.Append('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Azure RBAC Review - ' + $labelHtml + '</title>')
    $null = $html.Append("<style>$css</style></head><body>")
    $null = $html.Append('<div class="cover"><h1>Azure RBAC Privileged Access Review</h1>')
    $null = $html.Append("<div class=""meta""><strong>Client:</strong> $labelHtml</div>")
    $null = $html.Append("<div class=""meta""><strong>Tenant ID:</strong> $TenantIdValue</div>")
    $null = $html.Append('<div class="meta"><strong>Assessment Type:</strong> Azure resource role assignments (active and PIM-eligible), management group to resource</div>')
    $null = $html.Append("<div class=""meta""><strong>Assessment Date:</strong> $assessmentDate</div>")
    $null = $html.Append("<div class=""meta counts""><strong>Findings:</strong> <span class=""badge-critical"">$critCount Critical</span><span class=""badge-high"">$highCount High</span><span class=""badge-medium"">$medCount Medium</span><span class=""badge-low"">$lowCount Low</span></div>")
    $null = $html.Append('</div>')

    $null = $html.Append('<h2>1. Scorecard</h2>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $Scorecard -Columns @('Metric', 'Value', 'Status', 'Target', 'Commentary')))

    $null = $html.Append('<h2>2. Findings by Type</h2>')
    $null = $html.Append('<p class="section-intro">Each finding type with the number of occurrences and the recommended remediation. Full detail is in section 8 and in AzureFindings.csv.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $findingTypeSummary -Columns @('RiskRating', 'FindingType', 'Count', 'Recommendation')))

    $null = $html.Append('<h2>3. Subscriptions</h2>')
    $null = $html.Append('<p class="section-intro">Effective counts include access inherited from management groups and the tenant root, and access granted through group membership. Owners means principals holding a Critical-tier role (can manage role assignments) at or above the subscription.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $SubscriptionSummary -Columns $subCols))

    $null = $html.Append('<h2>4. Users with Critical or High Azure Access</h2>')
    $null = $html.Append('<p class="section-intro">Users (members and guests) whose highest Azure role is Critical or High tier, directly or through groups. Standing means active without PIM. The full list of every user is in AzureUserSummary.csv and the subscription matrix in AzureAccessMatrix.csv.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $topUsers -Columns $userCols))

    $null = $html.Append('<h2>5. Service Principals and Managed Identities with Critical or High Azure Access</h2>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $workloads -Columns $workloadCols))

    $null = $html.Append('<h2>6. Custom Roles in Use</h2>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $CustomRoles -Columns @('RoleName', 'PrivilegeTier', 'AssignmentCount', 'WildcardActions', 'AssignableScopes')))

    $null = $html.Append('<h2>7. Owners of Groups that Hold Azure Roles</h2>')
    $null = $html.Append('<p class="section-intro">Group owners can add members, so each owner below can grant themselves the Azure access the group holds.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $GroupOwners -Columns @('GroupDisplayName', 'HighestGroupTier', 'IsAssignableToRole', 'OwnerDisplayName', 'OwnerUserPrincipalName', 'OwnerType')))

    $null = $html.Append('<h2>8. Detailed Findings</h2>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $sortedFindings -Columns $findingCols))

    $null = $html.Append('<h2>9. Coverage Gaps</h2>')
    $null = $html.Append('<p class="section-intro">Scopes the review account could not read. Assignments at these scopes are missing from this report. Grant Reader at the Tenant Root Group and re-run for complete coverage.</p>')
    $null = $html.Append((ConvertTo-AzRbacHtmlTable -Rows $CoverageGaps -Columns @('Scope', 'Operation', 'StatusCode')))

    $null = $html.Append('</body></html>')
    [System.IO.File]::WriteAllText($htmlPath, $html.ToString(), [System.Text.Encoding]::UTF8)

    return [pscustomobject]@{
        MarkdownPath = $mdPath
        HtmlPath     = $htmlPath
    }
}

function Write-AzRbacWorkbookSheets {
    [CmdletBinding()]
    param(
        [string]$WorkbookPath,
        [object[]]$SheetMap
    )

    if (-not (Test-ImportExcelAvailable)) {
        Write-PimLog -Level WARN -Message 'ImportExcel not installed. Azure RBAC sheets skipped; CSV evidence is still exported.'
        return $false
    }

    Import-Module ImportExcel -ErrorAction Stop -Verbose:$false

    foreach ($sheet in $SheetMap) {
        $rows = @($sheet.Data)
        if ($rows.Count -eq 0) {
            $rows = @([pscustomobject]@{ Info = 'No data returned for this sheet.' })
        }

        $tableName = ($sheet.Name -replace '[^A-Za-z0-9_]', '_')
        if ($tableName -notmatch '^[A-Za-z]') { $tableName = "T_$tableName" }

        try {
            $rows | Export-Excel -Path $WorkbookPath -WorksheetName $sheet.Name -TableName $tableName -AutoSize -FreezeTopRow -AutoFilter -Append
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to write sheet $($sheet.Name): $($_.Exception.Message)"
        }
    }

    return $true
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

function Get-AzureRbacReview {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$OutputFolder,
        [string]$TenantLabel,
        [string[]]$SubscriptionId,
        [string]$WorkbookPath,
        [int]$MaxOwnersPerSubscription = 3,
        [switch]$IncludeResourceLevelAccess,
        [switch]$IncludePimForGroups,
        [switch]$UseDeviceAuthentication,
        [switch]$SkipGraphConnect,
        [switch]$ForceReConnect
    )

    $script:AzRbacCoverageGaps = New-Object System.Collections.ArrayList
    $runStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')

    # ---- Connections ------------------------------------------------------------------------
    if (-not $SkipGraphConnect) {
        $null = Connect-GraphForPimReview -TenantId $TenantId -IncludeAzureRbac -IncludePimForGroups:$IncludePimForGroups -ForceReConnect:$ForceReConnect
    }

    $graphContext = $null
    if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) {
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    }

    $azTenant = $TenantId
    if ($graphContext -and $graphContext.TenantId) {
        $azTenant = [string]$graphContext.TenantId
    }

    $azContext = Connect-AzureForRbacReview -TenantId $azTenant -UseDeviceAuthentication:$UseDeviceAuthentication -ForceReConnect:$ForceReConnect
    $tenantGuid = [string]$azContext.Tenant.Id

    if ($IncludePimForGroups -and $graphContext) {
        $hasPimGroupScope = @($graphContext.Scopes) -contains 'PrivilegedEligibilitySchedule.Read.AzureADGroup'
        if (-not $hasPimGroupScope) {
            Write-PimLog -Level WARN -Message 'Graph context lacks PrivilegedEligibilitySchedule.Read.AzureADGroup. PIM for Groups eligible members will not be expanded.'
            $IncludePimForGroups = $false
        }
    }

    # ---- Output location --------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($TenantLabel)) {
        $TenantLabel = $tenantGuid
        try {
            $org = @(Get-GraphPagedResults -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName')
            if ($org.Count -gt 0 -and $org[0].displayName) { $TenantLabel = [string]$org[0].displayName }
        }
        catch {
            Write-Verbose 'Organization display name not available; using tenant ID as label.'
        }
        $TenantLabel = (Get-SafeFileName -Name $TenantLabel) -replace '\s+', '_'
    }

    if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
        $OutputFolder = Join-Path -Path (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Output') -ChildPath $TenantLabel) -ChildPath "AzureRun-$runStamp"
    }
    $OutputFolder = Ensure-Directory -Path $OutputFolder
    $rawFolder = Ensure-Directory -Path (Join-Path -Path $OutputFolder -ChildPath 'Raw')

    # ---- Management groups and subscriptions ------------------------------------------------
    Write-PimLog -Message 'Enumerating management groups.'
    $mgNames = @{}
    $managementGroups = @(Get-ArmPagedResults -Uri "$($script:AzRbacArmBase)/providers/Microsoft.Management/managementGroups?api-version=2021-04-01" -Operation 'List management groups' -Scope '/' -TolerateErrors)
    foreach ($mg in $managementGroups) {
        $mgId = ([string](Get-AzRbacProp -InputObject $mg -Name 'name')).ToLowerInvariant()
        $mgDisplay = Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $mg -Name 'properties') -Name 'displayName'
        if (-not $mgDisplay) { $mgDisplay = $mgId }
        $mgNames[$mgId] = [string]$mgDisplay
    }
    Write-PimLog -Message "Management groups visible: $($mgNames.Count)."

    Write-PimLog -Message 'Enumerating subscriptions.'
    $subscriptionsRaw = @(Get-ArmPagedResults -Uri "$($script:AzRbacArmBase)/subscriptions?api-version=2022-12-01" -Operation 'List subscriptions' -Scope '/')
    $subscriptions = @(
        $subscriptionsRaw | Where-Object {
            $subTenant = [string](Get-AzRbacProp -InputObject $_ -Name 'tenantId')
            [string]::IsNullOrWhiteSpace($subTenant) -or $subTenant -eq $tenantGuid
        }
    )

    if ($SubscriptionId -and @($SubscriptionId).Count -gt 0) {
        $wanted = @($SubscriptionId | ForEach-Object { $_.ToLowerInvariant() })
        $subscriptions = @($subscriptions | Where-Object { $wanted -contains ([string]$_.subscriptionId).ToLowerInvariant() })
        Write-PimLog -Message "Subscription filter applied: $($subscriptions.Count) of $($wanted.Count) requested subscriptions visible."
    }

    $subNames = @{}
    $subStates = @{}
    foreach ($sub in $subscriptions) {
        $sid = ([string]$sub.subscriptionId).ToLowerInvariant()
        $subNames[$sid] = [string](Get-AzRbacProp -InputObject $sub -Name 'displayName')
        $subStates[$sid] = [string](Get-AzRbacProp -InputObject $sub -Name 'state')
    }
    $subIds = @($subNames.Keys)
    Write-PimLog -Message "Subscriptions in scope: $($subIds.Count)."

    # ---- Hierarchy and resource counts (Azure Resource Graph) --------------------------------
    $subMgChain = @{}
    $subMgPath = @{}
    $resourceCountBySub = @{}
    $resourceCountByRg = @{}
    $rgCountBySub = @{}
    $totalResources = 0

    if ($subIds.Count -gt 0) {
        try {
            $containers = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $subIds -Query "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, mgChain = properties.managementGroupAncestorsChain")
            foreach ($c in $containers) {
                $sid = ([string](Get-AzRbacProp -InputObject $c -Name 'subscriptionId')).ToLowerInvariant()
                $chain = @(Get-AzRbacProp -InputObject $c -Name 'mgChain')
                $ids = @()
                $names = @()
                foreach ($link in $chain) {
                    if ($null -eq $link) { continue }
                    $linkName = ([string](Get-AzRbacProp -InputObject $link -Name 'name')).ToLowerInvariant()
                    $linkDisplay = [string](Get-AzRbacProp -InputObject $link -Name 'displayName')
                    if ($linkName) {
                        $ids += $linkName
                        if (-not $mgNames.ContainsKey($linkName) -and $linkDisplay) { $mgNames[$linkName] = $linkDisplay }
                        $names += $(if ($linkDisplay) { $linkDisplay } else { $linkName })
                    }
                }
                $subMgChain[$sid] = $ids
                # ARG returns the chain nearest-first; present it root-first.
                [array]::Reverse($names)
                $subMgPath[$sid] = ($names -join ' > ')
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Resource Graph hierarchy query failed ($($_.Exception.Message)). Falling back to management group descendants."
            foreach ($mgId in @($mgNames.Keys)) {
                $desc = @(Get-ArmPagedResults -Uri "$($script:AzRbacArmBase)/providers/Microsoft.Management/managementGroups/$mgId/descendants?api-version=2021-04-01" -Operation 'List management group descendants' -Scope "/providers/Microsoft.Management/managementGroups/$mgId" -TolerateErrors)
                foreach ($d in $desc) {
                    if ([string](Get-AzRbacProp -InputObject $d -Name 'type') -match 'subscriptions$') {
                        $sid = ([string](Get-AzRbacProp -InputObject $d -Name 'name')).ToLowerInvariant()
                        if (-not $subMgChain.ContainsKey($sid)) { $subMgChain[$sid] = @() }
                        $subMgChain[$sid] = @($subMgChain[$sid]) + $mgId
                    }
                }
            }
        }

        try {
            $counts = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $subIds -Query 'resources | summarize Resources = count() by subscriptionId, resourceGroup = tolower(resourceGroup)')
            foreach ($row in $counts) {
                $sid = ([string](Get-AzRbacProp -InputObject $row -Name 'subscriptionId')).ToLowerInvariant()
                $rg = [string](Get-AzRbacProp -InputObject $row -Name 'resourceGroup')
                $n = [int](Get-AzRbacProp -InputObject $row -Name 'Resources')
                if (-not $resourceCountBySub.ContainsKey($sid)) { $resourceCountBySub[$sid] = 0 }
                $resourceCountBySub[$sid] += $n
                $resourceCountByRg["$sid|$rg"] = $n
                $totalResources += $n
            }

            $rgs = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $subIds -Query "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | summarize ResourceGroups = count() by subscriptionId")
            foreach ($row in $rgs) {
                $sid = ([string](Get-AzRbacProp -InputObject $row -Name 'subscriptionId')).ToLowerInvariant()
                $rgCountBySub[$sid] = [int](Get-AzRbacProp -InputObject $row -Name 'ResourceGroups')
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Resource Graph count query failed: $($_.Exception.Message). Blast radius counts will be blank."
            Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph resource counts' -StatusCode '' -Message $_.Exception.Message
        }
    }

    $resourceCountByMg = @{}
    foreach ($sid in $subIds) {
        if (-not $subMgChain.ContainsKey($sid) -or -not $resourceCountBySub.ContainsKey($sid)) { continue }
        foreach ($mgId in @($subMgChain[$sid])) {
            if (-not $resourceCountByMg.ContainsKey($mgId)) { $resourceCountByMg[$mgId] = 0 }
            $resourceCountByMg[$mgId] += $resourceCountBySub[$sid]
        }
    }

    # ---- Role assignments, eligibility and schedule instances -------------------------------
    $assignmentById = @{}
    $eligibilityByKey = @{}
    $scheduleByOrigin = @{}

    $scopeTargets = New-Object System.Collections.ArrayList
    $null = $scopeTargets.Add(@{ Scope = ''; Display = '/'; Filter = '&$filter=atScope()' })
    foreach ($mgId in @($mgNames.Keys)) {
        $null = $scopeTargets.Add(@{ Scope = "/providers/Microsoft.Management/managementGroups/$mgId"; Display = "/providers/Microsoft.Management/managementGroups/$mgId"; Filter = '&$filter=atScope()' })
    }
    foreach ($sid in $subIds) {
        # No filter at subscription scope: returns assignments at, above and below the subscription.
        $null = $scopeTargets.Add(@{ Scope = "/subscriptions/$sid"; Display = "/subscriptions/$sid"; Filter = '' })
    }

    $targetIndex = 0
    foreach ($target in $scopeTargets) {
        $targetIndex++
        Write-Progress -Activity 'Azure RBAC review' -Status "Reading role assignments: $($target.Display)" -PercentComplete ([int](($targetIndex / [Math]::Max(1, $scopeTargets.Count)) * 100))

        $raUri = "$($script:AzRbacArmBase)$($target.Scope)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01$($target.Filter)"
        foreach ($ra in @(Get-ArmPagedResults -Uri $raUri -Operation 'List role assignments' -Scope $target.Display -TolerateErrors)) {
            $raId = ([string](Get-AzRbacProp -InputObject $ra -Name 'id')).ToLowerInvariant()
            if ($raId -and -not $assignmentById.ContainsKey($raId)) { $assignmentById[$raId] = $ra }
        }

        $eligUri = "$($script:AzRbacArmBase)$($target.Scope)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01$($target.Filter)"
        foreach ($el in @(Get-ArmPagedResults -Uri $eligUri -Operation 'List PIM eligibility' -Scope $target.Display -TolerateErrors)) {
            $p = Get-AzRbacProp -InputObject $el -Name 'properties'
            if ([string](Get-AzRbacProp -InputObject $p -Name 'memberType') -eq 'Group') { continue }
            $status = [string](Get-AzRbacProp -InputObject $p -Name 'status')
            if ($status -and $status -notin @('Provisioned', 'Accepted', 'Granted', 'AdminApproved')) { continue }
            $key = ('{0}|{1}|{2}' -f (Get-AzRbacProp -InputObject $p -Name 'principalId'), (Get-AzRbacLastSegment -Value (Get-AzRbacProp -InputObject $p -Name 'roleDefinitionId')), (Get-AzRbacProp -InputObject $p -Name 'scope')).ToLowerInvariant()
            if (-not $eligibilityByKey.ContainsKey($key)) { $eligibilityByKey[$key] = $el }
        }

        $schedUri = "$($script:AzRbacArmBase)$($target.Scope)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01$($target.Filter)"
        foreach ($si in @(Get-ArmPagedResults -Uri $schedUri -Operation 'List PIM assignment schedules' -Scope $target.Display -TolerateErrors)) {
            $p = Get-AzRbacProp -InputObject $si -Name 'properties'
            $origin = [string](Get-AzRbacProp -InputObject $p -Name 'originRoleAssignmentId')
            if ($origin) { $scheduleByOrigin[$origin.ToLowerInvariant()] = $p }
        }
    }
    Write-Progress -Activity 'Azure RBAC review' -Completed
    Write-PimLog -Message "Collected $($assignmentById.Count) active role assignments and $($eligibilityByKey.Count) PIM-eligible assignments."

    # ---- Role definitions -------------------------------------------------------------------
    # Only the role definitions actually referenced are fetched. Listing every definition returns
    # several MB of JSON, which Windows PowerShell 5.1 handles poorly.
    Write-PimLog -Message 'Reading role definitions in use.'
    $roleDefs = @{}
    $referencedRoleIds = @{}
    foreach ($ra in $assignmentById.Values) {
        $rid = [string](Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $ra -Name 'properties') -Name 'roleDefinitionId')
        if ($rid) { $referencedRoleIds[(Get-AzRbacLastSegment -Value $rid)] = $rid }
    }
    foreach ($el in $eligibilityByKey.Values) {
        $rid = [string](Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $el -Name 'properties') -Name 'roleDefinitionId')
        if ($rid) { $referencedRoleIds[(Get-AzRbacLastSegment -Value $rid)] = $rid }
    }
    foreach ($guid in @($referencedRoleIds.Keys)) {
        if ($roleDefs.ContainsKey($guid)) { continue }
        try {
            $rd = Invoke-ArmRequest -Uri ("{0}{1}?api-version=2022-04-01" -f $script:AzRbacArmBase, $referencedRoleIds[$guid])
            if ($rd) { $roleDefs[$guid] = $rd }
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read role definition $($referencedRoleIds[$guid]): $($_.Exception.Message)"
        }
    }

    $roleInfo = @{}
    foreach ($guid in @($roleDefs.Keys)) {
        $rd = $roleDefs[$guid]
        $props = Get-AzRbacProp -InputObject $rd -Name 'properties'
        $tierInfo = Get-AzRbacRoleTier -RoleDefinition $rd
        $roleType = [string](Get-AzRbacProp -InputObject $props -Name 'type')
        $roleInfo[$guid] = [pscustomobject]@{
            RoleDefinitionGuid = $guid
            RoleName           = [string](Get-AzRbacProp -InputObject $props -Name 'roleName')
            RoleType           = if ($roleType -match 'Custom') { 'Custom' } else { 'BuiltIn' }
            PrivilegeTier      = $tierInfo.Tier
            TierReason         = $tierInfo.Reason
            WildcardActions    = $tierInfo.WildcardActions
            AssignableScopes   = (@(Get-AzRbacProp -InputObject $props -Name 'assignableScopes') -join '; ')
        }
    }

    # ---- Normalise assignments --------------------------------------------------------------
    $armPrincipalTypes = @{}
    $normalised = New-Object System.Collections.ArrayList

    $addAssignment = {
        param($Props, $State, $AssignmentId, $Source)

        $principalId = ([string](Get-AzRbacProp -InputObject $Props -Name 'principalId')).ToLowerInvariant()
        $roleGuid = Get-AzRbacLastSegment -Value ([string](Get-AzRbacProp -InputObject $Props -Name 'roleDefinitionId'))
        $scopeInfo = Get-AzRbacScopeInfo -Scope ([string](Get-AzRbacProp -InputObject $Props -Name 'scope')) -ManagementGroupNames $mgNames -SubscriptionNames $subNames
        $armType = [string](Get-AzRbacProp -InputObject $Props -Name 'principalType')
        if ($principalId -and $armType -and -not $armPrincipalTypes.ContainsKey($principalId)) { $armPrincipalTypes[$principalId] = $armType }

        $role = $null
        if ($roleGuid -and $roleInfo.ContainsKey($roleGuid)) { $role = $roleInfo[$roleGuid] }

        $endDate = $null
        $startDate = $null
        $assignmentType = 'Permanent'
        if ($State -eq 'Eligible') {
            $endDate = Get-AzRbacProp -InputObject $Props -Name 'endDateTime'
            $startDate = Get-AzRbacProp -InputObject $Props -Name 'startDateTime'
            $assignmentType = if ($endDate) { 'Eligible (time-bound)' } else { 'Eligible (permanent)' }
        }
        elseif ($AssignmentId -and $scheduleByOrigin.ContainsKey($AssignmentId)) {
            $sched = $scheduleByOrigin[$AssignmentId]
            $endDate = Get-AzRbacProp -InputObject $sched -Name 'endDateTime'
            $startDate = Get-AzRbacProp -InputObject $sched -Name 'startDateTime'
            $schedType = [string](Get-AzRbacProp -InputObject $sched -Name 'assignmentType')
            if ($schedType -eq 'Activated') { $assignmentType = 'PIM activated (JIT)' }
            elseif ($endDate) { $assignmentType = 'Active (time-bound)' }
        }

        $condition = [string](Get-AzRbacProp -InputObject $Props -Name 'condition')
        $resourcesInScope = $null
        switch ($scopeInfo.ScopeLevel) {
            'Root' { $resourcesInScope = $totalResources }
            'ManagementGroup' {
                if ($resourceCountByMg.ContainsKey($scopeInfo.ManagementGroupId)) { $resourcesInScope = $resourceCountByMg[$scopeInfo.ManagementGroupId] } else { $resourcesInScope = 0 }
            }
            'Subscription' { if ($resourceCountBySub.ContainsKey($scopeInfo.SubscriptionId)) { $resourcesInScope = $resourceCountBySub[$scopeInfo.SubscriptionId] } else { $resourcesInScope = 0 } }
            'ResourceGroup' { $k = "$($scopeInfo.SubscriptionId)|$($scopeInfo.ResourceGroup)"; if ($resourceCountByRg.ContainsKey($k)) { $resourcesInScope = $resourceCountByRg[$k] } else { $resourcesInScope = 0 } }
            'Resource' { $resourcesInScope = 1 }
        }

        $null = $normalised.Add([pscustomobject]@{
            AssignmentId       = $AssignmentId
            Source             = $Source
            AssignmentState    = $State
            AssignmentType     = $assignmentType
            StartDateTime      = $startDate
            EndDateTime        = $endDate
            PrincipalId        = $principalId
            ArmPrincipalType   = $armType
            RoleDefinitionGuid = $roleGuid
            RoleName           = if ($role) { $role.RoleName } else { "Unknown role ($roleGuid)" }
            RoleType           = if ($role) { $role.RoleType } else { 'Unknown' }
            PrivilegeTier      = if ($role) { $role.PrivilegeTier } else { 'Unknown' }
            Scope              = $scopeInfo.Scope
            ScopeLevel         = $scopeInfo.ScopeLevel
            ScopeName          = $scopeInfo.ScopeName
            ManagementGroupId  = $scopeInfo.ManagementGroupId
            SubscriptionId     = $scopeInfo.SubscriptionId
            SubscriptionName   = $scopeInfo.SubscriptionName
            ResourceGroup      = $scopeInfo.ResourceGroup
            ResourceType       = $scopeInfo.ResourceType
            ResourcesInScope   = $resourcesInScope
            HasCondition       = -not [string]::IsNullOrWhiteSpace($condition)
            Condition          = $condition
            CreatedOn          = Get-AzRbacProp -InputObject $Props -Name 'createdOn'
            CreatedBy          = Get-AzRbacProp -InputObject $Props -Name 'createdBy'
            Description        = Get-AzRbacProp -InputObject $Props -Name 'description'
        })
    }

    foreach ($raId in @($assignmentById.Keys)) {
        $props = Get-AzRbacProp -InputObject $assignmentById[$raId] -Name 'properties'
        & $addAssignment $props 'Active' $raId 'roleAssignments'
    }
    foreach ($key in @($eligibilityByKey.Keys)) {
        $el = $eligibilityByKey[$key]
        $props = Get-AzRbacProp -InputObject $el -Name 'properties'
        $elId = ([string](Get-AzRbacProp -InputObject $el -Name 'id')).ToLowerInvariant()
        & $addAssignment $props 'Eligible' $elId 'roleEligibilityScheduleInstances'
    }

    # Out-of-scope subscriptions can surface through 'below' listings at management group level. Keep them,
    # but they will not appear in the subscription matrix.

    # ---- Resolve principals and expand groups -----------------------------------------------
    Write-PimLog -Message "Resolving $(@($normalised | Select-Object -ExpandProperty PrincipalId -Unique).Count) principals through Microsoft Graph."
    $principals = Resolve-AzRbacPrincipals -PrincipalIds @($normalised | ForEach-Object { $_.PrincipalId }) -ArmPrincipalTypes $armPrincipalTypes

    foreach ($a in $normalised) {
        $p = $null
        if ($principals.ContainsKey($a.PrincipalId)) { $p = $principals[$a.PrincipalId] }
        $a | Add-Member -NotePropertyName PrincipalType -NotePropertyValue $(if ($p) { $p.PrincipalType } else { $a.ArmPrincipalType }) -Force
        $a | Add-Member -NotePropertyName PrincipalCategory -NotePropertyValue $(if ($p) { $p.Category } else { 'Unresolved' }) -Force
        $a | Add-Member -NotePropertyName PrincipalDisplayName -NotePropertyValue $(if ($p) { $p.DisplayName } else { $a.PrincipalId }) -Force
        $a | Add-Member -NotePropertyName PrincipalUserPrincipalName -NotePropertyValue $(if ($p) { $p.UserPrincipalName } else { $null }) -Force
        $a | Add-Member -NotePropertyName AccountEnabled -NotePropertyValue $(if ($p) { $p.AccountEnabled } else { $null }) -Force
        $a | Add-Member -NotePropertyName PrincipalResolved -NotePropertyValue $(if ($p) { $p.Resolved } else { $false }) -Force
    }

    $groupMembers = New-Object System.Collections.ArrayList
    $groupOwners = New-Object System.Collections.ArrayList
    $groupExpansion = @{}
    $groupIds = @($normalised | Where-Object { $_.PrincipalType -eq 'Group' -and $_.PrincipalResolved } | Select-Object -ExpandProperty PrincipalId -Unique)
    Write-PimLog -Message "Expanding $($groupIds.Count) groups that hold Azure roles."

    foreach ($gid in $groupIds) {
        $gName = $principals[$gid].DisplayName
        $expansion = Get-AzRbacGroupExpansion -GroupId $gid -GroupDisplayName $gName -IncludePimForGroups:$IncludePimForGroups
        $groupExpansion[$gid] = $expansion
        foreach ($m in @($expansion.Members)) { $null = $groupMembers.Add($m) }

        $groupTiers = @($normalised | Where-Object { $_.PrincipalId -eq $gid } | ForEach-Object { $_.PrivilegeTier })
        $highestGroupTier = @($groupTiers | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_ }; Descending = $true } | Select-Object -First 1)
        foreach ($o in @($expansion.Owners)) {
            $o | Add-Member -NotePropertyName HighestGroupTier -NotePropertyValue $(if ($highestGroupTier.Count -gt 0) { $highestGroupTier[0] } else { $null }) -Force
            $o | Add-Member -NotePropertyName IsAssignableToRole -NotePropertyValue $principals[$gid].IsAssignableToRole -Force
            $null = $groupOwners.Add($o)
        }
    }

    # ---- Effective access rows (one per principal per assignment) ---------------------------
    $accessRows = New-Object System.Collections.ArrayList
    foreach ($a in $normalised) {
        $base = [ordered]@{
            RoleName         = $a.RoleName
            RoleType         = $a.RoleType
            PrivilegeTier    = $a.PrivilegeTier
            ScopeLevel       = $a.ScopeLevel
            ScopeName        = $a.ScopeName
            SubscriptionName = $a.SubscriptionName
            ResourceGroup    = $a.ResourceGroup
            ResourcesInScope = $a.ResourcesInScope
            AssignmentState  = $a.AssignmentState
            AssignmentType   = $a.AssignmentType
            EndDateTime      = $a.EndDateTime
            HasCondition     = $a.HasCondition
            Scope            = $a.Scope
            SubscriptionId   = $a.SubscriptionId
            ManagementGroupId = $a.ManagementGroupId
            AssignmentId     = $a.AssignmentId
        }

        if ($a.PrincipalType -eq 'Group' -and $groupExpansion.ContainsKey($a.PrincipalId)) {
            $members = @($groupExpansion[$a.PrincipalId].Members)
            if ($members.Count -eq 0) {
                $failed = [bool]$groupExpansion[$a.PrincipalId].ExpansionFailed
                $label = if ($failed) { 'membership could not be read' } else { 'empty group' }
                $row = [ordered]@{
                    PrincipalId = $a.PrincipalId; DisplayName = "$($a.PrincipalDisplayName) ($label)"; UserPrincipalName = $null
                    PrincipalCategory = 'Group'; AccountEnabled = $null; AccessPath = $(if ($failed) { 'Group (expansion failed)' } else { 'Group (no members)' }); ViaGroupName = $a.PrincipalDisplayName; ViaGroupId = $a.PrincipalId; MembershipType = $null
                    EffectiveState = $a.AssignmentState; IsStanding = $false
                }
                foreach ($k in $base.Keys) { $row[$k] = $base[$k] }
                $null = $accessRows.Add([pscustomobject]$row)
                continue
            }

            foreach ($m in $members) {
                $effectiveState = $a.AssignmentState
                if ($m.MembershipType -like 'Eligible*') { $effectiveState = 'Eligible' }
                $isStanding = ($effectiveState -eq 'Active') -and ($a.AssignmentType -eq 'Permanent')

                $row = [ordered]@{
                    PrincipalId = $m.MemberId; DisplayName = $m.DisplayName; UserPrincipalName = $m.UserPrincipalName
                    PrincipalCategory = $m.Category; AccountEnabled = $m.AccountEnabled; AccessPath = 'Group'; ViaGroupName = $a.PrincipalDisplayName; ViaGroupId = $a.PrincipalId; MembershipType = $m.MembershipType
                    EffectiveState = $effectiveState; IsStanding = $isStanding
                }
                foreach ($k in $base.Keys) { $row[$k] = $base[$k] }
                $null = $accessRows.Add([pscustomobject]$row)
            }
        }
        else {
            $row = [ordered]@{
                PrincipalId = $a.PrincipalId; DisplayName = $a.PrincipalDisplayName; UserPrincipalName = $a.PrincipalUserPrincipalName
                PrincipalCategory = $a.PrincipalCategory; AccountEnabled = $a.AccountEnabled; AccessPath = 'Direct'; ViaGroupName = $null; ViaGroupId = $null; MembershipType = $null
                EffectiveState = $a.AssignmentState; IsStanding = ($a.AssignmentState -eq 'Active') -and ($a.AssignmentType -eq 'Permanent')
            }
            foreach ($k in $base.Keys) { $row[$k] = $base[$k] }
            $null = $accessRows.Add([pscustomobject]$row)
        }
    }
    Write-PimLog -Message "Built $($accessRows.Count) effective access rows."

    # Which subscriptions does a root or management group scope reach? Cached per management group.
    $mgReachCache = @{}
    $getReachedSubs = {
        param($Row)
        if ($Row.ScopeLevel -eq 'Root') { return @($subIds) }
        if ($Row.ScopeLevel -eq 'ManagementGroup') {
            $mgKey = [string]$Row.ManagementGroupId
            if (-not $mgReachCache.ContainsKey($mgKey)) {
                $mgReachCache[$mgKey] = @($subIds | Where-Object { $subMgChain.ContainsKey($_) -and (@($subMgChain[$_]) -contains $mgKey) })
            }
            return @($mgReachCache[$mgKey])
        }
        return @()
    }

    # Index every non-group access row by the subscriptions it reaches (including inheritance).
    $rowsBySub = @{}
    foreach ($r in $accessRows) {
        if ($r.PrincipalCategory -eq 'Group') { continue }
        $targets = @()
        if ($r.ScopeLevel -in @('Root', 'ManagementGroup')) { $targets = @(& $getReachedSubs $r) }
        elseif ($r.SubscriptionId) { $targets = @($r.SubscriptionId) }
        foreach ($sid in $targets) {
            if (-not $rowsBySub.ContainsKey($sid)) { $rowsBySub[$sid] = New-Object System.Collections.ArrayList }
            $null = $rowsBySub[$sid].Add($r)
        }
    }

    # ---- Per principal summary ---------------------------------------------------------------
    $userSummary = New-Object System.Collections.ArrayList
    $principalSubCells = @{}

    foreach ($grp in @($accessRows | Where-Object { $_.PrincipalCategory -ne 'Group' } | Group-Object -Property PrincipalId)) {
        $rows = @($grp.Group)
        $first = $rows[0]

        $fullSubs = @{}
        $partialRg = @{}
        $partialRes = @{}
        $cells = @{}

        foreach ($r in $rows) {
            $label = if ($r.EffectiveState -eq 'Eligible') { "$($r.RoleName) [Eligible]" } else { $r.RoleName }
            if ($r.ScopeLevel -in @('Root', 'ManagementGroup')) {
                foreach ($sid in (& $getReachedSubs $r)) {
                    $fullSubs[$sid] = $true
                    if (-not $cells.ContainsKey($sid)) { $cells[$sid] = New-Object System.Collections.ArrayList }
                    $null = $cells[$sid].Add("$label (inherited)")
                }
            }
            elseif ($r.ScopeLevel -eq 'Subscription') {
                $fullSubs[$r.SubscriptionId] = $true
                if (-not $cells.ContainsKey($r.SubscriptionId)) { $cells[$r.SubscriptionId] = New-Object System.Collections.ArrayList }
                $null = $cells[$r.SubscriptionId].Add($label)
            }
            elseif ($r.ScopeLevel -eq 'ResourceGroup') {
                $partialRg["$($r.SubscriptionId)|$($r.ResourceGroup)"] = $r
                if ($r.SubscriptionId) {
                    if (-not $cells.ContainsKey($r.SubscriptionId)) { $cells[$r.SubscriptionId] = New-Object System.Collections.ArrayList }
                    $null = $cells[$r.SubscriptionId].Add("$label @ RG $($r.ScopeName)")
                }
            }
            elseif ($r.ScopeLevel -eq 'Resource') {
                $partialRes[$r.Scope.ToLowerInvariant()] = $r
                if ($r.SubscriptionId) {
                    if (-not $cells.ContainsKey($r.SubscriptionId)) { $cells[$r.SubscriptionId] = New-Object System.Collections.ArrayList }
                    $null = $cells[$r.SubscriptionId].Add("$label @ $($r.ScopeName)")
                }
            }
        }

        $resourcesReachable = 0
        foreach ($sid in @($fullSubs.Keys)) { if ($resourceCountBySub.ContainsKey($sid)) { $resourcesReachable += $resourceCountBySub[$sid] } }
        foreach ($k in @($partialRg.Keys)) {
            $sid = $k.Split('|')[0]
            if ($fullSubs.ContainsKey($sid)) { continue }
            if ($resourceCountByRg.ContainsKey($k)) { $resourcesReachable += $resourceCountByRg[$k] }
        }
        foreach ($k in @($partialRes.Keys)) {
            $r = $partialRes[$k]
            if ($fullSubs.ContainsKey($r.SubscriptionId)) { continue }
            if ($partialRg.ContainsKey("$($r.SubscriptionId)|$($r.ResourceGroup)")) { continue }
            $resourcesReachable += 1
        }

        $reachedSubIds = @($cells.Keys)
        $highest = @($rows | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true } | Select-Object -First 1)[0].PrivilegeTier
        $privRows = @($rows | Where-Object { (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })
        $criticalAccess = @($rows | Where-Object { $_.PrivilegeTier -eq 'Critical' } | ForEach-Object {
            $suffix = if ($_.EffectiveState -eq 'Eligible') { ' [Eligible]' } else { '' }
            "$($_.RoleName) @ $($_.ScopeName)$suffix"
        } | Select-Object -Unique)
        $criticalText = (@($criticalAccess | Select-Object -First 10) -join '; ')
        if ($criticalAccess.Count -gt 10) { $criticalText += "; +$($criticalAccess.Count - 10) more" }

        $null = $userSummary.Add([pscustomobject]@{
            DisplayName             = $first.DisplayName
            UserPrincipalName       = $first.UserPrincipalName
            PrincipalCategory       = $first.PrincipalCategory
            AccountEnabled          = $first.AccountEnabled
            HighestTier             = $highest
            TotalAccessPaths        = $rows.Count
            ActivePaths             = @($rows | Where-Object { $_.EffectiveState -eq 'Active' }).Count
            EligiblePaths           = @($rows | Where-Object { $_.EffectiveState -eq 'Eligible' }).Count
            StandingPrivilegedCount = @($privRows | Where-Object { $_.IsStanding }).Count
            EligiblePrivilegedCount = @($privRows | Where-Object { $_.EffectiveState -eq 'Eligible' }).Count
            DirectPaths             = @($rows | Where-Object { $_.AccessPath -eq 'Direct' }).Count
            GroupPaths              = @($rows | Where-Object { $_.AccessPath -eq 'Group' }).Count
            ViaGroups               = (@($rows | Where-Object { $_.ViaGroupName } | Select-Object -ExpandProperty ViaGroupName -Unique) -join '; ')
            SubscriptionsReachable  = $reachedSubIds.Count
            SubscriptionsFull       = $fullSubs.Count
            ResourcesReachable      = $resourcesReachable
            CriticalAccess          = $criticalText
            PrincipalId             = $grp.Name
        })

        $principalSubCells[$grp.Name] = $cells
    }

    # ---- Access matrix: principals x subscriptions ------------------------------------------
    $subColumnNames = @{}
    $usedNames = @{}
    foreach ($sid in ($subIds | Sort-Object -Property @{ Expression = { $subNames[$_] } })) {
        $colName = "$($subNames[$sid])"
        if ([string]::IsNullOrWhiteSpace($colName)) { $colName = $sid }
        if ($usedNames.ContainsKey($colName.ToLowerInvariant())) { $colName = "$colName ($($sid.Substring(0, 8)))" }
        $usedNames[$colName.ToLowerInvariant()] = $true
        $subColumnNames[$sid] = $colName
    }
    $orderedSubIds = @($subIds | Sort-Object -Property @{ Expression = { $subColumnNames[$_] } })

    $matrix = New-Object System.Collections.ArrayList
    foreach ($u in ($userSummary | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, DisplayName)) {
        $row = [ordered]@{
            DisplayName       = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            PrincipalCategory = $u.PrincipalCategory
            HighestTier       = $u.HighestTier
        }
        $cells = $principalSubCells[$u.PrincipalId]
        foreach ($sid in $orderedSubIds) {
            $value = ''
            if ($cells -and $cells.ContainsKey($sid)) {
                $items = @($cells[$sid] | Select-Object -Unique)
                $value = (@($items | Select-Object -First 6) -join '; ')
                if ($items.Count -gt 6) { $value += "; +$($items.Count - 6) more" }
            }
            $row[$subColumnNames[$sid]] = $value
        }
        $null = $matrix.Add([pscustomobject]$row)
    }

    # ---- Subscription summary ----------------------------------------------------------------
    $subscriptionSummary = New-Object System.Collections.ArrayList
    foreach ($sid in $orderedSubIds) {
        $effective = @()
        if ($rowsBySub.ContainsKey($sid)) { $effective = @($rowsBySub[$sid]) }
        $atOrAbove = @($effective | Where-Object { $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') })
        $owners = @($atOrAbove | Where-Object { $_.PrivilegeTier -eq 'Critical' -and $_.PrincipalCategory -in @('Member', 'Guest') })
        $standingOwners = @($owners | Where-Object { $_.IsStanding } | Select-Object -ExpandProperty PrincipalId -Unique)
        $eligibleOwners = @($owners | Where-Object { $_.EffectiveState -eq 'Eligible' } | Select-Object -ExpandProperty PrincipalId -Unique)
        $allOwners = @($owners | Select-Object -ExpandProperty PrincipalId -Unique)
        $pimEligible = @($normalised | Where-Object { $_.SubscriptionId -eq $sid -and $_.AssignmentState -eq 'Eligible' }).Count
        $guests = @($effective | Where-Object { $_.PrincipalCategory -eq 'Guest' } | Select-Object -ExpandProperty PrincipalId -Unique)

        $risk = 'Low'
        if ($standingOwners.Count -gt $MaxOwnersPerSubscription) { $risk = 'High' }
        elseif ($standingOwners.Count -gt 0 -and $pimEligible -eq 0) { $risk = 'Medium' }
        elseif ($guests.Count -gt 0) { $risk = 'Medium' }

        $null = $subscriptionSummary.Add([pscustomobject]@{
            SubscriptionName       = $subNames[$sid]
            SubscriptionId         = $sid
            State                  = $subStates[$sid]
            ManagementGroupPath    = if ($subMgPath.ContainsKey($sid)) { $subMgPath[$sid] } else { $null }
            ResourceGroups         = if ($rgCountBySub.ContainsKey($sid)) { $rgCountBySub[$sid] } else { $null }
            Resources              = if ($resourceCountBySub.ContainsKey($sid)) { $resourceCountBySub[$sid] } else { 0 }
            AssignmentsAtOrBelow   = @($normalised | Where-Object { $_.SubscriptionId -eq $sid }).Count
            EffectivePrincipals    = @($effective | Select-Object -ExpandProperty PrincipalId -Unique).Count
            EffectiveOwners        = $allOwners.Count
            StandingOwners         = $standingOwners.Count
            EligibleOwners         = $eligibleOwners.Count
            GuestsWithAccess       = $guests.Count
            PimEligibleAssignments = $pimEligible
            RiskRating             = $risk
        })
    }

    # ---- Custom roles -----------------------------------------------------------------------
    $customRoles = @(
        $roleInfo.Values |
        Where-Object { $_.RoleType -eq 'Custom' } |
        ForEach-Object {
            $guid = $_.RoleDefinitionGuid
            [pscustomobject]@{
                RoleName         = $_.RoleName
                PrivilegeTier    = $_.PrivilegeTier
                AssignmentCount  = @($normalised | Where-Object { $_.RoleDefinitionGuid -eq $guid }).Count
                WildcardActions  = $_.WildcardActions
                TierReason       = $_.TierReason
                AssignableScopes = $_.AssignableScopes
                RoleDefinitionId = $guid
            }
        } |
        Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true }, @{ Expression = 'AssignmentCount'; Descending = $true }
    )

    # ---- Findings ---------------------------------------------------------------------------
    $findings = New-Object System.Collections.ArrayList
    $addFinding = {
        param($Rating, $Type, $Subject, $RoleName, $ScopeName, $Details, $Recommendation, $Scope)
        $null = $findings.Add([pscustomobject]@{
            RiskRating     = $Rating
            FindingType    = $Type
            Subject        = $Subject
            RoleName       = $RoleName
            ScopeName      = $ScopeName
            Details        = $Details
            Recommendation = $Recommendation
            Scope          = $Scope
        })
    }

    foreach ($a in @($normalised | Where-Object { $_.ScopeLevel -eq 'Root' })) {
        & $addFinding 'Critical' 'RootScopeAssignment' $a.PrincipalDisplayName $a.RoleName $a.ScopeName "$($a.AssignmentState) $($a.AssignmentType) assignment at tenant root (/), reaching every management group, subscription and resource." 'Remove role assignments at root scope. These are usually left behind after Elevate Access by a Global Administrator. Use the Tenant Root Group management group with PIM instead.' $a.Scope
    }

    foreach ($r in @($accessRows | Where-Object { $_.IsStanding -and $_.PrincipalCategory -in @('Member', 'Guest') -and $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') })) {
        $via = if ($r.AccessPath -eq 'Group') { " via group $($r.ViaGroupName)" } else { ' (direct)' }
        if ($r.PrivilegeTier -eq 'Critical') {
            & $addFinding 'High' 'StandingCriticalAccess' $r.DisplayName $r.RoleName $r.ScopeName "Permanent active $($r.RoleName) at $($r.ScopeLevel) scope$via. Can grant any access in $($r.ResourcesInScope) resources." 'Convert to a PIM-eligible assignment with approval and MFA on activation, or remove.' $r.Scope
        }
        elseif ($r.PrivilegeTier -eq 'High') {
            & $addFinding 'Medium' 'StandingHighAccess' $r.DisplayName $r.RoleName $r.ScopeName "Permanent active $($r.RoleName) at $($r.ScopeLevel) scope$via." 'Convert to a PIM-eligible assignment, or reduce scope to the resource groups actually needed.' $r.Scope
        }
    }

    foreach ($grp in @($accessRows | Where-Object { $_.PrincipalCategory -eq 'Guest' } | Group-Object -Property PrincipalId)) {
        $rows = @($grp.Group)
        $top = @($rows | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true })[0]
        $rating = if ((Get-AzRbacTierRank -Tier $top.PrivilegeTier) -ge 3) { 'High' } else { 'Medium' }
        $roles = (@($rows | ForEach-Object { "$($_.RoleName) @ $($_.ScopeName)" } | Select-Object -Unique | Select-Object -First 8) -join '; ')
        & $addFinding $rating 'GuestAzureAccess' $top.DisplayName $top.RoleName $top.ScopeName "Guest account holds $($rows.Count) Azure access path(s): $roles" 'Confirm a current business need and sponsor, place under an access review, and prefer eligible over active assignments.' $top.Scope
    }

    foreach ($a in @($normalised | Where-Object { -not $_.PrincipalResolved })) {
        & $addFinding 'Medium' 'OrphanedAssignment' $a.PrincipalId $a.RoleName $a.ScopeName "Assignment ($($a.AssignmentState)) to a principal that no longer exists or cannot be read. ARM principal type: $($a.ArmPrincipalType)." 'Delete the orphaned assignment. If the identity was deleted, the assignment can be silently reused if the object is restored.' $a.Scope
    }

    foreach ($grp in @($accessRows | Where-Object { $_.PrincipalCategory -in @('Member', 'Guest') -and $_.AccountEnabled -eq $false } | Group-Object -Property PrincipalId)) {
        $first = $grp.Group[0]
        & $addFinding 'Medium' 'DisabledAccountWithAccess' $first.DisplayName $first.RoleName $first.ScopeName "Disabled account still holds $($grp.Count) Azure access path(s)." 'Remove Azure role assignments and group memberships as part of leaver processing.' $first.Scope
    }

    foreach ($r in @($accessRows | Where-Object { $_.PrincipalCategory -in @('ServicePrincipal', 'ManagedIdentity') -and $_.EffectiveState -eq 'Active' -and $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })) {
        $rating = if ($r.PrivilegeTier -eq 'Critical' -or $r.ScopeLevel -ne 'Subscription') { 'High' } else { 'Medium' }
        & $addFinding $rating 'WorkloadIdentityBroadAccess' $r.DisplayName $r.RoleName $r.ScopeName "$($r.PrincipalCategory) holds $($r.RoleName) at $($r.ScopeLevel) scope." 'Scope workload identities to the resource groups they deploy to. Avoid Owner or User Access Administrator for automation; use a constrained Role Based Access Control Administrator condition if role assignment is required.' $r.Scope
    }

    $directSeen = @{}
    foreach ($a in @($normalised | Where-Object { $_.PrincipalCategory -in @('Member', 'Guest') -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })) {
        # An eligible assignment and its PIM activation are the same grant; report it once.
        $directKey = "$($a.PrincipalId)|$($a.RoleDefinitionGuid)|$($a.Scope)".ToLowerInvariant()
        if ($directSeen.ContainsKey($directKey)) { continue }
        $directSeen[$directKey] = $true
        & $addFinding 'Low' 'DirectUserAssignment' $a.PrincipalDisplayName $a.RoleName $a.ScopeName "$($a.RoleName) assigned directly to the user ($($a.AssignmentState))." 'Assign privileged Azure roles to role-assignable groups (or PIM for Groups) so membership is reviewed in one place.' $a.Scope
    }

    foreach ($a in @($normalised | Where-Object { $_.AssignmentState -eq 'Eligible' -and $_.AssignmentType -eq 'Eligible (permanent)' -and $_.PrivilegeTier -eq 'Critical' })) {
        & $addFinding 'Low' 'PermanentEligibility' $a.PrincipalDisplayName $a.RoleName $a.ScopeName 'Eligible assignment for a Critical-tier role has no end date.' 'Set an eligibility expiry (for example 12 months) and cover it with an access review.' $a.Scope
    }

    foreach ($cr in @($customRoles | Where-Object { $_.AssignmentCount -gt 0 -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })) {
        & $addFinding 'High' 'PrivilegedCustomRole' $cr.RoleName $cr.RoleName $cr.AssignableScopes "Custom role is $($cr.PrivilegeTier) tier: $($cr.TierReason) Wildcards: $($cr.WildcardActions)" 'Replace wildcard actions with the specific operations needed, or use the equivalent built-in role so the privilege is obvious to reviewers.' $null
    }

    foreach ($s in @($subscriptionSummary)) {
        if ($s.StandingOwners -gt $MaxOwnersPerSubscription) {
            & $addFinding 'Medium' 'ExcessiveSubscriptionOwners' $s.SubscriptionName 'Critical-tier roles' $s.SubscriptionName "$($s.StandingOwners) users hold standing Critical-tier access (target: <= $MaxOwnersPerSubscription)." 'Reduce standing owners; keep the rest as PIM-eligible.' "/subscriptions/$($s.SubscriptionId)"
        }
        if ($s.StandingOwners -gt 0 -and $s.PimEligibleAssignments -eq 0) {
            & $addFinding 'Medium' 'NoPimInSubscription' $s.SubscriptionName 'All' $s.SubscriptionName 'Privileged access exists but no PIM-eligible assignments were found at or below this subscription.' 'Onboard the subscription to PIM for Azure resources and move privileged roles to eligible.' "/subscriptions/$($s.SubscriptionId)"
        }
    }

    foreach ($gid in $groupIds) {
        $groupAssignments = @($normalised | Where-Object { $_.PrincipalId -eq $gid })
        $top = @($groupAssignments | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true })[0]
        if ((Get-AzRbacTierRank -Tier $top.PrivilegeTier) -lt 3) { continue }

        if ($groupExpansion[$gid].ExpansionFailed) {
            & $addFinding 'Medium' 'GroupMembershipUnreadable' $top.PrincipalDisplayName $top.RoleName $top.ScopeName "Group holds $($top.RoleName) but its membership could not be read, so the users with this access are not listed in this report." 'Check the review account can read group membership (Group.Read.All) and re-run.' $top.Scope
        }

        $owners = @($groupExpansion[$gid].Owners)
        if ($owners.Count -gt 0) {
            $ownerNames = (@($owners | ForEach-Object { if ($_.OwnerUserPrincipalName) { $_.OwnerUserPrincipalName } else { $_.OwnerDisplayName } }) -join '; ')
            & $addFinding 'Medium' 'GroupOwnerEscalationPath' $top.PrincipalDisplayName $top.RoleName $top.ScopeName "Group holds $($top.RoleName) and has $($owners.Count) owner(s) who can add members: $ownerNames" 'Remove group owners, or make sure every owner is already entitled to the access the group grants. Use PIM for Groups for privileged access groups.' $top.Scope
        }

        if ($principals[$gid].IsAssignableToRole -eq $false) {
            & $addFinding 'Medium' 'NonRoleAssignableGroup' $top.PrincipalDisplayName $top.RoleName $top.ScopeName "Group holding $($top.RoleName) is not role-assignable, so Groups Administrators, User Administrators and other Entra roles can change its membership." 'Use a role-assignable group (isAssignableToRole) for privileged Azure access so only Privileged Role Administrators can manage membership.' $top.Scope
        }
    }

    # ---- Scorecard --------------------------------------------------------------------------
    $privilegedUserRows = @($accessRows | Where-Object { $_.PrincipalCategory -in @('Member', 'Guest') -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })
    $standingPriv = @($privilegedUserRows | Where-Object { $_.IsStanding }).Count
    $eligiblePriv = @($privilegedUserRows | Where-Object { $_.EffectiveState -eq 'Eligible' }).Count
    $pimCoverage = if (($standingPriv + $eligiblePriv) -gt 0) { [Math]::Round(($eligiblePriv / ($standingPriv + $eligiblePriv)) * 100, 1) } else { 100 }
    $standingCriticalUsers = @($accessRows | Where-Object { $_.IsStanding -and $_.PrivilegeTier -eq 'Critical' -and $_.PrincipalCategory -in @('Member', 'Guest') } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $rootCount = @($normalised | Where-Object { $_.ScopeLevel -eq 'Root' }).Count
    $guestPriv = @($privilegedUserRows | Where-Object { $_.PrincipalCategory -eq 'Guest' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $orphaned = @($normalised | Where-Object { -not $_.PrincipalResolved }).Count
    $spCritical = @($accessRows | Where-Object { $_.PrincipalCategory -in @('ServicePrincipal', 'ManagedIdentity') -and $_.PrivilegeTier -eq 'Critical' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $subsOverLimit = @($subscriptionSummary | Where-Object { $_.StandingOwners -gt $MaxOwnersPerSubscription }).Count

    $scorecard = @(
        [pscustomobject]@{ Metric = 'ManagementGroupsVisible'; Value = $mgNames.Count; Status = 'Info'; Target = ''; Commentary = 'Management groups readable by the review account.' },
        [pscustomobject]@{ Metric = 'SubscriptionsReviewed'; Value = $subIds.Count; Status = 'Info'; Target = ''; Commentary = 'Subscriptions in scope for this review.' },
        [pscustomobject]@{ Metric = 'ResourcesInScope'; Value = $totalResources; Status = 'Info'; Target = ''; Commentary = 'Resources counted through Azure Resource Graph.' },
        [pscustomobject]@{ Metric = 'ActiveAssignments'; Value = @($normalised | Where-Object { $_.AssignmentState -eq 'Active' }).Count; Status = 'Info'; Target = ''; Commentary = 'Active role assignments at every scope.' },
        [pscustomobject]@{ Metric = 'EligibleAssignments'; Value = @($normalised | Where-Object { $_.AssignmentState -eq 'Eligible' }).Count; Status = 'Info'; Target = ''; Commentary = 'PIM for Azure resources eligible assignments.' },
        [pscustomobject]@{ Metric = 'PrivilegedPimCoveragePercent'; Value = $pimCoverage; Status = $(if ($pimCoverage -ge 90) { 'Green' } elseif ($pimCoverage -ge 60) { 'Amber' } else { 'Red' }); Target = '>= 90'; Commentary = 'Share of user access paths to Critical/High roles that are eligible rather than standing.' },
        [pscustomobject]@{ Metric = 'UsersWithStandingCriticalAccess'; Value = $standingCriticalUsers; Status = $(if ($standingCriticalUsers -le 2) { 'Green' } elseif ($standingCriticalUsers -le 5) { 'Amber' } else { 'Red' }); Target = '<= 2'; Commentary = 'Users with permanent Owner, User Access Administrator or equivalent anywhere in Azure.' },
        [pscustomobject]@{ Metric = 'RootScopeAssignments'; Value = $rootCount; Status = $(if ($rootCount -eq 0) { 'Green' } else { 'Red' }); Target = '0'; Commentary = 'Assignments at tenant root (/).' },
        [pscustomobject]@{ Metric = 'GuestsWithPrivilegedAccess'; Value = $guestPriv; Status = $(if ($guestPriv -eq 0) { 'Green' } else { 'Red' }); Target = '0'; Commentary = 'Guest accounts with Critical or High tier Azure roles.' },
        [pscustomobject]@{ Metric = 'OrphanedAssignments'; Value = $orphaned; Status = $(if ($orphaned -eq 0) { 'Green' } else { 'Amber' }); Target = '0'; Commentary = 'Assignments to deleted or unreadable principals.' },
        [pscustomobject]@{ Metric = 'WorkloadIdentitiesWithCriticalRoles'; Value = $spCritical; Status = $(if ($spCritical -eq 0) { 'Green' } else { 'Amber' }); Target = '0'; Commentary = 'Service principals and managed identities that can manage role assignments.' },
        [pscustomobject]@{ Metric = 'SubscriptionsOverOwnerLimit'; Value = $subsOverLimit; Status = $(if ($subsOverLimit -eq 0) { 'Green' } else { 'Red' }); Target = '0'; Commentary = "Subscriptions with more than $MaxOwnersPerSubscription standing Critical-tier users." },
        [pscustomobject]@{ Metric = 'CoverageGaps'; Value = $script:AzRbacCoverageGaps.Count; Status = $(if ($script:AzRbacCoverageGaps.Count -eq 0) { 'Green' } else { 'Amber' }); Target = '0'; Commentary = 'Scopes or APIs the review account could not read.' }
    )

    # ---- Optional resource-level access ------------------------------------------------------
    $resourceAccessPath = $null
    if ($IncludeResourceLevelAccess -and $subIds.Count -gt 0) {
        Write-PimLog -Message 'Building resource-level access (one row per resource per principal). This can be large.'
        $resourceAccessPath = Join-Path -Path $rawFolder -ChildPath 'AzureResourceAccess.csv'
        if (Test-Path -Path $resourceAccessPath) { Remove-Item -Path $resourceAccessPath -Force }

        $bySub = @{}
        $byRg = @{}
        $byRes = @{}
        foreach ($r in @($accessRows | Where-Object { $_.PrincipalCategory -ne 'Group' })) {
            if ($r.ScopeLevel -in @('Root', 'ManagementGroup')) {
                foreach ($sid in (& $getReachedSubs $r)) {
                    if (-not $bySub.ContainsKey($sid)) { $bySub[$sid] = New-Object System.Collections.ArrayList }
                    $null = $bySub[$sid].Add($r)
                }
            }
            elseif ($r.ScopeLevel -eq 'Subscription') {
                if (-not $bySub.ContainsKey($r.SubscriptionId)) { $bySub[$r.SubscriptionId] = New-Object System.Collections.ArrayList }
                $null = $bySub[$r.SubscriptionId].Add($r)
            }
            elseif ($r.ScopeLevel -eq 'ResourceGroup') {
                $k = "$($r.SubscriptionId)|$($r.ResourceGroup)"
                if (-not $byRg.ContainsKey($k)) { $byRg[$k] = New-Object System.Collections.ArrayList }
                $null = $byRg[$k].Add($r)
            }
            elseif ($r.ScopeLevel -eq 'Resource') {
                $k = $r.Scope.ToLowerInvariant()
                if (-not $byRes.ContainsKey($k)) { $byRes[$k] = New-Object System.Collections.ArrayList }
                $null = $byRes[$k].Add($r)
            }
        }

        $resources = @()
        try {
            $resources = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $subIds -Query 'resources | project id = tolower(id), name, type, resourceGroup = tolower(resourceGroup), subscriptionId = tolower(subscriptionId), location')
        }
        catch {
            Write-PimLog -Level WARN -Message "Resource inventory query failed: $($_.Exception.Message)"
        }

        $buffer = New-Object System.Collections.ArrayList
        $written = 0
        foreach ($res in $resources) {
            $applicable = @()
            if ($bySub.ContainsKey($res.subscriptionId)) { $applicable += @($bySub[$res.subscriptionId]) }
            $rgKey = "$($res.subscriptionId)|$($res.resourceGroup)"
            if ($byRg.ContainsKey($rgKey)) { $applicable += @($byRg[$rgKey]) }
            # Child resources (for example a SQL database) inherit from their parent resource scope.
            foreach ($k in @($byRes.Keys)) {
                if ($res.id -eq $k -or $res.id.StartsWith("$k/")) { $applicable += @($byRes[$k]) }
            }

            foreach ($pg in @($applicable | Group-Object -Property PrincipalId)) {
                $rows = @($pg.Group)
                $first = $rows[0]
                $top = @($rows | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true })[0]
                $null = $buffer.Add([pscustomobject]@{
                    SubscriptionName  = $subNames[$res.subscriptionId]
                    ResourceGroup     = $res.resourceGroup
                    ResourceName      = $res.name
                    ResourceType      = $res.type
                    DisplayName       = $first.DisplayName
                    UserPrincipalName = $first.UserPrincipalName
                    PrincipalCategory = $first.PrincipalCategory
                    HighestTier       = $top.PrivilegeTier
                    Roles             = (@($rows | ForEach-Object {
                        $state = if ($_.EffectiveState -eq 'Eligible') { ' [Eligible]' } else { '' }
                        "$($_.RoleName)$state from $($_.ScopeLevel) $($_.ScopeName)"
                    } | Select-Object -Unique) -join '; ')
                    ResourceId        = $res.id
                    PrincipalId       = $pg.Name
                })
            }

            if ($buffer.Count -ge 5000) {
                $buffer | Export-Csv -Path $resourceAccessPath -NoTypeInformation -Encoding UTF8 -Append
                $written += $buffer.Count
                $buffer.Clear()
            }
        }
        if ($buffer.Count -gt 0) {
            $buffer | Export-Csv -Path $resourceAccessPath -NoTypeInformation -Encoding UTF8 -Append
            $written += $buffer.Count
        }
        Write-PimLog -Message "Resource-level access: $written rows across $($resources.Count) resources written to $resourceAccessPath"
    }

    # ---- Export -----------------------------------------------------------------------------
    $assignmentExport = @($normalised | Select-Object PrincipalDisplayName, PrincipalUserPrincipalName, PrincipalCategory, PrincipalType, AccountEnabled, PrincipalResolved, RoleName, RoleType, PrivilegeTier, ScopeLevel, ScopeName, SubscriptionName, ResourceGroup, ResourceType, ResourcesInScope, AssignmentState, AssignmentType, StartDateTime, EndDateTime, HasCondition, Condition, CreatedOn, CreatedBy, Description, Scope, SubscriptionId, ManagementGroupId, PrincipalId, RoleDefinitionGuid, AssignmentId, Source)
    $accessExport = @($accessRows | Select-Object DisplayName, UserPrincipalName, PrincipalCategory, AccountEnabled, AccessPath, ViaGroupName, MembershipType, RoleName, RoleType, PrivilegeTier, ScopeLevel, ScopeName, SubscriptionName, ResourceGroup, ResourcesInScope, AssignmentState, EffectiveState, AssignmentType, IsStanding, EndDateTime, HasCondition, Scope, SubscriptionId, ManagementGroupId, PrincipalId, ViaGroupId, AssignmentId)
    $userSummaryExport = @($userSummary | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, @{ Expression = 'StandingPrivilegedCount'; Descending = $true }, DisplayName)
    $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    $findingsExport = @($findings | Sort-Object -Property @{ Expression = { $severityOrder[$_.RiskRating] } }, FindingType, Subject)
    $groupOwnerExport = @($groupOwners | Select-Object GroupDisplayName, HighestGroupTier, IsAssignableToRole, OwnerDisplayName, OwnerUserPrincipalName, OwnerType, GroupId, OwnerId)
    $subscriptionExport = @($subscriptionSummary)
    $coverageExport = @($script:AzRbacCoverageGaps)

    Export-PimData -Data $assignmentExport -CsvPath (Join-Path $rawFolder 'AzureRoleAssignments.csv')
    Export-PimData -Data $accessExport -CsvPath (Join-Path $rawFolder 'AzureUserAccess.csv')
    Export-PimData -Data $userSummaryExport -CsvPath (Join-Path $rawFolder 'AzureUserSummary.csv')
    Export-PimData -Data @($matrix) -CsvPath (Join-Path $rawFolder 'AzureAccessMatrix.csv')
    Export-PimData -Data $subscriptionExport -CsvPath (Join-Path $rawFolder 'AzureSubscriptionSummary.csv')
    Export-PimData -Data $findingsExport -CsvPath (Join-Path $rawFolder 'AzureFindings.csv')
    Export-PimData -Data @($groupMembers) -CsvPath (Join-Path $rawFolder 'AzureGroupMembers.csv')
    Export-PimData -Data $groupOwnerExport -CsvPath (Join-Path $rawFolder 'AzureGroupOwners.csv')
    Export-PimData -Data $customRoles -CsvPath (Join-Path $rawFolder 'AzureCustomRoles.csv')
    Export-PimData -Data $scorecard -CsvPath (Join-Path $rawFolder 'AzureScorecard.csv')
    Export-PimData -Data $coverageExport -CsvPath (Join-Path $rawFolder 'AzureCoverageGaps.csv')
    Export-PimData -Data @($roleInfo.Values | Sort-Object RoleType, RoleName) -CsvPath (Join-Path $rawFolder 'AzureRoleDefinitions.csv')

    $summaryInfo = New-AzRbacSummaryReport `
        -OutputFolder $OutputFolder `
        -TenantLabel $TenantLabel `
        -TenantIdValue $tenantGuid `
        -Scorecard $scorecard `
        -Findings $findingsExport `
        -SubscriptionSummary $subscriptionExport `
        -UserSummary $userSummaryExport `
        -CustomRoles $customRoles `
        -GroupOwners $groupOwnerExport `
        -CoverageGaps $coverageExport

    $workbookWritten = $false
    $targetWorkbook = $WorkbookPath
    if ([string]::IsNullOrWhiteSpace($targetWorkbook)) {
        $targetWorkbook = Join-Path -Path $OutputFolder -ChildPath (Get-SafeFileName -Name ("AzureRbac_Review_{0}_{1}.xlsx" -f $TenantLabel, $runStamp))
    }
    $sheetMap = @(
        @{ Name = '40_Az_Scorecard'; Data = $scorecard },
        @{ Name = '41_Az_Findings'; Data = $findingsExport },
        @{ Name = '42_Az_Access_Matrix'; Data = @($matrix) },
        @{ Name = '43_Az_User_Summary'; Data = $userSummaryExport },
        @{ Name = '44_Az_User_Access'; Data = $accessExport },
        @{ Name = '45_Az_Role_Assignments'; Data = $assignmentExport },
        @{ Name = '46_Az_Subscriptions'; Data = $subscriptionExport },
        @{ Name = '47_Az_Group_Members'; Data = @($groupMembers) },
        @{ Name = '48_Az_Group_Owners'; Data = $groupOwnerExport },
        @{ Name = '49_Az_Custom_Roles'; Data = $customRoles },
        @{ Name = '50_Az_Coverage_Gaps'; Data = $coverageExport }
    )
    try {
        $workbookWritten = Write-AzRbacWorkbookSheets -WorkbookPath $targetWorkbook -SheetMap $sheetMap
    }
    catch {
        Write-PimLog -Level WARN -Message "Azure RBAC workbook sheets could not be written: $($_.Exception.Message)"
    }

    Write-PimLog -Message "Azure RBAC review complete. Findings: $($findings.Count). Output: $OutputFolder"

    return [pscustomobject]@{
        OutputFolder        = $OutputFolder
        SummaryMarkdownPath = $summaryInfo.MarkdownPath
        SummaryHtmlPath     = $summaryInfo.HtmlPath
        WorkbookPath        = if ($workbookWritten) { $targetWorkbook } else { $null }
        ResourceAccessPath  = $resourceAccessPath
        Counts              = [pscustomobject]@{
            ManagementGroups = $mgNames.Count
            Subscriptions    = $subIds.Count
            Resources        = $totalResources
            Assignments      = $normalised.Count
            AccessRows       = $accessRows.Count
            Principals       = $userSummary.Count
            Findings         = $findings.Count
            CoverageGaps     = $script:AzRbacCoverageGaps.Count
        }
        Scorecard           = $scorecard
        Findings            = $findingsExport
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-AzureRbacReview @PSBoundParameters
}
