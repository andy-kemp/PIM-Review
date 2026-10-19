<#
.SYNOPSIS
Read-only Azure RBAC review: every role assignment (active and PIM-eligible) from the tenant root
down to individual resources, with groups expanded to users.

.DESCRIPTION
Collects:
- Active Azure role assignments at every scope (root, management group, subscription, resource group, resource)
- PIM for Azure resources eligible assignments, and whether active ones are permanent, time-bound or PIM-activated
- Role definitions with a privilege tier derived from their actual permissions (conditions respected)
- Principals resolved through Microsoft Graph, with deleted principals confirmed one by one
- Transitive group membership, PIM for Groups eligible members, group owners
- Service principal publisher, credentials and owners; managed identity host resources
- Last sign-in and on-premises sync status for everyone with privileged access
- Activity Log: who actually made changes, and role assignment changes, over a window (default 30 days)
- Azure Lighthouse delegations to other tenants
- Access outside RBAC: Key Vault access policies, storage shared keys, SQL authentication, AKS local accounts,
  key-based (local) authentication
- Deny assignments
- Resource counts per scope (blast radius) via Azure Resource Graph

Outputs: an HTML and Markdown report, CSV evidence in Raw/, and workbook sheets 40-62 when ImportExcel is present.

This script is read-only. It does not modify Azure or Entra configuration.

Required access:
- Azure: Reader at the Tenant Root Group for full coverage. Anything the account cannot read is recorded in
  AzureCoverageGaps.csv and the report.
- Graph (delegated): Directory.Read.All, User.Read.All, Group.Read.All, Application.Read.All, AuditLog.Read.All.
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
    [int]$ActivityLogDays = 30,
    [int]$MaxActivityEventsPerSubscription = 25000,
    [int]$DormantDays = 90,
    [switch]$IncludeResourceLevelAccess,
    [switch]$IncludePimForGroups,
    [switch]$SkipActivityLog,
    [switch]$SkipExtendedChecks,
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

# Function-only companions: extended collectors and the HTML/Markdown report.
. (Join-Path -Path $PSScriptRoot -ChildPath 'Get-AzureRbacInsights.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'New-AzureRbacReport.ps1')

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

        # A client-side exception (-1: expired token, no context, DNS) is retried once only; retrying it
        # with full backoff makes a run look hung for minutes per call.
        $retryable = ($statusCode -eq 429) -or ($statusCode -ge 500) -or ($statusCode -eq -1 -and $attempt -lt 1)
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
    $rbacConstrained = $false
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
                if (-not $excluded) {
                    $canManageRbac = $true
                    # Some built-in roles (for example Defender scanner operators, Storage Actions task
                    # assignment) can only assign specific roles, enforced by a condition on the definition.
                    if (-not [string]::IsNullOrWhiteSpace([string](Get-AzRbacProp -InputObject $perm -Name 'condition'))) {
                        $rbacConstrained = $true
                    }
                }
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
    if ($canManageRbac -and -not $rbacConstrained) {
        $tier = 'Critical'
        $reason = 'Can create role assignments (Microsoft.Authorization/roleAssignments/write) and therefore grant itself or others any access.'
    }
    elseif ($canManageRbac -and $rbacConstrained) {
        $tier = 'High'
        $reason = 'Can create role assignments, but only those allowed by a condition built into the role definition.'
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
        RbacConstrained = $rbacConstrained
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

function Get-AzRbacUserDetail {
    param([string]$UserId)

    # Own cache: the shared Resolve-User cache may already hold this user from the Entra phase with a
    # narrower $select (no userType), which would hide guests.
    if (-not $script:AzRbacUserCache) { $script:AzRbacUserCache = @{} }
    $key = $UserId.ToLowerInvariant()
    if ($script:AzRbacUserCache.ContainsKey($key)) { return $script:AzRbacUserCache[$key] }

    $user = $null
    try {
        $user = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/${UserId}?`$select=id,displayName,userPrincipalName,userType,accountEnabled,mail,onPremisesSyncEnabled,createdDateTime"
    }
    catch {
        Write-Verbose "User $UserId not readable: $($_.Exception.Message)"
    }
    $script:AzRbacUserCache[$key] = $user
    return $user
}

function Resolve-AzRbacPrincipals {
    [CmdletBinding()]
    param(
        [string[]]$PrincipalIds,
        [hashtable]$ArmPrincipalTypes,
        [string]$TenantGuid
    )

    $map = @{}
    $ids = @($PrincipalIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    if ($ids.Count -eq 0) { return $map }

    $graphAvailable = $null -ne (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) -and $null -ne (Get-MgContext -ErrorAction SilentlyContinue)

    $resolvedObjects = @{}
    $lookupStatus = @{}

    if ($graphAvailable) {
        # Batch lookup first (needs Directory.Read.All). Anything not returned is checked one by one so a
        # failed or partial batch never turns live accounts into 'deleted'.
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
                Write-PimLog -Level WARN -Message "Batch directory lookup failed for $($batch.Count) principals ($($_.Exception.Message)). Falling back to one-by-one lookups."
            }
        }

        $missing = @($ids | Where-Object { -not $resolvedObjects.ContainsKey($_) })
        if ($missing.Count -gt 0) {
            Write-PimLog -Message "Confirming $($missing.Count) principals not returned by the batch lookup."
        }
        foreach ($id in $missing) {
            try {
                $obj = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$id"
                if ($obj) { $resolvedObjects[$id] = $obj }
            }
            catch {
                $msg = [string]$_.Exception.Message
                if ($msg -match 'Request_ResourceNotFound|NotFound|404|does not exist') {
                    $lookupStatus[$id] = 'Deleted'
                }
                else {
                    $lookupStatus[$id] = 'LookupFailed'
                    Write-Verbose "Lookup failed for principal $id : $msg"
                }
            }
        }
    }
    else {
        Write-PimLog -Level WARN -Message 'No Microsoft Graph context. Principals will be reported by object ID only and groups will not be expanded.'
        Add-AzRbacCoverageGap -Scope 'Microsoft Graph' -Operation 'Principal resolution' -StatusCode '' -Message 'No Microsoft Graph connection; names, guests, group members and deleted principals cannot be determined.'
        foreach ($id in $ids) { $lookupStatus[$id] = 'LookupFailed' }
    }

    foreach ($id in $ids) {
        $armType = $null
        if ($ArmPrincipalTypes -and $ArmPrincipalTypes.ContainsKey($id)) { $armType = $ArmPrincipalTypes[$id] }

        $obj = $null
        if ($resolvedObjects.ContainsKey($id)) { $obj = $resolvedObjects[$id] }

        $principal = [ordered]@{
            PrincipalId            = $id
            Resolved               = $null -ne $obj
            PrincipalType          = $armType
            Category               = 'Unknown'
            DisplayName            = $null
            UserPrincipalName      = $null
            UserType               = $null
            AccountEnabled         = $null
            OnPremisesSyncEnabled  = $null
            AppId                  = $null
            AppOwnerOrganizationId = $null
            ServicePrincipalType   = $null
            IsAssignableToRole     = $null
        }

        if ($obj) {
            $odataType = [string](Get-AzRbacProp -InputObject $obj -Name '@odata.type')
            $principal.DisplayName = Get-AzRbacProp -InputObject $obj -Name 'displayName'

            if ($odataType -match 'user') {
                $principal.PrincipalType = 'User'
                $user = Get-AzRbacUserDetail -UserId $id
                if (-not $user) { $user = $obj }
                $principal.DisplayName = Get-AzRbacProp -InputObject $user -Name 'displayName'
                $principal.UserPrincipalName = Get-AzRbacProp -InputObject $user -Name 'userPrincipalName'
                $principal.UserType = Get-AzRbacProp -InputObject $user -Name 'userType'
                $principal.AccountEnabled = Get-AzRbacProp -InputObject $user -Name 'accountEnabled'
                $principal.OnPremisesSyncEnabled = Get-AzRbacProp -InputObject $user -Name 'onPremisesSyncEnabled'
                $isGuest = ($principal.UserType -eq 'Guest') -or ([string]$principal.UserPrincipalName -match '#EXT#')
                $principal.Category = if ($isGuest) { 'Guest' } else { 'Member' }
            }
            elseif ($odataType -match 'group') {
                $principal.PrincipalType = 'Group'
                $principal.Category = 'Group'
                try {
                    $group = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/groups/${id}?`$select=id,displayName,isAssignableToRole,securityEnabled,groupTypes"
                    $principal.IsAssignableToRole = [bool](Get-AzRbacProp -InputObject $group -Name 'isAssignableToRole')
                }
                catch {
                    Write-Verbose "Group details not readable for $id"
                }
            }
            elseif ($odataType -match 'servicePrincipal') {
                $principal.PrincipalType = 'ServicePrincipal'
                $sp = $obj
                try {
                    $sp = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${id}?`$select=id,displayName,appId,servicePrincipalType,appOwnerOrganizationId,accountEnabled"
                }
                catch {
                    Write-Verbose "Service principal details not readable for $id"
                }
                $principal.DisplayName = Get-AzRbacProp -InputObject $sp -Name 'displayName'
                $principal.AppId = Get-AzRbacProp -InputObject $sp -Name 'appId'
                $principal.AccountEnabled = Get-AzRbacProp -InputObject $sp -Name 'accountEnabled'
                $principal.ServicePrincipalType = [string](Get-AzRbacProp -InputObject $sp -Name 'servicePrincipalType')
                $principal.AppOwnerOrganizationId = [string](Get-AzRbacProp -InputObject $sp -Name 'appOwnerOrganizationId')

                if (Test-AzRbacMicrosoftPrincipal -AppOwnerOrganizationId $principal.AppOwnerOrganizationId -DisplayName $principal.DisplayName -ServicePrincipalType $principal.ServicePrincipalType) {
                    $principal.Category = 'MicrosoftPlatform'
                }
                elseif ($principal.ServicePrincipalType -eq 'ManagedIdentity') {
                    $principal.Category = 'ManagedIdentity'
                }
                elseif ($principal.AppOwnerOrganizationId -and $TenantGuid -and $principal.AppOwnerOrganizationId -ne $TenantGuid) {
                    $principal.Category = 'ExternalApp'
                }
                else {
                    $principal.Category = 'ServicePrincipal'
                }
            }
        }
        else {
            if (-not $principal.PrincipalType) { $principal.PrincipalType = 'Unknown' }
            $status = if ($lookupStatus.ContainsKey($id)) { $lookupStatus[$id] } else { 'LookupFailed' }
            if ($armType -match '^Foreign') {
                $principal.Category = 'ForeignPrincipal'
                $principal.DisplayName = "Foreign principal ($id)"
            }
            elseif ($status -eq 'Deleted') {
                $principal.Category = 'Deleted'
                $principal.DisplayName = "Deleted $armType ($id)"
            }
            else {
                $principal.Category = 'LookupFailed'
                $principal.DisplayName = "Unresolved ($id)"
            }
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
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers?`$select=id,displayName,userPrincipalName,userType,accountEnabled,appId,servicePrincipalType,appOwnerOrganizationId"
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
            $memberId = [string](Get-AzRbacProp -InputObject $m -Name 'id')
            if ([string]::IsNullOrWhiteSpace($memberId)) { continue }

            $type = Get-PrincipalType -Principal $m
            if ($type -ne 'User' -and $type -ne 'ServicePrincipal') { continue }

            $category = 'Member'
            if ($type -eq 'User') {
                $isGuest = ((Get-AzRbacProp -InputObject $m -Name 'userType') -eq 'Guest') -or ([string](Get-AzRbacProp -InputObject $m -Name 'userPrincipalName') -match '#EXT#')
                if ($isGuest) { $category = 'Guest' }
            }
            else {
                $spType = [string](Get-AzRbacProp -InputObject $m -Name 'servicePrincipalType')
                $category = if ($spType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
                if (Test-AzRbacMicrosoftPrincipal -AppOwnerOrganizationId ([string](Get-AzRbacProp -InputObject $m -Name 'appOwnerOrganizationId')) -DisplayName ([string](Get-AzRbacProp -InputObject $m -Name 'displayName')) -ServicePrincipalType $spType) {
                    $category = 'MicrosoftPlatform'
                }
            }

            $null = $members.Add([pscustomobject]@{
                GroupId           = $GroupId
                GroupDisplayName  = $GroupDisplayName
                MemberId          = $memberId.ToLowerInvariant()
                DisplayName       = Get-AzRbacProp -InputObject $m -Name 'displayName'
                UserPrincipalName = Get-AzRbacProp -InputObject $m -Name 'userPrincipalName'
                PrincipalType     = $type
                Category          = $category
                AccountEnabled    = Get-AzRbacProp -InputObject $m -Name 'accountEnabled'
                AppId             = Get-AzRbacProp -InputObject $m -Name 'appId'
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

                $user = Get-AzRbacUserDetail -UserId $principalId
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
                    AppId             = $null
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
            $ownerId = [string](Get-AzRbacProp -InputObject $o -Name 'id')
            if ([string]::IsNullOrWhiteSpace($ownerId)) { continue }
            $null = $owners.Add([pscustomobject]@{
                GroupId                = $GroupId
                GroupDisplayName       = $GroupDisplayName
                OwnerId                = $ownerId
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
# Workbook
# ---------------------------------------------------------------------------------------------

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
        [int]$ActivityLogDays = 30,
        [int]$MaxActivityEventsPerSubscription = 25000,
        [int]$DormantDays = 90,
        [switch]$IncludeResourceLevelAccess,
        [switch]$IncludePimForGroups,
        [switch]$SkipActivityLog,
        [switch]$SkipExtendedChecks,
        [switch]$UseDeviceAuthentication,
        [switch]$SkipGraphConnect,
        [switch]$ForceReConnect
    )

    $script:AzRbacCoverageGaps = New-Object System.Collections.ArrayList
    $script:AzRbacUserCache = @{}
    $runStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $nowUtc = (Get-Date).ToUniversalTime()
    $userCategories = @('Member', 'Guest')
    $workloadCategories = @('ServicePrincipal', 'ManagedIdentity', 'ExternalApp')

    # ---- Connections ------------------------------------------------------------------------
    if (-not $SkipGraphConnect) {
        $null = Connect-GraphForPimReview -TenantId $TenantId -IncludeAzureRbac -IncludePimForGroups:$IncludePimForGroups -ForceReConnect:$ForceReConnect
    }

    $graphContext = $null
    if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) {
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    }
    if (-not $graphContext) {
        Write-PimLog -Level WARN -Message 'No Microsoft Graph connection. The review will list assignments by object ID only; guests, group members and deleted principals cannot be identified.'
    }

    $azTenant = $TenantId
    if ($graphContext -and $graphContext.TenantId) {
        $azTenant = [string]$graphContext.TenantId
    }

    $azContext = Connect-AzureForRbacReview -TenantId $azTenant -UseDeviceAuthentication:$UseDeviceAuthentication -ForceReConnect:$ForceReConnect
    $tenantGuid = ([string]$azContext.Tenant.Id).ToLowerInvariant()

    if ($graphContext -and $graphContext.TenantId -and ([string]$graphContext.TenantId).ToLowerInvariant() -ne $tenantGuid) {
        throw "Microsoft Graph is connected to tenant $($graphContext.TenantId) but Azure is connected to $tenantGuid. Reconnect with -ForceReConnect."
    }

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
    }
    $TenantLabel = (Get-SafeFileName -Name $TenantLabel) -replace '\s+', '_'

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
            [string]::IsNullOrWhiteSpace($subTenant) -or $subTenant.ToLowerInvariant() -eq $tenantGuid
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
                [array]::Reverse($names)
                $subMgPath[$sid] = ($names -join ' > ')
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Resource Graph hierarchy query failed ($($_.Exception.Message)). Falling back to management group descendants."
            Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph: management group hierarchy' -StatusCode '' -Message $_.Exception.Message
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

    # Resource Graph only returns resources the review account can read. A subscription with resource
    # groups but no visible resources almost always means missing Reader, not an empty subscription.
    $subResourcesVisible = @{}
    foreach ($sid in $subIds) {
        $visible = $resourceCountBySub.ContainsKey($sid)
        $subResourcesVisible[$sid] = $visible
        if (-not $visible -and $rgCountBySub.ContainsKey($sid) -and $rgCountBySub[$sid] -gt 0) {
            Add-AzRbacCoverageGap -Scope "/subscriptions/$sid" -Operation 'Resources not visible' -StatusCode '' -Message "$($subNames[$sid]) has $($rgCountBySub[$sid]) resource group(s) but no resources are readable. Grant Reader for resource counts, data plane checks and managed identity mapping."
        }
    }
    $visibleSubIds = @($subIds | Where-Object { $subResourcesVisible[$_] })

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
    # PIM schedule APIs do not support the tenant root; only role assignments are read there.
    $null = $scopeTargets.Add(@{ Scope = ''; Display = '/'; Filter = '&$filter=atScope()'; Pim = $false })
    foreach ($mgId in @($mgNames.Keys)) {
        $null = $scopeTargets.Add(@{ Scope = "/providers/Microsoft.Management/managementGroups/$mgId"; Display = "/providers/Microsoft.Management/managementGroups/$mgId"; Filter = '&$filter=atScope()'; Pim = $true })
    }
    foreach ($sid in $subIds) {
        # No filter at subscription scope: returns assignments at, above and below the subscription.
        $null = $scopeTargets.Add(@{ Scope = "/subscriptions/$sid"; Display = "/subscriptions/$sid"; Filter = ''; Pim = $true })
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

        if (-not $target.Pim) { continue }

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

    # ---- Extended collection (outside RBAC, usage, external access) -------------------------
    $lighthouse = @()
    $denyAssignments = @()
    $resourceSecurity = [pscustomobject]@{ KeyVaults = @(); KeyVaultAccessPolicies = @(); StorageAccounts = @(); SqlServers = @(); AksClusters = @(); LocalAuthResources = @() }
    $miHosts = @{}
    $activity = $null

    if (-not $SkipExtendedChecks -and $subIds.Count -gt 0) {
        Write-PimLog -Message 'Reading Azure Lighthouse delegations.'
        $lighthouse = @(Get-AzRbacLighthouseDelegations -SubscriptionIds $subIds -SubscriptionNames $subNames)

        Write-PimLog -Message 'Reading deny assignments.'
        $denyAssignments = @(Get-AzRbacDenyAssignments -SubscriptionIds $subIds -SubscriptionNames $subNames)

        if ($visibleSubIds.Count -gt 0) {
            Write-PimLog -Message 'Checking access paths outside Azure RBAC (Key Vault, storage, SQL, AKS, local auth).'
            $resourceSecurity = Get-AzRbacResourceSecurity -SubscriptionIds $visibleSubIds -SubscriptionNames $subNames

            Write-PimLog -Message 'Mapping managed identities to their resources.'
            $miHosts = Get-AzRbacManagedIdentityHosts -SubscriptionIds $visibleSubIds
        }

        if (-not $SkipActivityLog -and $ActivityLogDays -gt 0) {
            Write-PimLog -Message "Reading Activity Log for the last $ActivityLogDays days (who actually made changes)."
            $activity = Get-AzRbacActivityLog -SubscriptionIds $subIds -SubscriptionNames $subNames -Days $ActivityLogDays -MaxEventsPerSubscription $MaxActivityEventsPerSubscription
        }
    }

    # ---- Role definitions -------------------------------------------------------------------
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
    foreach ($guid in @(@($lighthouse | ForEach-Object { $_.RoleDefinitionGuid }) + @(if ($activity) { $activity.RbacChanges | ForEach-Object { $_.RoleDefinitionGuid } }))) {
        if ($guid -and -not $referencedRoleIds.ContainsKey($guid)) { $referencedRoleIds[$guid] = "/providers/Microsoft.Authorization/roleDefinitions/$guid" }
    }
    foreach ($guid in @($referencedRoleIds.Keys)) {
        if ($roleDefs.ContainsKey($guid)) { continue }
        try {
            $rd = Invoke-ArmRequest -Uri ("{0}{1}?api-version=2022-04-01" -f $script:AzRbacArmBase, $referencedRoleIds[$guid])
            if ($rd) { $roleDefs[$guid] = $rd }
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read role definition $($referencedRoleIds[$guid]): $($_.Exception.Message)"
            Add-AzRbacCoverageGap -Scope $referencedRoleIds[$guid] -Operation 'Read role definition' -StatusCode '' -Message "Assignments of this role are reported with tier Unknown. $($_.Exception.Message)"
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
    $roleNameOf = {
        param($Guid)
        if ($Guid -and $roleInfo.ContainsKey($Guid)) { return $roleInfo[$Guid].RoleName }
        return $Guid
    }
    $roleTierOf = {
        param($Guid)
        if ($Guid -and $roleInfo.ContainsKey($Guid)) { return $roleInfo[$Guid].PrivilegeTier }
        return 'Unknown'
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
        $hasCondition = -not [string]::IsNullOrWhiteSpace($condition)

        $tier = if ($role) { $role.PrivilegeTier } else { 'Unknown' }
        $tierNote = $null
        if ($tier -eq 'Critical' -and $hasCondition) {
            # A condition on the assignment (for example 'Role Based Access Control Administrator, may only
            # assign Reader') limits which roles can be granted.
            $tier = 'High'
            $tierNote = 'Role assignment rights limited by a condition on this assignment.'
        }

        $resourcesInScope = $null
        switch ($scopeInfo.ScopeLevel) {
            'Root' { $resourcesInScope = $totalResources }
            'ManagementGroup' { if ($resourceCountByMg.ContainsKey($scopeInfo.ManagementGroupId)) { $resourcesInScope = $resourceCountByMg[$scopeInfo.ManagementGroupId] } else { $resourcesInScope = 0 } }
            'Subscription' { if ($resourceCountBySub.ContainsKey($scopeInfo.SubscriptionId)) { $resourcesInScope = $resourceCountBySub[$scopeInfo.SubscriptionId] } }
            'ResourceGroup' { $k = "$($scopeInfo.SubscriptionId)|$($scopeInfo.ResourceGroup)"; if ($resourceCountByRg.ContainsKey($k)) { $resourcesInScope = $resourceCountByRg[$k] } elseif ($subResourcesVisible.ContainsKey($scopeInfo.SubscriptionId) -and $subResourcesVisible[$scopeInfo.SubscriptionId]) { $resourcesInScope = 0 } }
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
            PrivilegeTier      = $tier
            TierNote           = $tierNote
            Scope              = $scopeInfo.Scope
            ScopeLevel         = $scopeInfo.ScopeLevel
            ScopeName          = $scopeInfo.ScopeName
            ManagementGroupId  = $scopeInfo.ManagementGroupId
            SubscriptionId     = $scopeInfo.SubscriptionId
            SubscriptionName   = $scopeInfo.SubscriptionName
            ResourceGroup      = $scopeInfo.ResourceGroup
            ResourceType       = $scopeInfo.ResourceType
            ResourcesInScope   = $resourcesInScope
            HasCondition       = $hasCondition
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

    # ---- Resolve principals and expand groups -----------------------------------------------
    $idsToResolve = New-Object System.Collections.ArrayList
    foreach ($a in $normalised) { $null = $idsToResolve.Add($a.PrincipalId) }
    foreach ($p in @($resourceSecurity.KeyVaultAccessPolicies)) { if ($p.ObjectId) { $null = $idsToResolve.Add($p.ObjectId) } }
    if ($activity) { foreach ($c in @($activity.RbacChanges)) { if ($c.PrincipalId) { $null = $idsToResolve.Add($c.PrincipalId) } } }

    $uniqueIds = @($idsToResolve | Where-Object { $_ } | Select-Object -Unique)
    Write-PimLog -Message "Resolving $($uniqueIds.Count) principals through Microsoft Graph."
    $principals = Resolve-AzRbacPrincipals -PrincipalIds $uniqueIds -ArmPrincipalTypes $armPrincipalTypes -TenantGuid $tenantGuid

    foreach ($a in $normalised) {
        $p = $null
        if ($principals.ContainsKey($a.PrincipalId)) { $p = $principals[$a.PrincipalId] }
        $a | Add-Member -NotePropertyName PrincipalType -NotePropertyValue $(if ($p) { $p.PrincipalType } else { $a.ArmPrincipalType }) -Force
        $a | Add-Member -NotePropertyName PrincipalCategory -NotePropertyValue $(if ($p) { $p.Category } else { 'LookupFailed' }) -Force
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
    $memberAppIds = @{}
    foreach ($a in $normalised) {
        $base = [ordered]@{
            RoleName          = $a.RoleName
            RoleType          = $a.RoleType
            PrivilegeTier     = $a.PrivilegeTier
            ScopeLevel        = $a.ScopeLevel
            ScopeName         = $a.ScopeName
            SubscriptionName  = $a.SubscriptionName
            ResourceGroup     = $a.ResourceGroup
            ResourcesInScope  = $a.ResourcesInScope
            AssignmentState   = $a.AssignmentState
            AssignmentType    = $a.AssignmentType
            EndDateTime       = $a.EndDateTime
            HasCondition      = $a.HasCondition
            Scope             = $a.Scope
            SubscriptionId    = $a.SubscriptionId
            ManagementGroupId = $a.ManagementGroupId
            AssignmentId      = $a.AssignmentId
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
                if ($m.AppId) { $memberAppIds[$m.MemberId] = $m.AppId }
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

    # ---- Sign-in activity, workload details, activity mapping --------------------------------
    $principalRowsById = @{}
    foreach ($grp in @($accessRows | Where-Object { $_.PrincipalCategory -ne 'Group' } | Group-Object -Property PrincipalId)) {
        $principalRowsById[$grp.Name] = @($grp.Group)
    }

    $signIn = $null
    $workloads = @{}
    if (-not $SkipExtendedChecks -and $graphContext) {
        $userIdsForSignIn = @($principalRowsById.Keys | Where-Object { $principalRowsById[$_][0].PrincipalCategory -in $userCategories })
        $spIdsForDetail = @($principalRowsById.Keys | Where-Object { $principalRowsById[$_][0].PrincipalCategory -in $workloadCategories })

        Write-PimLog -Message "Reading credentials, owners and publisher for $($spIdsForDetail.Count) workload identities."
        $workloads = Get-AzRbacWorkloadDetails -ServicePrincipalIds $spIdsForDetail -TenantGuid $tenantGuid

        $spAppIds = New-Object System.Collections.ArrayList
        foreach ($id in $spIdsForDetail) {
            $appId = $null
            if ($workloads.ContainsKey($id)) { $appId = $workloads[$id].AppId }
            elseif ($principals.ContainsKey($id)) { $appId = $principals[$id].AppId }
            elseif ($memberAppIds.ContainsKey($id)) { $appId = $memberAppIds[$id] }
            if ($appId) { $null = $spAppIds.Add($appId) }
        }

        $signIn = Get-AzRbacSignInActivity -UserIds $userIdsForSignIn -ServicePrincipalAppIds @($spAppIds)
    }

    # Activity Log 'caller' is a UPN for users and an object or application ID for service principals.
    $activityByPrincipal = @{}
    $activitySubsRead = @{}
    if ($activity) {
        $callerToPrincipal = @{}
        foreach ($prinId in @($principalRowsById.Keys)) {
            $first = $principalRowsById[$prinId][0]
            $callerToPrincipal[$prinId] = $prinId
            if ($first.UserPrincipalName) { $callerToPrincipal[([string]$first.UserPrincipalName).ToLowerInvariant()] = $prinId }
            $appId = $null
            if ($workloads.ContainsKey($prinId)) { $appId = $workloads[$prinId].AppId }
            elseif ($principals.ContainsKey($prinId)) { $appId = $principals[$prinId].AppId }
            if ($appId) { $callerToPrincipal[([string]$appId).ToLowerInvariant()] = $prinId }
        }

        foreach ($row in @($activity.CallerActivity)) {
            $activitySubsRead[$row.SubscriptionId] = $true
            $prinId = $null
            if ($callerToPrincipal.ContainsKey($row.Caller)) { $prinId = $callerToPrincipal[$row.Caller] }
            $row | Add-Member -NotePropertyName PrincipalId -NotePropertyValue $prinId -Force
            $row | Add-Member -NotePropertyName HasAzureRole -NotePropertyValue ($null -ne $prinId) -Force
            if (-not $prinId) { continue }
            if (-not $activityByPrincipal.ContainsKey($prinId)) { $activityByPrincipal[$prinId] = [pscustomobject]@{ Events = 0; LastChange = $null; Subscriptions = New-Object System.Collections.ArrayList } }
            $entry = $activityByPrincipal[$prinId]
            $entry.Events += $row.ChangeEvents
            if ($row.LastChange -and (($null -eq $entry.LastChange) -or $row.LastChange -gt $entry.LastChange)) { $entry.LastChange = $row.LastChange }
            $null = $entry.Subscriptions.Add($row.SubscriptionName)
        }

        foreach ($c in @($activity.RbacChanges)) {
            $p = $null
            if ($c.PrincipalId -and $principals.ContainsKey($c.PrincipalId)) { $p = $principals[$c.PrincipalId] }
            $c | Add-Member -NotePropertyName PrincipalDisplayName -NotePropertyValue $(if ($p) { $p.DisplayName } else { $c.PrincipalId }) -Force
            $c | Add-Member -NotePropertyName PrincipalCategory -NotePropertyValue $(if ($p) { $p.Category } else { $null }) -Force
            $c | Add-Member -NotePropertyName RoleName -NotePropertyValue (& $roleNameOf $c.RoleDefinitionGuid) -Force
            $c | Add-Member -NotePropertyName PrivilegeTier -NotePropertyValue (& $roleTierOf $c.RoleDefinitionGuid) -Force
        }
    }

    # Key Vault access policies: name the principals and add them to each principal's data plane access.
    $kvPolicyByPrincipal = @{}
    foreach ($p in @($resourceSecurity.KeyVaultAccessPolicies)) {
        $pr = $null
        if ($p.ObjectId -and $principals.ContainsKey($p.ObjectId)) { $pr = $principals[$p.ObjectId] }
        $p | Add-Member -NotePropertyName PrincipalDisplayName -NotePropertyValue $(if ($pr) { $pr.DisplayName } else { $p.ObjectId }) -Force
        $p | Add-Member -NotePropertyName PrincipalCategory -NotePropertyValue $(if ($pr) { $pr.Category } else { 'LookupFailed' }) -Force
        $p | Add-Member -NotePropertyName UserPrincipalName -NotePropertyValue $(if ($pr) { $pr.UserPrincipalName } else { $null }) -Force
        if ($p.CanReadSecretsOrKeys -and $p.ObjectId) {
            if (-not $kvPolicyByPrincipal.ContainsKey($p.ObjectId)) { $kvPolicyByPrincipal[$p.ObjectId] = New-Object System.Collections.ArrayList }
            $null = $kvPolicyByPrincipal[$p.ObjectId].Add($p.VaultName)
        }
    }

    # ---- Per principal summary ---------------------------------------------------------------
    $userSummary = New-Object System.Collections.ArrayList
    $principalSubCells = @{}

    foreach ($prinId in @($principalRowsById.Keys)) {
        $rows = @($principalRowsById[$prinId])
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
        $countsComplete = $true
        foreach ($sid in @($fullSubs.Keys)) {
            if ($resourceCountBySub.ContainsKey($sid)) { $resourcesReachable += $resourceCountBySub[$sid] }
            elseif (-not ($subResourcesVisible.ContainsKey($sid) -and $subResourcesVisible[$sid])) { $countsComplete = $false }
        }
        foreach ($k in @($partialRg.Keys)) {
            $sid = $k.Split('|')[0]
            if ($fullSubs.ContainsKey($sid)) { continue }
            if ($resourceCountByRg.ContainsKey($k)) { $resourcesReachable += $resourceCountByRg[$k] }
            elseif (-not ($subResourcesVisible.ContainsKey($sid) -and $subResourcesVisible[$sid])) { $countsComplete = $false }
        }
        foreach ($k in @($partialRes.Keys)) {
            $r = $partialRes[$k]
            if ($fullSubs.ContainsKey($r.SubscriptionId)) { continue }
            if ($partialRg.ContainsKey("$($r.SubscriptionId)|$($r.ResourceGroup)")) { continue }
            $resourcesReachable += 1
        }

        $highest = @($rows | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true } | Select-Object -First 1)[0].PrivilegeTier
        $privRows = @($rows | Where-Object { (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })
        $criticalAccess = @($rows | Where-Object { $_.PrivilegeTier -eq 'Critical' } | ForEach-Object {
            $suffix = if ($_.EffectiveState -eq 'Eligible') { ' [Eligible]' } else { '' }
            "$($_.RoleName) @ $($_.ScopeName)$suffix"
        } | Select-Object -Unique)
        $criticalText = (@($criticalAccess | Select-Object -First 10) -join '; ')
        if ($criticalAccess.Count -gt 10) { $criticalText += "; +$($criticalAccess.Count - 10) more" }

        $lastSignIn = $null
        $onPremSynced = $null
        $createdDate = $null
        $signInKnown = $false
        if ($signIn) {
            if ($first.PrincipalCategory -in $userCategories -and $signIn.Users.ContainsKey($prinId)) {
                $u = $signIn.Users[$prinId]
                $lastSignIn = $u.LastSignIn
                $onPremSynced = $u.OnPremisesSyncEnabled
                $createdDate = $u.CreatedDateTime
                $signInKnown = [bool]$u.SignInDataAvailable
            }
            elseif ($first.PrincipalCategory -in $workloadCategories) {
                $appId = $null
                if ($workloads.ContainsKey($prinId)) { $appId = $workloads[$prinId].AppId } elseif ($memberAppIds.ContainsKey($prinId)) { $appId = $memberAppIds[$prinId] }
                if ($appId -and $signIn.ServicePrincipals.ContainsKey(([string]$appId).ToLowerInvariant())) { $lastSignIn = $signIn.ServicePrincipals[([string]$appId).ToLowerInvariant()] }
                $signInKnown = [bool]$signIn.ServicePrincipalSignInAvailable
            }
        }
        $daysSinceSignIn = if ($lastSignIn) { [int]($nowUtc - $lastSignIn).TotalDays } else { $null }
        $isoDate = { param($d) if ($d -is [datetime]) { $d.ToString('yyyy-MM-dd HH:mm') } else { $d } }

        $act = $null
        if ($activityByPrincipal.ContainsKey($prinId)) { $act = $activityByPrincipal[$prinId] }

        $miHost = $null
        if ($miHosts.ContainsKey($prinId)) { $miHost = (@($miHosts[$prinId] | ForEach-Object { "$($_.HostResource) [$($_.Kind)]" } | Select-Object -Unique) -join '; ') }

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
            SubscriptionsReachable  = $cells.Count
            SubscriptionsFull       = $fullSubs.Count
            ResourcesReachable      = $resourcesReachable
            ResourceCountComplete   = $countsComplete
            LastSignIn              = & $isoDate $lastSignIn
            DaysSinceSignIn         = $daysSinceSignIn
            SignInDataAvailable     = $signInKnown
            OnPremisesSynced        = $onPremSynced
            CreatedDateTime         = & $isoDate $createdDate
            AzureChangeEvents       = if ($act) { $act.Events } elseif ($activity) { 0 } else { $null }
            LastAzureChange         = if ($act) { & $isoDate $act.LastChange } else { $null }
            KeyVaultPolicyAccess    = if ($kvPolicyByPrincipal.ContainsKey($prinId)) { (@($kvPolicyByPrincipal[$prinId] | Select-Object -Unique) -join '; ') } else { $null }
            ManagedIdentityHost     = $miHost
            CriticalAccess          = $criticalText
            PrincipalId             = $prinId
        })

        $principalSubCells[$prinId] = $cells
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
    $subscriptionDetail = @{}
    foreach ($sid in $orderedSubIds) {
        $effective = @()
        if ($rowsBySub.ContainsKey($sid)) { $effective = @($rowsBySub[$sid]) }
        $atOrAbove = @($effective | Where-Object { $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') })
        $owners = @($atOrAbove | Where-Object { $_.PrivilegeTier -eq 'Critical' -and $_.PrincipalCategory -in $userCategories })
        $standingOwners = @($owners | Where-Object { $_.IsStanding } | Select-Object -ExpandProperty PrincipalId -Unique)
        $eligibleOwners = @($owners | Where-Object { $_.EffectiveState -eq 'Eligible' } | Select-Object -ExpandProperty PrincipalId -Unique)
        $allOwners = @($owners | Select-Object -ExpandProperty PrincipalId -Unique)
        # Eligibility inherited from management groups counts: PIM done at MG level is still PIM.
        $pimEligible = @($effective | Where-Object { $_.EffectiveState -eq 'Eligible' }).Count
        $guests = @($effective | Where-Object { $_.PrincipalCategory -eq 'Guest' } | Select-Object -ExpandProperty PrincipalId -Unique)
        $workloadPriv = @($atOrAbove | Where-Object { $_.PrincipalCategory -in $workloadCategories -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 } | Select-Object -ExpandProperty PrincipalId -Unique)
        $lhCount = @($lighthouse | Where-Object { $_.SubscriptionId -eq $sid }).Count

        $risk = 'Low'
        if ($standingOwners.Count -gt $MaxOwnersPerSubscription) { $risk = 'High' }
        elseif ($standingOwners.Count -gt 0 -and $pimEligible -eq 0) { $risk = 'Medium' }
        elseif ($guests.Count -gt 0 -or $workloadPriv.Count -gt 0) { $risk = 'Medium' }

        $null = $subscriptionSummary.Add([pscustomobject]@{
            SubscriptionName       = $subNames[$sid]
            SubscriptionId         = $sid
            State                  = $subStates[$sid]
            ManagementGroupPath    = if ($subMgPath.ContainsKey($sid)) { $subMgPath[$sid] } else { $null }
            ResourceGroups         = if ($rgCountBySub.ContainsKey($sid)) { $rgCountBySub[$sid] } else { $null }
            Resources              = if ($resourceCountBySub.ContainsKey($sid)) { [string]$resourceCountBySub[$sid] } elseif ($rgCountBySub.ContainsKey($sid) -and $rgCountBySub[$sid] -gt 0) { 'Not visible' } else { '0' }
            AssignmentsAtOrBelow   = @($normalised | Where-Object { $_.SubscriptionId -eq $sid }).Count
            EffectivePrincipals    = @($effective | Select-Object -ExpandProperty PrincipalId -Unique).Count
            EffectiveOwners        = $allOwners.Count
            StandingOwners         = $standingOwners.Count
            EligibleOwners         = $eligibleOwners.Count
            GuestsWithAccess       = $guests.Count
            PrivilegedWorkloads    = $workloadPriv.Count
            LighthouseAuthorizations = $lhCount
            PimEligiblePaths       = $pimEligible
            RiskRating             = $risk
        })

        # Per subscription privileged principal list for the report.
        $subscriptionDetail[$sid] = @(
            $atOrAbove |
            Where-Object { (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 } |
            Group-Object -Property PrincipalId |
            ForEach-Object {
                $g = @($_.Group)
                $top = @($g | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true })[0]
                [pscustomobject]@{
                    DisplayName       = $top.DisplayName
                    UserPrincipalName = $top.UserPrincipalName
                    PrincipalCategory = $top.PrincipalCategory
                    HighestTier       = $top.PrivilegeTier
                    Roles             = (@($g | ForEach-Object {
                        $via = if ($_.AccessPath -eq 'Group') { " via $($_.ViaGroupName)" } else { '' }
                        $from = if ($_.ScopeLevel -ne 'Subscription') { " from $($_.ScopeName)" } else { '' }
                        $st = if ($_.EffectiveState -eq 'Eligible') { ' [Eligible]' } else { '' }
                        "$($_.RoleName)$st$from$via"
                    } | Select-Object -Unique) -join '; ')
                    Standing          = (@($g | Where-Object { $_.IsStanding }).Count -gt 0)
                }
            } |
            Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, DisplayName
        )
    }

    # ---- Group summary ----------------------------------------------------------------------
    $groupSummary = @(
        foreach ($gid in $groupIds) {
            $ga = @($normalised | Where-Object { $_.PrincipalId -eq $gid })
            $top = @($ga | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true })[0]
            $exp = $groupExpansion[$gid]
            $members = @($exp.Members)
            [pscustomobject]@{
                GroupName          = $principals[$gid].DisplayName
                HighestTier        = $top.PrivilegeTier
                Roles              = (@($ga | ForEach-Object { $st = if ($_.AssignmentState -eq 'Eligible') { ' [Eligible]' } else { '' }; "$($_.RoleName)$st @ $($_.ScopeName)" } | Select-Object -Unique) -join '; ')
                Members            = @($members | Select-Object -ExpandProperty MemberId -Unique).Count
                GuestMembers       = @($members | Where-Object { $_.Category -eq 'Guest' } | Select-Object -ExpandProperty MemberId -Unique).Count
                WorkloadMembers    = @($members | Where-Object { $_.Category -in @('ServicePrincipal', 'ManagedIdentity', 'MicrosoftPlatform') } | Select-Object -ExpandProperty MemberId -Unique).Count
                EligibleMembers    = @($members | Where-Object { $_.MembershipType -like 'Eligible*' } | Select-Object -ExpandProperty MemberId -Unique).Count
                Owners             = (@($exp.Owners | ForEach-Object { if ($_.OwnerUserPrincipalName) { $_.OwnerUserPrincipalName } else { $_.OwnerDisplayName } }) -join '; ')
                IsAssignableToRole = $principals[$gid].IsAssignableToRole
                MembershipReadable = -not [bool]$exp.ExpansionFailed
                GroupId            = $gid
            }
        }
    )
    $groupSummary = @($groupSummary | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, @{ Expression = 'Members'; Descending = $true })

    # ---- Workload identity summary ----------------------------------------------------------
    $workloadSummary = @(
        $userSummary | Where-Object { $_.PrincipalCategory -in @('ServicePrincipal', 'ManagedIdentity', 'ExternalApp', 'MicrosoftPlatform') } | ForEach-Object {
            $w = $null
            if ($workloads.ContainsKey($_.PrincipalId)) { $w = $workloads[$_.PrincipalId] }
            [pscustomobject]@{
                DisplayName          = $_.DisplayName
                PrincipalCategory    = $_.PrincipalCategory
                Publisher            = if ($w) { $w.Publisher } elseif ($_.PrincipalCategory -eq 'MicrosoftPlatform') { 'Microsoft' } else { $null }
                HighestTier          = $_.HighestTier
                SubscriptionsReachable = $_.SubscriptionsReachable
                CriticalAccess       = $_.CriticalAccess
                LastSignIn           = $_.LastSignIn
                DaysSinceSignIn      = $_.DaysSinceSignIn
                AzureChangeEvents    = $_.AzureChangeEvents
                ActiveSecrets        = if ($w) { $w.ActiveSecrets } else { $null }
                ActiveCertificates   = if ($w) { $w.ActiveCertificates } else { $null }
                FederatedCredentials = if ($w) { $w.FederatedCredentials } else { $null }
                LongLivedCredentials = if ($w) { $w.LongLivedCredentials } else { $null }
                LongestLifetimeDays  = if ($w) { $w.LongestLifetimeDays } else { $null }
                ExpiredCredentials   = if ($w) { $w.ExpiredCredentials } else { $null }
                NextExpiry           = if ($w -and $w.NextExpiry) { $w.NextExpiry.ToString('yyyy-MM-dd') } else { $null }
                Owners               = if ($w) { $w.Owners } else { $null }
                ManagedIdentityHost  = $_.ManagedIdentityHost
                AppId                = if ($w) { $w.AppId } else { $null }
                PrincipalId          = $_.PrincipalId
            }
        } | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, DisplayName
    )

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

    # ---- Lighthouse rows with role names ------------------------------------------------------
    foreach ($l in $lighthouse) {
        $l | Add-Member -NotePropertyName RoleName -NotePropertyValue (& $roleNameOf $l.RoleDefinitionGuid) -Force
        $l | Add-Member -NotePropertyName PrivilegeTier -NotePropertyValue (& $roleTierOf $l.RoleDefinitionGuid) -Force
        $delegated = @(([string]$l.DelegatedRoleDefinitionIds).Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { & $roleNameOf $_ })
        $l | Add-Member -NotePropertyName CanAssignRoles -NotePropertyValue ($delegated -join '; ') -Force
    }

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
    $describeRows = {
        param($Rows, $Max)
        $items = @($Rows | ForEach-Object {
            $via = if ($_.AccessPath -eq 'Group') { " via group $($_.ViaGroupName)" } else { ' (direct)' }
            "$($_.RoleName) @ $($_.ScopeName)$via"
        } | Select-Object -Unique)
        $text = (@($items | Select-Object -First $Max) -join '; ')
        if ($items.Count -gt $Max) { $text += "; +$($items.Count - $Max) more" }
        return $text
    }

    foreach ($a in @($normalised | Where-Object { $_.ScopeLevel -eq 'Root' })) {
        $rating = if ($a.PrincipalCategory -eq 'MicrosoftPlatform') { 'Low' } else { 'Critical' }
        & $addFinding $rating 'RootScopeAssignment' $a.PrincipalDisplayName $a.RoleName $a.ScopeName "$($a.AssignmentState) $($a.AssignmentType) assignment at tenant root (/), reaching every management group, subscription and resource." 'Remove role assignments at root scope. These are usually left behind after Elevate Access by a Global Administrator. Use the Tenant Root Group management group with PIM instead.' $a.Scope
    }

    # Standing privileged access: one finding per person, listing every place it applies.
    foreach ($grp in @($accessRows | Where-Object { $_.IsStanding -and $_.PrincipalCategory -in $userCategories -and $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 } | Group-Object -Property PrincipalId)) {
        $rows = @($grp.Group)
        $crit = @($rows | Where-Object { $_.PrivilegeTier -eq 'Critical' })
        $first = $rows[0]
        if ($crit.Count -gt 0) {
            & $addFinding 'High' 'StandingCriticalAccess' $first.DisplayName (@($crit | Select-Object -ExpandProperty RoleName -Unique) -join ', ') (@($crit | Select-Object -ExpandProperty ScopeName -Unique) -join ', ') "Permanent active access that can grant any access: $(& $describeRows $crit 12)" 'Remove, or convert to PIM-eligible with approval and MFA on activation. Keep standing Owner / User Access Administrator to break-glass accounts only.' $crit[0].Scope
        }
        else {
            & $addFinding 'Medium' 'StandingHighAccess' $first.DisplayName (@($rows | Select-Object -ExpandProperty RoleName -Unique) -join ', ') (@($rows | Select-Object -ExpandProperty ScopeName -Unique) -join ', ') "Permanent active write access at subscription scope or above: $(& $describeRows $rows 12)" 'Reduce scope to the resource groups actually needed, or make the assignment PIM-eligible.' $rows[0].Scope
        }
    }

    foreach ($grp in @($accessRows | Where-Object { $_.PrincipalCategory -eq 'Guest' } | Group-Object -Property PrincipalId)) {
        $rows = @($grp.Group)
        $top = @($rows | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.PrivilegeTier }; Descending = $true })[0]
        $rating = if ((Get-AzRbacTierRank -Tier $top.PrivilegeTier) -ge 3) { 'High' } else { 'Medium' }
        & $addFinding $rating 'GuestAzureAccess' $top.DisplayName $top.RoleName $top.ScopeName "Guest account holds $($rows.Count) Azure access path(s): $(& $describeRows $rows 8)" 'Confirm a current business need and sponsor, place under an access review, and prefer eligible over active assignments.' $top.Scope
    }

    foreach ($a in @($normalised | Where-Object { $_.PrincipalCategory -eq 'Deleted' })) {
        & $addFinding 'Medium' 'OrphanedAssignment' $a.PrincipalId $a.RoleName $a.ScopeName "Assignment ($($a.AssignmentState)) to a $($a.ArmPrincipalType) that no longer exists in the directory." 'Delete the orphaned assignment so it cannot be inherited if the object is restored.' $a.Scope
    }
    $lookupFailed = @($normalised | Where-Object { $_.PrincipalCategory -eq 'LookupFailed' })
    if ($lookupFailed.Count -gt 0) {
        & $addFinding 'Low' 'PrincipalLookupFailed' "$(@($lookupFailed | Select-Object -ExpandProperty PrincipalId -Unique).Count) principals" 'Various' 'Various' 'These principals could not be looked up in Microsoft Graph, so they are neither confirmed as live nor as deleted. Their access is listed by object ID.' 'Check the review account has Directory.Read.All and re-run.' $null
    }
    foreach ($a in @($normalised | Where-Object { $_.PrincipalCategory -eq 'ForeignPrincipal' })) {
        & $addFinding 'Medium' 'ForeignPrincipalAccess' $a.PrincipalId $a.RoleName $a.ScopeName "Assignment to a principal from another tenant ($($a.ArmPrincipalType))." 'Confirm which external organisation this is and whether access is still required.' $a.Scope
    }

    foreach ($grp in @($accessRows | Where-Object { $_.PrincipalCategory -in $userCategories -and $_.AccountEnabled -eq $false } | Group-Object -Property PrincipalId)) {
        $first = $grp.Group[0]
        & $addFinding 'Medium' 'DisabledAccountWithAccess' $first.DisplayName $first.RoleName $first.ScopeName "Disabled account still holds $($grp.Count) Azure access path(s): $(& $describeRows @($grp.Group) 6)" 'Remove Azure role assignments and group memberships as part of leaver processing.' $first.Scope
    }

    foreach ($grp in @($accessRows | Where-Object { $_.PrincipalCategory -in $workloadCategories -and $_.EffectiveState -eq 'Active' -and $_.ScopeLevel -in @('Root', 'ManagementGroup', 'Subscription') -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 } | Group-Object -Property PrincipalId)) {
        $rows = @($grp.Group)
        $first = $rows[0]
        $broad = @($rows | Where-Object { $_.PrivilegeTier -eq 'Critical' -or $_.ScopeLevel -ne 'Subscription' })
        $rating = if ($broad.Count -gt 0) { 'High' } else { 'Medium' }
        & $addFinding $rating 'WorkloadIdentityBroadAccess' $first.DisplayName (@($rows | Select-Object -ExpandProperty RoleName -Unique) -join ', ') (@($rows | Select-Object -ExpandProperty ScopeName -Unique) -join ', ') "$($first.PrincipalCategory) holds: $(& $describeRows $rows 10)" 'Scope workload identities to the resource groups they deploy to. Avoid Owner or User Access Administrator for automation; use Role Based Access Control Administrator with a condition if it must assign roles.' $first.Scope
    }

    foreach ($grp in @($normalised | Where-Object { $_.PrincipalCategory -in $userCategories -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 } | Group-Object -Property PrincipalId)) {
        $rows = @($grp.Group)
        $unique = @($rows | Group-Object -Property RoleDefinitionGuid, Scope | ForEach-Object { $_.Group[0] })
        $items = (@($unique | ForEach-Object { "$($_.RoleName) @ $($_.ScopeName)" } | Select-Object -First 10) -join '; ')
        & $addFinding 'Low' 'DirectUserAssignment' $rows[0].PrincipalDisplayName (@($unique | Select-Object -ExpandProperty RoleName -Unique) -join ', ') (@($unique | Select-Object -ExpandProperty ScopeName -Unique) -join ', ') "Privileged roles assigned directly to the user rather than a group: $items" 'Assign privileged Azure roles to role-assignable groups (or PIM for Groups) so membership is reviewed in one place.' $unique[0].Scope
    }

    foreach ($a in @($normalised | Where-Object { $_.AssignmentState -eq 'Eligible' -and $_.AssignmentType -eq 'Eligible (permanent)' -and $_.PrivilegeTier -eq 'Critical' })) {
        & $addFinding 'Low' 'PermanentEligibility' $a.PrincipalDisplayName $a.RoleName $a.ScopeName 'Eligible assignment for a Critical-tier role has no end date.' 'Set an eligibility expiry (for example 12 months) and cover it with an access review.' $a.Scope
    }

    foreach ($cr in @($customRoles | Where-Object { $_.AssignmentCount -gt 0 -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })) {
        & $addFinding 'High' 'PrivilegedCustomRole' $cr.RoleName $cr.RoleName $cr.AssignableScopes "Custom role is $($cr.PrivilegeTier) tier: $($cr.TierReason) Wildcards: $($cr.WildcardActions)" 'Replace wildcard actions with the specific operations needed, or use the equivalent built-in role so the privilege is obvious to reviewers. A role named Reader that can assign roles is especially misleading.' $null
    }

    $subsWithoutPim = @($subscriptionSummary | Where-Object { $_.StandingOwners -gt 0 -and $_.PimEligiblePaths -eq 0 })
    if ($subsWithoutPim.Count -gt 0) {
        & $addFinding 'Medium' 'NoPimInSubscription' "$($subsWithoutPim.Count) subscription(s)" 'Critical-tier roles' (@($subsWithoutPim | Select-Object -ExpandProperty SubscriptionName) -join ', ') 'Privileged access exists but nothing is PIM-eligible at, above or below these subscriptions, so all privileged access is standing.' 'Onboard to PIM for Azure resources (ideally at management group level) and move Owner, User Access Administrator and Contributor to eligible.' $null
    }
    foreach ($s in @($subscriptionSummary | Where-Object { $_.StandingOwners -gt $MaxOwnersPerSubscription })) {
        & $addFinding 'Medium' 'ExcessiveSubscriptionOwners' $s.SubscriptionName 'Critical-tier roles' $s.SubscriptionName "$($s.StandingOwners) users hold standing Critical-tier access (target: <= $MaxOwnersPerSubscription)." 'Reduce standing owners; keep the rest as PIM-eligible.' "/subscriptions/$($s.SubscriptionId)"
    }

    foreach ($g in $groupSummary) {
        if ((Get-AzRbacTierRank -Tier $g.HighestTier) -lt 3) { continue }
        if (-not $g.MembershipReadable) {
            & $addFinding 'Medium' 'GroupMembershipUnreadable' $g.GroupName $g.HighestTier $null "Group holds $($g.HighestTier)-tier Azure roles but its membership could not be read, so the users with this access are not listed." 'Check the review account can read group membership (Group.Read.All) and re-run.' $null
        }
        if ($g.Owners) {
            & $addFinding 'Medium' 'GroupOwnerEscalationPath' $g.GroupName $g.HighestTier $null "Group holds $($g.Roles). Owners who can add members (and so grant themselves this access): $($g.Owners)" 'Remove group owners, or make sure every owner is already entitled to the access the group grants. Use PIM for Groups for privileged access groups.' $null
        }
        if ($g.IsAssignableToRole -ne $true) {
            & $addFinding 'Medium' 'NonRoleAssignableGroup' $g.GroupName $g.HighestTier $null "Group holds $($g.Roles) but is not role-assignable, so Groups Administrators, User Administrators and other Entra roles can change its membership." 'Use a role-assignable group (isAssignableToRole) for privileged Azure access so only Privileged Role Administrators can manage membership.' $null
        }
        if ($g.GuestMembers -gt 0) {
            & $addFinding 'High' 'GuestInPrivilegedGroup' $g.GroupName $g.HighestTier $null "$($g.GuestMembers) guest(s) are members of a group holding $($g.Roles)." 'Remove guests from privileged groups or give them separate, scoped and reviewed access.' $null
        }
    }

    # Sign-in based findings.
    foreach ($u in @($userSummary | Where-Object { $_.PrincipalCategory -in $userCategories -and (Get-AzRbacTierRank -Tier $_.HighestTier) -ge 3 })) {
        if ($u.SignInDataAvailable -and $u.AccountEnabled -ne $false) {
            $created = Get-AzRbacDateValue -Value $u.CreatedDateTime
            $oldEnough = (-not $created) -or (($nowUtc - $created).TotalDays -gt $DormantDays)
            if (($null -eq $u.LastSignIn -and $oldEnough) -or ($u.DaysSinceSignIn -gt $DormantDays)) {
                $since = if ($u.LastSignIn) { "$($u.DaysSinceSignIn) days ago" } else { 'never (or before sign-in logging)' }
                $rating = if ($u.HighestTier -eq 'Critical' -and $u.StandingPrivilegedCount -gt 0) { 'High' } else { 'Medium' }
                & $addFinding $rating 'DormantPrivilegedAccount' $u.DisplayName $u.HighestTier $null "Last sign-in $since but holds $($u.HighestTier)-tier Azure access ($($u.CriticalAccess))." "Disable or remove access for accounts unused for more than $DormantDays days." $null
            }
        }
        if ($u.OnPremisesSynced -eq $true -and $u.HighestTier -eq 'Critical') {
            & $addFinding 'Medium' 'SyncedPrivilegedAccount' $u.DisplayName $u.HighestTier $null 'Account is synchronised from on-premises Active Directory and can manage Azure role assignments. A compromise of on-premises AD gives control of Azure.' 'Use cloud-only administrative accounts for privileged Azure access.' $null
        }
        if ($activity -and $u.StandingPrivilegedCount -gt 0 -and $u.AzureChangeEvents -eq 0 -and $u.AccountEnabled -ne $false) {
            & $addFinding 'Low' 'UnusedStandingAccess' $u.DisplayName $u.HighestTier $null "Holds standing $($u.HighestTier)-tier access but made no changes in Azure in the last $($activity.Days) days." 'Reduce to Reader or make the access PIM-eligible; standing write access that is not used is pure risk.' $null
        }
    }

    # Workload identity findings.
    foreach ($w in @($workloadSummary | Where-Object { $_.PrincipalCategory -ne 'MicrosoftPlatform' })) {
        $privileged = (Get-AzRbacTierRank -Tier $w.HighestTier) -ge 3
        if ($w.PrincipalCategory -eq 'ExternalApp') {
            $rating = if ($privileged) { 'High' } else { 'Medium' }
            & $addFinding $rating 'ThirdPartyAppAzureAccess' $w.DisplayName $w.HighestTier $null "Application published by another organisation ($($w.Publisher)) holds Azure access. Its credentials are managed outside this tenant." 'Confirm the vendor relationship and scope its access to the minimum resources.' $null
        }
        if (-not $privileged) { continue }
        if ($w.Owners) {
            $rating = if ($w.HighestTier -eq 'Critical') { 'High' } else { 'Medium' }
            & $addFinding $rating 'AppOwnerEscalationPath' $w.DisplayName $w.HighestTier $null "Owners can add credentials to this identity and act with its Azure access: $($w.Owners)" 'Remove owners from privileged application registrations and enterprise apps; manage them through a controlled pipeline.' $null
        }
        if ($w.LongLivedCredentials -gt 0) {
            & $addFinding 'Medium' 'LongLivedCredential' $w.DisplayName $w.HighestTier $null "$($w.LongLivedCredentials) credential(s) valid for more than 400 days (longest $($w.LongestLifetimeDays) days)." 'Use federated credentials (workload identity federation) or a managed identity; otherwise rotate secrets at least every 6-12 months.' $null
        }
        elseif ($w.ActiveSecrets -gt 0 -and $w.ActiveCertificates -eq 0 -and $w.FederatedCredentials -eq 0) {
            & $addFinding 'Low' 'SecretOnlyCredential' $w.DisplayName $w.HighestTier $null "Authenticates with client secrets only ($($w.ActiveSecrets) active)." 'Prefer federated credentials or certificates over client secrets.' $null
        }
        if ($w.PrincipalCategory -in @('ServicePrincipal', 'ExternalApp') -and $null -ne $w.DaysSinceSignIn -and $w.DaysSinceSignIn -gt $DormantDays) {
            & $addFinding 'Medium' 'DormantWorkloadIdentity' $w.DisplayName $w.HighestTier $null "No sign-in for $($w.DaysSinceSignIn) days but still holds $($w.HighestTier)-tier Azure access." 'Remove the role assignments (and the credentials) if the identity is no longer used.' $null
        }
        if ($w.PrincipalCategory -eq 'ManagedIdentity' -and $w.ManagedIdentityHost) {
            $hostIsCompute = $w.ManagedIdentityHost -match 'virtualmachines|microsoft\.web/sites|automationaccounts|logic/workflows|containerinstance|containerapps|managedclusters|batchaccounts|databricks|datafactory|synapse|machinelearningservices'
            $rating = if ($w.HighestTier -eq 'Critical' -and $hostIsCompute) { 'High' } else { 'Medium' }
            & $addFinding $rating 'ManagedIdentityEscalationPath' $w.DisplayName $w.HighestTier $null "Managed identity holds $($w.HighestTier)-tier access ($($w.CriticalAccess)) and is attached to $($w.ManagedIdentityHost). Anyone who can run code on or modify that resource can act as this identity." 'Scope the identity to what the workload needs, and restrict who can change or run code on the host resource.' $null
        }
    }

    # External tenants via Lighthouse.
    foreach ($l in $lighthouse) {
        $privileged = (Get-AzRbacTierRank -Tier $l.PrivilegeTier) -ge 3 -or $l.CanAssignRoles
        $rating = if ($privileged -and $l.AuthorizationType -eq 'Permanent') { 'High' } else { 'Medium' }
        $tenantText = if ($l.ManagedByTenant) { "$($l.ManagedByTenant) ($($l.ManagedByTenantId))" } else { $l.ManagedByTenantId }
        $assignText = if ($l.CanAssignRoles) { " Can assign: $($l.CanAssignRoles)." } else { '' }
        & $addFinding $rating 'LighthouseDelegation' $tenantText $l.RoleName $l.SubscriptionName "External tenant has $($l.AuthorizationType) $($l.RoleName) for '$($l.PrincipalDisplayName)' through Lighthouse offer '$($l.OfferName)'.$assignText This access does not appear in the subscription's role assignments." 'Confirm the contract still requires this access, prefer eligible (JIT) authorisations, and review the offer at least annually.' $l.Scope
    }

    # Access outside RBAC.
    foreach ($v in @($resourceSecurity.KeyVaults | Where-Object { $_.PermissionModel -eq 'Access policies' })) {
        & $addFinding 'Medium' 'KeyVaultAccessPolicies' $v.VaultName 'Access policy' $v.SubscriptionName "Vault uses access policies ($($v.AccessPolicyCount)), so secret and key access is not visible in Azure RBAC. Anyone with Contributor or Key Vault Contributor on it can grant themselves secret access." 'Migrate the vault to the Azure RBAC permission model.' $v.ResourceId
    }
    foreach ($p in @($resourceSecurity.KeyVaultAccessPolicies | Where-Object { $_.CanReadSecretsOrKeys -and $_.PrincipalCategory -in @('Guest', 'Deleted', 'ExternalApp', 'ForeignPrincipal') })) {
        $rating = if ($p.PrincipalCategory -eq 'Deleted') { 'Low' } else { 'High' }
        & $addFinding $rating 'KeyVaultPolicyRiskyPrincipal' $p.PrincipalDisplayName 'Access policy' $p.VaultName "$($p.PrincipalCategory) principal has secret/key access through an access policy (secrets: $($p.SecretPermissions); keys: $($p.KeyPermissions))." 'Remove the access policy entry.' $p.ResourceId
    }
    foreach ($k in @($resourceSecurity.AksClusters | Where-Object { -not $_.LocalAccountsDisabled })) {
        & $addFinding 'High' 'AksLocalAccounts' $k.ClusterName 'Kubernetes cluster-admin' $k.SubscriptionName 'Local accounts are enabled, so anyone who can list cluster admin credentials gets cluster-admin without Entra ID or Azure RBAC.' 'Disable local accounts and use Entra ID with Azure RBAC for Kubernetes authorisation.' $k.ResourceId
    }
    foreach ($s in @($resourceSecurity.SqlServers | Where-Object { -not $_.EntraOnlyAuth })) {
        & $addFinding 'Medium' 'SqlAuthenticationEnabled' $s.ServerName "SQL admin '$($s.SqlAdminLogin)'" $s.SubscriptionName 'SQL authentication is enabled, so database access exists outside Entra ID and is not visible in this review.' 'Enable Microsoft Entra-only authentication.' $s.ResourceId
    }
    $sharedKey = @($resourceSecurity.StorageAccounts | Where-Object { $_.SharedKeyAccess -ne 'Disabled' })
    foreach ($grp in @($sharedKey | Group-Object -Property SubscriptionName)) {
        & $addFinding 'Low' 'StorageSharedKeyAccess' "$($grp.Count) storage account(s)" 'listKeys' $grp.Name "Shared key access is enabled on: $((@($grp.Group | Select-Object -ExpandProperty AccountName | Select-Object -First 15) -join ', '))$(if ($grp.Count -gt 15) { ' ...' }). Anyone with Contributor (listKeys) gets full data access that bypasses Entra ID and RBAC data roles." 'Disable shared key access where applications use Entra ID; otherwise rotate keys and restrict who holds listKeys.' $null
    }
    $localAuth = @($resourceSecurity.LocalAuthResources | Where-Object { $_.LocalAuth -eq 'Enabled' })
    foreach ($grp in @($localAuth | Group-Object -Property SubscriptionName)) {
        & $addFinding 'Low' 'LocalAuthEnabled' "$($grp.Count) resource(s)" 'Access keys' $grp.Name "Key-based (local) authentication is enabled on: $((@($grp.Group | ForEach-Object { "$($_.ResourceName) ($($_.ResourceType))" } | Select-Object -First 12) -join ', '))$(if ($grp.Count -gt 12) { ' ...' })." 'Disable local authentication (disableLocalAuth) so access goes through Entra ID and RBAC.' $null
    }

    # Recent grants of privileged roles.
    if ($activity) {
        foreach ($c in @($activity.RbacChanges | Where-Object { $_.Change -eq 'Granted' -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 4 })) {
            & $addFinding 'Low' 'RecentPrivilegedGrant' $c.PrincipalDisplayName $c.RoleName $c.SubscriptionName "$($c.RoleName) granted by $($c.ChangedBy) on $(if ($c.Timestamp -is [datetime]) { $c.Timestamp.ToString('yyyy-MM-dd') } else { $c.Timestamp }) at $($c.Scope)." 'Confirm each recent Critical-tier grant was approved.' $c.Scope
        }
    }

    # ---- Scorecard --------------------------------------------------------------------------
    $privilegedUserRows = @($accessRows | Where-Object { $_.PrincipalCategory -in $userCategories -and (Get-AzRbacTierRank -Tier $_.PrivilegeTier) -ge 3 })
    $standingPriv = @($privilegedUserRows | Where-Object { $_.IsStanding }).Count
    $eligiblePriv = @($privilegedUserRows | Where-Object { $_.EffectiveState -eq 'Eligible' }).Count
    $pimCoverage = if (($standingPriv + $eligiblePriv) -gt 0) { [Math]::Round(($eligiblePriv / ($standingPriv + $eligiblePriv)) * 100, 1) } else { 100 }
    $standingCriticalUsers = @($accessRows | Where-Object { $_.IsStanding -and $_.PrivilegeTier -eq 'Critical' -and $_.PrincipalCategory -in $userCategories } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $canGrantAccess = @($accessRows | Where-Object { $_.PrivilegeTier -eq 'Critical' -and $_.PrincipalCategory -ne 'MicrosoftPlatform' -and $_.PrincipalCategory -ne 'Group' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $rootCount = @($normalised | Where-Object { $_.ScopeLevel -eq 'Root' -and $_.PrincipalCategory -ne 'MicrosoftPlatform' }).Count
    $guestAny = @($accessRows | Where-Object { $_.PrincipalCategory -eq 'Guest' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $orphaned = @($normalised | Where-Object { $_.PrincipalCategory -eq 'Deleted' }).Count
    $spCritical = @($accessRows | Where-Object { $_.PrincipalCategory -in $workloadCategories -and $_.PrivilegeTier -eq 'Critical' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
    $subsOverLimit = @($subscriptionSummary | Where-Object { $_.StandingOwners -gt $MaxOwnersPerSubscription }).Count
    $dormant = @($findings | Where-Object { $_.FindingType -eq 'DormantPrivilegedAccount' }).Count
    $kvPolicies = @($resourceSecurity.KeyVaults | Where-Object { $_.PermissionModel -eq 'Access policies' }).Count
    $externalTenants = @($lighthouse | Select-Object -ExpandProperty ManagedByTenantId -Unique).Count

    $statusOf = {
        param($Value, $Green, $Amber)
        if ($Value -le $Green) { return 'Green' }
        if ($Value -le $Amber) { return 'Amber' }
        return 'Red'
    }

    $scorecard = @(
        [pscustomobject]@{ Metric = 'Management groups'; Value = $mgNames.Count; Status = 'Info'; Target = ''; Commentary = 'Management groups readable by the review account.' },
        [pscustomobject]@{ Metric = 'Subscriptions reviewed'; Value = $subIds.Count; Status = 'Info'; Target = ''; Commentary = "Resources visible in $($visibleSubIds.Count) of them." },
        [pscustomobject]@{ Metric = 'Resources visible'; Value = $totalResources; Status = 'Info'; Target = ''; Commentary = 'Resources the review account can read through Azure Resource Graph.' },
        [pscustomobject]@{ Metric = 'Role assignments (active)'; Value = @($normalised | Where-Object { $_.AssignmentState -eq 'Active' }).Count; Status = 'Info'; Target = ''; Commentary = 'At every scope from tenant root to individual resources.' },
        [pscustomobject]@{ Metric = 'Role assignments (PIM-eligible)'; Value = @($normalised | Where-Object { $_.AssignmentState -eq 'Eligible' }).Count; Status = 'Info'; Target = ''; Commentary = 'PIM for Azure resources.' },
        [pscustomobject]@{ Metric = 'Identities that can grant access'; Value = $canGrantAccess; Status = 'Info'; Target = ''; Commentary = 'Users and workload identities holding Owner, User Access Administrator or equivalent anywhere (excluding Microsoft platform identities).' },
        [pscustomobject]@{ Metric = 'Users with standing Critical access'; Value = $standingCriticalUsers; Status = (& $statusOf $standingCriticalUsers 2 5); Target = '<= 2 (break-glass)'; Commentary = 'Permanent Owner, User Access Administrator or equivalent.' },
        [pscustomobject]@{ Metric = 'Privileged access through PIM'; Value = "$pimCoverage%"; Status = $(if ($pimCoverage -ge 90) { 'Green' } elseif ($pimCoverage -ge 60) { 'Amber' } else { 'Red' }); Target = '>= 90%'; Commentary = 'Share of user access paths to Critical/High roles that are eligible rather than standing.' },
        [pscustomobject]@{ Metric = 'Dormant privileged users'; Value = $(if ($signIn -and $signIn.SignInAvailable) { $dormant } else { 'n/a' }); Status = $(if ($signIn -and $signIn.SignInAvailable) { & $statusOf $dormant 0 2 } else { 'Info' }); Target = '0'; Commentary = "No sign-in for $DormantDays days." },
        [pscustomobject]@{ Metric = 'Assignments at tenant root'; Value = $rootCount; Status = $(if ($rootCount -eq 0) { 'Green' } else { 'Red' }); Target = '0'; Commentary = 'Excluding Microsoft platform identities such as MS-PIM.' },
        [pscustomobject]@{ Metric = 'Guests with Azure access'; Value = $guestAny; Status = (& $statusOf $guestAny 0 3); Target = '0'; Commentary = 'Directly or through groups.' },
        [pscustomobject]@{ Metric = 'Orphaned assignments'; Value = $orphaned; Status = (& $statusOf $orphaned 0 10); Target = '0'; Commentary = 'Assignments to principals confirmed deleted.' },
        [pscustomobject]@{ Metric = 'Workload identities that can grant access'; Value = $spCritical; Status = (& $statusOf $spCritical 0 3); Target = '0'; Commentary = 'Service principals and managed identities with Critical-tier roles.' },
        [pscustomobject]@{ Metric = 'External tenants (Lighthouse)'; Value = $(if ($SkipExtendedChecks) { 'n/a' } else { $externalTenants }); Status = 'Info'; Target = ''; Commentary = 'Organisations with delegated access that is not shown in role assignments.' },
        [pscustomobject]@{ Metric = 'Key Vaults on access policies'; Value = $(if ($SkipExtendedChecks) { 'n/a' } else { $kvPolicies }); Status = $(if ($SkipExtendedChecks) { 'Info' } else { & $statusOf $kvPolicies 0 5 }); Target = '0'; Commentary = 'Secret access governed outside Azure RBAC.' },
        [pscustomobject]@{ Metric = 'Subscriptions over owner limit'; Value = $subsOverLimit; Status = $(if ($subsOverLimit -eq 0) { 'Green' } else { 'Red' }); Target = '0'; Commentary = "More than $MaxOwnersPerSubscription users with standing Critical-tier access." },
        [pscustomobject]@{ Metric = 'Coverage gaps'; Value = $script:AzRbacCoverageGaps.Count; Status = $(if ($script:AzRbacCoverageGaps.Count -eq 0) { 'Green' } else { 'Amber' }); Target = '0'; Commentary = 'Scopes or APIs the review account could not read (see the last section).' }
    )

    # ---- Optional resource-level access ------------------------------------------------------
    $resourceAccessPath = $null
    if ($IncludeResourceLevelAccess -and $visibleSubIds.Count -gt 0) {
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
            $resources = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $visibleSubIds -Query 'resources | project id = tolower(id), name, type, resourceGroup = tolower(resourceGroup), subscriptionId = tolower(subscriptionId), location')
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
    $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    $assignmentExport = @($normalised | Select-Object PrincipalDisplayName, PrincipalUserPrincipalName, PrincipalCategory, PrincipalType, AccountEnabled, PrincipalResolved, RoleName, RoleType, PrivilegeTier, TierNote, ScopeLevel, ScopeName, SubscriptionName, ResourceGroup, ResourceType, ResourcesInScope, AssignmentState, AssignmentType, StartDateTime, EndDateTime, HasCondition, Condition, CreatedOn, CreatedBy, Description, Scope, SubscriptionId, ManagementGroupId, PrincipalId, RoleDefinitionGuid, AssignmentId, Source)
    $accessExport = @($accessRows | Select-Object DisplayName, UserPrincipalName, PrincipalCategory, AccountEnabled, AccessPath, ViaGroupName, MembershipType, RoleName, RoleType, PrivilegeTier, ScopeLevel, ScopeName, SubscriptionName, ResourceGroup, ResourcesInScope, AssignmentState, EffectiveState, AssignmentType, IsStanding, EndDateTime, HasCondition, Scope, SubscriptionId, ManagementGroupId, PrincipalId, ViaGroupId, AssignmentId)
    $userSummaryExport = @($userSummary | Sort-Object -Property @{ Expression = { Get-AzRbacTierRank -Tier $_.HighestTier }; Descending = $true }, @{ Expression = 'StandingPrivilegedCount'; Descending = $true }, DisplayName)
    $findingsExport = @($findings | Sort-Object -Property @{ Expression = { $severityOrder[$_.RiskRating] } }, FindingType, Subject)
    $groupOwnerExport = @($groupOwners | Select-Object GroupDisplayName, HighestGroupTier, IsAssignableToRole, OwnerDisplayName, OwnerUserPrincipalName, OwnerType, GroupId, OwnerId)
    $subscriptionExport = @($subscriptionSummary)
    $coverageExport = @($script:AzRbacCoverageGaps)
    $activityExport = if ($activity) { @($activity.CallerActivity | Sort-Object -Property ChangeEvents -Descending | Select-Object Caller, SubscriptionName, ChangeEvents, @{ Name = 'LastChange'; Expression = { if ($_.LastChange -is [datetime]) { $_.LastChange.ToString('yyyy-MM-dd HH:mm') } else { $_.LastChange } } }, TopOperations, HasAzureRole, PrincipalId, SubscriptionId) } else { @() }
    $rbacChangeExport = if ($activity) { @($activity.RbacChanges | Select-Object @{ Name = 'Timestamp'; Expression = { if ($_.Timestamp -is [datetime]) { $_.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { $_.Timestamp } } }, Change, ChangedBy, PrincipalDisplayName, PrincipalCategory, RoleName, PrivilegeTier, SubscriptionName, Scope, PrincipalId, RoleDefinitionGuid, AssignmentId) } else { @() }
    $lighthouseExport = @($lighthouse | Select-Object SubscriptionName, ManagedByTenant, ManagedByTenantId, OfferName, AuthorizationType, PrincipalDisplayName, RoleName, PrivilegeTier, CanAssignRoles, Scope, PrincipalId, RoleDefinitionGuid, Description)
    $kvPolicyExport = @($resourceSecurity.KeyVaultAccessPolicies | Select-Object SubscriptionName, VaultName, PrincipalDisplayName, UserPrincipalName, PrincipalCategory, SecretPermissions, KeyPermissions, CertificatePermissions, CanReadSecretsOrKeys, ObjectId, ApplicationId, ResourceId)

    Export-PimData -Data $assignmentExport -CsvPath (Join-Path $rawFolder 'AzureRoleAssignments.csv')
    Export-PimData -Data $accessExport -CsvPath (Join-Path $rawFolder 'AzureUserAccess.csv')
    Export-PimData -Data $userSummaryExport -CsvPath (Join-Path $rawFolder 'AzureUserSummary.csv')
    Export-PimData -Data @($matrix) -CsvPath (Join-Path $rawFolder 'AzureAccessMatrix.csv')
    Export-PimData -Data $subscriptionExport -CsvPath (Join-Path $rawFolder 'AzureSubscriptionSummary.csv')
    Export-PimData -Data $findingsExport -CsvPath (Join-Path $rawFolder 'AzureFindings.csv')
    Export-PimData -Data @($groupMembers) -CsvPath (Join-Path $rawFolder 'AzureGroupMembers.csv')
    Export-PimData -Data $groupOwnerExport -CsvPath (Join-Path $rawFolder 'AzureGroupOwners.csv')
    Export-PimData -Data $groupSummary -CsvPath (Join-Path $rawFolder 'AzureGroupSummary.csv')
    Export-PimData -Data $workloadSummary -CsvPath (Join-Path $rawFolder 'AzureWorkloadIdentities.csv')
    Export-PimData -Data $customRoles -CsvPath (Join-Path $rawFolder 'AzureCustomRoles.csv')
    Export-PimData -Data $scorecard -CsvPath (Join-Path $rawFolder 'AzureScorecard.csv')
    Export-PimData -Data $coverageExport -CsvPath (Join-Path $rawFolder 'AzureCoverageGaps.csv')
    Export-PimData -Data @($roleInfo.Values | Sort-Object RoleType, RoleName) -CsvPath (Join-Path $rawFolder 'AzureRoleDefinitions.csv')
    Export-PimData -Data $lighthouseExport -CsvPath (Join-Path $rawFolder 'AzureLighthouseDelegations.csv')
    Export-PimData -Data @($denyAssignments) -CsvPath (Join-Path $rawFolder 'AzureDenyAssignments.csv')
    Export-PimData -Data @($resourceSecurity.KeyVaults) -CsvPath (Join-Path $rawFolder 'AzureKeyVaults.csv')
    Export-PimData -Data $kvPolicyExport -CsvPath (Join-Path $rawFolder 'AzureKeyVaultAccessPolicies.csv')
    Export-PimData -Data @($resourceSecurity.StorageAccounts) -CsvPath (Join-Path $rawFolder 'AzureStorageAccounts.csv')
    Export-PimData -Data @($resourceSecurity.SqlServers) -CsvPath (Join-Path $rawFolder 'AzureSqlServers.csv')
    Export-PimData -Data @($resourceSecurity.AksClusters) -CsvPath (Join-Path $rawFolder 'AzureAksClusters.csv')
    Export-PimData -Data @($resourceSecurity.LocalAuthResources) -CsvPath (Join-Path $rawFolder 'AzureLocalAuthResources.csv')
    Export-PimData -Data $activityExport -CsvPath (Join-Path $rawFolder 'AzureActivityByCaller.csv')
    Export-PimData -Data $rbacChangeExport -CsvPath (Join-Path $rawFolder 'AzureRoleAssignmentChanges.csv')

    $reportData = @{
        TenantLabel          = $TenantLabel
        TenantId             = $tenantGuid
        MaxOwners            = $MaxOwnersPerSubscription
        DormantDays          = $DormantDays
        ActivityDays         = $(if ($activity) { $activity.Days } else { $null })
        SignInAvailable      = [bool]($signIn -and $signIn.SignInAvailable)
        ExtendedChecks       = -not $SkipExtendedChecks
        Scorecard            = $scorecard
        Findings             = $findingsExport
        Subscriptions        = $subscriptionExport
        SubscriptionDetail   = $subscriptionDetail
        SubscriptionNames    = $subNames
        UserSummary          = $userSummaryExport
        Workloads            = $workloadSummary
        Groups               = $groupSummary
        CustomRoles          = $customRoles
        Lighthouse           = $lighthouseExport
        KeyVaults            = @($resourceSecurity.KeyVaults)
        KeyVaultPolicies     = $kvPolicyExport
        StorageAccounts      = @($resourceSecurity.StorageAccounts)
        SqlServers           = @($resourceSecurity.SqlServers)
        AksClusters          = @($resourceSecurity.AksClusters)
        LocalAuthResources   = @($resourceSecurity.LocalAuthResources)
        RbacChanges          = $rbacChangeExport
        ActivityByCaller     = $activityExport
        DenyAssignments      = @($denyAssignments)
        CoverageGaps         = $coverageExport
        ManagementGroups     = $mgNames.Count
        VisibleSubscriptions = $visibleSubIds.Count
        TotalResources       = $totalResources
    }
    $summaryInfo = New-AzureRbacReport -OutputFolder $OutputFolder -Data $reportData

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
        @{ Name = '47_Az_Groups'; Data = $groupSummary },
        @{ Name = '48_Az_Group_Members'; Data = @($groupMembers) },
        @{ Name = '49_Az_Group_Owners'; Data = $groupOwnerExport },
        @{ Name = '50_Az_Workload_Identities'; Data = $workloadSummary },
        @{ Name = '51_Az_Custom_Roles'; Data = $customRoles },
        @{ Name = '52_Az_Lighthouse'; Data = $lighthouseExport },
        @{ Name = '53_Az_KeyVaults'; Data = @($resourceSecurity.KeyVaults) },
        @{ Name = '54_Az_KV_Access_Policies'; Data = $kvPolicyExport },
        @{ Name = '55_Az_Storage'; Data = @($resourceSecurity.StorageAccounts) },
        @{ Name = '56_Az_SQL'; Data = @($resourceSecurity.SqlServers) },
        @{ Name = '57_Az_AKS'; Data = @($resourceSecurity.AksClusters) },
        @{ Name = '58_Az_Local_Auth'; Data = @($resourceSecurity.LocalAuthResources) },
        @{ Name = '59_Az_Activity_By_Caller'; Data = $activityExport },
        @{ Name = '60_Az_RBAC_Changes'; Data = $rbacChangeExport },
        @{ Name = '61_Az_Deny_Assignments'; Data = @($denyAssignments) },
        @{ Name = '62_Az_Coverage_Gaps'; Data = $coverageExport }
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
