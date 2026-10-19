<#
.SYNOPSIS
Additional data collectors for the Azure RBAC review. Function definitions only; dot-sourced by
Get-AzureRbacReview.ps1, which supplies the shared helpers (Invoke-ArmRequest, Get-AzRbacProp,
Invoke-AzRbacResourceGraphQuery, Add-AzRbacCoverageGap).

Everything here is read-only and degrades gracefully: a collector that cannot read its source logs a
warning, records a coverage gap and returns empty results rather than stopping the review.

Collectors:
- Get-AzRbacSignInActivity        last sign-in, account creation and on-premises sync for privileged users;
                                  last sign-in for service principals
- Get-AzRbacActivityLog           who actually made changes in each subscription (Activity Log), and
                                  recent role assignment changes
- Get-AzRbacLighthouseDelegations external tenants (MSPs) with access through Azure Lighthouse
- Get-AzRbacResourceSecurity      access paths outside Azure RBAC: Key Vault access policies, storage
                                  shared keys, SQL authentication, AKS local accounts, local/key auth
- Get-AzRbacManagedIdentityHosts  which resource each managed identity belongs to
- Get-AzRbacWorkloadDetails       service principal credentials, owners and publisher
- Get-AzRbacDenyAssignments       deny assignments
#>

# Microsoft-owned tenants that publish first-party service principals.
$script:AzRbacMicrosoftTenants = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
    '72f988bf-86f1-41af-91ab-2d7cd011db47',
    '33e01921-4d64-4f8c-a055-5bdaffd5e33d',
    'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'
)

function Test-AzRbacMicrosoftPrincipal {
    param(
        [string]$AppOwnerOrganizationId,
        [string]$DisplayName,
        [string]$ServicePrincipalType
    )

    if ($AppOwnerOrganizationId -and ($script:AzRbacMicrosoftTenants -contains $AppOwnerOrganizationId.ToLowerInvariant())) {
        return $true
    }

    # Defender for Cloud creates managed identities with these names in the customer tenant.
    if ($ServicePrincipalType -eq 'ManagedIdentity' -and [string]$DisplayName -match '/securityOperators/') {
        return $true
    }

    return $false
}

function Get-AzRbacDateValue {
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed
    }
    return $null
}

function Get-AzRbacLatestDate {
    param([object[]]$Values)

    $latest = $null
    foreach ($v in $Values) {
        $d = Get-AzRbacDateValue -Value $v
        if ($d -and (($null -eq $latest) -or ($d -gt $latest))) { $latest = $d }
    }
    return $latest
}

function Test-AzRbacForbidden {
    param([object]$ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    return ($message -match '403|Forbidden|Authorization_RequestDenied|Insufficient privileges|not have premium|premium license|Unauthorized')
}

# ---------------------------------------------------------------------------------------------
# Sign-in activity
# ---------------------------------------------------------------------------------------------

function Get-AzRbacSignInActivity {
    [CmdletBinding()]
    param(
        [string[]]$UserIds,
        [string[]]$ServicePrincipalAppIds
    )

    $users = @{}
    $servicePrincipals = @{}
    $signInAvailable = $true
    $spSignInAvailable = $true

    $ids = @($UserIds | Where-Object { $_ } | Select-Object -Unique)
    Write-PimLog -Message "Reading sign-in activity for $($ids.Count) users with Azure access."

    foreach ($id in $ids) {
        $select = 'id,createdDateTime,onPremisesSyncEnabled,lastPasswordChangeDateTime'
        if ($signInAvailable) { $select = "$select,signInActivity" }

        $user = $null
        try {
            $user = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/${id}?`$select=$select"
        }
        catch {
            if ($signInAvailable -and (Test-AzRbacForbidden -ErrorRecord $_)) {
                $signInAvailable = $false
                Write-PimLog -Level WARN -Message 'Sign-in activity is not readable (needs AuditLog.Read.All and Entra ID P1). Continuing without last sign-in dates.'
                Add-AzRbacCoverageGap -Scope 'Microsoft Graph' -Operation 'User sign-in activity' -StatusCode '403' -Message $_.Exception.Message
                try {
                    $user = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users/${id}?`$select=id,createdDateTime,onPremisesSyncEnabled,lastPasswordChangeDateTime"
                }
                catch {
                    $user = $null
                }
            }
        }

        if (-not $user) { continue }

        $activity = Get-AzRbacProp -InputObject $user -Name 'signInActivity'
        $lastInteractive = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $activity -Name 'lastSignInDateTime')
        $lastNonInteractive = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $activity -Name 'lastNonInteractiveSignInDateTime')
        $lastSuccessful = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $activity -Name 'lastSuccessfulSignInDateTime')
        $last = Get-AzRbacLatestDate -Values @($lastInteractive, $lastNonInteractive, $lastSuccessful)

        $users[$id.ToLowerInvariant()] = [pscustomobject]@{
            LastSignIn             = $last
            LastInteractiveSignIn  = $lastInteractive
            CreatedDateTime        = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $user -Name 'createdDateTime')
            OnPremisesSyncEnabled  = Get-AzRbacProp -InputObject $user -Name 'onPremisesSyncEnabled'
            LastPasswordChange     = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $user -Name 'lastPasswordChangeDateTime')
            SignInDataAvailable    = $signInAvailable
        }
    }

    $appIds = @($ServicePrincipalAppIds | Where-Object { $_ } | Select-Object -Unique)
    if ($appIds.Count -gt 0) {
        Write-PimLog -Message "Reading sign-in activity for $($appIds.Count) service principals with Azure access."
    }
    foreach ($appId in $appIds) {
        if (-not $spSignInAvailable) { break }
        try {
            $resp = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?`$filter=appId eq '$appId'"
            $row = @(Get-AzRbacProp -InputObject $resp -Name 'value') | Select-Object -First 1
            if ($row) {
                $lastActivity = Get-AzRbacProp -InputObject $row -Name 'lastSignInActivity'
                $servicePrincipals[$appId.ToLowerInvariant()] = Get-AzRbacLatestDate -Values @(
                    (Get-AzRbacProp -InputObject $lastActivity -Name 'lastSignInDateTime'),
                    (Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $row -Name 'applicationAuthenticationClientSignInActivity') -Name 'lastSignInDateTime'),
                    (Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $row -Name 'delegatedClientSignInActivity') -Name 'lastSignInDateTime')
                )
            }
        }
        catch {
            if (Test-AzRbacForbidden -ErrorRecord $_) {
                $spSignInAvailable = $false
                Write-PimLog -Level WARN -Message 'Service principal sign-in activity is not readable (needs AuditLog.Read.All). Continuing without it.'
                Add-AzRbacCoverageGap -Scope 'Microsoft Graph' -Operation 'Service principal sign-in activity' -StatusCode '403' -Message $_.Exception.Message
            }
        }
    }

    return [pscustomobject]@{
        Users                       = $users
        ServicePrincipals           = $servicePrincipals
        SignInAvailable             = $signInAvailable
        ServicePrincipalSignInAvailable = $spSignInAvailable
    }
}

# ---------------------------------------------------------------------------------------------
# Activity Log
# ---------------------------------------------------------------------------------------------

function Get-AzRbacActivityEvents {
    param(
        [string]$SubscriptionId,
        [string]$Filter,
        [string]$Select,
        [int]$MaxEvents
    )

    $encodedFilter = [System.Uri]::EscapeDataString($Filter)
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&`$filter=$encodedFilter&`$select=$Select"
    $events = New-Object System.Collections.ArrayList
    $truncated = $false

    while ($uri) {
        $response = Invoke-ArmRequest -Uri $uri -Method GET
        foreach ($e in @(Get-AzRbacProp -InputObject $response -Name 'value')) {
            if ($null -ne $e) { $null = $events.Add($e) }
        }
        if ($MaxEvents -gt 0 -and $events.Count -ge $MaxEvents) {
            $truncated = $true
            break
        }
        $uri = Get-AzRbacProp -InputObject $response -Name 'nextLink'
    }

    return [pscustomobject]@{ Events = @($events); Truncated = $truncated }
}

function Get-AzRbacActivityLog {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionIds,
        [hashtable]$SubscriptionNames,
        [int]$Days = 30,
        [int]$MaxEventsPerSubscription = 25000
    )

    if ($Days -lt 1) { $Days = 1 }
    if ($Days -gt 89) { $Days = 89 }

    $end = (Get-Date).ToUniversalTime()
    $start = $end.AddDays(-$Days)
    $window = "eventTimestamp ge '{0}' and eventTimestamp le '{1}'" -f $start.ToString('yyyy-MM-ddTHH:mm:ssZ'), $end.ToString('yyyy-MM-ddTHH:mm:ssZ')

    $callerActivity = @{}
    $rbacChanges = New-Object System.Collections.ArrayList
    $truncatedSubs = New-Object System.Collections.ArrayList

    $index = 0
    foreach ($sid in $SubscriptionIds) {
        $index++
        $subName = if ($SubscriptionNames -and $SubscriptionNames.ContainsKey($sid)) { $SubscriptionNames[$sid] } else { $sid }
        Write-Progress -Activity 'Azure RBAC review' -Status "Reading Activity Log ($Days days): $subName" -PercentComplete ([int](($index / [Math]::Max(1, $SubscriptionIds.Count)) * 100))

        # 1. Every change made in the subscription, aggregated per caller.
        try {
            $result = Get-AzRbacActivityEvents -SubscriptionId $sid -Filter $window -Select 'caller,eventTimestamp,operationName,status,resourceId' -MaxEvents $MaxEventsPerSubscription
            if ($result.Truncated) {
                $null = $truncatedSubs.Add($subName)
                Add-AzRbacCoverageGap -Scope "/subscriptions/$sid" -Operation 'Activity Log (truncated)' -StatusCode '' -Message "Stopped after $MaxEventsPerSubscription events; activity for this subscription is a sample, not complete."
            }

            foreach ($e in $result.Events) {
                $caller = [string](Get-AzRbacProp -InputObject $e -Name 'caller')
                if ([string]::IsNullOrWhiteSpace($caller)) { continue }

                $status = [string](Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $e -Name 'status') -Name 'value')
                if ($status -and $status -notin @('Succeeded', 'Accepted', 'Started')) { continue }

                $operation = [string](Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $e -Name 'operationName') -Name 'value')
                if ($operation -match '/read$') { continue }

                $key = "$($caller.ToLowerInvariant())|$sid"
                if (-not $callerActivity.ContainsKey($key)) {
                    $callerActivity[$key] = [pscustomobject]@{
                        Caller           = $caller.ToLowerInvariant()
                        SubscriptionId   = $sid
                        SubscriptionName = $subName
                        Events           = 0
                        LastActivity     = $null
                        Operations       = @{}
                    }
                }

                $entry = $callerActivity[$key]
                $entry.Events++
                $ts = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $e -Name 'eventTimestamp')
                if ($ts -and (($null -eq $entry.LastActivity) -or $ts -gt $entry.LastActivity)) { $entry.LastActivity = $ts }
                if ($operation) {
                    if (-not $entry.Operations.ContainsKey($operation)) { $entry.Operations[$operation] = 0 }
                    $entry.Operations[$operation]++
                }
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Activity Log not readable for $subName : $($_.Exception.Message)"
            Add-AzRbacCoverageGap -Scope "/subscriptions/$sid" -Operation 'Activity Log' -StatusCode '' -Message $_.Exception.Message
            continue
        }

        # 2. Role assignment changes, with the request body so we know who was granted what.
        try {
            $rbacFilter = "$window and resourceProvider eq 'Microsoft.Authorization'"
            $rbacResult = Get-AzRbacActivityEvents -SubscriptionId $sid -Filter $rbacFilter -Select 'caller,eventTimestamp,operationName,status,resourceId,properties,correlationId' -MaxEvents 5000
            $seen = @{}
            foreach ($e in $rbacResult.Events) {
                $operation = [string](Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $e -Name 'operationName') -Name 'value')
                if ($operation -notmatch 'roleAssignments/(write|delete)$') { continue }
                $status = [string](Get-AzRbacProp -InputObject (Get-AzRbacProp -InputObject $e -Name 'status') -Name 'value')
                if ($status -ne 'Succeeded') { continue }

                $correlation = [string](Get-AzRbacProp -InputObject $e -Name 'correlationId')
                $dedupe = "$correlation|$operation"
                if ($correlation -and $seen.ContainsKey($dedupe)) { continue }
                $seen[$dedupe] = $true

                $props = Get-AzRbacProp -InputObject $e -Name 'properties'
                $principalId = $null
                $roleDefinitionId = $null
                $scope = $null
                foreach ($bodyName in @('requestbody', 'responseBody')) {
                    $body = [string](Get-AzRbacProp -InputObject $props -Name $bodyName)
                    if ([string]::IsNullOrWhiteSpace($body)) { continue }
                    try {
                        $parsed = $body | ConvertFrom-Json -ErrorAction Stop
                        $bodyProps = Get-AzRbacProp -InputObject $parsed -Name 'Properties'
                        if (-not $bodyProps) { $bodyProps = Get-AzRbacProp -InputObject $parsed -Name 'properties' }
                        if (-not $principalId) { $principalId = Get-AzRbacProp -InputObject $bodyProps -Name 'PrincipalId' }
                        if (-not $principalId) { $principalId = Get-AzRbacProp -InputObject $bodyProps -Name 'principalId' }
                        if (-not $roleDefinitionId) { $roleDefinitionId = Get-AzRbacProp -InputObject $bodyProps -Name 'RoleDefinitionId' }
                        if (-not $roleDefinitionId) { $roleDefinitionId = Get-AzRbacProp -InputObject $bodyProps -Name 'roleDefinitionId' }
                        if (-not $scope) { $scope = Get-AzRbacProp -InputObject $bodyProps -Name 'Scope' }
                        if (-not $scope) { $scope = Get-AzRbacProp -InputObject $bodyProps -Name 'scope' }
                    }
                    catch {
                        Write-Verbose 'Activity Log request body was not JSON.'
                    }
                }

                $resourceId = [string](Get-AzRbacProp -InputObject $e -Name 'resourceId')
                if (-not $scope -and $resourceId -match '^(.*)/providers/Microsoft\.Authorization/roleAssignments/') { $scope = $Matches[1] }

                $null = $rbacChanges.Add([pscustomobject]@{
                    Timestamp          = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $e -Name 'eventTimestamp')
                    Change             = if ($operation -match 'delete$') { 'Removed' } else { 'Granted' }
                    ChangedBy          = Get-AzRbacProp -InputObject $e -Name 'caller'
                    SubscriptionName   = $subName
                    Scope              = $scope
                    PrincipalId        = if ($principalId) { ([string]$principalId).ToLowerInvariant() } else { $null }
                    RoleDefinitionGuid = if ($roleDefinitionId) { ([string]$roleDefinitionId).TrimEnd('/').Split('/')[-1].ToLowerInvariant() } else { $null }
                    AssignmentId       = $resourceId
                    SubscriptionId     = $sid
                })
            }
        }
        catch {
            Write-PimLog -Level WARN -Message "Role assignment change history not readable for $subName : $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity 'Azure RBAC review' -Completed

    $activityRows = @(
        $callerActivity.Values | ForEach-Object {
            $topOps = @($_.Operations.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Key) ($($_.Value))" })
            [pscustomobject]@{
                Caller           = $_.Caller
                SubscriptionName = $_.SubscriptionName
                ChangeEvents     = $_.Events
                LastChange       = $_.LastActivity
                TopOperations    = ($topOps -join '; ')
                SubscriptionId   = $_.SubscriptionId
            }
        }
    )

    return [pscustomobject]@{
        Days                   = $Days
        WindowStart            = $start
        CallerActivity         = $activityRows
        RbacChanges            = @($rbacChanges | Sort-Object -Property Timestamp -Descending)
        TruncatedSubscriptions = @($truncatedSubs)
    }
}

# ---------------------------------------------------------------------------------------------
# Azure Lighthouse (external tenants managing these subscriptions)
# ---------------------------------------------------------------------------------------------

function Get-AzRbacLighthouseDelegations {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionIds,
        [hashtable]$SubscriptionNames
    )

    $rows = New-Object System.Collections.ArrayList
    foreach ($sid in $SubscriptionIds) {
        $subName = if ($SubscriptionNames -and $SubscriptionNames.ContainsKey($sid)) { $SubscriptionNames[$sid] } else { $sid }
        $uri = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.ManagedServices/registrationAssignments?api-version=2022-10-01&`$expandRegistrationDefinition=true"
        $assignments = @(Get-ArmPagedResults -Uri $uri -Operation 'List Lighthouse delegations' -Scope "/subscriptions/$sid" -TolerateErrors)

        foreach ($a in $assignments) {
            $aProps = Get-AzRbacProp -InputObject $a -Name 'properties'
            $def = Get-AzRbacProp -InputObject $aProps -Name 'registrationDefinition'
            $defProps = Get-AzRbacProp -InputObject $def -Name 'properties'
            if (-not $defProps) { continue }

            $assignmentId = [string](Get-AzRbacProp -InputObject $a -Name 'id')
            $scope = $assignmentId -replace '/providers/Microsoft\.ManagedServices/registrationAssignments/.*$', ''

            $common = @{
                SubscriptionName  = $subName
                Scope             = $scope
                ManagedByTenantId = Get-AzRbacProp -InputObject $defProps -Name 'managedByTenantId'
                ManagedByTenant   = Get-AzRbacProp -InputObject $defProps -Name 'managedByTenantName'
                OfferName         = Get-AzRbacProp -InputObject $defProps -Name 'registrationDefinitionName'
                Description       = Get-AzRbacProp -InputObject $defProps -Name 'description'
                SubscriptionId    = $sid
            }

            foreach ($pair in @(@{ Kind = 'Permanent'; Items = @(Get-AzRbacProp -InputObject $defProps -Name 'authorizations') }, @{ Kind = 'Eligible (JIT)'; Items = @(Get-AzRbacProp -InputObject $defProps -Name 'eligibleAuthorizations') })) {
                foreach ($auth in $pair.Items) {
                    if ($null -eq $auth) { continue }
                    $row = [ordered]@{}
                    foreach ($k in $common.Keys) { $row[$k] = $common[$k] }
                    $row['AuthorizationType'] = $pair.Kind
                    $row['PrincipalDisplayName'] = Get-AzRbacProp -InputObject $auth -Name 'principalIdDisplayName'
                    $row['PrincipalId'] = Get-AzRbacProp -InputObject $auth -Name 'principalId'
                    $row['RoleDefinitionGuid'] = ([string](Get-AzRbacProp -InputObject $auth -Name 'roleDefinitionId')).Split('/')[-1].ToLowerInvariant()
                    $row['DelegatedRoleDefinitionIds'] = (@(Get-AzRbacProp -InputObject $auth -Name 'delegatedRoleDefinitionIds') -join '; ')
                    $null = $rows.Add([pscustomobject]$row)
                }
            }
        }
    }

    return @($rows)
}

# ---------------------------------------------------------------------------------------------
# Access paths outside Azure RBAC (Resource Graph)
# ---------------------------------------------------------------------------------------------

function Get-AzRbacResourceSecurity {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionIds,
        [hashtable]$SubscriptionNames
    )

    $result = [ordered]@{
        KeyVaults               = @()
        KeyVaultAccessPolicies  = @()
        StorageAccounts         = @()
        SqlServers              = @()
        AksClusters             = @()
        LocalAuthResources      = @()
    }

    if (@($SubscriptionIds).Count -eq 0) { return [pscustomobject]$result }

    $subNameOf = {
        param($Sid)
        $k = ([string]$Sid).ToLowerInvariant()
        if ($SubscriptionNames -and $SubscriptionNames.ContainsKey($k)) { return $SubscriptionNames[$k] }
        return $k
    }

    # Key Vaults and their access policies.
    try {
        $vaults = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $SubscriptionIds -Query "resources | where type =~ 'microsoft.keyvault/vaults' | project id = tolower(id), name, resourceGroup, subscriptionId = tolower(subscriptionId), rbac = properties.enableRbacAuthorization, policies = properties.accessPolicies, publicNetworkAccess = properties.publicNetworkAccess, purgeProtection = properties.enablePurgeProtection")
        $vaultRows = New-Object System.Collections.ArrayList
        $policyRows = New-Object System.Collections.ArrayList
        foreach ($v in $vaults) {
            $usesRbac = [bool](Get-AzRbacProp -InputObject $v -Name 'rbac')
            $policies = @(Get-AzRbacProp -InputObject $v -Name 'policies' | Where-Object { $null -ne $_ })
            $null = $vaultRows.Add([pscustomobject]@{
                SubscriptionName    = & $subNameOf $v.subscriptionId
                ResourceGroup       = $v.resourceGroup
                VaultName           = $v.name
                PermissionModel     = if ($usesRbac) { 'Azure RBAC' } else { 'Access policies' }
                AccessPolicyCount   = $policies.Count
                PublicNetworkAccess = Get-AzRbacProp -InputObject $v -Name 'publicNetworkAccess'
                PurgeProtection     = Get-AzRbacProp -InputObject $v -Name 'purgeProtection'
                ResourceId          = $v.id
                SubscriptionId      = $v.subscriptionId
            })

            if ($usesRbac) { continue }
            foreach ($p in $policies) {
                $perms = Get-AzRbacProp -InputObject $p -Name 'permissions'
                $secrets = @(Get-AzRbacProp -InputObject $perms -Name 'secrets')
                $keys = @(Get-AzRbacProp -InputObject $perms -Name 'keys')
                $certs = @(Get-AzRbacProp -InputObject $perms -Name 'certificates')
                $canRead = (@($secrets + $keys + $certs) | Where-Object { [string]$_ -match '^(get|list|all|decrypt|unwrapKey|sign)$' }).Count -gt 0
                $canManagePolicies = $false
                $null = $policyRows.Add([pscustomobject]@{
                    SubscriptionName       = & $subNameOf $v.subscriptionId
                    VaultName              = $v.name
                    ObjectId               = ([string](Get-AzRbacProp -InputObject $p -Name 'objectId')).ToLowerInvariant()
                    ApplicationId          = Get-AzRbacProp -InputObject $p -Name 'applicationId'
                    SecretPermissions      = ($secrets -join ', ')
                    KeyPermissions         = ($keys -join ', ')
                    CertificatePermissions = ($certs -join ', ')
                    CanReadSecretsOrKeys   = $canRead
                    ResourceId             = $v.id
                })
                $null = $canManagePolicies
            }
        }
        $result.KeyVaults = @($vaultRows)
        $result.KeyVaultAccessPolicies = @($policyRows)
    }
    catch {
        Write-PimLog -Level WARN -Message "Key Vault query failed: $($_.Exception.Message)"
        Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph: Key Vaults' -StatusCode '' -Message $_.Exception.Message
    }

    # Storage accounts: shared key access lets anyone holding the key bypass Entra and RBAC.
    try {
        $accounts = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $SubscriptionIds -Query "resources | where type =~ 'microsoft.storage/storageaccounts' | project id = tolower(id), name, resourceGroup, subscriptionId = tolower(subscriptionId), sharedKey = properties.allowSharedKeyAccess, blobPublic = properties.allowBlobPublicAccess, publicNetworkAccess = properties.publicNetworkAccess, defaultAction = properties.networkAcls.defaultAction")
        $result.StorageAccounts = @(
            $accounts | ForEach-Object {
                $sharedKey = Get-AzRbacProp -InputObject $_ -Name 'sharedKey'
                [pscustomobject]@{
                    SubscriptionName       = & $subNameOf $_.subscriptionId
                    ResourceGroup          = $_.resourceGroup
                    AccountName            = $_.name
                    SharedKeyAccess        = if ($null -eq $sharedKey) { 'Enabled (default)' } elseif ([bool]$sharedKey) { 'Enabled' } else { 'Disabled' }
                    AnonymousBlobAccess    = Get-AzRbacProp -InputObject $_ -Name 'blobPublic'
                    PublicNetworkAccess    = Get-AzRbacProp -InputObject $_ -Name 'publicNetworkAccess'
                    NetworkDefaultAction   = Get-AzRbacProp -InputObject $_ -Name 'defaultAction'
                    ResourceId             = $_.id
                    SubscriptionId         = $_.subscriptionId
                }
            }
        )
    }
    catch {
        Write-PimLog -Level WARN -Message "Storage account query failed: $($_.Exception.Message)"
        Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph: storage accounts' -StatusCode '' -Message $_.Exception.Message
    }

    # SQL servers: SQL authentication logins sit outside Entra.
    try {
        $servers = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $SubscriptionIds -Query "resources | where type =~ 'microsoft.sql/servers' | project id = tolower(id), name, resourceGroup, subscriptionId = tolower(subscriptionId), sqlAdmin = properties.administratorLogin, entraOnly = properties.administrators.azureADOnlyAuthentication, entraAdmin = properties.administrators.login, entraAdminType = properties.administrators.principalType, publicNetworkAccess = properties.publicNetworkAccess")
        $result.SqlServers = @(
            $servers | ForEach-Object {
                [pscustomobject]@{
                    SubscriptionName      = & $subNameOf $_.subscriptionId
                    ResourceGroup         = $_.resourceGroup
                    ServerName            = $_.name
                    EntraOnlyAuth         = [bool](Get-AzRbacProp -InputObject $_ -Name 'entraOnly')
                    SqlAdminLogin         = Get-AzRbacProp -InputObject $_ -Name 'sqlAdmin'
                    EntraAdmin            = Get-AzRbacProp -InputObject $_ -Name 'entraAdmin'
                    EntraAdminType        = Get-AzRbacProp -InputObject $_ -Name 'entraAdminType'
                    PublicNetworkAccess   = Get-AzRbacProp -InputObject $_ -Name 'publicNetworkAccess'
                    ResourceId            = $_.id
                    SubscriptionId        = $_.subscriptionId
                }
            }
        )
    }
    catch {
        Write-PimLog -Level WARN -Message "SQL server query failed: $($_.Exception.Message)"
        Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph: SQL servers' -StatusCode '' -Message $_.Exception.Message
    }

    # AKS: local accounts give cluster-admin without Entra.
    try {
        $clusters = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $SubscriptionIds -Query "resources | where type =~ 'microsoft.containerservice/managedclusters' | project id = tolower(id), name, resourceGroup, subscriptionId = tolower(subscriptionId), localDisabled = properties.disableLocalAccounts, azureRbac = properties.aadProfile.enableAzureRBAC, entraIntegrated = properties.aadProfile.managed, privateCluster = properties.apiServerAccessProfile.enablePrivateCluster")
        $result.AksClusters = @(
            $clusters | ForEach-Object {
                [pscustomobject]@{
                    SubscriptionName       = & $subNameOf $_.subscriptionId
                    ResourceGroup          = $_.resourceGroup
                    ClusterName            = $_.name
                    LocalAccountsDisabled  = [bool](Get-AzRbacProp -InputObject $_ -Name 'localDisabled')
                    EntraIntegrated        = [bool](Get-AzRbacProp -InputObject $_ -Name 'entraIntegrated')
                    AzureRbacForKubernetes = [bool](Get-AzRbacProp -InputObject $_ -Name 'azureRbac')
                    PrivateCluster         = [bool](Get-AzRbacProp -InputObject $_ -Name 'privateCluster')
                    ResourceId             = $_.id
                    SubscriptionId         = $_.subscriptionId
                }
            }
        )
    }
    catch {
        Write-PimLog -Level WARN -Message "AKS query failed: $($_.Exception.Message)"
        Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph: AKS clusters' -StatusCode '' -Message $_.Exception.Message
    }

    # Any resource exposing local (key) authentication: Cosmos DB, Service Bus, Event Hubs, Event Grid,
    # App Configuration, Cognitive Services / OpenAI, Search and others.
    try {
        $local = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $SubscriptionIds -Query "resources | where isnotnull(properties.disableLocalAuth) | project id = tolower(id), name, type, resourceGroup, subscriptionId = tolower(subscriptionId), disableLocalAuth = properties.disableLocalAuth")
        $result.LocalAuthResources = @(
            $local | ForEach-Object {
                [pscustomobject]@{
                    SubscriptionName = & $subNameOf $_.subscriptionId
                    ResourceGroup    = $_.resourceGroup
                    ResourceName     = $_.name
                    ResourceType     = $_.type
                    LocalAuth        = if ([bool](Get-AzRbacProp -InputObject $_ -Name 'disableLocalAuth')) { 'Disabled' } else { 'Enabled' }
                    ResourceId       = $_.id
                    SubscriptionId   = $_.subscriptionId
                }
            }
        )
    }
    catch {
        Write-PimLog -Level WARN -Message "Local authentication query failed: $($_.Exception.Message)"
        Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph: local authentication' -StatusCode '' -Message $_.Exception.Message
    }

    return [pscustomobject]$result
}

# ---------------------------------------------------------------------------------------------
# Managed identities: which resource does each identity belong to?
# ---------------------------------------------------------------------------------------------

function Get-AzRbacManagedIdentityHosts {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionIds
    )

    $map = @{}
    if (@($SubscriptionIds).Count -eq 0) { return $map }

    try {
        $uami = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $SubscriptionIds -Query "resources | where type =~ 'microsoft.managedidentity/userassignedidentities' | project id = tolower(id), name, principalId = tolower(tostring(properties.principalId))")
        $uamiById = @{}
        foreach ($u in $uami) { if ($u.principalId) { $uamiById[$u.id] = $u } }

        $hosts = @(Invoke-AzRbacResourceGraphQuery -Subscriptions $SubscriptionIds -Query "resources | where isnotnull(identity) and tostring(identity.type) !~ 'None' and isnotempty(tostring(identity.type)) | project id = tolower(id), name, type, resourceGroup, subscriptionId = tolower(subscriptionId), systemPrincipalId = tolower(tostring(identity.principalId)), userAssigned = identity.userAssignedIdentities")

        foreach ($h in $hosts) {
            $hostInfo = "$($h.type) $($h.name) (rg $($h.resourceGroup))"
            if ($h.systemPrincipalId) {
                if (-not $map.ContainsKey($h.systemPrincipalId)) { $map[$h.systemPrincipalId] = New-Object System.Collections.ArrayList }
                $null = $map[$h.systemPrincipalId].Add([pscustomobject]@{ Kind = 'System-assigned'; HostResource = $hostInfo; HostType = $h.type; HostId = $h.id })
            }

            $ua = Get-AzRbacProp -InputObject $h -Name 'userAssigned'
            if ($ua) {
                foreach ($prop in $ua.PSObject.Properties) {
                    $uaId = ([string]$prop.Name).ToLowerInvariant()
                    $principalId = [string](Get-AzRbacProp -InputObject $prop.Value -Name 'principalId')
                    if (-not $principalId -and $uamiById.ContainsKey($uaId)) { $principalId = $uamiById[$uaId].principalId }
                    if (-not $principalId) { continue }
                    $principalId = $principalId.ToLowerInvariant()
                    if (-not $map.ContainsKey($principalId)) { $map[$principalId] = New-Object System.Collections.ArrayList }
                    $null = $map[$principalId].Add([pscustomobject]@{ Kind = 'User-assigned'; HostResource = $hostInfo; HostType = $h.type; HostId = $h.id })
                }
            }
        }

        # User-assigned identities that exist but are not attached to anything still hold their roles.
        foreach ($u in $uami) {
            if ($u.principalId -and -not $map.ContainsKey($u.principalId)) {
                $map[$u.principalId] = New-Object System.Collections.ArrayList
                $null = $map[$u.principalId].Add([pscustomobject]@{ Kind = 'User-assigned (not attached)'; HostResource = "identity $($u.name)"; HostType = 'microsoft.managedidentity/userassignedidentities'; HostId = $u.id })
            }
        }
    }
    catch {
        Write-PimLog -Level WARN -Message "Managed identity mapping failed: $($_.Exception.Message)"
        Add-AzRbacCoverageGap -Scope '/' -Operation 'Resource Graph: managed identity hosts' -StatusCode '' -Message $_.Exception.Message
    }

    return $map
}

# ---------------------------------------------------------------------------------------------
# Service principals: publisher, credentials, owners
# ---------------------------------------------------------------------------------------------

function Get-AzRbacWorkloadDetails {
    [CmdletBinding()]
    param(
        [string[]]$ServicePrincipalIds,
        [string]$TenantGuid
    )

    $rows = @{}
    $now = (Get-Date).ToUniversalTime()

    foreach ($id in @($ServicePrincipalIds | Where-Object { $_ } | Select-Object -Unique)) {
        $sp = $null
        try {
            $sp = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${id}?`$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,createdDateTime,passwordCredentials,keyCredentials,alternativeNames"
        }
        catch {
            Write-PimLog -Level WARN -Message "Unable to read service principal $id : $($_.Exception.Message)"
            continue
        }

        $appId = [string](Get-AzRbacProp -InputObject $sp -Name 'appId')
        $spType = [string](Get-AzRbacProp -InputObject $sp -Name 'servicePrincipalType')
        $ownerOrg = [string](Get-AzRbacProp -InputObject $sp -Name 'appOwnerOrganizationId')
        $displayName = [string](Get-AzRbacProp -InputObject $sp -Name 'displayName')
        $isMicrosoft = Test-AzRbacMicrosoftPrincipal -AppOwnerOrganizationId $ownerOrg -DisplayName $displayName -ServicePrincipalType $spType
        $isThirdParty = (-not $isMicrosoft) -and $spType -ne 'ManagedIdentity' -and $ownerOrg -and $TenantGuid -and ($ownerOrg.ToLowerInvariant() -ne $TenantGuid.ToLowerInvariant())

        $credentials = New-Object System.Collections.ArrayList
        foreach ($c in @(Get-AzRbacProp -InputObject $sp -Name 'passwordCredentials')) { if ($c) { $null = $credentials.Add([pscustomobject]@{ Source = 'ServicePrincipal'; Type = 'Secret'; Start = Get-AzRbacDateValue -Value $c.startDateTime; End = Get-AzRbacDateValue -Value $c.endDateTime }) } }
        foreach ($c in @(Get-AzRbacProp -InputObject $sp -Name 'keyCredentials')) { if ($c) { $null = $credentials.Add([pscustomobject]@{ Source = 'ServicePrincipal'; Type = 'Certificate'; Start = Get-AzRbacDateValue -Value $c.startDateTime; End = Get-AzRbacDateValue -Value $c.endDateTime }) } }

        $owners = New-Object System.Collections.ArrayList
        $federatedCount = 0
        $appObjectId = $null

        if ($spType -ne 'ManagedIdentity' -and -not $isMicrosoft) {
            try {
                foreach ($o in @(Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$id/owners?`$select=id,displayName,userPrincipalName")) {
                    $null = $owners.Add([pscustomobject]@{ Id = $o.id; Name = $(if (Get-AzRbacProp -InputObject $o -Name 'userPrincipalName') { $o.userPrincipalName } else { $o.displayName }); Via = 'Enterprise app' })
                }
            }
            catch {
                Write-Verbose "Owners not readable for service principal $id"
            }

            # App registration lives in this tenant: its credentials and owners also control the identity.
            if (-not $isThirdParty -and $appId) {
                try {
                    $app = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/applications(appId='$appId')?`$select=id,displayName,passwordCredentials,keyCredentials"
                    $appObjectId = Get-AzRbacProp -InputObject $app -Name 'id'
                    foreach ($c in @(Get-AzRbacProp -InputObject $app -Name 'passwordCredentials')) { if ($c) { $null = $credentials.Add([pscustomobject]@{ Source = 'App registration'; Type = 'Secret'; Start = Get-AzRbacDateValue -Value $c.startDateTime; End = Get-AzRbacDateValue -Value $c.endDateTime }) } }
                    foreach ($c in @(Get-AzRbacProp -InputObject $app -Name 'keyCredentials')) { if ($c) { $null = $credentials.Add([pscustomobject]@{ Source = 'App registration'; Type = 'Certificate'; Start = Get-AzRbacDateValue -Value $c.startDateTime; End = Get-AzRbacDateValue -Value $c.endDateTime }) } }

                    if ($appObjectId) {
                        foreach ($o in @(Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId/owners?`$select=id,displayName,userPrincipalName")) {
                            $null = $owners.Add([pscustomobject]@{ Id = $o.id; Name = $(if (Get-AzRbacProp -InputObject $o -Name 'userPrincipalName') { $o.userPrincipalName } else { $o.displayName }); Via = 'App registration' })
                        }
                        try {
                            $federatedCount = @(Get-GraphPagedResults -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId/federatedIdentityCredentials").Count
                        }
                        catch {
                            Write-Verbose "Federated credentials not readable for app $appId"
                        }
                    }
                }
                catch {
                    Write-Verbose "App registration not readable for $appId"
                }
            }
        }

        $active = @($credentials | Where-Object { -not $_.End -or $_.End -gt $now })
        $expired = @($credentials | Where-Object { $_.End -and $_.End -le $now })
        $longLived = @($active | Where-Object { $_.Start -and $_.End -and (($_.End - $_.Start).TotalDays -gt 400) })
        $nextExpiry = @($active | Where-Object { $_.End } | Sort-Object -Property End | Select-Object -First 1)
        $maxLifetime = 0
        foreach ($c in $active) { if ($c.Start -and $c.End) { $maxLifetime = [Math]::Max($maxLifetime, [int](($c.End - $c.Start).TotalDays)) } }

        $rows[$id.ToLowerInvariant()] = [pscustomobject]@{
            PrincipalId             = $id.ToLowerInvariant()
            DisplayName             = $displayName
            AppId                   = $appId
            ServicePrincipalType    = $spType
            Publisher               = if ($isMicrosoft) { 'Microsoft' } elseif ($isThirdParty) { "External tenant $ownerOrg" } elseif ($spType -eq 'ManagedIdentity') { 'Managed identity' } else { 'This tenant' }
            IsMicrosoft             = $isMicrosoft
            IsThirdParty            = [bool]$isThirdParty
            AccountEnabled          = Get-AzRbacProp -InputObject $sp -Name 'accountEnabled'
            CreatedDateTime         = Get-AzRbacDateValue -Value (Get-AzRbacProp -InputObject $sp -Name 'createdDateTime')
            ActiveSecrets           = @($active | Where-Object { $_.Type -eq 'Secret' }).Count
            ActiveCertificates      = @($active | Where-Object { $_.Type -eq 'Certificate' }).Count
            FederatedCredentials    = $federatedCount
            ExpiredCredentials      = $expired.Count
            LongLivedCredentials    = $longLived.Count
            LongestLifetimeDays     = $maxLifetime
            NextExpiry              = if ($nextExpiry.Count -gt 0) { $nextExpiry[0].End } else { $null }
            Owners                  = (@($owners | ForEach-Object { "$($_.Name) ($($_.Via))" } | Select-Object -Unique) -join '; ')
            OwnerCount              = @($owners | Select-Object -ExpandProperty Id -Unique).Count
            AppObjectId             = $appObjectId
        }
    }

    return $rows
}

# ---------------------------------------------------------------------------------------------
# Deny assignments
# ---------------------------------------------------------------------------------------------

function Get-AzRbacDenyAssignments {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionIds,
        [hashtable]$SubscriptionNames
    )

    $rows = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($sid in $SubscriptionIds) {
        $subName = if ($SubscriptionNames -and $SubscriptionNames.ContainsKey($sid)) { $SubscriptionNames[$sid] } else { $sid }
        foreach ($d in @(Get-ArmPagedResults -Uri "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01" -Operation 'List deny assignments' -Scope "/subscriptions/$sid" -TolerateErrors)) {
            $did = ([string](Get-AzRbacProp -InputObject $d -Name 'id')).ToLowerInvariant()
            if ($seen.ContainsKey($did)) { continue }
            $seen[$did] = $true
            $p = Get-AzRbacProp -InputObject $d -Name 'properties'
            $perms = @(Get-AzRbacProp -InputObject $p -Name 'permissions')
            $null = $rows.Add([pscustomobject]@{
                SubscriptionName = $subName
                Name             = Get-AzRbacProp -InputObject $p -Name 'denyAssignmentName'
                Description      = Get-AzRbacProp -InputObject $p -Name 'description'
                Scope            = Get-AzRbacProp -InputObject $p -Name 'scope'
                IsSystemProtected = Get-AzRbacProp -InputObject $p -Name 'isSystemProtected'
                DeniedActions    = (@($perms | ForEach-Object { @(Get-AzRbacProp -InputObject $_ -Name 'actions') }) -join '; ')
                Principals       = (@(Get-AzRbacProp -InputObject $p -Name 'principals') | ForEach-Object { "$(Get-AzRbacProp -InputObject $_ -Name 'type') $(Get-AzRbacProp -InputObject $_ -Name 'id')" }) -join '; '
                ExcludedPrincipals = (@(Get-AzRbacProp -InputObject $p -Name 'excludePrincipals') | ForEach-Object { "$(Get-AzRbacProp -InputObject $_ -Name 'type') $(Get-AzRbacProp -InputObject $_ -Name 'id')" }) -join '; '
            })
        }
    }

    return @($rows)
}
