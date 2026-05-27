Set-StrictMode -Version Latest

$script:PimCache = @{
    DirectoryObjects = @{}
    Users            = @{}
    Groups           = @{}
    RoleDefinitions  = @{}
}

function Initialize-PimCache {
    [CmdletBinding()]
    param()

    $script:PimCache = @{
        DirectoryObjects = @{}
        Users            = @{}
        Groups           = @{}
        RoleDefinitions  = @{}
    }
}

function Write-PimLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$timestamp][$Level] $Message"

    switch ($Level) {
        'ERROR' { Write-Error $line }
        'WARN'  { Write-Warning $line }
        'DEBUG' { Write-Verbose $line }
        default { Write-Host $line }
    }
}

function Ensure-Directory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        $null = New-Item -Path $Path -ItemType Directory -Force
    }

    return (Resolve-Path -Path $Path).Path
}

function Start-PimTranscriptSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TranscriptPath
    )

    try {
        Start-Transcript -Path $TranscriptPath -Append -ErrorAction Stop | Out-Null
        Write-PimLog -Message "Transcript started at $TranscriptPath"
        return $true
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to start transcript: $($_.Exception.Message)"
        return $false
    }
}

function Stop-PimTranscriptSafe {
    [CmdletBinding()]
    param()

    try {
        Stop-Transcript | Out-Null
    }
    catch {
        Write-Verbose "Transcript was not active."
    }
}

function Get-RetryDelaySeconds {
    param(
        [Parameter(Mandatory)]
        [int]$Attempt,

        [int]$InitialDelaySeconds = 2,

        [object]$Exception
    )

    $retryAfter = $null

    if ($Exception -and $Exception.Response -and $Exception.Response.Headers) {
        try {
            if ($Exception.Response.Headers.RetryAfter -and $Exception.Response.Headers.RetryAfter.Delta) {
                $retryAfter = [int][Math]::Ceiling($Exception.Response.Headers.RetryAfter.Delta.TotalSeconds)
            }
        }
        catch {
            $retryAfter = $null
        }
    }

    if ($retryAfter) {
        return [Math]::Max(1, $retryAfter)
    }

    return [Math]::Min(60, [Math]::Pow(2, $Attempt) * $InitialDelaySeconds)
}

function Invoke-GraphRequestWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        [object]$Body,

        [int]$MaxRetries = 6,

        [int]$InitialDelaySeconds = 2
    )

    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        try {
            if ($PSBoundParameters.ContainsKey('Body')) {
                return Invoke-MgGraphRequest -Uri $Uri -Method $Method -Body $Body -OutputType PSObject -ErrorAction Stop
            }

            return Invoke-MgGraphRequest -Uri $Uri -Method $Method -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $message = $_.Exception.Message
            $isLast = $attempt -ge $MaxRetries

            if ($isLast) {
                Write-PimLog -Level ERROR -Message "Graph request failed after $($attempt + 1) attempts. Uri: $Uri. Error: $message"
                throw
            }

            $statusCode = $null
            try {
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
            }
            catch {
                $statusCode = $null
            }

            $retryable = $false
            if ($statusCode -in 429, 500, 502, 503, 504) {
                $retryable = $true
            }
            elseif ($message -match 'throttl|timeout|temporar|transient|Too Many Requests') {
                $retryable = $true
            }

            if (-not $retryable) {
                throw
            }

            $delay = Get-RetryDelaySeconds -Attempt $attempt -InitialDelaySeconds $InitialDelaySeconds -Exception $_.Exception
            Write-PimLog -Level WARN -Message "Retryable Graph error. Waiting $delay seconds before retry. Uri: $Uri. Error: $message"
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-GraphPagedResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $results = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri

    while ($nextUri) {
        $response = Invoke-GraphRequestWithRetry -Uri $nextUri -Method GET

        $hasValueProperty = $response -and ($null -ne $response.PSObject.Properties['value'])
        if ($hasValueProperty -and $response.value) {
            foreach ($item in $response.value) {
                $results.Add($item)
            }
        }
        elseif ($response) {
            $results.Add($response)
        }

        $hasNextLinkProperty = $response -and ($null -ne $response.PSObject.Properties['@odata.nextLink'])
        $nextUri = if ($hasNextLinkProperty) { $response.'@odata.nextLink' } else { $null }
    }

    return $results
}

function Resolve-DirectoryObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectId,

        [string]$Select = 'id,displayName,userPrincipalName,appId,mail,accountEnabled'
    )

    if ([string]::IsNullOrWhiteSpace($ObjectId)) {
        return $null
    }

    if ($script:PimCache.DirectoryObjects.ContainsKey($ObjectId)) {
        return $script:PimCache.DirectoryObjects[$ObjectId]
    }

    $uri = "https://graph.microsoft.com/v1.0/directoryObjects/$ObjectId/microsoft.graph.directoryObject?`$select=$Select"

    try {
        $obj = Invoke-GraphRequestWithRetry -Uri $uri
        $script:PimCache.DirectoryObjects[$ObjectId] = $obj
        return $obj
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to resolve directory object $ObjectId"
        return $null
    }
}

function Resolve-Group {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupId
    )

    if ($script:PimCache.Groups.ContainsKey($GroupId)) {
        return $script:PimCache.Groups[$GroupId]
    }

    $uri = "https://graph.microsoft.com/v1.0/groups/${GroupId}?`$select=id,displayName,mail,isAssignableToRole"

    try {
        $group = Invoke-GraphRequestWithRetry -Uri $uri
        $script:PimCache.Groups[$GroupId] = $group
        return $group
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to resolve group $GroupId"
        return $null
    }
}

function Resolve-User {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserId,

        [string]$Select = 'id,displayName,userPrincipalName,mail,accountEnabled,assignedLicenses'
    )

    if ($script:PimCache.Users.ContainsKey($UserId)) {
        return $script:PimCache.Users[$UserId]
    }

    $uri = "https://graph.microsoft.com/v1.0/users/${UserId}?`$select=$Select"

    try {
        $user = Invoke-GraphRequestWithRetry -Uri $uri
        $script:PimCache.Users[$UserId] = $user
        return $user
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to resolve user $UserId"
        return $null
    }
}

function Get-PrincipalType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Principal
    )

    $odataType = $null
    if ($Principal -and ($null -ne $Principal.PSObject.Properties['@odata.type'])) {
        $odataType = [string]$Principal.'@odata.type'
    }

    if ($odataType -match 'user') { return 'User' }
    if ($odataType -match 'group') { return 'Group' }
    if ($odataType -match 'servicePrincipal') { return 'ServicePrincipal' }
    if ($odataType -match 'device') { return 'Device' }

    if (($null -ne $Principal.PSObject.Properties['userPrincipalName']) -and $Principal.userPrincipalName) { return 'User' }
    if ($null -ne $Principal.PSObject.Properties['isAssignableToRole']) { return 'Group' }
    if (($null -ne $Principal.PSObject.Properties['appId']) -and $Principal.appId) { return 'ServicePrincipal' }

    if (($null -ne $Principal.PSObject.Properties['@odata.id']) -and [string]$Principal.'@odata.id' -match '/groups/') { return 'Group' }
    if (($null -ne $Principal.PSObject.Properties['@odata.id']) -and [string]$Principal.'@odata.id' -match '/users/') { return 'User' }

    return 'Unknown'
}

function Export-PimData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Data,

        [string]$CsvPath,

        [string]$JsonPath
    )

    if ($CsvPath) {
        $parent = Split-Path -Path $CsvPath -Parent
        $null = Ensure-Directory -Path $parent

        if (@($Data).Count -eq 0) {
            Set-Content -Path $CsvPath -Value '' -Encoding UTF8
        }
        else {
            $Data | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        }
    }

    if ($JsonPath) {
        $parent = Split-Path -Path $JsonPath -Parent
        $null = Ensure-Directory -Path $parent

        if (@($Data).Count -eq 0) {
            '[]' | Out-File -FilePath $JsonPath -Encoding UTF8
        }
        else {
            $Data | ConvertTo-Json -Depth 20 | Out-File -FilePath $JsonPath -Encoding UTF8
        }
    }
}

function Test-ImportExcelAvailable {
    [CmdletBinding()]
    param()

    return [bool](Get-Module -ListAvailable -Name ImportExcel)
}

function Get-SafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $regex = "[{0}]" -f [Regex]::Escape($invalid)
    $safe = [Regex]::Replace($Name, $regex, '_')
    return $safe.Trim()
}

function Convert-Iso8601DurationToHours {
    [CmdletBinding()]
    param(
        [string]$Duration
    )

    if ([string]::IsNullOrWhiteSpace($Duration)) {
        return $null
    }

    if ($Duration -eq 'P0D' -or $Duration -eq 'PT0S') {
        return 0
    }

    if ($Duration -notmatch '^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$') {
        return $null
    }

    $days = if ($Matches[1]) { [double]$Matches[1] } else { 0 }
    $hours = if ($Matches[2]) { [double]$Matches[2] } else { 0 }
    $minutes = if ($Matches[3]) { [double]$Matches[3] } else { 0 }
    $seconds = if ($Matches[4]) { [double]$Matches[4] } else { 0 }

    return [Math]::Round(($days * 24) + $hours + ($minutes / 60) + ($seconds / 3600), 2)
}

function Get-FriendlyLicenseName {
    [CmdletBinding()]
    param(
        [string]$SkuPartNumber
    )

    $map = @{
        'AAD_PREMIUM'          = 'Microsoft Entra ID P1'
        'AAD_PREMIUM_P2'       = 'Microsoft Entra ID P2'
        'ENTERPRISEPREMIUM'    = 'Microsoft 365 E5'
        'ENTERPRISEPACK'       = 'Office 365 E3'
        'SPE_E3'               = 'Microsoft 365 E3'
        'SPE_E5'               = 'Microsoft 365 E5'
        'EMS'                  = 'Enterprise Mobility + Security E3'
        'EMSPREMIUM'           = 'Enterprise Mobility + Security E5'
        'M365_F1'              = 'Microsoft 365 F1'
        'M365_F3'              = 'Microsoft 365 F3'
        'FLOW_FREE'            = 'Power Automate Free'
        'POWER_BI_PRO'         = 'Power BI Pro'
        'POWER_BI_PREMIUM_P1'  = 'Power BI Premium P1'
    }

    if ([string]::IsNullOrWhiteSpace($SkuPartNumber)) {
        return $null
    }

    if ($map.ContainsKey($SkuPartNumber)) {
        return $map[$SkuPartNumber]
    }

    return $SkuPartNumber
}

function Get-UniqueJoinedValue {
    [CmdletBinding()]
    param(
        [object[]]$Values,
        [string]$Separator = '; '
    )

    if (-not $Values) {
        return $null
    }

    return (($Values | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | Select-Object -Unique) -join $Separator)
}

Export-ModuleMember -Function Initialize-PimCache
Export-ModuleMember -Function Write-PimLog
Export-ModuleMember -Function Ensure-Directory
Export-ModuleMember -Function Start-PimTranscriptSafe
Export-ModuleMember -Function Stop-PimTranscriptSafe
Export-ModuleMember -Function Invoke-GraphRequestWithRetry
Export-ModuleMember -Function Get-GraphPagedResults
Export-ModuleMember -Function Resolve-DirectoryObject
Export-ModuleMember -Function Resolve-Group
Export-ModuleMember -Function Resolve-User
Export-ModuleMember -Function Get-PrincipalType
Export-ModuleMember -Function Export-PimData
Export-ModuleMember -Function Test-ImportExcelAvailable
Export-ModuleMember -Function Get-SafeFileName
Export-ModuleMember -Function Convert-Iso8601DurationToHours
Export-ModuleMember -Function Get-FriendlyLicenseName
Export-ModuleMember -Function Get-UniqueJoinedValue
