<#
.SYNOPSIS
Exports user licensing details for users in privileged assignment paths.

.DESCRIPTION
Attempts delegated user licenseDetails retrieval first, then falls back to assignedLicenses plus
subscribedSkus mapping when licenseDetails is unavailable.

Required delegated scopes:
- User.Read.All (user profile and licenseDetails)
- Organization.Read.All (subscribedSkus mapping)

Note:
- licenseDetails is delegated-only in this reporting workflow.

.EXAMPLE
./Get-PimUserLicenses.ps1 -UserIds $userIds -OutputFolder .\Output -IncludeLicenseDetails -Verbose
#>
[CmdletBinding()]
param(
    [string[]]$UserIds,

    [string]$OutputFolder,

    [switch]$IncludeLicenseDetails,

    [switch]$ReturnObjectsOnly
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
if (-not (Get-Module -Name PimReview.Common)) {
    Import-Module -Name $commonModulePath -DisableNameChecking -ErrorAction Stop -Verbose:$false
}

function Get-SubscribedSkuMap {
    [CmdletBinding()]
    param()

    $map = @{}

    try {
        $uri = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber'
        $skus = Get-GraphPagedResults -Uri $uri

        foreach ($sku in $skus) {
            if ($sku.skuId) {
                $map[[string]$sku.skuId] = [string]$sku.skuPartNumber
            }
        }
    }
    catch {
        Write-PimLog -Level WARN -Message "Unable to retrieve subscribedSkus mapping: $($_.Exception.Message)"
    }

    return $map
}

function Get-UserLicenseRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$User,

        [string[]]$AssignedSkuIds,

        [string[]]$SkuPartNumbers,

        [string]$Source
    )

    $friendlyNames = @($SkuPartNumbers | ForEach-Object { Get-FriendlyLicenseName -SkuPartNumber $_ })

    return [pscustomobject]@{
        UserId                 = $User.id
        DisplayName            = $User.displayName
        UserPrincipalName      = $User.userPrincipalName
        AccountEnabled         = $User.accountEnabled
        AssignedSkuIds         = (Get-UniqueJoinedValue -Values $AssignedSkuIds)
        SkuPartNumbers         = (Get-UniqueJoinedValue -Values $SkuPartNumbers)
        FriendlyLicenseNames   = (Get-UniqueJoinedValue -Values $friendlyNames)
        LicenseDataSource      = $Source
    }
}

function Get-PimUserLicenses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$UserIds,

        [Parameter(Mandatory)]
        [string]$OutputFolder,

        [switch]$IncludeLicenseDetails,

        [switch]$ReturnObjectsOnly
    )

    $distinctUserIds = @($UserIds | Where-Object { $_ } | Select-Object -Unique)
    Write-PimLog -Message "Retrieving licensing for $($distinctUserIds.Count) users."

    $subscribedSkuMap = Get-SubscribedSkuMap
    $rows = @()

    foreach ($userId in $distinctUserIds) {
        $user = Resolve-User -UserId $userId
        if (-not $user) {
            continue
        }

        $added = $false

        if ($IncludeLicenseDetails) {
            $licenseUri = "https://graph.microsoft.com/v1.0/users/$userId/licenseDetails?`$select=skuId,skuPartNumber"

            try {
                $details = Get-GraphPagedResults -Uri $licenseUri
                $detailSkuIds = @($details | ForEach-Object { [string]$_.skuId } | Where-Object { $_ } | Select-Object -Unique)
                $detailSkuParts = @($details | ForEach-Object { [string]$_.skuPartNumber } | Where-Object { $_ } | Select-Object -Unique)

                $rows += (Get-UserLicenseRow -User $user -AssignedSkuIds $detailSkuIds -SkuPartNumbers $detailSkuParts -Source 'licenseDetails')
                $added = $true
            }
            catch {
                Write-PimLog -Level WARN -Message "licenseDetails unavailable for user $($user.userPrincipalName). Falling back to assignedLicenses."
            }
        }

        if (-not $added) {
            $assignedSkuIds = @($user.assignedLicenses | ForEach-Object { [string]$_.skuId } | Where-Object { $_ } | Select-Object -Unique)
            $skuParts = foreach ($skuId in $assignedSkuIds) {
                if ($subscribedSkuMap.ContainsKey($skuId)) {
                    $subscribedSkuMap[$skuId]
                }
                else {
                    $skuId
                }
            }

            $rows += (Get-UserLicenseRow -User $user -AssignedSkuIds $assignedSkuIds -SkuPartNumbers $skuParts -Source 'assignedLicensesFallback')
        }
    }

    $result = @($rows)

    if (-not $ReturnObjectsOnly) {
        $csvPath = Join-Path -Path $OutputFolder -ChildPath 'Raw\UserLicenses.csv'
        Export-PimData -Data $result -CsvPath $csvPath
        Write-PimLog -Message "Exported user licensing dataset: $csvPath"
    }

    return $result
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-PimUserLicenses @PSBoundParameters
}


