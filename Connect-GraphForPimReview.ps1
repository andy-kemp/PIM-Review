<#
.SYNOPSIS
Connects to Microsoft Graph for read-only PIM review exports.

.DESCRIPTION
Establishes delegated authentication and requests only the scopes required by the selected review options.
This script is read-only and does not modify tenant configuration.

Scopes rationale:
- PIM role assignments and schedules: RoleManagement.Read.Directory
- PIM role policy settings/rules: RoleManagementPolicy.Read.Directory
- PIM for Groups membership/ownership: Group.Read.All
- User details and license data: User.Read.All, Organization.Read.All
- Approval and approval steps history (beta): RoleManagement.Read.Directory
- Conditional Access posture: Policy.Read.All
- Access reviews coverage: AccessReview.Read.All
- Workload identity hygiene: Application.Read.All

.EXAMPLE
./Connect-GraphForPimReview.ps1 -IncludeLicenseDetails -IncludeApprovalHistory -Verbose

.EXAMPLE
Connect-GraphForPimReview -Scopes @('RoleManagement.Read.Directory','Group.Read.All') -Verbose
#>
[CmdletBinding()]
param(
    [string[]]$Scopes,
    [string]$TenantId,
    [switch]$IncludeLicenseDetails,
    [switch]$IncludeApprovalHistory,
    [switch]$IncludePimForGroups,
    [switch]$ForceReConnect
)

$commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules\PimReview.Common.psm1'
Import-Module -Name $commonModulePath -DisableNameChecking

function Get-DefaultPimScopes {
    [CmdletBinding()]
    param(
        [switch]$IncludeLicenseDetails,
        [switch]$IncludeApprovalHistory,
        [switch]$IncludePimForGroups
    )

    $scopeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $null = $scopeSet.Add('RoleManagement.Read.Directory')
    $null = $scopeSet.Add('RoleManagementPolicy.Read.Directory')
    $null = $scopeSet.Add('Group.Read.All')

    if ($IncludeLicenseDetails) {
        $null = $scopeSet.Add('User.Read.All')
        $null = $scopeSet.Add('Organization.Read.All')
    }

    if ($IncludeApprovalHistory) {
        $null = $scopeSet.Add('RoleManagement.Read.Directory')
    }

    if ($IncludePimForGroups) {
        $null = $scopeSet.Add('PrivilegedAssignmentSchedule.Read.AzureADGroup')
        $null = $scopeSet.Add('PrivilegedEligibilitySchedule.Read.AzureADGroup')
    }

    $null = $scopeSet.Add('Policy.Read.All')
    $null = $scopeSet.Add('AccessReview.Read.All')
    $null = $scopeSet.Add('Application.Read.All')

    return @($scopeSet)
}

function Connect-GraphForPimReview {
    [CmdletBinding()]
    param(
        [string[]]$Scopes,
        [string]$TenantId,
        [switch]$IncludeLicenseDetails,
        [switch]$IncludeApprovalHistory,
        [switch]$IncludePimForGroups,
        [switch]$ForceReConnect
    )

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Microsoft Graph PowerShell SDK is not installed. Install-Module Microsoft.Graph -Scope CurrentUser'
    }

    $requestedScopes = if ($Scopes -and $Scopes.Count -gt 0) {
        $Scopes
    }
    else {
        Get-DefaultPimScopes -IncludeLicenseDetails:$IncludeLicenseDetails -IncludeApprovalHistory:$IncludeApprovalHistory -IncludePimForGroups:$IncludePimForGroups
    }

    $currentContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($currentContext -and -not $ForceReConnect) {
        if (-not [string]::IsNullOrWhiteSpace($TenantId) -and $currentContext.TenantId -ne $TenantId) {
            Write-PimLog -Level WARN -Message "Existing context tenant ($($currentContext.TenantId)) differs from requested tenant ($TenantId). Reconnecting."
        }
        else {
        $missing = @($requestedScopes | Where-Object { $_ -notin $currentContext.Scopes })
        if ($missing.Count -eq 0) {
            Write-PimLog -Message 'Existing Microsoft Graph context satisfies requested scopes.'
            return $currentContext
        }

        Write-PimLog -Level WARN -Message "Existing context is missing scopes: $($missing -join ', '). Reconnecting."
        }
    }

    $connectParams = @{
        Scopes    = $requestedScopes
        NoWelcome = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams.TenantId = $TenantId
        Write-PimLog -Message "Connecting to Microsoft Graph for tenant $TenantId with delegated scopes: $($requestedScopes -join ', ')"
    }
    else {
        Write-PimLog -Message "Connecting to Microsoft Graph with delegated scopes: $($requestedScopes -join ', ')"
    }

    Connect-MgGraph @connectParams

    $context = Get-MgContext
    if (-not $context) {
        throw 'Unable to establish Microsoft Graph context.'
    }

    Write-PimLog -Message "Connected. TenantId=$($context.TenantId) Account=$($context.Account)"
    return $context
}

if ($MyInvocation.InvocationName -ne '.') {
    Connect-GraphForPimReview @PSBoundParameters
}


