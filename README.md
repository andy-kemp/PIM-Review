# Microsoft Entra PIM Full Review (PowerShell 7 + Graph SDK)

This solution exports the current Privileged Identity Management (PIM) state for:
- Microsoft Entra roles
- Microsoft Entra PIM for Groups (assignment and eligibility schedules)
- PIM-related privileged groups in role assignment paths
- Group membership paths
- User licensing context
- Role approval settings and optional beta approval history
- Azure RBAC (optional): every Azure role assignment, active and PIM-eligible, from the tenant root through
  management groups, subscriptions and resource groups down to individual resources, with groups expanded to users

It produces:
- Raw CSV/JSON evidence files
- A single multi-sheet Excel workbook (when ImportExcel is available)
- Tenant-scoped run folder naming
- A markdown summary report for each run

The implementation is read-only and idempotent for reporting.

## Folder Structure

- `Modules/PimReview.Common.psm1`
- `Config/pim-review.config.json`
- `Connect-GraphForPimReview.ps1`
- `Get-PimRoleAssignments.ps1`
- `Get-PimRolePolicySettings.ps1`
- `Get-PimPrivilegedGroups.ps1`
- `Get-PimGroupMembers.ps1`
- `Get-PimUserLicenses.ps1`
- `Get-PimApprovalData.ps1`
- `Build-PimReviewWorkbook.ps1`
- `Get-AzureRbacReview.ps1` (Azure RBAC review; runs on its own or from `Invoke-FullPimReview.ps1`)
- `Invoke-FullPimReview.ps1`
- `Output/` (created/used at runtime)

## Prerequisites

- PowerShell 7+
- Microsoft Graph PowerShell SDK
- Optional: ImportExcel module for workbook creation
- For the Azure RBAC review: Az.Accounts module

Install modules:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ImportExcel -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser
```

## Delegated Graph Scopes Used

The connection script requests least-privilege scopes based on enabled features:

- PIM role assignments and schedules:
  - `RoleManagement.Read.Directory`
- PIM role policy settings and rules:
  - `RoleManagementPolicy.Read.Directory`
- PIM for Groups assignment and eligibility schedules:
  - `PrivilegedAssignmentSchedule.Read.AzureADGroup`
  - `PrivilegedEligibilitySchedule.Read.AzureADGroup`
- Group membership and group attributes:
  - `Group.Read.All`
- User profile and license details:
  - `User.Read.All`
- Subscribed SKU mapping fallback:
  - `Organization.Read.All`
- Tenant domain profile metadata:
  - `Domain.Read.All`
- Approval history and steps (beta-derived):
  - `RoleManagement.Read.Directory`
- Conditional Access posture:
  - `Policy.Read.All`
- Access review definitions:
  - `AccessReview.Read.All`
- Workload identity hygiene:
  - `Application.Read.All`
- Azure RBAC review (resolving principals and expanding groups):
  - `User.Read.All`, `Group.Read.All`, `Application.Read.All`
  - plus `PrivilegedEligibilitySchedule.Read.AzureADGroup` when PIM for Groups is enabled, to include eligible group members

## Workbook Sheets

When ImportExcel is available, the workbook includes:

- `00_Executive_Scorecard` (traffic light status, overall score, GA and break-glass control checks)
- `01_Summary`
- `02_Role_Assignments`
- `03_Role_Policy_Settings`
- `04_Group_Principals`
- `05_Group_Members`
- `06_PIM_Group_Assignments`
- `07_User_Licenses`
- `08_Approval_Settings`
- `09_Approval_History` (beta-derived where applicable)
- `10_User_Access_Paths` (user/guest direct and group-inherited privileged access paths)
- `11_User_Role_Summary` (one row per user with direct vs inherited role coverage and max risk)
- `12_Group_Role_Summary` (one row per privileged group with role coverage, member counts, and risk)
- `13_Activation_Requests` (beta-derived)
- `14_Activation_Anomalies`
- `15_Conditional_Access`
- `16_Access_Reviews` (beta-derived)
- `17_Workload_Risk`
- `18_Nested_Group_Paths`
- `19_SoD_Conflicts`
- `20_Findings`
- `21_User_Elevation_Paths` (each user and the roles they can elevate to via group membership)

When the Azure RBAC review is enabled, these sheets are appended to the same workbook:

- `40_Az_Scorecard`
- `41_Az_Findings`
- `42_Az_Access_Matrix` (every user and workload identity down the side, every subscription across the top)
- `43_Az_User_Summary` (one row per principal: highest tier, standing vs eligible, subscriptions and resources reachable)
- `44_Az_User_Access` (one row per principal per assignment, group assignments expanded to members)
- `45_Az_Role_Assignments` (every assignment, active and eligible, at every scope)
- `46_Az_Subscriptions`
- `47_Az_Group_Members`
- `48_Az_Group_Owners`
- `49_Az_Custom_Roles`
- `50_Az_Coverage_Gaps`

If ImportExcel is not installed, all CSV/JSON evidence is still exported.

## Configuration

Use `Config/pim-review.config.json` to define:

- output folder
- optional tenant ID to force connection to a specific tenant
- optional tenant label override for professional report naming (for example `South_of_Scotland_Enterprise`)
- include transitive members
- include approval history
- include license details
- include PIM for Groups dataset
- install ImportExcel automatically if missing
- prompt to install ImportExcel when workbook generation is requested
- activation duration threshold for findings
- high-impact roles list
- expected license SKUs list
- `IncludeAzureRbac`: run the Azure RBAC review as part of the full review
- `AzureSubscriptionIds`: limit the Azure review to these subscriptions (empty = every subscription visible)
- `AzureMaxOwnersPerSubscription`: standing Owner-tier users allowed per subscription before it is flagged (default 3)
- `AzureIncludeResourceLevelAccess`: also write one row per resource per principal (can be very large)
- `AzureUseDeviceAuthentication`: use device code sign-in for Azure

## How to Run

From the project root:

```powershell
pwsh ./Invoke-FullPimReview.ps1 -ConfigPath ./Config/pim-review.config.json -Verbose
```

To force a specific tenant for cross-tenant reviews:

```powershell
pwsh ./Invoke-FullPimReview.ps1 `
  -ConfigPath ./Config/pim-review.config.json `
  -TenantId <tenant-guid-or-domain> `
  -Verbose
```

If `TenantId` is not provided in config or command line, the script prompts at runtime for a tenant ID or verified domain. Press Enter at the prompt to continue with the current/default Graph context.

Optional switches can override config values:

```powershell
pwsh ./Invoke-FullPimReview.ps1 `
  -ConfigPath ./Config/pim-review.config.json `
  -IncludeTransitiveMembers `
  -IncludeApprovalHistory `
  -IncludeLicenseDetails `
  -InstallImportExcelIfMissing `
  -PromptToInstallImportExcel `
  -Verbose
```

## Azure RBAC Review

The Azure review reads every role assignment Azure Resource Manager knows about and answers "who can do what, where":

- Scopes: tenant root (`/`), every management group, subscription, resource group and resource
- Active assignments, marked as permanent, time-bound or PIM-activated
- PIM for Azure resources eligible assignments
- Inheritance: an assignment at a management group shows up against every subscription and resource beneath it
- Groups expanded transitively to users and service principals, including PIM for Groups eligible members
- Group owners, because an owner can add themselves to a group that holds Azure roles
- Role privilege tier worked out from each role's actual permissions, so custom roles are rated correctly:
  - Critical: can create role assignments (Owner, User Access Administrator, Role Based Access Control Administrator, or a custom role with `Microsoft.Authorization/*` or `*`)
  - High: full write (`*`) without role assignment rights (Contributor), or full data plane control (for example Key Vault Administrator)
  - Medium: other write or data actions
  - Low: read only
- Resource counts per scope from Azure Resource Graph, so each assignment shows its blast radius

### Azure permissions needed

- Reader at the Tenant Root Group gives full coverage (any role with `Microsoft.Authorization/*/read` works for the assignments themselves)
- Anything the account cannot read is listed in `AzureCoverageGaps.csv` and in the report, rather than silently missing

### Findings raised

- Assignments at tenant root (`/`), usually left behind by Elevate Access
- Standing (non-PIM) Critical or High tier access at subscription scope or above
- Guests with any Azure access
- Orphaned assignments to deleted principals
- Disabled accounts that still hold access
- Service principals and managed identities with broad Critical or High access
- Custom roles with wildcard or role assignment permissions
- Subscriptions with too many standing owners, or privileged access but no PIM
- Groups holding privileged roles that have owners, or that are not role-assignable
- Privileged roles assigned directly to users rather than through groups
- Critical tier eligibility with no expiry

### Running it

As part of the full review (set `IncludeAzureRbac` in config, or use the switch):

```powershell
pwsh ./Invoke-FullPimReview.ps1 -ConfigPath ./Config/pim-review.config.json -IncludeAzureRbac
```

Output goes in an `Azure` folder inside the run folder, and the sheets are appended to the PIM workbook.

On its own:

```powershell
pwsh ./Get-AzureRbacReview.ps1 -TenantId <tenant-guid-or-domain>
pwsh ./Get-AzureRbacReview.ps1 -TenantId <tenant> -SubscriptionId <sub1>,<sub2> -IncludeResourceLevelAccess
```

You sign in twice: once to Microsoft Graph and once to Azure (`Connect-AzAccount`). Both are read-only.

### Azure outputs

- `AzureRbac_Summary_<tenant>.html` and `.md` (scorecard, findings, subscriptions, privileged users and workload identities, custom roles, group owners, coverage gaps)
- `Raw/AzureRoleAssignments.csv`
- `Raw/AzureUserAccess.csv`
- `Raw/AzureUserSummary.csv`
- `Raw/AzureAccessMatrix.csv`
- `Raw/AzureSubscriptionSummary.csv`
- `Raw/AzureFindings.csv`
- `Raw/AzureGroupMembers.csv`, `Raw/AzureGroupOwners.csv`
- `Raw/AzureCustomRoles.csv`, `Raw/AzureRoleDefinitions.csv`
- `Raw/AzureScorecard.csv`, `Raw/AzureCoverageGaps.csv`
- `Raw/AzureResourceAccess.csv` (only with `-IncludeResourceLevelAccess`)

### Azure limitations

- Deny assignments and Azure Lighthouse delegations are not included.
- Classic subscription administrators are not included (retired by Microsoft).
- Data plane permissions outside Azure RBAC (Key Vault access policies, storage account keys, SQL logins) are not included.

## Raw Evidence Exports

Per run, the script creates tenant-scoped output under `Output`:

- `<tenantPrefix-or-name>_<tenantId>/Run-YYYYMMDD-HHMMSS/`

Each run folder contains:

- role assignments CSV
- role policy settings flat CSV + raw JSON
- privileged groups CSV
- per-group and combined membership CSV exports
- user licenses CSV
- approval settings CSV
- approval history CSV (beta-derived)
- tenant details CSV + JSON
- user access paths CSV
- user role access summary CSV
- group role access summary CSV
- activation requests CSV (beta-derived)
- activation anomalies CSV
- conditional access policy CSV
- access reviews CSV (beta-derived)
- workload identity risk CSV
- nested group privilege paths CSV
- segregation-of-duties conflicts CSV
- executive scorecard CSV
- user elevation paths CSV
- findings CSV
- run metadata JSON
- summary markdown and HTML report
- summary PDF report (when Word COM automation is available)
- transcript log

The HTML/PDF report is a detailed assessment document, including:

- consultancy-style cover page and section index
- numbered report sections for client presentation
- explicit role assignments for users and groups (active and eligible)
- per-user elevation paths based on group memberships
- executive scorecard with traffic-light status and consultative recommendations

`UserAccessPaths.csv` includes risk classification columns:

- `AccessRiskRating`
- `AccessRiskReason`

Executive scorecard includes explicit policy controls:

- maximum 5 active Global Administrator reachable users
- target of exactly 2 break-glass accounts

Workbook naming uses tenant context, for example:

- `PIM_Review_<tenantPrefix-or-name>_<timestamp>.xlsx`

Tenant label selection order is:

- `TenantLabelOverride` (if configured)
- tenant display name
- primary domain prefix (for example `sose` from `sose.scot`)
- initial `.onmicrosoft.com` prefix
- tenant ID fallback

## Limitations

- Approval history/steps use Microsoft Graph beta endpoints and are clearly marked beta-derived.
- API properties can vary by tenant and endpoint behavior.
- `licenseDetails` retrieval is delegated-only in this workflow; fallback uses assignedLicenses + subscribedSkus.
- Some approver display names may be unresolved if directory object resolution is restricted.

## Sample Run Command

```powershell
pwsh ./Invoke-FullPimReview.ps1 -ConfigPath ./Config/pim-review.config.json -Verbose
```
