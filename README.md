# Microsoft Entra PIM Full Review (PowerShell 7 + Graph SDK)

This solution exports the current Privileged Identity Management (PIM) state for:
- Microsoft Entra roles
- Microsoft Entra PIM for Groups (assignment and eligibility schedules)
- PIM-related privileged groups in role assignment paths
- Group membership paths
- User licensing context
- Role approval settings and optional beta approval history

It produces:
- Raw CSV/JSON evidence files
- A single multi-sheet Excel workbook (when ImportExcel is available)

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
- `Invoke-FullPimReview.ps1`
- `Output/` (created/used at runtime)

## Prerequisites

- PowerShell 7+
- Microsoft Graph PowerShell SDK
- Optional: ImportExcel module for workbook creation

Install modules:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ImportExcel -Scope CurrentUser
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
- Approval history and steps (beta-derived):
  - `RoleManagement.Read.Directory`

## Workbook Sheets

When ImportExcel is available, the workbook includes:

- `01_Summary`
- `02_Role_Assignments`
- `03_Role_Policy_Settings`
- `04_Group_Principals`
- `05_Group_Members`
- `06_PIM_Group_Assignments`
- `07_User_Licenses`
- `08_Approval_Settings`
- `09_Approval_History` (beta-derived where applicable)
- `10_Findings`

If ImportExcel is not installed, all CSV/JSON evidence is still exported.

## Configuration

Use `Config/pim-review.config.json` to define:

- output folder
- include transitive members
- include approval history
- include license details
- include PIM for Groups dataset
- install ImportExcel automatically if missing
- prompt to install ImportExcel when workbook generation is requested
- activation duration threshold for findings
- high-impact roles list
- expected license SKUs list

## How to Run

From the project root:

```powershell
pwsh ./Invoke-FullPimReview.ps1 -ConfigPath ./Config/pim-review.config.json -Verbose
```

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

## Raw Evidence Exports

Per run, the script creates a timestamped folder under `Output` containing:

- role assignments CSV
- role policy settings flat CSV + raw JSON
- privileged groups CSV
- per-group and combined membership CSV exports
- user licenses CSV
- approval settings CSV
- approval history CSV (beta-derived)
- findings CSV
- run metadata JSON
- transcript log

## Limitations

- Approval history/steps use Microsoft Graph beta endpoints and are clearly marked beta-derived.
- API properties can vary by tenant and endpoint behavior.
- `licenseDetails` retrieval is delegated-only in this workflow; fallback uses assignedLicenses + subscribedSkus.
- Some approver display names may be unresolved if directory object resolution is restricted.

## Sample Run Command

```powershell
pwsh ./Invoke-FullPimReview.ps1 -ConfigPath ./Config/pim-review.config.json -Verbose
```
