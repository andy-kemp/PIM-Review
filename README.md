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

## Quick Start: full PIM audit in one command

Double-click `Run-PimAudit.cmd` (or run `pwsh ./Start-PimAudit.ps1`). The first time, it asks for your tenants and saves them to `Config/audit-tenants.local.json` (git-ignored); after that it shows a menu of them.

```powershell
pwsh ./Start-PimAudit.ps1            # menu of tenants from the list
pwsh ./Start-PimAudit.ps1 -All       # every tenant in the list
pwsh ./Start-PimAudit.ps1 -Tenant SE # one tenant from the list by short name
```

Or name tenants directly:

```powershell
# One tenant
pwsh ./Start-PimAudit.ps1 -TenantId contoso.onmicrosoft.com

# Several tenants, with short names for the reports; builds the partnership roll-up at the end
pwsh ./Start-PimAudit.ps1 -TenantId tenant1.onmicrosoft.com, tenant2.onmicrosoft.com -TenantShortName T1, T2
```

`Start-PimAudit.ps1` checks and installs the modules it needs, then for each tenant runs everything with every option on: the Entra PIM review, the Azure RBAC review and the privileged access audit (PIM Phase 2 assessment, benchmarked against NCSC CAF B2). You sign in twice per tenant (Microsoft Graph, then Azure). Use an account with Global Reader in Entra and Reader at the tenant root management group in Azure. When it finishes it lists the reports and opens the Phase 2 assessment (or the partnership roll-up when there is more than one tenant).

Options: `-SkipAzure` (Entra only), `-IncludeResourceLevelAccess` (also list access on individual Azure resources; slower), `-UseDeviceCode` (Azure device-code sign-in), `-NoOpen`. A failed tenant does not stop the others.

Settings come from `Config/pim-review.config.local.json` when it exists (git-ignored), otherwise `Config/pim-review.config.json`; the tenant in the config is ignored in favour of `-TenantId`.

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
- `Get-AzureRbacInsights.ps1` (Azure review collectors: sign-in, Activity Log, Lighthouse, Key Vault/storage/SQL/AKS, workload credentials)
- `New-AzureRbacReport.ps1` (Azure review HTML/Markdown report)
- `Run-PimAudit.cmd` (double-click launcher for Start-PimAudit.ps1)
- `Start-PimAudit.ps1` (one command: full Entra, Azure and Phase 2 audit for one or more tenants)
- `Invoke-FullPimReview.ps1`
- `Invoke-PimPhase2Assessment.ps1` (PIM Phase 2 assessment over a tenant's Entra and Azure exports; runs offline)
- `New-PimPhase2Report.ps1` (Phase 2 HTML report)
- `Compare-PimPhase2Assessment.ps1` (diff between two assessments of one tenant)
- `Invoke-PimPartnershipRollup.ps1` (all partner tenants side by side)
- `Config/pim-phase2.catalogue.json` (trust levels, role catalogue, identity and organisation rules)
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
- Azure RBAC review:
  - `Directory.Read.All` (batch lookup of role assignment principals)
  - `User.Read.All`, `Group.Read.All` (users, guests, group members and owners)
  - `Application.Read.All` (service principal credentials, owners and publisher)
  - `AuditLog.Read.All` (last sign-in; also needs Entra ID P1)
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

- `40_Az_Scorecard`, `41_Az_Findings`
- `42_Az_Access_Matrix` (every user and workload identity down the side, every subscription across the top)
- `43_Az_User_Summary` (one row per principal: highest tier, standing vs eligible, reach, last sign-in, Azure changes)
- `44_Az_User_Access` (one row per principal per assignment, group assignments expanded to members)
- `45_Az_Role_Assignments` (every assignment, active and eligible, at every scope)
- `46_Az_Subscriptions`
- `47_Az_Groups`, `48_Az_Group_Members`, `49_Az_Group_Owners`
- `50_Az_Workload_Identities` (publisher, credentials, owners, managed identity host)
- `51_Az_Custom_Roles`
- `52_Az_Lighthouse`
- `53_Az_KeyVaults`, `54_Az_KV_Access_Policies`, `55_Az_Storage`, `56_Az_SQL`, `57_Az_AKS`, `58_Az_Local_Auth`
- `59_Az_Activity_By_Caller`, `60_Az_RBAC_Changes`
- `61_Az_Deny_Assignments`, `62_Az_Coverage_Gaps`

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
- `AzureActivityLogDays`: how far back to read the Activity Log for usage and role changes (default 30, max 89, 0 to skip)
- `AzureDormantDays`: no sign-in for this many days marks privileged access as dormant (default 90)
- `AzureSkipExtendedChecks`: only collect role assignments (skips sign-in, Activity Log, Lighthouse, Key Vault/storage/SQL/AKS, workload credentials)

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

The Azure review answers "who can do what, where, and are they using it", across the whole Azure estate.

### What it collects

- **Every role assignment**: tenant root (`/`), every management group, subscription, resource group and resource; active (permanent, time-bound or PIM-activated) and PIM-eligible.
- **Inheritance**: an assignment at a management group is shown against every subscription and resource beneath it.
- **People behind groups**: groups expanded transitively to users and service principals, including PIM for Groups eligible members; group owners and whether the group is role-assignable.
- **Privilege tier from real permissions**, so custom roles are rated correctly and conditions are respected:
  - Critical: can create role assignments (Owner, User Access Administrator, Role Based Access Control Administrator, custom roles with `Microsoft.Authorization/*` or `*`)
  - High: full write (`*`) without role assignment rights (Contributor), full data plane control (for example Key Vault Administrator), or role assignment rights limited by a condition
  - Medium: other write or data actions
  - Low: read only
- **Sign-in and identity hygiene**: last sign-in and on-premises sync for everyone with privileged access; for service principals, publisher (this tenant, Microsoft, or another organisation), credentials (secrets, certificates, federated, lifetime), and owners.
- **Usage**: the Activity Log over a window (default 30 days) shows who actually made changes, so standing write access that is never used stands out, plus every role assignment granted or removed in that window.
- **External access**: guests, and other organisations working in the subscriptions through Azure Lighthouse (not visible in role assignments).
- **Access outside Azure RBAC**: Key Vaults on access policies (and who can read secrets), storage accounts with shared key access, SQL servers allowing SQL logins, AKS clusters with local accounts, and other resources with key-based (local) auth.
- **Managed identities**: which resource each identity is attached to, because anyone who can run code there can use its access.
- **Deny assignments** and **resource counts per scope** (blast radius).

Microsoft platform identities (for example MS-PIM and Defender for Cloud scanners) are recognised and listed separately rather than raised as findings.

### Azure permissions needed

- Reader at the Tenant Root Group gives full coverage. With less (for example Security Reader), role assignments are still complete but resources are not readable, so resource counts, data plane checks and managed identity mapping are skipped for those subscriptions.
- Anything the account cannot read is listed in `AzureCoverageGaps.csv` and in the report, rather than silently missing.

### Findings raised

- Root-scope assignments (usually left behind by Elevate Access)
- Standing Critical or High access at subscription scope or above (one finding per person, listing every place)
- Dormant privileged accounts, privileged accounts synced from on-premises AD, standing access never used
- Guests with any Azure access, guests in privileged groups
- Orphaned assignments to deleted principals (confirmed one by one), assignments to foreign principals
- Disabled accounts that still hold access
- Workload identities with broad access; owners who could take them over; long-lived or secret-only credentials; dormant service principals; third-party applications with access; managed identities attached to compute
- Custom roles with wildcard or role assignment permissions
- Subscriptions with too many standing owners, or privileged access but no PIM
- Group owner escalation paths, non-role-assignable privileged groups
- Lighthouse delegations to other tenants
- Key Vault access policies, AKS local accounts, SQL authentication, storage shared keys, local auth
- Recent grants of Critical-tier roles
- Privileged roles assigned directly to users, Critical-tier eligibility with no expiry

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
pwsh ./Get-AzureRbacReview.ps1 -TenantId <tenant> -ActivityLogDays 89
pwsh ./Get-AzureRbacReview.ps1 -TenantId <tenant> -SkipExtendedChecks
```

You sign in twice: once to Microsoft Graph and once to Azure (`Connect-AzAccount`). Both are read-only.

### Azure outputs

- `AzureRbac_Summary_<tenant>.html` and `.md`: key insights, scorecard, findings by type, who can grant access, subscriptions and privileged access per subscription, people, groups, workload identities, external access, access outside RBAC, recent role changes, custom roles, all findings, coverage and method
- `Raw/` CSV evidence: `AzureRoleAssignments`, `AzureUserAccess`, `AzureUserSummary`, `AzureAccessMatrix`, `AzureSubscriptionSummary`, `AzureFindings`, `AzureGroupSummary`, `AzureGroupMembers`, `AzureGroupOwners`, `AzureWorkloadIdentities`, `AzureCustomRoles`, `AzureRoleDefinitions`, `AzureLighthouseDelegations`, `AzureKeyVaults`, `AzureKeyVaultAccessPolicies`, `AzureStorageAccounts`, `AzureSqlServers`, `AzureAksClusters`, `AzureLocalAuthResources`, `AzureActivityByCaller`, `AzureRoleAssignmentChanges`, `AzureDenyAssignments`, `AzureScorecard`, `AzureCoverageGaps`
- `Raw/AzureResourceAccess.csv` (only with `-IncludeResourceLevelAccess`): one row per resource per principal

### Azure limitations

- Classic subscription administrators are not included (retired by Microsoft).
- Database users, Kubernetes RoleBindings and VM local administrators are not included.
- The Activity Log keeps 90 days; very busy subscriptions are sampled (capped per subscription and flagged as a coverage gap).

## PIM Phase 2 Assessment

The Phase 2 assessment turns the Entra and Azure exports into the registers the PIM Phase 2 HLD and implementation runbook need. It reads only the Raw CSVs, so it runs offline and can be re-run whenever the role catalogue changes, without collecting again.

`Invoke-FullPimReview.ps1` runs it automatically at the end of each run (output in `<run>\Phase2`). Use `-SkipPhase2Assessment` to turn it off and `-TenantShortName CON` to set the short name used in partnership reports.

### What it produces

| File | Purpose |
| --- | --- |
| `P2_PrivilegedIdentities.csv` | Every privileged identity: account type (CLAD, everyday, guest, generic/service, break-glass, workload), organisation, linked everyday identity, highest trust level, phishing-resistant method, P2 licence, issues |
| `P2_AccessPaths.csv` | Every route from an identity to a role, Entra and Azure, with trust level: direct, PIM for Groups (eligible/active member), group member, nested group |
| `P2_SelfApproval.csv` | People who can request with one identity and approve with another (HLD F01) |
| `P2_ApproverGroups.csv` | Approver groups against HLD 7.6.3 (CLAD only, separate from the eligible population) |
| `P2_GroupBundles.csv` | Groups that bundle roles, TL1 inside bundles, recommended split (HLD 7.6.1) |
| `P2_TL1Paths.csv` | Every route to a TL1 role |
| `P2_StandingAccess.csv` | Permanent active access at TL1-TL3 (read-only Azure roles excluded, as the HLD allows them) |
| `P2_PolicyGaps.csv` | PIM role and group settings against the trust-level baseline |
| `P2_RoleCatalogue.csv` | Every role in use with trust level and holders (runbook 1.2) |
| `P2_MigrationWorksheet.csv` | One row per privileged path with a proposed action and blank Target path / Wave / Role owner / Decision columns |
| `P2_ExceptionCandidates.csv` | Break-glass, generic accounts, standing TL1/TL2, non-human TL1 |
| `P2_HldFindings.csv` | Status of F01-F15 in this tenant |
| `P2_Maturity.csv` | Measured indicators for the HLD 6.7 maturity baseline |
| `P2_Metrics.csv` / `.json` | Headline numbers used by the roll-up and diff |
| `P2_Controls.csv` | Every control check: result (Good / Partial / Weak / Not assessed), severity, finding, why it matters, what good looks like, recommended action, NCSC CAF outcome and NCSC principle |
| `P2_NcscCafBenchmark.csv` | Indicative rating for NCSC CAF 4.0 outcomes B2.a-B2.d |
| `P2_PimCoverage.csv` | Per role (and Azure scope): people who reach it just-in-time, time-bound or permanently |
| `P2_OversubscribedRoles.csv` | People per high-impact role against a guide (Microsoft: Global Administrator fewer than 5, subscription owners at most 3; catalogue guide for other TL1/TL2 roles) |
| `Privileged_Access_Audit_<tenant>.html` | The tenant report: at a glance, what is working well, what needs attention, NCSC benchmark, where PIM is and is not used, over-subscribed roles, detailed evidence |

### Trust levels

The audit classifies every role by the Trust Level model: TL1 Strategic Control (the tenant control plane, the cloud-era counterpart of Tier 0), TL2 Service Administration, TL3 Operational Administration and TL4 Workforce. Required controls rise with the level. See [From Tier 0 to Trust Levels](https://www.andykemp.com/2026/07/29/from-tier-0-to-trust-levels-rethinking-privileged-access-for-the-cloud-era/).

### The report

`Privileged_Access_Audit_<tenant>.html` is written for a non-specialist reader. It opens with a plain-English verdict and headline numbers, lists the controls that are working well and those that need attention (each with why it matters, what good looks like and the recommended action), and benchmarks the tenant against the NCSC Cyber Assessment Framework (CAF 4.0, Principle B2: identity and access control) and the NCSC secure system administration principles. CAF ratings are indicative: they use configuration evidence only, so indicators that need process evidence (monitoring, review records, joiners/movers/leavers) are marked Not assessed.

### Word report on your own template

`tools/new_audit_word_report.py` writes the same audit as a Word document on an existing branded template (for example the PIM Phase 2 HLD): it keeps the template's page setup, styles, logo header and footer, and replaces the body with the audit (cover, executive summary, trust level position, strengths, findings, PIM usage, over-subscribed roles, risk areas, NCSC benchmark, HLD alignment, recommended plan and appendices). Individuals are not named in the document; named detail stays in the CSV evidence. Needs Python 3 with `python-docx` and `matplotlib`. The template is client material and is not stored in this repository.

```bash
python3 tools/new_audit_word_report.py --phase2 Output/SE/Run-.../Phase2 --azure-raw Output/SE/Run-.../Azure/Raw \
    --template "PIM Phase2 - HLD.docx" --out "Privileged Access Audit - SE.docx" --tenant-name "Scottish Enterprise"
```

### Running it on its own

```powershell
# Latest Entra run and latest Azure run under a tenant's output folder
./Invoke-PimPhase2Assessment.ps1 -TenantFolder .\Output\Contoso -TenantShortName CON

# Explicit folders, with an identity map
./Invoke-PimPhase2Assessment.ps1 -EntraRunFolder .\Output\Contoso\Run-20261020-090000 `
    -AzureRunFolder .\Output\Contoso\Run-20261020-090000\Azure -IdentityMapCsv .\Config\identity-map.local.csv
```

### Role catalogue and rules

`Config/pim-phase2.catalogue.json` is a template. Copy it to `Config/pim-phase2.catalogue.local.json` (git-ignored) and put your programme's roles, domains and branding there; the scripts use the `.local.json` file when it exists. It holds:

- `TrustLevelBaselines`: TL1-TL4 activation duration, approval, MFA / authentication context, justification, permanent active/eligible, review cycle (HLD 7.5).
- `EntraRoles`: trust level per Entra role, with `Source` = `HLD`, `Proposed` or `Open`. Unlisted roles fall back to `EntraDefaultLevel`.
- `AzureRoleFamilies`, `AzureLevelMatrix`, `AzureSensitiveScopes`: Azure classification by role family and scope (HLD 7.11.2). Write-capable roles on scopes whose names match identity, key, security, logging or automation patterns are raised to TL1.
- `Identity`: CLAD UPN prefix and display-name patterns, other admin, generic and break-glass patterns.
- `Organisations.Domains`: UPN and guest home domains mapped to organisation and type (Tenant, Operator, Partner, Supplier).

Change the catalogue and re-run the assessment; no new collection is needed.

### Linking CLAD and everyday identities

Identities are linked by cleaned display name ("(Cloud Admin) Jane Smith" and "Jane Smith"), falling back to surname and initial from the CLAD UPN. Where that is not reliable, supply an identity map CSV with columns `PrivilegedUpn, EverydayUpn, Person` via `-IdentityMapCsv` (keep it as a `*.local.csv` file; it is git-ignored). The export only holds identities that have roles or approve, so a CLAD whose everyday account has neither shows as "No everyday identity in evidence". Self-approval checks are still complete, because every approver is in the evidence.

### Comparing runs (runbook 5.5)

```powershell
./Compare-PimPhase2Assessment.ps1 -Baseline .\Output\Contoso\Run-20261020-090000\Phase2 -Current .\Output\Contoso\Run-20261201-090000\Phase2
```

Lists access paths added, removed or changed (state or trust level), policy gaps opened or closed, self-approval routes added or removed, and the change in each headline metric.

### Partnership roll-up

```powershell
./Invoke-PimPartnershipRollup.ps1 -OutputRoot .\Output
```

Takes the latest assessment for each tenant and writes headline numbers and HLD finding status side by side, people with privilege in more than one tenant, all approver groups, and the role catalogue across tenants (for agreeing OD-02).

### Limits

- Monitoring (F10), password and recovery (F12), approver rota (F13) and device enforcement in practice (F06) cannot be measured from configuration; they need the runbook tests.
- The Excel workbook is optional. On devices where Application Control blocks the ImportExcel library (EPPlus.dll), the run continues and produces the HTML reports and CSV evidence.
- Purview role groups and billing roles are outside Entra and Azure RBAC and are not collected.
- Trust levels marked `Proposed` or `Open` are drafts until agreed by the partners.

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
