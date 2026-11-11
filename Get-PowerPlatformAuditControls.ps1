<#
.SYNOPSIS
Power Platform trust-level model and control checks. Function definitions only; dot-sourced by
Invoke-PowerPlatformAssessment.ps1.

.DESCRIPTION
Get-PpTrustLevelModel describes every Power Platform route to admin rights: what it can do, its trust level in
the Trust Level model (TL1 Strategic Control to TL4 Workforce), what that level needs, and what happens to it
when Power Platform Administrator is managed by PIM.

Get-PpAuditControls returns control checks in the same shape as the Entra/Azure privileged access audit
(Good / Partial / Weak / Not assessed, severity, finding, why it matters, what good looks like, recommended
action, NCSC CAF outcome and NCSC secure system administration principle), plus the CAF and SSA roll-ups.
#>

function Get-PpTrustLevelModel {
    # One row per kind of access. Catalogue entries (EntraRoles, PowerPlatformRoles) override the default levels.
    param($Catalogue)
    $rows = @(
        [pscustomobject]@{ Key = 'Global Administrator'; Layer = 'Entra role'; TrustLevel = 'TL1'
            CanDo = 'Everything in the tenant. In Power Platform: every admin action, and self-elevation to System Administrator in every Dataverse environment.'
            Needs = 'CLAD only, direct-eligible in PIM (never through a group), approval, phishing-resistant sign-in, short activation. Not used for Power Platform work.'
            UnderPim = 'Already in PIM under the Entra HLD. A GA activation is a route into all Power Platform data; self-elevation is logged to Purview.' }
        [pscustomobject]@{ Key = 'Power Platform Administrator'; Layer = 'Entra role'; TrustLevel = 'TL2'
            CanDo = 'All Power Platform admin functions in every environment regardless of security groups: create/delete/copy/restore environments, tenant settings, DLP policies, capacity, manage anyone''s apps, flows and agents, support tickets, and self-elevation to System Administrator in any environment.'
            Needs = 'CLAD, eligible in PIM, directly assigned (Microsoft does not support this role through groups), MFA or authentication context on activation, justification, activation of 4 hours or less, no Power Platform licence.'
            UnderPim = 'Admin centre and admin APIs only work while active; System Administrator gained by self-elevation is removed when the activation ends; flows and scripts that use admin connectors or admin PowerShell stop working outside activation.' }
        [pscustomobject]@{ Key = 'Dynamics 365 Administrator'; Layer = 'Entra role'; TrustLevel = 'TL2'
            CanDo = 'Most Power Platform admin functions, limited to environments whose security group they belong to; self-elevation to System Administrator in those environments.'
            Needs = 'As Power Platform Administrator. Membership of each environment''s security group is part of the access and must be reviewed with it.'
            UnderPim = 'As Power Platform Administrator, plus: self-elevation fails in environments whose security group the admin is not in.' }
        [pscustomobject]@{ Key = 'Fabric Administrator'; Layer = 'Entra role'; TrustLevel = 'TL2'
            CanDo = 'Power BI and Fabric tenant settings, workspaces and capacities. No Power Platform environment rights, but controls export and sharing of reporting data.'
            Needs = 'CLAD, eligible in PIM.'
            UnderPim = 'No effect on Power Apps, Power Automate or Dataverse.' }
        [pscustomobject]@{ Key = 'Dynamics 365 Business Central Administrator'; Layer = 'Entra role'; TrustLevel = 'TL3'
            CanDo = 'Business Central environments only.'
            Needs = 'CLAD, eligible in PIM.'
            UnderPim = 'No effect on Power Platform environments.' }
        [pscustomobject]@{ Key = 'System Administrator (production or default)'; Layer = 'Dataverse role'; TrustLevel = 'TL2'
            CanDo = 'Full control of one environment: all business data, security roles, users, solutions, plug-ins, auditing settings.'
            Needs = 'Not held standing by people. Gained just-in-time by a CLAD through Power Platform Administrator activation and self-elevation, or through a PIM for Groups group bound to a Dataverse group team.'
            UnderPim = 'PIM does not see roles assigned inside Dataverse. Standing assignments must be removed for PIM to mean anything; flows owned by these people may rely on the role.' }
        [pscustomobject]@{ Key = 'System Administrator (sandbox, test, trial)'; Layer = 'Dataverse role'; TrustLevel = 'TL3'
            CanDo = 'Full control of a non-production environment and any data copied into it.'
            Needs = 'Named people, reviewed; just-in-time where the environment holds copies of live data.'
            UnderPim = 'Not affected by PIM on the Entra role.' }
        [pscustomobject]@{ Key = 'System Administrator (developer environment)'; Layer = 'Dataverse role'; TrustLevel = 'TL4'
            CanDo = 'Full control of a personal developer environment.'
            Needs = 'Acceptable on the everyday account; recorded.'
            UnderPim = 'Not affected.' }
        [pscustomobject]@{ Key = 'System Customizer'; Layer = 'Dataverse role'; TrustLevel = 'TL3'
            CanDo = 'Change tables, forms, views and solutions; no security-role administration.'
            Needs = 'Everyday account is acceptable outside production; in production through a group, ideally PIM for Groups.'
            UnderPim = 'Not affected; this is the usual replacement when System Administrator is removed from an everyday account.' }
        [pscustomobject]@{ Key = 'Environment Admin (no Dataverse)'; Layer = 'Environment role'; TrustLevel = 'TL3'
            CanDo = 'Manage an environment without Dataverse: users, roles, apps and flows in it.'
            Needs = 'Named people, reviewed.'
            UnderPim = 'Not affected.' }
        [pscustomobject]@{ Key = 'Environment Maker'; Layer = 'Dataverse or environment role'; TrustLevel = 'TL4'
            CanDo = 'Create apps, flows, connections and agents in the environment.'
            Needs = 'Everyday account with the right licence.'
            UnderPim = 'Not affected. Makers keep building on everyday accounts.' }
        [pscustomobject]@{ Key = 'Power Platform RBAC owner / contributor / RBAC administrator (tenant scope)'; Layer = 'Power Platform RBAC'; TrustLevel = 'TL2'
            CanDo = 'Power Platform API administration granted outside Entra roles (mainly for service principals).'
            Needs = 'Service principals only, owned and reviewed; people use the Entra role through PIM.'
            UnderPim = 'Not governed by PIM: a parallel route that must be listed and reviewed.' }
        [pscustomobject]@{ Key = 'Management application (service principal)'; Layer = 'Power Platform admin registration'; TrustLevel = 'TL2'
            CanDo = 'Power Platform admin APIs as an application, without a user or PIM.'
            Needs = 'Named owner, certificate credential, monitoring, registered exception.'
            UnderPim = 'Not affected; automation that needs standing admin rights should move here rather than stay on a person.' }
    )
    $ov = $null
    if ($Catalogue) { $ov = $Catalogue.PSObject.Properties['PowerPlatformRoles'] }
    foreach ($r in $rows) {
        $tl = $null
        if ($r.Layer -eq 'Entra role' -and $Catalogue -and $Catalogue.EntraRoles -and $Catalogue.EntraRoles.PSObject.Properties[$r.Key]) { $tl = $Catalogue.EntraRoles.($r.Key).Level }
        if ($ov -and $ov.Value.PSObject.Properties[$r.Key]) { $tl = $ov.Value.($r.Key).Level }
        if ($tl) { $r.TrustLevel = [string]$tl }
    }
    return $rows
}

function Get-PpAuditControls {
    [CmdletBinding()]
    param([hashtable]$Ctx)

    $controls = New-Object System.Collections.ArrayList
    $gapText = @{
        'PPI-01' = 'Power Platform admin roles are held by everyday accounts'; 'PPI-02' = 'everyday accounts are standing System Administrators in production'
        'PPI-03' = 'CLAD accounts own flows, apps or connections'; 'PPI-05' = 'few Power Platform admins use phishing-resistant sign-in'
        'PPI-07' = 'guests hold Power Platform admin rights'; 'PPP-01' = 'Power Platform admin roles are held permanently'
        'PPP-02' = 'PIM settings for Power Platform roles fall short of the TL2 baseline'; 'PPP-04' = 'Power Platform admin roles are granted through groups, which Microsoft does not support'
        'PPC-01' = 'Conditional Access does not cover all Power Platform admins'; 'PPC-02' = 'Power Platform admins are not required to use phishing-resistant sign-in'
        'PPE-01' = 'production environments have too many System Administrators'; 'PPE-03' = 'production environments have no security group'
        'PPE-05' = 'Dataverse auditing is off in production'; 'PPW-01' = 'flows will break when admin rights are removed'
        'PPG-01' = 'anyone can create environments'; 'PPG-02' = 'DLP does not cover every environment'
    }
    $add = {
        param([string]$Id, [string]$Area, [string]$Title, [string]$Result, [string]$Severity, [string]$Finding, [string]$Why, [string]$Good, [string]$Action, [string]$Caf, [string]$Ssa, [string]$Reference, [string]$Evidence)
        if ($Result -eq 'Good' -or $Result -eq 'Not assessed') { $Severity = '' }
        $Finding = $Finding -replace ':\s*\.$', '.'
        $null = $controls.Add([pscustomobject]@{
            Id = $Id; Area = $Area; Control = $Title; Gap = $gapText[$Id]; Result = $Result; Severity = $Severity
            Finding = $Finding; WhyItMatters = $Why; WhatGoodLooksLike = $Good; RecommendedAction = $Action
            CafOutcome = $Caf; NcscPrinciple = $Ssa; Reference = $Reference; Evidence = $Evidence
        })
    }
    $pl = { param($n, $one, $many) if ([int]$n -eq 1) { "$n $one" } else { "$n $many" } }
    $names = { param($rows, $prop, $max) $v = @($rows | ForEach-Object { $_.$prop } | Where-Object { $_ } | Sort-Object -Unique); $t = (@($v | Select-Object -First $max) -join '; '); if ($v.Count -gt $max) { $t += "; and $($v.Count - $max) more" }; $t }

    $people = @($Ctx.People)
    $humans = @($people | Where-Object { $_.AccountType -in @('CLAD', 'Other admin account', 'Everyday', 'Guest', 'Generic/Service') })
    $adminRoleNames = @('Power Platform Administrator', 'Dynamics 365 Administrator')
    $ppAdmins = @($humans | Where-Object { $_.TenantAdminRoles })
    $tenantRows = @($Ctx.TenantRoles | Where-Object { $_.PrincipalType -eq 'User' -and $_.RoleName -in $adminRoleNames })
    $baseline = $Ctx.Baseline
    $hasPp = [bool]$Ctx.Meta.powerPlatformApiAvailable
    $envs = @($Ctx.Environments)
    $prodEnvs = @($envs | Where-Object { $_.IsProd })

    # =========================================================================================
    # Administrator population
    # =========================================================================================
    $n = @($tenantRows | Select-Object -ExpandProperty UserId -Unique).Count
    $guide = 10
    & $add 'PPA-01' 'Administrator population' 'Power Platform and Dynamics 365 Administrator are held by a small number of people' $(if ($n -le $guide) { 'Good' } else { 'Weak' }) 'Medium' `
        "$(& $pl $n 'person holds' 'people hold') Power Platform Administrator or Dynamics 365 Administrator (eligible or active)." `
        'Each holder can change DLP and tenant settings, delete environments and reach any environment''s data by self-elevation.' `
        "No more than $guide people, all with a business need recorded." `
        'Remove the role from anyone who has not needed it in the last 90 days (see PIM usage), and record a need for the rest.' `
        'B2.c, B2.d' 'SSA 4' 'Assessment guide for TL2 roles' 'PP_People.csv'
    $gaN = @($Ctx.TenantRoles | Where-Object { $_.PrincipalType -eq 'User' -and $_.RoleName -eq 'Global Administrator' } | Select-Object -ExpandProperty UserId -Unique).Count
    & $add 'PPA-02' 'Administrator population' 'Few people can reach Power Platform data through Global Administrator' $(if ($gaN -lt 5) { 'Good' } else { 'Weak' }) 'Medium' `
        "$(& $pl $gaN 'person' 'people') can become Global Administrator, and so can self-elevate into every Dataverse environment." `
        'Global Administrator is a TL1 route into all Power Platform data, alongside its route into Azure.' `
        'Fewer than five, CLAD only, and alerting on Power Platform self-elevation (Purview audit).' `
        'Covered by the Entra HLD. Add Power Platform self-elevation to the monitoring use cases.' `
        'B2.c' 'SSA 5' 'Microsoft: fewer than five Global Administrators' 'PP_AccessPaths.csv'

    # =========================================================================================
    # Everyday and CLAD accounts
    # =========================================================================================
    $everydayAdmins = @($ppAdmins | Where-Object { $_.AccountType -in @('Everyday', 'Guest') -and $_.Enabled -ne $false })
    & $add 'PPI-01' 'Everyday and CLAD accounts' 'Power Platform admin roles are held only by dedicated admin accounts (CLADs)' $(if ($everydayAdmins.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
        "$(& $pl $everydayAdmins.Count 'everyday or guest account holds' 'everyday or guest accounts hold') Power Platform or Dynamics 365 Administrator: $(& $names $everydayAdmins 'UserPrincipalName' 10)." `
        'The same account reads email, browses and builds flows. One phished session carries tenant-wide Power Platform admin rights.' `
        'Admin roles on CLADs only. Everyday accounts keep the maker roles and licences they build with.' `
        'Create the CLADs listed in PP_CladProvisioning.csv, make them eligible, then remove the role from the everyday accounts once their flows are checked.' `
        'B2.c' 'SSA 3' 'PIM Phase 2 HLD: CLAD for all admin work' 'PP_CladProvisioning.csv'

    $prodSa = @($Ctx.EnvRoles | Where-Object { $_.PrincipalType -eq 'User' -and $_.IsAdminRole -and $_.IsProd })
    $prodSaEveryday = @($prodSa | Where-Object { $_.AccountType -in @('Everyday', 'Guest') -and $_.Enabled -ne $false })
    $ppl = @($prodSaEveryday | Select-Object -ExpandProperty UserId -Unique)
    $res = if (-not $hasPp) { 'Not assessed' } elseif ($ppl.Count -eq 0) { 'Good' } else { 'Weak' }
    & $add 'PPI-02' 'Everyday and CLAD accounts' 'No everyday account is a standing System Administrator in production' $res 'High' `
        "$(& $pl $ppl.Count 'everyday account is' 'everyday accounts are') System Administrator in a production or default environment, directly or through a team: $(& $names $prodSaEveryday 'UserPrincipalName' 10)." `
        'System Administrator is assigned inside Dataverse, so PIM never sees it. It gives full control of the environment''s data, users and security.' `
        'Production System Administrator is reached just-in-time from a CLAD (PIM activation and self-elevation). Everyday accounts hold scoped roles such as System Customizer.' `
        'Give each person a scoped role that covers what they build, check their flows (PP_FlowsAtRisk.csv), then remove System Administrator.' `
        'B2.c' 'SSA 4' 'Microsoft: remove old System Administrator assignments before using PIM' 'PP_AccessPaths.csv'

    $cladBuild = @($humans | Where-Object { $_.AccountType -eq 'CLAD' -and (([int]$_.FlowsOwned + [int]$_.AppsOwned + [int]$_.ConnectionsOwned) -gt 0) })
    & $add 'PPI-03' 'Everyday and CLAD accounts' 'CLAD accounts administer only: they own no flows, apps or connections' $(if (-not $hasPp) { 'Not assessed' } elseif ($cladBuild.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
        "$(& $pl $cladBuild.Count 'CLAD owns' 'CLADs own') flows, apps or connections: $(& $names $cladBuild 'UserPrincipalName' 10)." `
        'A connection created by a CLAD is a stored privileged credential. It keeps working outside the PIM window and is used by anyone the flow or app is shared with.' `
        'CLADs own nothing in Power Platform. Business automation runs on everyday or service accounts.' `
        'Move each item to the person''s everyday account or a service account, then delete the CLAD''s connections.' `
        'B2.c' 'SSA 3' '' 'PP_People.csv'

    $cladLic = @($humans | Where-Object { $_.AccountType -eq 'CLAD' -and ($_.PremiumLicence -or $_.OfficeLicence) })
    & $add 'PPI-04' 'Everyday and CLAD accounts' 'CLAD accounts carry no Power Platform or Office licence' $(if ($cladLic.Count -eq 0) { 'Good' } else { 'Partial' }) 'Medium' `
        "$(& $pl $cladLic.Count 'CLAD has' 'CLADs have') a Power Platform, Dynamics or Office licence: $(& $names $cladLic 'UserPrincipalName' 10)." `
        'A licence lets the CLAD build, receive mail and run apps, which is the everyday account''s job. Unlicensed admins still administer (Microsoft gives them administrative access mode).' `
        'No licence on CLADs.' `
        'Remove the licences.' `
        'B2.c' 'SSA 3' 'Microsoft: unlicensed admins get administrative access mode' 'PP_People.csv'

    $known = @($ppAdmins | Where-Object { $null -ne $_.PhishingResistant -and [string]$_.PhishingResistant -ne '' })
    if ($known.Count -eq 0) {
        & $add 'PPI-05' 'Everyday and CLAD accounts' 'Power Platform admins sign in with phishing-resistant methods' 'Not assessed' '' 'Sign-in methods could not be read.' '' '' '' 'B2.a, B2.c' 'SSA 2' '' 'PP_People.csv'
    }
    else {
        $pr = @($known | Where-Object { [string]$_.PhishingResistant -eq 'True' })
        $pct = [int][Math]::Round(100 * $pr.Count / $known.Count)
        & $add 'PPI-05' 'Everyday and CLAD accounts' 'Power Platform admins sign in with phishing-resistant methods' $(if ($pct -ge 90) { 'Good' } elseif ($pct -ge 50) { 'Partial' } else { 'Weak' }) 'High' `
            "$pct% of Power Platform admins ($($pr.Count) of $($known.Count)) have a passkey, FIDO2 key, Windows Hello or certificate registered." `
            'Admin roles are the prime phishing target; app-based MFA can be relayed by adversary-in-the-middle kits.' `
            'Every admin has a phishing-resistant method and Conditional Access requires it.' `
            'Register passkeys for the CLADs (TAP onboarding, as in the passkey programme), then enforce with an authentication strength.' `
            'B2.a, B2.c' 'SSA 2' 'NCSC CAF B2.a: authentication follows up-to-date best practice' 'PP_People.csv'
    }

    $dead = @($people | Where-Object { ($_.Enabled -eq $false -or $_.Found -eq $false) -and ($_.TenantAdminRoles -or $_.ProdSysAdminEnvironments -or $_.OtherSysAdminEnvironments) })
    & $add 'PPI-06' 'Everyday and CLAD accounts' 'Disabled and deleted accounts hold no Power Platform admin rights' $(if ($dead.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
        "$(& $pl $dead.Count 'disabled or deleted account still holds' 'disabled or deleted accounts still hold') admin rights: $(& $names $dead 'UserPrincipalName' 10)." `
        'Leftover rights come back the moment an account is re-enabled, and show the leaver process misses Power Platform.' `
        'Rights removed when people leave.' `
        'Remove the roles and add Dataverse roles to the leaver checklist.' `
        'B2.d' 'SSA 4' '' 'PP_People.csv'

    $guests = @($people | Where-Object { $_.AccountType -eq 'Guest' -and ($_.TenantAdminRoles -or $_.ProdSysAdminEnvironments) })
    & $add 'PPI-07' 'Everyday and CLAD accounts' 'Guests and suppliers hold no standing Power Platform admin rights' $(if ($guests.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
        "$(& $pl $guests.Count 'guest holds' 'guests hold') Power Platform admin or production System Administrator: $(& $names $guests 'UserPrincipalName' 10)." `
        'Guest accounts are secured by another organisation''s identity controls.' `
        'Supplier admin access is eligible, time-limited and on accounts this tenant controls.' `
        'Move supplier access to supplier CLADs in this tenant, eligible only, with an end date.' `
        'B2.c, B2.d' 'SSA 4' '' 'PP_People.csv'

    # =========================================================================================
    # PIM
    # =========================================================================================
    $perm = @($tenantRows | Where-Object { $_.State -eq 'Active' -and [string]$_.Permanent -eq 'True' })
    $permPeople = @($perm | Select-Object -ExpandProperty UserId -Unique)
    & $add 'PPP-01' 'PIM' 'Power Platform admin roles are just-in-time (eligible), not permanent' $(if ($tenantRows.Count -eq 0) { 'Not assessed' } elseif ($permPeople.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
        "$(& $pl $permPeople.Count 'person holds' 'people hold') Power Platform or Dynamics 365 Administrator permanently: $(& $names $perm 'UserPrincipalName' 10)." `
        'A permanent role is always on: no activation, approval, justification or time limit, and nothing in the audit trail says when it was needed.' `
        'Eligible only, activated when needed. Automation that needs standing rights uses a registered service principal instead.' `
        'Convert to eligible after the CLAD is in place and the PIM impact items (PP_PimImpact.csv) are cleared.' `
        'B2.c' 'SSA 4' 'PIM Phase 2 HLD TL2 baseline' 'PP_PimCoverage.csv'

    $gaps = @($Ctx.PolicyGaps | Where-Object { $_.RoleName -in $adminRoleNames })
    if ($gaps.Count -eq 0) {
        & $add 'PPP-02' 'PIM' 'PIM settings for Power Platform roles meet the TL2 baseline' 'Not assessed' '' 'Role settings could not be read.' '' '' '' 'B2.c' 'SSA 4' '' 'PP_PolicyGaps.csv'
    }
    else {
        $bad = @($gaps | Where-Object { $_.Gaps })
        & $add 'PPP-02' 'PIM' 'PIM settings for Power Platform roles meet the TL2 baseline' $(if ($bad.Count -eq 0) { 'Good' } elseif ($bad.Count -lt $gaps.Count) { 'Partial' } else { 'Weak' }) 'Medium' `
            $(if ($bad.Count) { (@($bad | ForEach-Object { "$($_.RoleName): $($_.Gaps)" }) -join '. ') + '.' } else { 'Both roles meet the TL2 baseline.' }) `
            'Loose settings (long activations, no MFA, no justification, permanent assignments allowed) turn PIM into a formality.' `
            "TL2: activation $($baseline.MaxActivationHours) hours or less, MFA or authentication context, justification, no permanent eligible or active assignments." `
            'Apply the TL2 role settings from the Entra HLD to both roles.' `
            'B2.c' 'SSA 4' 'PIM Phase 2 HLD 7.5' 'PP_PolicyGaps.csv'
    }

    $ctxRoles = @($Ctx.RoleSettings | Where-Object { $_.RoleName -in $adminRoleNames })
    if ($ctxRoles.Count) {
        $withCtx = @($ctxRoles | Where-Object { [string]$_.AuthContextRequired -eq 'True' })
        & $add 'PPP-03' 'PIM' 'Activating Power Platform admin roles needs an authentication context (phishing-resistant step-up)' $(if ($withCtx.Count -eq $ctxRoles.Count) { 'Good' } elseif ($withCtx.Count) { 'Partial' } else { 'Weak' }) 'Medium' `
            "$($withCtx.Count) of $($ctxRoles.Count) roles require an authentication context on activation." `
            'Plain MFA on activation accepts whatever method the session already has. An authentication context lets Conditional Access demand a passkey and a compliant device at the moment of elevation.' `
            'Authentication context on activation, mapped to a Conditional Access policy requiring phishing-resistant strength.' `
            'Use the TL2 context created for the Entra roles (FR-03) on both Power Platform roles.' `
            'B2.a, B2.c' 'SSA 2' 'PIM Phase 2 runbook FR-03' 'PP_RoleSettings.csv'
    }

    $grp = @($tenantRows | Where-Object { $_.AssignedVia -eq 'Group' })
    & $add 'PPP-04' 'PIM' 'Power Platform admin roles are assigned directly, not through groups' $(if ($grp.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
        "$(& $pl @($grp | Select-Object -ExpandProperty UserId -Unique).Count 'person gets' 'people get') Power Platform or Dynamics 365 Administrator through a group: $(& $names $grp 'GroupName' 6)." `
        'Microsoft states that Global, Power Platform and Dynamics 365 Administrator must be assigned directly for Power Platform; group-based assignment is not supported, and self-elevation does not work through groups. This is an exception to the trust-level function-group model.' `
        'Direct-eligible assignments to CLADs, reviewed on the TL2 cycle.' `
        'Assign these two roles directly (eligible) and record them as an exception to the function-group design, as for Global Administrator.' `
        'B2.c' 'SSA 4' 'Microsoft: service admin roles must be directly assigned' 'PP_AccessPaths.csv'

    $elig = @($ppAdmins | Where-Object { $_.TenantAdminPim -match 'eligible' })
    if ($elig.Count -gt 0) {
        $dormant = @($elig | Where-Object { [int]$_.Activations90d -eq 0 })
        & $add 'PPP-05' 'PIM' 'Eligible Power Platform admins use the role' $(if ($dormant.Count -eq 0) { 'Good' } else { 'Partial' }) 'Low' `
            "$(& $pl $dormant.Count 'eligible admin has' 'eligible admins have') not activated in $($Ctx.Meta.activationHistoryDays) days: $(& $names $dormant 'UserPrincipalName' 10)." `
            'Unused eligibility is still access an attacker can activate.' `
            'Eligibility only for people who use it; removed after a set period of non-use.' `
            'Remove eligibility from dormant admins at the next access review.' `
            'B2.d' 'SSA 4' '' 'PP_PimImpact.csv'
    }

    # =========================================================================================
    # Conditional Access
    # =========================================================================================
    if (-not $Ctx.Meta.conditionalAccessAvailable) {
        & $add 'PPC-01' 'Conditional Access' 'Conditional Access requires MFA for every Power Platform admin' 'Not assessed' '' 'Conditional Access could not be read.' '' '' '' 'B2.a' 'SSA 2' '' ''
    }
    else {
        $covered = @($ppAdmins | Where-Object { $_.CaAdminMfa })
        $phishCov = @($ppAdmins | Where-Object { $_.CaPhishingResistant })
        $dev = @($ppAdmins | Where-Object { $_.CaCompliantDevice })
        $tot = [Math]::Max(1, $ppAdmins.Count)
        & $add 'PPC-01' 'Conditional Access' 'Conditional Access requires MFA for every Power Platform admin' $(if ($ppAdmins.Count -eq 0) { 'Not assessed' } elseif ($covered.Count -eq $ppAdmins.Count) { 'Good' } elseif ($covered.Count) { 'Partial' } else { 'Weak' }) 'High' `
            "$($covered.Count) of $($ppAdmins.Count) Power Platform admins are covered by an enabled policy that requires MFA or an authentication strength for the admin portals or Power Platform." `
            'MFA in PIM only applies at activation. Conditional Access protects every sign-in to the admin centre and Power Platform APIs.' `
            'An enabled policy targeting the CLAD group (not the directory role, which only covers active holders) for all resources or Microsoft Admin Portals and the Power Platform apps.' `
            'Extend the CLAD policies from the Entra stream to cover Power Platform; check exclusions.' `
            'B2.a' 'SSA 2' '' 'PP_People.csv'
        & $add 'PPC-02' 'Conditional Access' 'Power Platform admins must use a phishing-resistant authentication strength' $(if ($ppAdmins.Count -eq 0) { 'Not assessed' } elseif ($phishCov.Count -eq $ppAdmins.Count) { 'Good' } elseif ($phishCov.Count) { 'Partial' } else { 'Weak' }) 'High' `
            "$($phishCov.Count) of $($ppAdmins.Count) Power Platform admins are covered by a policy requiring a phishing-resistant authentication strength." `
            'Registering a passkey does not stop an attacker using a weaker method; only an enforced authentication strength does.' `
            'Phishing-resistant strength enforced for every CLAD sign-in.' `
            'Apply the TL1/TL2 authentication strength policy to the CLAD group once passkeys are registered.' `
            'B2.a, B2.c' 'SSA 2' '' 'PP_ConditionalAccess.csv'
        & $add 'PPC-03' 'Conditional Access' 'Power Platform admin sessions come from trusted admin devices' $(if ($ppAdmins.Count -eq 0) { 'Not assessed' } elseif ($dev.Count -eq $ppAdmins.Count) { 'Good' } elseif ($dev.Count) { 'Partial' } else { 'Weak' }) 'Medium' `
            "$($dev.Count) of $($ppAdmins.Count) Power Platform admins are covered by a policy requiring a compliant or hybrid-joined device." `
            'A stolen admin token used from an unmanaged device bypasses MFA entirely.' `
            'CLAD sign-ins only from compliant admin devices (PAW or managed device).' `
            'Add the device requirement to the CLAD policy once admin devices are in place.' `
            'B2.b' 'SSA 1' '' 'PP_ConditionalAccess.csv'
    }

    # =========================================================================================
    # Environments
    # =========================================================================================
    if (-not $hasPp) {
        & $add 'PPE-01' 'Environments' 'Production environments have few System Administrators' 'Not assessed' '' 'Power Platform admin APIs could not be reached; activate Power Platform Administrator and re-run.' '' '' '' 'B2.c' 'SSA 4' '' ''
    }
    else {
        $over = @($Ctx.EnvSummary | Where-Object { $_.IsProd -and [int]$_.SystemAdminPeople -gt 3 })
        $read = @($Ctx.EnvSummary | Where-Object { $_.IsProd -and $_.RolesRead })
        & $add 'PPE-01' 'Environments' 'Production environments have few System Administrators' $(if ($read.Count -eq 0) { 'Not assessed' } elseif ($over.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
            "$(& $pl $over.Count 'production environment has' 'production environments have') more than three people as System Administrator: $(@($over | ForEach-Object { "$($_.Environment) ($($_.SystemAdminPeople))" }) -join '; ')." `
            'Every System Administrator can read and change all data in the environment and grant access to others.' `
            'Three or fewer named people per production environment, ideally none standing.' `
            'Reduce to named owners; everyone else gets scoped roles.' `
            'B2.c, B2.d' 'SSA 4' '' 'PP_Environments.csv'
        $team = @($Ctx.EnvRoles | Where-Object { $_.PrincipalType -eq 'User' -and $_.IsAdminRole -and $_.AssignedVia -ne 'Direct' })
        & $add 'PPE-02' 'Environments' 'System Administrator through teams is controlled' $(if ($team.Count -eq 0) { 'Good' } else { 'Partial' }) 'Medium' `
            "$(& $pl @($team | Select-Object -ExpandProperty UserId -Unique).Count 'person is' 'people are') System Administrator through a team or group: $(& $names $team 'TeamName' 6)." `
            'Anyone added to the team or group becomes System Administrator, often without the platform owner knowing.' `
            'Group teams for admin roles are bound to PIM for Groups groups, so membership is just-in-time and reviewed.' `
            'Put these groups under PIM for Groups, or remove the role from the team.' `
            'B2.c' 'SSA 4' '' 'PP_AccessPaths.csv'
        $noSg = @($prodEnvs | Where-Object { $_.HasDataverse -and -not $_.IsDefault -and -not $_.SecurityGroupId })
        & $add 'PPE-03' 'Environments' 'Production environments are restricted by a security group' $(if ($prodEnvs.Count -eq 0) { 'Not assessed' } elseif ($noSg.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
            "$(& $pl $noSg.Count 'production environment has' 'production environments have') no security group: $(& $names $noSg 'DisplayName' 10)." `
            'Without a security group any licensed user can be added, and Dynamics 365 Administrators are not limited.' `
            'An Entra security group on every production environment.' `
            'Assign a security group to each.' `
            'B2.d' 'SSA 4' '' 'PP_Environments.csv'
        $unmanaged = @($prodEnvs | Where-Object { -not $_.Managed })
        & $add 'PPE-04' 'Environments' 'Production environments are managed environments' $(if ($prodEnvs.Count -eq 0) { 'Not assessed' } elseif ($unmanaged.Count -eq 0) { 'Good' } else { 'Partial' }) 'Low' `
            "$(& $pl $unmanaged.Count 'production environment is' 'production environments are') not a managed environment: $(& $names $unmanaged 'DisplayName' 10)." `
            'Managed environments add sharing limits, usage insights, IP firewall and solution checker enforcement.' `
            'Production environments are managed.' `
            'Enable managed environments (licensing permitting).' `
            'B2.d' '' '' 'PP_Environments.csv'
        $readProd = @($prodEnvs | Where-Object { $_.HasDataverse -and $_.DataverseAccess -like 'OK*' })
        $noAudit = @($readProd | Where-Object { [string]$_.AuditEnabled -ne 'True' })
        & $add 'PPE-05' 'Environments' 'Dataverse auditing is on in production' $(if ($readProd.Count -eq 0) { 'Not assessed' } elseif ($noAudit.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
            "$(& $pl $noAudit.Count 'production environment has' 'production environments have') Dataverse auditing off: $(& $names $noAudit 'DisplayName' 10)." `
            'Without auditing there is no record of what an administrator changed or read after elevating.' `
            'Auditing on, including user access, with retention that matches the logging standard.' `
            'Turn on auditing in each production environment.' `
            'B2.d' 'SSA 5' '' 'PP_Environments.csv'
        $apps = @($Ctx.EnvRoles | Where-Object { $_.PrincipalType -eq 'Application user' -and $_.RoleName -eq 'System Administrator' })
        $mgmt = @($Ctx.ManagementApps)
        & $add 'PPE-06' 'Environments' 'Service principals with Power Platform admin rights are known and owned' $(if (($apps.Count + $mgmt.Count) -eq 0) { 'Good' } else { 'Partial' }) 'Low' `
            "$(& $pl $apps.Count 'application user is' 'application users are') System Administrator in an environment and $(& $pl $mgmt.Count 'application is' 'applications are') registered as a Power Platform management app." `
            'Non-human identities with admin rights cannot use PIM; their credentials are the control.' `
            'Each has a named owner, certificate credential, the narrowest role and monitoring.' `
            'Record an owner for each in the workload identity review.' `
            'B2.d' 'SSA 4' '' 'PP_AccessPaths.csv'
        $gap = @($envs | Where-Object { $_.DataverseAccess -in @('NoDataverseAccess', 'Failed') })
        & $add 'PPE-07' 'Environments' 'Every environment could be read' $(if ($gap.Count -eq 0) { 'Good' } else { 'Not assessed' }) '' `
            "$(& $pl $gap.Count 'environment' 'environments') could not be read, so their System Administrators and flows are missing from this report: $(& $names $gap 'DisplayName' 10)." `
            'Coverage gap in this audit, not a weakness of the tenant.' '' 'Re-run with -ElevateForAudit, or self-elevate in the admin centre first.' '' '' '' 'PP_Environments.csv'
    }

    # =========================================================================================
    # Workloads: what breaks
    # =========================================================================================
    if ($hasPp) {
        $high = @($Ctx.FlowsAtRisk | Where-Object Severity -eq 'High')
        & $add 'PPW-01' 'Readiness for PIM' 'No active flow depends on an admin role held by a person' $(if ($high.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
            "$(& $pl $high.Count 'active flow is' 'active flows are') likely to break when owners lose standing admin rights: $(& $names $high 'FlowName' 8)." `
            'Removing standing rights without preparing these stops business processes and gives PIM a bad name.' `
            'Business flows owned by service accounts or service principals in solutions, with scoped roles; nothing relies on a person''s admin role.' `
            'Work through PP_FlowsAtRisk.csv with each owner before converting their role to eligible.' `
            'B2.d' 'SSA 4' '' 'PP_FlowsAtRisk.csv'
        $admConn = @($Ctx.Connections | Where-Object { [string]$_.IsAdminConnector -eq 'True' -and $_.OwnerType -ne 'ServicePrincipal' })
        & $add 'PPW-02' 'Readiness for PIM' 'Admin connector connections are not owned by people' $(if ($admConn.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
            "$(& $pl $admConn.Count 'admin connector connection is' 'admin connector connections are') owned by a person: $(& $names $admConn 'OwnerUserPrincipalName' 8)." `
            'An admin connector connection acts with the owner''s admin rights for anyone using the flow or app; with PIM it fails whenever the role is not active.' `
            'Governance automation (for example the CoE Starter Kit) runs as a dedicated service account or service principal, registered as an exception.' `
            'Move these to the governance service identity; delete the personal connections.' `
            'B2.c' 'SSA 4' 'Microsoft: CoE Starter Kit and PIM, issue 8119' 'PP_ConnectionsAtRisk.csv'
        $orph = @($Ctx.FlowsAtRisk | Where-Object { $_.Reason -like 'Owner account is disabled*' })
        & $add 'PPW-03' 'Readiness for PIM' 'Active flows have an active owner' $(if ($orph.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
            "$(& $pl $orph.Count 'active flow is' 'active flows are') owned by a disabled or deleted account." `
            'They run on stored connections until a token expires, then fail without warning.' `
            'Every active flow has an active owner and a co-owner.' `
            'Reassign or turn them off.' `
            'B2.d' '' '' 'PP_FlowsAtRisk.csv'
    }

    # =========================================================================================
    # Guardrails
    # =========================================================================================
    $ts = $Ctx.TenantSettings
    if ($ts) {
        $flags = @{
            Production = [string](Get-PpSetting $ts 'disableEnvironmentCreationByNonAdminUsers')
            Trial = [string](Get-PpSetting $ts 'disableTrialEnvironmentCreationByNonAdminUsers')
            Developer = [string](Get-PpSetting $ts 'disableDeveloperEnvironmentCreationByNonAdminUsers')
        }
        $open = @($flags.Keys | Where-Object { $flags[$_] -ne 'True' } | Sort-Object)
        & $add 'PPG-01' 'Guardrails' 'Only admins can create environments' $(if ($open.Count -eq 0) { 'Good' } elseif ($open.Count -lt 3) { 'Partial' } else { 'Weak' }) 'Medium' `
            $(if ($open.Count) { "Non-admins can create $($open -join ', ') environments, where they become System Administrator." } else { 'Environment creation is limited to admins.' }) `
            'Each self-created environment makes its creator a System Administrator outside any review.' `
            'Production and trial creation limited to admins; developer environments allowed only if routed through a process.' `
            'Restrict environment creation in tenant settings.' `
            'B2.d' 'SSA 3' 'Microsoft: control who can create environments' 'pp-tenant-settings.json'
    }
    if ($hasPp) {
        $dlp = @($Ctx.Dlp)
        $all = @($dlp | Where-Object { $_.Scope -match 'AllEnvironments|ExceptEnvironments' })
        & $add 'PPG-02' 'Guardrails' 'A DLP policy covers every environment' $(if ($all.Count -gt 0) { 'Good' } elseif ($dlp.Count) { 'Partial' } else { 'Weak' }) 'Medium' `
            "$(& $pl $dlp.Count 'DLP policy exists' 'DLP policies exist'); $(& $pl $all.Count 'applies' 'apply') tenant-wide." `
            'Without a tenant-wide policy a new environment has no connector controls, including on admin connectors.' `
            'A tenant-wide baseline policy, with stricter policies for production.' `
            'Create a tenant-wide baseline DLP policy.' `
            'B2.d' '' '' 'PP_Dlp.csv'
    }
    $rb = @($Ctx.PpRbac | Where-Object { $_.PrincipalType -eq 'User' })
    if (@($Ctx.PpRbac).Count -gt 0) {
        & $add 'PPG-03' 'Guardrails' 'Power Platform RBAC is not used to give people standing admin rights' $(if ($rb.Count -eq 0) { 'Good' } else { 'Partial' }) 'Medium' `
            "$(& $pl $rb.Count 'Power Platform RBAC assignment is' 'Power Platform RBAC assignments are') made to people." `
            'Power Platform RBAC roles sit outside Entra and PIM, so they are a parallel, permanent route to admin rights.' `
            'People use the Entra role through PIM; Power Platform RBAC only for service principals.' `
            'Remove people from Power Platform RBAC roles.' `
            'B2.c' 'SSA 4' '' 'PP_AccessPaths.csv'
    }

    # =========================================================================================
    # Roll-ups (same rules as the Entra/Azure audit)
    # =========================================================================================
    $rate = {
        param([object[]]$Items)
        $assessed = @($Items | Where-Object { $_.Result -ne 'Not assessed' })
        if ($assessed.Count -eq 0) { return 'Not assessed' }
        if (@($assessed | Where-Object { $_.Result -eq 'Weak' -and $_.Severity -in @('Critical', 'High') }).Count -gt 0) { return 'Not achieved' }
        if (@($assessed | Where-Object { $_.Result -in @('Weak', 'Partial') }).Count -gt 0) { return 'Partially achieved' }
        return 'Achieved'
    }
    $caf = @(
        @{ Id = 'B2.a'; Title = 'Identity verification, authentication and authorisation'; Outcome = 'Access is robustly verified, authenticated and authorised, and limited to the minimum necessary.' },
        @{ Id = 'B2.b'; Title = 'Device management'; Outcome = 'Devices used for access, especially for privileged operations, are known and trusted.' },
        @{ Id = 'B2.c'; Title = 'Privileged user management'; Outcome = 'Privileged user access is closely managed: dedicated accounts, MFA, time-bound rights and regular review.' },
        @{ Id = 'B2.d'; Title = 'Identity and access management'; Outcome = 'Access rights are kept to the minimum, reviewed, and removed when no longer needed.' }
    )
    $cafRows = foreach ($c in $caf) {
        $items = @($controls | Where-Object { ([string]$_.CafOutcome).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -eq $c.Id } })
        [pscustomobject]@{ Outcome = $c.Id; Title = $c.Title; WhatTheOutcomeMeans = $c.Outcome; Rating = & $rate $items
            Good = @($items | Where-Object Result -eq 'Good').Count; Partial = @($items | Where-Object Result -eq 'Partial').Count; Weak = @($items | Where-Object Result -eq 'Weak').Count
            Controls = (@($items | ForEach-Object { $_.Id }) -join ', ') }
    }
    $ssa = @(
        @{ Id = 'SSA 1'; Title = 'Gain trust in your management devices' }, @{ Id = 'SSA 2'; Title = 'Protect your administration interfaces' },
        @{ Id = 'SSA 3'; Title = 'Risk manage administration using tiers' }, @{ Id = 'SSA 4'; Title = 'Use privileged access management' },
        @{ Id = 'SSA 5'; Title = 'Log and audit administration activities' }
    )
    $ssaRows = foreach ($s in $ssa) {
        $items = @($controls | Where-Object { $_.NcscPrinciple -eq $s.Id })
        $r = & $rate $items
        $label = switch ($r) { 'Achieved' { 'Strong' } 'Partially achieved' { 'Partly in place' } 'Not achieved' { 'Weak' } default { 'Not assessed' } }
        [pscustomobject]@{ Principle = $s.Id; Title = $s.Title; Rating = $label; Good = @($items | Where-Object Result -eq 'Good').Count; Partial = @($items | Where-Object Result -eq 'Partial').Count; Weak = @($items | Where-Object Result -eq 'Weak').Count; Controls = (@($items | ForEach-Object { $_.Id }) -join ', ') }
    }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; '' = 4 }
    return [pscustomobject]@{
        Controls = @($controls); Caf = @($cafRows); Ssa = @($ssaRows)
        Strengths = @($controls | Where-Object Result -eq 'Good')
        Weaknesses = @($controls | Where-Object { $_.Result -in @('Weak', 'Partial') } | Sort-Object @{ Expression = { if ($_.Result -eq 'Weak') { 0 } else { 1 } } }, @{ Expression = { $sevRank[[string]$_.Severity] } })
    }
}

function Get-PpSetting {
    # Finds a tenant setting by name anywhere in the listTenantSettings response.
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [string] -or $Obj -is [ValueType]) { return $null }
    foreach ($p in $Obj.PSObject.Properties) {
        if ($p.Name -eq $Name) { return $p.Value }
        if ($p.Value -and -not ($p.Value -is [string]) -and -not ($p.Value -is [ValueType])) {
            $v = Get-PpSetting $p.Value $Name
            if ($null -ne $v) { return $v }
        }
    }
    return $null
}
