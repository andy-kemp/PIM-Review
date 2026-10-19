<#
.SYNOPSIS
Control checks for the privileged access audit, benchmarked against the NCSC Cyber Assessment Framework
(CAF 4.0, Principle B2 Identity and Access Control), the NCSC secure system administration principles and
Microsoft guidance. Function definitions only; dot-sourced by Invoke-PimPhase2Assessment.ps1.

.DESCRIPTION
Each control returns a plain-English result: Good, Partial, Weak or Not assessed, with what was found,
why it matters, what good looks like and the recommended action. Controls are then rolled up to an
indicative CAF rating per contributing outcome (B2.a-B2.d) and to the five NCSC secure system
administration principles. Ratings use configuration evidence only; a full CAF assessment also needs
process evidence (joiners/movers/leavers, review records, monitoring), so they are indicative.
#>

function Get-PimAuditPercent {
    param([double]$Part, [double]$Whole)
    if ($Whole -le 0) { return $null }
    return [int][Math]::Round(($Part / $Whole) * 100, 0)
}

function Get-PimAuditControls {
    [CmdletBinding()]
    param([hashtable]$Ctx)

    $humanTypes = @('CLAD', 'Other admin account', 'Everyday', 'Guest', 'Generic/Service')
    $privPaths = @($Ctx.PrivPaths)
    $human = @($privPaths | Where-Object { $_.AccountType -in $humanTypes })
    $entraHuman = @($human | Where-Object Plane -eq 'Entra')
    $azureHuman = @($human | Where-Object { $_.Plane -eq 'Azure' -and $_.AzureFamily -ne 'Reader' })
    $identities = @($Ctx.Identities)
    $policyByRole = $Ctx.PolicyByRole
    $baselines = $Ctx.Catalogue.TrustLevelBaselines
    $peopleOf = { param($Rows) @($Rows | Select-Object -ExpandProperty Person -Unique) }
    $hasEntra = [bool]$Ctx.HasEntra
    $hasAzure = [bool]$Ctx.HasAzure

    # Short wording of each control when it is not met, used in the summary verdict.
    $gapText = @{
        'ADM-01' = 'too many people can become Global Administrator'; 'ADM-02' = 'Global Administrator is held permanently'; 'ADM-03' = 'no break-glass accounts were found'
        'PIM-01' = 'some TL1 Entra access is permanent'; 'PIM-02' = 'many Entra admin roles are held permanently'; 'PIM-03' = 'Azure write access is mostly permanent (no PIM)'
        'PIM-04' = 'TL1 roles are bundled with routine roles in the same groups'; 'PIM-05' = 'some TL1 roles activate without approval'; 'PIM-06' = 'people can approve their own elevation'
        'PIM-07' = 'some TL1 activations last too long'; 'PIM-08' = 'some admin roles activate without MFA'; 'PIM-09' = 'some activations need no justification'
        'PIM-10' = 'TL1 activation does not enforce phishing-resistant sign-in'; 'PIM-11' = 'eligibility never expires'
        'ID-01' = 'everyday and guest accounts hold admin rights'; 'ID-02' = 'admin accounts have email and Office licences'; 'ID-03' = 'few TL1 admins use phishing-resistant MFA'
        'ID-04' = 'no Conditional Access MFA policy targets admin roles'; 'ID-05' = 'shared and service user accounts hold admin rights'; 'ID-06' = 'supplier and guest admin access is permanent'
        'ID-07' = 'disabled accounts still hold access'; 'ID-08' = 'some assignments belong to deleted identities'; 'DEV-01' = 'admin access is not limited to trusted admin devices'
        'GOV-01' = 'privileged access is not reviewed regularly'; 'GOV-02' = 'some privileged users are not licensed for PIM'
        'AZ-01' = 'subscriptions have more than three owners'; 'AZ-02' = 'TL1 Azure access is held permanently'; 'AZ-03' = 'there is access at the root management group'; 'AZ-04' = 'other organisations have permanent write access to Azure through Lighthouse'; 'ADM-04' = 'Global Administrator is granted through groups'; 'WL-01' = 'automation accounts hold TL1 rights'
    }
    $controls = New-Object System.Collections.ArrayList
    $add = {
        param([string]$Id, [string]$Area, [string]$Title, [string]$Result, [string]$Severity, [string]$Finding, [string]$Why, [string]$Good, [string]$Action, [string]$Caf, [string]$Ssa, [string]$Reference, [string]$Evidence)
        if ($Result -eq 'Good' -or $Result -eq 'Not assessed') { $Severity = '' }
        $null = $controls.Add([pscustomobject]@{
            Id = $Id; Area = $Area; Control = $Title; Gap = $gapText[$Id]; Result = $Result; Severity = $Severity
            Finding = $Finding; WhyItMatters = $Why; WhatGoodLooksLike = $Good; RecommendedAction = $Action
            CafOutcome = $Caf; NcscPrinciple = $Ssa; Reference = $Reference; Evidence = $Evidence
        })
    }
    $pl = { param($n, $one, $many) if ([int]$n -eq 1) { "$n $one" } else { "$n $many" } }

    # ---- Role policies of TL1 / TL2 roles in use -------------------------------------------------
    $rolePolicies = New-Object System.Collections.ArrayList
    foreach ($r in @($Ctx.Catalogue_InUse | Where-Object { $_.Plane -eq 'Entra' -and $_.TrustLevel -in @('TL1', 'TL2') })) {
        $k = ([string]$r.Role).ToLowerInvariant()
        if ($policyByRole -and $policyByRole.ContainsKey($k)) { $null = $rolePolicies.Add([pscustomobject]@{ Role = $r.Role; TrustLevel = $r.TrustLevel; Policy = $policyByRole[$k] }) }
    }
    $tl1Policies = @($rolePolicies | Where-Object TrustLevel -eq 'TL1')

    # =========================================================================================
    # Administrator population and emergency access
    # =========================================================================================
    $gaPeople = @($Ctx.GaPeople)
    if ($hasEntra) {
        $n = $gaPeople.Count
        $res = if ($n -lt 5) { 'Good' } else { 'Weak' }
        $sev = if ($n -ge 10) { 'High' } else { 'Medium' }
        & $add 'ADM-01' 'Administrator population' 'Global Administrator is limited to a small number of people' $res $sev `
            "$(& $pl $n 'person can' 'people can') become Global Administrator, directly or by activating a group (break-glass accounts excluded)." `
            'Global Administrator controls the whole tenant, every Microsoft 365 service and, by elevation, every Azure subscription. Each extra holder is another account an attacker can phish to take over everything.' `
            'Fewer than five named people, each with a documented need, plus two break-glass accounts.' `
            'Agree the justified Global Administrator population with the partner and remove eligibility from everyone else. Move day-to-day tasks to narrower roles (for example User, Groups, Exchange or Security Administrator).' `
            'B2.a, B2.c' 'SSA 4' 'Microsoft: limit Global Administrators to fewer than five' 'P2_TL1Paths.csv'
    }

    $standingGa = @($entraHuman | Where-Object { $_.Role -eq 'Global Administrator' -and $_.Standing })
    if ($hasEntra) {
        $n = @(& $peopleOf $standingGa).Count
        & $add 'ADM-02' 'Administrator population' 'Nobody holds Global Administrator permanently (other than break-glass)' $(if ($n -eq 0) { 'Good' } else { 'Weak' }) 'Critical' `
            $(if ($n -eq 0) { 'No named person holds Global Administrator permanently; every human route needs activation.' } else { "$(& $pl $n 'person holds' 'people hold') Global Administrator permanently, with no activation step." }) `
            'Permanent Global Administrator is always on, so a stolen session or token gives immediate control of the tenant.' `
            'Only the two break-glass accounts hold Global Administrator permanently; everyone else is eligible and activates when needed.' `
            'Convert permanent Global Administrator assignments to eligible in PIM.' `
            'B2.c' 'SSA 4' 'Microsoft: use PIM for just-in-time access' 'P2_StandingAccess.csv'
    }

    $gaHuman = @($entraHuman | Where-Object { $_.Role -eq 'Global Administrator' })
    if ($hasEntra -and $gaHuman.Count -gt 0) {
        $viaGroup = @($gaHuman | Where-Object { $_.PathType -ne 'Direct' })
        $groups = @($viaGroup | Where-Object ViaGroup | Select-Object -ExpandProperty ViaGroup -Unique)
        & $add 'ADM-04' 'Administrator population' 'Global Administrator is only assigned directly to named admin accounts, never through a group' $(if ($viaGroup.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
            $(if ($viaGroup.Count -eq 0) { 'Every route to Global Administrator is a direct assignment to a named account.' } else { "$(& $pl @(& $peopleOf $viaGroup).Count 'person reaches' 'people reach') Global Administrator through $(& $pl $groups.Count 'group' 'groups') ($($groups -join ', ')) rather than a direct assignment." }) `
            'Through a group, Global Administrator is granted by group membership: whoever manages the group decides who becomes Global Administrator, the role cannot have its own settings or review, and one activation brings every other role in the group with it.' `
            'Global Administrator assigned directly, as eligible, to each named CLAD in the agreed population, with its own approval, activation and review settings. No group holds Global Administrator.' `
            'Remove Global Administrator from the groups and assign it directly (eligible) to the agreed named CLADs only.' `
            'B2.c' 'SSA 3' 'HLD 7.6.1: TL1 roles assigned directly as eligible' 'P2_TL1Paths.csv'
    }

    $bg = @($identities | Where-Object AccountType -eq 'BreakGlass')
    if ($hasEntra) {
        $res = if ($bg.Count -eq 2) { 'Good' } elseif ($bg.Count -eq 0) { 'Weak' } else { 'Partial' }
        & $add 'ADM-03' 'Administrator population' 'Emergency (break-glass) access accounts exist' $res $(if ($bg.Count -eq 0) { 'High' } else { 'Low' }) `
            $(if ($bg.Count -eq 0) { 'No break-glass accounts were recognised from the naming rules. If they exist under other names, add them to the catalogue.' } else { "$(& $pl $bg.Count 'break-glass account was' 'break-glass accounts were') found: $(@($bg | Select-Object -ExpandProperty Identity) -join ', ')." }) `
            'Without emergency accounts, a Conditional Access mistake or an identity provider outage can lock every administrator out.' `
            'Two cloud-only emergency accounts with permanent Global Administrator, phishing-resistant credentials held securely, excluded only where necessary from Conditional Access, and sign-ins alerted.' `
            'Confirm the accounts are cloud-only, tested regularly and that any sign-in raises an alert.' `
            'B2.c' 'SSA 4' 'Microsoft: emergency access account recommendations' 'P2_PrivilegedIdentities.csv'
    }

    # =========================================================================================
    # Just-in-time access (PIM)
    # =========================================================================================
    if ($hasEntra) {
        $t1 = @($entraHuman | Where-Object TrustLevel -eq 'TL1')
        $elig = @($t1 | Where-Object EffectiveState -eq 'Eligible').Count
        $pct = Get-PimAuditPercent $elig $t1.Count
        $res = if ($null -eq $pct -or $pct -ge 95) { 'Good' } elseif ($pct -ge 70) { 'Partial' } else { 'Weak' }
        & $add 'PIM-01' 'Just-in-time access' 'TL1 (Strategic Control) Entra roles are only available just-in-time' $res 'High' `
            "$pct% of routes to TL1 Entra roles need activation in PIM ($elig of $($t1.Count)); the rest are always on." `
            'TL1 roles can take over the tenant. Standing access means the privilege is exposed all the time, not just when someone is working.' `
            'All TL1 access is eligible and time-bound; nobody except break-glass holds it permanently.' `
            'Convert the remaining permanent TL1 routes to eligible, starting with those held through groups (see Standing access).' `
            'B2.c' 'SSA 4' 'NCSC CAF B2.c: temporary, time-bound privileged rights' 'P2_StandingAccess.csv'

        $all = $entraHuman
        $elig = @($all | Where-Object EffectiveState -eq 'Eligible').Count
        $pct = Get-PimAuditPercent $elig $all.Count
        $res = if ($null -eq $pct -or $pct -ge 90) { 'Good' } elseif ($pct -ge 60) { 'Partial' } else { 'Weak' }
        & $add 'PIM-02' 'Just-in-time access' 'Entra admin roles generally use PIM rather than permanent assignment' $res 'Medium' `
            "$pct% of all privileged Entra routes (TL1-TL3) need activation ($elig of $($all.Count))." `
            'Permanent admin roles widen the window in which a compromised account can be misused.' `
            'Eligible assignments for all privileged roles, with permanent active assignment kept for break-glass and documented exceptions.' `
            'Work through P2_MigrationWorksheet.csv and convert permanent assignments to eligible.' `
            'B2.d' 'SSA 4' '' 'P2_AccessPaths.csv'
    }

    if ($hasAzure) {
        $elig = @($azureHuman | Where-Object EffectiveState -eq 'Eligible').Count
        $pct = Get-PimAuditPercent $elig $azureHuman.Count
        $res = if ($azureHuman.Count -eq 0 -or $pct -ge 90) { 'Good' } elseif ($pct -ge 50) { 'Partial' } else { 'Weak' }
        $finding = if ($azureHuman.Count -eq 0) { 'No people hold privileged (write-capable) Azure roles.' }
                   elseif ($elig -eq 0) { "PIM for Azure resources is not in use: all $($azureHuman.Count) privileged Azure routes held by people are permanent." }
                   else { "$pct% of privileged Azure routes held by people need activation ($elig of $($azureHuman.Count))." }
        & $add 'PIM-03' 'Just-in-time access' 'Azure write access uses PIM' $res 'High' $finding `
            'Owner, Contributor and data-plane roles in Azure can change or delete workloads, read secrets and grant access. Held permanently, they are always available to anyone who compromises the account.' `
            'Privileged Azure roles are eligible through PIM for Azure resources at the narrowest scope, with read-only roles left permanent where appropriate.' `
            'Enable PIM for Azure resources at management group or subscription level, starting with Owner, User Access Administrator and Contributor at subscription scope and above.' `
            'B2.c' 'SSA 4' 'NCSC CAF B2.c; Microsoft: no standing access for privileged Azure roles' 'P2_AccessPaths.csv (Plane = Azure)'
    }
    else {
        & $add 'PIM-03' 'Just-in-time access' 'Azure write access uses PIM' 'Not assessed' '' 'No Azure review was supplied for this tenant.' '' '' 'Run the audit with Azure included.' 'B2.c' 'SSA 4' '' ''
    }

    if ($hasEntra) {
        $bundles = @($Ctx.Tl1InBundles)
        & $add 'PIM-04' 'Just-in-time access' 'TL1 roles are not bundled with everyday admin roles' $(if ($bundles.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
            $(if ($bundles.Count -eq 0) { 'No group hands out a TL1 role together with other roles.' } else { "$(& $pl $bundles.Count 'group gives' 'groups give') TL1 roles together with other roles, so one activation grants TL1 alongside routine roles. Largest: $(@($bundles | Sort-Object Roles -Descending | Select-Object -First 1 | ForEach-Object { "$($_.Group) ($($_.Roles) roles)" }) -join '')." }) `
            'When Global Administrator or similar sits in the same group as routine roles, people activate TL1 for everyday tasks, and the role cannot be governed on its own.' `
            'TL1 roles assigned directly as eligible, or through a single-purpose group, with their own approval and activation settings.' `
            'Move TL1 roles out of the operational groups listed in Group bundles.' `
            'B2.c' 'SSA 3' 'NCSC: risk manage administration using tiers' 'P2_GroupBundles.csv'

        if ($tl1Policies.Count -gt 0) {
            $withAppr = @($tl1Policies | Where-Object { $_.Policy.ApprovalRequired -eq $true }).Count
            $res = if ($withAppr -eq $tl1Policies.Count) { 'Good' } elseif ($withAppr -gt 0) { 'Partial' } else { 'Weak' }
            & $add 'PIM-05' 'Activation controls' 'Activating a TL1 role needs approval' $res 'High' `
                "$withAppr of $($tl1Policies.Count) TL1 roles in use require approval to activate." `
                'Approval is the check that a second person agrees TL1 access is needed now.' `
                'Every TL1 role requires approval from an independent approver group.' `
                'Turn on approval for the remaining TL1 roles (see PIM settings).' `
                'B2.c' 'SSA 4' '' 'P2_PolicyGaps.csv'
        }

        $sa = @($Ctx.SelfApprovalPeople); $saT1 = @($Ctx.SelfApprovalTl1People); $ae = @($Ctx.ApproverEveryday)
        $res = if ($sa.Count -eq 0 -and $ae.Count -eq 0) { 'Good' } else { 'Weak' }
        $sev = if ($saT1.Count -gt 0) { 'Critical' } else { 'High' }
        & $add 'PIM-06' 'Activation controls' 'Approvers are independent of the people they approve' $res $sev `
            $(if ($res -eq 'Good') { 'No person can approve their own elevation, and approver groups hold admin identities only.' } else { "$(& $pl $sa.Count 'person' 'people') can request elevation with one account and approve it with another ($($saT1.Count) for TL1 roles). $(& $pl $ae.Count 'approver group contains' 'approver groups contain') everyday or guest accounts." }) `
            'PIM only stops the same account approving its own request. If a person''s everyday account is an approver for the role their admin account requests, the approval is a formality and gives no assurance.' `
            'Approver groups contain admin (CLAD) identities only, and nobody approves a role they can request themselves.' `
            'Rebuild the approver groups from admin identities of people who are not eligible for the roles they approve, and remove everyday accounts.' `
            'B2.c' 'SSA 4' 'NCSC CAF B2.c: privileged individuals are known and managed' 'P2_SelfApproval.csv, P2_ApproverGroups.csv'

        if ($tl1Policies.Count -gt 0) {
            $maxH = [double]$baselines.TL1.MaxActivationHours
            $over = @($tl1Policies | Where-Object { $_.Policy.MaxActivationHours -and $_.Policy.MaxActivationHours -gt $maxH })
            & $add 'PIM-07' 'Activation controls' "TL1 activations are short (no more than $maxH hours)" $(if ($over.Count -eq 0) { 'Good' } else { 'Partial' }) 'Medium' `
                $(if ($over.Count -eq 0) { "All $($tl1Policies.Count) TL1 roles limit activation to $maxH hours or less." } else { "$(& $pl $over.Count 'TL1 role allows' 'TL1 roles allow') activation for longer than $maxH hours: $(@($over | ForEach-Object { "$($_.Role) ($($_.Policy.MaxActivationHours)h)" } | Select-Object -First 6) -join ', ')." }) `
                'The longer an activation lasts, the longer the privilege is exposed after the task is finished.' `
                "TL1 activation of $maxH hours or less, TL2 four hours, TL3 eight hours." `
                'Reduce the maximum activation duration on the roles listed.' `
                'B2.c' 'SSA 4' '' 'P2_PolicyGaps.csv'
        }

        if ($rolePolicies.Count -gt 0) {
            $noMfa = @($rolePolicies | Where-Object { -not $_.Policy.MfaRequired -and -not $_.Policy.AuthContext })
            & $add 'PIM-08' 'Activation controls' 'Activating an admin role needs MFA' $(if ($noMfa.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
                $(if ($noMfa.Count -eq 0) { "All $($rolePolicies.Count) TL1 and TL2 roles in use require MFA or an authentication context on activation." } else { "$(& $pl $noMfa.Count 'TL1/TL2 role does' 'TL1/TL2 roles do') not require MFA on activation: $(@($noMfa | Select-Object -ExpandProperty Role -First 6) -join ', ')." }) `
                'MFA at activation stops an attacker using a stolen session to elevate.' `
                'Every privileged role requires MFA (and for TL1 an authentication context requiring a FIDO2 key) on activation.' `
                'Turn on MFA on activation for the roles listed.' `
                'B2.a, B2.c' 'SSA 2' 'NCSC CAF B2.c: MFA for all privileged access' 'P2_PolicyGaps.csv'

            $noJust = @($rolePolicies | Where-Object { $_.Policy.Justification -eq $false })
            & $add 'PIM-09' 'Activation controls' 'Activations record a justification' $(if ($noJust.Count -eq 0) { 'Good' } else { 'Partial' }) 'Low' `
                $(if ($noJust.Count -eq 0) { "All $($rolePolicies.Count) TL1 and TL2 roles in use require a justification on activation." } else { "$(& $pl $noJust.Count 'TL1/TL2 role does' 'TL1/TL2 roles do') not ask for a justification." }) `
                'A recorded reason links each elevation to a task and makes review and investigation possible.' `
                'Justification (and a ticket number for TL1) on every activation.' `
                'Require justification on the roles listed.' `
                'B2.c' 'SSA 5' '' 'P2_PolicyGaps.csv'
        }

        if ($tl1Policies.Count -gt 0) {
            $ctx1 = @($tl1Policies | Where-Object { $_.Policy.AuthContext }).Count
            $res = if ($ctx1 -eq $tl1Policies.Count) { 'Good' } elseif ($ctx1 -gt 0) { 'Partial' } else { 'Partial' }
            & $add 'PIM-10' 'Activation controls' 'TL1 activation enforces phishing-resistant sign-in (authentication context)' $res 'Medium' `
                "$ctx1 of $($tl1Policies.Count) TL1 roles bind activation to a Conditional Access authentication context." `
                'An authentication context lets Conditional Access demand phishing-resistant MFA and a managed device at the moment of elevation, not just at sign-in.' `
                'Every TL1 role uses an authentication context that requires phishing-resistant MFA and a compliant privileged device.' `
                'Create the TL1 authentication context and Conditional Access policy, then bind it to each TL1 role.' `
                'B2.a, B2.c' 'SSA 2' 'NCSC CAF B2.a: authentication follows up-to-date best practice' 'P2_PolicyGaps.csv'
        }

        if ($rolePolicies.Count -gt 0) {
            $permElig = @($rolePolicies | Where-Object { $_.Policy.PermanentEligible -eq $true })
            $noEnd = @($entraHuman | Where-Object { $_.EffectiveState -eq 'Eligible' -and [string]::IsNullOrWhiteSpace([string]$_.EndDateTime) }).Count
            $eligTotal = @($entraHuman | Where-Object EffectiveState -eq 'Eligible').Count
            & $add 'PIM-11' 'Access lifecycle' 'Eligibility expires and has to be renewed' $(if ($permElig.Count -eq 0) { 'Good' } else { 'Partial' }) 'Medium' `
                "$(& $pl $permElig.Count 'TL1/TL2 role allows' 'TL1/TL2 roles allow') permanent eligibility; $noEnd of $eligTotal eligible routes have no end date." `
                'Eligibility that never expires stays in place after people change role, so access builds up over time.' `
                'Eligibility ends after the review period for its trust level (3 months TL1, 6 months TL2, 12 months TL3) and is renewed only after review.' `
                'Require an expiry on eligible assignments for TL1 and TL2 roles.' `
                'B2.d' 'SSA 4' 'NCSC CAF B2.d: rights reviewed and revoked when no longer needed' 'P2_PolicyGaps.csv'
        }
    }

    # =========================================================================================
    # Admin identities
    # =========================================================================================
    $humanIds = @($identities | Where-Object { $_.AccountType -in $humanTypes })
    if ($humanIds.Count -gt 0) {
        $everydayHigh = @($humanIds | Where-Object { $_.AccountType -in @('Everyday', 'Guest') -and $_.HighestTrustLevel -in @('TL1', 'TL2') })
        $everydayT1 = @($everydayHigh | Where-Object HighestTrustLevel -eq 'TL1')
        $clad = @($humanIds | Where-Object { $_.AccountType -in @('CLAD', 'Other admin account') })
        $res = if ($everydayHigh.Count -eq 0) { 'Good' } else { 'Weak' }
        & $add 'ID-01' 'Admin identities' 'Admin rights are held by separate admin accounts, not everyday accounts' $res $(if ($everydayT1.Count -gt 0) { 'High' } else { 'Medium' }) `
            $(if ($res -eq 'Good') { "All TL1 and TL2 access is held by dedicated admin accounts ($($clad.Count) in use)." } else { $cr = @($Ctx.CladRows); "$($clad.Count) dedicated admin accounts are in use, but $(& $pl $everydayHigh.Count 'everyday or guest account holds' 'everyday or guest accounts hold') TL1/TL2 access ($($everydayT1.Count) at TL1). Across all levels, $(@($cr | Where-Object { $_.Action -like '*existing CLAD*' }).Count) of these people already have a CLAD and $(@($cr | Where-Object { $_.Action -like '*create CLAD*' }).Count) need one (P2_CladProvisioning.csv)." }) `
            'Everyday accounts read email and browse the web, so they are the accounts most likely to be phished. Admin rights on them put privilege one click away from an attacker.' `
            'Privileged roles held only by dedicated, cloud-only admin accounts that are not used for email or browsing.' `
            'Give every person who does admin work a CLAD (clad_<surname><initial>, display name "(Cloud Admin) First Last"), move their rights to it and remove all admin rights and approver membership from everyday and guest accounts.' `
            'B2.c' 'SSA 3' 'NCSC CAF B2.c: dedicated, separate privileged accounts' 'P2_PrivilegedIdentities.csv'

        $withLicence = @($clad | Where-Object { $_.Issues -match 'productivity licence' })
        $licKnown = @($clad | Where-Object { $null -ne $_.HasP2Licence -and [string]$_.HasP2Licence -ne '' }).Count
        if ($licKnown -gt 0) {
            & $add 'ID-02' 'Admin identities' 'Admin accounts are not used for email and productivity' $(if ($withLicence.Count -eq 0) { 'Good' } else { 'Partial' }) 'Medium' `
                $(if ($withLicence.Count -eq 0) { 'No admin account has a productivity (mailbox / Office) licence.' } else { "$(& $pl $withLicence.Count 'admin account has' 'admin accounts have') a productivity licence, so may be used for email or Office." }) `
                'Admin accounts with a mailbox can receive phishing and are used outside admin tasks.' `
                'Admin accounts licensed for Entra ID P2 / governance only, with no mailbox.' `
                'Remove productivity licences from admin accounts.' `
                'B2.c' 'SSA 3' 'NCSC CAF B2.c: roles logically separated (e.g. email and privileged actions)' 'P2_PrivilegedIdentities.csv'
        }

        $t1Ids = @($humanIds | Where-Object HighestTrustLevel -eq 'TL1')
        $prKnown = @($t1Ids | Where-Object { [string]$_.PhishingResistant -in @('True', 'False') -or $_.PhishingResistant -is [bool] })
        if ($prKnown.Count -gt 0) {
            $pr = @($prKnown | Where-Object { [string]$_.PhishingResistant -eq 'True' }).Count
            $pct = Get-PimAuditPercent $pr $prKnown.Count
            $res = if ($pct -ge 90) { 'Good' } elseif ($pct -ge 50) { 'Partial' } else { 'Weak' }
            & $add 'ID-03' 'Admin identities' 'TL1 admins use phishing-resistant MFA' $res 'High' `
                "$pct% of identities that can reach TL1 have a phishing-resistant method registered ($pr of $($prKnown.Count))." `
                'Push and SMS MFA can be phished or fatigued; phishing-resistant methods (FIDO2 keys, passkeys, Windows Hello, certificate) cannot be relayed.' `
                'All TL1 identities use FIDO2 / passkeys, enforced by an authentication strength.' `
                'Issue FIDO2 keys or passkeys to TL1 admins and enforce them with an authentication strength.' `
                'B2.a, B2.c' 'SSA 2' 'NCSC CAF B2.a: authentication follows up-to-date best practice' 'P2_PrivilegedIdentities.csv'
        }
        else {
            & $add 'ID-03' 'Admin identities' 'TL1 admins use phishing-resistant MFA' 'Not assessed' '' 'Authentication method registration was not available.' '' '' 'Re-run with authentication strength collection.' 'B2.a, B2.c' 'SSA 2' '' ''
        }

        $generic = @($humanIds | Where-Object AccountType -eq 'Generic/Service')
        & $add 'ID-05' 'Admin identities' 'No shared, generic or service user accounts hold admin rights' $(if ($generic.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
            $(if ($generic.Count -eq 0) { 'No generic or shared user accounts hold privileged roles.' } else { "$(& $pl $generic.Count 'generic or service user account holds' 'generic or service user accounts hold') privileged access: $(@($generic | Select-Object -ExpandProperty Identity -First 6) -join ', ')." }) `
            'Shared accounts cannot be tied to a person, usually have static passwords and often sit outside MFA, so their use cannot be attributed or controlled.' `
            'Named admin accounts for people; workload identities (managed identities, service principals) for automation.' `
            'Replace each account with a named account or a workload identity, or record an exception with compensating controls.' `
            'B2.c' 'SSA 4' 'NCSC CAF B2.c: generic, shared or default accounts is a Not achieved indicator' 'P2_ExceptionCandidates.csv'

        $third = @($human | Where-Object { $_.PersonOrganisationType -eq 'Supplier' -or $_.AccountType -eq 'Guest' })
        if ($third.Count -gt 0) {
            $tb = @($third | Where-Object { $_.EffectiveState -eq 'Eligible' -or -not [string]::IsNullOrWhiteSpace([string]$_.EndDateTime) }).Count
            $pct = Get-PimAuditPercent $tb $third.Count
            $res = if ($pct -ge 95) { 'Good' } elseif ($pct -ge 50) { 'Partial' } else { 'Weak' }
            & $add 'ID-06' 'Admin identities' 'Supplier and guest admin access is time-bound' $res 'High' `
                "$pct% of privileged routes held by suppliers and guests are eligible or have an end date ($tb of $($third.Count)), across $(@(& $peopleOf $third).Count) people." `
                'Third-party accounts are managed outside your joiners and leavers process; standing access remains after a contract or person changes.' `
                'Third-party access is eligible, approved, and ends with the contract or engagement.' `
                'Make supplier and guest access eligible with an end date tied to the contract, and give each a named sponsor.' `
                'B2.c' 'SSA 4' 'NCSC CAF B2.c: temporary, time-bound rights for third-party support' 'P2_MigrationWorksheet.csv'
        }

        $disabled = @($identities | Where-Object { [string]$_.AccountEnabled -eq 'False' })
        & $add 'ID-07' 'Access lifecycle' 'Disabled accounts hold no access' $(if ($disabled.Count -eq 0) { 'Good' } else { 'Weak' }) 'Medium' `
            $(if ($disabled.Count -eq 0) { 'No disabled account still holds a privileged role.' } else { "$(& $pl $disabled.Count 'disabled account still holds' 'disabled accounts still hold') privileged access." }) `
            'Access left on disabled accounts is restored the moment the account is re-enabled, deliberately or by mistake.' `
            'Leaver process removes role assignments, not just the sign-in.' `
            'Remove the assignments and add role removal to the leaver process.' `
            'B2.a, B2.d' 'SSA 4' 'NCSC CAF B2.d: rights do not stay active after users leave' 'P2_PrivilegedIdentities.csv'

        $deleted = @($identities | Where-Object AccountType -eq 'Deleted identity')
        $unres = @($identities | Where-Object AccountType -eq 'Unresolved')
        $parts = @()
        if ($deleted.Count -gt 0) { $parts += "$(& $pl $deleted.Count 'deleted identity still holds' 'deleted identities still hold') privileged Azure role assignments" }
        if ($unres.Count -gt 0) { $parts += "$(& $pl $unres.Count 'assignment holder' 'assignment holders') could not be read" }
        & $add 'ID-08' 'Access lifecycle' 'Role assignments are removed when an identity is deleted' $(if ($deleted.Count + $unres.Count -eq 0) { 'Good' } else { 'Partial' }) 'Low' `
            $(if ($parts.Count -eq 0) { 'Every assignment belongs to a current user, group or workload identity.' } else { ($parts -join '; ') + '.' }) `
            'Orphaned assignments show that removal is not part of the leaver or decommissioning process. They clutter reviews and hide real access.' `
            'Assignments are removed when the identity is deleted.' `
            'Remove the orphaned assignments (listed in P2_PrivilegedIdentities.csv as Deleted identity) and add assignment clean-up to decommissioning.' `
            'B2.a, B2.d' 'SSA 4' '' 'P2_PrivilegedIdentities.csv'
    }

    # Conditional Access: MFA and managed devices for admins.
    if ($hasEntra) {
        $ca = @($Ctx.CaPolicies | Where-Object { $_.State -eq 'enabled' })
        $caAdminMfa = @($ca | Where-Object { $_.IncludeRoleIds -and [string]$_.GrantControls -match 'mfa|authenticationStrength' })
        & $add 'ID-04' 'Admin identities' 'Conditional Access requires MFA for admin roles' $(if ($caAdminMfa.Count -gt 0) { 'Good' } else { 'Weak' }) 'High' `
            $(if ($caAdminMfa.Count -gt 0) { "$(& $pl $caAdminMfa.Count 'enabled Conditional Access policy requires' 'enabled Conditional Access policies require') MFA for directory roles: $(@($caAdminMfa | Select-Object -ExpandProperty PolicyName -First 3) -join '; ')." } else { 'No enabled Conditional Access policy targets admin roles with MFA.' }) `
            'Conditional Access enforces MFA at every sign-in to an admin role, not only at activation.' `
            'A policy targeting all privileged directory roles requires phishing-resistant MFA (authentication strength).' `
            'Create or extend a policy covering all privileged roles, with an authentication strength.' `
            'B2.a, B2.c' 'SSA 2' 'NCSC CAF B2.c: MFA for all privileged access' 'ConditionalAccessPolicies.csv'

        $caDevice = @($ca | Where-Object { [string]$_.GrantControls -match 'compliantDevice|domainJoinedDevice' -and ($_.IncludeRoleIds -or [string]$_.PolicyName -match '(?i)admin|privileg') })
        & $add 'DEV-01' 'Admin devices' 'Admin access only from managed, trusted devices' $(if ($caDevice.Count -gt 0) { 'Partial' } else { 'Weak' }) 'High' `
            $(if ($caDevice.Count -gt 0) { "$(& $pl $caDevice.Count 'enabled policy requires' 'enabled policies require') a compliant or joined device for admins. Configuration cannot show whether dedicated privileged access workstations are used." } else { 'No enabled Conditional Access policy requires a managed device for admin access.' }) `
            'An admin working from an unmanaged or everyday device exposes their session to malware on that device.' `
            'Privileged operations from dedicated, hardened privileged access workstations (CAF B2.b Achieved).' `
            'Confirm the device controls by testing, and plan privileged access workstations (or cloud PAWs) for TL1 admins.' `
            'B2.b' 'SSA 1' 'NCSC CAF B2.b; NCSC: gain trust in your management devices' 'ConditionalAccessPolicies.csv'
    }

    # =========================================================================================
    # Governance
    # =========================================================================================
    if ($hasEntra) {
        $reviews = @($Ctx.AccessReviews)
        $privReviews = @($reviews | Where-Object { ([string]$_.DisplayName + ' ' + [string]$_.Description) -match '(?i)PIM|privileg|role|admin|global' -and ([string]$_.DisplayName + ' ' + [string]$_.Description) -notmatch '(?i)guest' })
        # Review scope cannot be read from this export, so configured reviews count as Partial at best.
        $res = if ($reviews.Count -gt 0) { 'Partial' } else { 'Weak' }
        & $add 'GOV-01' 'Governance' 'Privileged access is reviewed regularly' $res $(if ($res -eq 'Weak') { 'High' } else { 'Medium' }) `
            $(if ($reviews.Count -eq 0) { 'No access reviews are configured.' } elseif ($privReviews.Count -eq 0) { "$(& $pl $reviews.Count 'access review is' 'access reviews are') configured, but none appears to cover privileged roles or PIM groups: $(@($reviews | Select-Object -ExpandProperty DisplayName -First 4) -join '; ')." } else { "$(& $pl $privReviews.Count 'access review appears' 'access reviews appear') to cover some privileged access ($(@($privReviews | Select-Object -ExpandProperty DisplayName -First 4) -join '; ')). Confirm every TL1 role and PIM group is in scope." }) `
            'Without regular review, eligibility builds up as people change roles, and nobody confirms it is still needed.' `
            'Recurring access reviews of every privileged role and PIM group: quarterly for TL1, six-monthly for TL2, annually for TL3, with auto-removal of unconfirmed access.' `
            "Set up the access reviews in P2_AccessReviewPlan.csv ($(@($Ctx.ReviewPlan).Count) reviews): every privileged role, PIM group and Azure subscription on its trust-level cycle, plus supplier, CLAD and approver reviews, with automatic removal when access is not confirmed." `
            'B2.c, B2.d' 'SSA 4' 'NCSC CAF B2.c/B2.d: privileged rights regularly reviewed' 'AccessReviews.beta.csv'

        $noP2 = @($Ctx.NoP2)
        if ($Ctx.HasLicences) {
            & $add 'GOV-02' 'Governance' 'Privileged users are licensed for PIM' $(if ($noP2.Count -eq 0) { 'Good' } else { 'Partial' }) 'Low' `
                $(if ($noP2.Count -eq 0) { 'Every privileged person has an Entra ID P2 or governance licence.' } else { "$(& $pl $noP2.Count 'privileged person has' 'privileged people have') no Entra ID P2 (or suite including it) recorded." }) `
                'PIM, access reviews and risk-based Conditional Access need Entra ID P2 (or ID Governance) for each user who benefits.' `
                'Every user in scope of PIM is licensed.' `
                'Confirm licensing for the people listed (a group-based or tenant-level licence may not show per user).' `
                'B2.d' 'SSA 4' '' 'P2_PrivilegedIdentities.csv'
        }

        & $add 'LOG-01' 'Governance' 'Privileged activity is logged, alerted and reviewed' 'Not assessed' '' `
            'Logging, alerting and review of privileged activity cannot be confirmed from role configuration.' `
            'CAF B2.c Achieved needs all privileged activity recorded and reviewed.' `
            'Entra audit and PIM logs, Azure Activity logs and sign-in logs sent to the SIEM, with alerts on TL1 activation, assignment changes and break-glass use.' `
            'Evidence the SIEM connectors and alert rules (runbook 1.4).' `
            'B2.c' 'SSA 5' 'NCSC: log and audit administration activities' ''
    }

    # =========================================================================================
    # Azure
    # =========================================================================================
    if ($hasAzure) {
        $ownerRoles = @('owner', 'user access administrator', 'role based access control administrator')
        $subOwners = @($Ctx.AzureAccess | Where-Object { $_.PrincipalCategory -in @('Member', 'Guest') -and ([string]$_.RoleName).ToLowerInvariant() -in $ownerRoles -and $_.ScopeLevel -eq 'Subscription' } |
            Group-Object SubscriptionName | ForEach-Object { [pscustomobject]@{ Subscription = $_.Name; People = @($_.Group | Select-Object -ExpandProperty PrincipalId -Unique).Count } })
        $overSubs = @($subOwners | Where-Object { $_.People -gt 3 })
        & $add 'AZ-01' 'Azure' 'Each subscription has no more than three owners' $(if ($overSubs.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
            $(if ($overSubs.Count -eq 0) { "No subscription has more than three people with Owner-level access ($($subOwners.Count) subscriptions with owners)." } else { "$(& $pl $overSubs.Count 'subscription has' 'subscriptions have') more than three people with Owner, User Access Administrator or RBAC Administrator: $(@($overSubs | Sort-Object People -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Subscription) ($($_.People))" }) -join ', ')." }) `
            'Owner-level roles can grant any access to anyone, so each extra holder is another route to full control of the subscription.' `
            'At most three owners per subscription, preferably eligible through PIM.' `
            'Reduce owners to three or fewer and use Contributor or narrower roles for day-to-day work.' `
            'B2.c' 'SSA 4' 'Microsoft Defender for Cloud: a maximum of 3 owners should be designated for subscriptions' 'AzureUserAccess.csv'

        $azStd = @($Ctx.AzStandingTl1)
        & $add 'AZ-02' 'Azure' 'No standing TL1 access across subscriptions or management groups' $(if ($azStd.Count -eq 0) { 'Good' } else { 'Weak' }) 'High' `
            $(if ($azStd.Count -eq 0) { 'Nobody holds TL1 Azure access permanently at subscription scope or above.' } else { "$(& $pl @(& $peopleOf $azStd).Count 'person holds' 'people hold') TL1 Azure access permanently at subscription scope or above ($($azStd.Count) routes)." }) `
            'TL1 at subscription or management group scope gives control of every resource beneath, including the ability to grant access.' `
            'TL1 Azure access is eligible through PIM and limited to the platform team.' `
            'Convert these to eligible assignments in PIM for Azure resources.' `
            'B2.c' 'SSA 4' '' 'P2_StandingAccess.csv'

        $root = @($Ctx.AzRoot)
        $rootBlocked = @($Ctx.AzCoverageGaps | Where-Object { $_.Scope -eq '/' -and $_.Operation -match 'role assignments' }).Count -gt 0
        if ($rootBlocked) {
            & $add 'AZ-03' 'Azure' 'Root management group access is limited' 'Not assessed' '' `
                'Role assignments at the tenant root could not be read: the reviewing account has no access at root.' '' '' `
                'Re-run with Reader at the tenant root management group (a Global Administrator can grant this temporarily by elevating access).' 'B2.d' 'SSA 3' '' 'AzureCoverageGaps.csv'
        }
        else {
        & $add 'AZ-03' 'Azure' 'Root management group access is limited' $(if ($root.Count -eq 0) { 'Good' } else { 'Partial' }) 'Medium' `
            $(if ($root.Count -eq 0) { 'Nobody holds privileged access at the tenant root management group.' } else { "$(& $pl $root.Count 'route grants' 'routes grant') privileged access at the tenant root." }) `
            'Root scope access applies to every subscription in the tenant.' `
            'No standing human access at root; use management group scope for the platform team.' `
            'Remove or make eligible any root scope assignment.' `
            'B2.d' 'SSA 3' '' 'P2_AccessPaths.csv'
        }

        $lh = @($Ctx.AzLighthouse)
        $lhPriv = @($lh | Where-Object { $_.PrivilegeTier -in @('Critical', 'High') -or ([string]$_.RoleName -notmatch '(?i)reader' -and $_.PrivilegeTier -ne 'Low') })
        $lhPermPriv = @($lhPriv | Where-Object { [string]$_.AuthorizationType -ne 'Eligible' })
        $byTenant = @($lh | Group-Object ManagedByTenant | ForEach-Object { "$($_.Name) ($($_.Count))" })
        $res = if ($lh.Count -eq 0 -or $lhPermPriv.Count -eq 0) { 'Good' } else { 'Weak' }
        & $add 'AZ-04' 'Azure' 'Access delegated to other organisations (Azure Lighthouse) is just-in-time' $res 'High' `
            $(if ($lh.Count -eq 0) { 'No Azure Lighthouse delegations to other tenants.' } elseif ($lhPermPriv.Count -eq 0) { "$($lh.Count) Lighthouse authorisations from $($byTenant -join ', '); all write-capable ones are eligible." } else { "$($lh.Count) Lighthouse authorisations give other tenants access: $($byTenant -join ', '). $(& $pl $lhPermPriv.Count 'write-capable authorisation is' 'write-capable authorisations are') permanent (for example $(@($lhPermPriv | Select-Object -First 3 | ForEach-Object { "$($_.RoleName) for $($_.ManagedByTenant) on $($_.SubscriptionName)" }) -join '; '))." }) `
            'Lighthouse lets people in another organisation''s tenant act in your subscriptions. You cannot see or control their accounts, MFA or devices, and their access does not appear in your own PIM.' `
            'Write-capable Lighthouse access uses eligible authorisations (PIM in the managing tenant) with approval, and each delegation is reviewed with the supplier contract.' `
            'Replace permanent Contributor-level authorisations with eligible ones, confirm each managing tenant and offer is still needed, and remove the rest.' `
            'B2.c' 'SSA 4' 'NCSC CAF B2.c: temporary, time-bound rights for third-party support' 'AzureLighthouseDelegations.csv'
    }

    $nonHuman = @($identities | Where-Object { $_.AccountType -eq 'WorkloadIdentity' -and $_.HighestTrustLevel -eq 'TL1' })
    if ($nonHuman.Count -gt 0) {
        & $add 'WL-01' 'Workload identities' 'Automation accounts with TL1 rights are known and owned' 'Partial' 'Medium' `
            "$(& $pl $nonHuman.Count 'workload identity holds' 'workload identities hold') TL1 rights. They cannot use PIM and are outside the scope of this phase." `
            'Service principals and managed identities with TL1 rights are an attack path if their credentials or the resources hosting them are compromised.' `
            'Each has a named owner, the narrowest role, credential hygiene and monitoring.' `
            'Record an owner for each and review whether the rights are needed.' `
            'B2.d' 'SSA 4' '' 'P2_PrivilegedIdentities.csv'
    }

    # =========================================================================================
    # Roll-ups
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
    $cafRows = New-Object System.Collections.ArrayList
    foreach ($c in $caf) {
        $items = @($controls | Where-Object { ([string]$_.CafOutcome).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -eq $c.Id } })
        $null = $cafRows.Add([pscustomobject]@{
            Outcome = $c.Id; Title = $c.Title; WhatTheOutcomeMeans = $c.Outcome; Rating = & $rate $items
            Good = @($items | Where-Object Result -eq 'Good').Count
            Partial = @($items | Where-Object Result -eq 'Partial').Count
            Weak = @($items | Where-Object Result -eq 'Weak').Count
            Controls = (@($items | ForEach-Object { $_.Id }) -join ', ')
        })
    }
    $ssa = @(
        @{ Id = 'SSA 1'; Title = 'Gain trust in your management devices' },
        @{ Id = 'SSA 2'; Title = 'Protect your administration interfaces' },
        @{ Id = 'SSA 3'; Title = 'Risk manage administration using tiers' },
        @{ Id = 'SSA 4'; Title = 'Use privileged access management' },
        @{ Id = 'SSA 5'; Title = 'Log and audit administration activities' }
    )
    $ssaRows = New-Object System.Collections.ArrayList
    foreach ($s in $ssa) {
        $items = @($controls | Where-Object { $_.NcscPrinciple -eq $s.Id })
        $r = & $rate $items
        $label = switch ($r) { 'Achieved' { 'Strong' } 'Partially achieved' { 'Partly in place' } 'Not achieved' { 'Weak' } default { 'Not assessed' } }
        $null = $ssaRows.Add([pscustomobject]@{ Principle = $s.Id; Title = $s.Title; Rating = $label; Good = @($items | Where-Object Result -eq 'Good').Count; Partial = @($items | Where-Object Result -eq 'Partial').Count; Weak = @($items | Where-Object Result -eq 'Weak').Count; Controls = (@($items | ForEach-Object { $_.Id }) -join ', ') })
    }

    # =========================================================================================
    # Where PIM is used, and where it is not
    # =========================================================================================
    $coverage = {
        param([object[]]$Rows, [string]$Plane)
        $out = New-Object System.Collections.ArrayList
        foreach ($g in @($Rows | Group-Object -Property { if ($Plane -eq 'Azure') { "$($_.Role)|$($_.ScopeLevel)" } else { $_.Role } })) {
            $rs = @($g.Group)
            $ppl = @($rs | Select-Object -ExpandProperty Person -Unique)
            $standingPeople = @($rs | Where-Object Standing | Select-Object -ExpandProperty Person -Unique)
            $eligiblePeople = @($ppl | Where-Object { $p = $_; @($rs | Where-Object { $_.Person -eq $p -and $_.EffectiveState -ne 'Eligible' }).Count -eq 0 })
            $timeBound = $ppl.Count - $eligiblePeople.Count - $standingPeople.Count
            if ($timeBound -lt 0) { $timeBound = 0 }
            # Time-bound active routes are current activations or assignments with an end date, so a role
            # with no permanent holders counts as just-in-time.
            $status = if ($standingPeople.Count -eq 0 -and $eligiblePeople.Count -gt 0) { 'Just-in-time (PIM)' } elseif ($standingPeople.Count -eq 0) { 'Time-bound active' } elseif ($eligiblePeople.Count -eq 0) { 'Permanent (no PIM)' } else { 'Mixed' }
            $null = $out.Add([pscustomobject]@{
                Plane = $Plane; Role = $rs[0].Role; ScopeLevel = $rs[0].ScopeLevel; TrustLevel = (@($rs | Select-Object -ExpandProperty TrustLevel -Unique | Sort-Object) | Select-Object -First 1)
                People = $ppl.Count; JustInTime = $eligiblePeople.Count; Permanent = $standingPeople.Count; TimeBound = $timeBound; PimStatus = $status
                ViaGroups = (@($rs | Where-Object ViaGroup | Select-Object -ExpandProperty ViaGroup -Unique | Select-Object -First 4) -join '; ')
            })
        }
        return @($out | Sort-Object @{ Expression = { switch ($_.TrustLevel) { 'TL1' { 1 } 'TL2' { 2 } 'TL3' { 3 } default { 4 } } } }, @{ Expression = 'People'; Descending = $true })
    }
    $covEntra = & $coverage $entraHuman 'Entra'
    $covAzure = & $coverage @($azureHuman | Where-Object { $_.TrustLevel -in @('TL1', 'TL2') }) 'Azure'

    # =========================================================================================
    # Over-subscribed roles
    # =========================================================================================
    $guide = $Ctx.Catalogue.HolderGuidance
    $tl1Guide = if ($guide -and $guide.TL1) { [int]$guide.TL1 } else { 5 }
    $tl2Guide = if ($guide -and $guide.TL2) { [int]$guide.TL2 } else { 10 }
    $over = New-Object System.Collections.ArrayList
    foreach ($g in @($entraHuman | Where-Object { $_.TrustLevel -in @('TL1', 'TL2') } | Group-Object Role)) {
        $rs = @($g.Group); $n = @($rs | Select-Object -ExpandProperty Person -Unique).Count
        $tl = $rs[0].TrustLevel
        if ($g.Name -eq 'Global Administrator') { $max = 4; $src = 'Microsoft: fewer than five' }
        elseif ($tl -eq 'TL1') { $max = $tl1Guide; $src = 'Assessment guide for TL1 roles' }
        else { $max = $tl2Guide; $src = 'Assessment guide for TL2 roles' }
        $null = $over.Add([pscustomobject]@{ Plane = 'Entra'; Role = $g.Name; Scope = 'Tenant'; TrustLevel = $tl; People = $n; Guide = $max; GuideSource = $src; Status = $(if ($n -gt $max) { 'Over' } else { 'Within' }); TimesGuide = [Math]::Round($n / [double]$max, 1) })
    }
    $anyTl1 = @($entraHuman | Where-Object TrustLevel -eq 'TL1' | Select-Object -ExpandProperty Person -Unique).Count
    if ($hasEntra) { $null = $over.Add([pscustomobject]@{ Plane = 'Entra'; Role = 'Any TL1 (privileged) Entra role'; Scope = 'Tenant'; TrustLevel = 'TL1'; People = $anyTl1; Guide = 9; GuideSource = 'Microsoft: fewer than 10 privileged role assignments'; Status = $(if ($anyTl1 -gt 9) { 'Over' } else { 'Within' }); TimesGuide = [Math]::Round($anyTl1 / 9.0, 1) }) }
    if ($hasAzure) {
        foreach ($s in @($subOwners)) {
            $null = $over.Add([pscustomobject]@{ Plane = 'Azure'; Role = 'Owner / User Access Administrator / RBAC Administrator'; Scope = "Subscription: $($s.Subscription)"; TrustLevel = 'TL1'; People = $s.People; Guide = 3; GuideSource = 'Microsoft Defender for Cloud: maximum 3 owners'; Status = $(if ($s.People -gt 3) { 'Over' } else { 'Within' }); TimesGuide = [Math]::Round($s.People / 3.0, 1) })
        }
    }
    $over = @($over | Sort-Object @{ Expression = { if ($_.Status -eq 'Over') { 0 } else { 1 } } }, @{ Expression = 'TimesGuide'; Descending = $true })

    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; '' = 4 }
    $strengths = @($controls | Where-Object Result -eq 'Good')
    $weaknesses = @($controls | Where-Object { $_.Result -in @('Weak', 'Partial') } | Sort-Object @{ Expression = { if ($_.Result -eq 'Weak') { 0 } else { 1 } } }, @{ Expression = { $sevRank[[string]$_.Severity] } })

    return [pscustomobject]@{
        Controls = @($controls); Caf = @($cafRows); Ssa = @($ssaRows)
        CoverageEntra = @($covEntra); CoverageAzure = @($covAzure)
        Oversubscribed = @($over); Strengths = $strengths; Weaknesses = $weaknesses
    }
}
