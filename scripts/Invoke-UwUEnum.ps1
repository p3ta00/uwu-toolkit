<#
.SYNOPSIS
    UwU Toolkit - Comprehensive Active Directory Enumeration Script

.DESCRIPTION
    Full AD enumeration script using PowerView. Covers:
    - Domain/Forest information
    - Trust relationships
    - Users (privileged, SPNs, descriptions, delegation)
    - Groups and memberships
    - Computers and their properties
    - GPOs
    - ACLs and permissions
    - Foreign security principals

.PARAMETER OutputDir
    Directory to save enumeration results (default: .\UwUEnum_Results)

.PARAMETER Quick
    Run quick enumeration only (skip time-consuming checks)

.PARAMETER NoFiles
    Don't write output files, only display to console

.EXAMPLE
    . .\Invoke-UwUEnum.ps1
    Invoke-UwUEnum

.EXAMPLE
    Invoke-UwUEnum -OutputDir C:\Results -Quick

.NOTES
    Author: UwU Toolkit
    Requires: PowerView.ps1 loaded in session
#>

function Invoke-UwUEnum {
    [CmdletBinding()]
    param(
        [string]$OutputDir = ".\UwUEnum_Results",
        [switch]$Quick,
        [switch]$NoFiles
    )

    $Banner = @"

    ╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱★
    ┃╭╮╭╮┃╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱
    ╰╯┃┃┣┻━┳━━┳┳╮╭╮╭┳╮╱╭┳╮╭╮╭╮
    ╱╱┃┃┃╭╮┃╭╮┃┃┃┃╰╯┃┃╱┃┃╰╯╰╯┃
    ╱╱┃┃┃╭╮┃╭╮┃╰╯┃┃┃┃╰━╯┣╮╭╮╭╯
    ╱╱╰╯╰╯╰┻╯╰┻━━┻┻┻┻━╮╭┻╯╰╯╰╯
    ╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭━╯┃  AD Enum
    ╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╰━━╯  v1.0

    ∧,,,∧  ~ Active Directory Enumeration ~
   ( ̳• · •̳)
   /    づ♡

"@

    Write-Host $Banner -ForegroundColor Magenta

    # Check if PowerView is loaded
    if (-not (Get-Command Get-DomainUser -ErrorAction SilentlyContinue)) {
        Write-Host "[!] PowerView not loaded. Attempting to load..." -ForegroundColor Yellow
        $PVPaths = @(
            "C:\Tools\PowerView.ps1",
            ".\PowerView.ps1",
            "$env:USERPROFILE\Desktop\PowerView.ps1"
        )
        $loaded = $false
        foreach ($path in $PVPaths) {
            if (Test-Path $path) {
                . $path
                Write-Host "[+] Loaded PowerView from: $path" -ForegroundColor Green
                $loaded = $true
                break
            }
        }
        if (-not $loaded) {
            Write-Host "[-] PowerView.ps1 not found. Please load it first:" -ForegroundColor Red
            Write-Host "    . C:\Path\To\PowerView.ps1" -ForegroundColor Cyan
            return
        }
    }

    # Create output directory
    if (-not $NoFiles) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputDir = "$OutputDir`_$timestamp"
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Host "[*] Output directory: $OutputDir" -ForegroundColor Cyan
    }

    function Write-Section($title) {
        Write-Host "`n" -NoNewline
        Write-Host ("=" * 60) -ForegroundColor Magenta
        Write-Host "  $title" -ForegroundColor Cyan
        Write-Host ("=" * 60) -ForegroundColor Magenta
    }

    function Save-Results($data, $filename, $title) {
        if ($data) {
            Write-Host "[+] $title" -ForegroundColor Green
            $data | Format-List
            if (-not $NoFiles) {
                $data | Out-File "$OutputDir\$filename.txt"
                $data | Export-Csv "$OutputDir\$filename.csv" -NoTypeInformation -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host "[-] No results for: $title" -ForegroundColor Yellow
        }
    }

    # ================================================================
    # DOMAIN & FOREST INFORMATION
    # ================================================================
    Write-Section "DOMAIN & FOREST INFORMATION"

    Write-Host "[*] Getting domain info..." -ForegroundColor Cyan
    $domain = Get-Domain
    Save-Results $domain "01_domain_info" "Domain Information"

    Write-Host "[*] Getting forest info..." -ForegroundColor Cyan
    $forest = Get-Forest
    Save-Results $forest "02_forest_info" "Forest Information"

    Write-Host "[*] Getting domain controllers..." -ForegroundColor Cyan
    $dcs = Get-DomainController
    Save-Results $dcs "03_domain_controllers" "Domain Controllers"

    # ================================================================
    # TRUST RELATIONSHIPS
    # ================================================================
    Write-Section "TRUST RELATIONSHIPS"

    Write-Host "[*] Getting domain trusts..." -ForegroundColor Cyan
    $trusts = Get-DomainTrust
    Save-Results $trusts "04_domain_trusts" "Domain Trusts"

    Write-Host "[*] Getting forest trusts..." -ForegroundColor Cyan
    $forestTrusts = Get-ForestTrust -ErrorAction SilentlyContinue
    Save-Results $forestTrusts "05_forest_trusts" "Forest Trusts"

    Write-Host "[*] Getting foreign group members..." -ForegroundColor Cyan
    $foreignMembers = Get-DomainForeignGroupMember
    Save-Results $foreignMembers "06_foreign_group_members" "Foreign Group Members (Cross-Domain Admins)"

    # ================================================================
    # USER ENUMERATION
    # ================================================================
    Write-Section "USER ENUMERATION"

    Write-Host "[*] Getting all domain users..." -ForegroundColor Cyan
    $users = Get-DomainUser -Properties samaccountname,description,memberof,pwdlastset,lastlogon
    $userCount = ($users | Measure-Object).Count
    Write-Host "[+] Found $userCount users" -ForegroundColor Green
    if (-not $NoFiles) {
        $users | Select-Object samaccountname,description | Out-File "$OutputDir\07_all_users.txt"
    }

    Write-Host "[*] Getting users with descriptions (password hints)..." -ForegroundColor Cyan
    $usersWithDesc = Get-DomainUser -Properties samaccountname,description |
        Where-Object { $_.description } |
        Select-Object samaccountname,description
    Save-Results $usersWithDesc "08_users_with_descriptions" "Users with Descriptions (Check for passwords!)"

    Write-Host "[*] Getting Kerberoastable users (SPN set)..." -ForegroundColor Cyan
    $spnUsers = Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,description
    Save-Results $spnUsers "09_kerberoastable_users" "Kerberoastable Users (SPN Set)"

    Write-Host "[*] Getting AS-REP roastable users (no preauth)..." -ForegroundColor Cyan
    $asrepUsers = Get-DomainUser -PreauthNotRequired -Properties samaccountname,description
    Save-Results $asrepUsers "10_asrep_roastable_users" "AS-REP Roastable Users (No Preauth)"

    Write-Host "[*] Getting users with constrained delegation..." -ForegroundColor Cyan
    $constrainedDeleg = Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
    Save-Results $constrainedDeleg "11_constrained_delegation_users" "Users with Constrained Delegation"

    Write-Host "[*] Getting users with unconstrained delegation..." -ForegroundColor Cyan
    $unconstrainedDeleg = Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties samaccountname
    Save-Results $unconstrainedDeleg "12_unconstrained_delegation_users" "Users with Unconstrained Delegation"

    Write-Host "[*] Getting Domain Admins..." -ForegroundColor Cyan
    $domainAdmins = Get-DomainGroupMember -Identity "Domain Admins" -Recurse
    Save-Results $domainAdmins "13_domain_admins" "Domain Admins"

    Write-Host "[*] Getting Enterprise Admins..." -ForegroundColor Cyan
    $enterpriseAdmins = Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse -ErrorAction SilentlyContinue
    Save-Results $enterpriseAdmins "14_enterprise_admins" "Enterprise Admins"

    # ================================================================
    # GROUP ENUMERATION
    # ================================================================
    Write-Section "GROUP ENUMERATION"

    Write-Host "[*] Getting all domain groups..." -ForegroundColor Cyan
    $groups = Get-DomainGroup -Properties samaccountname,description,member
    $groupCount = ($groups | Measure-Object).Count
    Write-Host "[+] Found $groupCount groups" -ForegroundColor Green
    if (-not $NoFiles) {
        $groups | Select-Object samaccountname,description | Out-File "$OutputDir\15_all_groups.txt"
    }

    Write-Host "[*] Getting privileged groups..." -ForegroundColor Cyan
    $privGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "DnsAdmins",
        "Remote Desktop Users",
        "Remote Management Users"
    )

    foreach ($group in $privGroups) {
        $members = Get-DomainGroupMember -Identity $group -Recurse -ErrorAction SilentlyContinue
        if ($members) {
            Write-Host "[+] $group members:" -ForegroundColor Green
            $members | ForEach-Object { Write-Host "    - $($_.MemberName)" -ForegroundColor White }
            if (-not $NoFiles) {
                $members | Out-File "$OutputDir\group_$($group -replace ' ','_').txt"
            }
        }
    }

    # ================================================================
    # COMPUTER ENUMERATION
    # ================================================================
    Write-Section "COMPUTER ENUMERATION"

    Write-Host "[*] Getting all domain computers..." -ForegroundColor Cyan
    $computers = Get-DomainComputer -Properties dnshostname,operatingsystem,distinguishedname,objectguid
    $compCount = ($computers | Measure-Object).Count
    Write-Host "[+] Found $compCount computers" -ForegroundColor Green
    Save-Results $computers "16_all_computers" "Domain Computers"

    Write-Host "[*] Getting computers with unconstrained delegation..." -ForegroundColor Cyan
    $unconstrainedComp = Get-DomainComputer -Unconstrained -Properties dnshostname
    Save-Results $unconstrainedComp "17_unconstrained_delegation_computers" "Computers with Unconstrained Delegation"

    Write-Host "[*] Getting computers with LAPS..." -ForegroundColor Cyan
    $lapsComps = Get-DomainComputer -Properties dnshostname,ms-mcs-admpwd,ms-mcs-admpwdexpirationtime |
        Where-Object { $_.'ms-mcs-admpwd' }
    Save-Results $lapsComps "18_laps_computers" "Computers with LAPS (if readable)"

    # ================================================================
    # GPO ENUMERATION
    # ================================================================
    Write-Section "GPO ENUMERATION"

    Write-Host "[*] Getting all GPOs..." -ForegroundColor Cyan
    $gpos = Get-DomainGPO -Properties displayname,name,gpcfilesyspath
    Save-Results $gpos "19_all_gpos" "Group Policy Objects"

    if (-not $Quick) {
        Write-Host "[*] Checking GPO permissions..." -ForegroundColor Cyan
        $gpoPerms = Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs |
            Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner" } |
            Select-Object ObjectDN,ActiveDirectoryRights,SecurityIdentifier
        Save-Results $gpoPerms "20_gpo_permissions" "GPO Modification Rights"
    }

    # ================================================================
    # ACL ENUMERATION (if not Quick mode)
    # ================================================================
    if (-not $Quick) {
        Write-Section "ACL ENUMERATION"

        Write-Host "[*] Finding interesting ACLs (this may take a while)..." -ForegroundColor Cyan

        Write-Host "[*] Checking for DCSync rights..." -ForegroundColor Cyan
        $dcSyncRights = Get-DomainObjectAcl -SearchBase "DC=$((Get-Domain).Name -replace '\.',',DC=')" -SearchScope Base |
            Where-Object {
                ($_.ObjectAceType -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c") -and
                ($_.ActiveDirectoryRights -match "ExtendedRight")
            }
        Save-Results $dcSyncRights "21_dcsync_rights" "DCSync Rights"

        Write-Host "[*] Checking for GenericAll on users..." -ForegroundColor Cyan
        $genericAllUsers = Get-DomainUser | Get-DomainObjectAcl -ResolveGUIDs |
            Where-Object { $_.ActiveDirectoryRights -eq "GenericAll" } |
            Select-Object ObjectDN,SecurityIdentifier -First 50
        Save-Results $genericAllUsers "22_genericall_users" "GenericAll Rights on Users (first 50)"
    }

    # ================================================================
    # LOCAL GROUP ENUMERATION
    # ================================================================
    Write-Section "LOCAL GROUP ENUMERATION"

    Write-Host "[*] Getting local admin access (current host)..." -ForegroundColor Cyan
    try {
        $localAdmins = Get-NetLocalGroupMember -GroupName "Administrators" -ErrorAction SilentlyContinue
        Save-Results $localAdmins "23_local_administrators" "Local Administrators"

        $rmu = Get-NetLocalGroupMember -GroupName "Remote Management Users" -ErrorAction SilentlyContinue
        Save-Results $rmu "24_remote_management_users" "Remote Management Users"

        $rdp = Get-NetLocalGroupMember -GroupName "Remote Desktop Users" -ErrorAction SilentlyContinue
        Save-Results $rdp "25_remote_desktop_users" "Remote Desktop Users"
    } catch {
        Write-Host "[-] Could not enumerate local groups" -ForegroundColor Yellow
    }

    # ================================================================
    # SHARES ENUMERATION (if not Quick mode)
    # ================================================================
    if (-not $Quick) {
        Write-Section "SHARE ENUMERATION"

        Write-Host "[*] Finding accessible shares (sampling DCs)..." -ForegroundColor Cyan
        $dcs | ForEach-Object {
            $shares = Get-NetShare -ComputerName $_.Name -ErrorAction SilentlyContinue
            if ($shares) {
                Write-Host "[+] Shares on $($_.Name):" -ForegroundColor Green
                $shares | ForEach-Object { Write-Host "    - $($_.Name): $($_.Remark)" }
            }
        }
    }

    # ================================================================
    # SUMMARY
    # ================================================================
    Write-Section "ENUMERATION COMPLETE"

    $summary = @"

    [+] Enumeration Summary
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Domain Users:           $userCount
    Domain Groups:          $groupCount
    Domain Computers:       $compCount
    Kerberoastable Users:   $(($spnUsers | Measure-Object).Count)
    AS-REP Roastable:       $(($asrepUsers | Measure-Object).Count)
    Constrained Deleg:      $(($constrainedDeleg | Measure-Object).Count)
    Foreign Members:        $(($foreignMembers | Measure-Object).Count)
    Domain Trusts:          $(($trusts | Measure-Object).Count)
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"@

    Write-Host $summary -ForegroundColor Cyan

    if (-not $NoFiles) {
        $summary | Out-File "$OutputDir\00_SUMMARY.txt"
        Write-Host "[+] Results saved to: $OutputDir" -ForegroundColor Green
    }

    # High-value targets
    Write-Host "`n[!] HIGH-VALUE FINDINGS TO INVESTIGATE:" -ForegroundColor Red

    if ($usersWithDesc) {
        Write-Host "    - Users with descriptions (check for passwords)" -ForegroundColor Yellow
    }
    if ($spnUsers) {
        Write-Host "    - Kerberoastable accounts found" -ForegroundColor Yellow
    }
    if ($asrepUsers) {
        Write-Host "    - AS-REP roastable accounts found" -ForegroundColor Yellow
    }
    if ($constrainedDeleg) {
        Write-Host "    - Constrained delegation configured" -ForegroundColor Yellow
    }
    if ($foreignMembers) {
        Write-Host "    - Cross-domain admin access detected" -ForegroundColor Yellow
    }

    Write-Host "`n    ∧,,,∧" -ForegroundColor Magenta
    Write-Host "   ( ̳• · •̳)  Happy hunting!" -ForegroundColor Magenta
    Write-Host "   /    づ♡`n" -ForegroundColor Magenta
}

# Export function
Export-ModuleMember -Function Invoke-UwUEnum -ErrorAction SilentlyContinue
