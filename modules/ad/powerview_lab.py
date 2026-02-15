"""
HTB Academy PowerView Lab Helper
Provides commands and answers for the AD PowerView module
"""

from core.module_base import ModuleBase, ModuleType, Platform


class PowerViewLab(ModuleBase):
    """
    HTB Academy AD PowerView Lab Helper
    Provides PowerView commands and expected answers
    """

    def __init__(self):
        super().__init__()
        self.name = "powerview_lab"
        self.description = "HTB Academy PowerView Lab helper with commands and answers"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["htb", "academy", "powerview", "lab", "helper", "ad"]

        # Register options
        self.register_option("SECTION", "Lab section to show",
                           default="all",
                           choices=["all", "overview", "users", "groups", "computers",
                                   "acls", "gpos", "trusts", "rights", "ldap", "filters",
                                   "ldap_search_filters", "builtin_tools", "ldap_anonymous_bind",
                                   "credentialed_ldap", "assessment"])
        self.register_option("SHOW_ANSWERS", "Show answers", default="yes",
                           choices=["yes", "no"])

        # Lab data
        self.lab_sections = {
            "overview": {
                "title": "PowerView/SharpView Overview & Usage",
                "target": "10.129.x.x (WS01)",
                "creds": "htb-student:Academy_student_AD!",
                "questions": [
                    {
                        "q": "Find the SID of the user liam.jones",
                        "cmd": "Convert-NameToSid liam.jones",
                        "answer": "S-1-5-21-2974783224-3764228556-2640795941-1705"
                    },
                    {
                        "q": "What is the child domain of our current domain?",
                        "cmd": "Get-DomainTrustMapping",
                        "answer": "LOGISTICS.INLANEFREIGHT.LOCAL"
                    },
                    {
                        "q": "What user maps to the SID S-1-5-21-2974783224-3764228556-2640795941-1893?",
                        "cmd": "Convert-SidToName S-1-5-21-2974783224-3764228556-2640795941-1893",
                        "answer": "rita.grant"
                    }
                ]
            },
            "users": {
                "title": "Enumerating AD Users",
                "questions": [
                    {
                        "q": "Find another user configured with Kerberos constrained delegation",
                        "cmd": "Get-DomainUser -TrustedtoAuth",
                        "answer": "svc-scan"
                    },
                    {
                        "q": "Find the second user with a password in the description field",
                        "cmd": "Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}",
                        "answer": "W4y_am_I_d0ing_Th1s?"
                    },
                    {
                        "q": "Find another user with an SPN set that is not listed",
                        "cmd": "Get-DomainUser * -SPN | select samaccountname",
                        "answer": "WSUSupdatesvc"
                    },
                    {
                        "q": "Find another user in the administrators group from another domain",
                        "cmd": "Get-DomainGroup -Identity administrators | select member",
                        "answer": "bob.barker"
                    }
                ]
            },
            "groups": {
                "title": "Enumerating AD Groups",
                "questions": [
                    {
                        "q": "Find the user in the Records Management group",
                        "cmd": "Get-DomainGroup -Identity 'Records Management' | select member",
                        "answer": "jennifer.chandler"
                    },
                    {
                        "q": "Find the member of the Remote Management Users group on WS01",
                        "cmd": "Find-DomainLocalGroupMember -ComputerName WS01 -GroupName 'Remote Management Users'",
                        "answer": "samantha.patel"
                    }
                ]
            },
            "computers": {
                "title": "Enumerating AD Computers",
                "questions": [
                    {
                        "q": "How many hosts are present in the domain?",
                        "cmd": "(Get-DomainComputer).count",
                        "answer": "5"
                    },
                    {
                        "q": "What is the objectguid value of the EXCHG01 host?",
                        "cmd": "Get-DomainComputer -Identity EXCHG01 -Properties * | select objectguid",
                        "answer": "ec252fbd-765d-4833-9f9d-f1eaf712089e"
                    },
                    {
                        "q": "What OU does the WS01 host belong to?",
                        "cmd": "Get-DomainComputer -Identity WS01",
                        "answer": "Staff Workstations"
                    }
                ]
            },
            "acls": {
                "title": "Enumerating Domain ACLs",
                "questions": [
                    {
                        "q": "Find a user who has GenericAll rights over the joe.evans user",
                        "cmd": "(Get-ACL \"AD:$((Get-ADUser joe.evans).distinguishedname)\").access | ? {$_.ActiveDirectoryRights -match 'GenericAll'} | Select IdentityReference",
                        "answer": "douglas.bull"
                    },
                    {
                        "q": "Find the name of a non-standard share on the WS01 computer",
                        "cmd": "Get-NetShare",
                        "answer": "Client_Invoices"
                    },
                    {
                        "q": "Find another user with DCSync rights",
                        "cmd": "$dcsync = Get-ObjectACL \"DC=inlanefreight,DC=local\" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value; Convert-SidtoName $dcsync",
                        "answer": "gillian.fisher"
                    }
                ]
            },
            "gpos": {
                "title": "Enumerating Group Policy Objects (GPOs)",
                "questions": [
                    {
                        "q": "Find the GUID of the Audit Policy GPO",
                        "cmd": "Get-DomainGPO -Identity 'Audit Policy' | select displayname,objectguid",
                        "answer": "8bb15712-8a05-47e7-9dcf-897999d695fe"
                    }
                ]
            },
            "trusts": {
                "title": "Enumerating AD Trusts",
                "questions": [
                    {
                        "q": "What is the name of the child domain?",
                        "cmd": "Get-DomainTrustMapping",
                        "answer": "LOGISTICS.INLANEFREIGHT.LOCAL"
                    },
                    {
                        "q": "What other forest does the current domain have a trust with?",
                        "cmd": "Get-DomainTrustMapping",
                        "answer": "freightlogistics.local"
                    },
                    {
                        "q": "What is the trust direction for this trust?",
                        "cmd": "Get-DomainTrustMapping",
                        "answer": "Bidirectional"
                    }
                ]
            },
            "rights": {
                "title": "Rights and Privileges in AD",
                "target": "10.129.2.174 (ACADEMY-AD-WS01)",
                "creds": "htb-student:Academy_student_AD!",
                "description": "Understanding rights and privileges in Active Directory - privileged groups, dangerous memberships, and escalation paths",
                "questions": [
                    {
                        "q": "Find the user in the DNSAdmins group (format first.last)",
                        "cmd": "Get-DomainGroupMember -Identity 'DnsAdmins' | Select MemberName",
                        "answer": "hazel.lamb",
                        "note": "DnsAdmins can load arbitrary DLLs on DCs and create WPAD records for MITM"
                    },
                    {
                        "q": "How many users are in the Help Desk group?",
                        "cmd": "(Get-DomainGroupMember -Identity 'Help Desk').count",
                        "answer": "3",
                        "note": "Help Desk may have password reset or other delegated rights"
                    },
                    {
                        "q": "What OU is the Help Desk group managed by?",
                        "cmd": "Get-DomainGroup -Identity 'Help Desk' -Properties managedby | Select managedby",
                        "answer": "Microsoft Exchange Security Groups",
                        "note": "Group managers can modify group membership - check for escalation paths"
                    }
                ]
            },
            "ldap": {
                "title": "LDAP Overview",
                "target": "10.129.2.174 (ACADEMY-AD-WS01)",
                "creds": "htb-student:Academy_student_AD!",
                "description": "Understanding LDAP queries and AD enumeration using native LDAP filters",
                "questions": [
                    {
                        "q": "Find another disabled user (first.last)",
                        "cmd": "Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol",
                        "answer": "luke.gibbons",
                        "note": "UAC flag 2 = ACCOUNTDISABLE. Look for users in first.last format (not built-in accounts)"
                    },
                    {
                        "q": "How many users exist in the INLANEFREIGHT.LOCAL domain?",
                        "cmd": "(Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user))').count",
                        "answer": "1044",
                        "note": "Can also use PowerView: (Get-DomainUser).count"
                    },
                    {
                        "q": "How many computers exist in the INLANEFREIGHT.LOCAL domain?",
                        "cmd": "(Get-ADObject -LDAPFilter '(objectCategory=computer)').count",
                        "answer": "5",
                        "note": "Can also use PowerView: (Get-DomainComputer).count"
                    },
                    {
                        "q": "How many groups exist in the INLANEFREIGHT.LOCAL domain?",
                        "cmd": "(Get-ADObject -LDAPFilter '(objectClass=group)').count",
                        "answer": "73",
                        "note": "Can also use PowerView: (Get-DomainGroup).count"
                    }
                ]
            },
            "filters": {
                "title": "Active Directory Search Filters",
                "target": "10.129.2.174 (ACADEMY-AD-WS01)",
                "creds": "htb-student:Academy_student_AD!",
                "description": "PowerShell Filter parameter with AD module - using operators like -eq, -like, -and, -or for precise queries",
                "questions": [
                    {
                        "q": "Find another user with DoesNotRequirePreAuth set (first.last)",
                        "cmd": "Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'}",
                        "answer": "ross.begum",
                        "note": "ASREPRoastable user - can obtain TGT without pre-auth. PowerView: Get-DomainUser -PreauthNotRequired"
                    },
                    {
                        "q": "Find the SID of the WS01 host",
                        "cmd": "Get-ADComputer -Filter {Name -eq 'WS01'} -Properties objectsid | Select objectsid",
                        "answer": "S-1-5-21-2974783224-3764228556-2640795941-1105",
                        "note": "PowerView: (Get-DomainComputer -Identity WS01).objectsid"
                    },
                    {
                        "q": "Find an account with SPN that is also in Protected Users group",
                        "cmd": "Get-ADUser -Filter \"adminCount -eq '1'\" -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName",
                        "answer": "sqlprod",
                        "note": "sqlprod has SPN MSSQLSvc/sql01:1433 and is member of Protected Users. Kerberoastable but protected from credential theft"
                    }
                ]
            },
            "ldap_search_filters": {
                "title": "LDAP Search Filters",
                "target": "10.129.2.174 (ACADEMY-AD-WS01)",
                "creds": "htb-student:Academy_student_AD!",
                "description": "LDAP filter syntax with matching rule OIDs, RecursiveMatch, SearchBase/SearchScope parameters",
                "questions": [
                    {
                        "q": "Find another group (not listed in section) that harry.jones is a member of (case sensitive)",
                        "cmd": "Get-ADGroup -Filter 'member -RecursiveMatch \"CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL\"' | select name",
                        "answer": "network operations",
                        "note": "Use RecursiveMatch or LDAP OID 1.2.840.113556.1.4.1941 for nested group membership. PowerView: Get-DomainGroup -MemberIdentity harry.jones"
                    },
                    {
                        "q": "Find another user marked as trusted for delegation",
                        "cmd": "Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name",
                        "answer": "sql-test",
                        "note": "TRUSTED_FOR_DELEGATION flag (524288) = unconstrained delegation. PowerView: Get-DomainUser -Unconstrained"
                    },
                    {
                        "q": "Find the number of users in the IT OU",
                        "cmd": "(Get-ADUser -SearchBase 'OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL' -SearchScope Subtree -Filter *).count",
                        "answer": "118",
                        "note": "SearchScope Subtree searches all child containers. PowerView: (Get-DomainUser -SearchBase 'OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL').count"
                    }
                ]
            },
            "builtin_tools": {
                "title": "Enumerating Active Directory with Built-in Tools",
                "target": "10.129.2.174 (ACADEMY-AD-WS01)",
                "creds": "htb-student:Academy_student_AD!",
                "description": "DS Tools, AD PowerShell module, WMI, ADSI for AD enumeration. UAC attribute flags control account behavior.",
                "questions": [
                    {
                        "q": "What is the UAC value for DONT_REQ_PREAUTH?",
                        "cmd": "Static value - see UAC flag table",
                        "answer": "4194304",
                        "note": "DONT_REQ_PREAUTH = 4194304. ASREPRoastable accounts. Use Get-DomainUser -PreauthNotRequired or Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}"
                    },
                    {
                        "q": "List the user in the Pentest OU (first.last)",
                        "cmd": "Get-DomainUser -Identity clark.thompson | Select-Object distinguishedname",
                        "answer": "clark.thompson",
                        "note": "PowerView: Get-DomainOU -Identity Pentest to find OU, then verify user with Get-DomainUser. Located at CN=clark.thompson,OU=Pentest,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"
                    }
                ]
            },
            "ldap_anonymous_bind": {
                "title": "LDAP Anonymous Bind",
                "target": "10.129.42.188 (DC01)",
                "creds": "No credentials required - anonymous bind",
                "description": "Enumerate AD via LDAP anonymous bind using ldapsearch, windapsearch, or Python ldap3",
                "questions": [
                    {
                        "q": "What is the domain functional level?",
                        "cmd": "ldapsearch -H ldap://TARGET -x -s base -b \"\" domainFunctionality",
                        "answer": "2016",
                        "note": "domainFunctionality: 7 = Windows Server 2016. Also: windapsearch --dc TARGET -m metadata"
                    },
                    {
                        "q": "Find a user with unconstrained delegation who is also part of the Protected Users group",
                        "cmd": "windapsearch --dc TARGET -m unconstrained (then check Protected Users members)",
                        "answer": "sqldev",
                        "note": "sqldev has unconstrained delegation AND is member of Protected Users. ldapsearch -x -b dc=inlanefreight,dc=local \"(cn=Protected Users)\" member"
                    },
                    {
                        "q": "What OU is the user Kevin Gregory part of (one word, case sensitive)?",
                        "cmd": "ldapsearch -H ldap://TARGET -x -b dc=inlanefreight,dc=local \"(sAMAccountName=kevin*)\" dn",
                        "answer": "Finance",
                        "note": "DN: CN=kevin.gregory,OU=Finance,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"
                    }
                ]
            },
            "credentialed_ldap": {
                "title": "Credentialed LDAP Enumeration",
                "target": "10.129.42.188 (DC01)",
                "creds": "james.cross:Academy_Student! (anonymous bind also works)",
                "description": "LDAP enumeration with credentials using ldapsearch-ad.py and windapsearch. UAC flags enumeration.",
                "questions": [
                    {
                        "q": "What is the minimum password length for user accounts?",
                        "cmd": "ldapsearch -H ldap://TARGET -x -b dc=inlanefreight,dc=local \"(objectClass=domain)\" minPwdLength",
                        "answer": "7",
                        "note": "ldapsearch-ad.py -l TARGET -d inlanefreight -u james.cross -p PASSWORD -t pass-pols"
                    },
                    {
                        "q": "What user account requires a smart card for interactive logon (SMARTCARD_REQUIRED)?",
                        "cmd": "ldapsearch -H ldap://TARGET -x -b dc=inlanefreight,dc=local \"(userAccountControl:1.2.840.113556.1.4.803:=262144)\" sAMAccountName",
                        "answer": "sarah.lafferty",
                        "note": "SMARTCARD_REQUIRED UAC flag = 262144"
                    },
                    {
                        "q": "What is the password history size of the domain?",
                        "cmd": "ldapsearch -H ldap://TARGET -x -b dc=inlanefreight,dc=local \"(objectClass=domain)\" pwdHistoryLength",
                        "answer": "5",
                        "note": "pwdHistoryLength = number of passwords remembered"
                    },
                    {
                        "q": "What user account has ENCRYPTED_TEXT_PWD_ALLOWED set?",
                        "cmd": "ldapsearch -H ldap://TARGET -x -b dc=inlanefreight,dc=local \"(userAccountControl:1.2.840.113556.1.4.803:=128)\" sAMAccountName",
                        "answer": "wilford.stewart",
                        "note": "ENCRYPTED_TEXT_PWD_ALLOWED UAC flag = 128 (store passwords using reversible encryption)"
                    },
                    {
                        "q": "What is the userAccountControl bitmask for NORMAL_ACCOUNT and ENCRYPTED_TEXT_PWD_ALLOWED?",
                        "cmd": "NORMAL_ACCOUNT (512) + ENCRYPTED_TEXT_PWD_ALLOWED (128)",
                        "answer": "640",
                        "note": "512 + 128 = 640 (decimal). UAC flags are additive bitmasks."
                    }
                ]
            },
            "assessment": {
                "title": "Active Directory LDAP - Skills Assessment",
                "target": "10.129.202.128 (INLANEFREIGHTENUM1.LOCAL)",
                "creds": "htb-student:Acad_ad_enum_skillz!",
                "description": "Final skills assessment covering all AD LDAP enumeration techniques: UAC flags, nested groups, OUs, SPNs, privileges",
                "questions": [
                    {
                        "q": "Find the one user who has a useraccountcontrol attribute equivalent to 262656",
                        "cmd": "Get-ADUser -LDAPFilter '(userAccountControl=262656)' | select samaccountname",
                        "answer": "abigail.henry",
                        "note": "262656 = 262144 (SMARTCARD_REQUIRED) + 512 (NORMAL_ACCOUNT). ldapsearch: (userAccountControl=262656)"
                    },
                    {
                        "q": "Using built-in tools enumerate a user that has the PASSWD_NOTREQD UAC value set",
                        "cmd": "Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=32)' | select samaccountname",
                        "answer": "clive.jones",
                        "note": "PASSWD_NOTREQD = 32. Can have blank password. dsquery: dsquery * -filter \"(userAccountControl:1.2.840.113556.1.4.803:=32)\""
                    },
                    {
                        "q": "What group is the IT Support group nested into?",
                        "cmd": "Get-ADGroup -Identity 'IT Support' -Properties memberof | select -ExpandProperty memberof",
                        "answer": "Server Technicians",
                        "note": "Check MemberOf attribute for parent groups. PowerView: Get-DomainGroup 'IT Support' | select memberof"
                    },
                    {
                        "q": "Who is a part of this group through nested group membership?",
                        "cmd": "Get-ADGroupMember -Identity 'Server Technicians' -Recursive | select samaccountname",
                        "answer": "sally.andrews",
                        "note": "Use -Recursive to find all nested members. PowerView: Get-DomainGroupMember 'Server Technicians' -Recurse"
                    },
                    {
                        "q": "How many users are in the Former Employees OU?",
                        "cmd": "(Get-ADUser -SearchBase 'OU=Former Employees,DC=INLANEFREIGHTENUM1,DC=LOCAL' -Filter *).count",
                        "answer": "103",
                        "note": "Use SearchBase to target specific OU. ldapsearch: -b 'OU=Former Employees,DC=...' '(objectClass=user)'"
                    },
                    {
                        "q": "What is the name of the computer that starts with RD? (Submit the FQDN in all capital letters)",
                        "cmd": "Get-ADComputer -Filter 'Name -like \"RD*\"' -Properties dnshostname | select dnshostname",
                        "answer": "RDS01.INLANEFREIGHTENUM1.LOCAL",
                        "note": "Filter with wildcard. ldapsearch: '(&(objectClass=computer)(cn=RD*))' dNSHostName"
                    },
                    {
                        "q": "How many groups exist where the admincount attribute is set to 1?",
                        "cmd": "(Get-ADGroup -LDAPFilter '(adminCount=1)').count",
                        "answer": "13",
                        "note": "adminCount=1 indicates protected groups (modified by AdminSDHolder). PowerView: (Get-DomainGroup -AdminCount).count"
                    },
                    {
                        "q": "What user could be subjected to an ASREPRoasting attack and is NOT a protected user? (first.last)",
                        "cmd": "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties memberof | ? {$_.memberof -notmatch 'Protected Users'}",
                        "answer": "wilbur.douglas",
                        "note": "DONT_REQ_PREAUTH (4194304) = ASREPRoastable. Exclude users in Protected Users group. PowerView: Get-DomainUser -PreauthNotRequired"
                    },
                    {
                        "q": "What is the samaccountname of the one SPN set in the domain?",
                        "cmd": "Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties serviceprincipalname | select samaccountname",
                        "answer": "mssqlprod",
                        "note": "Kerberoastable account. PowerView: Get-DomainUser -SPN | select samaccountname,serviceprincipalname"
                    },
                    {
                        "q": "What non-default privilege does the htb-student user have?",
                        "cmd": "whoami /priv (on RDP session)",
                        "answer": "SeBackupPrivilege",
                        "note": "SeBackupPrivilege allows reading any file regardless of ACL - can dump SAM/SYSTEM or copy NTDS.dit"
                    }
                ]
            }
        }

    def run(self) -> bool:
        section = self.get_option("SECTION")
        show_answers = self.get_option("SHOW_ANSWERS") == "yes"

        if section == "all":
            sections_to_show = list(self.lab_sections.keys())
        else:
            sections_to_show = [section]

        for sec in sections_to_show:
            if sec not in self.lab_sections:
                continue

            data = self.lab_sections[sec]
            self.print_line()
            self.print_line("=" * 70)
            self.print_good(data["title"])
            self.print_line("=" * 70)

            if "target" in data:
                self.print_status(f"Target: {data['target']}")
            if "creds" in data:
                self.print_status(f"Credentials: {data['creds']}")

            self.print_line()

            if "description" in data:
                self.print_line(f"  {data['description']}")
                self.print_line()

            for i, q in enumerate(data["questions"], 1):
                self.print_status(f"Q{i}: {q['q']}")
                self.print_line(f"    Command: {q['cmd']}")
                if show_answers:
                    self.print_good(f"    Answer: {q['answer']}")
                if "note" in q:
                    self.print_warning(f"    Note: {q['note']}")
                self.print_line()

        self.print_line()
        self.print_status("Setup Instructions:")
        self.print_line("1. Connect via RDP: xfreerdp /v:<TARGET_IP> /u:htb-student /p:<PASSWORD>")
        self.print_line("2. Open PowerShell as Administrator")
        self.print_line("3. cd C:\\Tools")
        self.print_line("4. Import-Module .\\PowerView.ps1")
        self.print_line("5. Run the commands above")

        return True

    def check(self) -> bool:
        return True
