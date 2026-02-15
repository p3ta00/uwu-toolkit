"""
Active Directory Enumeration Module
Comprehensive AD enumeration using LDAP and Impacket
Similar to PowerView/SharpView functionality
"""

import subprocess
import socket
import struct
import base64
from typing import Optional, List, Dict, Any
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class ADEnumerator(ModuleBase):
    """
    Active Directory enumeration module
    Provides PowerView-like functionality using Python tools
    """

    def __init__(self):
        super().__init__()
        self.name = "ad_enum"
        self.description = "Active Directory enumeration (PowerView-like)"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "ldap", "enumeration", "powerview", "domain", "windows"]
        self.references = [
            "https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology"
        ]

        # Register options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)
        self.register_option("ACTION", "Enumeration action",
                           default="domain",
                           choices=["domain", "users", "groups", "computers", "trusts",
                                   "gpos", "ous", "sid", "spn", "asrep", "acl", "shares"])
        self.register_option("TARGET_USER", "Target user for SID/ACL lookup", default="")
        self.register_option("TARGET_GROUP", "Target group for member enumeration", default="")
        self.register_option("OUTPUT", "Output file for results", default="")

        # LDAP connection
        self._ldap_conn = None

    def run(self) -> bool:
        action = self.get_option("ACTION")
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Action: {action}")

        # Build base DN from domain
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

        actions = {
            "domain": self._enum_domain,
            "users": self._enum_users,
            "groups": self._enum_groups,
            "computers": self._enum_computers,
            "trusts": self._enum_trusts,
            "gpos": self._enum_gpos,
            "ous": self._enum_ous,
            "sid": self._convert_sid,
            "spn": self._enum_spn_users,
            "asrep": self._enum_asrep_users,
            "acl": self._enum_acls,
            "shares": self._enum_shares,
        }

        if action in actions:
            return actions[action](dc_ip, domain, user, password, base_dn)
        else:
            self.print_error(f"Unknown action: {action}")
            return False

    def _run_ldapsearch(self, dc_ip: str, domain: str, user: str, password: str,
                        base_dn: str, ldap_filter: str, attrs: str = "*") -> tuple:
        """Run ldapsearch and return results"""
        cmd = [
            "ldapsearch",
            "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", base_dn,
            ldap_filter,
            attrs
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr

    def _run_nxc(self, dc_ip: str, user: str, password: str,
                 module: str = "smb", extra_args: List[str] = None) -> tuple:
        """Run netexec command"""
        nxc_path = find_tool("nxc") or find_tool("netexec")
        if not nxc_path:
            return -1, "", "netexec/nxc not found"

        cmd = [nxc_path, module, dc_ip, "-u", user, "-p", password]
        if extra_args:
            cmd.extend(extra_args)

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr

    def _sid_to_string(self, sid_bytes: bytes) -> str:
        """Convert binary SID to string format"""
        if isinstance(sid_bytes, str):
            # Already a string, try to decode if base64
            try:
                sid_bytes = base64.b64decode(sid_bytes)
            except:
                return sid_bytes

        if len(sid_bytes) < 8:
            return ""

        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

        sub_authorities = []
        for i in range(sub_auth_count):
            offset = 8 + (i * 4)
            if offset + 4 <= len(sid_bytes):
                sub_auth = struct.unpack('<I', sid_bytes[offset:offset+4])[0]
                sub_authorities.append(str(sub_auth))

        return f"S-{revision}-{authority}-{'-'.join(sub_authorities)}"

    def _enum_domain(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate domain information"""
        self.print_status("Enumerating domain information...")

        # Get domain info via LDAP
        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(objectClass=domain)",
            "distinguishedName name dc ms-DS-MachineAccountQuota"
        )

        if ret == 0:
            self.print_good("Domain Information:")
            self.print_line(stdout)
        else:
            self.print_error(f"LDAP query failed: {stderr}")

        # Get domain controllers
        self.print_status("Enumerating Domain Controllers...")
        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            "cn dNSHostName operatingSystem"
        )

        if ret == 0:
            self.print_good("Domain Controllers:")
            self.print_line(stdout)

        return True

    def _enum_users(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate domain users"""
        self.print_status("Enumerating domain users...")

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(objectClass=user)",
            "sAMAccountName userPrincipalName description memberOf userAccountControl"
        )

        if ret == 0:
            self.print_good("Domain Users:")
            self.print_line(stdout)
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_groups(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate domain groups"""
        self.print_status("Enumerating domain groups...")

        target_group = self.get_option("TARGET_GROUP")

        if target_group:
            # Get specific group members
            ldap_filter = f"(&(objectClass=group)(cn={target_group}))"
            attrs = "member managedBy"
        else:
            ldap_filter = "(objectClass=group)"
            attrs = "cn description member"

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            ldap_filter, attrs
        )

        if ret == 0:
            self.print_good("Domain Groups:")
            self.print_line(stdout)
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_computers(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate domain computers"""
        self.print_status("Enumerating domain computers...")

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(objectClass=computer)",
            "cn dNSHostName operatingSystem operatingSystemVersion description userAccountControl"
        )

        if ret == 0:
            self.print_good("Domain Computers:")
            self.print_line(stdout)
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_trusts(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate domain trusts"""
        self.print_status("Enumerating domain trusts...")

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(objectClass=trustedDomain)",
            "cn trustPartner trustDirection trustType trustAttributes"
        )

        if ret == 0:
            self.print_good("Domain Trusts:")
            self.print_line(stdout)

            # Parse trust direction
            if "trustDirection: 1" in stdout:
                self.print_status("Trust Direction 1 = Inbound")
            if "trustDirection: 2" in stdout:
                self.print_status("Trust Direction 2 = Outbound")
            if "trustDirection: 3" in stdout:
                self.print_status("Trust Direction 3 = Bidirectional")

            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_gpos(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate Group Policy Objects"""
        self.print_status("Enumerating GPOs...")

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password,
            f"CN=Policies,CN=System,{base_dn}",
            "(objectClass=groupPolicyContainer)",
            "displayName cn gPCFileSysPath"
        )

        if ret == 0:
            self.print_good("Group Policy Objects:")
            self.print_line(stdout)
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_ous(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate Organizational Units"""
        self.print_status("Enumerating OUs...")

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(objectClass=organizationalUnit)",
            "name description"
        )

        if ret == 0:
            self.print_good("Organizational Units:")
            self.print_line(stdout)
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _convert_sid(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Convert username to SID or vice versa"""
        target = self.get_option("TARGET_USER")

        if not target:
            self.print_error("TARGET_USER is required for SID lookup")
            return False

        self.print_status(f"Looking up SID for: {target}")

        # Check if input is a SID or username
        if target.startswith("S-1-"):
            # Convert SID to name
            ldap_filter = f"(objectSid={target})"
        else:
            # Convert name to SID
            ldap_filter = f"(sAMAccountName={target})"

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            ldap_filter,
            "sAMAccountName objectSid"
        )

        if ret == 0:
            self.print_good("SID Lookup Result:")
            self.print_line(stdout)

            # Parse objectSid from output
            for line in stdout.split('\n'):
                if 'objectSid::' in line:
                    sid_b64 = line.split('::')[1].strip()
                    sid_bytes = base64.b64decode(sid_b64)
                    sid_str = self._sid_to_string(sid_bytes)
                    self.print_good(f"SID: {sid_str}")

            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_spn_users(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate users with SPNs (Kerberoastable)"""
        self.print_status("Enumerating Kerberoastable users (SPN set)...")

        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
            "sAMAccountName servicePrincipalName"
        )

        if ret == 0:
            self.print_good("Users with SPNs (Kerberoastable):")
            self.print_line(stdout)
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_asrep_users(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate users without Kerberos preauth (ASREPRoastable)"""
        self.print_status("Enumerating ASREPRoastable users...")

        # UAC flag 4194304 = DONT_REQUIRE_PREAUTH
        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            "sAMAccountName userAccountControl"
        )

        if ret == 0:
            self.print_good("ASREPRoastable Users:")
            self.print_line(stdout)
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_acls(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate ACLs for a target object"""
        target = self.get_option("TARGET_USER")

        if not target:
            self.print_error("TARGET_USER is required for ACL enumeration")
            return False

        self.print_status(f"Enumerating ACLs for: {target}")

        # Get the object's nTSecurityDescriptor
        ret, stdout, stderr = self._run_ldapsearch(
            dc_ip, domain, user, password, base_dn,
            f"(sAMAccountName={target})",
            "nTSecurityDescriptor"
        )

        if ret == 0:
            self.print_good("ACL Information:")
            self.print_line(stdout)
            self.print_warning("Note: Full ACL parsing requires BloodHound or manual analysis")
            return True

        self.print_error(f"Query failed: {stderr}")
        return False

    def _enum_shares(self, dc_ip: str, domain: str, user: str, password: str, base_dn: str) -> bool:
        """Enumerate SMB shares"""
        self.print_status("Enumerating SMB shares...")

        ret, stdout, stderr = self._run_nxc(dc_ip, user, password, "smb", ["--shares"])

        if ret == 0 or "Enumerated shares" in stdout:
            self.print_good("SMB Shares:")
            self.print_line(stdout)
            return True

        self.print_error(f"Share enumeration failed: {stderr}")
        return False

    def check(self) -> bool:
        """Check if we can reach the DC"""
        dc_ip = self.get_option("RHOSTS")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((dc_ip, 389))
            sock.close()
            return result == 0
        except:
            return False
