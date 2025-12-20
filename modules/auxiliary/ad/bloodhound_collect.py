"""
BloodHound Collection Module
Collect AD data using bloodhound-python or RustHound for offline analysis
"""

import os
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class BloodHoundCollector(ModuleBase):
    """
    Collect Active Directory data using bloodhound-python or RustHound.
    Outputs JSON files for import into BloodHound CE.
    Supports both local execution and Exegol container execution.
    """

    def __init__(self):
        super().__init__()
        self.name = "bloodhound_collect"
        self.description = "Collect AD data for BloodHound analysis"
        self.author = "UwU Toolkit"
        self.version = "1.1.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "bloodhound", "rusthound", "enumeration", "collection", "domain"]
        self.references = [
            "https://github.com/fox-it/BloodHound.py",
            "https://github.com/NH-RED-TEAM/RustHound",
            "https://bloodhound.readthedocs.io/"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)
        self.register_option("USER", "Domain username", default="")
        self.register_option("PASS", "Domain password or NTLM hash", default="")

        # Tool selection
        self.register_option("RUSTHOUND", "Use RustHound instead of bloodhound-python",
                           default="no", choices=["yes", "no"])

        # Collection options
        self.register_option("COLLECTION", "Collection method",
                           default="all",
                           choices=["all", "default", "dconly", "group", "localadmin",
                                   "session", "trusts", "acl", "container", "objectprops", "gpo"])
        self.register_option("ZIP", "Compress output to ZIP file",
                           default="yes", choices=["yes", "no"])
        self.register_option("LDAPS", "Use LDAPS (port 636)",
                           default="no", choices=["yes", "no"])

        # RustHound specific
        self.register_option("ADCS", "Collect ADCS/PKI data (RustHound only)",
                           default="yes", choices=["yes", "no"])

        # Output
        self.register_option("OUTPUT", "Output directory for JSON files",
                           default="bloodhound_output")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        use_rusthound = self.get_option("RUSTHOUND") == "yes"

        if use_rusthound:
            return self._run_rusthound()
        else:
            return self._run_bloodhound_python()

    def _run_bloodhound_python(self) -> bool:
        """Run collection using bloodhound-python"""
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        collection = self.get_option("COLLECTION")
        do_zip = self.get_option("ZIP") == "yes"
        use_ldaps = self.get_option("LDAPS") == "yes"
        output_dir = self.get_option("OUTPUT")

        self.print_status(f"Collector: bloodhound-python")
        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user if user else '(anonymous)'}")
        self.print_status(f"Collection: {collection}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        # Build command parts
        cmd_parts = ["bloodhound-python"]

        # Authentication
        if user:
            cmd_parts.extend(["-u", user])
            if password:
                # Check if it's a hash (32 hex chars)
                if len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password):
                    cmd_parts.extend(["--hashes", f":{password}"])
                else:
                    cmd_parts.extend(["-p", password])

        cmd_parts.extend(["-d", domain])
        cmd_parts.extend(["-dc", dc_ip])
        cmd_parts.extend(["-ns", dc_ip])
        cmd_parts.extend(["-c", collection])

        if use_ldaps:
            cmd_parts.append("--use-ldaps")

        if do_zip:
            cmd_parts.append("--zip")

        # Display command (hide password)
        display_parts = cmd_parts.copy()
        if password and "-p" in display_parts:
            idx = display_parts.index("-p")
            if idx + 1 < len(display_parts):
                display_parts[idx + 1] = "[HIDDEN]"
        self.print_status(f"Command: {' '.join(display_parts)}")
        self.print_line()

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Try local first, then Exegol
        bh_path = find_tool("bloodhound-python") or find_tool("bloodhound.py")
        if bh_path:
            self.print_status("Using local bloodhound-python")
            cmd_parts.extend(["-op", f"{output_dir}/"])
            ret, stdout, stderr = self.run_command(cmd_parts, timeout=600)
            output_text = stdout + stderr
        else:
            self.print_status("Using Exegol container for bloodhound-python")
            cmd = " ".join(f"'{p}'" if ' ' in p else p for p in cmd_parts)
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=600)
            output_text = stdout + stderr

        # Parse output
        self._parse_bloodhound_output(output_text)

        if ret == 0 or "done" in output_text.lower():
            self.print_line()
            self.print_good("BloodHound collection completed!")
            if do_zip:
                self.print_status(f"ZIP file saved to: {output_dir}/")
            self.print_status("Import the output into BloodHound CE for analysis")
            return True
        else:
            self.print_error("BloodHound collection failed")
            if output_text:
                self.print_error(output_text)
            return False

    def _run_rusthound(self) -> bool:
        """Run collection using RustHound"""
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        collection = self.get_option("COLLECTION")
        do_zip = self.get_option("ZIP") == "yes"
        use_ldaps = self.get_option("LDAPS") == "yes"
        adcs = self.get_option("ADCS") == "yes"
        output_dir = self.get_option("OUTPUT")

        self.print_status(f"Collector: RustHound")
        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user if user else '(anonymous)'}")
        self.print_status(f"Collection: {collection}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        # Build command
        cmd_parts = ["rusthound"]

        # Domain and DC
        cmd_parts.extend(["-d", domain])
        cmd_parts.extend(["-i", dc_ip])

        # Authentication
        if user:
            cmd_parts.extend(["-u", user])
            if password:
                # Check if it's a hash (32 hex chars)
                if len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password):
                    cmd_parts.extend(["-H", password])
                else:
                    cmd_parts.extend(["-p", password])

        # Collection method
        if collection != "all":
            cmd_parts.extend(["-c", collection])

        # LDAPS
        if use_ldaps:
            cmd_parts.append("--ldaps")

        # DNS server
        cmd_parts.extend(["--dns-tcp", "-n", dc_ip])

        # BloodHound CE output format
        cmd_parts.append("--bloodhound-ce")

        # ADCS collection
        if adcs:
            cmd_parts.append("--adcs")

        # ZIP output
        if do_zip:
            cmd_parts.append("--zip")

        # Output directory
        cmd_parts.extend(["-o", output_dir])

        # Build command string for display
        cmd = " ".join(cmd_parts)

        # Display command (hide password)
        display_cmd = cmd.replace(f"-p {password}", "-p [HIDDEN]") if password and not (
            len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password)
        ) else cmd
        self.print_status(f"Command: {display_cmd}")
        self.print_line()

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Try local first, then Exegol
        rh_path = find_tool("rusthound")
        if rh_path:
            self.print_status("Using local RustHound")
            ret, stdout, stderr = self.run_command(cmd_parts, timeout=600)
            output_text = stdout + stderr
        else:
            self.print_status("Using Exegol container for RustHound")
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=600)
            output_text = stdout + stderr

        # Parse and display output
        self._parse_rusthound_output(output_text)

        if ret == 0 or "json file(s) written" in output_text.lower():
            self.print_line()
            self.print_good("RustHound collection completed!")
            if do_zip:
                self.print_status(f"ZIP file saved to: {output_dir}/")
            self.print_status("Import the output into BloodHound CE for analysis")
            return True
        else:
            self.print_error("RustHound collection failed")
            if "error" in output_text.lower():
                self.print_error(output_text)
            return False

    def _parse_bloodhound_output(self, output: str) -> None:
        """Parse bloodhound-python output"""
        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            # Status updates
            if "INFO" in stripped:
                if "Connecting to LDAP" in stripped:
                    self.print_status("Connecting to LDAP server...")
                elif "Found AD domain" in stripped:
                    self.print_good(f"  {stripped.split('INFO')[-1].strip()}")
                elif "Enumerating" in stripped:
                    self.print_status(f"  Enumerating {stripped.split('Enumerating')[-1].strip()}")
                elif "Done" in stripped:
                    self.print_good(f"  {stripped.split('INFO')[-1].strip()}")
                elif "users" in stripped.lower() or "computers" in stripped.lower() or "groups" in stripped.lower():
                    self.print_good(f"  {stripped.split('INFO')[-1].strip()}")
                elif "Compressing" in stripped or "zip" in stripped.lower():
                    self.print_good(f"  {stripped.split('INFO')[-1].strip()}")

            elif "WARNING" in stripped:
                self.print_warning(f"  {stripped.split('WARNING')[-1].strip()}")

            elif "ERROR" in stripped:
                self.print_error(f"  {stripped.split('ERROR')[-1].strip()}")

            elif ".json" in stripped or ".zip" in stripped:
                self.print_good(f"  Output: {stripped}")

    def _parse_rusthound_output(self, output: str) -> None:
        """Parse RustHound output"""
        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            # Progress indicators
            if "Starting" in stripped or "Collecting" in stripped:
                self.print_status(stripped)
            elif "users" in stripped.lower() or "computers" in stripped.lower():
                self.print_good(f"  {stripped}")
            elif "groups" in stripped.lower() or "ous" in stripped.lower():
                self.print_good(f"  {stripped}")
            elif "gpos" in stripped.lower() or "containers" in stripped.lower():
                self.print_good(f"  {stripped}")
            elif "trusts" in stripped.lower() or "acl" in stripped.lower():
                self.print_good(f"  {stripped}")
            elif "adcs" in stripped.lower() or "certificate" in stripped.lower():
                self.print_good(f"  {stripped}")
            elif "json" in stripped.lower() or "zip" in stripped.lower():
                self.print_good(f"  {stripped}")
            elif "error" in stripped.lower():
                self.print_error(f"  {stripped}")
            elif "warning" in stripped.lower():
                self.print_warning(f"  {stripped}")
            elif "written" in stripped.lower():
                self.print_good(stripped)

    def check(self) -> bool:
        """Check if collector is available"""
        use_rusthound = self.get_option("RUSTHOUND") == "yes"

        if use_rusthound:
            # Check RustHound
            if find_tool("rusthound"):
                return True
            ret, stdout, stderr = self.run_in_exegol("which rusthound", timeout=10)
            return ret == 0
        else:
            # Check bloodhound-python
            if find_tool("bloodhound-python") or find_tool("bloodhound.py"):
                return True
            ret, stdout, stderr = self.run_in_exegol("which bloodhound-python", timeout=10)
            return ret == 0
