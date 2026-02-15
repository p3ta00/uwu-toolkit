"""
BloodHound Collection Module
Collect AD data using bloodhound-python or RustHound for offline analysis
"""

import os
import shlex
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
            "https://github.com/SpecterOps/BloodHound",
            "https://github.com/fox-it/BloodHound.py",
            "https://github.com/NH-RED-TEAM/RustHound",
            "https://bloodhound.readthedocs.io/"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DC_HOST", "Domain Controller hostname (e.g., DC01) - auto-detected if empty", default="")
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


    def run(self) -> bool:
        use_rusthound = self.get_option("RUSTHOUND") == "yes"

        if use_rusthound:
            return self._run_rusthound()
        else:
            return self._run_bloodhound_python()

    def _run_bloodhound_python(self) -> bool:
        """Run collection using bloodhound-ce.py (BloodHound CE collector)"""
        dc_ip = self.get_option("RHOSTS")
        dc_host = self.get_option("DC_HOST")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        collection = self.get_option("COLLECTION")
        do_zip = self.get_option("ZIP") == "yes"
        use_ldaps = self.get_option("LDAPS") == "yes"
        output_dir = self.get_option("OUTPUT")

        # Build DC FQDN - auto-detect if DC_HOST not provided
        dc_fqdn = None
        if dc_host:
            if '.' in dc_host:
                dc_fqdn = dc_host  # Already FQDN
            else:
                dc_fqdn = f"{dc_host}.{domain}"  # Construct FQDN
        else:
            # Auto-detect DC hostname and FQDN since bloodhound-ce.py requires it
            detected_host, detected_fqdn = self._detect_dc_hostname(dc_ip, domain)
            if detected_fqdn:
                dc_fqdn = detected_fqdn
            elif detected_host:
                dc_fqdn = f"{detected_host}.{domain}"

        # Validate DOMAIN against DC FQDN when available
        if dc_fqdn and '.' in dc_fqdn:
            fqdn_domain = '.'.join(dc_fqdn.split('.')[1:])
            if fqdn_domain and fqdn_domain.lower() != domain.lower():
                self.print_warning(f"DOMAIN mismatch: set to '{domain}' but DC FQDN indicates '{fqdn_domain}'")
                self.print_warning(f"Auto-correcting DOMAIN to '{fqdn_domain}'")
                domain = fqdn_domain

        self.print_status(f"Collector: bloodhound-ce.py")
        if dc_fqdn:
            self.print_status(f"Target DC: {dc_fqdn} ({dc_ip})")
        else:
            self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user if user else '(anonymous)'}")
        self.print_status(f"Collection: {collection}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        # Build command for bloodhound-ce.py
        # Syntax: bloodhound-ce.py --zip -c All -d domain -u user -p pass -dc DC.domain -ns IP
        cmd_parts = ["bloodhound-ce.py"]

        # ZIP first (before other options)
        if do_zip:
            cmd_parts.append("--zip")

        # Collection method (capitalize for bloodhound-ce.py)
        collection_map = {
            "all": "All",
            "default": "Default",
            "dconly": "DCOnly",
            "group": "Group",
            "localadmin": "LocalAdmin",
            "session": "Session",
            "trusts": "Trusts",
            "acl": "ACL",
            "container": "Container",
            "objectprops": "ObjectProps",
            "gpo": "GPOLocalGroup"
        }
        coll_value = collection_map.get(collection.lower(), "All")
        cmd_parts.extend(["-c", coll_value])

        # Domain
        cmd_parts.extend(["-d", domain])

        # Authentication
        if user:
            cmd_parts.extend(["-u", user])
            if password:
                # Check if it's a hash (32 hex chars)
                if len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password):
                    cmd_parts.extend(["--hashes", f":{password}"])
                else:
                    cmd_parts.extend(["-p", password])

        # DC FQDN (required for bloodhound-ce.py)
        if dc_fqdn:
            cmd_parts.extend(["-dc", dc_fqdn])
        else:
            # If no DC_HOST provided, try to construct from domain
            self.print_warning("DC_HOST not set - bloodhound-ce.py requires DC FQDN")
            self.print_status("Set DC_HOST to the DC hostname (e.g., DC01)")

        # Nameserver (DC IP)
        cmd_parts.extend(["-ns", dc_ip])

        if use_ldaps:
            cmd_parts.append("--use-ldaps")

        # Build display command (hide password)
        display_parts = cmd_parts.copy()
        if password and "-p" in display_parts:
            idx = display_parts.index("-p")
            if idx + 1 < len(display_parts):
                display_parts[idx + 1] = "'[HIDDEN]'"

        # Quote values with special chars for display
        display_cmd = " ".join(display_parts)
        self.print_status(f"Command: {display_cmd}")
        self.print_line()

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Build shell-safe command with proper quoting for special chars
        cmd = " ".join(shlex.quote(p) for p in cmd_parts)

        # Run in Exegol from the output directory so files are saved there
        self.print_status("Running bloodhound-ce.py in Exegol...")
        full_cmd = f"cd {output_dir} && {cmd}"
        ret, stdout, stderr = self.run_in_exegol(full_cmd, timeout=600)
        output_text = stdout + stderr

        # Parse output
        self._parse_bloodhound_output(output_text)

        # Check for known failure patterns even if ret == 0
        error_patterns = ["failure to authenticate", "invalidcredentials", "could not authenticate",
                          "kdc_err_preauth_failed", "connection refused", "lifetimetimeout"]
        has_error = any(pat in output_text.lower() for pat in error_patterns)

        if has_error:
            self.print_line()
            self.print_error("BloodHound collection failed")
            for line in output_text.split('\n'):
                stripped = line.strip()
                if stripped and ("error" in stripped.lower() or "failure" in stripped.lower() or "could not" in stripped.lower()):
                    self.print_error(f"  {stripped}")
            return False
        elif ret == 0 or "done" in output_text.lower() or "written" in output_text.lower():
            self.print_line()
            self.print_good("BloodHound collection completed!")

            # Find and display the output file
            if do_zip:
                ret2, zip_files, _ = self.run_in_exegol(f"ls -t {output_dir}/*bloodhound*.zip 2>/dev/null | head -1", timeout=10)
                if zip_files and zip_files.strip():
                    self.print_good(f"ZIP file: {zip_files.strip()}")
                else:
                    self.print_status(f"ZIP file saved to: {output_dir}/")

            self.print_status("Import the output into BloodHound CE for analysis")
            return True
        else:
            self.print_line()
            self.print_error("BloodHound collection failed")
            if output_text:
                for line in output_text.split('\n'):
                    if line.strip():
                        self.print_error(f"  {line.strip()}")
            return False

    def _run_rusthound(self) -> bool:
        """Run collection using RustHound"""
        dc_ip = self.get_option("RHOSTS")
        dc_host = self.get_option("DC_HOST")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        collection = self.get_option("COLLECTION")
        do_zip = self.get_option("ZIP") == "yes"
        use_ldaps = self.get_option("LDAPS") == "yes"
        adcs = self.get_option("ADCS") == "yes"
        output_dir = self.get_option("OUTPUT")

        # Validate DOMAIN against DC_HOST FQDN if available
        if dc_host and '.' in dc_host:
            fqdn_domain = '.'.join(dc_host.split('.')[1:])
            if fqdn_domain and fqdn_domain.lower() != domain.lower():
                self.print_warning(f"DOMAIN mismatch: set to '{domain}' but DC FQDN indicates '{fqdn_domain}'")
                self.print_warning(f"Auto-correcting DOMAIN to '{fqdn_domain}'")
                domain = fqdn_domain

        self.print_status(f"Collector: RustHound")
        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user if user else '(anonymous)'}")
        self.print_status(f"Collection: {collection}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        # Build command - use long-form args for compatibility
        cmd_parts = ["rusthound"]

        # Domain and DC
        cmd_parts.extend(["--domain", domain])
        cmd_parts.extend(["--ldapip", dc_ip])

        # Authentication
        if user:
            cmd_parts.extend(["--ldapusername", user])
            if password:
                # Check if it's a hash (32 hex chars)
                if len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password):
                    cmd_parts.extend(["--ldappassword-hash", password])
                else:
                    cmd_parts.extend(["--ldappassword", password])

        # Collection method - only add if not "all" (all is default)
        if collection != "all":
            cmd_parts.extend(["--collection", collection])

        # LDAPS
        if use_ldaps:
            cmd_parts.append("--ldaps")

        # DNS server
        cmd_parts.extend(["--dns-tcp", "--name-server", dc_ip])

        # ADCS collection (if supported)
        if adcs:
            cmd_parts.append("--adcs")

        # ZIP output
        if do_zip:
            cmd_parts.append("--zip")

        # Output directory
        cmd_parts.extend(["-o", output_dir])

        # Build shell-safe command string (for run_in_exegol which goes through bash)
        shell_cmd = " ".join(shlex.quote(p) for p in cmd_parts)

        # Display command (hide password)
        display_parts = cmd_parts.copy()
        if password:
            is_hash = len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password)
            flag = "--ldappassword-hash" if is_hash else "--ldappassword"
            if flag in display_parts:
                idx = display_parts.index(flag)
                if idx + 1 < len(display_parts):
                    display_parts[idx + 1] = "[HIDDEN]"
        self.print_status(f"Command: {' '.join(display_parts)}")
        self.print_line()

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Try local first, then Exegol
        rh_path = find_tool("rusthound")

        def run_rusthound(parts, cmd_str):
            if rh_path:
                self.print_status("Using local RustHound")
                ret, stdout, stderr = self.run_command(parts, timeout=600)
            else:
                self.print_status("Using Exegol container for RustHound")
                ret, stdout, stderr = self.run_in_exegol(cmd_str, timeout=600)
            return ret, stdout + stderr

        ret, output_text = run_rusthound(cmd_parts, shell_cmd)

        # Check if LDAP signing is required and retry with LDAPS
        if "strongerAuthRequired" in output_text or "integrity checking" in output_text.lower():
            if not use_ldaps:
                self.print_warning("LDAP signing required - retrying with LDAPS...")
                cmd_parts.insert(cmd_parts.index("--dns-tcp"), "--ldaps")
                shell_cmd = " ".join(shlex.quote(p) for p in cmd_parts)
                ret, output_text = run_rusthound(cmd_parts, shell_cmd)

        # Parse and display output
        self._parse_rusthound_output(output_text)

        # Check for known failure patterns even if ret == 0
        error_patterns = ["invalidcredentials", "failed to authenticate", "strongerauthrequired",
                          "connection refused", "network unreachable", "no such host"]
        has_error = any(pat in output_text.lower() for pat in error_patterns)

        if has_error:
            self.print_line()
            self.print_error("RustHound collection failed")
            for line in output_text.split('\n'):
                if "error" in line.lower() or "failed" in line.lower():
                    self.print_error(f"  {line.strip()}")
            return False
        elif ret == 0 or "json file(s) written" in output_text.lower():
            self.print_line()
            self.print_good("RustHound collection completed!")
            if do_zip:
                self.print_status(f"ZIP file saved to: {output_dir}/")
            self.print_status("Import the output into BloodHound CE for analysis")
            return True
        else:
            self.print_line()
            self.print_error("RustHound collection failed")
            if output_text.strip():
                for line in output_text.split('\n'):
                    if line.strip():
                        self.print_error(f"  {line.strip()}")
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

    def _detect_dc_hostname(self, dc_ip: str, domain: str) -> tuple:
        """Try to auto-detect DC hostname using various methods.

        Returns: (hostname, fqdn) tuple. fqdn may be None if only hostname detected.
        """
        import re

        self.print_status(f"Auto-detecting DC hostname for {dc_ip}...")

        # Method 1: Try nmap reverse DNS (works without auth, returns full FQDN)
        ret, stdout, stderr = self.run_in_exegol(
            f"nmap -Pn -sn {dc_ip} 2>/dev/null | grep 'Nmap scan report'", timeout=15)
        output = stdout + stderr
        # Parse: "Nmap scan report for DC-STELLAR.stellarcomms.local (10.0.27.48)"
        nmap_match = re.search(r'Nmap scan report for ([^\s(]+)', output)
        if nmap_match:
            fqdn = nmap_match.group(1)
            hostname = fqdn.split('.')[0]
            if hostname and hostname != dc_ip:
                # Return full FQDN if it has domain parts (hostname.domain)
                if '.' in fqdn:
                    self.print_good(f"Detected DC: {fqdn}")
                    return hostname, fqdn
                else:
                    self.print_good(f"Detected DC hostname: {hostname}")
                    return hostname, None

        # Method 2: Try NetExec SMB scan
        ret, stdout, stderr = self.run_in_exegol(f"nxc smb {dc_ip}", timeout=15)
        output = stdout + stderr
        # Parse: SMB  10.1.61.93  445  DC01  Windows... (name:DC01)
        name_match = re.search(r'\(name:([^)]+)\)', output)
        if name_match:
            hostname = name_match.group(1)
            self.print_good(f"Detected DC hostname: {hostname}")
            return hostname, None

        # Method 3: Try nmblookup
        ret, stdout, stderr = self.run_in_exegol(f"nmblookup -A {dc_ip}", timeout=10)
        output = stdout + stderr
        for line in output.split('\n'):
            if '<00>' in line and 'GROUP' not in line:
                hostname = line.split()[0].strip()
                if hostname:
                    self.print_good(f"Detected DC hostname: {hostname}")
                    return hostname, None

        self.print_warning("Could not auto-detect DC hostname")
        return "", None

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
            # Check bloodhound-ce.py (preferred) or bloodhound-python
            if find_tool("bloodhound-ce.py") or find_tool("bloodhound-python"):
                return True
            ret, stdout, stderr = self.run_in_exegol("which bloodhound-ce.py", timeout=10)
            return ret == 0
