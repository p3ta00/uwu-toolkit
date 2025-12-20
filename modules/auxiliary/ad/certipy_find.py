"""
Certipy AD CS Enumeration Module
Find vulnerable certificate templates (ESC1-ESC8)
"""

from core.module_base import ModuleBase, ModuleType, Platform


class CertipyFind(ModuleBase):
    """
    Certipy enumeration module for AD Certificate Services.
    Discovers certificate templates and identifies ESC vulnerabilities.
    """

    def __init__(self):
        super().__init__()
        self.name = "certipy_find"
        self.description = "Certipy AD CS enumeration - find vulnerable certificate templates"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "adcs", "certificate", "certipy", "esc1", "esc2", "esc3", "esc4", "esc8"]
        self.references = [
            "https://github.com/ly4k/Certipy",
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)

        # Certipy options
        self.register_option("VULNERABLE_ONLY", "Only show vulnerable templates",
                           default="yes", choices=["yes", "no"])
        self.register_option("OUTPUT", "Output file prefix", default="certipy_output")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        vuln_only = self.get_option("VULNERABLE_ONLY") == "yes"
        output = self.get_option("OUTPUT")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user}")
        self.print_status(f"Vulnerable Only: {vuln_only}")
        self.print_line()

        # Build command - use the certipy path in Exegol
        cmd_parts = [
            "/root/.local/share/pipx/venvs/netexec/bin/certipy",
            "find",
            "-u", f"'{user}@{domain}'",
            "-p", f"'{password}'",
            "-dc-ip", dc_ip,
            "-stdout"
        ]

        if vuln_only:
            cmd_parts.append("-vulnerable")

        cmd = " ".join(cmd_parts)
        self.print_status(f"Command: certipy find -u {user}@{domain} -p [HIDDEN] -dc-ip {dc_ip} -stdout" +
                         (" -vulnerable" if vuln_only else ""))
        self.print_line()

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=180)
        output_text = stdout + stderr

        # Parse and display results
        vulnerabilities = self._parse_output(output_text)

        if vulnerabilities:
            self.print_line()
            self.print_good(f"Found {len(vulnerabilities)} vulnerable template(s)!")
            self.print_line()
            self.print_status("Exploitation guidance:")
            for vuln in vulnerabilities:
                self._print_exploitation_guidance(vuln)
            return True
        else:
            self.print_warning("No vulnerable templates found")
            return ret == 0

    def _parse_output(self, output: str) -> list:
        """Parse certipy output and identify vulnerabilities"""
        vulnerabilities = []
        current_template = None
        in_template = False

        for line in output.split('\n'):
            stripped = line.strip()

            # Track Certificate Authorities
            if "CA Name" in line and ":" in line:
                ca_name = line.split(":", 1)[1].strip()
                self.print_good(f"Certificate Authority: {ca_name}")

            # Track templates
            if "Template Name" in line and ":" in line:
                current_template = line.split(":", 1)[1].strip()
                in_template = True
                self.print_line()
                self.print_status(f"Template: {current_template}")

            # Look for vulnerabilities
            if "[!] Vulnerabilities" in line:
                self.print_good(f"  [!] VULNERABLE")

            if "ESC" in stripped and in_template:
                vuln_type = stripped.split(":")[0].strip() if ":" in stripped else stripped
                if vuln_type.startswith("ESC"):
                    self.print_good(f"  Vulnerability: {vuln_type}")
                    vulnerabilities.append({
                        "template": current_template,
                        "vuln": vuln_type,
                        "full_line": stripped
                    })

            # Key configuration items
            if "Enrollee Supplies Subject" in line and "True" in line:
                self.print_warning(f"  {stripped}")
            if "Client Authentication" in line and "True" in line:
                self.print_status(f"  {stripped}")
            if "Enrollment Rights" in line:
                self.print_status(f"  {stripped}")
            if "User Enrollable" in line:
                self.print_good(f"  {stripped}")

        return vulnerabilities

    def _print_exploitation_guidance(self, vuln: dict):
        """Print exploitation guidance for each vulnerability type"""
        template = vuln.get("template", "Unknown")
        vuln_type = vuln.get("vuln", "Unknown")

        if "ESC1" in vuln_type:
            self.print_status(f"  [{vuln_type}] Template '{template}' - Enrollee can supply subject")
            self.print_status(f"    Exploit: use auxiliary/ad/certipy_exploit")
            self.print_status(f"             set TEMPLATE {template}")
            self.print_status(f"             set TARGET_USER Administrator")
        elif "ESC2" in vuln_type:
            self.print_status(f"  [{vuln_type}] Template '{template}' - Any Purpose EKU")
        elif "ESC3" in vuln_type:
            self.print_status(f"  [{vuln_type}] Template '{template}' - Enrollment Agent")
        elif "ESC4" in vuln_type:
            self.print_status(f"  [{vuln_type}] Template '{template}' - Vulnerable ACL")
        elif "ESC8" in vuln_type:
            self.print_status(f"  [{vuln_type}] Web Enrollment NTLM Relay")

    def check(self) -> bool:
        ret, stdout, stderr = self.run_in_exegol(
            "ls /root/.local/share/pipx/venvs/netexec/bin/certipy", timeout=10)
        return ret == 0
