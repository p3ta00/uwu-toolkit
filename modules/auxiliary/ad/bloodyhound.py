"""
BloodyAD ACL Enumeration and Abuse Module
Enumerate writable objects and dangerous ACLs in Active Directory
"""

import os
from typing import List, Optional
from core.module_base import ModuleBase, ModuleType, Platform


class BloodyADEnum(ModuleBase):
    """
    BloodyAD integration for ACL enumeration and abuse.
    Finds writable objects, dangerous permissions, and attack paths.
    """

    def __init__(self):
        super().__init__()
        self.name = "bloody_enum"
        self.description = "BloodyAD ACL enumeration - find writable objects and attack paths"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "acl", "enumeration", "bloodyhound", "bloodyad", "permissions"]
        self.references = [
            "https://github.com/CravateRouge/bloodyAD",
            "https://cravaterouge.github.io/bloodyAD/"
        ]

        # Core options - inherit from globals
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)

        # Action options
        self.register_option("ACTION", "Enumeration action",
                           default="writable",
                           choices=["writable", "owned", "membership", "object", "children"])
        self.register_option("TARGET", "Target object for specific queries (user/group/computer)", default="")
        self.register_option("DETAIL", "Show detailed output", default="yes", choices=["yes", "no"])

        # Output
        self.register_option("OUTPUT", "Output file for results", default="")
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        action = self.get_option("ACTION")
        target = self.get_option("TARGET")
        detail = self.get_option("DETAIL") == "yes"
        output_file = self.get_option("OUTPUT")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user}")
        self.print_status(f"Action: {action}")
        if target:
            self.print_status(f"Target Object: {target}")
        self.print_line()

        # Build bloodyAD command
        cmd_parts = [
            "bloodyAD",
            "-u", user,
            "-p", f"'{password}'",
            "-d", domain,
            "--host", dc_ip,
            "get"
        ]

        if action == "writable":
            cmd_parts.append("writable")
            if detail:
                cmd_parts.append("--detail")
        elif action == "owned":
            cmd_parts.append("owned")
        elif action == "membership":
            if not target:
                self.print_error("TARGET required for membership action")
                return False
            cmd_parts.extend(["membership", target])
        elif action == "object":
            if not target:
                self.print_error("TARGET required for object action")
                return False
            cmd_parts.extend(["object", target])
        elif action == "children":
            if not target:
                self.print_error("TARGET required for children action")
                return False
            cmd_parts.extend(["children", target])

        cmd = " ".join(cmd_parts)
        self.print_status(f"Command: bloodyAD -u {user} -p [HIDDEN] -d {domain} --host {dc_ip} get {action}")
        self.print_line()

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        # Parse and display results
        findings = self._parse_output(output, action)

        # Save output
        if output_file and output:
            try:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.print_good(f"Output saved to: {output_file}")
            except Exception as e:
                self.print_warning(f"Could not save: {e}")

        return len(findings) > 0 or ret == 0

    def _parse_output(self, output: str, action: str) -> List[str]:
        """Parse bloodyAD output and highlight important findings"""
        findings = []
        current_dn = ""

        for line in output.split('\n'):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Track distinguished names
            if line_stripped.startswith("distinguishedName:"):
                current_dn = line_stripped.split(":", 1)[1].strip()
                self.print_line()
                self.print_good(f"Object: {current_dn}")
                findings.append(current_dn)
            # Highlight dangerous permissions
            elif any(perm in line_stripped for perm in ["WRITE", "CREATE_CHILD", "DELETE", "FULL_CONTROL"]):
                self.print_warning(f"  {line_stripped}")
            elif "GenericAll" in line_stripped or "GenericWrite" in line_stripped:
                self.print_good(f"  [DANGEROUS] {line_stripped}")
            elif "WriteDacl" in line_stripped or "WriteOwner" in line_stripped:
                self.print_good(f"  [DANGEROUS] {line_stripped}")
            elif "ForceChangePassword" in line_stripped:
                self.print_good(f"  [DANGEROUS] {line_stripped}")
            elif line_stripped.startswith("member"):
                self.print_status(f"  {line_stripped}")
            elif ":" in line_stripped:
                self.print_line(f"  {line_stripped}")

        if findings:
            self.print_line()
            self.print_good(f"Found {len(findings)} objects with permissions")

        return findings

    def check(self) -> bool:
        ret, stdout, stderr = self.run_in_exegol("which bloodyAD", timeout=10)
        return ret == 0
