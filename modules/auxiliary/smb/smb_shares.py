"""
SMB Share Enumeration Module
Uses netexec (nxc) to enumerate SMB shares
"""

import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class SMBShareEnum(ModuleBase):
    """
    SMB share enumeration using netexec (nxc)
    Tests null, guest, and anonymous sessions when no creds provided
    """

    def __init__(self):
        super().__init__()
        self.name = "smb_shares"
        self.description = "SMB share enumeration using nxc with multi-auth testing"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.NETWORK
        self.tags = ["smb", "shares", "enumeration", "windows", "network", "nxc", "netexec"]
        self.references = [
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb"
        ]

        self.register_option("RHOSTS", "Target host(s)", required=True)
        self.register_option("RPORT", "SMB port", default=445)
        self.register_option("USER", "Username for authentication", default="")
        self.register_option("PASS", "Password for authentication", default="")
        self.register_option("DOMAIN", "Domain name", default="")

    def run(self) -> bool:
        tool = None
        for t in ["nxc", "netexec", "crackmapexec", "cme"]:
            if find_tool(t):
                tool = t
                break

        if not tool:
            self.print_error("netexec/nxc not found. Install with: apt install netexec")
            return False

        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")

        self.print_status(f"Starting SMB share enumeration on {target}")

        if user:
            self.print_status(f"Using provided credentials: {user}")
            return self._run_nxc(tool, target, user, password, domain)
        else:
            self.print_status("No credentials provided - testing multiple auth methods")
            results = []

            # Test 1: Null session (empty user/pass)
            self.print_status("[1/3] Testing null session...")
            results.append(self._run_nxc(tool, target, "", "", domain))

            # Test 2: Guest account
            self.print_status("[2/3] Testing guest account...")
            results.append(self._run_nxc(tool, target, "guest", "", domain))

            # Test 3: Anonymous account
            self.print_status("[3/3] Testing anonymous account...")
            results.append(self._run_nxc(tool, target, "anonymous", "", domain))

            return any(results)

    def _run_nxc(self, tool: str, target: str, user: str, password: str, domain: str) -> bool:
        """Run nxc with specified credentials"""
        cmd = [tool, "smb", target, "--shares"]

        if user:
            cmd.extend(["-u", user])
            cmd.extend(["-p", password if password else ""])
        else:
            cmd.extend(["-u", ""])
            cmd.extend(["-p", ""])

        if domain:
            cmd.extend(["-d", domain])

        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        try:
            result = subprocess.run(cmd)
            self.print_line()
            return result.returncode == 0
        except KeyboardInterrupt:
            self.print_warning("Interrupted")
            return False
        except FileNotFoundError:
            self.print_error(f"Tool not found: {cmd[0]}")
            return False

    def check(self) -> bool:
        """Check if target has SMB open"""
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")

        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, int(port)))
            sock.close()
            return result == 0
        except:
            return False
