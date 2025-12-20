"""
SMB Enumeration Module
Comprehensive SMB/CIFS enumeration using multiple tools
"""

import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class SMBEnumerator(ModuleBase):
    """
    SMB enumeration module supporting multiple enumeration tools
    Supports: enum4linux-ng, smbclient, crackmapexec, smbmap
    """

    def __init__(self):
        super().__init__()
        self.name = "enum4linux"
        self.description = "SMB/CIFS enumeration using multiple tools"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.NETWORK
        self.tags = ["smb", "cifs", "enumeration", "windows", "network", "shares"]
        self.references = [
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb"
        ]

        # Register options
        self.register_option("RHOSTS", "Target host(s)", required=True)
        self.register_option("RPORT", "SMB port", default=445)
        self.register_option("USER", "Username for authentication", default="")
        self.register_option("PASS", "Password for authentication", default="")
        self.register_option("DOMAIN", "Domain name", default="")
        self.register_option("TOOL", "Tool to use: enum4linux, smbclient, cme, smbmap, all",
                           default="enum4linux", choices=["enum4linux", "smbclient", "cme", "smbmap", "all"])
        self.register_option("NULL_SESSION", "Try null session", default="yes", choices=["yes", "no"])
        self.register_option("OUTPUT", "Output directory", default="./smb_results")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        tool = self.get_option("TOOL")

        self.print_status(f"Starting SMB enumeration on {target}")

        if tool == "all":
            results = []
            for t in ["enum4linux", "smbclient", "cme", "smbmap"]:
                results.append(self._run_tool(t))
            return any(results)

        return self._run_tool(tool)

    def _run_tool(self, tool: str) -> bool:
        """Run specific enumeration tool"""
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")

        if tool == "enum4linux":
            return self._run_enum4linux()
        elif tool == "smbclient":
            return self._run_smbclient()
        elif tool == "cme":
            return self._run_crackmapexec()
        elif tool == "smbmap":
            return self._run_smbmap()

        return False

    def _run_enum4linux(self) -> bool:
        """Run enum4linux-ng"""
        # Try enum4linux-ng first, fall back to enum4linux
        tool = "enum4linux-ng" if find_tool("enum4linux-ng") else "enum4linux"

        if not find_tool(tool):
            self.print_warning(f"{tool} not found, skipping")
            return False

        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")

        if tool == "enum4linux-ng":
            cmd = ["enum4linux-ng", "-A", target]
            if user:
                cmd.extend(["-u", user])
            if password:
                cmd.extend(["-p", password])
        else:
            cmd = ["enum4linux", "-a", target]
            if user:
                cmd.extend(["-u", user])
            if password:
                cmd.extend(["-p", password])

        self.print_status(f"Running {tool}...")
        return self._execute(cmd)

    def _run_smbclient(self) -> bool:
        """Run smbclient to list shares"""
        if not find_tool("smbclient"):
            self.print_warning("smbclient not found, skipping")
            return False

        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        null_session = self.get_option("NULL_SESSION") == "yes"

        cmd = ["smbclient", "-L", target]

        if null_session and not user:
            cmd.extend(["-N"])  # No password (null session)
        elif user:
            cmd.extend(["-U", f"{user}%{password}" if password else user])

        self.print_status("Running smbclient to list shares...")
        return self._execute(cmd)

    def _run_crackmapexec(self) -> bool:
        """Run crackmapexec/netexec"""
        # Try netexec first (newer), fall back to crackmapexec
        tool = None
        for t in ["nxc", "netexec", "crackmapexec", "cme"]:
            if find_tool(t):
                tool = t
                break

        if not tool:
            self.print_warning("crackmapexec/netexec not found, skipping")
            return False

        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")

        cmd = [tool, "smb", target, "--shares"]

        if user:
            cmd.extend(["-u", user])
            if password:
                cmd.extend(["-p", password])
        else:
            cmd.extend(["-u", "", "-p", ""])  # Null session

        if domain:
            cmd.extend(["-d", domain])

        self.print_status(f"Running {tool}...")
        return self._execute(cmd)

    def _run_smbmap(self) -> bool:
        """Run smbmap"""
        if not find_tool("smbmap"):
            self.print_warning("smbmap not found, skipping")
            return False

        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")

        cmd = ["smbmap", "-H", target]

        if user:
            cmd.extend(["-u", user])
            if password:
                cmd.extend(["-p", password])
        else:
            cmd.extend(["-u", "null"])  # Null session

        if domain:
            cmd.extend(["-d", domain])

        self.print_status("Running smbmap...")
        return self._execute(cmd)

    def _execute(self, cmd: list) -> bool:
        """Execute command"""
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
