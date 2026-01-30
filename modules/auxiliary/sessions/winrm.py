"""
WinRM Session Module
Get interactive shell on Windows targets using Evil-WinRM
"""

import os
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class WinRM(ModuleBase):
    """
    WinRM session module using Evil-WinRM.
    Provides interactive PowerShell access to Windows targets.
    Supports password and hash authentication.
    """

    def __init__(self):
        super().__init__()
        self.name = "winrm"
        self.description = "WinRM shell session via Evil-WinRM"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["session", "winrm", "shell", "evil-winrm", "powershell", "windows"]
        self.references = [
            "https://github.com/Hackplayers/evil-winrm",
            "https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm"
        ]

        # Target options
        self.register_option("RHOSTS", "Target host IP", required=True)
        self.register_option("RPORT", "Target WinRM port", default=5985)
        self.register_option("USER", "Username", required=True)
        self.register_option("PASS", "Password or NTLM hash", required=True)

        # Auth options
        self.register_option("AUTH_TYPE", "Authentication type",
                           default="password",
                           choices=["password", "hash"])
        self.register_option("SSL", "Use SSL (port 5986)",
                           default="no", choices=["yes", "no"])

        # Script/binary options
        self.register_option("SCRIPTS", "Path to PowerShell scripts directory", default="")
        self.register_option("EXECUTABLES", "Path to executables directory for upload", default="")


    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        auth_type = self.get_option("AUTH_TYPE")
        use_ssl = self.get_option("SSL") == "yes"
        scripts_path = self.get_option("SCRIPTS")
        exe_path = self.get_option("EXECUTABLES")

        # Auto-detect SSL based on port
        if port == 5986:
            use_ssl = True

        self.print_status(f"Target: {target}:{port}")
        self.print_status(f"User: {user}")
        self.print_status(f"Auth: {auth_type}")
        self.print_status(f"SSL: {'Yes' if use_ssl else 'No'}")
        self.print_line()

        tool_path = find_tool("evil-winrm")

        if tool_path:
            # Local execution
            cmd = [tool_path, "-i", target, "-u", user]

            if auth_type == "hash":
                cmd.extend(["-H", password])
            else:
                cmd.extend(["-p", password])

            if port != 5985:
                cmd.extend(["-P", str(port)])

            if use_ssl:
                cmd.append("-S")

            if scripts_path:
                cmd.extend(["-s", scripts_path])

            if exe_path:
                cmd.extend(["-e", exe_path])

            # Display command (hide password/hash)
            display_cmd = " ".join(cmd).replace(password, "[HIDDEN]")
            self.print_status(f"Command: {display_cmd}")
            self.print_line()

            self.print_good("Starting Evil-WinRM session...")
            self.print_status("Type 'exit' to close the session")
            self.print_line()

            try:
                result = subprocess.run(cmd)
                self.print_line()
                if result.returncode == 0:
                    self.print_good("Session closed")
                else:
                    self.print_warning(f"Session ended with code {result.returncode}")
                return result.returncode == 0
            except KeyboardInterrupt:
                self.print_line()
                self.print_warning("Session interrupted")
                return True
            except Exception as e:
                self.print_error(f"Session failed: {e}")
                return False

        else:
            # Exegol execution
            self.print_status("Using Exegol for evil-winrm")

            cmd = f"evil-winrm -i {target} -u {user}"

            if auth_type == "hash":
                cmd += f" -H {password}"
            else:
                cmd += f" -p '{password}'"

            if port != 5985:
                cmd += f" -P {port}"

            if use_ssl:
                cmd += " -S"

            if scripts_path:
                cmd += f" -s {scripts_path}"

            if exe_path:
                cmd += f" -e {exe_path}"

            # Display command (hide password/hash)
            display_cmd = cmd.replace(password, "[HIDDEN]")
            self.print_status(f"Command: {display_cmd}")
            self.print_line()

            self.print_good("Starting Evil-WinRM session in Exegol...")
            self.print_status("Type 'exit' to close the session")
            self.print_line()

            ret = self.run_in_exegol_interactive(cmd)

            self.print_line()
            if ret == 0:
                self.print_good("Session closed")
            return ret == 0

    def check(self) -> bool:
        """Check if evil-winrm is available"""
        if find_tool("evil-winrm"):
            return True

        # Check Exegol
        ret, stdout, stderr = self.run_in_exegol("which evil-winrm", timeout=10)
        return ret == 0
