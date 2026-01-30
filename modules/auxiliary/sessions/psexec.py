"""
PSExec Session Module
Get interactive shell on Windows targets using Impacket's psexec.py
"""

import os
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class PSExec(ModuleBase):
    """
    PSExec session module using Impacket.
    Provides interactive shell access to Windows targets.
    Supports password and hash authentication.
    """

    def __init__(self):
        super().__init__()
        self.name = "psexec"
        self.description = "PSExec shell session via Impacket"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["session", "psexec", "shell", "impacket", "smb", "windows"]
        self.references = [
            "https://github.com/fortra/impacket",
            "https://www.thehacker.recipes/ad/movement/smbexec"
        ]

        # Target options
        self.register_option("RHOSTS", "Target host IP", required=True)
        self.register_option("RPORT", "Target SMB port", default=445)
        self.register_option("DOMAIN", "Domain name", default="")
        self.register_option("USER", "Username", required=True)
        self.register_option("PASS", "Password or NTLM hash", required=True)

        # Auth options
        self.register_option("AUTH_TYPE", "Authentication type",
                           default="password",
                           choices=["password", "hash"])

        # Execution options
        self.register_option("COMMAND", "Command to execute (empty = interactive shell)", default="")
        self.register_option("CODEC", "Output codec", default="437")
        self.register_option("SERVICE_NAME", "Custom service name (random if empty)", default="")

        # Alternative exec methods
        self.register_option("EXEC_METHOD", "Execution method",
                           default="psexec",
                           choices=["psexec", "smbexec", "wmiexec", "atexec", "dcomexec"])


    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        auth_type = self.get_option("AUTH_TYPE")
        command = self.get_option("COMMAND")
        codec = self.get_option("CODEC")
        service_name = self.get_option("SERVICE_NAME")
        exec_method = self.get_option("EXEC_METHOD")

        # Map exec method to tool name
        tool_map = {
            "psexec": "psexec.py",
            "smbexec": "smbexec.py",
            "wmiexec": "wmiexec.py",
            "atexec": "atexec.py",
            "dcomexec": "dcomexec.py",
        }
        tool_name = tool_map.get(exec_method, "psexec.py")

        self.print_status(f"Target: {target}:{port}")
        self.print_status(f"Method: {exec_method}")
        if domain:
            self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user}")
        self.print_status(f"Auth: {auth_type}")
        if command:
            self.print_status(f"Command: {command}")
        else:
            self.print_status("Mode: Interactive shell")
        self.print_line()

        # Build target string: domain/user:pass@target or user:pass@target
        if domain:
            target_str = f"{domain}/{user}"
        else:
            target_str = user

        # Build command
        tool_path = find_tool(tool_name)

        if tool_path:
            # Local execution
            cmd = [tool_path]

            # Add credentials
            if auth_type == "hash":
                cmd.extend(["-hashes", f":{password}"])
                cmd.append(f"{target_str}@{target}")
            else:
                cmd.append(f"{target_str}:{password}@{target}")

            # Add port if non-standard
            if port != 445:
                cmd.extend(["-port", str(port)])

            # Add codec
            cmd.extend(["-codec", codec])

            # Add service name for psexec/smbexec
            if service_name and exec_method in ["psexec", "smbexec"]:
                cmd.extend(["-service-name", service_name])

            # Add command if specified
            if command:
                cmd.append(command)

            # Display command (hide password)
            display_cmd = " ".join(cmd).replace(password, "[HIDDEN]")
            self.print_status(f"Command: {display_cmd}")
            self.print_line()

            # Run interactively
            self.print_good(f"Starting {exec_method} session...")
            self.print_status("Type 'exit' to close the session")
            self.print_line()

            try:
                # Run in foreground for interactive shell
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
            self.print_status(f"Using Exegol for {tool_name}")

            # Build command string
            if auth_type == "hash":
                cred_str = f"-hashes :{password} {target_str}@{target}"
            else:
                cred_str = f"'{target_str}:{password}@{target}'"

            cmd = f"{tool_name} {cred_str}"

            if port != 445:
                cmd += f" -port {port}"

            cmd += f" -codec {codec}"

            if service_name and exec_method in ["psexec", "smbexec"]:
                cmd += f" -service-name {service_name}"

            if command:
                cmd += f" {command}"

            # Display command (hide password)
            display_cmd = cmd.replace(password, "[HIDDEN]")
            self.print_status(f"Command: {display_cmd}")
            self.print_line()

            self.print_good(f"Starting {exec_method} session in Exegol...")
            self.print_status("Type 'exit' to close the session")
            self.print_line()

            # Run interactively in Exegol
            ret = self.run_in_exegol_interactive(cmd)

            self.print_line()
            if ret == 0:
                self.print_good("Session closed")
            return ret == 0

    def check(self) -> bool:
        """Check if impacket tools are available"""
        exec_method = self.get_option("EXEC_METHOD")
        tool_map = {
            "psexec": "psexec.py",
            "smbexec": "smbexec.py",
            "wmiexec": "wmiexec.py",
            "atexec": "atexec.py",
            "dcomexec": "dcomexec.py",
        }
        tool_name = tool_map.get(exec_method, "psexec.py")

        if find_tool(tool_name):
            return True

        # Check Exegol
        ret, stdout, stderr = self.run_in_exegol(f"which {tool_name}", timeout=10)
        return ret == 0
