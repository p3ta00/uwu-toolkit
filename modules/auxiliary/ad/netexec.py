"""
NetExec Integration Module
Multi-protocol credential validation and enumeration
Runs inside Exegol container for tool availability
"""

import re
from typing import List, Dict, Optional, Tuple
from core.module_base import ModuleBase, ModuleType, Platform


class NetExec(ModuleBase):
    """
    NetExec (nxc) integration for credential validation and enumeration.
    Supports SMB, LDAP, WinRM, RDP, MSSQL, SSH protocols.
    Automatically runs inside Exegol container.
    """

    def __init__(self):
        super().__init__()
        self.name = "netexec"
        self.description = "NetExec credential validation and enumeration"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "credentials", "smb", "ldap", "winrm", "enumeration", "netexec", "nxc"]
        self.references = [
            "https://github.com/Pennyw0rth/NetExec",
            "https://www.netexec.wiki/"
        ]

        # Core options
        self.register_option("RHOSTS", "Target host(s) - IP, range, or CIDR", required=True)
        self.register_option("DOMAIN", "Domain name", default="")
        self.register_option("USER", "Username (empty for null session)", default="")
        self.register_option("PASS", "Password, hash, or password file", default="")

        # Authentication options
        self.register_option("AUTH_TYPE", "Authentication type",
                           default="password",
                           choices=["password", "hash", "aesKey"])
        self.register_option("PROTOCOL", "Protocol to use",
                           default="smb",
                           choices=["smb", "ldap", "winrm", "rdp", "mssql", "ssh", "wmi"])

        # Action options
        self.register_option("ACTION", "Action to perform",
                           default="check",
                           choices=["check", "shares", "users", "groups", "sessions",
                                   "disks", "loggedon", "localgroups", "pass-pol",
                                   "rid-brute", "spider", "execute", "sam", "lsa", "ntds"])

        # Execution options (for ACTION=execute)
        self.register_option("EXEC_TYPE", "Execution type: cmd (-x) or powershell (-X)",
                           default="cmd",
                           choices=["cmd", "powershell", "ps"])
        self.register_option("EXECUTE", "Command to execute on target", default="")
        self.register_option("EXEC_METHOD", "Execution method (smbexec, wmiexec, atexec, mmcexec) - SMB only",
                           default="",
                           choices=["", "smbexec", "wmiexec", "atexec", "mmcexec"])

        # Spider options (for ACTION=spider)
        self.register_option("SPIDER_SHARE", "Share to spider", default="")
        self.register_option("SPIDER_CONTENT", "Spider for content matching regex", default="")

        # Module options
        self.register_option("NXC_MODULE", "NetExec module to run", default="")
        self.register_option("NXC_MODULE_OPTIONS", "Module options (key=value,key=value)", default="")

        # Output
        self.register_option("OUTPUT", "Output file for results", default="")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container name (auto-detect if empty)", default="")

        # RDP options
        self.register_option("RDP_CONFIRM", "Auto-confirm RDP execution prompt",
                           default="yes", choices=["yes", "no"])

        # Streaming output
        self.register_option("STREAM", "Stream output in real-time",
                           default="yes", choices=["yes", "no"])

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        auth_type = self.get_option("AUTH_TYPE")
        protocol = self.get_option("PROTOCOL")
        action = self.get_option("ACTION")
        # Auto-detect: if EXECUTE is set, switch to execute action
        execute_cmd = self.get_option("EXECUTE")
        if execute_cmd and action == "check":
            action = "execute"

        self.print_status(f"Target: {target}")
        if domain:
            self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user if user else '(null session)'}")
        self.print_status(f"Protocol: {protocol.upper()}")
        self.print_status(f"Action: {action}")
        self.print_line()

        # Build base command
        cmd_parts = ["NetExec", protocol, target]

        # Add authentication (support null/guest/anonymous sessions)
        if user:
            cmd_parts.extend(["-u", user])
        else:
            cmd_parts.extend(["-u", "''"])  # Empty string for null session

        if auth_type == "hash" and password:
            cmd_parts.extend(["-H", password])
        elif auth_type == "aesKey" and password:
            cmd_parts.extend(["--aes-key", password])
        else:
            if password:
                # Quote password to handle special characters
                cmd_parts.extend(["-p", f"'{password}'"])
            else:
                cmd_parts.extend(["-p", "''"])  # Empty string for null session

        # Add domain if specified
        if domain:
            cmd_parts.extend(["-d", domain])

        # Build action-specific arguments
        action_args = self._build_action_args(action)
        cmd_parts.extend(action_args)

        # Add module if specified
        nxc_module = self.get_option("NXC_MODULE")
        if nxc_module:
            cmd_parts.extend(["-M", nxc_module])
            module_opts = self.get_option("NXC_MODULE_OPTIONS")
            if module_opts:
                cmd_parts.extend(["-o", module_opts])

        # Execute in Exegol
        cmd = " ".join(cmd_parts)

        # Auto-confirm RDP execution if enabled
        if protocol == "rdp" and action == "execute" and self.get_option("RDP_CONFIRM") == "yes":
            cmd = f"echo y | {cmd}"

        self.print_status(f"Executing: {cmd}")
        self.print_line()

        # Use streaming or buffered output
        if self.get_option("STREAM") == "yes":
            ret = self.run_in_exegol_stream(cmd)
            output = ""  # Output already printed
        else:
            ret, stdout, stderr = self.run_in_exegol(cmd)
            output = stdout + stderr
            if output:
                self._parse_and_display(output, action)

        # Save output if requested
        output_file = self.get_option("OUTPUT")
        if output_file and output:
            try:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.print_good(f"Output saved to: {output_file}")
            except Exception as e:
                self.print_warning(f"Could not save output: {e}")

        # Determine success based on output
        if "[+]" in output or "Pwn3d!" in output:
            return True
        elif "[-]" in output and "STATUS_LOGON_FAILURE" in output:
            self.print_error("Authentication failed")
            return False

        return ret == 0

    def _build_action_args(self, action: str) -> List[str]:
        """Build action-specific command arguments"""
        args = []

        if action == "check":
            # Just validate credentials, no extra args needed
            pass
        elif action == "shares":
            args.append("--shares")
        elif action == "users":
            args.append("--users")
        elif action == "groups":
            args.append("--groups")
        elif action == "sessions":
            args.append("--sessions")
        elif action == "disks":
            args.append("--disks")
        elif action == "loggedon":
            args.append("--loggedon-users")
        elif action == "localgroups":
            args.append("--local-groups")
        elif action == "pass-pol":
            args.append("--pass-pol")
        elif action == "rid-brute":
            args.append("--rid-brute")
        elif action == "spider":
            share = self.get_option("SPIDER_SHARE")
            if share:
                args.extend(["--spider", share])
            content = self.get_option("SPIDER_CONTENT")
            if content:
                args.extend(["--content", "--pattern", content])
        elif action == "execute":
            execute_cmd = self.get_option("EXECUTE")
            if execute_cmd:
                exec_type = self.get_option("EXEC_TYPE")
                exec_flag = "-X" if exec_type in ["powershell", "ps"] else "-x"
                # Quote the command to handle special characters
                escaped_cmd = execute_cmd.replace("'", "'\\''")
                args.extend([exec_flag, f"'{escaped_cmd}'"])
                # --exec-method only works with SMB protocol and only if specified
                protocol = self.get_option("PROTOCOL")
                exec_method = self.get_option("EXEC_METHOD")
                if protocol == "smb" and exec_method:
                    args.extend(["--exec-method", exec_method])
        elif action == "sam":
            args.append("--sam")
        elif action == "lsa":
            args.append("--lsa")
        elif action == "ntds":
            args.append("--ntds")

        return args

    def _parse_and_display(self, output: str, action: str) -> None:
        """Parse NetExec output and display with highlighting"""
        for line in output.split('\n'):
            if not line.strip():
                continue

            # Highlight important findings
            if "Pwn3d!" in line:
                self.print_good(f"🎯 ADMIN ACCESS: {line}")
            elif "[+]" in line:
                # Check for specific important findings
                if "STATUS_ACCOUNT_DISABLED" in line:
                    self.print_warning(line)
                elif "Administrator" in line or "Domain Admin" in line:
                    self.print_good(f"⭐ {line}")
                else:
                    self.print_good(line)
            elif "[-]" in line:
                self.print_error(line)
            elif "[*]" in line:
                self.print_status(line.replace("[*]", "").strip())
            elif "READ" in line or "WRITE" in line:
                # Share access
                self.print_good(f"📁 {line}")
            else:
                self.print_line(f"    {line}")

    def check(self) -> bool:
        """Verify NetExec is available in Exegol"""
        ret, stdout, stderr = self.run_in_exegol("which NetExec || which nxc")
        return ret == 0
