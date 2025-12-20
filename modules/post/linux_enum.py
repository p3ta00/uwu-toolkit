"""
Linux Post-Exploitation Enumeration Module
Comprehensive local enumeration for Linux systems
"""

import subprocess
import os
from core.module_base import ModuleBase, ModuleType, Platform


class LinuxEnumerator(ModuleBase):
    """
    Linux local enumeration module
    Runs comprehensive enumeration scripts on compromised Linux hosts
    """

    def __init__(self):
        super().__init__()
        self.name = "linux_enum"
        self.description = "Linux local enumeration and privilege escalation checks"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.POST
        self.platform = Platform.LINUX
        self.tags = ["linux", "enumeration", "privesc", "post-exploitation", "local"]

        # Register options
        self.register_option("SESSION", "Session/target to enumerate", default="local")
        self.register_option("OUTPUT", "Output directory for results", default="./linux_enum_results")
        self.register_option("TOOL", "Enumeration tool: linpeas, linenum, lse, manual",
                           default="manual", choices=["linpeas", "linenum", "lse", "manual", "all"])

    def run(self) -> bool:
        session = self.get_option("SESSION")
        output_dir = self.get_option("OUTPUT")
        tool = self.get_option("TOOL")

        os.makedirs(output_dir, exist_ok=True)

        if session != "local":
            self.print_warning("Remote sessions not yet implemented")
            self.print_status("Running locally instead")

        self.print_status(f"Starting Linux enumeration using {tool}")

        if tool == "all":
            self._run_manual()
            self._run_linpeas()
        elif tool == "manual":
            return self._run_manual()
        elif tool == "linpeas":
            return self._run_linpeas()
        elif tool == "linenum":
            return self._run_linenum()
        elif tool == "lse":
            return self._run_lse()

        return True

    def _run_manual(self) -> bool:
        """Run manual enumeration commands"""
        output_dir = self.get_option("OUTPUT")

        commands = [
            ("System Info", ["uname", "-a"]),
            ("OS Release", ["cat", "/etc/os-release"]),
            ("Hostname", ["hostname"]),
            ("Current User", ["id"]),
            ("All Users", ["cat", "/etc/passwd"]),
            ("Sudo Rights", ["sudo", "-l"]),
            ("SUID Binaries", ["find", "/", "-perm", "-4000", "-type", "f", "-ls"]),
            ("World Writable", ["find", "/", "-perm", "-2", "-type", "f", "-ls"]),
            ("Capabilities", ["getcap", "-r", "/"]),
            ("Cron Jobs", ["cat", "/etc/crontab"]),
            ("User Cron", ["ls", "-la", "/var/spool/cron/crontabs/"]),
            ("Network Info", ["ip", "a"]),
            ("Listening Ports", ["ss", "-tulpn"]),
            ("Running Processes", ["ps", "auxww"]),
            ("Installed Packages", ["dpkg", "-l"]),
            ("Home Directories", ["ls", "-la", "/home/"]),
            ("SSH Keys", ["find", "/home", "-name", "id_rsa"]),
            ("History Files", ["find", "/home", "-name", ".*history"]),
            ("Config Files", ["find", "/etc", "-name", "*.conf"]),
        ]

        results = []
        for name, cmd in commands:
            self.print_status(f"Running: {name}")
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                output = result.stdout or result.stderr or "(no output)"
                results.append(f"\n{'='*60}\n{name}\n{'='*60}\n{output}")
            except Exception as e:
                results.append(f"\n{'='*60}\n{name}\n{'='*60}\n[ERROR] {e}")

        # Save results
        output_file = f"{output_dir}/manual_enum.txt"
        with open(output_file, "w") as f:
            f.write("\n".join(results))

        self.print_good(f"Results saved to {output_file}")
        return True

    def _run_linpeas(self) -> bool:
        """Run linpeas enumeration script"""
        self.print_status("Running linpeas...")

        # Check for linpeas
        linpeas_paths = [
            "/usr/share/peass/linpeas/linpeas.sh",
            "/opt/linpeas/linpeas.sh",
            "./linpeas.sh",
        ]

        linpeas = None
        for path in linpeas_paths:
            if os.path.exists(path):
                linpeas = path
                break

        if not linpeas:
            self.print_warning("linpeas.sh not found locally")
            self.print_status("Downloading linpeas...")
            try:
                subprocess.run([
                    "curl", "-L", "-o", "/tmp/linpeas.sh",
                    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
                ], check=True)
                subprocess.run(["chmod", "+x", "/tmp/linpeas.sh"])
                linpeas = "/tmp/linpeas.sh"
            except:
                self.print_error("Failed to download linpeas")
                return False

        output_dir = self.get_option("OUTPUT")
        output_file = f"{output_dir}/linpeas_output.txt"

        try:
            with open(output_file, "w") as f:
                subprocess.run(
                    ["bash", linpeas],
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    timeout=600
                )
            self.print_good(f"linpeas output saved to {output_file}")
            return True
        except Exception as e:
            self.print_error(f"linpeas failed: {e}")
            return False

    def _run_linenum(self) -> bool:
        """Run LinEnum script"""
        self.print_status("Running LinEnum...")
        self.print_warning("LinEnum not yet implemented - use linpeas instead")
        return False

    def _run_lse(self) -> bool:
        """Run linux-smart-enumeration"""
        self.print_status("Running linux-smart-enumeration...")
        self.print_warning("LSE not yet implemented - use linpeas instead")
        return False

    def check(self) -> bool:
        """Check if we're on Linux"""
        import platform
        return platform.system() == "Linux"
