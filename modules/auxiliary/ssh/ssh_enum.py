"""
SSH Enumeration Module
SSH service enumeration, user enumeration, and security checking
"""

import subprocess
import shutil
import socket
from core.module_base import ModuleBase, ModuleType, Platform


class SSHEnumerator(ModuleBase):
    """
    SSH service enumeration and security assessment
    """

    def __init__(self):
        super().__init__()
        self.name = "ssh_enum"
        self.description = "SSH service enumeration and user detection"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.LINUX
        self.tags = ["ssh", "linux", "enumeration", "authentication", "user-enum"]

        # Register options
        self.register_option("RHOSTS", "Target host(s)", required=True)
        self.register_option("RPORT", "SSH port", default=22)
        self.register_option("USER_FILE", "Username wordlist for enumeration", default="")
        self.register_option("CHECK_AUTH_METHODS", "Check authentication methods", default="yes")
        self.register_option("ENUM_USERS", "Attempt user enumeration (CVE-2018-15473)", default="no")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        port = int(self.get_option("RPORT"))

        self.print_status(f"Enumerating SSH on {target}:{port}")

        # Check if port is open
        if not self._check_port(target, port):
            self.print_error(f"SSH port {port} is not open")
            return False

        self.print_good(f"SSH port {port} is open")

        # Get banner
        banner = self._get_banner(target, port)
        if banner:
            self.print_good(f"SSH Banner: {banner}")

        # Check auth methods
        if self.get_option("CHECK_AUTH_METHODS") == "yes":
            self._check_auth_methods(target, port)

        # Run nmap scripts
        self._run_nmap_ssh(target, port)

        # User enumeration if requested
        if self.get_option("ENUM_USERS") == "yes":
            self._enum_users(target, port)

        return True

    def _check_port(self, target: str, port: int) -> bool:
        """Check if SSH port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False

    def _get_banner(self, target: str, port: int) -> str:
        """Get SSH banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""

    def _check_auth_methods(self, target: str, port: int) -> None:
        """Check available authentication methods"""
        self.print_status("Checking authentication methods...")

        if shutil.which("ssh"):
            try:
                # Use -o to check auth methods
                result = subprocess.run(
                    ["ssh", "-o", "PreferredAuthentications=none",
                     "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null",
                     "-o", "BatchMode=yes",
                     "-p", str(port),
                     f"test@{target}"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # Auth methods are shown in the error output
                if "Permission denied" in result.stderr:
                    # Parse the allowed methods
                    for line in result.stderr.split("\n"):
                        if "Permission denied" in line or "authentication" in line.lower():
                            self.print_status(line.strip())
            except:
                pass

    def _run_nmap_ssh(self, target: str, port: int) -> None:
        """Run nmap SSH scripts"""
        if not shutil.which("nmap"):
            return

        self.print_status("Running nmap SSH scripts...")
        try:
            subprocess.run(
                ["nmap", "-p", str(port), "-sV",
                 "--script", "ssh-hostkey,ssh-auth-methods,ssh2-enum-algos",
                 target],
                timeout=120
            )
        except:
            pass

    def _enum_users(self, target: str, port: int) -> None:
        """Attempt SSH user enumeration"""
        self.print_status("Attempting user enumeration...")

        user_file = self.get_option("USER_FILE")
        if not user_file:
            self.print_warning("No user wordlist specified (USER_FILE)")
            self.print_status("Consider: /usr/share/wordlists/metasploit/unix_users.txt")
            return

        # Try using nmap script
        if shutil.which("nmap"):
            try:
                subprocess.run(
                    ["nmap", "-p", str(port),
                     "--script", "ssh-brute",
                     "--script-args", f"userdb={user_file}",
                     target],
                    timeout=300
                )
            except:
                pass

        # Could also try ssh-audit or other tools
        if shutil.which("ssh-audit"):
            self.print_status("Running ssh-audit...")
            try:
                subprocess.run(["ssh-audit", f"{target}:{port}"], timeout=60)
            except:
                pass

    def check(self) -> bool:
        """Check if target has SSH open"""
        target = self.get_option("RHOSTS")
        port = int(self.get_option("RPORT"))
        return self._check_port(target, port)
