"""
Web Application Scanner Module
Comprehensive web vulnerability scanning
"""

import subprocess
import shutil
import os
from core.module_base import ModuleBase, ModuleType, Platform


class WebScanner(ModuleBase):
    """
    Web application vulnerability scanner
    Integrates nikto, whatweb, nuclei, and custom checks
    """

    def __init__(self):
        super().__init__()
        self.name = "web_scanner"
        self.description = "Web application vulnerability scanner"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WEB
        self.tags = ["web", "scanner", "vulnerability", "nikto", "nuclei", "whatweb"]

        # Register options
        self.register_option("TARGET_URL", "Target URL to scan", required=True)
        self.register_option("TOOL", "Tool: whatweb, nikto, nuclei, all",
                           default="whatweb", choices=["whatweb", "nikto", "nuclei", "all"])
        self.register_option("PROXY", "Proxy URL (for Burp)", default="")
        self.register_option("USER_AGENT", "Custom User-Agent", default="")
        self.register_option("COOKIES", "Session cookies", default="")
        self.register_option("OUTPUT", "Output directory", default="./web_scan_results")
        self.register_option("AGGRESSIVE", "Aggressive mode (may be noisy)", default="no",
                           choices=["yes", "no"])

    def run(self) -> bool:
        target = self.get_option("TARGET_URL")
        tool = self.get_option("TOOL")
        output_dir = self.get_option("OUTPUT")

        os.makedirs(output_dir, exist_ok=True)

        self.print_status(f"Scanning {target}")

        if tool == "all":
            self._run_whatweb()
            self._run_nikto()
            self._run_nuclei()
            return True

        if tool == "whatweb":
            return self._run_whatweb()
        elif tool == "nikto":
            return self._run_nikto()
        elif tool == "nuclei":
            return self._run_nuclei()

        return False

    def _run_whatweb(self) -> bool:
        """Run whatweb for technology detection"""
        if not shutil.which("whatweb"):
            self.print_warning("whatweb not found, skipping")
            return False

        target = self.get_option("TARGET_URL")
        output_dir = self.get_option("OUTPUT")
        aggressive = self.get_option("AGGRESSIVE") == "yes"

        cmd = ["whatweb", target, "-v"]

        if aggressive:
            cmd.extend(["-a", "3"])
        else:
            cmd.extend(["-a", "1"])

        if self.get_option("PROXY"):
            cmd.extend(["--proxy", self.get_option("PROXY")])

        if self.get_option("USER_AGENT"):
            cmd.extend(["--user-agent", self.get_option("USER_AGENT")])

        output_file = f"{output_dir}/whatweb.txt"
        cmd.extend(["--log-verbose", output_file])

        self.print_status("Running whatweb...")
        return self._execute(cmd)

    def _run_nikto(self) -> bool:
        """Run nikto for vulnerability scanning"""
        if not shutil.which("nikto"):
            self.print_warning("nikto not found, skipping")
            return False

        target = self.get_option("TARGET_URL")
        output_dir = self.get_option("OUTPUT")

        cmd = ["nikto", "-h", target]

        if self.get_option("PROXY"):
            cmd.extend(["-useproxy", self.get_option("PROXY")])

        output_file = f"{output_dir}/nikto.txt"
        cmd.extend(["-o", output_file])

        self.print_status("Running nikto (this may take a while)...")
        return self._execute(cmd)

    def _run_nuclei(self) -> bool:
        """Run nuclei for template-based scanning"""
        if not shutil.which("nuclei"):
            self.print_warning("nuclei not found, skipping")
            return False

        target = self.get_option("TARGET_URL")
        output_dir = self.get_option("OUTPUT")
        aggressive = self.get_option("AGGRESSIVE") == "yes"

        cmd = ["nuclei", "-u", target]

        if aggressive:
            cmd.extend(["-severity", "info,low,medium,high,critical"])
        else:
            cmd.extend(["-severity", "medium,high,critical"])

        if self.get_option("PROXY"):
            cmd.extend(["-proxy", self.get_option("PROXY")])

        if self.get_option("HEADERS"):
            for header in self.get_option("HEADERS").split(","):
                cmd.extend(["-H", header])

        output_file = f"{output_dir}/nuclei.txt"
        cmd.extend(["-o", output_file])

        self.print_status("Running nuclei...")
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
        """Check if target is reachable"""
        import urllib.request
        target = self.get_option("TARGET_URL")
        try:
            urllib.request.urlopen(target, timeout=10)
            return True
        except:
            return False
