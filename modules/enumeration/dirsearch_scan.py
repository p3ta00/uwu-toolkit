"""
Directory/File Enumeration Module
Web content discovery with multiple tool support
"""

import subprocess
import shutil
import os
from core.module_base import ModuleBase, ModuleType, Platform


class DirSearchScanner(ModuleBase):
    """
    Web directory and file enumeration scanner
    Supports gobuster, feroxbuster, ffuf, and dirsearch
    """

    def __init__(self):
        super().__init__()
        self.name = "dirsearch_scan"
        self.description = "Web directory and file enumeration"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.WEB
        self.tags = ["web", "enumeration", "directory", "bruteforce", "dirsearch", "gobuster"]

        # Register options
        self.register_option("TARGET_URL", "Target URL (e.g., http://example.com)", required=True)
        self.register_option("WORDLIST", "Path to wordlist",
                           default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        self.register_option("TOOL", "Tool to use: gobuster, feroxbuster, ffuf, dirsearch",
                           default="auto", choices=["auto", "gobuster", "feroxbuster", "ffuf", "dirsearch"])
        self.register_option("EXTENSIONS", "File extensions to search (e.g., php,html,txt)", default="")
        self.register_option("THREADS", "Number of threads", default=50)
        self.register_option("TIMEOUT", "Request timeout in seconds", default=10)
        self.register_option("STATUS_CODES", "Status codes to include (default: 200,204,301,302,307,401,403)",
                           default="200,204,301,302,307,401,403")
        self.register_option("USER_AGENT", "Custom User-Agent string", default="")
        self.register_option("COOKIES", "Session cookies", default="")
        self.register_option("HEADERS", "Custom headers (format: Header1:Value1,Header2:Value2)", default="")
        self.register_option("PROXY", "Proxy URL (e.g., http://127.0.0.1:8080)", default="")
        self.register_option("OUTPUT", "Output file path", default="")
        self.register_option("EXTRA_ARGS", "Additional tool arguments", default="")

    def run(self) -> bool:
        target = self.get_option("TARGET_URL")
        wordlist = self.get_option("WORDLIST")
        tool = self.get_option("TOOL")

        # Validate wordlist
        if not os.path.exists(wordlist):
            self.print_error(f"Wordlist not found: {wordlist}")
            return False

        # Auto-select tool
        if tool == "auto":
            tool = self._find_best_tool()
            if not tool:
                self.print_error("No supported enumeration tool found")
                self.print_status("Install one of: gobuster, feroxbuster, ffuf, dirsearch")
                return False
            self.print_status(f"Auto-selected tool: {tool}")

        # Build and run command
        if tool == "gobuster":
            return self._run_gobuster()
        elif tool == "feroxbuster":
            return self._run_feroxbuster()
        elif tool == "ffuf":
            return self._run_ffuf()
        elif tool == "dirsearch":
            return self._run_dirsearch()

        return False

    def _find_best_tool(self) -> str:
        """Find the best available tool"""
        preference = ["feroxbuster", "gobuster", "ffuf", "dirsearch"]
        for tool in preference:
            if shutil.which(tool):
                return tool
        return ""

    def _run_gobuster(self) -> bool:
        """Run gobuster"""
        cmd = [
            "gobuster", "dir",
            "-u", self.get_option("TARGET_URL"),
            "-w", self.get_option("WORDLIST"),
            "-t", str(self.get_option("THREADS")),
            "-s", self.get_option("STATUS_CODES"),
            "--timeout", f"{self.get_option('TIMEOUT')}s",
        ]

        if self.get_option("EXTENSIONS"):
            cmd.extend(["-x", self.get_option("EXTENSIONS")])
        if self.get_option("USER_AGENT"):
            cmd.extend(["-a", self.get_option("USER_AGENT")])
        if self.get_option("COOKIES"):
            cmd.extend(["-c", self.get_option("COOKIES")])
        if self.get_option("PROXY"):
            cmd.extend(["-p", self.get_option("PROXY")])
        if self.get_option("OUTPUT"):
            cmd.extend(["-o", self.get_option("OUTPUT")])
        if self.get_option("EXTRA_ARGS"):
            cmd.extend(self.get_option("EXTRA_ARGS").split())

        return self._execute(cmd)

    def _run_feroxbuster(self) -> bool:
        """Run feroxbuster"""
        cmd = [
            "feroxbuster",
            "-u", self.get_option("TARGET_URL"),
            "-w", self.get_option("WORDLIST"),
            "-t", str(self.get_option("THREADS")),
            "--timeout", str(self.get_option("TIMEOUT")),
            "-s", self.get_option("STATUS_CODES"),
        ]

        if self.get_option("EXTENSIONS"):
            cmd.extend(["-x", self.get_option("EXTENSIONS")])
        if self.get_option("USER_AGENT"):
            cmd.extend(["-a", self.get_option("USER_AGENT")])
        if self.get_option("PROXY"):
            cmd.extend(["-p", self.get_option("PROXY")])
        if self.get_option("OUTPUT"):
            cmd.extend(["-o", self.get_option("OUTPUT")])
        if self.get_option("EXTRA_ARGS"):
            cmd.extend(self.get_option("EXTRA_ARGS").split())

        return self._execute(cmd)

    def _run_ffuf(self) -> bool:
        """Run ffuf"""
        url = self.get_option("TARGET_URL")
        if not url.endswith("/"):
            url += "/"
        url += "FUZZ"

        cmd = [
            "ffuf",
            "-u", url,
            "-w", self.get_option("WORDLIST"),
            "-t", str(self.get_option("THREADS")),
            "-timeout", str(self.get_option("TIMEOUT")),
            "-mc", self.get_option("STATUS_CODES"),
        ]

        if self.get_option("EXTENSIONS"):
            exts = self.get_option("EXTENSIONS")
            cmd.extend(["-e", f".{exts.replace(',', ',.')}"])
        if self.get_option("USER_AGENT"):
            cmd.extend(["-H", f"User-Agent: {self.get_option('USER_AGENT')}"])
        if self.get_option("COOKIES"):
            cmd.extend(["-H", f"Cookie: {self.get_option('COOKIES')}"])
        if self.get_option("PROXY"):
            cmd.extend(["-x", self.get_option("PROXY")])
        if self.get_option("OUTPUT"):
            cmd.extend(["-o", self.get_option("OUTPUT")])
        if self.get_option("EXTRA_ARGS"):
            cmd.extend(self.get_option("EXTRA_ARGS").split())

        return self._execute(cmd)

    def _run_dirsearch(self) -> bool:
        """Run dirsearch"""
        cmd = [
            "dirsearch",
            "-u", self.get_option("TARGET_URL"),
            "-w", self.get_option("WORDLIST"),
            "-t", str(self.get_option("THREADS")),
            "--timeout", str(self.get_option("TIMEOUT")),
        ]

        if self.get_option("EXTENSIONS"):
            cmd.extend(["-e", self.get_option("EXTENSIONS")])
        if self.get_option("USER_AGENT"):
            cmd.extend(["--user-agent", self.get_option("USER_AGENT")])
        if self.get_option("COOKIES"):
            cmd.extend(["--cookie", self.get_option("COOKIES")])
        if self.get_option("PROXY"):
            cmd.extend(["--proxy", self.get_option("PROXY")])
        if self.get_option("OUTPUT"):
            cmd.extend(["-o", self.get_option("OUTPUT")])
        if self.get_option("EXTRA_ARGS"):
            cmd.extend(self.get_option("EXTRA_ARGS").split())

        return self._execute(cmd)

    def _execute(self, cmd: list) -> bool:
        """Execute the command"""
        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        try:
            result = subprocess.run(cmd)
            return result.returncode == 0
        except KeyboardInterrupt:
            self.print_warning("Scan interrupted")
            return False
        except FileNotFoundError:
            self.print_error(f"Tool not found: {cmd[0]}")
            return False

    def check(self) -> bool:
        """Check if any tool is available"""
        return bool(self._find_best_tool())
