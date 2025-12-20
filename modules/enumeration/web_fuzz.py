"""
Web Fuzzing Module - Directory, Vhost, and Subdomain Discovery
Supports feroxbuster, ffuf, and gobuster backends

Based on methodology from:
- The Hacker Recipes
- OSCP best practices
- Bug bounty techniques
"""

import subprocess
import shutil
import os
import re
from typing import List, Optional, Dict
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform
from core.wordlists import resolve_wordlist, WordlistResolver


class WebFuzz(ModuleBase):
    """
    Web fuzzing module supporting:
    - Directory bruteforce
    - Virtual host (vhost) discovery
    - Subdomain enumeration

    Uses feroxbuster, ffuf, or gobuster as backend
    """

    # File extensions by technology
    EXTENSIONS = {
        "php": ".php,.php5,.php7,.phtml,.inc",
        "asp": ".asp,.aspx,.ashx,.asmx,.config",
        "jsp": ".jsp,.jspx,.do,.action",
        "cgi": ".cgi,.pl,.py,.sh",
        "html": ".html,.htm,.shtml",
        "txt": ".txt,.md,.log,.bak,.old,.swp",
        "backup": ".bak,.old,.orig,.backup,.swp,.save,~",
        "config": ".conf,.config,.ini,.xml,.yaml,.yml,.json,.env",
        "all": ".php,.asp,.aspx,.jsp,.html,.txt,.bak,.old,.config,.xml,.json",
    }

    def __init__(self):
        super().__init__()
        self.name = "web_fuzz"
        self.description = "Web fuzzing - directories, vhosts, subdomains"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.WEB
        self.tags = ["web", "fuzzing", "directories", "vhost", "subdomain", "recon"]

        # Register options
        self.register_option("URL", "Target URL (http://target.com)", required=True)
        self.register_option("MODE", "Fuzzing mode",
                           default="dir",
                           choices=["dir", "vhost", "subdomain", "all"])
        self.register_option("WORDLIST", "Wordlist to use (name or path)",
                           default="dir_medium")
        self.register_option("EXTENSIONS", "File extensions (name or custom)",
                           default="")
        self.register_option("THREADS", "Number of threads", default="50")
        self.register_option("TOOL", "Backend tool to use",
                           default="auto",
                           choices=["auto", "feroxbuster", "ffuf", "gobuster"])
        self.register_option("RECURSION", "Enable recursive scanning",
                           default="yes", choices=["yes", "no"])
        self.register_option("DEPTH", "Recursion depth", default="2")
        self.register_option("FILTER_SIZE", "Filter responses by size (comma-sep)", default="")
        self.register_option("FILTER_CODE", "Filter status codes (comma-sep)", default="404")
        self.register_option("FILTER_WORDS", "Filter by word count", default="")
        self.register_option("OUTPUT", "Output directory", default="./web_fuzz_results")
        self.register_option("DOMAIN", "Domain for vhost/subdomain mode", default="")
        self.register_option("TIMEOUT", "Request timeout in seconds", default="10")
        self.register_option("FOLLOW_REDIRECT", "Follow redirects", default="yes", choices=["yes", "no"])

    def run(self) -> bool:
        url = self.get_option("URL").rstrip("/")
        mode = self.get_option("MODE")
        tool = self.get_option("TOOL")
        output_dir = self.get_option("OUTPUT")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Web Fuzzer")
        self.print_good("=" * 60)
        self.print_status(f"Target: {url}")
        self.print_status(f"Mode: {mode}")
        self.print_line()

        # Detect tool
        if tool == "auto":
            tool = self._detect_tool()

        self.print_status(f"Using: {tool}")

        # Run appropriate mode
        if mode == "dir":
            return self._fuzz_directories(url, tool, output_dir, timestamp)
        elif mode == "vhost":
            return self._fuzz_vhosts(url, tool, output_dir, timestamp)
        elif mode == "subdomain":
            return self._fuzz_subdomains(url, tool, output_dir, timestamp)
        elif mode == "all":
            self._fuzz_directories(url, tool, output_dir, timestamp)
            self._fuzz_vhosts(url, tool, output_dir, timestamp)
            return True

        return False

    def _detect_tool(self) -> str:
        """Detect available fuzzing tool"""
        for tool in ["feroxbuster", "ffuf", "gobuster"]:
            paths = [f"/opt/tools/bin/{tool}", f"/opt/tools/{tool}/{tool}", f"/usr/bin/{tool}"]
            for path in paths:
                if os.path.exists(path):
                    return tool
            if shutil.which(tool):
                return tool
        return "ffuf"  # Fallback

    def _get_tool_path(self, tool: str) -> str:
        """Get full path to tool"""
        paths = [f"/opt/tools/bin/{tool}", f"/opt/tools/{tool}/{tool}"]
        for path in paths:
            if os.path.exists(path):
                return path
        return shutil.which(tool) or tool

    def _get_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path using cross-platform resolver"""
        resolved = resolve_wordlist(wordlist, fallback="common")
        if resolved:
            return resolved
        # Fallback to direct path if exists
        if os.path.exists(wordlist):
            return wordlist
        self.print_warning(f"Wordlist '{wordlist}' not found, using common.txt fallback")
        return resolve_wordlist("common") or "/usr/share/wordlists/dirb/common.txt"

    def _get_extensions(self, ext: str) -> str:
        """Resolve extension preset to string"""
        if not ext:
            return ""
        if ext in self.EXTENSIONS:
            return self.EXTENSIONS[ext]
        return ext

    def _fuzz_directories(self, url: str, tool: str, output_dir: str, timestamp: str) -> bool:
        """Directory bruteforce"""
        self.print_line()
        self.print_good("[Directory Fuzzing]")
        self.print_line("-" * 40)

        wordlist = self._get_wordlist(self.get_option("WORDLIST"))
        extensions = self._get_extensions(self.get_option("EXTENSIONS"))
        threads = self.get_option("THREADS")
        recursion = self.get_option("RECURSION") == "yes"
        depth = self.get_option("DEPTH")
        timeout = self.get_option("TIMEOUT")
        follow = self.get_option("FOLLOW_REDIRECT") == "yes"
        filter_code = self.get_option("FILTER_CODE")
        filter_size = self.get_option("FILTER_SIZE")
        filter_words = self.get_option("FILTER_WORDS")

        # Parse target for output filename
        target_clean = re.sub(r'[^a-zA-Z0-9]', '_', url)
        output_file = f"{output_dir}/{target_clean}_{timestamp}_dirs"

        tool_path = self._get_tool_path(tool)

        if tool == "feroxbuster":
            cmd = self._build_feroxbuster_cmd(url, wordlist, extensions, threads, recursion,
                                               depth, timeout, follow, filter_code, filter_size,
                                               output_file)
        elif tool == "ffuf":
            cmd = self._build_ffuf_dir_cmd(url, wordlist, extensions, threads, timeout,
                                           follow, filter_code, filter_size, filter_words,
                                           output_file)
        else:  # gobuster
            cmd = self._build_gobuster_dir_cmd(url, wordlist, extensions, threads, timeout,
                                               follow, filter_code, output_file)

        # Replace tool name with full path
        cmd[0] = tool_path

        self.print_status(f"Wordlist: {wordlist}")
        self.print_status(f"Extensions: {extensions or 'none'}")
        self.print_status(f"Command: {' '.join(cmd[:10])}...")
        self.print_line()

        return self._run_tool(cmd)

    def _build_feroxbuster_cmd(self, url: str, wordlist: str, extensions: str, threads: str,
                                recursion: bool, depth: str, timeout: str, follow: bool,
                                filter_code: str, filter_size: str, output_file: str) -> List[str]:
        """Build feroxbuster command"""
        cmd = [
            "feroxbuster",
            "-u", url,
            "-w", wordlist,
            "-t", threads,
            "--timeout", timeout,
            "-o", f"{output_file}.txt",
            "--no-state",
        ]

        if extensions:
            cmd.extend(["-x", extensions.replace(".", "")])

        if recursion:
            cmd.extend(["-d", depth])
        else:
            cmd.extend(["-n"])  # No recursion

        if not follow:
            cmd.append("-r")  # Don't follow redirects (feroxbuster follows by default)

        if filter_code:
            for code in filter_code.split(","):
                cmd.extend(["-C", code.strip()])

        if filter_size:
            for size in filter_size.split(","):
                cmd.extend(["-S", size.strip()])

        return cmd

    def _build_ffuf_dir_cmd(self, url: str, wordlist: str, extensions: str, threads: str,
                            timeout: str, follow: bool, filter_code: str, filter_size: str,
                            filter_words: str, output_file: str) -> List[str]:
        """Build ffuf directory command"""
        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-t", threads,
            "-timeout", timeout,
            "-o", f"{output_file}.json",
            "-of", "json",
            "-ic",  # Ignore comments in wordlist
        ]

        if extensions:
            cmd.extend(["-e", extensions])

        if follow:
            cmd.append("-r")

        if filter_code:
            cmd.extend(["-fc", filter_code])

        if filter_size:
            cmd.extend(["-fs", filter_size])

        if filter_words:
            cmd.extend(["-fw", filter_words])

        return cmd

    def _build_gobuster_dir_cmd(self, url: str, wordlist: str, extensions: str, threads: str,
                                timeout: str, follow: bool, filter_code: str, output_file: str) -> List[str]:
        """Build gobuster directory command"""
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", threads,
            "--timeout", f"{timeout}s",
            "-o", f"{output_file}.txt",
        ]

        if extensions:
            cmd.extend(["-x", extensions.lstrip(".")])

        if follow:
            cmd.append("-r")

        if filter_code:
            # Gobuster uses -b for exclude status codes
            cmd.extend(["-b", filter_code])

        return cmd

    def _fuzz_vhosts(self, url: str, tool: str, output_dir: str, timestamp: str) -> bool:
        """Virtual host fuzzing"""
        self.print_line()
        self.print_good("[VHost Fuzzing]")
        self.print_line("-" * 40)

        domain = self.get_option("DOMAIN")
        if not domain:
            # Try to extract domain from URL
            match = re.search(r'https?://([^/:]+)', url)
            if match:
                domain = match.group(1)
            else:
                self.print_error("DOMAIN is required for vhost fuzzing")
                return False

        wordlist = self._get_wordlist("vhosts")
        threads = self.get_option("THREADS")
        filter_size = self.get_option("FILTER_SIZE")
        filter_words = self.get_option("FILTER_WORDS")

        target_clean = re.sub(r'[^a-zA-Z0-9]', '_', domain)
        output_file = f"{output_dir}/{target_clean}_{timestamp}_vhosts"

        tool_path = self._get_tool_path(tool)

        # Get baseline response size first
        self.print_status(f"Target domain: {domain}")
        self.print_status("Getting baseline response for filtering...")

        if tool == "ffuf":
            cmd = [
                tool_path,
                "-u", url,
                "-H", f"Host: FUZZ.{domain}",
                "-w", wordlist,
                "-t", threads,
                "-o", f"{output_file}.json",
                "-of", "json",
                "-ic",
            ]

            if filter_size:
                cmd.extend(["-fs", filter_size])
            if filter_words:
                cmd.extend(["-fw", filter_words])

            # Auto-calibrate if no filters specified
            if not filter_size and not filter_words:
                cmd.append("-ac")

        elif tool == "gobuster":
            cmd = [
                tool_path, "vhost",
                "-u", url,
                "-w", wordlist,
                "-t", threads,
                "-o", f"{output_file}.txt",
                "--append-domain",
            ]
        else:
            # Feroxbuster doesn't have vhost mode, use ffuf
            self.print_warning("Feroxbuster doesn't support vhost mode, using ffuf")
            return self._fuzz_vhosts_ffuf(url, domain, wordlist, threads, output_file)

        self.print_status(f"Command: {' '.join(cmd[:10])}...")
        self.print_line()

        return self._run_tool(cmd)

    def _fuzz_vhosts_ffuf(self, url: str, domain: str, wordlist: str, threads: str, output_file: str) -> bool:
        """VHost fuzzing with ffuf fallback"""
        tool_path = self._get_tool_path("ffuf")

        cmd = [
            tool_path,
            "-u", url,
            "-H", f"Host: FUZZ.{domain}",
            "-w", wordlist,
            "-t", threads,
            "-o", f"{output_file}.json",
            "-of", "json",
            "-ac",  # Auto-calibrate
            "-ic",
        ]

        return self._run_tool(cmd)

    def _fuzz_subdomains(self, url: str, tool: str, output_dir: str, timestamp: str) -> bool:
        """Subdomain enumeration via DNS"""
        self.print_line()
        self.print_good("[Subdomain Fuzzing]")
        self.print_line("-" * 40)

        domain = self.get_option("DOMAIN")
        if not domain:
            match = re.search(r'https?://([^/:]+)', url)
            if match:
                domain = match.group(1)
            else:
                self.print_error("DOMAIN is required for subdomain fuzzing")
                return False

        wordlist = self._get_wordlist("subdomains")
        threads = self.get_option("THREADS")

        target_clean = re.sub(r'[^a-zA-Z0-9]', '_', domain)
        output_file = f"{output_dir}/{target_clean}_{timestamp}_subdomains"

        tool_path = self._get_tool_path(tool)

        if tool == "gobuster":
            cmd = [
                tool_path, "dns",
                "-d", domain,
                "-w", wordlist,
                "-t", threads,
                "-o", f"{output_file}.txt",
            ]
        elif tool == "ffuf":
            cmd = [
                tool_path,
                "-u", f"http://FUZZ.{domain}",
                "-w", wordlist,
                "-t", threads,
                "-o", f"{output_file}.json",
                "-of", "json",
                "-mc", "200,301,302,403",
            ]
        else:
            # Use gobuster for DNS
            self.print_warning("Using gobuster for DNS enumeration")
            cmd = [
                "gobuster", "dns",
                "-d", domain,
                "-w", wordlist,
                "-t", threads,
                "-o", f"{output_file}.txt",
            ]

        self.print_status(f"Domain: {domain}")
        self.print_status(f"Command: {' '.join(cmd[:10])}...")
        self.print_line()

        return self._run_tool(cmd)

    def _run_tool(self, cmd: List[str]) -> bool:
        """Run fuzzing tool with live output"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            found_count = 0
            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if line:
                    # Highlight findings
                    if any(code in line for code in ["200", "301", "302", "403", "500"]):
                        self.print_good(line)
                        found_count += 1
                    elif "error" in line.lower() or "timeout" in line.lower():
                        self.print_error(line)
                    else:
                        self.print_line(line)

            process.wait()

            self.print_line()
            self.print_status(f"Fuzzing complete. Found {found_count} potential results.")
            return process.returncode == 0

        except FileNotFoundError:
            self.print_error(f"Tool not found: {cmd[0]}")
            return False
        except Exception as e:
            self.print_error(f"Error running fuzzer: {e}")
            return False

    def check(self) -> bool:
        """Check if at least one fuzzing tool is available"""
        for tool in ["feroxbuster", "ffuf", "gobuster"]:
            if shutil.which(tool) or os.path.exists(f"/opt/tools/bin/{tool}"):
                return True
        self.print_error("No fuzzing tool found (need feroxbuster, ffuf, or gobuster)")
        return False
