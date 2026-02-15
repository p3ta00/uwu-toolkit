"""
Web Fuzzing Module - Directory and File Discovery
Supports feroxbuster, ffuf, and gobuster backends with auto-detection.
Runs directory/file fuzzing with configurable extensions, filters, and recursion.
"""

import subprocess
import shutil
import shlex
import os
import re
from typing import List, Optional, Dict
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform, find_tool
from core.wordlists import resolve_wordlist, WordlistResolver


class WebFuzz(ModuleBase):
    """
    Web fuzzing module for directory and file discovery.

    Auto mode picks the best available tool: feroxbuster > ffuf > gobuster.
    Supports recursive scanning, extension lists, response filtering, and
    multiple output formats.
    """

    # File extension presets by technology
    EXTENSIONS = {
        "php": "php,php5,php7,phtml,inc",
        "asp": "asp,aspx,ashx,asmx,config",
        "jsp": "jsp,jspx,do,action",
        "cgi": "cgi,pl,py,sh",
        "html": "html,htm,shtml",
        "txt": "txt,md,log,bak,old,swp",
        "backup": "bak,old,orig,backup,swp,save",
        "config": "conf,config,ini,xml,yaml,yml,json,env",
        "all": "php,asp,aspx,jsp,html,txt,bak,old,config,xml,json",
    }

    def __init__(self):
        super().__init__()
        self.name = "web_fuzz"
        self.description = "Web fuzzing - directory and file discovery"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.WEB
        self.tags = ["web", "fuzzing", "directories", "files", "recon", "enumeration"]
        self.references = [
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#directory-file-discovery",
        ]

        # Register options
        self.register_option("RHOSTS", "Target IP or hostname", required=True)
        self.register_option("RPORT", "Target port", default="80")
        self.register_option("URL", "Full URL override (takes precedence over RHOSTS/RPORT)", default="")
        self.register_option("WORDLIST", "Wordlist name or path (e.g., dir_medium, common)",
                             default="dir_medium")
        self.register_option("EXTENSIONS", "File extensions: preset name or comma-separated (e.g., php,txt,bak)",
                             default="")
        self.register_option("THREADS", "Number of threads", default="10")
        self.register_option("TOOL", "Backend fuzzing tool",
                             default="auto",
                             choices=["auto", "feroxbuster", "ffuf", "gobuster"])
        self.register_option("RECURSION", "Enable recursive scanning",
                             default="yes", choices=["yes", "no"])
        self.register_option("DEPTH", "Recursion depth", default="2")
        self.register_option("FILTER_CODE", "Filter response status codes (comma-sep)", default="404")
        self.register_option("FILTER_SIZE", "Filter responses by size (comma-sep)", default="")
        self.register_option("FILTER_WORDS", "Filter by word count", default="")
        self.register_option("SSL", "Use HTTPS", default="no", choices=["yes", "no"])
        self.register_option("FOLLOW_REDIRECT", "Follow redirects",
                             default="yes", choices=["yes", "no"])
        self.register_option("TIMEOUT", "Request timeout in seconds", default="10")
        self.register_option("OUTPUT", "Output file for results", default="")
        self.register_option("EXTRA_ARGS", "Additional tool arguments", default="")

    def _detect_tool(self) -> str:
        """Auto-detect the best available fuzzing tool.
        Priority: feroxbuster > ffuf > gobuster."""
        for tool in ["feroxbuster", "ffuf", "gobuster"]:
            if find_tool(tool):
                return tool
            # Check in Exegol
            ret, stdout, _ = self.run_in_exegol(f"which {tool}", timeout=10)
            if ret == 0 and stdout.strip():
                return tool
        self.print_warning("No fuzzing tool found locally or in Exegol. Defaulting to ffuf.")
        return "ffuf"

    def _resolve_wordlist(self, name: str) -> str:
        """Resolve wordlist name to a full path."""
        resolved = resolve_wordlist(name, fallback="common")
        if resolved:
            return resolved
        if os.path.exists(name):
            return name
        # Try common Exegol paths
        exegol_paths = [
            f"/opt/lists/seclists/Discovery/Web-Content/{name}",
            f"/usr/share/wordlists/seclists/Discovery/Web-Content/{name}",
            f"/usr/share/wordlists/{name}",
        ]
        for p in exegol_paths:
            if os.path.exists(p):
                return p
        self.print_warning(f"Wordlist '{name}' not found locally. Passing to Exegol as-is.")
        # Return a sensible default that should exist in Exegol
        return resolve_wordlist("common") or "/usr/share/wordlists/dirb/common.txt"

    def _resolve_extensions(self, ext: str) -> str:
        """Resolve extension preset name or return raw extension string."""
        if not ext:
            return ""
        if ext in self.EXTENSIONS:
            return self.EXTENSIONS[ext]
        # Clean up user input (remove dots, spaces)
        return ext.replace(".", "").replace(" ", "")

    def _build_url(self) -> str:
        """Build the target URL from options."""
        url = self.get_option("URL")
        if url:
            return url.rstrip("/")

        rhosts = self.get_option("RHOSTS")
        rport = self.get_option("RPORT")
        use_ssl = self.get_option("SSL") == "yes"

        protocol = "https" if use_ssl else "http"
        if (rport == "80" and not use_ssl) or (rport == "443" and use_ssl):
            return f"{protocol}://{rhosts}"
        return f"{protocol}://{rhosts}:{rport}"

    def run(self) -> bool:
        url = self._build_url()
        tool = self.get_option("TOOL")
        wordlist = self._resolve_wordlist(self.get_option("WORDLIST"))
        extensions = self._resolve_extensions(self.get_option("EXTENSIONS"))
        threads = self.get_option("THREADS")
        recursion = self.get_option("RECURSION") == "yes"
        depth = self.get_option("DEPTH")
        timeout = self.get_option("TIMEOUT")
        follow = self.get_option("FOLLOW_REDIRECT") == "yes"
        filter_code = self.get_option("FILTER_CODE")
        filter_size = self.get_option("FILTER_SIZE")
        filter_words = self.get_option("FILTER_WORDS")
        output = self.get_option("OUTPUT")
        extra_args = self.get_option("EXTRA_ARGS")

        # Auto-detect tool
        if tool == "auto":
            tool = self._detect_tool()

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Web Fuzzer - Directory/File Discovery")
        self.print_good("=" * 60)
        self.print_status(f"Target: {url}")
        self.print_status(f"Tool: {tool}")
        self.print_status(f"Wordlist: {wordlist}")
        self.print_status(f"Extensions: {extensions or 'none'}")
        self.print_status(f"Threads: {threads}")
        self.print_status(f"Recursion: {'yes (depth=' + depth + ')' if recursion else 'no'}")
        self.print_line()

        if tool == "feroxbuster":
            return self._run_feroxbuster(url, wordlist, extensions, threads, recursion,
                                          depth, timeout, follow, filter_code, filter_size,
                                          output, extra_args)
        elif tool == "ffuf":
            return self._run_ffuf(url, wordlist, extensions, threads, timeout, follow,
                                   filter_code, filter_size, filter_words, output, extra_args)
        elif tool == "gobuster":
            return self._run_gobuster(url, wordlist, extensions, threads, timeout, follow,
                                       filter_code, output, extra_args)
        else:
            self.print_error(f"Unsupported tool: {tool}")
            return False

    def _run_feroxbuster(self, url, wordlist, extensions, threads, recursion,
                          depth, timeout, follow, filter_code, filter_size,
                          output, extra_args) -> bool:
        """Run directory fuzzing with feroxbuster."""
        self.print_good("[Feroxbuster Directory Scan]")

        cmd = (
            f"feroxbuster "
            f"-u {shlex.quote(url)} "
            f"-w {shlex.quote(wordlist)} "
            f"-t {threads} "
            f"--timeout {timeout} "
            f"--no-state"
        )

        if extensions:
            cmd += f" -x {extensions}"

        if recursion:
            cmd += f" -d {depth}"
        else:
            cmd += " -n"

        if not follow:
            cmd += " --dont-follow-redirects"

        if filter_code:
            for code in filter_code.split(","):
                cmd += f" -C {code.strip()}"

        if filter_size:
            for size in filter_size.split(","):
                cmd += f" -S {size.strip()}"

        if output:
            cmd += f" -o {shlex.quote(output)}"

        if extra_args:
            cmd += f" {extra_args}"

        self.print_status(f"Command: {cmd}")
        self.print_line()

        ret = self.run_in_exegol_stream(cmd, timeout=1800)

        self.print_line()
        if output:
            self.print_good(f"Results saved to: {output}")

        self.print_status("Manual command for reference:")
        self.print_line(f"  {cmd}")

        return ret == 0

    def _run_ffuf(self, url, wordlist, extensions, threads, timeout, follow,
                   filter_code, filter_size, filter_words, output, extra_args) -> bool:
        """Run directory fuzzing with ffuf."""
        self.print_good("[ffuf Directory Scan]")

        cmd = (
            f"ffuf "
            f"-u {shlex.quote(url + '/FUZZ')} "
            f"-w {shlex.quote(wordlist)} "
            f"-t {threads} "
            f"-timeout {timeout} "
            f"-ic -c"
        )

        if extensions:
            # ffuf wants extensions with dots
            ext_with_dots = ",".join(f".{e}" if not e.startswith(".") else e for e in extensions.split(","))
            cmd += f" -e {ext_with_dots}"

        if follow:
            cmd += " -r"

        if filter_code:
            cmd += f" -fc {filter_code}"

        if filter_size:
            cmd += f" -fs {filter_size}"

        if filter_words:
            cmd += f" -fw {filter_words}"

        if output:
            cmd += f" -o {shlex.quote(output)} -of json"

        if extra_args:
            cmd += f" {extra_args}"

        self.print_status(f"Command: {cmd}")
        self.print_line()

        ret = self.run_in_exegol_stream(cmd, timeout=1800)

        self.print_line()
        if output:
            self.print_good(f"Results saved to: {output}")
            self._parse_ffuf_results(output)

        self.print_status("Manual command for reference:")
        self.print_line(f"  {cmd}")

        return ret == 0

    def _run_gobuster(self, url, wordlist, extensions, threads, timeout, follow,
                       filter_code, output, extra_args) -> bool:
        """Run directory fuzzing with gobuster."""
        self.print_good("[Gobuster Directory Scan]")

        cmd = (
            f"gobuster dir "
            f"-u {shlex.quote(url)} "
            f"-w {shlex.quote(wordlist)} "
            f"-t {threads} "
            f"--timeout {timeout}s"
        )

        if extensions:
            cmd += f" -x {extensions}"

        if follow:
            cmd += " -r"

        if filter_code:
            cmd += f" -b {filter_code}"

        if output:
            cmd += f" -o {shlex.quote(output)}"

        if extra_args:
            cmd += f" {extra_args}"

        self.print_status(f"Command: {cmd}")
        self.print_line()

        ret = self.run_in_exegol_stream(cmd, timeout=1800)

        self.print_line()
        if output:
            self.print_good(f"Results saved to: {output}")

        self.print_status("Manual command for reference:")
        self.print_line(f"  {cmd}")

        return ret == 0

    def _parse_ffuf_results(self, output_file):
        """Parse ffuf JSON output and display summary."""
        try:
            import json
            with open(output_file, 'r') as f:
                data = json.load(f)

            results = data.get("results", [])
            if not results:
                return

            self.print_line()
            self.print_good(f"Found {len(results)} result(s):")
            self.print_line(f"{'Path':<50} {'Status':<8} {'Size':<10} {'Words':<8}")
            self.print_line("-" * 76)

            for r in results:
                path = r.get("input", {}).get("FUZZ", "unknown")
                status = r.get("status", 0)
                size = r.get("length", 0)
                words_count = r.get("words", 0)
                self.print_good(f"/{path:<49} {status:<8} {size:<10} {words_count:<8}")

        except Exception:
            pass

    def check(self) -> bool:
        """Check if at least one fuzzing tool is available."""
        for tool in ["feroxbuster", "ffuf", "gobuster"]:
            if find_tool(tool):
                self.print_good(f"{tool} found locally")
                return True

        # Check Exegol
        for tool in ["feroxbuster", "ffuf", "gobuster"]:
            ret, stdout, _ = self.run_in_exegol(f"which {tool}", timeout=10)
            if ret == 0 and stdout.strip():
                self.print_good(f"{tool} found in Exegol")
                return True

        self.print_error("No fuzzing tool found (need feroxbuster, ffuf, or gobuster)")
        return False
