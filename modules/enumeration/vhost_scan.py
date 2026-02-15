"""
VHost Scanner - Automated Virtual Host Discovery
Discovers virtual hosts using gobuster vhost, ffuf, or curl-based brute forcing.
Supports smart auto-calibration to filter false positives.
"""

import subprocess
import shutil
import shlex
import re
import json
import os
from collections import Counter
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class VHostScanner(ModuleBase):
    """
    Automated virtual host discovery using ffuf or gobuster.

    Phase 1: Calibration run to detect baseline response (auto mode)
    Phase 2: Full scan with auto-detected or manual filters

    Supports gobuster vhost mode and ffuf -H "Host: FUZZ.domain" mode.
    Parses results for valid vhosts by filtering on response code and size.
    """

    def __init__(self):
        super().__init__()
        self.name = "vhost_scan"
        self.description = "Automated vhost discovery with smart filtering"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.WEB
        self.tags = ["web", "enumeration", "vhost", "subdomain", "ffuf", "gobuster", "virtualhost"]
        self.references = [
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/vhost-fuzzing",
        ]

        self.requires_tools = []  # Checked dynamically

        self.register_option("RHOSTS", "Target IP address", required=True)
        self.register_option("DOMAIN", "Base domain (e.g., htb.local)", required=True)
        self.register_option("WORDLIST", "Subdomain/vhost wordlist",
                             default="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        self.register_option("RPORT", "Target port", default="80")
        self.register_option("SSL", "Use HTTPS", default="no", choices=["yes", "no"])
        self.register_option("THREADS", "Number of threads", default="10")
        self.register_option("TOOL", "Fuzzing tool to use",
                             default="auto", choices=["auto", "ffuf", "gobuster", "curl"])
        self.register_option("CALIBRATION_SIZE", "Number of requests for auto-calibration", default="10")
        self.register_option("FILTER_MODE", "Filter mode: auto, size, status, words, lines",
                             default="auto", choices=["auto", "size", "status", "words", "lines"])
        self.register_option("OUTPUT", "Output file for results", default="")
        self.register_option("EXTRA_ARGS", "Additional tool arguments", default="")

    def _detect_tool(self) -> str:
        """Detect the best available fuzzing tool. Prefers ffuf > gobuster > curl."""
        for tool in ["ffuf", "gobuster"]:
            if find_tool(tool):
                return tool
            # Check inside Exegol
            ret, stdout, _ = self.run_in_exegol(f"which {tool}", timeout=10)
            if ret == 0 and stdout.strip():
                return tool
        # curl is always available
        return "curl"

    def run(self) -> bool:
        target_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        wordlist = self.get_option("WORDLIST")
        port = self.get_option("RPORT")
        use_ssl = self.get_option("SSL") == "yes"
        threads = self.get_option("THREADS")
        tool = self.get_option("TOOL")
        calibration_size = int(self.get_option("CALIBRATION_SIZE"))
        filter_mode = self.get_option("FILTER_MODE")
        output = self.get_option("OUTPUT")
        extra_args = self.get_option("EXTRA_ARGS")

        # Auto-detect tool
        if tool == "auto":
            tool = self._detect_tool()

        # Build base URL
        protocol = "https" if use_ssl else "http"
        if (port == "80" and not use_ssl) or (port == "443" and use_ssl):
            base_url = f"{protocol}://{target_ip}"
        else:
            base_url = f"{protocol}://{target_ip}:{port}"

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  VHost Scanner - Virtual Host Discovery")
        self.print_good("=" * 60)
        self.print_status(f"Target: {base_url}")
        self.print_status(f"Domain: FUZZ.{domain}")
        self.print_status(f"Wordlist: {wordlist}")
        self.print_status(f"Tool: {tool}")
        self.print_status(f"Threads: {threads}")
        self.print_line()

        if tool == "ffuf":
            return self._run_ffuf(base_url, domain, wordlist, threads,
                                  calibration_size, filter_mode, output, extra_args)
        elif tool == "gobuster":
            return self._run_gobuster(base_url, domain, wordlist, threads, output, extra_args)
        elif tool == "curl":
            return self._run_curl(base_url, domain, wordlist, output)
        else:
            self.print_error(f"Unsupported tool: {tool}")
            return False

    def _run_ffuf(self, base_url, domain, wordlist, threads,
                  calibration_size, filter_mode, output, extra_args) -> bool:
        """Run vhost scan using ffuf with auto-calibration."""

        # Phase 1: Calibration (if auto mode)
        filter_type = None
        filter_value = None

        if filter_mode == "auto":
            self.print_good("[Phase 1] Calibration - Detecting baseline response")
            self.print_status(f"Running {calibration_size} sample requests...")
            filter_value, filter_type = self._calibrate_ffuf(base_url, domain, calibration_size)

            if filter_value is None:
                self.print_warning("Could not auto-detect filter. Using ffuf -ac (auto-calibrate).")
            else:
                self.print_good(f"Detected baseline: {filter_type}={filter_value}")
                self.print_status(f"Will filter responses with {filter_type}={filter_value}")
            self.print_line()

        # Phase 2: Full scan
        self.print_good("[Phase 2] Full VHost Scan")

        cmd = (
            f"ffuf -u {shlex.quote(base_url)} "
            f"-H 'Host: FUZZ.{domain}' "
            f"-w {shlex.quote(wordlist)} "
            f"-t {threads} -c"
        )

        # Apply filters
        if filter_mode == "auto" and filter_type:
            if filter_type == "size":
                cmd += f" -fs {filter_value}"
            elif filter_type == "status":
                cmd += f" -fc {filter_value}"
            elif filter_type == "words":
                cmd += f" -fw {filter_value}"
            elif filter_type == "lines":
                cmd += f" -fl {filter_value}"
        elif filter_mode == "auto" and not filter_type:
            cmd += " -ac"
        elif filter_mode == "size":
            cmd += f" -fs {filter_value}" if filter_value else ""
        elif filter_mode == "status":
            cmd += f" -fc {filter_value}" if filter_value else ""
        elif filter_mode == "words":
            cmd += f" -fw {filter_value}" if filter_value else ""
        elif filter_mode == "lines":
            cmd += f" -fl {filter_value}" if filter_value else ""

        if output:
            cmd += f" -o {shlex.quote(output)} -of json"

        if extra_args:
            cmd += f" {extra_args}"

        self.print_status(f"Command: {cmd}")
        self.print_line()

        # Run via Exegol for tool availability
        ret = self.run_in_exegol_stream(cmd, timeout=600)

        self.print_line()
        if output:
            self.print_good(f"Results saved to: {output}")

        # Parse and display results if output file exists
        if output and os.path.exists(output):
            self._parse_ffuf_results(output)

        self.print_line()
        self.print_status("Manual command for reference:")
        self.print_line(f"  {cmd}")

        return ret == 0

    def _calibrate_ffuf(self, base_url, domain, sample_size) -> tuple:
        """
        Run calibration requests with fake subdomains to detect baseline.
        Returns (filter_value, filter_type) or (None, None).
        """
        calibration_words = [
            "thisdoesnotexist123456", "notarealsubdomain999",
            "fakehost123abc", "nonexistent-vhost-test",
            "calibration-test-xyz", "randomsubdomain000",
            "testvhost999999", "doesnotexist-abc",
            "fakevirtualhost123", "calibrate-baseline-test"
        ]

        # Write calibration words to temp file and run ffuf silently
        words_str = "\\n".join(calibration_words[:sample_size])
        cmd = (
            f"echo -e '{words_str}' | "
            f"ffuf -u {shlex.quote(base_url)} "
            f"-H 'Host: FUZZ.{domain}' "
            f"-w - -t 5 -s "
            f"-o /tmp/vhost_calibration.json -of json"
        )

        try:
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=30)

            # Read calibration JSON
            ret2, json_data, _ = self.run_in_exegol("cat /tmp/vhost_calibration.json", timeout=10)
            if ret2 != 0 or not json_data.strip():
                return None, None

            data = json.loads(json_data)
            results = data.get("results", [])

            if not results:
                return None, None

            sizes = [r.get("length", 0) for r in results]
            statuses = [r.get("status", 0) for r in results]
            words = [r.get("words", 0) for r in results]
            lines = [r.get("lines", 0) for r in results]

            size_counter = Counter(sizes)
            words_counter = Counter(words)
            lines_counter = Counter(lines)
            status_counter = Counter(statuses)

            common_size = size_counter.most_common(1)[0] if sizes else (0, 0)
            common_words = words_counter.most_common(1)[0] if words else (0, 0)
            common_lines = lines_counter.most_common(1)[0] if lines else (0, 0)
            common_status = status_counter.most_common(1)[0] if statuses else (0, 0)

            threshold = sample_size * 0.8

            if common_size[1] >= threshold:
                return common_size[0], "size"
            if common_words[1] >= threshold:
                return common_words[0], "words"
            if common_lines[1] >= threshold:
                return common_lines[0], "lines"
            if common_status[1] >= threshold and common_status[0] != 200:
                return common_status[0], "status"
            if sizes:
                return common_size[0], "size"

            return None, None

        except (json.JSONDecodeError, KeyError, IndexError):
            return None, None
        except Exception as e:
            self.print_warning(f"Calibration error: {e}")
            return None, None

    def _run_gobuster(self, base_url, domain, wordlist, threads, output, extra_args) -> bool:
        """Run vhost scan using gobuster vhost mode."""
        self.print_good("[Gobuster VHost Scan]")

        cmd = (
            f"gobuster vhost "
            f"-u {shlex.quote(base_url)} "
            f"-w {shlex.quote(wordlist)} "
            f"-t {threads} "
            f"--append-domain"
        )

        if output:
            cmd += f" -o {shlex.quote(output)}"

        if extra_args:
            cmd += f" {extra_args}"

        self.print_status(f"Command: {cmd}")
        self.print_line()

        ret = self.run_in_exegol_stream(cmd, timeout=600)

        if output:
            self.print_good(f"Results saved to: {output}")

        return ret == 0

    def _run_curl(self, base_url, domain, wordlist, output) -> bool:
        """Fallback curl-based brute forcing when no fuzzer is available."""
        self.print_good("[Curl-based VHost Brute Force]")
        self.print_warning("This is slower than ffuf/gobuster. Consider installing ffuf.")
        self.print_line()

        # First get baseline response size
        baseline_cmd = f"curl -s -o /dev/null -w '%{{size_download}}' -H 'Host: doesnotexist12345.{domain}' {shlex.quote(base_url)}"
        ret, stdout, _ = self.run_in_exegol(baseline_cmd, timeout=15)
        baseline_size = stdout.strip() if ret == 0 else "0"
        self.print_status(f"Baseline response size: {baseline_size} bytes")

        # Build a shell script that iterates the wordlist
        scan_script = (
            f"while IFS= read -r word; do "
            f"  size=$(curl -s -o /dev/null -w '%{{size_download}}' "
            f"    -H \"Host: ${{word}}.{domain}\" {shlex.quote(base_url)}); "
            f"  if [ \"$size\" != \"{baseline_size}\" ]; then "
            f"    echo \"[FOUND] ${{word}}.{domain} (size: $size)\"; "
            f"  fi; "
            f"done < {shlex.quote(wordlist)}"
        )

        if output:
            scan_script = scan_script.replace(
                'echo "[FOUND]',
                f'echo "[FOUND]" | tee -a {shlex.quote(output)}; echo "[FOUND]'
            )

        ret = self.run_in_exegol_stream(scan_script, timeout=3600)
        return ret == 0

    def _parse_ffuf_results(self, output_file):
        """Parse ffuf JSON output and display results in a table."""
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            results = data.get("results", [])
            if not results:
                self.print_warning("No vhosts discovered.")
                return

            self.print_line()
            self.print_good(f"Discovered {len(results)} virtual host(s):")
            self.print_line(f"{'VHost':<40} {'Status':<8} {'Size':<10} {'Words':<8} {'Lines':<8}")
            self.print_line("-" * 74)

            for r in results:
                vhost = r.get("input", {}).get("FUZZ", "unknown")
                status = r.get("status", 0)
                size = r.get("length", 0)
                words_count = r.get("words", 0)
                lines_count = r.get("lines", 0)
                self.print_good(f"{vhost:<40} {status:<8} {size:<10} {words_count:<8} {lines_count:<8}")

        except (json.JSONDecodeError, FileNotFoundError) as e:
            self.print_warning(f"Could not parse results file: {e}")

    def check(self) -> bool:
        """Check if at least one vhost fuzzing tool is available."""
        # Check locally
        for tool in ["ffuf", "gobuster"]:
            if find_tool(tool):
                self.print_good(f"{tool} found locally")
                return True

        # Check in Exegol
        for tool in ["ffuf", "gobuster"]:
            ret, stdout, _ = self.run_in_exegol(f"which {tool}", timeout=10)
            if ret == 0 and stdout.strip():
                self.print_good(f"{tool} found in Exegol")
                return True

        # curl is always available
        ret, _, _ = self.run_in_exegol("which curl", timeout=10)
        if ret == 0:
            self.print_warning("Only curl available (slow). Install ffuf or gobuster for better performance.")
            return True

        self.print_error("No vhost scanning tools found (need ffuf, gobuster, or curl)")
        return False
