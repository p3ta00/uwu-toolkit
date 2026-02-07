"""
VHost Scanner - Automated Virtual Host Discovery
Runs ffuf to discover virtual hosts, auto-detecting filter values
"""

import subprocess
import shutil
import re
import json
from collections import Counter
from core.module_base import ModuleBase, ModuleType, Platform


class VHostScanner(ModuleBase):
    """
    Automated virtual host discovery using ffuf.

    Phase 1: Calibration run to detect baseline response
    Phase 2: Full scan with auto-detected filters
    """

    def __init__(self):
        super().__init__()
        self.name = "vhost_scan"
        self.description = "Automated vhost discovery with smart filtering"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.WEB
        self.tags = ["web", "enumeration", "vhost", "subdomain", "ffuf", "virtualhost"]

        self.register_option("RHOSTS", "Target IP address", required=True)
        self.register_option("DOMAIN", "Base domain (e.g., htb.local)", required=True)
        self.register_option("WORDLIST", "Subdomain wordlist",
                           default="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        self.register_option("PORT", "Target port", default="80")
        self.register_option("SSL", "Use HTTPS", default="no", choices=["yes", "no"])
        self.register_option("THREADS", "Number of threads", default="40")
        self.register_option("CALIBRATION_SIZE", "Number of requests for calibration", default="10")
        self.register_option("FILTER_MODE", "Filter mode: auto, size, status, words, lines",
                           default="auto", choices=["auto", "size", "status", "words", "lines"])
        self.register_option("OUTPUT", "Output file for results", default="")
        self.register_option("EXTRA_ARGS", "Additional ffuf arguments", default="")

    def run(self) -> bool:
        target_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        wordlist = self.get_option("WORDLIST")
        port = self.get_option("PORT")
        use_ssl = self.get_option("SSL") == "yes"
        threads = self.get_option("THREADS")
        calibration_size = int(self.get_option("CALIBRATION_SIZE"))
        filter_mode = self.get_option("FILTER_MODE")

        # Check ffuf is available
        if not shutil.which("ffuf"):
            self.print_error("ffuf not found. Install it first.")
            return False

        # Build base URL
        protocol = "https" if use_ssl else "http"
        if port in ["80", "443"]:
            base_url = f"{protocol}://{target_ip}"
        else:
            base_url = f"{protocol}://{target_ip}:{port}"

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  VHost Scanner - Automated Virtual Host Discovery")
        self.print_good("=" * 60)
        self.print_status(f"Target: {base_url}")
        self.print_status(f"Domain: FUZZ.{domain}")
        self.print_status(f"Wordlist: {wordlist}")
        self.print_line()

        # Phase 1: Calibration
        self.print_good("[Phase 1] Calibration - Detecting baseline response")
        self.print_status(f"Running {calibration_size} sample requests...")

        filter_value, filter_type = self._calibrate(base_url, domain, wordlist, calibration_size)

        if filter_value is None:
            self.print_warning("Could not auto-detect filter. Running without filters.")
            self.print_warning("You may see many false positives.")
            filter_type = None
        else:
            self.print_good(f"Detected baseline: {filter_type}={filter_value}")
            self.print_status(f"Will filter responses with {filter_type}={filter_value}")

        self.print_line()

        # Phase 2: Full scan
        self.print_good("[Phase 2] Full VHost Scan")

        cmd = [
            "ffuf",
            "-u", base_url,
            "-H", f"Host: FUZZ.{domain}",
            "-w", wordlist,
            "-t", str(threads),
            "-c",  # Colorize output
        ]

        # Apply filter based on calibration
        if filter_type == "size":
            cmd.extend(["-fs", str(filter_value)])
        elif filter_type == "status":
            cmd.extend(["-fc", str(filter_value)])
        elif filter_type == "words":
            cmd.extend(["-fw", str(filter_value)])
        elif filter_type == "lines":
            cmd.extend(["-fl", str(filter_value)])

        # Output file
        output = self.get_option("OUTPUT")
        if output:
            cmd.extend(["-o", output, "-of", "json"])

        # Extra args
        extra = self.get_option("EXTRA_ARGS")
        if extra:
            cmd.extend(extra.split())

        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        try:
            result = subprocess.run(cmd)

            self.print_line()
            if output:
                self.print_good(f"Results saved to: {output}")

            # Print manual command for reference
            self.print_line()
            self.print_status("Manual command for future reference:")
            self.print_line(f"  {' '.join(cmd)}")

            return result.returncode == 0

        except KeyboardInterrupt:
            self.print_warning("Scan interrupted")
            return False
        except Exception as e:
            self.print_error(f"Error: {e}")
            return False

    def _calibrate(self, base_url: str, domain: str, wordlist: str, sample_size: int) -> tuple:
        """
        Run calibration requests to detect baseline response.
        Returns (filter_value, filter_type) or (None, None) if detection fails.
        """
        # Use random/fake subdomains for calibration
        calibration_words = [
            "thisdoesnotexist123456",
            "notarealsubdomain999",
            "fakehost123abc",
            "nonexistent-vhost-test",
            "calibration-test-xyz",
            "randomsubdomain000",
            "testvhost999999",
            "doesnotexist-abc",
            "fakevirtualhost123",
            "calibrate-baseline-test"
        ]

        # Run ffuf with JSON output to parse results
        cmd = [
            "ffuf",
            "-u", base_url,
            "-H", f"Host: FUZZ.{domain}",
            "-w", "-",  # Read from stdin
            "-t", "5",
            "-s",  # Silent mode
            "-o", "/tmp/vhost_calibration.json",
            "-of", "json",
        ]

        try:
            # Feed calibration words via stdin
            input_data = "\n".join(calibration_words[:sample_size])
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse JSON output
            with open("/tmp/vhost_calibration.json", "r") as f:
                data = json.load(f)

            results = data.get("results", [])

            if not results:
                return None, None

            # Collect response characteristics
            sizes = [r.get("length", 0) for r in results]
            statuses = [r.get("status", 0) for r in results]
            words = [r.get("words", 0) for r in results]
            lines = [r.get("lines", 0) for r in results]

            # Find most common values (baseline)
            size_counter = Counter(sizes)
            status_counter = Counter(statuses)
            words_counter = Counter(words)
            lines_counter = Counter(lines)

            # Get most common of each
            common_size = size_counter.most_common(1)[0] if sizes else (0, 0)
            common_status = status_counter.most_common(1)[0] if statuses else (0, 0)
            common_words = words_counter.most_common(1)[0] if words else (0, 0)
            common_lines = lines_counter.most_common(1)[0] if lines else (0, 0)

            # Decide best filter - prefer size if consistent, then words, then lines
            # Status is usually 200 for both valid and invalid vhosts

            # If all responses have same size, use size filter
            if common_size[1] >= sample_size * 0.8:  # 80% have same size
                return common_size[0], "size"

            # If all have same word count
            if common_words[1] >= sample_size * 0.8:
                return common_words[0], "words"

            # If all have same line count
            if common_lines[1] >= sample_size * 0.8:
                return common_lines[0], "lines"

            # If status is consistent and not 200 (e.g., 302 redirect)
            if common_status[1] >= sample_size * 0.8 and common_status[0] != 200:
                return common_status[0], "status"

            # Default to size even if not perfectly consistent
            if sizes:
                return common_size[0], "size"

            return None, None

        except subprocess.TimeoutExpired:
            self.print_warning("Calibration timed out")
            return None, None
        except json.JSONDecodeError:
            self.print_warning("Could not parse calibration results")
            return None, None
        except FileNotFoundError:
            self.print_warning("Calibration output not found")
            return None, None
        except Exception as e:
            self.print_warning(f"Calibration error: {e}")
            return None, None

    def check(self) -> bool:
        """Check if ffuf is available"""
        if shutil.which("ffuf"):
            self.print_good("ffuf found")
            return True
        self.print_error("ffuf not found")
        return False
