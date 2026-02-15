"""
RustScan Port Scanner
Default: rustscan -a <ip> -- -sCV
Optional: UDP scan for top UDP ports via nmap -sU
"""

import subprocess
import shutil
import os
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform


class FastPortScanner(ModuleBase):
    """
    RustScan-based port scanner.
    Default: rustscan -a <ip> -- -sCV (all TCP ports + service enum)
    UDP option: nmap -sU --top-ports <n> for top UDP ports
    """

    def __init__(self):
        super().__init__()
        self.name = "portscan_fast"
        self.description = "RustScan port scanner (rustscan -a <ip> -- -sCV)"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["network", "scanner", "enumeration", "rustscan", "recon", "ports"]

        self.register_option("RHOSTS", "Target host(s) - IP or CIDR", required=True)
        self.register_option("BATCH_SIZE", "RustScan batch size (concurrent port probes)",
                           default="1500")
        self.register_option("NMAP_ARGS", "Nmap arguments passed after --",
                           default="-sCV")
        self.register_option("UDP", "Include UDP scan for top ports",
                           default="no", choices=["yes", "no"])
        self.register_option("UDP_PORTS", "Number of top UDP ports to scan",
                           default="20")
        self.register_option("OUTPUT", "Output directory for results",
                           default="./scan_results")

    @staticmethod
    def _find_rustscan() -> str:
        """Return rustscan binary path (PATH first, then common locations)."""
        path = shutil.which("rustscan")
        if path:
            return path
        for candidate in ["/root/.cargo/bin/rustscan", "/opt/resources/linux/rustscan"]:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return "rustscan"  # let it fail with FileNotFoundError

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        batch_size = self.get_option("BATCH_SIZE")
        nmap_args = self.get_option("NMAP_ARGS")
        include_udp = self.get_option("UDP") == "yes"
        output_dir = self.get_option("OUTPUT")

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "_")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  RustScan Port Scanner")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        # --- TCP Scan ---
        self.print_good("[TCP] RustScan -> Nmap Service Enum")
        self.print_line("-" * 40)

        tcp_ok = self._run_rustscan(target, batch_size, nmap_args, output_dir, safe_target, timestamp)

        # --- UDP Scan ---
        if include_udp:
            self.print_line()
            self.print_good("[UDP] Top Port Scan")
            self.print_line("-" * 40)
            self._run_udp(target, output_dir, safe_target, timestamp)

        # Output file listing
        self.print_line()
        self.print_status("Output Files:")
        for f in sorted(os.listdir(output_dir)):
            if timestamp in f:
                self.print_line(f"  {output_dir}/{f}")

        return tcp_ok

    def _run_rustscan(self, target: str, batch_size: str, nmap_args: str,
                      output_dir: str, safe_target: str, timestamp: str) -> bool:
        """Run: rustscan -a <target> --batch-size <n> -- <nmap_args>"""

        rustscan_bin = self._find_rustscan()
        cmd = [rustscan_bin, "-a", target, "--batch-size", batch_size, "--"]
        cmd.extend(nmap_args.split())

        # Add nmap output flags so results get saved
        output_base = f"{output_dir}/{safe_target}_{timestamp}_tcp"
        cmd.extend(["-oA", output_base])

        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            for line in iter(process.stdout.readline, ""):
                line = line.rstrip()
                if not line:
                    continue
                if "/tcp" in line and "open" in line:
                    self.print_good(line)
                elif "Open" in line:
                    self.print_good(line)
                elif "http" in line.lower() or "ssl" in line.lower():
                    self.print_warning(line)
                elif "Service Info" in line or "VERSION" in line:
                    self.print_status(line)
                elif line.startswith("[") or line.startswith(".-") or line.startswith("|"):
                    # rustscan banner/formatting
                    self.print_line(line)
                else:
                    self.print_line(f"    {line}")

            process.wait()
            self.print_line()

            if process.returncode == 0:
                self.print_good(f"TCP scan complete. Results: {output_base}.*")
                return True
            else:
                self.print_error(f"RustScan exited with code {process.returncode}")
                return False

        except FileNotFoundError:
            self.print_error("rustscan not found — install: cargo install rustscan")
            return False
        except Exception as e:
            self.print_error(f"RustScan error: {e}")
            return False

    def _run_udp(self, target: str, output_dir: str, safe_target: str, timestamp: str) -> bool:
        """Run: nmap -sU --top-ports <n> on target"""

        top_n = self.get_option("UDP_PORTS")
        output_base = f"{output_dir}/{safe_target}_{timestamp}_udp"

        cmd = [
            "sudo", "nmap", "-sU", "-sV", "--version-intensity", "0",
            "--top-ports", top_n, "--open",
            "-oA", output_base,
            target
        ]

        self.print_status(f"Scanning top {top_n} UDP ports...")
        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            for line in iter(process.stdout.readline, ""):
                line = line.rstrip()
                if not line:
                    continue
                if "/udp" in line and "open" in line:
                    self.print_good(line)
                elif "open|filtered" in line:
                    self.print_warning(line)
                else:
                    self.print_line(f"    {line}")

            process.wait()
            self.print_line()

            if process.returncode == 0:
                self.print_good(f"UDP scan complete. Results: {output_base}.*")
                return True
            else:
                self.print_error(f"nmap UDP exited with code {process.returncode}")
                return False

        except Exception as e:
            self.print_error(f"UDP scan error: {e}")
            return False

    def check(self) -> bool:
        """Check if rustscan is available"""
        rs = self._find_rustscan()
        if rs == "rustscan" and not shutil.which("rustscan"):
            self.print_error("rustscan not found — install: cargo install rustscan")
            return False
        self.print_good(f"rustscan found: {rs}")

        if not shutil.which("nmap"):
            self.print_warning("nmap not found — UDP scan and service enum won't work")
        else:
            self.print_good("nmap found (used for service enum via -- flags)")

        return True
