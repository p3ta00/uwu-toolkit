"""
Fast Port Scanner - Two-Phase Scanning
Phase 1: Fast discovery using masscan or nmap with high rate
Phase 2: Detailed enumeration of discovered ports with nmap -sCV

Based on methodology from top pentesters (OSCP, HTB):
- RustScan/Masscan for speed -> Nmap for detail
- DivideAndScan approach
"""

import subprocess
import shutil
import os
import re
import threading
import time
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform


class FastPortScanner(ModuleBase):
    """
    Two-phase port scanner:
    1. Fast scan all 65535 ports (masscan or nmap --min-rate)
    2. Service enumeration on discovered ports (nmap -sCV)

    Includes UDP scanning option for top ports
    """

    def __init__(self):
        super().__init__()
        self.name = "portscan_fast"
        self.description = "Fast two-phase port scanner (discovery + enumeration)"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["network", "scanner", "enumeration", "nmap", "masscan", "recon", "ports"]

        # Register options
        self.register_option("RHOSTS", "Target host(s) - single IP or CIDR", required=True)
        self.register_option("SCAN_TYPE", "Scan type",
                           default="full",
                           choices=["full", "top1000", "top100", "custom"])
        self.register_option("PORTS", "Custom ports (for custom scan type)", default="")
        self.register_option("RATE", "Packets per second for fast scan", default="1000")
        self.register_option("SCANNER", "Fast scanner to use",
                           default="auto",
                           choices=["auto", "masscan", "nmap"])
        self.register_option("ENUMERATE", "Run service enumeration after discovery",
                           default="yes", choices=["yes", "no"])
        self.register_option("UDP", "Include UDP scan (top 20 ports)",
                           default="no", choices=["yes", "no"])
        self.register_option("OUTPUT", "Output directory", default="./scan_results")
        self.register_option("THREADS", "Nmap threads for enumeration", default="4")
        self.register_option("INTERFACE", "Network interface (for masscan)", default="")

        self.discovered_ports: Dict[str, Set[int]] = {}
        self.scan_results: Dict[str, dict] = {}

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        scan_type = self.get_option("SCAN_TYPE")
        rate = self.get_option("RATE")
        scanner = self.get_option("SCANNER")
        enumerate_services = self.get_option("ENUMERATE") == "yes"
        include_udp = self.get_option("UDP") == "yes"
        output_dir = self.get_option("OUTPUT")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Fast Port Scanner - Two Phase Methodology")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Scan Type: {scan_type}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        # Determine which scanner to use
        if scanner == "auto":
            scanner = self._detect_scanner()

        self.print_status(f"Using scanner: {scanner}")

        # Phase 1: Fast port discovery
        self.print_line()
        self.print_good("[Phase 1] Fast Port Discovery")
        self.print_line("-" * 40)

        open_ports = self._phase1_discovery(target, scan_type, rate, scanner, output_dir, timestamp)

        if not open_ports:
            self.print_warning("No open ports discovered")
            return True

        self.print_line()
        self.print_good(f"Discovered {len(open_ports)} open TCP port(s): {','.join(map(str, sorted(open_ports)))}")

        # Phase 2: Service enumeration
        if enumerate_services and open_ports:
            self.print_line()
            self.print_good("[Phase 2] Service Enumeration")
            self.print_line("-" * 40)

            self._phase2_enumerate(target, open_ports, output_dir, timestamp)

        # UDP Scan
        if include_udp:
            self.print_line()
            self.print_good("[Phase 3] UDP Port Scan (Top 20)")
            self.print_line("-" * 40)

            self._udp_scan(target, output_dir, timestamp)

        # Summary
        self._print_summary(target, open_ports, output_dir, timestamp)

        return True

    def _detect_scanner(self) -> str:
        """Detect available fast scanner"""
        if shutil.which("masscan"):
            return "masscan"
        return "nmap"

    def _phase1_discovery(self, target: str, scan_type: str, rate: str,
                          scanner: str, output_dir: str, timestamp: str) -> Set[int]:
        """Phase 1: Fast port discovery"""

        open_ports: Set[int] = set()

        if scan_type == "full":
            port_range = "1-65535"
        elif scan_type == "top1000":
            port_range = None  # Default nmap top 1000
        elif scan_type == "top100":
            port_range = None
        else:
            port_range = self.get_option("PORTS")

        output_file = f"{output_dir}/{target.replace('/', '_')}_{timestamp}_discovery"

        if scanner == "masscan":
            open_ports = self._run_masscan(target, port_range, rate, output_file)
        else:
            open_ports = self._run_nmap_fast(target, port_range, rate, scan_type, output_file)

        return open_ports

    def _run_masscan(self, target: str, port_range: str, rate: str, output_file: str) -> Set[int]:
        """Run masscan for fast port discovery"""
        interface = self.get_option("INTERFACE")

        cmd = ["sudo", "masscan", target, "-p", port_range or "1-65535",
               "--rate", rate, "-oL", f"{output_file}.masscan"]

        if interface:
            cmd.extend(["-e", interface])

        self.print_status(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Parse masscan output
            open_ports: Set[int] = set()
            if os.path.exists(f"{output_file}.masscan"):
                with open(f"{output_file}.masscan", "r") as f:
                    for line in f:
                        if line.startswith("open"):
                            parts = line.split()
                            if len(parts) >= 3:
                                try:
                                    port = int(parts[2])
                                    open_ports.add(port)
                                    self.print_status(f"Found open port: {port}/tcp")
                                except ValueError:
                                    pass
            return open_ports

        except subprocess.TimeoutExpired:
            self.print_error("Masscan timed out")
            return set()
        except Exception as e:
            self.print_error(f"Masscan error: {e}")
            return set()

    def _run_nmap_fast(self, target: str, port_range: Optional[str], rate: str,
                       scan_type: str, output_file: str) -> Set[int]:
        """Run nmap with high rate for fast discovery"""

        cmd = ["nmap", "-sS", "-T4", "--min-rate", rate, "--open", "-oG", f"{output_file}.gnmap"]

        if scan_type == "full" or port_range:
            cmd.extend(["-p", port_range or "1-65535"])
        elif scan_type == "top100":
            cmd.extend(["--top-ports", "100"])
        # top1000 is nmap default

        cmd.append(target)

        self.print_status(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)

            # Parse grepable output for open ports
            open_ports: Set[int] = set()
            if os.path.exists(f"{output_file}.gnmap"):
                with open(f"{output_file}.gnmap", "r") as f:
                    for line in f:
                        if "/open/" in line:
                            # Extract ports from format: 22/open/tcp//ssh//
                            port_matches = re.findall(r'(\d+)/open/tcp', line)
                            for port in port_matches:
                                p = int(port)
                                open_ports.add(p)
                                self.print_status(f"Found open port: {p}/tcp")

            # Also check stdout for real-time feedback
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        match = re.match(r'^(\d+)/tcp\s+open', line.strip())
                        if match:
                            open_ports.add(int(match.group(1)))

            return open_ports

        except subprocess.TimeoutExpired:
            self.print_error("Nmap discovery timed out")
            return set()
        except Exception as e:
            self.print_error(f"Nmap error: {e}")
            return set()

    def _phase2_enumerate(self, target: str, ports: Set[int], output_dir: str, timestamp: str) -> None:
        """Phase 2: Detailed service enumeration with nmap -sCV"""

        port_str = ",".join(map(str, sorted(ports)))
        output_file = f"{output_dir}/{target.replace('/', '_')}_{timestamp}_services"

        cmd = [
            "nmap", "-sC", "-sV", "-p", port_str,
            "-oA", output_file,
            "--version-intensity", "5",
            target
        ]

        self.print_status(f"Enumerating services on ports: {port_str}")
        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        try:
            # Run with output streaming
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, bufsize=1)

            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if line:
                    # Highlight interesting findings
                    if '/tcp' in line and 'open' in line:
                        self.print_good(line)
                    elif 'http' in line.lower() or 'ssl' in line.lower():
                        self.print_warning(line)
                    elif 'VERSION' in line or 'Service Info' in line:
                        self.print_status(line)
                    else:
                        self.print_line(line)

            process.wait()

            self.print_line()
            self.print_good(f"Service scan complete. Results saved to: {output_file}.*")

        except Exception as e:
            self.print_error(f"Service enumeration error: {e}")

    def _udp_scan(self, target: str, output_dir: str, timestamp: str) -> None:
        """Scan top UDP ports"""

        output_file = f"{output_dir}/{target.replace('/', '_')}_{timestamp}_udp"

        # Top 20 UDP ports commonly found open
        top_udp = "53,67,68,69,123,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353,49152"

        cmd = [
            "sudo", "nmap", "-sU", "-sV", "--version-intensity", "0",
            "-p", top_udp,
            "--open",
            "-oA", output_file,
            target
        ]

        self.print_status(f"Scanning top 20 UDP ports...")
        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, bufsize=1)

            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if line:
                    if '/udp' in line and 'open' in line:
                        self.print_good(line)
                    elif 'open|filtered' in line:
                        self.print_warning(line)
                    else:
                        self.print_line(line)

            process.wait()

        except Exception as e:
            self.print_error(f"UDP scan error: {e}")

    def _print_summary(self, target: str, ports: Set[int], output_dir: str, timestamp: str) -> None:
        """Print scan summary"""

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Scan Summary")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Open TCP Ports: {len(ports)}")

        if ports:
            self.print_line()
            self.print_status("Port Summary:")
            for port in sorted(ports):
                service = self._guess_service(port)
                self.print_line(f"  {port}/tcp - {service}")

        self.print_line()
        self.print_status("Output Files:")
        for f in os.listdir(output_dir):
            if timestamp in f:
                self.print_line(f"  {output_dir}/{f}")

        # Quick wins to check
        self.print_line()
        self.print_warning("Quick Wins to Check:")

        web_ports = ports & {80, 443, 8080, 8443, 8000, 8888}
        if web_ports:
            self.print_line(f"  [WEB] HTTP on ports: {','.join(map(str, web_ports))}")
            self.print_line(f"        -> Run: use enumeration/web_fuzz")

        if 21 in ports:
            self.print_line("  [FTP] Check anonymous login: nmap --script ftp-anon -p21 TARGET")

        if 22 in ports:
            self.print_line("  [SSH] Check version for CVEs, try common creds")

        if 139 in ports or 445 in ports:
            self.print_line("  [SMB] Run: enum4linux-ng TARGET, smbclient -L TARGET")

        if 53 in ports:
            self.print_line("  [DNS] Run: use enumeration/dns_enum, try zone transfer")

        if 389 in ports or 636 in ports:
            self.print_line("  [LDAP] Run: use auxiliary/ad/ldap_enum, check anonymous bind")

        if 3389 in ports:
            self.print_line("  [RDP] Check NLA, try common creds")

        if 5985 in ports or 5986 in ports:
            self.print_line("  [WinRM] Try: evil-winrm -i TARGET -u USER -p PASS")

    def _guess_service(self, port: int) -> str:
        """Guess service name from common ports"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind",
            135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP",
            443: "HTTPS", 445: "SMB", 464: "Kerberos", 587: "SMTP",
            636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL",
            6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            9200: "Elasticsearch", 27017: "MongoDB"
        }
        return services.get(port, "unknown")

    def check(self) -> bool:
        """Check if required tools are available"""
        if not shutil.which("nmap"):
            self.print_error("nmap not found")
            return False
        return True
