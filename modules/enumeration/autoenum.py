"""
AutoEnum - Automated Enumeration Pipeline
Streamlined for penetration testing and security assessments

Workflow:
1. Fast port scan (all TCP + top UDP)
2. Service detection on open ports
3. Service-specific enumeration (web, SMB, DNS, etc.)

Based on top pentester methodology:
- RustScan/Masscan -> Nmap -sCV
- AutoRecon-style service enumeration
- nmapAutomator workflow
"""

import subprocess
import shutil
import os
import re
import threading
import time
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.module_base import ModuleBase, ModuleType, Platform
from core.wordlists import resolve_wordlist


class AutoEnum(ModuleBase):
    """
    Automated enumeration pipeline that:
    1. Discovers open ports quickly
    2. Enumerates services in detail
    3. Launches service-specific scans automatically

    Like AutoRecon but more focused and faster
    """

    # Service detection patterns
    SERVICE_PATTERNS = {
        "http": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
        "smb": [139, 445],
        "ftp": [21],
        "ssh": [22],
        "dns": [53],
        "ldap": [389, 636],
        "mssql": [1433],
        "mysql": [3306],
        "rdp": [3389],
        "winrm": [5985, 5986],
        "vnc": [5900, 5901],
        "smtp": [25, 587],
        "nfs": [111, 2049],
        "kerberos": [88],
    }

    def __init__(self):
        super().__init__()
        self.name = "autoenum"
        self.description = "Automated enumeration pipeline (like AutoRecon)"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["auto", "enumeration", "recon", "pipeline", "autorecon"]

        # Register options
        self.register_option("RHOSTS", "Target IP or hostname", required=True)
        self.register_option("OUTPUT", "Output directory", default="./autoenum_results")
        self.register_option("SPEED", "Scan speed profile",
                           default="normal",
                           choices=["fast", "normal", "thorough"])
        self.register_option("UDP", "Include UDP scan", default="no", choices=["yes", "no"])
        self.register_option("SERVICES", "Specific services to enum (comma-sep, or 'all')",
                           default="all")
        self.register_option("THREADS", "Max concurrent service scans", default="4")
        self.register_option("WEB_FUZZ", "Run web directory fuzzing", default="yes", choices=["yes", "no"])
        self.register_option("WORDLIST", "Wordlist size for fuzzing",
                           default="medium",
                           choices=["small", "medium", "large"])

        self.open_ports: Set[int] = set()
        self.services: Dict[int, str] = {}
        self.findings: List[str] = []

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        output_dir = self.get_option("OUTPUT")
        speed = self.get_option("SPEED")
        include_udp = self.get_option("UDP") == "yes"
        max_threads = int(self.get_option("THREADS"))

        # Create output structure
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_dir = f"{output_dir}/{target.replace('.', '_')}_{timestamp}"
        os.makedirs(target_dir, exist_ok=True)
        os.makedirs(f"{target_dir}/scans", exist_ok=True)
        os.makedirs(f"{target_dir}/services", exist_ok=True)

        self.print_line()
        self.print_good("=" * 70)
        self.print_good("  AutoEnum - Automated Enumeration Pipeline")
        self.print_good("=" * 70)
        self.print_status(f"Target: {target}")
        self.print_status(f"Output: {target_dir}")
        self.print_status(f"Speed: {speed}")
        self.print_line()

        start_time = time.time()

        # Phase 1: Port Discovery
        self.print_good("[Phase 1/3] Port Discovery")
        self.print_line("-" * 50)
        self._discover_ports(target, speed, target_dir)

        if not self.open_ports:
            self.print_warning("No open ports found. Host may be down or filtered.")
            return True

        self.print_line()
        self.print_good(f"Found {len(self.open_ports)} open TCP port(s)")

        # Phase 2: Service Detection
        self.print_line()
        self.print_good("[Phase 2/3] Service Detection")
        self.print_line("-" * 50)
        self._detect_services(target, target_dir)

        # Phase 3: Service-Specific Enumeration
        self.print_line()
        self.print_good("[Phase 3/3] Service Enumeration")
        self.print_line("-" * 50)
        self._enumerate_services(target, target_dir, max_threads)

        # UDP Scan (if enabled)
        if include_udp:
            self.print_line()
            self.print_good("[Bonus] UDP Scan")
            self.print_line("-" * 50)
            self._scan_udp(target, target_dir)

        # Generate report
        elapsed = time.time() - start_time
        self._generate_report(target, target_dir, elapsed)

        return True

    def _discover_ports(self, target: str, speed: str, output_dir: str) -> None:
        """Phase 1: Fast port discovery"""

        rate_map = {"fast": "5000", "normal": "1000", "thorough": "500"}
        rate = rate_map.get(speed, "1000")

        output_file = f"{output_dir}/scans/tcp_discovery"

        # Use nmap with high rate for discovery
        cmd = [
            "nmap", "-sS", "-p-", "--min-rate", rate,
            "-T4", "--open", "-oG", f"{output_file}.gnmap",
            "-oN", f"{output_file}.nmap",
            target
        ]

        self.print_status(f"Scanning all 65535 TCP ports (rate: {rate}/s)...")
        self.print_status(f"Command: nmap -sS -p- --min-rate {rate} {target}")

        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if '/tcp' in line and 'open' in line:
                    self.print_good(f"  {line}")
                    # Extract port
                    match = re.match(r'^(\d+)/tcp', line.strip())
                    if match:
                        self.open_ports.add(int(match.group(1)))

            process.wait()

            # Also parse gnmap for complete results
            if os.path.exists(f"{output_file}.gnmap"):
                with open(f"{output_file}.gnmap", 'r') as f:
                    for line in f:
                        ports = re.findall(r'(\d+)/open/tcp', line)
                        for p in ports:
                            self.open_ports.add(int(p))

        except Exception as e:
            self.print_error(f"Port discovery error: {e}")

    def _detect_services(self, target: str, output_dir: str) -> None:
        """Phase 2: Service version detection"""

        if not self.open_ports:
            return

        port_str = ",".join(map(str, sorted(self.open_ports)))
        output_file = f"{output_dir}/scans/service_detection"

        cmd = [
            "nmap", "-sC", "-sV", "-p", port_str,
            "-oA", output_file,
            target
        ]

        self.print_status(f"Detecting services on {len(self.open_ports)} ports...")

        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            current_port = None
            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if line:
                    # Parse service info
                    if '/tcp' in line and 'open' in line:
                        self.print_good(f"  {line}")
                        match = re.match(r'^(\d+)/tcp\s+open\s+(\S+)', line.strip())
                        if match:
                            port, service = int(match.group(1)), match.group(2)
                            self.services[port] = service
                    elif '|' in line:  # Script output
                        self.print_status(f"    {line}")
                    elif 'Service Info' in line:
                        self.print_warning(f"  {line}")

            process.wait()

        except Exception as e:
            self.print_error(f"Service detection error: {e}")

    def _enumerate_services(self, target: str, output_dir: str, max_threads: int) -> None:
        """Phase 3: Service-specific enumeration"""

        tasks = []

        # Identify services to enumerate
        for port, service in self.services.items():
            service_lower = service.lower()

            if "http" in service_lower or port in self.SERVICE_PATTERNS["http"]:
                tasks.append(("http", port, service))
            elif "smb" in service_lower or "microsoft-ds" in service_lower or port in self.SERVICE_PATTERNS["smb"]:
                tasks.append(("smb", port, service))
            elif "ftp" in service_lower or port in self.SERVICE_PATTERNS["ftp"]:
                tasks.append(("ftp", port, service))
            elif "ssh" in service_lower or port in self.SERVICE_PATTERNS["ssh"]:
                tasks.append(("ssh", port, service))
            elif "dns" in service_lower or "domain" in service_lower or port in self.SERVICE_PATTERNS["dns"]:
                tasks.append(("dns", port, service))
            elif "ldap" in service_lower or port in self.SERVICE_PATTERNS["ldap"]:
                tasks.append(("ldap", port, service))
            elif "ms-sql" in service_lower or port in self.SERVICE_PATTERNS["mssql"]:
                tasks.append(("mssql", port, service))
            elif "mysql" in service_lower or port in self.SERVICE_PATTERNS["mysql"]:
                tasks.append(("mysql", port, service))

        if not tasks:
            self.print_status("No services identified for detailed enumeration")
            return

        self.print_status(f"Launching {len(tasks)} service enumeration tasks...")

        # Run service enumeration in parallel
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {}
            for service_type, port, service_name in tasks:
                future = executor.submit(
                    self._enum_service, target, service_type, port, output_dir
                )
                futures[future] = (service_type, port)

            for future in as_completed(futures):
                service_type, port = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.print_good(f"  [{service_type}:{port}] Enumeration complete")
                except Exception as e:
                    self.print_error(f"  [{service_type}:{port}] Error: {e}")

    def _enum_service(self, target: str, service_type: str, port: int, output_dir: str) -> bool:
        """Enumerate specific service type"""

        service_dir = f"{output_dir}/services/{service_type}_{port}"
        os.makedirs(service_dir, exist_ok=True)

        if service_type == "http":
            return self._enum_http(target, port, service_dir)
        elif service_type == "smb":
            return self._enum_smb(target, service_dir)
        elif service_type == "ftp":
            return self._enum_ftp(target, port, service_dir)
        elif service_type == "ssh":
            return self._enum_ssh(target, port, service_dir)
        elif service_type == "dns":
            return self._enum_dns(target, service_dir)
        elif service_type == "ldap":
            return self._enum_ldap(target, port, service_dir)
        elif service_type == "mssql":
            return self._enum_mssql(target, service_dir)
        elif service_type == "mysql":
            return self._enum_mysql(target, service_dir)

        return False

    def _enum_http(self, target: str, port: int, output_dir: str) -> bool:
        """Enumerate HTTP service"""
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"

        # Nmap HTTP scripts
        self._run_cmd([
            "nmap", "-p", str(port), "--script", "http-headers,http-methods,http-robots.txt,http-title",
            "-oN", f"{output_dir}/nmap_http.txt", target
        ])

        # Directory fuzzing (if enabled)
        if self.get_option("WEB_FUZZ") == "yes":
            wordlist_size = self.get_option("WORDLIST")
            wordlist_map = {
                "small": "common",
                "medium": "dir_small",
                "large": "dir_medium",
            }
            wordlist_name = wordlist_map.get(wordlist_size, "dir_small")
            wordlist = resolve_wordlist(wordlist_name, fallback="common")

            if not wordlist:
                self.print_warning("No wordlist found for web fuzzing")
            else:
                # Find fuzzer tool
                ferox_path = shutil.which("feroxbuster") or "/opt/tools/bin/feroxbuster"
                ffuf_path = shutil.which("ffuf") or "/opt/tools/bin/ffuf"

                if os.path.exists(ferox_path):
                    self._run_cmd([
                        ferox_path, "-u", url, "-w", wordlist,
                        "-t", "30", "-o", f"{output_dir}/feroxbuster.txt", "-n", "--no-state"
                    ], timeout=300)
                elif os.path.exists(ffuf_path):
                    self._run_cmd([
                        ffuf_path, "-u", f"{url}/FUZZ", "-w", wordlist,
                        "-t", "30", "-o", f"{output_dir}/ffuf.json", "-of", "json"
                    ], timeout=300)

        # Nikto (quick scan)
        if shutil.which("nikto"):
            self._run_cmd([
                "nikto", "-h", url, "-maxtime", "120s",
                "-o", f"{output_dir}/nikto.txt"
            ], timeout=180)

        return True

    def _enum_smb(self, target: str, output_dir: str) -> bool:
        """Enumerate SMB service"""

        # enum4linux-ng
        if shutil.which("enum4linux-ng"):
            self._run_cmd([
                "enum4linux-ng", "-A", target,
                "-oA", f"{output_dir}/enum4linux"
            ], timeout=300)
        elif shutil.which("enum4linux"):
            self._run_cmd([
                "enum4linux", "-a", target
            ], timeout=300, output_file=f"{output_dir}/enum4linux.txt")

        # smbclient list shares
        self._run_cmd([
            "smbclient", "-L", target, "-N"
        ], timeout=30, output_file=f"{output_dir}/smbclient_shares.txt")

        # Nmap SMB scripts
        self._run_cmd([
            "nmap", "-p", "139,445", "--script", "smb-enum-shares,smb-enum-users,smb-os-discovery",
            "-oN", f"{output_dir}/nmap_smb.txt", target
        ], timeout=120)

        return True

    def _enum_ftp(self, target: str, port: int, output_dir: str) -> bool:
        """Enumerate FTP service"""

        # Check anonymous access
        self._run_cmd([
            "nmap", "-p", str(port), "--script", "ftp-anon,ftp-bounce,ftp-syst",
            "-oN", f"{output_dir}/nmap_ftp.txt", target
        ])

        return True

    def _enum_ssh(self, target: str, port: int, output_dir: str) -> bool:
        """Enumerate SSH service"""

        # SSH audit scripts
        self._run_cmd([
            "nmap", "-p", str(port), "--script", "ssh2-enum-algos,ssh-hostkey",
            "-oN", f"{output_dir}/nmap_ssh.txt", target
        ])

        return True

    def _enum_dns(self, target: str, output_dir: str) -> bool:
        """Enumerate DNS service"""

        # Try zone transfer
        self._run_cmd([
            "dig", f"@{target}", "AXFR"
        ], timeout=30, output_file=f"{output_dir}/zone_transfer.txt")

        return True

    def _enum_ldap(self, target: str, port: int, output_dir: str) -> bool:
        """Enumerate LDAP service"""

        # Anonymous bind test
        self._run_cmd([
            "ldapsearch", "-H", f"ldap://{target}:{port}", "-x",
            "-s", "base", "-b", "", "namingContexts"
        ], timeout=30, output_file=f"{output_dir}/ldap_anon.txt")

        # Nmap LDAP scripts
        self._run_cmd([
            "nmap", "-p", str(port), "--script", "ldap-rootdse",
            "-oN", f"{output_dir}/nmap_ldap.txt", target
        ])

        return True

    def _enum_mssql(self, target: str, output_dir: str) -> bool:
        """Enumerate MSSQL service"""

        self._run_cmd([
            "nmap", "-p", "1433", "--script", "ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info",
            "-oN", f"{output_dir}/nmap_mssql.txt", target
        ])

        return True

    def _enum_mysql(self, target: str, output_dir: str) -> bool:
        """Enumerate MySQL service"""

        self._run_cmd([
            "nmap", "-p", "3306", "--script", "mysql-info,mysql-enum",
            "-oN", f"{output_dir}/nmap_mysql.txt", target
        ])

        return True

    def _scan_udp(self, target: str, output_dir: str) -> None:
        """Scan top UDP ports"""

        output_file = f"{output_dir}/scans/udp_scan"

        cmd = [
            "sudo", "nmap", "-sU", "--top-ports", "20",
            "-sV", "--version-intensity", "0",
            "-oA", output_file, target
        ]

        self.print_status("Scanning top 20 UDP ports...")

        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if '/udp' in line and 'open' in line:
                    self.print_good(f"  {line}")

            process.wait()

        except Exception as e:
            self.print_error(f"UDP scan error: {e}")

    def _run_cmd(self, cmd: List[str], timeout: int = 120, output_file: str = None) -> Optional[str]:
        """Run command with optional timeout and output file"""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )

            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                    if result.stderr:
                        f.write("\n--- STDERR ---\n")
                        f.write(result.stderr)

            return result.stdout

        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    def _generate_report(self, target: str, output_dir: str, elapsed: float) -> None:
        """Generate summary report"""

        report_file = f"{output_dir}/REPORT.txt"

        self.print_line()
        self.print_good("=" * 70)
        self.print_good("  Enumeration Complete")
        self.print_good("=" * 70)

        with open(report_file, 'w') as f:
            f.write(f"AutoEnum Report for {target}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Duration: {elapsed:.1f} seconds\n")
            f.write("=" * 60 + "\n\n")

            f.write("[OPEN PORTS]\n")
            for port in sorted(self.open_ports):
                service = self.services.get(port, "unknown")
                f.write(f"  {port}/tcp - {service}\n")

            f.write("\n[OUTPUT FILES]\n")
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), output_dir)
                    f.write(f"  {rel_path}\n")

        self.print_status(f"Target: {target}")
        self.print_status(f"Duration: {elapsed:.1f} seconds")
        self.print_status(f"Open ports: {len(self.open_ports)}")
        self.print_line()

        self.print_status("Open Ports:")
        for port in sorted(self.open_ports):
            service = self.services.get(port, "unknown")
            self.print_good(f"  {port}/tcp - {service}")

        self.print_line()
        self.print_status(f"Full report: {report_file}")
        self.print_status(f"Results directory: {output_dir}")

        # Quick wins
        self.print_line()
        self.print_warning("Quick Wins to Check:")

        if any(p in self.open_ports for p in [80, 443, 8080]):
            self.print_line("  [WEB] Check web fuzzer output, look for admin panels")

        if 21 in self.open_ports:
            self.print_line("  [FTP] Check for anonymous access")

        if 139 in self.open_ports or 445 in self.open_ports:
            self.print_line("  [SMB] Check enum4linux output, try null session")

        if 389 in self.open_ports:
            self.print_line("  [LDAP] Check anonymous bind results")

    def check(self) -> bool:
        """Check if nmap is available"""
        if not shutil.which("nmap"):
            self.print_error("nmap not found")
            return False
        return True
