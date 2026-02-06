"""
Auto Enumerator - Automated Target Enumeration
Phase 1: Fast port discovery with service detection (rustscan -sV)
Phase 2: Optional UDP scanning

All scanners run with real-time verbose output streaming.
"""

import subprocess
import shutil
import os
import re
import sys
import select
import time
from typing import Set, Optional
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform


class AutoEnumerator(ModuleBase):
    """
    Automated target enumeration with verbose real-time output.

    1. Fast scan all ports with service detection (rustscan -sV / masscan / nmap)
    2. Optional UDP scanning (top 20 ports)
    """

    def __init__(self):
        super().__init__()
        self.name = "auto_enumerator"
        self.description = "Automated target enumeration with live verbose output"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["network", "scanner", "enumeration", "nmap", "masscan", "rustscan", "recon", "ports", "auto"]

        # Register options
        self.register_option("RHOSTS", "Target host(s) - single IP or CIDR", required=True)
        self.register_option("SCAN_TYPE", "Scan type",
                           default="full",
                           choices=["full", "top1000", "top100", "custom"])
        self.register_option("PORTS", "Custom ports (for custom scan type)", default="")
        self.register_option("RATE", "Packets per second for fast scan", default="1000")
        self.register_option("SCANNER", "Fast scanner to use",
                           default="auto",
                           choices=["auto", "rustscan", "masscan", "nmap"])
        self.register_option("UDP", "Include UDP scan (top 20 ports)",
                           default="no", choices=["yes", "no"])
        self.register_option("OUTPUT", "Output directory", default="./scan_results")
        self.register_option("VERBOSE", "Show all scanner output",
                           default="yes", choices=["yes", "no"])
        self.register_option("INTERFACE", "Network interface (for masscan)", default="")

    def _stream_process(self, cmd: list, timeout: int = 900) -> tuple:
        """Run a command with real-time output streaming. Returns (return_code, full_output)"""
        self.print_status(f"Executing: {' '.join(cmd)}")
        self.print_line()

        full_output = []

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            start_time = time.time()
            verbose = self.get_option("VERBOSE") == "yes"

            while True:
                # Check timeout
                if time.time() - start_time > timeout:
                    process.kill()
                    self.print_error(f"Command timed out after {timeout}s")
                    break

                # Read line with timeout
                line = process.stdout.readline()

                if line:
                    line = line.rstrip()
                    full_output.append(line)

                    # Always show important lines, optionally show all
                    if self._is_important_line(line):
                        self._print_highlighted(line)
                    elif verbose:
                        self.print_line(f"    {line}")

                # Check if process finished
                if process.poll() is not None:
                    # Read any remaining output
                    remaining = process.stdout.read()
                    if remaining:
                        for l in remaining.split('\n'):
                            if l.strip():
                                full_output.append(l)
                                if self._is_important_line(l):
                                    self._print_highlighted(l)
                                elif verbose:
                                    self.print_line(f"    {l}")
                    break

            return process.returncode, '\n'.join(full_output)

        except Exception as e:
            self.print_error(f"Execution error: {e}")
            return -1, '\n'.join(full_output)

    def _is_important_line(self, line: str) -> bool:
        """Check if a line contains important information"""
        important_patterns = [
            r'\d+/tcp\s+open',
            r'\d+/udp\s+open',
            r'Open \d+\.\d+\.\d+\.\d+:\d+',
            r'Discovered open port',
            r'PORT\s+STATE\s+SERVICE',
            r'Service Info:',
            r'http-title:',
            r'ssl-cert:',
            r'smb-os-discovery:',
            r'Host is up',
            r'Nmap scan report',
            r'Starting',
            r'Completed',
            r'open\s+tcp',
            r'open\s+udp',
        ]
        for pattern in important_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

    def _print_highlighted(self, line: str) -> None:
        """Print a line with appropriate highlighting"""
        line_lower = line.lower()

        if 'open' in line_lower and ('tcp' in line_lower or 'udp' in line_lower):
            self.print_good(line)
        elif 'discovered' in line_lower or 'found' in line_lower:
            self.print_good(line)
        elif 'error' in line_lower or 'failed' in line_lower:
            self.print_error(line)
        elif 'warning' in line_lower:
            self.print_warning(line)
        elif 'starting' in line_lower or 'completed' in line_lower:
            self.print_status(line)
        elif 'http' in line_lower or 'ssl' in line_lower or 'smb' in line_lower:
            self.print_warning(line)
        else:
            self.print_status(line)

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        scan_type = self.get_option("SCAN_TYPE")
        rate = self.get_option("RATE")
        scanner = self.get_option("SCANNER")
        include_udp = self.get_option("UDP") == "yes"
        output_dir = self.get_option("OUTPUT")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Auto Enumerator - Automated Target Enumeration")
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
        self.print_good("=" * 60)
        self.print_good("[Phase 1] Fast Port Discovery")
        self.print_good("=" * 60)

        open_ports = self._phase1_discovery(target, scan_type, rate, scanner, output_dir, timestamp)

        if not open_ports:
            self.print_warning("No open ports discovered")
            return True

        self.print_line()
        self.print_good(f"[+] Discovered {len(open_ports)} open TCP port(s)")
        self.print_good(f"[+] Ports: {','.join(map(str, sorted(open_ports)))}")

        # UDP Scan
        if include_udp:
            self.print_line()
            self.print_good("=" * 60)
            self.print_good("[Phase 2] UDP Port Scan (Top 20)")
            self.print_good("=" * 60)

            self._udp_scan(target, output_dir, timestamp)

        # Summary
        self._print_summary(target, open_ports, output_dir, timestamp)

        return True

    def _detect_scanner(self) -> str:
        """Detect available fast scanner - prefer rustscan > masscan > nmap"""
        if shutil.which("rustscan"):
            self.print_status("Detected: rustscan (fastest)")
            return "rustscan"
        if shutil.which("masscan"):
            self.print_status("Detected: masscan (fast)")
            return "masscan"
        self.print_status("Detected: nmap (fallback)")
        return "nmap"

    def _phase1_discovery(self, target: str, scan_type: str, rate: str,
                          scanner: str, output_dir: str, timestamp: str) -> Set[int]:
        """Phase 1: Fast port discovery with live output"""

        if scan_type == "full":
            port_range = "1-65535"
        elif scan_type == "top1000":
            port_range = None
        elif scan_type == "top100":
            port_range = None
        else:
            port_range = self.get_option("PORTS")

        output_file = f"{output_dir}/{target.replace('/', '_')}_{timestamp}_discovery"

        if scanner == "rustscan":
            return self._run_rustscan(target, port_range, rate, output_file)
        elif scanner == "masscan":
            return self._run_masscan(target, port_range, rate, output_file)
        else:
            return self._run_nmap_fast(target, port_range, rate, scan_type, output_file)

    def _run_rustscan(self, target: str, port_range: str, rate: str, output_file: str) -> Set[int]:
        """Run rustscan with live output"""

        cmd = ["rustscan", "-a", target, "--ulimit", "5000"]

        # Add port range if not full scan
        if port_range and port_range != "1-65535":
            cmd.extend(["-p", port_range])

        # Nmap options after --
        cmd.extend(["--", "-sV", "-Pn", "-T4"])

        returncode, output = self._stream_process(cmd, timeout=600)

        # Parse output for open ports
        open_ports: Set[int] = set()

        for line in output.split('\n'):
            # Match rustscan greppable format: IP -> [ports]
            match = re.search(r'->\s*\[([^\]]+)\]', line)
            if match:
                ports_str = match.group(1)
                for p in ports_str.split(','):
                    p = p.strip()
                    if p.isdigit():
                        open_ports.add(int(p))

            # Also match "Open IP:PORT" format
            match = re.search(r'Open \d+\.\d+\.\d+\.\d+:(\d+)', line)
            if match:
                open_ports.add(int(match.group(1)))

            # Match nmap output if rustscan ran nmap
            match = re.match(r'^(\d+)/tcp\s+open', line.strip())
            if match:
                open_ports.add(int(match.group(1)))

        # Save output
        with open(f"{output_file}.rustscan", "w") as f:
            f.write(output)
            f.write(f"\n\n# Open ports: {','.join(map(str, sorted(open_ports)))}\n")

        return open_ports

    def _run_masscan(self, target: str, port_range: str, rate: str, output_file: str) -> Set[int]:
        """Run masscan with live output"""
        interface = self.get_option("INTERFACE")

        cmd = ["sudo", "masscan", target, "-p", port_range or "1-65535",
               "--rate", rate, "-oL", f"{output_file}.masscan", "--open"]

        if interface:
            cmd.extend(["-e", interface])

        returncode, output = self._stream_process(cmd, timeout=600)

        # Parse output for open ports
        open_ports: Set[int] = set()

        # Parse from output file
        if os.path.exists(f"{output_file}.masscan"):
            with open(f"{output_file}.masscan", "r") as f:
                for line in f:
                    if line.startswith("open"):
                        parts = line.split()
                        if len(parts) >= 3:
                            try:
                                port = int(parts[2])
                                open_ports.add(port)
                            except ValueError:
                                pass

        # Also parse from stdout
        for line in output.split('\n'):
            match = re.search(r'Discovered open port (\d+)/tcp', line)
            if match:
                open_ports.add(int(match.group(1)))

        return open_ports

    def _run_nmap_fast(self, target: str, port_range: Optional[str], rate: str,
                       scan_type: str, output_file: str) -> Set[int]:
        """Run nmap fast scan with live output"""

        cmd = ["nmap", "-sS", "-Pn", "-n", "-T4", "--min-rate", rate,
               "--open", "-oG", f"{output_file}.gnmap", "-oN", f"{output_file}.nmap"]

        if scan_type == "full" or port_range:
            cmd.extend(["-p", port_range or "1-65535"])
        elif scan_type == "top100":
            cmd.extend(["--top-ports", "100"])
        # top1000 is nmap default

        cmd.append(target)

        returncode, output = self._stream_process(cmd, timeout=900)

        # Parse output for open ports
        open_ports: Set[int] = set()

        for line in output.split('\n'):
            match = re.match(r'^(\d+)/tcp\s+open', line.strip())
            if match:
                open_ports.add(int(match.group(1)))

        # Also parse from gnmap file
        if os.path.exists(f"{output_file}.gnmap"):
            with open(f"{output_file}.gnmap", "r") as f:
                for line in f:
                    port_matches = re.findall(r'(\d+)/open/tcp', line)
                    for port in port_matches:
                        open_ports.add(int(port))

        return open_ports

    def _udp_scan(self, target: str, output_dir: str, timestamp: str) -> None:
        """UDP scan with live output"""

        output_file = f"{output_dir}/{target.replace('/', '_')}_{timestamp}_udp"

        # Top 20 UDP ports
        top_udp = "53,67,68,69,123,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353,49152"

        cmd = [
            "sudo", "nmap", "-sU", "-sV", "--version-intensity", "0",
            "-p", top_udp, "--open",
            "-oA", output_file,
            target
        ]

        self._stream_process(cmd, timeout=600)

    def _print_summary(self, target: str, ports: Set[int], output_dir: str, timestamp: str) -> None:
        """Print scan summary with next steps"""

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  ENUMERATION SUMMARY")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Open TCP Ports: {len(ports)}")

        if ports:
            self.print_line()
            self.print_status("Discovered Services:")
            for port in sorted(ports):
                service = self._guess_service(port)
                self.print_line(f"  {port}/tcp - {service}")

        self.print_line()
        self.print_status("Output Files:")
        for f in sorted(os.listdir(output_dir)):
            if timestamp in f:
                self.print_line(f"  {output_dir}/{f}")

        # Attack suggestions based on discovered ports
        self.print_line()
        self.print_warning("=" * 60)
        self.print_warning("  SUGGESTED NEXT STEPS")
        self.print_warning("=" * 60)

        if 88 in ports and (389 in ports or 636 in ports):
            self.print_good("  [AD] Domain Controller detected!")
            self.print_line("       -> use auxiliary/ad/ad_enumerate_all")
            self.print_line("       -> use auxiliary/ad/bloodhound_collect")
            self.print_line("       -> use auxiliary/ad/kerberoast")
            self.print_line("       -> use auxiliary/ad/asreproast")

        web_ports = ports & {80, 443, 8080, 8443, 8000, 8888}
        if web_ports:
            self.print_good(f"  [WEB] HTTP on ports: {','.join(map(str, sorted(web_ports)))}")
            self.print_line("        -> use enumeration/dirsearch_scan")
            self.print_line("        -> use auxiliary/web/web_scanner")

        if 21 in ports:
            self.print_good("  [FTP] Port 21 open")
            self.print_line("        -> Check anonymous: nmap --script ftp-anon -p21 TARGET")

        if 22 in ports:
            self.print_good("  [SSH] Port 22 open")
            self.print_line("        -> Check version, try creds")

        if 139 in ports or 445 in ports:
            self.print_good("  [SMB] Ports 139/445 open")
            self.print_line("        -> use auxiliary/smb/enum4linux")
            self.print_line("        -> use auxiliary/smb/smb_shares")
            self.print_line("        -> smbclient -L //TARGET -N")

        if 3389 in ports:
            self.print_good("  [RDP] Port 3389 open")
            self.print_line("        -> use auxiliary/rdp/rdp_check")
            self.print_line("        -> xfreerdp /v:TARGET")

        if 5985 in ports or 5986 in ports:
            self.print_good("  [WinRM] Ports 5985/5986 open")
            self.print_line("        -> use auxiliary/sessions/winrm")
            self.print_line("        -> evil-winrm -i TARGET -u USER -p PASS")

        if 1433 in ports:
            self.print_good("  [MSSQL] Port 1433 open")
            self.print_line("        -> use auxiliary/impacket/mssqlclient")

        if 3306 in ports:
            self.print_good("  [MySQL] Port 3306 open")
            self.print_line("        -> mysql -h TARGET -u root -p")

        self.print_line()

    def _guess_service(self, port: int) -> str:
        """Guess service name from common ports"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind",
            135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP",
            443: "HTTPS", 445: "SMB", 464: "Kpasswd", 587: "SMTP",
            593: "RPC-HTTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3268: "GC",
            3269: "GC-SSL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
            9389: "ADWS", 27017: "MongoDB"
        }
        return services.get(port, "unknown")

    def check(self) -> bool:
        """Check if required tools are available"""
        if not shutil.which("nmap"):
            self.print_error("nmap not found - required")
            return False

        self.print_good("nmap found")

        if shutil.which("rustscan"):
            self.print_good("rustscan found (fastest scanner)")
        elif shutil.which("masscan"):
            self.print_good("masscan found (fast scanner)")
        else:
            self.print_warning("No fast scanner found, will use nmap --min-rate")

        return True
