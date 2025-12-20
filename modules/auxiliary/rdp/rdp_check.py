"""
RDP Enumeration and Check Module
RDP service detection and vulnerability checking
"""

import subprocess
import shutil
import socket
from core.module_base import ModuleBase, ModuleType, Platform


class RDPChecker(ModuleBase):
    """
    RDP service enumeration and security checking
    Checks for NLA, encryption, and common vulnerabilities
    """

    def __init__(self):
        super().__init__()
        self.name = "rdp_check"
        self.description = "RDP service enumeration and vulnerability checking"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["rdp", "windows", "enumeration", "remote-desktop", "bluekeep"]
        self.references = [
            "CVE-2019-0708 (BlueKeep)",
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp"
        ]

        # Register options
        self.register_option("RHOSTS", "Target host(s)", required=True)
        self.register_option("RPORT", "RDP port", default=3389)
        self.register_option("CHECK_BLUEKEEP", "Check for BlueKeep vulnerability", default="yes",
                           choices=["yes", "no"])
        self.register_option("CHECK_NLA", "Check NLA status", default="yes", choices=["yes", "no"])
        self.register_option("USER", "Username for auth check", default="")
        self.register_option("PASS", "Password for auth check", default="")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        port = int(self.get_option("RPORT"))

        self.print_status(f"Checking RDP on {target}:{port}")

        # First check if port is open
        if not self._check_port(target, port):
            self.print_error(f"RDP port {port} is not open on {target}")
            return False

        self.print_good(f"RDP port {port} is open")

        results = {
            "port_open": True,
            "nla_required": None,
            "bluekeep_vulnerable": None,
        }

        # Check NLA status
        if self.get_option("CHECK_NLA") == "yes":
            results["nla_required"] = self._check_nla(target, port)

        # Check for BlueKeep
        if self.get_option("CHECK_BLUEKEEP") == "yes":
            results["bluekeep_vulnerable"] = self._check_bluekeep(target, port)

        # Run nmap scripts if available
        self._run_nmap_rdp(target, port)

        # Summary
        self.print_line()
        self.print_status("=== Summary ===")
        self.print_status(f"Target: {target}:{port}")
        if results["nla_required"] is not None:
            status = "Required" if results["nla_required"] else "NOT Required (potential risk)"
            self.print_status(f"NLA: {status}")
        if results["bluekeep_vulnerable"] is not None:
            if results["bluekeep_vulnerable"]:
                self.print_error("BlueKeep: VULNERABLE!")
            else:
                self.print_good("BlueKeep: Not vulnerable or patched")

        return True

    def _check_port(self, target: str, port: int) -> bool:
        """Check if RDP port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False

    def _check_nla(self, target: str, port: int) -> bool:
        """Check if NLA is required"""
        self.print_status("Checking NLA status...")

        # Try using rdp-sec-check if available
        if shutil.which("rdp-sec-check"):
            try:
                result = subprocess.run(
                    ["rdp-sec-check", f"{target}:{port}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if "NLA" in result.stdout:
                    self.print_status("NLA status detected via rdp-sec-check")
                    print(result.stdout)
                    return "ENABLED" in result.stdout or "Required" in result.stdout
            except:
                pass

        # Try nmap script
        if shutil.which("nmap"):
            try:
                result = subprocess.run(
                    ["nmap", "-p", str(port), "--script", "rdp-enum-encryption", target],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if "CredSSP (NLA)" in result.stdout:
                    self.print_good("NLA is supported/required")
                    return True
            except:
                pass

        self.print_warning("Could not determine NLA status")
        return None

    def _check_bluekeep(self, target: str, port: int) -> bool:
        """Check for BlueKeep vulnerability (CVE-2019-0708)"""
        self.print_status("Checking for BlueKeep (CVE-2019-0708)...")

        # Try nmap script first
        if shutil.which("nmap"):
            try:
                result = subprocess.run(
                    ["nmap", "-p", str(port), "--script", "rdp-vuln-ms12-020,rdp-ntlm-info", target],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                print(result.stdout)

                if "VULNERABLE" in result.stdout.upper():
                    return True
            except Exception as e:
                self.print_warning(f"Nmap scan failed: {e}")

        # Try metasploit module via msfconsole if available
        if shutil.which("msfconsole"):
            self.print_status("Consider running: msfconsole -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS {target}; run'")

        return False

    def _run_nmap_rdp(self, target: str, port: int) -> None:
        """Run nmap RDP scripts"""
        if not shutil.which("nmap"):
            return

        self.print_status("Running nmap RDP scripts...")
        try:
            result = subprocess.run(
                ["nmap", "-p", str(port), "-sV", "--script", "rdp-*", target],
                capture_output=False,
                timeout=300
            )
        except:
            pass

    def check(self) -> bool:
        """Quick check if target has RDP open"""
        target = self.get_option("RHOSTS")
        port = int(self.get_option("RPORT"))
        return self._check_port(target, port)
