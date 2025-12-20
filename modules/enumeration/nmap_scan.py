"""
Custom Nmap Scanner Module
Provides various scanning profiles with easy configuration
"""

import subprocess
import shutil
from core.module_base import ModuleBase, ModuleType, Platform


class NmapScanner(ModuleBase):
    """
    Enhanced Nmap scanner with predefined profiles and output management
    """

    def __init__(self):
        super().__init__()
        self.name = "nmap_scan"
        self.description = "Custom Nmap scanner with multiple profiles"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["network", "scanner", "enumeration", "nmap", "recon"]

        # Register options
        self.register_option("RHOSTS", "Target host(s) or CIDR range", required=True)
        self.register_option("PORTS", "Port specification (default: top 1000)", default="")
        self.register_option("PROFILE", "Scan profile: quick, standard, full, vuln, stealth",
                           default="standard", choices=["quick", "standard", "full", "vuln", "stealth", "udp"])
        self.register_option("OUTPUT", "Output directory for results", default="./nmap_results")
        self.register_option("EXTRA_ARGS", "Additional nmap arguments", default="")
        self.register_option("USE_SUDO", "Run with sudo (required for some scans)", default="auto")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        profile = self.get_option("PROFILE")
        ports = self.get_option("PORTS")
        output_dir = self.get_option("OUTPUT")
        extra_args = self.get_option("EXTRA_ARGS")
        use_sudo = self.get_option("USE_SUDO")

        # Check nmap exists
        if not shutil.which("nmap"):
            self.print_error("nmap not found in PATH")
            return False

        # Build command based on profile
        cmd = self._build_command(profile, target, ports, output_dir, extra_args)

        # Determine if sudo is needed
        needs_sudo = profile in ["full", "vuln", "stealth", "udp"] or use_sudo == "yes"
        if use_sudo == "auto" and needs_sudo:
            self.print_status("This scan profile requires root privileges")

        if needs_sudo and use_sudo != "no":
            cmd = ["sudo"] + cmd

        self.print_status(f"Running {profile} scan against {target}")
        self.print_status(f"Command: {' '.join(cmd)}")
        self.print_line()

        # Create output directory
        import os
        os.makedirs(output_dir, exist_ok=True)

        # Run nmap
        try:
            result = subprocess.run(cmd, capture_output=False)
            return result.returncode == 0
        except KeyboardInterrupt:
            self.print_warning("Scan interrupted")
            return False

    def _build_command(self, profile: str, target: str, ports: str, output_dir: str, extra: str) -> list:
        """Build nmap command based on profile"""
        base_output = f"{output_dir}/scan_{target.replace('/', '_')}"

        profiles = {
            "quick": [
                "nmap", "-T4", "-F",
                "-oA", f"{base_output}_quick"
            ],
            "standard": [
                "nmap", "-sC", "-sV", "-T4",
                "-oA", f"{base_output}_standard"
            ],
            "full": [
                "nmap", "-sC", "-sV", "-p-", "-T4",
                "-oA", f"{base_output}_full"
            ],
            "vuln": [
                "nmap", "-sC", "-sV", "--script=vuln",
                "-oA", f"{base_output}_vuln"
            ],
            "stealth": [
                "nmap", "-sS", "-T2", "-f",
                "-oA", f"{base_output}_stealth"
            ],
            "udp": [
                "nmap", "-sU", "-sV", "--top-ports", "100",
                "-oA", f"{base_output}_udp"
            ],
        }

        cmd = profiles.get(profile, profiles["standard"])

        # Add custom ports if specified
        if ports:
            cmd.extend(["-p", ports])

        # Add extra arguments
        if extra:
            cmd.extend(extra.split())

        # Add target
        cmd.append(target)

        return cmd

    def check(self) -> bool:
        """Check if nmap is available"""
        return shutil.which("nmap") is not None
