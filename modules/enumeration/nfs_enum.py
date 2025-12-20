"""
NFS Enumeration Module
Enumerate NFS shares and check for misconfigurations
"""

import subprocess
import shutil
import os
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform


class NFSEnum(ModuleBase):
    """
    NFS enumeration module:
    - Discover NFS shares with showmount
    - Check mount permissions
    - Mount and list contents
    - Find interesting files (SSH keys, configs, etc.)
    """

    def __init__(self):
        super().__init__()
        self.name = "nfs_enum"
        self.description = "NFS share enumeration and exploitation"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["nfs", "network", "shares", "enumeration", "linux"]
        self.references = [
            "https://book.hacktricks.wiki/en/network-services-pentesting/nfs-service-pentesting.html",
        ]

        # Register options
        self.register_option("RHOST", "Target host", required=True)
        self.register_option("MOUNT_POINT", "Local mount point", default="/tmp/nfs_mount")
        self.register_option("AUTO_MOUNT", "Automatically mount discovered shares",
                           default="yes", choices=["yes", "no"])
        self.register_option("SEARCH_FILES", "Search for interesting files after mounting",
                           default="yes", choices=["yes", "no"])
        self.register_option("OUTPUT", "Output directory", default="./nfs_results")

    def run(self) -> bool:
        target = self.get_option("RHOST")
        mount_point = self.get_option("MOUNT_POINT")
        auto_mount = self.get_option("AUTO_MOUNT") == "yes"
        search_files = self.get_option("SEARCH_FILES") == "yes"
        output_dir = self.get_option("OUTPUT")

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  NFS Enumeration")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_line()

        # Phase 1: Show exports
        self.print_good("[Phase 1] Discovering NFS Exports")
        self.print_line("-" * 40)

        shares = self._get_exports(target)
        if not shares:
            self.print_warning("No NFS exports found or host unreachable")
            return False

        self.print_good(f"Found {len(shares)} export(s):")
        for share, access in shares:
            self.print_status(f"  {share} -> {access}")

        # Phase 2: Mount shares
        if auto_mount:
            self.print_line()
            self.print_good("[Phase 2] Mounting Shares")
            self.print_line("-" * 40)

            mounted_shares = []
            for share, access in shares:
                share_mount = f"{mount_point}/{share.replace('/', '_')}"
                if self._mount_share(target, share, share_mount):
                    mounted_shares.append((share, share_mount))

            # Phase 3: Search for interesting files
            if search_files and mounted_shares:
                self.print_line()
                self.print_good("[Phase 3] Searching for Interesting Files")
                self.print_line("-" * 40)

                all_findings = []
                for share, share_mount in mounted_shares:
                    findings = self._search_interesting_files(share_mount)
                    if findings:
                        all_findings.extend(findings)
                        self.print_good(f"Findings in {share}:")
                        for f_type, f_path in findings:
                            self.print_status(f"  [{f_type}] {f_path}")

                # Save findings
                if all_findings:
                    self._save_findings(all_findings, output_dir, timestamp, target)

            # Cleanup info
            self.print_line()
            self.print_warning("Mounted shares (remember to unmount):")
            for share, share_mount in mounted_shares:
                self.print_status(f"  {share_mount}")
                self.print_line(f"    Unmount: sudo umount {share_mount}")

        # Summary
        self._print_summary(target, shares)

        return True

    def _get_exports(self, target: str) -> List[Tuple[str, str]]:
        """Get NFS exports using showmount"""
        try:
            result = subprocess.run(
                ["showmount", "-e", target],
                capture_output=True, text=True, timeout=30
            )

            shares = []
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        share = parts[0]
                        access = ' '.join(parts[1:])
                        shares.append((share, access))

            return shares

        except subprocess.TimeoutExpired:
            self.print_error("showmount timed out")
            return []
        except FileNotFoundError:
            self.print_error("showmount not found. Install nfs-common package.")
            return []
        except Exception as e:
            self.print_error(f"Error getting exports: {e}")
            return []

    def _mount_share(self, target: str, share: str, mount_point: str) -> bool:
        """Mount an NFS share"""
        try:
            os.makedirs(mount_point, exist_ok=True)

            # Try mounting with different options
            mount_opts = [
                [],  # Default
                ["-o", "vers=3"],  # NFSv3
                ["-o", "vers=2"],  # NFSv2
                ["-o", "nolock"],  # No lock
            ]

            for opts in mount_opts:
                cmd = ["sudo", "mount", "-t", "nfs"] + opts + [f"{target}:{share}", mount_point]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    self.print_good(f"Mounted: {target}:{share} -> {mount_point}")
                    return True

            self.print_error(f"Failed to mount {share}")
            return False

        except Exception as e:
            self.print_error(f"Mount error for {share}: {e}")
            return False

    def _search_interesting_files(self, mount_point: str) -> List[Tuple[str, str]]:
        """Search for interesting files in mounted share"""
        findings = []

        # Interesting patterns
        patterns = {
            "SSH_KEY": ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.pem"],
            "CONFIG": ["*.conf", "*.config", "*.ini", "*.yaml", "*.yml"],
            "CREDENTIALS": ["*.htpasswd", "shadow", "passwd", "credentials*", "*.kdbx"],
            "DATABASE": ["*.sql", "*.db", "*.sqlite*"],
            "BACKUP": ["*.bak", "*.backup", "*.old", "*.tar*", "*.zip"],
            "FLAG": ["flag*", "proof*", "root.txt", "user.txt"],
            "SENSITIVE": [".bash_history", ".mysql_history", "wp-config.php", ".env"],
        }

        try:
            for root, dirs, files in os.walk(mount_point):
                # Check for .ssh directory
                if ".ssh" in dirs:
                    ssh_dir = os.path.join(root, ".ssh")
                    findings.append(("SSH_DIR", ssh_dir))
                    # Check for keys
                    for ssh_file in os.listdir(ssh_dir):
                        if ssh_file in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys"]:
                            findings.append(("SSH_KEY", os.path.join(ssh_dir, ssh_file)))

                # Check files
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()

                    for cat, pats in patterns.items():
                        for pat in pats:
                            if pat.startswith("*"):
                                if file_lower.endswith(pat[1:].lower()):
                                    findings.append((cat, file_path))
                                    break
                            elif pat.endswith("*"):
                                if file_lower.startswith(pat[:-1].lower()):
                                    findings.append((cat, file_path))
                                    break
                            elif file_lower == pat.lower():
                                findings.append((cat, file_path))
                                break

        except PermissionError:
            self.print_warning(f"Permission denied accessing some files in {mount_point}")
        except Exception as e:
            self.print_error(f"Error searching files: {e}")

        return findings

    def _save_findings(self, findings: List[Tuple[str, str]], output_dir: str,
                       timestamp: str, target: str) -> None:
        """Save findings to file"""
        output_file = f"{output_dir}/{target.replace('.', '_')}_{timestamp}_nfs_findings.txt"

        try:
            with open(output_file, 'w') as f:
                f.write(f"NFS Enumeration Findings for {target}\n")
                f.write(f"Time: {timestamp}\n")
                f.write("=" * 60 + "\n\n")

                for f_type, f_path in findings:
                    f.write(f"[{f_type}] {f_path}\n")

            self.print_good(f"Findings saved to: {output_file}")

        except Exception as e:
            self.print_error(f"Error saving findings: {e}")

    def _print_summary(self, target: str, shares: List[Tuple[str, str]]) -> None:
        """Print enumeration summary"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  NFS Enumeration Summary")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Exports Found: {len(shares)}")

        self.print_line()
        self.print_warning("Next Steps:")
        self.print_line("  1. Check mounted shares for SSH keys")
        self.print_line("  2. Look for credentials in config files")
        self.print_line("  3. Check for writable shares (upload SSH key)")
        self.print_line("  4. If root_squash is off, upload SUID binary")

        self.print_line()
        self.print_warning("Manual Commands:")
        for share, access in shares:
            self.print_line(f"  mount -t nfs {target}:{share} /mnt/nfs")

        if shares:
            self.print_line()
            self.print_line("  # Check root_squash:")
            self.print_line(f"  nmap --script nfs-showmount {target}")
            self.print_line(f"  rpcinfo -p {target}")

    def check(self) -> bool:
        """Check if required tools are available"""
        if not shutil.which("showmount"):
            self.print_error("showmount not found. Install nfs-common.")
            return False
        return True
