"""
FTP Enumeration Module
Enumerate FTP servers for anonymous access and interesting files
"""

import subprocess
import shutil
import os
import ftplib
import socket
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform


class FTPEnum(ModuleBase):
    """
    FTP enumeration module:
    - Check for anonymous login
    - List directory contents recursively
    - Download interesting files
    - Check for writable directories
    - Banner grabbing for version detection
    """

    def __init__(self):
        super().__init__()
        self.name = "ftp_enum"
        self.description = "FTP server enumeration and file discovery"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["ftp", "network", "enumeration", "anonymous", "files"]
        self.references = [
            "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ftp.html",
        ]

        # Register options
        self.register_option("RHOST", "Target host", required=True)
        self.register_option("RPORT", "FTP port", default="21")
        self.register_option("USERNAME", "FTP username (blank for anonymous)", default="anonymous")
        self.register_option("PASSWORD", "FTP password", default="anonymous@example.com")
        self.register_option("DOWNLOAD", "Download interesting files",
                           default="yes", choices=["yes", "no"])
        self.register_option("OUTPUT", "Output directory for downloads", default="./ftp_loot")
        self.register_option("MAX_FILES", "Max files to download", default="50")
        self.register_option("CHECK_WRITE", "Check for writable directories",
                           default="yes", choices=["yes", "no"])
        self.register_option("TIMEOUT", "Connection timeout in seconds", default="10")

    def run(self) -> bool:
        target = self.get_option("RHOST")
        port = int(self.get_option("RPORT"))
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        download = self.get_option("DOWNLOAD") == "yes"
        output_dir = self.get_option("OUTPUT")
        max_files = int(self.get_option("MAX_FILES"))
        check_write = self.get_option("CHECK_WRITE") == "yes"
        timeout = int(self.get_option("TIMEOUT"))

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  FTP Enumeration")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}:{port}")
        self.print_status(f"Username: {username}")
        self.print_line()

        # Phase 1: Banner grabbing
        self.print_good("[Phase 1] Banner Grabbing")
        self.print_line("-" * 40)

        banner = self._grab_banner(target, port, timeout)
        if banner:
            self.print_status(f"Banner: {banner}")
        else:
            self.print_warning("Could not grab banner")

        # Phase 2: Login attempt
        self.print_line()
        self.print_good("[Phase 2] Authentication")
        self.print_line("-" * 40)

        ftp = self._connect_ftp(target, port, username, password, timeout)
        if not ftp:
            self.print_error("Failed to connect/authenticate")
            return False

        self.print_good(f"Successfully logged in as: {username}")

        # Phase 3: Directory listing
        self.print_line()
        self.print_good("[Phase 3] Directory Enumeration")
        self.print_line("-" * 40)

        all_files = []
        interesting_files = []
        writable_dirs = []

        self._recursive_list(ftp, "/", all_files, interesting_files, depth=0, max_depth=5)

        self.print_status(f"Total files found: {len(all_files)}")
        self.print_status(f"Interesting files: {len(interesting_files)}")

        if interesting_files:
            self.print_line()
            self.print_good("Interesting files found:")
            for f_type, f_path in interesting_files:
                self.print_status(f"  [{f_type}] {f_path}")

        # Phase 4: Check writable directories
        if check_write:
            self.print_line()
            self.print_good("[Phase 4] Checking Writable Directories")
            self.print_line("-" * 40)

            writable_dirs = self._check_writable(ftp, "/")
            if writable_dirs:
                self.print_good("Writable directories found:")
                for d in writable_dirs:
                    self.print_status(f"  {d}")
            else:
                self.print_warning("No writable directories found")

        # Phase 5: Download files
        if download and interesting_files:
            self.print_line()
            self.print_good("[Phase 5] Downloading Files")
            self.print_line("-" * 40)

            downloaded = self._download_files(ftp, interesting_files[:max_files],
                                              f"{output_dir}/{target}_{timestamp}")
            self.print_good(f"Downloaded {downloaded} file(s)")

        # Cleanup
        try:
            ftp.quit()
        except:
            pass

        # Summary
        self._print_summary(target, port, username, all_files, interesting_files,
                           writable_dirs, output_dir, timestamp)

        return True

    def _grab_banner(self, target: str, port: int, timeout: int) -> Optional[str]:
        """Grab FTP banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except Exception as e:
            return None

    def _connect_ftp(self, target: str, port: int, username: str,
                     password: str, timeout: int) -> Optional[ftplib.FTP]:
        """Connect to FTP server"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=timeout)
            ftp.login(username, password)
            return ftp
        except ftplib.error_perm as e:
            self.print_error(f"Login failed: {e}")
            return None
        except Exception as e:
            self.print_error(f"Connection error: {e}")
            return None

    def _recursive_list(self, ftp: ftplib.FTP, path: str, all_files: List[str],
                        interesting: List[Tuple[str, str]], depth: int, max_depth: int) -> None:
        """Recursively list FTP directories"""
        if depth > max_depth:
            return

        try:
            ftp.cwd(path)
            items = []
            ftp.retrlines('LIST', items.append)

            for item in items:
                parts = item.split()
                if len(parts) < 9:
                    continue

                perms = parts[0]
                name = ' '.join(parts[8:])
                full_path = f"{path.rstrip('/')}/{name}"

                if perms.startswith('d'):
                    # Directory
                    if name not in ['.', '..']:
                        self._recursive_list(ftp, full_path, all_files, interesting,
                                           depth + 1, max_depth)
                else:
                    # File
                    all_files.append(full_path)

                    # Check if interesting
                    f_type = self._classify_file(name)
                    if f_type:
                        interesting.append((f_type, full_path))

        except ftplib.error_perm:
            pass  # Access denied
        except Exception as e:
            pass

    def _classify_file(self, filename: str) -> Optional[str]:
        """Classify file as interesting or not"""
        name_lower = filename.lower()

        # SSH keys
        if name_lower in ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys']:
            return "SSH_KEY"

        # Credentials
        if any(x in name_lower for x in ['password', 'passwd', 'credential', 'secret', '.htpasswd']):
            return "CREDENTIALS"

        # Config files
        if name_lower.endswith(('.conf', '.config', '.ini', '.yaml', '.yml', '.xml', '.json')):
            return "CONFIG"

        # Backup files
        if name_lower.endswith(('.bak', '.backup', '.old', '.tar', '.tar.gz', '.zip', '.7z')):
            return "BACKUP"

        # Database
        if name_lower.endswith(('.sql', '.db', '.sqlite', '.sqlite3', '.mdb')):
            return "DATABASE"

        # Flags/sensitive
        if any(x in name_lower for x in ['flag', 'proof', 'root.txt', 'user.txt', '.env']):
            return "FLAG"

        # Text files that might contain info
        if name_lower.endswith('.txt'):
            return "TEXT"

        # Scripts
        if name_lower.endswith(('.sh', '.py', '.pl', '.php', '.asp', '.aspx', '.jsp')):
            return "SCRIPT"

        return None

    def _check_writable(self, ftp: ftplib.FTP, path: str, depth: int = 0) -> List[str]:
        """Check for writable directories"""
        writable = []
        max_depth = 3

        if depth > max_depth:
            return writable

        try:
            ftp.cwd(path)

            # Try to create test file
            test_name = ".uwu_write_test"
            try:
                ftp.storbinary(f'STOR {test_name}', open('/dev/null', 'rb'))
                ftp.delete(test_name)
                writable.append(path)
                self.print_status(f"  Writable: {path}")
            except:
                pass

            # Check subdirectories
            items = []
            ftp.retrlines('LIST', items.append)

            for item in items:
                parts = item.split()
                if len(parts) >= 9 and parts[0].startswith('d'):
                    name = ' '.join(parts[8:])
                    if name not in ['.', '..']:
                        full_path = f"{path.rstrip('/')}/{name}"
                        writable.extend(self._check_writable(ftp, full_path, depth + 1))

        except:
            pass

        return writable

    def _download_files(self, ftp: ftplib.FTP, files: List[Tuple[str, str]],
                        output_dir: str) -> int:
        """Download interesting files"""
        os.makedirs(output_dir, exist_ok=True)
        downloaded = 0

        for f_type, f_path in files:
            try:
                # Create local path
                local_name = f_path.replace('/', '_').lstrip('_')
                local_path = os.path.join(output_dir, local_name)

                # Download file
                with open(local_path, 'wb') as f:
                    ftp.retrbinary(f'RETR {f_path}', f.write)

                self.print_status(f"  Downloaded: {f_path} -> {local_name}")
                downloaded += 1

            except Exception as e:
                self.print_warning(f"  Failed to download {f_path}: {e}")

        return downloaded

    def _print_summary(self, target: str, port: int, username: str,
                       all_files: List[str], interesting: List[Tuple[str, str]],
                       writable: List[str], output_dir: str, timestamp: str) -> None:
        """Print enumeration summary"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  FTP Enumeration Summary")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}:{port}")
        self.print_status(f"Login: {username}")
        self.print_status(f"Total Files: {len(all_files)}")
        self.print_status(f"Interesting Files: {len(interesting)}")
        self.print_status(f"Writable Directories: {len(writable)}")

        if interesting:
            self.print_line()
            self.print_warning("Interesting files by category:")
            by_type: Dict[str, List[str]] = {}
            for f_type, f_path in interesting:
                if f_type not in by_type:
                    by_type[f_type] = []
                by_type[f_type].append(f_path)

            for f_type, files in by_type.items():
                self.print_line(f"  [{f_type}]: {len(files)} file(s)")

        if writable:
            self.print_line()
            self.print_warning("Exploitation opportunities:")
            self.print_line("  - Upload web shell if FTP root is web root")
            self.print_line("  - Upload SSH key to .ssh/authorized_keys")
            self.print_line("  - Upload cron job if writable cron dir")

        self.print_line()
        self.print_status(f"Downloaded files saved to: {output_dir}")

    def check(self) -> bool:
        """Check requirements"""
        return True  # Uses built-in ftplib
