"""
pspy64 Process Monitor Module
Automated process monitoring for privilege escalation reconnaissance
Runs pspy64 for configurable duration and saves output to loot
"""

import os
import time
import subprocess
import threading
from datetime import datetime
from typing import Optional, List, Tuple
from core.module_base import ModuleBase, ModuleType, Platform


class PspyMonitor(ModuleBase):
    """
    Run pspy64 on target Linux system for process monitoring

    Features:
    - Upload pspy64 to target via SSH
    - Run for configurable duration (default 2 minutes)
    - Capture and parse output for interesting processes
    - Save to loot directory with timestamp
    - Highlight cron jobs, scripts, and privileged processes
    """

    # Interesting process patterns
    INTERESTING_PATTERNS = [
        '/bin/sh', '/bin/bash', 'python', 'perl', 'ruby',
        'cron', 'root', 'mysql', 'postgres', 'backup',
        'script', '.sh', 'wget', 'curl', 'nc', 'ncat',
        'passwd', 'shadow', 'sudoers', 'ssh', 'key',
        '/tmp/', '/var/tmp/', '/dev/shm/',
    ]

    def __init__(self):
        super().__init__()
        self.name = "pspy_monitor"
        self.description = "Run pspy64 for process monitoring - detect cron jobs and privilege escalation vectors"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.POST
        self.platform = Platform.LINUX
        self.tags = ["privesc", "linux", "process", "cron", "monitoring", "pspy"]
        self.references = [
            "https://github.com/DominicBreuker/pspy",
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/",
        ]

        # Register options
        self.register_option("RHOST", "Target host IP", required=True)
        self.register_option("RPORT", "SSH port", default="22")
        self.register_option("USERNAME", "SSH username", required=True)
        self.register_option("PASSWORD", "SSH password", default="")
        self.register_option("SSH_KEY", "Path to SSH private key", default="")
        self.register_option("DURATION", "Monitoring duration in seconds", default="120")
        self.register_option("PSPY_PATH", "Path to pspy64 binary (local)", default="/opt/resources/linux/pspy/pspy64")
        self.register_option("REMOTE_PATH", "Remote path to upload pspy64", default="/tmp/pspy64")
        self.register_option("LOOT_DIR", "Directory to save loot", default="~/.uwu-toolkit/loot")
        self.register_option("EXEGOL_CONTAINER", "Exegol container name", default="")

        # Runtime
        self._process = None
        self._output_lines = []
        self._interesting_finds = []

    def _get_loot_dir(self) -> str:
        """Get and create loot directory"""
        loot_dir = os.path.expanduser(self.get_option("LOOT_DIR"))
        os.makedirs(loot_dir, exist_ok=True)
        return loot_dir

    def _build_ssh_cmd(self, remote_cmd: str) -> List[str]:
        """Build SSH command with proper authentication"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        if ssh_key:
            return [
                "ssh", "-i", ssh_key,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(port),
                f"{user}@{host}",
                remote_cmd
            ]
        elif password:
            return [
                "sshpass", "-p", password,
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(port),
                f"{user}@{host}",
                remote_cmd
            ]
        else:
            return [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(port),
                f"{user}@{host}",
                remote_cmd
            ]

    def _build_scp_cmd(self, local_path: str, remote_path: str) -> List[str]:
        """Build SCP command for file upload"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        if ssh_key:
            return [
                "scp", "-i", ssh_key,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(port),
                local_path,
                f"{user}@{host}:{remote_path}"
            ]
        elif password:
            return [
                "sshpass", "-p", password,
                "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(port),
                local_path,
                f"{user}@{host}:{remote_path}"
            ]
        else:
            return [
                "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(port),
                local_path,
                f"{user}@{host}:{remote_path}"
            ]

    def _run_via_exegol(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Run command via Exegol container if configured"""
        container = self.get_option("EXEGOL_CONTAINER")
        if container:
            docker_cmd = ["docker", "exec", container] + cmd
            try:
                result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=300)
                return result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                return -1, "", "Command timed out"
            except Exception as e:
                return -1, "", str(e)
        else:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                return result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                return -1, "", "Command timed out"
            except Exception as e:
                return -1, "", str(e)

    def _upload_pspy(self) -> bool:
        """Upload pspy64 to target"""
        local_path = self.get_option("PSPY_PATH")
        remote_path = self.get_option("REMOTE_PATH")

        # Check if local pspy exists
        container = self.get_option("EXEGOL_CONTAINER")
        if container:
            # Check inside container
            ret, out, err = self._run_via_exegol(["test", "-f", local_path])
            if ret != 0:
                # Try common Exegol paths
                for path in ["/opt/resources/linux/pspy/pspy64", "/opt/tools/pspy64"]:
                    ret, out, err = self._run_via_exegol(["test", "-f", path])
                    if ret == 0:
                        local_path = path
                        break
                else:
                    self.print_error(f"pspy64 not found in container. Downloading...")
                    self._run_via_exegol([
                        "wget", "-q",
                        "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64",
                        "-O", "/tmp/pspy64"
                    ])
                    local_path = "/tmp/pspy64"

        self.print_status(f"Uploading pspy64 to {remote_path}...")
        scp_cmd = self._build_scp_cmd(local_path, remote_path)
        ret, out, err = self._run_via_exegol(scp_cmd)

        if ret != 0:
            self.print_error(f"Failed to upload pspy64: {err}")
            return False

        # Make executable
        chmod_cmd = self._build_ssh_cmd(f"chmod +x {remote_path}")
        ret, out, err = self._run_via_exegol(chmod_cmd)

        if ret != 0:
            self.print_error(f"Failed to chmod pspy64: {err}")
            return False

        self.print_good("pspy64 uploaded successfully")
        return True

    def _run_pspy(self, duration: int) -> str:
        """Run pspy64 and capture output"""
        remote_path = self.get_option("REMOTE_PATH")

        self.print_status(f"Running pspy64 for {duration} seconds...")
        self.print_status("Monitoring processes... (Ctrl+C to stop early)")

        # Run pspy with timeout
        pspy_cmd = self._build_ssh_cmd(f"timeout {duration} {remote_path} -pf -i 1000 2>&1 || true")

        container = self.get_option("EXEGOL_CONTAINER")
        if container:
            full_cmd = ["docker", "exec", container] + pspy_cmd
        else:
            full_cmd = pspy_cmd

        try:
            # Run with extended timeout
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=duration + 30
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.print_warning("pspy monitoring timed out")
            return ""
        except Exception as e:
            self.print_error(f"Error running pspy: {e}")
            return ""

    def _parse_output(self, output: str) -> None:
        """Parse pspy output for interesting processes"""
        self._output_lines = output.split('\n')
        self._interesting_finds = []

        for line in self._output_lines:
            if not line.strip():
                continue

            # Check for interesting patterns
            for pattern in self.INTERESTING_PATTERNS:
                if pattern.lower() in line.lower():
                    self._interesting_finds.append(line)
                    break

            # Check for UID=0 (root processes)
            if 'UID=0' in line:
                if line not in self._interesting_finds:
                    self._interesting_finds.append(line)

    def _save_loot(self, output: str) -> str:
        """Save output to loot directory"""
        loot_dir = self._get_loot_dir()
        host = self.get_option("RHOST")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Full output
        full_path = os.path.join(loot_dir, f"pspy_{host}_{timestamp}.log")
        with open(full_path, 'w') as f:
            f.write(f"# pspy64 output from {host}\n")
            f.write(f"# Captured: {datetime.now().isoformat()}\n")
            f.write(f"# Duration: {self.get_option('DURATION')} seconds\n")
            f.write("#" + "="*60 + "\n\n")
            f.write(output)

        # Interesting finds
        if self._interesting_finds:
            interesting_path = os.path.join(loot_dir, f"pspy_{host}_{timestamp}_interesting.log")
            with open(interesting_path, 'w') as f:
                f.write(f"# Interesting processes from {host}\n")
                f.write(f"# Captured: {datetime.now().isoformat()}\n")
                f.write("#" + "="*60 + "\n\n")
                for line in self._interesting_finds:
                    f.write(line + '\n')
            self.print_good(f"Interesting finds saved: {interesting_path}")

        return full_path

    def _cleanup(self) -> None:
        """Clean up pspy from target"""
        remote_path = self.get_option("REMOTE_PATH")
        self.print_status("Cleaning up pspy64 from target...")

        rm_cmd = self._build_ssh_cmd(f"rm -f {remote_path}")
        self._run_via_exegol(rm_cmd)

    def run(self) -> bool:
        """Main execution"""
        duration = int(self.get_option("DURATION"))

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  pspy64 Process Monitor")
        self.print_good("=" * 60)
        self.print_line()

        # Upload pspy64
        if not self._upload_pspy():
            return False

        # Run pspy
        output = self._run_pspy(duration)

        if not output:
            self.print_error("No output captured from pspy64")
            self._cleanup()
            return False

        # Parse output
        self._parse_output(output)

        # Save loot
        loot_path = self._save_loot(output)
        self.print_good(f"Full output saved: {loot_path}")

        # Print summary
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Summary")
        self.print_good("=" * 60)
        self.print_status(f"Total lines captured: {len(self._output_lines)}")
        self.print_status(f"Interesting processes: {len(self._interesting_finds)}")

        if self._interesting_finds:
            self.print_line()
            self.print_warning("Interesting Processes Found:")
            self.print_line("-" * 60)
            # Show first 20 interesting finds
            for line in self._interesting_finds[:20]:
                # Highlight UID=0
                if 'UID=0' in line:
                    self.print_warning(f"  {line[:100]}")
                else:
                    self.print_line(f"  {line[:100]}")

            if len(self._interesting_finds) > 20:
                self.print_line(f"  ... and {len(self._interesting_finds) - 20} more (see loot file)")

        # Cleanup
        self._cleanup()

        return True

    def check(self) -> bool:
        """Check if target is reachable via SSH"""
        ssh_cmd = self._build_ssh_cmd("echo 'test'")
        ret, out, err = self._run_via_exegol(ssh_cmd)

        if ret == 0 and 'test' in out:
            self.print_good("SSH connection successful")
            return True

        self.print_error(f"SSH connection failed: {err}")
        return False
