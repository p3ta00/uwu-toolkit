"""
LinPEAS Enumeration Module
Automated Linux privilege escalation enumeration with color output support
"""

import os
import subprocess
import re
from datetime import datetime
from typing import Optional, List, Tuple
from core.module_base import ModuleBase, ModuleType, Platform


class LinpeasEnum(ModuleBase):
    """
    Run LinPEAS on target Linux system for privilege escalation enumeration

    Features:
    - Upload linpeas.sh to target via SSH
    - Run with color output preservation
    - Save output with ANSI colors to loot
    - Parse for critical findings
    - View output with native colors via loot viewer
    """

    # Severity patterns to look for
    CRITICAL_PATTERNS = [
        r'95%.*PE',  # 95% PE - Critical escalation vector
        r'99%.*PE',  # 99% PE - Almost certain escalation
        r'\[1;31m.*\[0m',  # Red text (critical)
    ]

    HIGH_PATTERNS = [
        r'SUID',
        r'capabilities',
        r'NOPASSWD',
        r'writable',
        r'docker',
        r'lxd',
        r'/etc/passwd.*writable',
        r'/etc/shadow.*readable',
    ]

    def __init__(self):
        super().__init__()
        self.name = "linpeas_enum"
        self.description = "Run LinPEAS for comprehensive privilege escalation enumeration with color output"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.POST
        self.platform = Platform.LINUX
        self.tags = ["privesc", "linux", "enumeration", "linpeas", "post-exploitation"]
        self.references = [
            "https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS",
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/",
        ]

        # Register options
        self.register_option("RHOST", "Target host IP", required=True)
        self.register_option("RPORT", "SSH port", default="22")
        self.register_option("USERNAME", "SSH username", required=True)
        self.register_option("PASSWORD", "SSH password", default="")
        self.register_option("SSH_KEY", "Path to SSH private key", default="")
        self.register_option("LINPEAS_PATH", "Path to linpeas.sh (local)", default="/opt/resources/linux/linPEAS/linpeas.sh")
        self.register_option("LINPEAS_ARGS", "Additional linpeas arguments", default="-a")
        self.register_option("REMOTE_PATH", "Remote path to upload linpeas", default="/tmp/linpeas.sh")
        self.register_option("LOOT_DIR", "Directory to save loot", default="~/.uwu-toolkit/loot")
        self.register_option("EXEGOL_CONTAINER", "Exegol container name", default="")
        self.register_option("TIMEOUT", "Execution timeout in seconds", default="600")

        # Runtime
        self._critical_findings = []
        self._high_findings = []

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

        # Force pseudo-terminal allocation for colors
        base_opts = [
            "-tt",  # Force pseudo-terminal allocation
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(port),
        ]

        if ssh_key:
            return ["ssh", "-i", ssh_key] + base_opts + [f"{user}@{host}", remote_cmd]
        elif password:
            return ["sshpass", "-p", password, "ssh"] + base_opts + [f"{user}@{host}", remote_cmd]
        else:
            return ["ssh"] + base_opts + [f"{user}@{host}", remote_cmd]

    def _build_scp_cmd(self, local_path: str, remote_path: str) -> List[str]:
        """Build SCP command for file upload"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        base_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-P", str(port),
        ]

        if ssh_key:
            return ["scp", "-i", ssh_key] + base_opts + [local_path, f"{user}@{host}:{remote_path}"]
        elif password:
            return ["sshpass", "-p", password, "scp"] + base_opts + [local_path, f"{user}@{host}:{remote_path}"]
        else:
            return ["scp"] + base_opts + [local_path, f"{user}@{host}:{remote_path}"]

    def _run_via_exegol(self, cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
        """Run command via Exegol container if configured"""
        container = self.get_option("EXEGOL_CONTAINER")
        if container:
            docker_cmd = ["docker", "exec", container] + cmd
        else:
            docker_cmd = cmd

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, 'TERM': 'xterm-256color'}
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _upload_linpeas(self) -> bool:
        """Upload linpeas.sh to target"""
        local_path = self.get_option("LINPEAS_PATH")
        remote_path = self.get_option("REMOTE_PATH")

        container = self.get_option("EXEGOL_CONTAINER")
        if container:
            # Try common Exegol paths
            for path in [
                "/opt/resources/linux/linPEAS/linpeas.sh",
                "/opt/tools/linpeas.sh",
                "/usr/share/peass/linpeas/linpeas.sh"
            ]:
                ret, out, err = self._run_via_exegol(["test", "-f", path])
                if ret == 0:
                    local_path = path
                    break
            else:
                self.print_status("LinPEAS not found locally, downloading...")
                self._run_via_exegol([
                    "wget", "-q",
                    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
                    "-O", "/tmp/linpeas.sh"
                ], timeout=60)
                local_path = "/tmp/linpeas.sh"

        self.print_status(f"Uploading linpeas.sh to {remote_path}...")
        scp_cmd = self._build_scp_cmd(local_path, remote_path)
        ret, out, err = self._run_via_exegol(scp_cmd, timeout=60)

        if ret != 0:
            self.print_error(f"Failed to upload linpeas: {err}")
            return False

        # Make executable
        chmod_cmd = self._build_ssh_cmd(f"chmod +x {remote_path}")
        ret, out, err = self._run_via_exegol(chmod_cmd)

        if ret != 0:
            self.print_error(f"Failed to chmod linpeas: {err}")
            return False

        self.print_good("LinPEAS uploaded successfully")
        return True

    def _run_linpeas(self) -> str:
        """Run linpeas and capture output with colors"""
        remote_path = self.get_option("REMOTE_PATH")
        args = self.get_option("LINPEAS_ARGS")
        timeout = int(self.get_option("TIMEOUT"))

        self.print_status(f"Running LinPEAS (this may take several minutes)...")
        self.print_status("Color output is being captured for later viewing")

        # Run linpeas with ANSI colors enabled
        # Use script command to preserve colors through SSH
        linpeas_cmd = self._build_ssh_cmd(
            f"export TERM=xterm-256color && {remote_path} {args} 2>&1"
        )

        container = self.get_option("EXEGOL_CONTAINER")
        if container:
            full_cmd = ["docker", "exec", "-e", "TERM=xterm-256color", container] + linpeas_cmd
        else:
            full_cmd = linpeas_cmd

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, 'TERM': 'xterm-256color'}
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.print_warning("LinPEAS execution timed out (partial output may be available)")
            return ""
        except Exception as e:
            self.print_error(f"Error running linpeas: {e}")
            return ""

    def _parse_findings(self, output: str) -> None:
        """Parse output for critical and high severity findings"""
        self._critical_findings = []
        self._high_findings = []

        lines = output.split('\n')

        for i, line in enumerate(lines):
            # Strip ANSI codes for pattern matching
            clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)

            # Check for critical patterns
            for pattern in self.CRITICAL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE) or re.search(pattern, clean_line, re.IGNORECASE):
                    # Get context (line before and after)
                    context_start = max(0, i - 1)
                    context_end = min(len(lines), i + 2)
                    context = '\n'.join(lines[context_start:context_end])
                    if context not in self._critical_findings:
                        self._critical_findings.append(context)
                    break

            # Check for high patterns
            for pattern in self.HIGH_PATTERNS:
                if re.search(pattern, clean_line, re.IGNORECASE):
                    if line not in self._high_findings and line not in str(self._critical_findings):
                        self._high_findings.append(line)
                    break

    def _save_loot(self, output: str) -> Tuple[str, str]:
        """Save output to loot directory with colors preserved"""
        loot_dir = self._get_loot_dir()
        host = self.get_option("RHOST")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Full output with ANSI colors
        color_path = os.path.join(loot_dir, f"linpeas_{host}_{timestamp}_color.log")
        with open(color_path, 'w') as f:
            f.write(output)

        # Plain text version (stripped of ANSI)
        plain_output = re.sub(r'\x1b\[[0-9;]*m', '', output)
        plain_path = os.path.join(loot_dir, f"linpeas_{host}_{timestamp}_plain.txt")
        with open(plain_path, 'w') as f:
            f.write(f"# LinPEAS output from {host}\n")
            f.write(f"# Captured: {datetime.now().isoformat()}\n")
            f.write("#" + "="*60 + "\n\n")
            f.write(plain_output)

        # Findings summary
        if self._critical_findings or self._high_findings:
            findings_path = os.path.join(loot_dir, f"linpeas_{host}_{timestamp}_findings.txt")
            with open(findings_path, 'w') as f:
                f.write(f"# LinPEAS Findings Summary - {host}\n")
                f.write(f"# Captured: {datetime.now().isoformat()}\n")
                f.write("#" + "="*60 + "\n\n")

                if self._critical_findings:
                    f.write("=" * 60 + "\n")
                    f.write("CRITICAL FINDINGS\n")
                    f.write("=" * 60 + "\n\n")
                    for finding in self._critical_findings:
                        clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                        f.write(clean + "\n\n")

                if self._high_findings:
                    f.write("\n" + "=" * 60 + "\n")
                    f.write("HIGH SEVERITY FINDINGS\n")
                    f.write("=" * 60 + "\n\n")
                    for finding in self._high_findings[:50]:  # Limit to 50
                        clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                        f.write(clean + "\n")

            self.print_good(f"Findings saved: {findings_path}")

        return color_path, plain_path

    def _cleanup(self) -> None:
        """Clean up linpeas from target"""
        remote_path = self.get_option("REMOTE_PATH")
        self.print_status("Cleaning up linpeas from target...")

        rm_cmd = self._build_ssh_cmd(f"rm -f {remote_path}")
        self._run_via_exegol(rm_cmd)

    def run(self) -> bool:
        """Main execution"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  LinPEAS Privilege Escalation Enumeration")
        self.print_good("=" * 60)
        self.print_line()

        # Upload linpeas
        if not self._upload_linpeas():
            return False

        # Run linpeas
        output = self._run_linpeas()

        if not output:
            self.print_error("No output captured from LinPEAS")
            self._cleanup()
            return False

        # Parse findings
        self._parse_findings(output)

        # Save loot
        color_path, plain_path = self._save_loot(output)
        self.print_line()
        self.print_good(f"Color output saved: {color_path}")
        self.print_good(f"Plain text saved: {plain_path}")

        # Print summary
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Summary")
        self.print_good("=" * 60)
        self.print_status(f"Critical findings: {len(self._critical_findings)}")
        self.print_status(f"High severity findings: {len(self._high_findings)}")

        if self._critical_findings:
            self.print_line()
            self.print_warning("CRITICAL - Likely Privilege Escalation Vectors:")
            self.print_line("-" * 60)
            for finding in self._critical_findings[:5]:
                # Strip ANSI and truncate
                clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                for line in clean.split('\n')[:3]:
                    self.print_warning(f"  {line[:80]}")
                self.print_line()

        if self._high_findings:
            self.print_line()
            self.print_status("HIGH - Notable Findings (sample):")
            self.print_line("-" * 60)
            for finding in self._high_findings[:10]:
                clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                self.print_line(f"  {clean[:80]}")

        self.print_line()
        self.print_good("To view with colors: loot view <filename>")

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
