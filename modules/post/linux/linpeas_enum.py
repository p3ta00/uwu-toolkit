"""
LinPEAS Enumeration Module
Runs LinPEAS on remote Linux targets via tmux for background execution.
Supports attach/detach, status checks, and session management.
"""

import os
import re
import shlex
from datetime import datetime
from typing import List, Tuple
from core.module_base import ModuleBase, ModuleType, Platform


class LinpeasEnum(ModuleBase):
    """
    Run LinPEAS on target Linux system for privilege escalation enumeration.

    Uses tmux to run LinPEAS in the background so the console is not blocked.
    Output is teed to a loot file for later review and parsing.

    Actions:
      run    - Upload linpeas, start in tmux, auto-attach (Ctrl+B, D to detach)
      attach - Reattach to a running linpeas tmux session
      status - Check if the linpeas session is still running
      kill   - Stop the tmux session and clean up remote files
    """

    # Severity patterns for parsing saved output
    CRITICAL_PATTERNS = [
        r'95%.*PE',
        r'99%.*PE',
        r'\[1;31m.*\[0m',
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
        self.description = "Run LinPEAS in a tmux background session for privilege escalation enumeration"
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
        self.register_option("LINPEAS_PATH", "Path to linpeas.sh (inside Exegol)", default="/opt/resources/linux/linPEAS/linpeas.sh")
        self.register_option("LINPEAS_ARGS", "Additional linpeas arguments", default="-a")
        self.register_option("REMOTE_PATH", "Remote path to upload linpeas", default="/tmp/linpeas.sh")
        self.register_option("LOOT_DIR", "Directory to save loot", default="~/.uwu-toolkit/loot")
        self.register_option("ACTION", "Action to perform", default="run", choices=["run", "attach", "status", "kill"])

        # Runtime
        self._critical_findings = []
        self._high_findings = []

    # =========================================================================
    # Helpers
    # =========================================================================

    def _session_name(self) -> str:
        """Tmux session name based on target host"""
        host = self.get_option("RHOST")
        return f"uwu-linpeas-{host}"

    def _get_loot_dir(self) -> str:
        """Get and create loot directory (inside Exegol)"""
        loot_dir = self.get_option("LOOT_DIR")
        # Expand ~ inside Exegol context
        if loot_dir.startswith("~"):
            loot_dir = loot_dir.replace("~", "/root", 1)
        self.run_in_exegol(f"mkdir -p {shlex.quote(loot_dir)}")
        return loot_dir

    def _loot_path(self) -> str:
        """Full path for the loot output file"""
        loot_dir = self._get_loot_dir()
        host = self.get_option("RHOST")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{loot_dir}/linpeas_{host}_{timestamp}.log"

    def _build_ssh_base(self) -> str:
        """Build the SSH command prefix string (sshpass + ssh flags)"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        ssh_opts = "-tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

        if ssh_key:
            return f"ssh -i {shlex.quote(ssh_key)} {ssh_opts} -p {port} {user}@{host}"
        elif password:
            return f"sshpass -p {shlex.quote(password)} ssh {ssh_opts} -p {port} {user}@{host}"
        else:
            return f"ssh {ssh_opts} -p {port} {user}@{host}"

    def _build_scp_base(self) -> str:
        """Build the SCP command prefix string"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        scp_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

        if ssh_key:
            return f"scp -i {shlex.quote(ssh_key)} {scp_opts} -P {port}", f"{user}@{host}"
        elif password:
            return f"sshpass -p {shlex.quote(password)} scp {scp_opts} -P {port}", f"{user}@{host}"
        else:
            return f"scp {scp_opts} -P {port}", f"{user}@{host}"

    # =========================================================================
    # Upload
    # =========================================================================

    def _upload_linpeas(self) -> bool:
        """Upload linpeas.sh to the target via SCP"""
        local_path = self.get_option("LINPEAS_PATH")
        remote_path = self.get_option("REMOTE_PATH")

        # Verify linpeas exists locally (inside Exegol)
        ret, out, err = self.run_in_exegol(f"test -f {shlex.quote(local_path)} && echo EXISTS")
        if "EXISTS" not in out:
            # Try fallback paths
            fallback_paths = [
                "/opt/resources/linux/linPEAS/linpeas.sh",
                "/opt/tools/linpeas.sh",
                "/usr/share/peass/linpeas/linpeas.sh",
            ]
            found = False
            for path in fallback_paths:
                ret, out, err = self.run_in_exegol(f"test -f {shlex.quote(path)} && echo EXISTS")
                if "EXISTS" in out:
                    local_path = path
                    found = True
                    break

            if not found:
                self.print_status("LinPEAS not found locally, downloading...")
                ret, out, err = self.run_in_exegol(
                    "wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O /tmp/linpeas_download.sh",
                    timeout=60
                )
                if ret != 0:
                    self.print_error(f"Failed to download linpeas: {err}")
                    return False
                local_path = "/tmp/linpeas_download.sh"

        self.print_status(f"Uploading {local_path} to {remote_path}...")

        scp_prefix, user_host = self._build_scp_base()
        scp_cmd = f"{scp_prefix} {shlex.quote(local_path)} {user_host}:{remote_path}"
        ret, out, err = self.run_in_exegol(scp_cmd, timeout=60)

        if ret != 0:
            self.print_error(f"Failed to upload linpeas: {err}")
            return False

        # Make executable
        ssh_base = self._build_ssh_base()
        ret, out, err = self.run_in_exegol(f"{ssh_base} 'chmod +x {remote_path}'")
        if ret != 0:
            self.print_error(f"Failed to chmod linpeas: {err}")
            return False

        self.print_good("LinPEAS uploaded successfully")
        return True

    # =========================================================================
    # Tmux Actions
    # =========================================================================

    def _action_run(self) -> bool:
        """Upload linpeas, start tmux session, auto-attach"""
        session = self._session_name()

        # Check if session already exists
        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo RUNNING")
        if "RUNNING" in out:
            self.print_warning(f"Session '{session}' already running. Use ACTION=attach to reattach or ACTION=kill to stop.")
            return False

        # Upload linpeas to target
        if not self._upload_linpeas():
            return False

        # Build paths and commands
        remote_path = self.get_option("REMOTE_PATH")
        args = self.get_option("LINPEAS_ARGS")
        loot_path = self._loot_path()

        self.print_status(f"Loot will be saved to: {loot_path}")

        # Build the SSH command that runs linpeas
        ssh_base = self._build_ssh_base()
        ssh_cmd = f"{ssh_base} 'export TERM=xterm-256color && {remote_path} {args} 2>&1'"

        # Start in tmux with tee to loot file
        # Use double-quoting carefully: tmux new-session -d -s <name> "<command>"
        tmux_cmd = f"tmux new-session -d -s {shlex.quote(session)} \"{ssh_cmd} | tee {shlex.quote(loot_path)}\""
        ret, out, err = self.run_in_exegol(tmux_cmd)

        if ret != 0:
            self.print_error(f"Failed to start tmux session: {err}")
            return False

        self.print_good(f"LinPEAS started in tmux session: {session}")
        self.print_status("Attaching to session... (Ctrl+B, D to detach)")
        self.print_line()

        # Attach interactively so user can watch live
        self.run_in_exegol_interactive(f"tmux attach-session -t {shlex.quote(session)}")

        # After detach/exit, check if still running
        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo RUNNING")
        if "RUNNING" in out:
            self.print_line()
            self.print_good(f"LinPEAS still running in background session: {session}")
            self.print_status("Use ACTION=attach to reattach, ACTION=status to check, ACTION=kill to stop")
        else:
            self.print_line()
            self.print_good("LinPEAS session completed.")
            self._post_run_parse(loot_path)

        return True

    def _action_attach(self) -> bool:
        """Reattach to an existing linpeas tmux session"""
        session = self._session_name()

        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo RUNNING")
        if "RUNNING" not in out:
            self.print_error(f"No active session '{session}' found.")
            self.print_status("Use ACTION=run to start a new LinPEAS session.")
            return False

        self.print_status(f"Reattaching to session: {session} (Ctrl+B, D to detach)")
        self.run_in_exegol_interactive(f"tmux attach-session -t {shlex.quote(session)}")

        # Check status after detach
        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo RUNNING")
        if "RUNNING" in out:
            self.print_good(f"Session '{session}' still running in background.")
        else:
            self.print_good("Session completed.")

        return True

    def _action_status(self) -> bool:
        """Check if a linpeas tmux session is running"""
        session = self._session_name()

        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo RUNNING")
        if "RUNNING" in out:
            self.print_good(f"Session '{session}' is RUNNING.")

            # Show a tail of the loot file if available
            loot_dir = self._get_loot_dir()
            host = self.get_option("RHOST")
            # Find the most recent loot file for this host
            ret2, out2, err2 = self.run_in_exegol(
                f"ls -t {shlex.quote(loot_dir)}/linpeas_{host}_*.log 2>/dev/null | head -1"
            )
            loot_file = out2.strip()
            if loot_file:
                ret3, out3, err3 = self.run_in_exegol(f"wc -l {shlex.quote(loot_file)}")
                line_count = out3.strip().split()[0] if out3.strip() else "?"
                self.print_status(f"Loot file: {loot_file} ({line_count} lines so far)")

            self.print_status("Use ACTION=attach to watch live output, ACTION=kill to stop.")
        else:
            self.print_warning(f"No active session '{session}'.")

            # Check if loot file exists from a completed run
            loot_dir = self._get_loot_dir()
            host = self.get_option("RHOST")
            ret2, out2, err2 = self.run_in_exegol(
                f"ls -t {shlex.quote(loot_dir)}/linpeas_{host}_*.log 2>/dev/null | head -1"
            )
            loot_file = out2.strip()
            if loot_file:
                self.print_good(f"Completed loot available: {loot_file}")
                self.print_status("Parsing findings from loot file...")
                self._post_run_parse(loot_file)

        return True

    def _action_kill(self) -> bool:
        """Kill the tmux session and clean up"""
        session = self._session_name()

        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo RUNNING")
        if "RUNNING" in out:
            self.run_in_exegol(f"tmux kill-session -t {shlex.quote(session)}")
            self.print_good(f"Session '{session}' killed.")
        else:
            self.print_warning(f"No active session '{session}' to kill.")

        # Clean up remote file
        remote_path = self.get_option("REMOTE_PATH")
        ssh_base = self._build_ssh_base()
        self.print_status(f"Cleaning up {remote_path} on target...")
        self.run_in_exegol(f"{ssh_base} 'rm -f {remote_path}'", timeout=15)
        self.print_good("Cleanup complete.")

        # Parse any loot that was captured
        loot_dir = self._get_loot_dir()
        host = self.get_option("RHOST")
        ret2, out2, err2 = self.run_in_exegol(
            f"ls -t {shlex.quote(loot_dir)}/linpeas_{host}_*.log 2>/dev/null | head -1"
        )
        loot_file = out2.strip()
        if loot_file:
            self.print_status("Parsing captured output...")
            self._post_run_parse(loot_file)

        return True

    # =========================================================================
    # Output Parsing
    # =========================================================================

    def _post_run_parse(self, loot_path: str) -> None:
        """Parse the loot file for findings and print a summary"""
        # Read the loot file content
        ret, output, err = self.run_in_exegol(f"cat {shlex.quote(loot_path)}")
        if ret != 0 or not output:
            self.print_warning("Could not read loot file for parsing.")
            return

        # Parse findings
        self._parse_findings(output)

        # Save a plain-text version and findings summary
        self._save_parsed_loot(output, loot_path)

        # Print summary
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  LinPEAS Summary")
        self.print_good("=" * 60)
        self.print_status(f"Critical findings: {len(self._critical_findings)}")
        self.print_status(f"High severity findings: {len(self._high_findings)}")
        self.print_good(f"Full output: {loot_path}")

        if self._critical_findings:
            self.print_line()
            self.print_warning("CRITICAL - Likely Privilege Escalation Vectors:")
            self.print_line("-" * 60)
            for finding in self._critical_findings[:5]:
                clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                for line in clean.split('\n')[:3]:
                    self.print_warning(f"  {line[:100]}")
                self.print_line()

        if self._high_findings:
            self.print_line()
            self.print_status("HIGH - Notable Findings (sample):")
            self.print_line("-" * 60)
            for finding in self._high_findings[:10]:
                clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                self.print_line(f"  {clean[:100]}")

        self.print_line()
        self.print_good("To view with colors: loot view <filename>")

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

    def _save_parsed_loot(self, output: str, color_log_path: str) -> None:
        """Save plain text and findings summary alongside the color log"""
        # Derive paths from the color log path
        base = color_log_path.rsplit('.log', 1)[0]
        plain_path = f"{base}_plain.txt"
        host = self.get_option("RHOST")
        timestamp = datetime.now().isoformat()

        # Plain text version (strip ANSI codes) — write via Exegol
        plain_header = f"# LinPEAS output from {host}\\n# Captured: {timestamp}\\n#{'=' * 60}\\n\\n"
        # Use sed to strip ANSI and write
        strip_cmd = (
            f"sed 's/\\x1b\\[[0-9;]*m//g' {shlex.quote(color_log_path)} "
            f"| (printf '{plain_header}' && cat) > {shlex.quote(plain_path)}"
        )
        self.run_in_exegol(strip_cmd)
        self.print_good(f"Plain text saved: {plain_path}")

        # Findings summary
        if self._critical_findings or self._high_findings:
            findings_path = f"{base}_findings.txt"
            findings_lines = []
            findings_lines.append(f"# LinPEAS Findings Summary - {host}")
            findings_lines.append(f"# Captured: {timestamp}")
            findings_lines.append("#" + "=" * 60)
            findings_lines.append("")

            if self._critical_findings:
                findings_lines.append("=" * 60)
                findings_lines.append("CRITICAL FINDINGS")
                findings_lines.append("=" * 60)
                findings_lines.append("")
                for finding in self._critical_findings:
                    clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                    findings_lines.append(clean)
                    findings_lines.append("")

            if self._high_findings:
                findings_lines.append("")
                findings_lines.append("=" * 60)
                findings_lines.append("HIGH SEVERITY FINDINGS")
                findings_lines.append("=" * 60)
                findings_lines.append("")
                for finding in self._high_findings[:50]:
                    clean = re.sub(r'\x1b\[[0-9;]*m', '', finding)
                    findings_lines.append(clean)

            # Write findings file via Exegol
            findings_content = "\\n".join(
                line.replace("'", "'\\''") for line in findings_lines
            )
            self.run_in_exegol(f"printf '{findings_content}\\n' > {shlex.quote(findings_path)}")
            self.print_good(f"Findings saved: {findings_path}")

    # =========================================================================
    # Main Entry Points
    # =========================================================================

    def run(self) -> bool:
        """Main execution — dispatches to the appropriate action"""
        action = self.get_option("ACTION")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  LinPEAS Privilege Escalation Enumeration")
        self.print_good("=" * 60)
        self.print_status(f"Target: {self.get_option('RHOST')}  |  Action: {action}")
        self.print_line()

        if action == "run":
            return self._action_run()
        elif action == "attach":
            return self._action_attach()
        elif action == "status":
            return self._action_status()
        elif action == "kill":
            return self._action_kill()
        else:
            self.print_error(f"Unknown action: {action}")
            return False

    def check(self) -> bool:
        """Check if target is reachable via SSH"""
        ssh_base = self._build_ssh_base()
        ret, out, err = self.run_in_exegol(f"{ssh_base} 'echo uwu_test'", timeout=15)

        if ret == 0 and "uwu_test" in out:
            self.print_good("SSH connection successful")
            return True

        self.print_error(f"SSH connection failed: {err}")
        return False


module = LinpeasEnum()
