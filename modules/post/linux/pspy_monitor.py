"""
pspy64 Process Monitor Module
Tmux-based process monitoring for privilege escalation reconnaissance
Runs pspy64 in a background tmux session with live attach/detach support
"""

import os
import shlex
from datetime import datetime
from typing import List
from core.module_base import ModuleBase, ModuleType, Platform


class PspyMonitor(ModuleBase):
    """
    Run pspy64 on target Linux system for process monitoring via tmux

    Features:
    - Upload pspy64 to target via SSH
    - Run in a tmux session (background, detach/reattach)
    - Output teed to loot file for offline review
    - Highlight cron jobs, scripts, and privileged processes
    - Actions: run, attach, status, kill
    """

    # Interesting process patterns for post-run analysis
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
        self.description = "Run pspy64 in a tmux session for process monitoring - detect cron jobs and privilege escalation vectors"
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
        self.register_option("PSPY_PATH", "Path to pspy64 binary (local/container)", default="/opt/resources/linux/pspy/pspy64")
        self.register_option("REMOTE_PATH", "Remote path to upload pspy64", default="/tmp/pspy64")
        self.register_option("LOOT_DIR", "Directory to save loot", default="~/.uwu-toolkit/loot")
        self.register_option(
            "ACTION", "Action to perform",
            default="run",
            choices=["run", "attach", "status", "kill"]
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _session_name(self) -> str:
        """Tmux session name based on target host"""
        host = self.get_option("RHOST")
        return f"uwu-pspy-{host}"

    def _get_loot_dir(self) -> str:
        """Get and create loot directory (inside Exegol)"""
        loot_dir = self.get_option("LOOT_DIR")
        # Expand ~ for the container's home
        if loot_dir.startswith("~"):
            loot_dir = loot_dir.replace("~", "/root", 1)
        self.run_in_exegol(f"mkdir -p {shlex.quote(loot_dir)}")
        return loot_dir

    def _loot_path(self) -> str:
        """Build the loot file path"""
        loot_dir = self._get_loot_dir()
        host = self.get_option("RHOST")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{loot_dir}/pspy_{host}_{timestamp}.log"

    def _build_ssh_base(self) -> str:
        """Build the SSH command prefix with auth"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

        if ssh_key:
            return f"ssh -tt -i {shlex.quote(ssh_key)} {ssh_opts} -p {port} {user}@{host}"
        elif password:
            return f"sshpass -p {shlex.quote(password)} ssh -tt {ssh_opts} -p {port} {user}@{host}"
        else:
            return f"ssh -tt {ssh_opts} -p {port} {user}@{host}"

    def _build_scp_cmd(self, local_path: str, remote_path: str) -> str:
        """Build SCP command string for file upload"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        scp_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

        if ssh_key:
            return f"scp -i {shlex.quote(ssh_key)} {scp_opts} -P {port} {shlex.quote(local_path)} {user}@{host}:{remote_path}"
        elif password:
            return f"sshpass -p {shlex.quote(password)} scp {scp_opts} -P {port} {shlex.quote(local_path)} {user}@{host}:{remote_path}"
        else:
            return f"scp {scp_opts} -P {port} {shlex.quote(local_path)} {user}@{host}:{remote_path}"

    def _build_ssh_cmd(self, remote_cmd: str) -> str:
        """Build a full SSH command that executes remote_cmd on the target"""
        ssh_base = self._build_ssh_base()
        return f"{ssh_base} {shlex.quote(remote_cmd)}"

    # =========================================================================
    # Actions
    # =========================================================================

    def _upload_pspy(self) -> bool:
        """Upload pspy64 to target via SCP"""
        local_path = self.get_option("PSPY_PATH")
        remote_path = self.get_option("REMOTE_PATH")

        # Check if pspy64 exists locally (inside Exegol)
        ret, out, err = self.run_in_exegol(f"test -f {shlex.quote(local_path)} && echo EXISTS")
        if "EXISTS" not in out:
            # Try common Exegol paths
            for path in ["/opt/resources/linux/pspy/pspy64", "/opt/tools/pspy64"]:
                ret, out, err = self.run_in_exegol(f"test -f {shlex.quote(path)} && echo EXISTS")
                if "EXISTS" in out:
                    local_path = path
                    self.print_status(f"Found pspy64 at {local_path}")
                    break
            else:
                self.print_error(f"pspy64 not found at {local_path} or common paths")
                self.print_status("Attempting to download pspy64...")
                ret, out, err = self.run_in_exegol(
                    "wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64",
                    timeout=60
                )
                if ret != 0:
                    self.print_error(f"Failed to download pspy64: {err}")
                    return False
                local_path = "/tmp/pspy64"
                self.print_good("Downloaded pspy64")

        self.print_status(f"Uploading pspy64 to {remote_path}...")
        scp_cmd = self._build_scp_cmd(local_path, remote_path)
        ret, out, err = self.run_in_exegol(scp_cmd, timeout=60)

        if ret != 0:
            self.print_error(f"Failed to upload pspy64: {err}")
            return False

        # Make executable
        chmod_cmd = self._build_ssh_cmd(f"chmod +x {remote_path}")
        ret, out, err = self.run_in_exegol(chmod_cmd, timeout=15)

        if ret != 0:
            self.print_error(f"Failed to chmod pspy64: {err}")
            return False

        self.print_good("pspy64 uploaded successfully")
        return True

    def _action_run(self) -> bool:
        """Upload pspy64, start tmux session, and attach"""
        session = self._session_name()

        # Check if session already exists
        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo EXISTS")
        if "EXISTS" in out:
            self.print_warning(f"Tmux session '{session}' already exists")
            self.print_status("Use ACTION=attach to reattach, or ACTION=kill to stop it first")
            return False

        # Upload pspy64
        if not self._upload_pspy():
            return False

        # Build paths
        remote_path = self.get_option("REMOTE_PATH")
        loot_path = self._loot_path()

        # Build the SSH command that runs pspy
        ssh_base = self._build_ssh_base()
        ssh_cmd = f"{ssh_base} '{remote_path} -pf -i 1000 2>&1'"

        # Start in tmux with tee to loot file
        tmux_cmd = f"tmux new-session -d -s {shlex.quote(session)} \"{ssh_cmd} | tee {loot_path}\""

        self.print_status(f"Starting pspy64 in tmux session: {session}")
        ret, out, err = self.run_in_exegol(tmux_cmd)

        if ret != 0:
            self.print_error(f"Failed to start tmux session: {err}")
            return False

        self.print_good(f"pspy64 running in tmux session: {session}")
        self.print_good(f"Output teed to: {loot_path}")
        self.print_line()
        self.print_status("Attaching to session... (Ctrl+B, D to detach)")
        self.print_line()

        # Attach interactively
        self.run_in_exegol_interactive(f"tmux attach-session -t {shlex.quote(session)}")

        # After detach/exit, check if session still exists
        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo EXISTS")
        if "EXISTS" in out:
            self.print_line()
            self.print_good(f"Detached. pspy64 continues running in background.")
            self.print_status(f"  Reattach:  ACTION=attach")
            self.print_status(f"  Status:    ACTION=status")
            self.print_status(f"  Stop:      ACTION=kill")
        else:
            self.print_line()
            self.print_status("Tmux session ended.")
            self._analyze_loot(loot_path)

        return True

    def _action_attach(self) -> bool:
        """Reattach to an existing pspy tmux session"""
        session = self._session_name()

        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo EXISTS")
        if "EXISTS" not in out:
            self.print_error(f"No tmux session '{session}' found")
            self.print_status("Start one first with ACTION=run")
            return False

        self.print_status(f"Attaching to session: {session} (Ctrl+B, D to detach)")
        self.run_in_exegol_interactive(f"tmux attach-session -t {shlex.quote(session)}")

        # After detach
        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo EXISTS")
        if "EXISTS" in out:
            self.print_good("Detached. Session still running in background.")
        else:
            self.print_status("Session ended.")

        return True

    def _action_status(self) -> bool:
        """Check if pspy tmux session is still running"""
        session = self._session_name()

        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo EXISTS")
        if "EXISTS" in out:
            self.print_good(f"Session '{session}' is RUNNING")

            # Show last few lines of output
            ret, out, err = self.run_in_exegol(
                f"tmux capture-pane -t {shlex.quote(session)} -p -S -10"
            )
            if ret == 0 and out.strip():
                self.print_line()
                self.print_status("Last lines of output:")
                self.print_line("-" * 60)
                for line in out.strip().split('\n'):
                    self.print_line(f"  {line}")
                self.print_line("-" * 60)

            return True
        else:
            self.print_warning(f"Session '{session}' is NOT running")
            return False

    def _action_kill(self) -> bool:
        """Kill the tmux session and clean up pspy from the remote target"""
        session = self._session_name()
        remote_path = self.get_option("REMOTE_PATH")

        # Kill tmux session
        ret, out, err = self.run_in_exegol(f"tmux has-session -t {shlex.quote(session)} 2>/dev/null && echo EXISTS")
        if "EXISTS" in out:
            self.print_status(f"Killing tmux session: {session}")
            self.run_in_exegol(f"tmux kill-session -t {shlex.quote(session)}")
            self.print_good("Tmux session killed")
        else:
            self.print_status(f"No active tmux session '{session}' to kill")

        # Clean up pspy from remote target
        self.print_status(f"Cleaning up {remote_path} from remote target...")
        cleanup_ssh = self._build_ssh_cmd(f"pkill -f {remote_path} 2>/dev/null; rm -f {remote_path}")
        ret, out, err = self.run_in_exegol(cleanup_ssh, timeout=15)

        if ret == 0:
            self.print_good("Remote cleanup complete")
        else:
            self.print_warning(f"Remote cleanup may have partially failed: {err}")

        # Find and analyze latest loot file
        host = self.get_option("RHOST")
        loot_dir = self._get_loot_dir()
        ret, out, err = self.run_in_exegol(
            f"ls -t {loot_dir}/pspy_{host}_*.log 2>/dev/null | head -1"
        )
        if ret == 0 and out.strip():
            loot_path = out.strip()
            self._analyze_loot(loot_path)

        return True

    # =========================================================================
    # Loot Analysis
    # =========================================================================

    def _analyze_loot(self, loot_path: str) -> None:
        """Parse a pspy loot file for interesting processes and save summary"""
        self.print_status(f"Analyzing loot: {loot_path}")

        ret, out, err = self.run_in_exegol(f"cat {shlex.quote(loot_path)}", timeout=30)
        if ret != 0 or not out.strip():
            self.print_warning("No output to analyze")
            return

        lines = out.split('\n')
        interesting_finds: List[str] = []

        for line in lines:
            if not line.strip():
                continue

            # Check for interesting patterns
            for pattern in self.INTERESTING_PATTERNS:
                if pattern.lower() in line.lower():
                    interesting_finds.append(line)
                    break
            else:
                # Check for UID=0 (root processes) if no pattern matched
                if 'UID=0' in line:
                    interesting_finds.append(line)

        # Print summary
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Analysis Summary")
        self.print_good("=" * 60)
        self.print_status(f"Total lines captured: {len(lines)}")
        self.print_status(f"Interesting processes: {len(interesting_finds)}")

        if interesting_finds:
            # Save interesting finds to separate file
            interesting_path = loot_path.replace(".log", "_interesting.log")
            interesting_content = f"# Interesting processes from {self.get_option('RHOST')}\n"
            interesting_content += f"# Analyzed: {datetime.now().isoformat()}\n"
            interesting_content += "#" + "=" * 60 + "\n\n"
            for line in interesting_finds:
                interesting_content += line + '\n'

            # Write via Exegol
            escaped_content = interesting_content.replace("'", "'\\''")
            self.run_in_exegol(
                f"printf '%s' '{escaped_content}' > {shlex.quote(interesting_path)}"
            )

            self.print_good(f"Interesting finds saved: {interesting_path}")
            self.print_line()
            self.print_warning("Interesting Processes Found:")
            self.print_line("-" * 60)

            # Show first 20 interesting finds
            for line in interesting_finds[:20]:
                if 'UID=0' in line:
                    self.print_warning(f"  {line[:120]}")
                else:
                    self.print_line(f"  {line[:120]}")

            if len(interesting_finds) > 20:
                self.print_line(f"  ... and {len(interesting_finds) - 20} more (see loot file)")

        self.print_line()
        self.print_good(f"Full output: {loot_path}")

    # =========================================================================
    # Main Entry Points
    # =========================================================================

    def run(self) -> bool:
        """Main execution - dispatch based on ACTION"""
        action = self.get_option("ACTION")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  pspy64 Process Monitor")
        self.print_good("=" * 60)
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
        ssh_cmd = self._build_ssh_cmd("echo pspy_check_ok")
        ret, out, err = self.run_in_exegol(ssh_cmd, timeout=15)

        if ret == 0 and 'pspy_check_ok' in out:
            self.print_good("SSH connection successful")
            return True

        self.print_error(f"SSH connection failed: {err}")
        return False


module = PspyMonitor()
