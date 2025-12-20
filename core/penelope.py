"""
Penelope Shell Handler Integration for UwU Toolkit
Provides interactive Penelope shell management with session integration
https://github.com/brightio/penelope
"""

import os
import sys
import subprocess
import shutil
import select
import pty
import termios
import tty
import re
import threading
import time
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
from datetime import datetime
from dataclasses import dataclass, field

from .colors import Colors, Style
from .shells import ShellManager, Shell, ShellType, ShellStatus, get_shell_manager


@dataclass
class PenelopeSession:
    """Represents a Penelope shell session"""
    id: int
    remote_ip: str
    remote_port: int
    hostname: str = "unknown"
    user: str = "unknown"
    os_type: str = "unknown"
    upgraded: bool = False
    created_at: datetime = field(default_factory=datetime.now)


class PenelopeClient:
    """Wrapper for Penelope shell handler"""

    def __init__(self, config=None):
        self.config = config
        self.penelope_path: Optional[str] = None
        self._find_penelope()

    def _find_penelope(self) -> None:
        """Find Penelope executable"""
        # Common locations
        search_paths = [
            "/opt/penelope/penelope.py",
            "/opt/tools/penelope/penelope.py",
            "/usr/local/bin/penelope",
            "~/.local/bin/penelope",
            "/opt/tools/bin/penelope",
        ]

        # Check PATH first
        penelope = shutil.which("penelope") or shutil.which("penelope.py")
        if penelope:
            self.penelope_path = penelope
        else:
            for path in search_paths:
                p = Path(path).expanduser()
                if p.exists() and p.is_file():
                    self.penelope_path = str(p)
                    break

    def is_available(self) -> Tuple[bool, str]:
        """Check if Penelope is available"""
        if not self.penelope_path:
            return False, "Penelope not found. Install from: https://github.com/brightio/penelope"
        return True, f"Penelope ready ({self.penelope_path})"

    def get_version(self) -> Optional[str]:
        """Get Penelope version"""
        if not self.penelope_path:
            return None
        try:
            result = subprocess.run(
                [self.penelope_path, "--help"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Try to extract version from help output
            return "latest"
        except:
            return None


class PenelopeMode:
    """Interactive Penelope mode handler - runs Penelope in pseudo-terminal"""

    def __init__(self, client: PenelopeClient, config=None):
        self.client = client
        self.config = config
        self.running = False
        self.backgrounded = False
        self.process: Optional[subprocess.Popen] = None
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None
        self.listen_port: int = 4444
        self.listen_interface: str = "0.0.0.0"
        self.sessions: Dict[int, PenelopeSession] = {}
        self._output_buffer: str = ""
        self._shell_manager = get_shell_manager()
        self._session_monitor_thread: Optional[threading.Thread] = None

    def start(self, port: int = 4444, interface: str = "0.0.0.0") -> None:
        """Start interactive Penelope mode"""
        available, msg = self.client.is_available()
        if not available:
            print(Style.error(msg))
            return

        self.listen_port = port
        self.listen_interface = interface
        self.running = True
        self.backgrounded = False

        print()
        print(f"  {Colors.NEON_ORANGE}╔══════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_PINK}Penelope Shell Handler{Colors.RESET}                             {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  Listening on {Colors.NEON_GREEN}{interface}:{port}{Colors.RESET}                        {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_CYAN}Ctrl+D{Colors.RESET} - Background and return to UwU              {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_CYAN}quit{Colors.RESET}   - Exit Penelope and return to UwU           {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}╚══════════════════════════════════════════════════════╝{Colors.RESET}")
        print()

        self._run_penelope()

    def resume(self) -> None:
        """Resume backgrounded Penelope session"""
        if not self.process or self.process.poll() is not None:
            print(Style.warning("No backgrounded Penelope session"))
            print(Style.info("Use 'penelope' or 'penelope <port>' to start a new session"))
            return

        self.running = True
        self.backgrounded = False

        print()
        print(Style.success("Resumed Penelope session"))
        print(Style.info(f"Listening on {self.listen_interface}:{self.listen_port}"))
        print()

        self._resume_interactive()

    def _run_penelope(self) -> None:
        """Run Penelope in pseudo-terminal"""
        # Create pseudo-terminal
        self.master_fd, self.slave_fd = pty.openpty()

        # Build command
        cmd = [self.client.penelope_path, str(self.listen_port)]
        if self.listen_interface != "0.0.0.0":
            cmd = [self.client.penelope_path, "-i", self.listen_interface, str(self.listen_port)]

        try:
            # Start Penelope process
            self.process = subprocess.Popen(
                cmd,
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid
            )

            # Close slave in parent
            os.close(self.slave_fd)
            self.slave_fd = None

            # Start session monitor thread
            self._start_session_monitor()

            # Run interactive loop
            self._interactive_loop()

        except Exception as e:
            print(Style.error(f"Failed to start Penelope: {e}"))
            self._cleanup()

    def _start_session_monitor(self) -> None:
        """Start thread to monitor for new sessions"""
        def monitor():
            while self.running and not self.backgrounded:
                self._parse_sessions_from_buffer()
                time.sleep(1)

        self._session_monitor_thread = threading.Thread(target=monitor, daemon=True)
        self._session_monitor_thread.start()

    def _parse_sessions_from_buffer(self) -> None:
        """Parse Penelope output for session info and sync with shell manager"""
        # Penelope outputs session info like:
        # [+] Got shell from 10.10.10.100:54321 -> 0.0.0.0:4444
        # Session ID: 1

        # Pattern for new connection
        conn_pattern = r'\[\+\].*?(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*.*?:(\d+)'

        for match in re.finditer(conn_pattern, self._output_buffer):
            remote_ip = match.group(1)
            remote_port = int(match.group(2))
            local_port = int(match.group(3))

            # Check if we already have this shell
            existing = False
            for shell in self._shell_manager.shells.values():
                if shell.remote_ip == remote_ip and shell.remote_port == remote_port:
                    existing = True
                    break

            if not existing:
                # Add to shell manager
                shell = Shell(
                    id=self._shell_manager.next_id,
                    shell_type=ShellType.PENELOPE,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    local_port=local_port,
                    process=self.process,
                    status=ShellStatus.ACTIVE
                )
                self._shell_manager.shells[shell.id] = shell
                self._shell_manager.next_id += 1

                # Also track locally
                self.sessions[shell.id] = PenelopeSession(
                    id=shell.id,
                    remote_ip=remote_ip,
                    remote_port=remote_port
                )

    def _resume_interactive(self) -> None:
        """Resume interactive loop with existing process"""
        if self.master_fd is None:
            print(Style.error("No active Penelope PTY"))
            return
        self._interactive_loop()

    def _interactive_loop(self) -> None:
        """Main interactive loop - forward I/O between user and Penelope"""
        old_settings = termios.tcgetattr(sys.stdin)

        try:
            tty.setraw(sys.stdin.fileno())

            while self.running and not self.backgrounded:
                if self.process.poll() is not None:
                    self.running = False
                    break

                rlist, _, _ = select.select([sys.stdin, self.master_fd], [], [], 0.1)

                for fd in rlist:
                    if fd == sys.stdin:
                        try:
                            data = os.read(sys.stdin.fileno(), 1024)
                        except OSError:
                            break

                        if not data:
                            continue

                        # Check for Ctrl+D (EOF) - background
                        if data == b'\x04':
                            self.backgrounded = True
                            break

                        try:
                            os.write(self.master_fd, data)
                        except OSError:
                            self.running = False
                            break

                    elif fd == self.master_fd:
                        try:
                            data = os.read(self.master_fd, 4096)
                        except OSError:
                            self.running = False
                            break

                        if not data:
                            self.running = False
                            break

                        # Buffer output for session parsing
                        try:
                            self._output_buffer += data.decode('utf-8', errors='replace')
                            # Keep buffer manageable
                            if len(self._output_buffer) > 10000:
                                self._output_buffer = self._output_buffer[-5000:]
                        except:
                            pass

                        try:
                            os.write(sys.stdout.fileno(), data)
                            sys.stdout.flush()
                        except OSError:
                            break

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

        if self.backgrounded:
            print()
            print(Style.info("Penelope session backgrounded"))
            print(Style.dim(f"  Listener still active on port {self.listen_port}"))
            print(Style.dim("  Use 'penelope resume' or 'penelope fg' to return"))
            print(Style.dim("  Use 'shells' to see connected sessions"))
        elif not self.running:
            print()
            print(Style.info("Penelope session ended"))
            self._cleanup()

    def _cleanup(self) -> None:
        """Clean up resources"""
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

        if self.slave_fd:
            try:
                os.close(self.slave_fd)
            except OSError:
                pass
            self.slave_fd = None

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            self.process = None

        # Mark Penelope shells as dead
        for session_id in self.sessions:
            if session_id in self._shell_manager.shells:
                self._shell_manager.shells[session_id].status = ShellStatus.DEAD

    def is_backgrounded(self) -> bool:
        """Check if there's a backgrounded Penelope session"""
        return self.process is not None and self.process.poll() is None

    def get_sessions(self) -> List[PenelopeSession]:
        """Get all Penelope sessions"""
        return list(self.sessions.values())

    def status(self) -> Dict[str, Any]:
        """Get Penelope status"""
        return {
            "running": self.running,
            "backgrounded": self.backgrounded,
            "port": self.listen_port if self.process else None,
            "sessions": len(self.sessions),
            "process_alive": self.process is not None and self.process.poll() is None
        }


def get_penelope_help() -> str:
    """Return help text for Penelope commands"""
    return f"""
{Colors.NEON_ORANGE}Penelope Shell Handler Commands{Colors.RESET}
{Colors.NEON_ORANGE}================================{Colors.RESET}

{Colors.NEON_PURPLE}Start Listener{Colors.RESET}
  {Colors.NEON_CYAN}penelope{Colors.RESET}
      Start Penelope on default port (4444)

  {Colors.NEON_CYAN}penelope <port>{Colors.RESET}
      Start Penelope on specified port

  {Colors.NEON_CYAN}penelope -i <interface> <port>{Colors.RESET}
      Start on specific interface

{Colors.NEON_PURPLE}Session Management{Colors.RESET}
  {Colors.NEON_CYAN}penelope resume{Colors.RESET} or {Colors.NEON_CYAN}penelope fg{Colors.RESET}
      Resume backgrounded Penelope session

  {Colors.NEON_CYAN}shells{Colors.RESET}
      List all shell sessions (including Penelope)

  {Colors.NEON_CYAN}interact <id>{Colors.RESET}
      Interact with a shell session

{Colors.NEON_PURPLE}Info{Colors.RESET}
  {Colors.NEON_CYAN}penelope status{Colors.RESET}
      Check Penelope status

{Colors.NEON_PURPLE}Typical Workflow{Colors.RESET}
  1. {Colors.NEON_CYAN}penelope 4444{Colors.RESET}     Start listener
  2. Receive shells...
  3. {Colors.NEON_GREEN}Ctrl+D{Colors.RESET}            Background (listener stays active)
  4. {Colors.NEON_CYAN}shells{Colors.RESET}            View all sessions
  5. {Colors.NEON_CYAN}penelope resume{Colors.RESET}   Return to Penelope
  6. Use Penelope menu to interact with shells

{Colors.NEON_PURPLE}Penelope Features{Colors.RESET}
  - Auto shell upgrade (PTY)
  - Session persistence
  - Multi-session handling
  - Spawn functionality
  - Download/Upload files

{Colors.NEON_PURPLE}Inside Penelope{Colors.RESET}
  {Colors.NEON_GREEN}show{Colors.RESET}          List sessions
  {Colors.NEON_GREEN}interact <n>{Colors.RESET}  Interact with session
  {Colors.NEON_GREEN}upgrade{Colors.RESET}       Upgrade to PTY
  {Colors.NEON_GREEN}spawn{Colors.RESET}         Spawn new listener
  {Colors.NEON_GREEN}download{Colors.RESET}      Download file
  {Colors.NEON_GREEN}upload{Colors.RESET}        Upload file
"""


# Global Penelope mode instance
_penelope_mode: Optional[PenelopeMode] = None


def get_penelope_mode(config=None) -> PenelopeMode:
    """Get or create global Penelope mode instance"""
    global _penelope_mode
    if _penelope_mode is None:
        client = PenelopeClient(config)
        _penelope_mode = PenelopeMode(client, config)
    return _penelope_mode
