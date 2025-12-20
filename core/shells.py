"""
Shell Management System for UwU Toolkit
Provides Sliver-like shell management with:
- Multiple shell tracking
- Shell interaction via ID
- Penelope and nc listener integration
- Ctrl+D to return to uwu-toolkit
"""

import os
import sys
import pty
import select
import signal
import socket as socket_module
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from . import tmux_status
from typing import Dict, List, Optional, Tuple, Callable, Any
from enum import Enum
from pathlib import Path

from .colors import Colors, Style


class ShellType(Enum):
    """Type of shell connection"""
    REVERSE = "reverse"
    BIND = "bind"
    PENELOPE = "penelope"
    NC = "nc"


class ShellStatus(Enum):
    """Shell connection status"""
    ACTIVE = "active"
    DEAD = "dead"
    UNKNOWN = "unknown"


@dataclass
class Shell:
    """Represents a connected shell session"""
    id: int
    shell_type: ShellType
    remote_ip: str
    remote_port: int
    local_port: int
    sock: Any = None  # socket object
    process: Optional[subprocess.Popen] = None
    pty_fd: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    os_info: str = "Unknown"
    user: str = "Unknown"
    hostname: str = "Unknown"
    status: ShellStatus = ShellStatus.ACTIVE
    notes: str = ""

    def __post_init__(self):
        if isinstance(self.shell_type, str):
            self.shell_type = ShellType(self.shell_type)
        if isinstance(self.status, str):
            self.status = ShellStatus(self.status)


class ShellManager:
    """
    Manages multiple shell sessions.
    Provides Sliver-like interface for shell interaction.
    """

    def __init__(self):
        self.shells: Dict[int, Shell] = {}
        self.next_id = 1
        self.listeners: Dict[int, dict] = {}  # port -> listener info
        self.active_shell: Optional[Shell] = None
        self._lock = threading.Lock()
        self._listener_threads: Dict[int, threading.Thread] = {}
        self._running = True

    def add_shell(self, shell_type: ShellType, remote_ip: str, remote_port: int,
                  local_port: int, sock: Any = None,
                  process: Optional[subprocess.Popen] = None) -> Shell:
        """Register a new shell connection"""
        with self._lock:
            shell = Shell(
                id=self.next_id,
                shell_type=shell_type,
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=local_port,
                sock=sock,
                process=process
            )
            self.shells[self.next_id] = shell
            self.next_id += 1

            # Try to get basic info
            self._probe_shell(shell)

            return shell

    def _probe_shell(self, shell: Shell) -> None:
        """Try to get OS/user info from shell"""
        # This will be implemented based on shell type
        pass

    def remove_shell(self, shell_id: int) -> bool:
        """Remove a shell by ID"""
        with self._lock:
            if shell_id in self.shells:
                shell = self.shells[shell_id]
                self._cleanup_shell(shell)
                del self.shells[shell_id]
                return True
            return False

    def _cleanup_shell(self, shell: Shell) -> None:
        """Clean up shell resources"""
        try:
            if shell.sock:
                shell.sock.close()
            if shell.process:
                shell.process.terminate()
            if shell.pty_fd:
                os.close(shell.pty_fd)
        except Exception:
            pass

    def get_shell(self, shell_id: int) -> Optional[Shell]:
        """Get shell by ID"""
        return self.shells.get(shell_id)

    def list_shells(self) -> List[Shell]:
        """List all shells"""
        return list(self.shells.values())

    def interact(self, shell_id: int) -> bool:
        """
        Interact with a shell session.
        Returns to uwu-toolkit on Ctrl+D (EOF).
        """
        shell = self.get_shell(shell_id)
        if not shell:
            print(Style.error(f"Shell {shell_id} not found"))
            return False

        if shell.status == ShellStatus.DEAD:
            print(Style.error(f"Shell {shell_id} is dead"))
            return False

        self.active_shell = shell
        print(Style.success(f"Interacting with shell {shell_id}"))
        print(Style.info(f"Remote: {shell.remote_ip}:{shell.remote_port}"))
        print(Style.warning("Press Ctrl+D to return to uwu-toolkit"))
        print()

        try:
            if shell.sock:
                self._interact_socket(shell)
            elif shell.process:
                self._interact_process(shell)
            else:
                print(Style.error("Shell has no connection"))
                return False
        except Exception as e:
            print(Style.error(f"Interaction error: {e}"))
        finally:
            self.active_shell = None
            print()
            print(Style.info("Returning to uwu-toolkit"))

        return True

    def _interact_socket(self, shell: Shell) -> None:
        """Interactive session with socket-based shell"""
        sock = shell.sock
        if not sock:
            return

        # Set socket to non-blocking
        sock.setblocking(False)

        # Save terminal settings
        import termios
        import tty
        old_settings = termios.tcgetattr(sys.stdin)

        try:
            # Set terminal to raw mode
            tty.setraw(sys.stdin.fileno())

            while True:
                # Wait for input from stdin or socket
                readable, _, _ = select.select([sys.stdin, sock], [], [], 0.1)

                for r in readable:
                    if r == sys.stdin:
                        # Read from terminal
                        try:
                            data = os.read(sys.stdin.fileno(), 1024)
                            if not data:
                                # EOF (Ctrl+D)
                                return
                            # Check for Ctrl+D
                            if b'\x04' in data:
                                return
                            sock.send(data)
                        except (OSError, IOError):
                            pass

                    elif r == sock:
                        # Read from socket
                        try:
                            data = sock.recv(4096)
                            if not data:
                                print("\r\nConnection closed by remote host\r\n")
                                shell.status = ShellStatus.DEAD
                                return
                            sys.stdout.write(data.decode('utf-8', errors='replace'))
                            sys.stdout.flush()
                            shell.last_active = datetime.now()
                        except socket_module.error:
                            pass
                        except BlockingIOError:
                            pass

        except KeyboardInterrupt:
            pass
        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

    def _interact_process(self, shell: Shell) -> None:
        """Interactive session with process-based shell (Penelope)"""
        proc = shell.process
        if not proc or not proc.stdin or not proc.stdout:
            return

        import termios
        import tty
        old_settings = termios.tcgetattr(sys.stdin)

        try:
            tty.setraw(sys.stdin.fileno())

            while proc.poll() is None:
                readable, _, _ = select.select([sys.stdin, proc.stdout], [], [], 0.1)

                for r in readable:
                    if r == sys.stdin:
                        data = os.read(sys.stdin.fileno(), 1024)
                        if not data or b'\x04' in data:
                            return
                        proc.stdin.write(data)
                        proc.stdin.flush()

                    elif r == proc.stdout:
                        data = proc.stdout.read(4096)
                        if data:
                            sys.stdout.write(data.decode('utf-8', errors='replace'))
                            sys.stdout.flush()
                            shell.last_active = datetime.now()

        except KeyboardInterrupt:
            pass
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

    def start_listener(self, port: int, listener_type: str = "nc",
                       callback: Optional[Callable] = None) -> bool:
        """
        Start a listener on specified port.
        Supports: nc (netcat), penelope
        """
        if port in self.listeners:
            print(Style.warning(f"Listener already running on port {port}"))
            return False

        if listener_type == "nc":
            return self._start_nc_listener(port, callback)
        elif listener_type == "penelope":
            return self._start_penelope_listener(port, callback)
        else:
            print(Style.error(f"Unknown listener type: {listener_type}"))
            return False

    def _start_nc_listener(self, port: int, callback: Optional[Callable] = None) -> bool:
        """Start netcat listener in background"""
        def nc_thread():
            try:
                # Create server socket
                server = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
                server.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
                server.bind(('0.0.0.0', port))
                server.listen(5)
                server.settimeout(1.0)  # Allow checking for shutdown

                self.listeners[port] = {
                    "type": "nc",
                    "socket": server,
                    "started": datetime.now(),
                    "connections": 0
                }

                print(Style.success(f"[*] Listening on 0.0.0.0:{port}"))

                while self._running and port in self.listeners:
                    try:
                        client, addr = server.accept()
                        remote_ip, remote_port = addr

                        # Register the shell
                        shell = self.add_shell(
                            shell_type=ShellType.NC,
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            local_port=port,
                            sock=client
                        )

                        self.listeners[port]["connections"] += 1

                        # Update tmux status bar - shell received!
                        tmux_status.update_listener(port, "connected", self.listeners[port]["connections"])

                        print()
                        print(f"{Colors.NEON_GREEN}[+] Shell {shell.id} connected from {remote_ip}:{remote_port}{Colors.RESET}")
                        print(f"{Colors.NEON_CYAN}[*] Use 'interact {shell.id}' to interact{Colors.RESET}")

                        if callback:
                            callback(shell)

                    except socket_module.timeout:
                        continue
                    except Exception as e:
                        if self._running:
                            print(Style.error(f"Accept error: {e}"))
                        break

            except Exception as e:
                print(Style.error(f"Listener error: {e}"))
            finally:
                if port in self.listeners:
                    try:
                        self.listeners[port]["socket"].close()
                    except:
                        pass
                    del self.listeners[port]

        thread = threading.Thread(target=nc_thread, daemon=True)
        thread.start()
        self._listener_threads[port] = thread

        # Give it a moment to start
        time.sleep(0.2)
        return port in self.listeners

    def _start_penelope_listener(self, port: int, callback: Optional[Callable] = None) -> bool:
        """Start Penelope listener"""
        # Check if penelope is available
        penelope_path = self._find_penelope()
        if not penelope_path:
            print(Style.error("Penelope not found. Install with: pip install penelope-shell"))
            print(Style.info("Falling back to nc listener"))
            return self._start_nc_listener(port, callback)

        def penelope_thread():
            try:
                # Start penelope
                cmd = [penelope_path, str(port)]
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=0
                )

                self.listeners[port] = {
                    "type": "penelope",
                    "process": proc,
                    "started": datetime.now(),
                    "connections": 0
                }

                print(Style.success(f"[*] Penelope listening on 0.0.0.0:{port}"))

                # Monitor for connections
                while self._running and proc.poll() is None and port in self.listeners:
                    time.sleep(0.5)

            except Exception as e:
                print(Style.error(f"Penelope error: {e}"))
            finally:
                if port in self.listeners:
                    try:
                        self.listeners[port]["process"].terminate()
                    except:
                        pass
                    del self.listeners[port]

        thread = threading.Thread(target=penelope_thread, daemon=True)
        thread.start()
        self._listener_threads[port] = thread

        time.sleep(0.5)
        return port in self.listeners

    def _find_penelope(self) -> Optional[str]:
        """Find penelope executable"""
        import shutil

        # Check common locations
        paths = [
            shutil.which("penelope"),
            "/usr/local/bin/penelope",
            "/opt/penelope/penelope.py",
            str(Path.home() / ".local/bin/penelope"),
        ]

        for p in paths:
            if p and os.path.exists(p):
                return p

        return None

    def stop_listener(self, port: int) -> bool:
        """Stop a listener"""
        if port not in self.listeners:
            return False

        listener = self.listeners[port]

        try:
            if listener["type"] == "nc":
                listener["socket"].close()
            elif listener["type"] == "penelope":
                listener["process"].terminate()
        except:
            pass

        del self.listeners[port]
        return True

    def list_listeners(self) -> List[dict]:
        """List all active listeners"""
        result = []
        for port, info in self.listeners.items():
            result.append({
                "port": port,
                "type": info["type"],
                "started": info["started"],
                "connections": info.get("connections", 0)
            })
        return result

    def kill_shell(self, shell_id: int) -> bool:
        """Kill a shell connection"""
        shell = self.get_shell(shell_id)
        if not shell:
            return False

        self._cleanup_shell(shell)
        shell.status = ShellStatus.DEAD
        return True

    def shutdown(self) -> None:
        """Shutdown all listeners and shells"""
        self._running = False

        # Stop all listeners
        for port in list(self.listeners.keys()):
            self.stop_listener(port)

        # Cleanup all shells
        for shell_id in list(self.shells.keys()):
            self.remove_shell(shell_id)


def print_shells_table(shells: List[Shell]) -> None:
    """Print shells in a nice table format"""
    if not shells:
        print(Style.warning("No active shells"))
        return

    print()
    print(f"  {Colors.NEON_CYAN}Active Shells{Colors.RESET}")
    print(f"  {Colors.NEON_PINK}{'='*70}{Colors.RESET}")
    print()
    print(f"  {Colors.BRIGHT_WHITE}{'ID':<4} {'Type':<10} {'Remote':<22} {'User@Host':<20} {'Status':<8}{Colors.RESET}")
    print(f"  {Colors.GRID}{'-'*4} {'-'*10} {'-'*22} {'-'*20} {'-'*8}{Colors.RESET}")

    for shell in shells:
        remote = f"{shell.remote_ip}:{shell.remote_port}"
        user_host = f"{shell.user}@{shell.hostname}"[:20]

        if shell.status == ShellStatus.ACTIVE:
            status_color = Colors.NEON_GREEN
            status = "ACTIVE"
        elif shell.status == ShellStatus.DEAD:
            status_color = Colors.RED
            status = "DEAD"
        else:
            status_color = Colors.YELLOW
            status = "UNKNOWN"

        print(f"  {Colors.NEON_CYAN}{shell.id:<4}{Colors.RESET} "
              f"{shell.shell_type.value:<10} "
              f"{remote:<22} "
              f"{user_host:<20} "
              f"{status_color}{status:<8}{Colors.RESET}")

    print()
    print(f"  {Colors.GRID}Use 'interact <ID>' to interact with a shell{Colors.RESET}")
    print(f"  {Colors.GRID}Use 'kill <ID>' to kill a shell{Colors.RESET}")
    print()


def print_listeners_table(listeners: List[dict]) -> None:
    """Print listeners in a nice table format"""
    if not listeners:
        print(Style.warning("No active listeners"))
        return

    print()
    print(f"  {Colors.NEON_CYAN}Active Listeners{Colors.RESET}")
    print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}")
    print()
    print(f"  {Colors.BRIGHT_WHITE}{'Port':<8} {'Type':<12} {'Connections':<12} {'Started':<16}{Colors.RESET}")
    print(f"  {Colors.GRID}{'-'*8} {'-'*12} {'-'*12} {'-'*16}{Colors.RESET}")

    for listener in listeners:
        started = listener["started"].strftime("%H:%M:%S")
        print(f"  {Colors.NEON_GREEN}{listener['port']:<8}{Colors.RESET} "
              f"{listener['type']:<12} "
              f"{listener['connections']:<12} "
              f"{started:<16}")

    print()


# Global shell manager instance
_shell_manager: Optional[ShellManager] = None


def get_shell_manager() -> ShellManager:
    """Get the global shell manager instance"""
    global _shell_manager
    if _shell_manager is None:
        _shell_manager = ShellManager()
    return _shell_manager
