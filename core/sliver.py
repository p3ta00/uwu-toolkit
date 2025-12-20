"""
Sliver C2 Integration for UwU Toolkit
Provides interactive Sliver client within UwU with session management
"""

import os
import sys
import subprocess
import shutil
import signal
import select
import pty
import termios
import tty
import fcntl
import struct
import re
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from datetime import datetime

from .colors import Colors, Style


class SliverClient:
    """Wrapper for Sliver C2 client operations"""

    def __init__(self, config=None):
        self.config = config
        self.sliver_path: Optional[str] = None
        self.server_path: Optional[str] = None
        self.config_dir: Optional[Path] = None
        self.configs_path: Optional[Path] = None
        self._find_sliver()

    def _find_sliver(self) -> None:
        """Find Sliver client and server binaries"""
        # Common locations
        search_paths = [
            "/opt/tools/bin/sliver-client",
            "/opt/tools/bin/sliver",
            "/usr/local/bin/sliver-client",
            "/usr/local/bin/sliver",
            "~/.sliver-client/sliver-client",
        ]

        # Check PATH first
        client = shutil.which("sliver-client") or shutil.which("sliver")
        if client:
            self.sliver_path = client
        else:
            for path in search_paths:
                p = Path(path).expanduser()
                if p.exists() and p.is_file():
                    self.sliver_path = str(p)
                    break

        # Find server
        server_paths = [
            "/opt/tools/bin/sliver-server",
            "/usr/local/bin/sliver-server",
        ]
        server = shutil.which("sliver-server")
        if server:
            self.server_path = server
        else:
            for path in server_paths:
                p = Path(path).expanduser()
                if p.exists():
                    self.server_path = str(p)
                    break

        # Config location - Sliver stores configs in ~/.sliver-client/configs/
        self.config_dir = Path.home() / ".sliver-client"
        self.configs_path = self.config_dir / "configs"

    def is_available(self) -> Tuple[bool, str]:
        """Check if Sliver client is available"""
        if not self.sliver_path:
            return False, "Sliver client not found. Install from: https://github.com/BishopFox/sliver"

        # Check if config exists
        configs = self.get_configs()
        if not configs:
            return False, f"No Sliver configs found in {self.configs_path}. Import with: sliver-client import <config>"

        return True, f"Sliver client ready ({self.sliver_path})"

    def get_configs(self) -> List[Path]:
        """Get available Sliver client configs"""
        if not self.configs_path or not self.configs_path.exists():
            return []
        return list(self.configs_path.glob("*.cfg"))

    def server_is_available(self) -> bool:
        """Check if Sliver server binary is available"""
        return self.server_path is not None


class SliverMode:
    """Interactive Sliver mode handler - runs Sliver client in pseudo-terminal"""

    def __init__(self, client: SliverClient, config=None):
        self.client = client
        self.config = config
        self.running = False
        self.backgrounded = False
        self.process: Optional[subprocess.Popen] = None
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None
        self.old_settings = None
        self.active_config: Optional[str] = None
        self.active_session: Optional[str] = None  # Track active session ID
        self._output_buffer: str = ""  # Buffer for parsing session info

    def start(self, config_name: Optional[str] = None) -> None:
        """Start interactive Sliver mode"""
        available, msg = self.client.is_available()
        if not available:
            print(Style.error(msg))
            return

        self.running = True
        self.backgrounded = False

        print()
        print(f"  {Colors.NEON_ORANGE}╔══════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_PINK}Sliver C2 Interactive Mode{Colors.RESET}                         {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_CYAN}Ctrl+X{Colors.RESET} - Background and return to UwU              {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_CYAN}exit{Colors.RESET}   - Exit Sliver and return to UwU             {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}╚══════════════════════════════════════════════════════╝{Colors.RESET}")
        print()

        self._run_sliver()

    def resume(self) -> None:
        """Resume backgrounded Sliver session"""
        if not self.process or self.process.poll() is not None:
            print(Style.warning("No backgrounded Sliver session"))
            print(Style.info("Use 'sliver' to start a new session"))
            return

        self.running = True
        self.backgrounded = False

        print()
        print(Style.success("Resumed Sliver session"))
        if self.active_session:
            print(Style.info(f"Restoring session: {self.active_session}"))
        print()

        # If we had an active session, re-select it
        if self.active_session and self.master_fd:
            try:
                # Send 'use <session_id>' command to restore context
                cmd = f"use {self.active_session}\n"
                os.write(self.master_fd, cmd.encode())
            except OSError:
                pass

        self._resume_interactive()

    def _run_sliver(self) -> None:
        """Run Sliver client in pseudo-terminal"""
        # Create pseudo-terminal
        self.master_fd, self.slave_fd = pty.openpty()

        # Set PTY size to match current terminal
        try:
            winsize = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b'\x00' * 8)
            fcntl.ioctl(self.slave_fd, termios.TIOCSWINSZ, winsize)
        except:
            pass

        # Build command - sliver-client handles config selection internally
        cmd = [self.client.sliver_path]

        try:
            # Start Sliver process
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

            # Set up SIGWINCH handler for terminal resize
            self._setup_winch_handler()

            # Run interactive loop
            self._interactive_loop()

        except Exception as e:
            print(Style.error(f"Failed to start Sliver: {e}"))
            self._cleanup()

    def _setup_winch_handler(self) -> None:
        """Set up handler for terminal window size changes"""
        def handle_winch(signum, frame):
            if self.master_fd:
                try:
                    winsize = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, b'\x00' * 8)
                    fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
                except:
                    pass
        signal.signal(signal.SIGWINCH, handle_winch)

    def _detect_active_session(self) -> None:
        """Parse output buffer to detect active session changes"""
        # Strip ANSI codes for parsing
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_buffer = ansi_escape.sub('', self._output_buffer)

        # Pattern 1: [*] Active session SESSION_NAME (uuid)
        match = re.search(r'\[\*\]\s*Active session\s+\S+\s+\(([a-f0-9-]+)\)', clean_buffer)
        if match:
            self.active_session = match.group(1)
            return

        # Pattern 2: Prompt with session name: sliver (SESSION_NAME) >
        # This indicates we're in a session context
        match = re.search(r'sliver\s+\(([A-Z_]+)\)\s*>', clean_buffer)
        if match:
            # We have a session name, but need the UUID
            # Look for the UUID in recent output
            session_name = match.group(1)
            # Try to find UUID associated with this name
            uuid_match = re.search(rf'{session_name}\s+\(([a-f0-9-]+)\)', clean_buffer)
            if uuid_match:
                self.active_session = uuid_match.group(1)

        # Pattern 3: Detect when session is backgrounded/cleared
        if re.search(r'sliver\s*>\s*$', clean_buffer) and 'background' in clean_buffer.lower():
            # Returned to main sliver prompt after background
            pass  # Keep the session ID for resume

    def _resume_interactive(self) -> None:
        """Resume interactive loop with existing process"""
        if self.master_fd is None:
            print(Style.error("No active Sliver PTY"))
            return

        self._interactive_loop()

    def _interactive_loop(self) -> None:
        """Main interactive loop - forward I/O between user and Sliver"""
        # Save terminal settings
        old_settings = termios.tcgetattr(sys.stdin)

        try:
            # Configure terminal for pass-through mode
            # Use cbreak mode which preserves escape sequences better than raw
            new_settings = termios.tcgetattr(sys.stdin)
            # Disable canonical mode and echo
            new_settings[3] = new_settings[3] & ~(termios.ICANON | termios.ECHO | termios.ISIG)
            # Set minimum characters to 1, timeout to 0
            new_settings[6][termios.VMIN] = 1
            new_settings[6][termios.VTIME] = 0
            termios.tcsetattr(sys.stdin, termios.TCSANOW, new_settings)

            while self.running and not self.backgrounded:
                # Check if process is still running
                if self.process.poll() is not None:
                    self.running = False
                    break

                # Wait for input from either stdin or sliver
                rlist, _, _ = select.select([sys.stdin, self.master_fd], [], [], 0.1)

                for fd in rlist:
                    if fd == sys.stdin:
                        # Read from user
                        try:
                            data = os.read(sys.stdin.fileno(), 1024)
                        except OSError:
                            break

                        if not data:
                            continue

                        # Check for Ctrl+X - background (avoiding Ctrl+D conflict with Sliver)
                        if data == b'\x18':
                            self.backgrounded = True
                            break

                        # Forward to Sliver
                        try:
                            os.write(self.master_fd, data)
                        except OSError:
                            self.running = False
                            break

                    elif fd == self.master_fd:
                        # Read from Sliver
                        try:
                            data = os.read(self.master_fd, 16384)
                        except OSError:
                            self.running = False
                            break

                        if not data:
                            self.running = False
                            break

                        # Buffer output to detect session changes
                        try:
                            text = data.decode('utf-8', errors='replace')
                            self._output_buffer += text
                            # Keep buffer manageable
                            if len(self._output_buffer) > 5000:
                                self._output_buffer = self._output_buffer[-2500:]
                            # Parse for session selection
                            self._detect_active_session()
                        except:
                            pass

                        # Forward to user
                        try:
                            os.write(sys.stdout.fileno(), data)
                        except OSError:
                            break

        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

        if self.backgrounded:
            print()
            print(Style.info("Sliver session backgrounded"))
            if self.active_session:
                print(Style.dim(f"  Active session: {self.active_session[:8]}..."))
            print(Style.dim("  Use 'sliver resume' or 'sliver fg' to return"))
        elif not self.running:
            print()
            print(Style.info("Sliver session ended"))
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

    def is_backgrounded(self) -> bool:
        """Check if there's a backgrounded Sliver session"""
        return self.process is not None and self.process.poll() is None


class SliverServer:
    """Sliver server management"""

    def __init__(self, client: SliverClient):
        self.client = client
        self.process: Optional[subprocess.Popen] = None

    def start(self, daemon: bool = True, auto_setup: bool = True) -> bool:
        """Start Sliver server and auto-configure if needed"""
        if not self.client.server_path:
            print(Style.error("Sliver server not found"))
            return False

        already_running = self.is_running()

        if already_running:
            print(Style.info("Sliver server already running"))
        else:
            # Start the server
            cmd = [self.client.server_path, "daemon"]

            try:
                if daemon:
                    self.process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                    print(Style.success("Sliver server started in background"))
                else:
                    print(Style.info("Starting Sliver server (Ctrl+C to stop)..."))
                    subprocess.run(cmd)
                    return True
            except Exception as e:
                print(Style.error(f"Failed to start server: {e}"))
                return False

            # Wait for server to be ready
            import time
            print(Style.info("Waiting for server to initialize..."))
            time.sleep(2)

        # Auto-setup: generate and import config if none exist OR if server was freshly started
        if auto_setup:
            configs = self.client.get_configs()

            # If server was freshly started (not already running), old configs are stale
            # because they have certificates from a previous server instance
            if not already_running and configs:
                print(Style.warning("Server freshly started - existing configs may be stale"))
                print(Style.info("Regenerating client config for new server instance..."))
                # Remove old configs
                for cfg in configs:
                    try:
                        cfg.unlink()
                    except:
                        pass
                configs = []  # Force regeneration

            if not configs:
                print(Style.info("No valid client configs, generating..."))
                if self._generate_and_import_config():
                    print(Style.success("Client config created and imported"))
                else:
                    print(Style.warning("Could not auto-generate config"))
                    print(Style.info("Manual setup: sliver-server operator --name uwu --lhost 127.0.0.1 --save /tmp/uwu.cfg"))
            else:
                print(Style.info(f"Found {len(configs)} existing config(s)"))

        print()
        print(Style.success("Sliver ready! Use 'sliver connect' to start client"))
        return True

    def _generate_and_import_config(self) -> bool:
        """Generate operator config and import it"""
        import time
        import tempfile

        if not self.client.server_path:
            return False

        # Create temp file for config
        config_path = "/tmp/uwu_sliver_operator.cfg"
        operator_name = os.environ.get("USER", "uwu")

        try:
            # Generate operator config using sliver-server
            print(Style.info(f"Generating operator config for '{operator_name}'..."))
            gen_cmd = [
                self.client.server_path,
                "operator",
                "--name", operator_name,
                "--lhost", "127.0.0.1",
                "--save", config_path
            ]

            result = subprocess.run(
                gen_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(Style.error(f"Failed to generate config: {result.stderr}"))
                return False

            # Check if config file was created
            if not os.path.exists(config_path):
                print(Style.error("Config file was not created"))
                return False

            # Import the config using sliver-client
            print(Style.info("Importing config to client..."))

            # Find sliver-client
            client_bin = self.client.sliver_path
            if not client_bin:
                client_bin = shutil.which("sliver-client") or shutil.which("sliver")

            if not client_bin:
                print(Style.error("Sliver client not found"))
                return False

            import_cmd = [client_bin, "import", config_path]
            result = subprocess.run(
                import_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(Style.error(f"Failed to import config: {result.stderr}"))
                return False

            # Refresh client's config list
            self.client._find_sliver()

            # Clean up temp file
            try:
                os.remove(config_path)
            except:
                pass

            return True

        except subprocess.TimeoutExpired:
            print(Style.error("Command timed out"))
            return False
        except Exception as e:
            print(Style.error(f"Error: {e}"))
            return False

    def stop(self) -> bool:
        """Stop Sliver server"""
        if self.process:
            self.process.terminate()
            self.process = None
            print(Style.success("Sliver server stopped"))
            return True

        # Try to find and kill running server
        try:
            result = subprocess.run(
                ["pkill", "-f", "sliver-server"],
                capture_output=True
            )
            if result.returncode == 0:
                print(Style.success("Sliver server stopped"))
                return True
        except:
            pass

        print(Style.warning("No Sliver server process found"))
        return False

    def is_running(self) -> bool:
        """Check if Sliver server is running"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "sliver-server"],
                capture_output=True
            )
            return result.returncode == 0
        except:
            return False


def get_sliver_help() -> str:
    """Return help text for Sliver commands"""
    return f"""
{Colors.NEON_ORANGE}Sliver C2 Commands{Colors.RESET}
{Colors.NEON_ORANGE}=================={Colors.RESET}

{Colors.NEON_PURPLE}Server{Colors.RESET}
  {Colors.NEON_CYAN}sliver start{Colors.RESET}
      Start Sliver server daemon (background)

  {Colors.NEON_CYAN}sliver stop{Colors.RESET}
      Stop Sliver server

{Colors.NEON_PURPLE}Client{Colors.RESET}
  {Colors.NEON_CYAN}sliver connect{Colors.RESET}
      Connect to Sliver server (interactive client)
      {Colors.NEON_GREEN}Ctrl+X{Colors.RESET} to background, {Colors.NEON_GREEN}exit{Colors.RESET} to quit

  {Colors.NEON_CYAN}sliver connect <config>{Colors.RESET}
      Connect using specific config file

  {Colors.NEON_CYAN}sliver resume{Colors.RESET} or {Colors.NEON_CYAN}sliver fg{Colors.RESET}
      Resume backgrounded client session

{Colors.NEON_PURPLE}Info{Colors.RESET}
  {Colors.NEON_CYAN}sliver status{Colors.RESET}
      Check server/client status

  {Colors.NEON_CYAN}sliver configs{Colors.RESET}
      List available client configs

{Colors.NEON_PURPLE}Typical Workflow{Colors.RESET}
  1. {Colors.NEON_CYAN}sliver start{Colors.RESET}      Start the server
  2. {Colors.NEON_CYAN}sliver connect{Colors.RESET}    Connect with client
  3. Work in Sliver...
  4. {Colors.NEON_GREEN}Ctrl+X{Colors.RESET}            Background client (server stays running)
  5. Do other UwU stuff...
  6. {Colors.NEON_CYAN}sliver resume{Colors.RESET}     Return to client
  7. {Colors.NEON_GREEN}exit{Colors.RESET}              Quit client
  8. {Colors.NEON_CYAN}sliver stop{Colors.RESET}       Stop server when done

{Colors.NEON_PURPLE}Quick Reference (inside Sliver){Colors.RESET}
  {Colors.NEON_GREEN}sessions{Colors.RESET}        List active sessions
  {Colors.NEON_GREEN}beacons{Colors.RESET}         List active beacons
  {Colors.NEON_GREEN}use <id>{Colors.RESET}        Interact with session/beacon
  {Colors.NEON_GREEN}generate{Colors.RESET}        Create implant
  {Colors.NEON_GREEN}mtls/http/dns{Colors.RESET}   Start listeners
  {Colors.NEON_GREEN}jobs{Colors.RESET}            List active listeners
"""
