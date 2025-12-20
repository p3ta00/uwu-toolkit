"""
Ligolo-ng Integration for UwU Toolkit
Provides interactive Ligolo-ng proxy management with agent tracking
https://github.com/nicocha30/ligolo-ng
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


@dataclass
class LigoloAgent:
    """Represents a Ligolo-ng agent connection"""
    id: int
    remote_ip: str
    hostname: str = "unknown"
    user: str = "unknown"
    os_type: str = "unknown"
    connected_at: datetime = field(default_factory=datetime.now)
    tunnel_active: bool = False


class LigoloClient:
    """Wrapper for Ligolo-ng proxy operations"""

    def __init__(self, config=None):
        self.config = config
        self.proxy_path: Optional[str] = None
        self.agent_path: Optional[str] = None
        self._find_ligolo()

    def _find_ligolo(self) -> None:
        """Find Ligolo-ng proxy and agent binaries"""
        # Common locations for proxy
        proxy_paths = [
            "/opt/ligolo-ng/proxy",
            "/opt/tools/ligolo-ng/proxy",
            "/usr/local/bin/ligolo-proxy",
            "~/.local/bin/ligolo-proxy",
            "/opt/tools/bin/ligolo-proxy",
        ]

        # Check PATH first
        proxy = shutil.which("ligolo-proxy") or shutil.which("proxy")
        if proxy and "ligolo" in proxy.lower():
            self.proxy_path = proxy
        else:
            for path in proxy_paths:
                p = Path(path).expanduser()
                if p.exists() and p.is_file():
                    self.proxy_path = str(p)
                    break

        # Find agent binary (for generating payloads)
        agent_paths = [
            "/opt/ligolo-ng/agent",
            "/opt/tools/ligolo-ng/agent",
            "/usr/local/bin/ligolo-agent",
            "~/.local/bin/ligolo-agent",
        ]

        agent = shutil.which("ligolo-agent") or shutil.which("agent")
        if agent and "ligolo" in agent.lower():
            self.agent_path = agent
        else:
            for path in agent_paths:
                p = Path(path).expanduser()
                if p.exists() and p.is_file():
                    self.agent_path = str(p)
                    break

    def is_available(self) -> Tuple[bool, str]:
        """Check if Ligolo-ng proxy is available"""
        if not self.proxy_path:
            return False, "Ligolo-ng proxy not found. Install from: https://github.com/nicocha30/ligolo-ng"
        return True, f"Ligolo-ng proxy ready ({self.proxy_path})"

    def check_tun_interface(self, interface: str = "ligolo") -> bool:
        """Check if TUN interface exists"""
        try:
            result = subprocess.run(
                ["ip", "link", "show", interface],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False

    def create_tun_interface(self, interface: str = "ligolo") -> bool:
        """Create TUN interface for Ligolo-ng"""
        if self.check_tun_interface(interface):
            return True

        try:
            # Create TUN interface
            subprocess.run(
                ["sudo", "ip", "tuntap", "add", "user", os.environ.get("USER", "root"),
                 "mode", "tun", interface],
                check=True,
                capture_output=True
            )
            # Bring it up
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "up"],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(Style.error(f"Failed to create TUN interface: {e}"))
            return False

    def add_route(self, network: str, interface: str = "ligolo") -> bool:
        """Add route through Ligolo interface"""
        try:
            subprocess.run(
                ["sudo", "ip", "route", "add", network, "dev", interface],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def remove_route(self, network: str) -> bool:
        """Remove route"""
        try:
            subprocess.run(
                ["sudo", "ip", "route", "del", network],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False


class LigoloMode:
    """Interactive Ligolo-ng mode handler - runs proxy in pseudo-terminal"""

    def __init__(self, client: LigoloClient, config=None):
        self.client = client
        self.config = config
        self.running = False
        self.backgrounded = False
        self.process: Optional[subprocess.Popen] = None
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None
        self.listen_port: int = 11601
        self.listen_interface: str = "0.0.0.0"
        self.tun_interface: str = "ligolo"
        self.agents: Dict[int, LigoloAgent] = {}
        self._output_buffer: str = ""
        self._agent_monitor_thread: Optional[threading.Thread] = None
        self.selfcert: bool = True  # Use self-signed cert by default

    def start(self, port: int = 11601, interface: str = "0.0.0.0",
              tun: str = "ligolo", selfcert: bool = True) -> None:
        """Start interactive Ligolo-ng proxy mode"""
        available, msg = self.client.is_available()
        if not available:
            print(Style.error(msg))
            return

        self.listen_port = port
        self.listen_interface = interface
        self.tun_interface = tun
        self.selfcert = selfcert
        self.running = True
        self.backgrounded = False

        # Check/create TUN interface
        print(Style.info(f"Checking TUN interface '{tun}'..."))
        if not self.client.check_tun_interface(tun):
            print(Style.warning(f"TUN interface '{tun}' not found, creating..."))
            if not self.client.create_tun_interface(tun):
                print(Style.error("Failed to create TUN interface. Run with sudo or create manually:"))
                print(f"  sudo ip tuntap add user $USER mode tun {tun}")
                print(f"  sudo ip link set {tun} up")
                return
            print(Style.success(f"TUN interface '{tun}' created"))
        else:
            print(Style.success(f"TUN interface '{tun}' ready"))

        print()
        print(f"  {Colors.NEON_ORANGE}╔══════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_PINK}Ligolo-ng Proxy{Colors.RESET}                                    {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  Listening on {Colors.NEON_GREEN}{interface}:{port}{Colors.RESET}                       {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  TUN Interface: {Colors.NEON_GREEN}{tun}{Colors.RESET}                               {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_CYAN}Ctrl+D{Colors.RESET} - Background and return to UwU              {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}║{Colors.RESET}  {Colors.NEON_CYAN}exit{Colors.RESET}   - Exit Ligolo and return to UwU             {Colors.NEON_ORANGE}║{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}╚══════════════════════════════════════════════════════╝{Colors.RESET}")
        print()

        self._run_ligolo()

    def resume(self) -> None:
        """Resume backgrounded Ligolo-ng session"""
        if not self.process or self.process.poll() is not None:
            print(Style.warning("No backgrounded Ligolo-ng session"))
            print(Style.info("Use 'ligolo' or 'ligolo <port>' to start a new session"))
            return

        self.running = True
        self.backgrounded = False

        print()
        print(Style.success("Resumed Ligolo-ng session"))
        print(Style.info(f"Listening on {self.listen_interface}:{self.listen_port}"))
        print(Style.info(f"TUN interface: {self.tun_interface}"))
        print()

        self._resume_interactive()

    def _run_ligolo(self) -> None:
        """Run Ligolo-ng proxy in pseudo-terminal"""
        # Create pseudo-terminal
        self.master_fd, self.slave_fd = pty.openpty()

        # Build command - newer ligolo-ng doesn't use -tun flag
        cmd = [
            self.client.proxy_path,
            "-laddr", f"{self.listen_interface}:{self.listen_port}",
            "-selfcert",  # Always use selfcert for ease of use
        ]

        try:
            # Start Ligolo proxy process
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

            # Start agent monitor thread
            self._start_agent_monitor()

            # Run interactive loop
            self._interactive_loop()

        except Exception as e:
            print(Style.error(f"Failed to start Ligolo-ng: {e}"))
            self._cleanup()

    def _start_agent_monitor(self) -> None:
        """Start thread to monitor for new agents"""
        def monitor():
            while self.running and not self.backgrounded:
                self._parse_agents_from_buffer()
                time.sleep(1)

        self._agent_monitor_thread = threading.Thread(target=monitor, daemon=True)
        self._agent_monitor_thread.start()

    def _parse_agents_from_buffer(self) -> None:
        """Parse Ligolo output for agent connections"""
        # Ligolo outputs agent info like:
        # [Agent] Agent joined. id=0, name=DESKTOP-ABC@user, remote=10.10.10.100:52341

        agent_pattern = r'\[Agent\].*?id=(\d+).*?name=([^,\s]+).*?remote=(\d+\.\d+\.\d+\.\d+)'

        for match in re.finditer(agent_pattern, self._output_buffer):
            agent_id = int(match.group(1))
            name = match.group(2)
            remote_ip = match.group(3)

            if agent_id not in self.agents:
                # Parse hostname and user from name (format: HOSTNAME@user or HOSTNAME\user)
                hostname = name
                user = "unknown"
                if '@' in name:
                    parts = name.split('@')
                    hostname = parts[0]
                    user = parts[1] if len(parts) > 1 else "unknown"
                elif '\\' in name:
                    parts = name.split('\\')
                    hostname = parts[1] if len(parts) > 1 else parts[0]
                    user = parts[0]

                self.agents[agent_id] = LigoloAgent(
                    id=agent_id,
                    remote_ip=remote_ip,
                    hostname=hostname,
                    user=user
                )

    def _resume_interactive(self) -> None:
        """Resume interactive loop with existing process"""
        if self.master_fd is None:
            print(Style.error("No active Ligolo-ng PTY"))
            return
        self._interactive_loop()

    def _interactive_loop(self) -> None:
        """Main interactive loop - forward I/O between user and Ligolo"""
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

                        # Buffer output for agent parsing
                        try:
                            self._output_buffer += data.decode('utf-8', errors='replace')
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
            print(Style.info("Ligolo-ng session backgrounded"))
            print(Style.dim(f"  Proxy still active on port {self.listen_port}"))
            print(Style.dim(f"  TUN interface '{self.tun_interface}' remains active"))
            print(Style.dim("  Use 'ligolo resume' or 'ligolo fg' to return"))
            print(Style.dim("  Use 'ligolo agents' to see connected agents"))
        elif not self.running:
            print()
            print(Style.info("Ligolo-ng session ended"))
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
        """Check if there's a backgrounded Ligolo session"""
        return self.process is not None and self.process.poll() is None

    def get_agents(self) -> List[LigoloAgent]:
        """Get all Ligolo agents"""
        return list(self.agents.values())

    def status(self) -> Dict[str, Any]:
        """Get Ligolo status"""
        return {
            "running": self.running,
            "backgrounded": self.backgrounded,
            "port": self.listen_port if self.process else None,
            "tun_interface": self.tun_interface,
            "agents": len(self.agents),
            "process_alive": self.process is not None and self.process.poll() is None
        }

    def add_route(self, network: str) -> bool:
        """Add route through Ligolo tunnel"""
        return self.client.add_route(network, self.tun_interface)

    def list_routes(self) -> List[str]:
        """List routes through Ligolo interface"""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "dev", self.tun_interface],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return [line.split()[0] for line in result.stdout.strip().split('\n') if line]
            return []
        except:
            return []


def get_ligolo_help() -> str:
    """Return help text for Ligolo-ng commands"""
    return f"""
{Colors.NEON_ORANGE}Ligolo-ng Proxy Commands{Colors.RESET}
{Colors.NEON_ORANGE}========================{Colors.RESET}

{Colors.NEON_PURPLE}Start Proxy (runs in tmux like evil-winrm){Colors.RESET}
  {Colors.NEON_CYAN}ligolo{Colors.RESET}
      Start Ligolo-ng proxy on default port (11601)

  {Colors.NEON_CYAN}ligolo <port>{Colors.RESET}
      Start proxy on specified port

  {Colors.NEON_CYAN}ligolo pty [port]{Colors.RESET}
      Start in PTY mode (no tmux, exits with UwU)

{Colors.NEON_PURPLE}Session Management{Colors.RESET}
  {Colors.NEON_CYAN}ligolo attach{Colors.RESET} or {Colors.NEON_CYAN}ligolo fg{Colors.RESET}
      Attach to backgrounded Ligolo session

  {Colors.NEON_CYAN}ligolo kill{Colors.RESET}
      Stop ligolo session

  {Colors.NEON_CYAN}ligolo status{Colors.RESET}
      Check Ligolo status

  {Colors.NEON_CYAN}ligolo agents{Colors.RESET}
      List connected agents

{Colors.NEON_PURPLE}Routing{Colors.RESET}
  {Colors.NEON_CYAN}ligolo route add <network>{Colors.RESET}
      Add route through Ligolo tunnel
      Example: ligolo route add 10.10.10.0/24

  {Colors.NEON_CYAN}ligolo routes{Colors.RESET}
      List active routes

{Colors.NEON_PURPLE}Typical Workflow{Colors.RESET}
  1. {Colors.NEON_CYAN}ligolo{Colors.RESET}               Start proxy (TUN auto-created)

  2. On target, run agent:
     {Colors.DIM}./agent -connect <YOUR_IP>:11601 -ignore-cert{Colors.RESET}

  3. In Ligolo proxy:
     {Colors.NEON_GREEN}session{Colors.RESET}             Select agent session
     {Colors.NEON_GREEN}start{Colors.RESET}               Start tunnel

  4. {Colors.NEON_CYAN}Ctrl+b d{Colors.RESET}             Detach (tunnel stays active)

  5. {Colors.NEON_CYAN}ligolo route add 10.10.10.0/24{Colors.RESET}
     Add route to internal network

  6. Access internal network directly!

  7. {Colors.NEON_CYAN}sessions{Colors.RESET}             View all sessions (shows ligolo)
     {Colors.NEON_CYAN}interact{Colors.RESET}             Return to manage sessions

{Colors.NEON_PURPLE}Inside Ligolo Proxy{Colors.RESET}
  {Colors.NEON_GREEN}session{Colors.RESET}         List/select agent sessions
  {Colors.NEON_GREEN}ifconfig{Colors.RESET}        Show agent network interfaces
  {Colors.NEON_GREEN}start{Colors.RESET}           Start tunnel on selected session
  {Colors.NEON_GREEN}stop{Colors.RESET}            Stop active tunnel
  {Colors.NEON_GREEN}listener_add{Colors.RESET}    Add listener for reverse connections
  {Colors.NEON_GREEN}listener_list{Colors.RESET}   List active listeners

{Colors.NEON_PURPLE}Agent Download & Deployment{Colors.RESET}
  {Colors.NEON_CYAN}ligolo download{Colors.RESET}
      Download latest agents from GitHub releases

  {Colors.NEON_CYAN}use post/pivot/ligolo_pivot{Colors.RESET}
      Auto-deploy agent to target via existing session

  Manual execution on target:
  Windows: {Colors.DIM}agent.exe -connect <IP>:11601 -ignore-cert{Colors.RESET}
  Linux:   {Colors.DIM}./agent -connect <IP>:11601 -ignore-cert{Colors.RESET}
"""


def print_agents_table(agents: List[LigoloAgent]) -> None:
    """Print agents in a nice table format"""
    if not agents:
        print(Style.warning("No connected agents"))
        return

    print()
    print(f"  {Colors.NEON_CYAN}Ligolo-ng Agents{Colors.RESET}")
    print(f"  {Colors.NEON_PINK}{'='*60}{Colors.RESET}")
    print()
    print(f"  {Colors.BRIGHT_WHITE}{'ID':<4} {'Remote IP':<16} {'Hostname':<20} {'User':<12} {'Tunnel':<8}{Colors.RESET}")
    print(f"  {Colors.GRID}{'-'*4} {'-'*16} {'-'*20} {'-'*12} {'-'*8}{Colors.RESET}")

    for agent in agents:
        tunnel_status = f"{Colors.NEON_GREEN}active{Colors.RESET}" if agent.tunnel_active else f"{Colors.YELLOW}idle{Colors.RESET}"
        print(f"  {Colors.NEON_CYAN}{agent.id:<4}{Colors.RESET} "
              f"{agent.remote_ip:<16} "
              f"{agent.hostname[:20]:<20} "
              f"{agent.user[:12]:<12} "
              f"{tunnel_status}")

    print()


# Global Ligolo mode instance
_ligolo_mode: Optional[LigoloMode] = None


def get_ligolo_mode(config=None) -> LigoloMode:
    """Get or create global Ligolo mode instance"""
    global _ligolo_mode
    if _ligolo_mode is None:
        client = LigoloClient(config)
        _ligolo_mode = LigoloMode(client, config)
    return _ligolo_mode
