"""
C2 (Command & Control) handler for UwU Toolkit console.
Handles Claude AI, Sliver C2, Penelope shell handler, and Ligolo-ng tunneling commands.
"""

import os
import subprocess
from pathlib import Path
from typing import List, Optional

from . import HandlerBase
from ..colors import Colors, Style
from ..claude import ClaudeAssistant, ClaudeMode, get_claude_help
from ..sliver import SliverClient, SliverMode, SliverServer, get_sliver_help
from ..penelope import PenelopeClient, PenelopeMode, get_penelope_mode, get_penelope_help
from ..ligolo import LigoloClient, LigoloMode, get_ligolo_mode, get_ligolo_help, print_agents_table


class C2Handler(HandlerBase):
    """Handles Claude AI, Sliver C2, Penelope shell handler, and Ligolo-ng tunneling commands."""

    # =========================================================================
    # Claude AI Commands
    # =========================================================================

    def cmd_claude(self, args: List[str]) -> None:
        """Claude AI assistant commands"""
        if not args:
            # Default: enter Claude mode
            self.console.claude_mode.start()
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "help":
            print(get_claude_help())

        elif subcmd == "mode":
            # Enter interactive Claude mode
            self.console.claude_mode.start()

        elif subcmd in ("resume", "fg"):
            # Resume backgrounded Claude session
            self.console.claude_mode.resume()

        elif subcmd == "sessions":
            # List all Claude sessions
            sessions = self.console.claude_mode.session_manager.list_sessions()
            if not sessions:
                print(Style.warning("No Claude sessions"))
                return

            active = self.console.claude_mode.session_manager.get_active_session()
            print(f"\n  {Style.highlight('Claude Sessions')}")
            print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}\n")

            for session in sessions:
                marker = f"{Colors.NEON_GREEN}*{Colors.RESET}" if session == active else " "
                msg_count = len(session.messages)
                user_msgs = sum(1 for m in session.messages if m["role"] == "user")
                created = session.created_at.strftime("%H:%M:%S")
                print(f"  {marker} {Colors.NEON_CYAN}{session.id}{Colors.RESET}  {session.name}")
                print(f"      {Colors.GRID}{user_msgs} prompts, created {created}{Colors.RESET}")
            print()
            print(Style.dim("  Use 'claude mode' to enter interactive mode"))

        elif subcmd == "status":
            available, msg = self.console.claude.is_available()
            if available:
                print(Style.success(msg))
                print(Style.info(f"Model: {self.console.claude.model}"))
            else:
                print(Style.error(msg))

        elif subcmd == "model":
            if not subargs:
                print(Style.info(f"Current model: {self.console.claude.model}"))
                print(Style.dim("Usage: claude model <model_name>"))
            else:
                self.console.claude.set_model(subargs[0])

        elif subcmd == "analyze":
            if not subargs:
                print(Style.error("Usage: claude analyze <path> [--focus <area>]"))
                return

            # Parse arguments
            paths = []
            focus = None
            i = 0
            while i < len(subargs):
                if subargs[i] == "--focus" and i + 1 < len(subargs):
                    focus = subargs[i + 1]
                    i += 2
                else:
                    paths.append(subargs[i])
                    i += 1

            if not paths:
                print(Style.error("No path specified"))
                return

            result = self.console.claude.analyze_vulnerabilities(paths, focus)
            print(result)

        elif subcmd == "debug":
            if not subargs:
                print(Style.error("Usage: claude debug <path> [--error \"message\"]"))
                return

            # Parse arguments
            paths = []
            error_msg = None
            i = 0
            while i < len(subargs):
                if subargs[i] == "--error" and i + 1 < len(subargs):
                    error_msg = subargs[i + 1]
                    i += 2
                else:
                    paths.append(subargs[i])
                    i += 1

            if not paths:
                print(Style.error("No path specified"))
                return

            result = self.console.claude.debug_code(paths, error_msg)
            print(result)

        elif subcmd == "ask":
            if not subargs:
                print(Style.error("Usage: claude ask \"question\" [--context <path>]"))
                return

            # Parse arguments - handle quoted strings
            question_parts = []
            context_paths = []
            i = 0
            while i < len(subargs):
                if subargs[i] == "--context" and i + 1 < len(subargs):
                    context_paths.append(subargs[i + 1])
                    i += 2
                else:
                    question_parts.append(subargs[i])
                    i += 1

            question = " ".join(question_parts)
            if not question:
                print(Style.error("No question provided"))
                return

            result = self.console.claude.ask(question, context_paths if context_paths else None)
            print(result)

        else:
            print(Style.error(f"Unknown subcommand: {subcmd}"))
            print(Style.info("Use 'claude help' for usage"))

    # =========================================================================
    # Sliver C2 Commands
    # =========================================================================

    def cmd_sliver(self, args: List[str]) -> None:
        """Sliver C2 commands"""
        if not args:
            print(get_sliver_help())
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "help":
            print(get_sliver_help())

        elif subcmd == "start":
            # Start Sliver server AND connect with client in tmux (all-in-one)
            self._start_sliver_full()

        elif subcmd == "stop":
            # Stop Sliver server
            self.console.sliver_server.stop()

        elif subcmd == "connect":
            # Connect with Sliver client in tmux (like ligolo/evil-winrm)
            config_name = subargs[0] if subargs else None
            self._start_sliver_tmux(config_name)

        elif subcmd in ("resume", "fg", "attach"):
            # Attach to tmux Sliver session
            self._attach_sliver_tmux()

        elif subcmd == "kill":
            # Kill Sliver tmux session
            self._kill_sliver_tmux()

        elif subcmd == "pty":
            # Old PTY mode (non-tmux)
            config_name = subargs[0] if subargs else None
            self.console.sliver_mode.start(config_name)

        elif subcmd == "configs":
            # List available configs
            configs = self.console.sliver_client.get_configs()
            if not configs:
                print(Style.warning("No Sliver configs found"))
                print(Style.info(f"Import with: sliver-client import <config.cfg>"))
                return

            print(f"\n  {Style.highlight('Sliver Client Configs')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")
            for cfg in configs:
                print(f"    {Colors.NEON_CYAN}{cfg.stem}{Colors.RESET}")
                print(f"      {Colors.GRID}{cfg}{Colors.RESET}")
            print()

        elif subcmd == "status":
            # Check Sliver status
            print(f"\n  {Style.highlight('Sliver Status')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")

            # Server status
            if self.console.sliver_server.is_running():
                print(f"  {Colors.NEON_GREEN}Server:{Colors.RESET}  Running")
            else:
                print(f"  {Colors.NEON_ORANGE}Server:{Colors.RESET}  Stopped")

            # Client status
            if self.console.sliver_mode.is_backgrounded():
                print(f"  {Colors.NEON_GREEN}Client:{Colors.RESET}  Backgrounded (use 'sliver resume')")
            else:
                print(f"  {Colors.GRID}Client:{Colors.RESET}  Not connected")

            # Configs
            configs = self.console.sliver_client.get_configs()
            print(f"  {Colors.GRID}Configs:{Colors.RESET} {len(configs)} available")

            # Binary paths
            if self.console.sliver_client.sliver_path:
                print(f"  {Colors.GRID}Client:{Colors.RESET}  {self.console.sliver_client.sliver_path}")
            if self.console.sliver_client.server_path:
                print(f"  {Colors.GRID}Server:{Colors.RESET}  {self.console.sliver_client.server_path}")
            print()

        else:
            print(Style.error(f"Unknown command: sliver {subcmd}"))
            print(Style.info("Use 'sliver help' for usage"))

    # =========================================================================
    # Sliver tmux helpers
    # =========================================================================

    def _start_sliver_full(self) -> bool:
        """Start Sliver server AND connect with client - all in one command"""
        import time

        # Check if tmux session already exists
        existing = self._find_sliver_tmux_session()
        if existing:
            print(Style.warning(f"Sliver session already exists: {existing}"))
            print(Style.info(f"Use 'sliver attach' to connect"))
            print(Style.info(f"Use 'sliver kill' to stop it"))
            return False

        # Step 1: Start server if not running
        if not self.console.sliver_server.is_running():
            print(Style.info("Starting Sliver server..."))
            if not self.console.sliver_server.start(daemon=True, auto_setup=True):
                print(Style.error("Failed to start server"))
                return False
            # Give it a moment to fully initialize
            time.sleep(1)
        else:
            print(Style.info("Sliver server already running"))

        # Step 2: Start client in tmux
        print(Style.info("Launching Sliver client in tmux..."))
        return self._start_sliver_tmux()

    def _find_sliver_tmux_session(self) -> Optional[str]:
        """Find existing Sliver tmux session (uwu-sliver)"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if line.startswith("uwu-sliver"):
                    return line
            return None
        except:
            return None

    def _start_sliver_tmux(self, config_name: str = None) -> bool:
        """Start Sliver client in a tmux session (like ligolo/evil-winrm)"""

        # Check if a Sliver session already exists
        existing = self._find_sliver_tmux_session()
        if existing:
            print(Style.warning(f"Sliver session already exists: {existing}"))
            print(Style.info(f"Use 'sliver attach' to connect"))
            print(Style.info(f"Use 'sliver kill' to stop it"))
            return False

        session_name = "uwu-sliver"

        # Find sliver-client binary
        if not self.console.sliver_client.sliver_path:
            print(Style.error("Sliver client not found"))
            return False

        sliver_cmd = self.console.sliver_client.sliver_path

        # Create tmux session
        result = subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_name, sliver_cmd],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            # Apply UwU theme to the session
            status_right = "#[fg=#00ffff]SLIVER C2 #[fg=#ff6eb4]| #[fg=#666666]Ctrl+b x to detach"
            theme_cmds = [
                ["tmux", "set-option", "-t", session_name, "status", "on"],
                ["tmux", "set-option", "-t", session_name, "status-style", "bg=#1a1a2e,fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "status-left-length", "50"],
                ["tmux", "set-option", "-t", session_name, "status-right-length", "120"],
                ["tmux", "set-option", "-t", session_name, "status-left", "#[bg=#ff6eb4,fg=#1a1a2e,bold] UwU #[bg=#1a1a2e,fg=#ff6eb4] "],
                ["tmux", "set-option", "-t", session_name, "status-right", status_right],
                ["tmux", "set-option", "-t", session_name, "status-interval", "2"],
                ["tmux", "set-option", "-t", session_name, "window-status-current-style", "bg=#ff00ff,fg=#1a1a2e,bold"],
                ["tmux", "set-option", "-t", session_name, "window-status-style", "bg=#1a1a2e,fg=#888888"],
                ["tmux", "set-option", "-t", session_name, "pane-border-style", "fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "pane-active-border-style", "fg=#00ffff"],
                ["tmux", "set-option", "-t", session_name, "message-style", "bg=#ff6eb4,fg=#1a1a2e,bold"],
                # Bind Ctrl+b x to detach (applied globally)
                ["tmux", "bind-key", "x", "detach-client"],
            ]
            for cmd in theme_cmds:
                subprocess.run(cmd, capture_output=True)

            print(Style.success(f"Starting Sliver C2 session..."))
            print(Style.info("Use Ctrl+b x to detach (background the session)"))
            print(Style.info("Use 'sessions' to list, 'interact' to reattach"))
            print()

            # Attach to session immediately
            os.system(f"tmux attach-session -t {session_name}")

            # Check if session still exists
            check_result = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True, timeout=5
            )

            print()
            if check_result.returncode == 0:
                print(Style.info(f"Session '{session_name}' is backgrounded"))
                print(Style.info("Use 'sessions' to list, 'sliver attach' to reattach"))
            else:
                print(Style.info("Session ended"))

            return True
        else:
            print(Style.error(f"Failed to start session: {result.stderr}"))
            return False

    def _attach_sliver_tmux(self) -> None:
        """Attach to Sliver tmux session"""

        session_name = self._find_sliver_tmux_session()

        if not session_name:
            print(Style.error("No Sliver session found"))
            print(Style.info("Use 'sliver connect' to start one"))
            return

        print(Style.info(f"Attaching to {session_name}..."))
        print(Style.info("Press Ctrl+b x to detach and return to UwU"))
        print()

        subprocess.run(["tmux", "attach-session", "-t", session_name])

        print()
        print(Style.info("Detached from Sliver session"))
        print(Style.info("Sliver is still running in background"))

    def _kill_sliver_tmux(self) -> None:
        """Kill Sliver tmux session"""

        session_name = self._find_sliver_tmux_session()

        if not session_name:
            print(Style.warning("No Sliver session found"))
            return

        result = subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            capture_output=True
        )

        if result.returncode == 0:
            print(Style.success(f"Session '{session_name}' killed"))
        else:
            print(Style.error("Failed to kill session"))

    # =========================================================================
    # Penelope Shell Handler Commands
    # =========================================================================

    def cmd_penelope(self, args: List[str]) -> None:
        """Penelope shell handler commands"""
        if not args:
            # Start Penelope with default port
            self.console.penelope_mode.start(port=4444)
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "help":
            print(get_penelope_help())

        elif subcmd in ("resume", "fg"):
            # Resume backgrounded Penelope session
            self.console.penelope_mode.resume()

        elif subcmd == "status":
            # Check Penelope status
            status = self.console.penelope_mode.status()
            print(f"\n  {Style.highlight('Penelope Status')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")

            if status["process_alive"]:
                if status["backgrounded"]:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}  Backgrounded (use 'penelope resume')")
                else:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}  Running")
                print(f"  {Colors.GRID}Port:{Colors.RESET}    {status['port']}")
                print(f"  {Colors.GRID}Sessions:{Colors.RESET} {status['sessions']}")
            else:
                print(f"  {Colors.GRID}Status:{Colors.RESET}  Not running")

            # Check if penelope is available
            available, msg = self.console.penelope_mode.client.is_available()
            if available:
                print(f"  {Colors.GRID}Binary:{Colors.RESET}  {self.console.penelope_mode.client.penelope_path}")
            else:
                print(f"  {Colors.NEON_ORANGE}Binary:{Colors.RESET}  Not found")
            print()

        elif subcmd.isdigit():
            # Start on specified port
            port = int(subcmd)
            self.console.penelope_mode.start(port=port)

        elif subcmd == "-i" and len(subargs) >= 2:
            # Start with specific interface
            interface = subargs[0]
            port = int(subargs[1])
            self.console.penelope_mode.start(port=port, interface=interface)

        else:
            print(Style.error(f"Unknown command: penelope {subcmd}"))
            print(Style.info("Use 'penelope help' for usage"))

    # =========================================================================
    # Ligolo-ng Tunneling Commands
    # =========================================================================

    def cmd_ligolo(self, args: List[str]) -> None:
        """Ligolo-ng proxy commands"""
        if not args:
            # Start Ligolo in tmux by default (like evil-winrm)
            self._start_ligolo_tmux(port=11601)
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "info":
            print(get_ligolo_help())

        elif subcmd in ("resume", "fg"):
            # Resume backgrounded Ligolo session
            self.console.ligolo_mode.resume()

        elif subcmd == "agents":
            # List connected agents
            agents = self.console.ligolo_mode.get_agents()
            print_agents_table(agents)

        elif subcmd == "status":
            # Check Ligolo status
            status = self.console.ligolo_mode.status()
            print(f"\n  {Style.highlight('Ligolo-ng Status')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")

            if status["process_alive"]:
                if status["backgrounded"]:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}    Backgrounded (use 'ligolo resume')")
                else:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}    Running")
                print(f"  {Colors.GRID}Port:{Colors.RESET}      {status['port']}")
                print(f"  {Colors.GRID}TUN:{Colors.RESET}       {status['tun_interface']}")
                print(f"  {Colors.GRID}Agents:{Colors.RESET}    {status['agents']}")
            else:
                print(f"  {Colors.GRID}Status:{Colors.RESET}    Not running")

            # Check if ligolo is available
            available, msg = self.console.ligolo_mode.client.is_available()
            if available:
                print(f"  {Colors.GRID}Binary:{Colors.RESET}    {self.console.ligolo_mode.client.proxy_path}")
            else:
                print(f"  {Colors.NEON_ORANGE}Binary:{Colors.RESET}    Not found")

            # Show routes
            routes = self.console.ligolo_mode.list_routes()
            if routes:
                print(f"  {Colors.GRID}Routes:{Colors.RESET}    {', '.join(routes)}")
            print()

        elif subcmd == "routes":
            # List active routes
            routes = self.console.ligolo_mode.list_routes()
            if routes:
                print(f"\n  {Style.highlight('Ligolo Routes')}")
                print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")
                for route in routes:
                    print(f"    {Colors.NEON_GREEN}{route}{Colors.RESET} via {self.console.ligolo_mode.tun_interface}")
                print()
            else:
                print(Style.warning("No routes configured"))
                print(Style.info("Use 'ligolo route add <network>' to add a route"))

        elif subcmd == "route":
            if not subargs:
                # Show current routes
                routes = self.console.ligolo_mode.list_routes()
                if routes:
                    print(f"\n  {Style.highlight('Ligolo Routes')}")
                    for route in routes:
                        print(f"    {Colors.NEON_GREEN}{route}{Colors.RESET}")
                    print()
                else:
                    print(Style.warning("No routes configured"))
                print(Style.info("Usage: ligolo route <network> [interface]"))
                print(Style.info("       ligolo route del <network>"))
                return

            first_arg = subargs[0]

            # Check if first arg is a network (contains /)
            if '/' in first_arg:
                # ligolo route 240.0.0.1/32 [interface]
                network = first_arg
                interface = subargs[1] if len(subargs) > 1 else "ligolo"

                try:
                    result = subprocess.run(
                        ["sudo", "ip", "route", "add", network, "dev", interface],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        print(Style.success(f"Route added: {network} via {interface}"))
                    elif "File exists" in result.stderr:
                        print(Style.warning(f"Route already exists: {network}"))
                    else:
                        print(Style.error(f"Failed: {result.stderr.strip()}"))
                except Exception as e:
                    print(Style.error(f"Failed to add route: {e}"))

            elif first_arg.lower() == "del" and len(subargs) >= 2:
                # ligolo route del <network>
                network = subargs[1]
                if self.console.ligolo_mode.client.remove_route(network):
                    print(Style.success(f"Route removed: {network}"))
                else:
                    print(Style.error(f"Failed to remove route: {network}"))

            elif first_arg.lower() == "add" and len(subargs) >= 2:
                # Legacy: ligolo route add <network> [interface]
                network = subargs[1]
                interface = subargs[2] if len(subargs) > 2 else "ligolo"
                try:
                    result = subprocess.run(
                        ["sudo", "ip", "route", "add", network, "dev", interface],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        print(Style.success(f"Route added: {network} via {interface}"))
                    elif "File exists" in result.stderr:
                        print(Style.warning(f"Route already exists: {network}"))
                    else:
                        print(Style.error(f"Failed: {result.stderr.strip()}"))
                except Exception as e:
                    print(Style.error(f"Failed to add route: {e}"))
            else:
                print(Style.error("Usage: ligolo route <network> [interface]"))
                print(Style.info("Examples:"))
                print(Style.info("  ligolo route 10.10.10.0/24        # uses 'ligolo' interface"))
                print(Style.info("  ligolo route 10.10.10.0/24 tun0   # uses 'tun0' interface"))

        elif subcmd == "download":
            # Download latest ligolo-ng agents from GitHub
            self._download_ligolo_agents()

        elif subcmd == "persistent":
            # Alias for starting in tmux (now the default)
            port = int(subargs[0]) if subargs and subargs[0].isdigit() else 11601
            self._start_ligolo_tmux(port)

        elif subcmd in ("attach",):
            # Attach to tmux ligolo session
            self._attach_ligolo_tmux()

        elif subcmd == "kill":
            # Kill ligolo tmux session
            self._kill_ligolo_tmux()

        elif subcmd == "pty":
            # Old PTY mode (non-tmux, exits with UwU)
            port = int(subargs[0]) if subargs and subargs[0].isdigit() else 11601
            self.console.ligolo_mode.start(port=port)

        elif subcmd.isdigit():
            # Start on specified port (in tmux by default)
            port = int(subcmd)
            self._start_ligolo_tmux(port=port)

        elif subcmd == "-tun" and subargs:
            # Start with specific TUN interface
            tun = subargs[0]
            port = int(subargs[1]) if len(subargs) > 1 else 11601
            self.console.ligolo_mode.start(port=port, tun=tun)

        else:
            print(Style.error(f"Unknown command: ligolo {subcmd}"))
            print(Style.info("Use 'ligolo info' for usage"))

    # =========================================================================
    # Ligolo tmux helpers
    # =========================================================================

    def _download_ligolo_agents(self) -> bool:
        """Download latest ligolo-ng agents from GitHub releases"""
        import urllib.request
        import json
        import zipfile
        import tarfile
        import io

        print(Style.info("Fetching latest ligolo-ng release info..."))

        # GitHub API for latest release
        api_url = "https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest"

        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "UwU-Toolkit"})
            with urllib.request.urlopen(req, timeout=30) as response:
                release_data = json.loads(response.read().decode())
        except Exception as e:
            print(Style.error(f"Failed to fetch release info: {e}"))
            return False

        version = release_data.get("tag_name", "unknown")
        print(Style.success(f"Latest version: {version}"))

        # Find agent assets (Windows and Linux amd64)
        assets = release_data.get("assets", [])
        agent_files = {
            "windows": None,
            "linux": None,
        }

        for asset in assets:
            name = asset.get("name", "").lower()
            url = asset.get("browser_download_url", "")

            # Match agent files (not proxy) - format: ligolo-ng_agent_X.X.X_os_arch
            if "_agent_" in name and "amd64" in name:
                if "windows" in name and "arm" not in name:
                    agent_files["windows"] = (asset.get("name"), url)
                elif "linux" in name and "arm" not in name:
                    agent_files["linux"] = (asset.get("name"), url)

        if not agent_files["windows"] and not agent_files["linux"]:
            print(Style.error("Could not find agent binaries in release"))
            return False

        # Create output directory
        output_dir = Path("/opt/tools/ligolo-ng")
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            # Test write access
            test_file = output_dir / ".write_test"
            test_file.touch()
            test_file.unlink()
        except (PermissionError, OSError):
            # Try user directory instead
            output_dir = Path.home() / ".local" / "share" / "ligolo-ng"
            output_dir.mkdir(parents=True, exist_ok=True)
            print(Style.warning(f"Using user directory: {output_dir}"))

        downloaded = []

        for os_type, asset_info in agent_files.items():
            if not asset_info:
                continue

            asset_name, download_url = asset_info
            print(Style.info(f"Downloading {asset_name}..."))

            try:
                req = urllib.request.Request(download_url, headers={"User-Agent": "UwU-Toolkit"})
                with urllib.request.urlopen(req, timeout=120) as response:
                    data = response.read()

                # Determine output filename
                if os_type == "windows":
                    out_name = "agent.exe"
                else:
                    out_name = "agent_linux_amd64"

                out_path = output_dir / out_name

                # Handle zip files (Windows)
                if asset_name.endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        # Find and extract agent binary
                        for zinfo in zf.namelist():
                            if "agent" in zinfo.lower() and not zinfo.endswith('/'):
                                with open(out_path, "wb") as f:
                                    f.write(zf.read(zinfo))
                                downloaded.append(str(out_path))
                                print(Style.success(f"  Saved: {out_path}"))
                                break

                # Handle tar.gz files (Linux)
                elif asset_name.endswith(".tar.gz") or asset_name.endswith(".tgz"):
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                        # Find and extract agent binary
                        for member in tf.getmembers():
                            if "agent" in member.name.lower() and member.isfile():
                                # Extract file content
                                extracted = tf.extractfile(member)
                                if extracted:
                                    with open(out_path, "wb") as f:
                                        f.write(extracted.read())
                                    out_path.chmod(0o755)
                                    downloaded.append(str(out_path))
                                    print(Style.success(f"  Saved: {out_path}"))
                                    break

                else:
                    # Direct binary (unlikely but handle it)
                    with open(out_path, "wb") as f:
                        f.write(data)
                    if os_type == "linux":
                        out_path.chmod(0o755)
                    downloaded.append(str(out_path))
                    print(Style.success(f"  Saved: {out_path}"))

            except Exception as e:
                print(Style.error(f"Failed to download {asset_name}: {e}"))

        if downloaded:
            print()
            print(Style.success(f"Downloaded {len(downloaded)} agent(s) to {output_dir}"))
            print(Style.info("Use 'ligolo_pivot' module to deploy agents to targets"))
            return True
        else:
            print(Style.error("No agents were downloaded"))
            return False

    def _find_ligolo_tmux_session(self) -> Optional[str]:
        """Find existing ligolo tmux session (uwu-ligolo-*)"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if line.startswith("uwu-ligolo"):
                    return line
            return None
        except:
            return None

    def _start_ligolo_tmux(self, port: int = 11601) -> bool:
        """Start ligolo in a tmux session (like evil-winrm)"""

        # Check if a ligolo session already exists
        existing = self._find_ligolo_tmux_session()
        if existing:
            print(Style.warning(f"Ligolo session already exists: {existing}"))
            print(Style.info(f"Use 'ligolo attach' to connect"))
            print(Style.info(f"Use 'ligolo kill' to stop it"))
            return False

        session_name = f"uwu-ligolo-{port}"

        # Find ligolo binary
        available, msg = self.console.ligolo_mode.client.is_available()
        if not available:
            print(Style.error("Ligolo-ng proxy not found"))
            return False

        proxy_path = self.console.ligolo_mode.client.proxy_path

        # Setup TUN interface first
        print(Style.info("Setting up TUN interface..."))
        self.console.ligolo_mode.client.create_tun_interface("ligolo")

        # Build ligolo command
        ligolo_cmd = f"{proxy_path} -laddr 0.0.0.0:{port} -selfcert"

        # Create tmux session
        result = subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_name, ligolo_cmd],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            # Apply UwU theme to the session
            status_right = "#[fg=#00ffff]LIGOLO #[fg=#ff6eb4]| #[fg=#ffffff]Port: {} #[fg=#ff6eb4]| #[fg=#666666]Ctrl+b x to detach".format(port)
            theme_cmds = [
                ["tmux", "set-option", "-t", session_name, "status", "on"],
                ["tmux", "set-option", "-t", session_name, "status-style", "bg=#1a1a2e,fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "status-left-length", "50"],
                ["tmux", "set-option", "-t", session_name, "status-right-length", "120"],
                ["tmux", "set-option", "-t", session_name, "status-left", "#[bg=#ff6eb4,fg=#1a1a2e,bold] UwU #[bg=#1a1a2e,fg=#ff6eb4] "],
                ["tmux", "set-option", "-t", session_name, "status-right", status_right],
                ["tmux", "set-option", "-t", session_name, "status-interval", "2"],
                ["tmux", "set-option", "-t", session_name, "window-status-current-style", "bg=#ff00ff,fg=#1a1a2e,bold"],
                ["tmux", "set-option", "-t", session_name, "window-status-style", "bg=#1a1a2e,fg=#888888"],
                ["tmux", "set-option", "-t", session_name, "pane-border-style", "fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "pane-active-border-style", "fg=#00ffff"],
                ["tmux", "set-option", "-t", session_name, "message-style", "bg=#ff6eb4,fg=#1a1a2e,bold"],
                # Bind Ctrl+b x to detach (applied globally)
                ["tmux", "bind-key", "x", "detach-client"],
            ]
            for cmd in theme_cmds:
                subprocess.run(cmd, capture_output=True)

            print(Style.success(f"Starting Ligolo-ng session..."))
            print(Style.info(f"Port: {port} | TUN: ligolo"))
            print(Style.info("Use Ctrl+b d to detach (background the session)"))
            print(Style.info("Use 'sessions' to list, 'interact' to reattach"))
            print()

            # Attach to session immediately (like evil-winrm does)
            os.system(f"tmux attach-session -t {session_name}")

            # Check if session still exists (user might have exited)
            check_result = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True, timeout=5
            )

            print()
            if check_result.returncode == 0:
                print(Style.info(f"Session '{session_name}' is backgrounded"))
                print(Style.info("Use 'sessions' to list, 'interact' to reattach"))
            else:
                print(Style.info("Session ended"))

            return True
        else:
            print(Style.error(f"Failed to start session: {result.stderr}"))
            return False

    def _attach_ligolo_tmux(self) -> None:
        """Attach to ligolo tmux session"""

        session_name = self._find_ligolo_tmux_session()

        if not session_name:
            print(Style.error("No ligolo session found"))
            print(Style.info("Use 'ligolo [port]' to start one"))
            return

        print(Style.info(f"Attaching to {session_name}..."))
        print(Style.info("Press Ctrl+b d to detach and return to UwU"))
        print()

        # Attach to session (this will take over the terminal)
        subprocess.run(["tmux", "attach-session", "-t", session_name])

        print()
        print(Style.info("Detached from ligolo session"))
        print(Style.info("Ligolo is still running in background"))

    def _kill_ligolo_tmux(self) -> None:
        """Kill ligolo tmux session"""

        session_name = self._find_ligolo_tmux_session()

        if not session_name:
            print(Style.warning("No ligolo session found"))
            return

        # Kill the session
        result = subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            capture_output=True
        )

        if result.returncode == 0:
            print(Style.success(f"Session '{session_name}' killed"))
        else:
            print(Style.error("Failed to kill session"))
