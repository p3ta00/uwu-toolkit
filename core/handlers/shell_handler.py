"""
Shell/session command handler for UwU Toolkit console.
Handles shell listing, interaction, killing, upgrading, and listener management.
"""

import os
import subprocess
from typing import List

from . import HandlerBase
from ..colors import Colors, Style
from .. import tmux_status
from ..shells import (
    ShellManager,
    get_shell_manager,
    print_shells_table,
    print_listeners_table,
    ShellType,
    ShellStatus,
)


class ShellHandler(HandlerBase):
    """Handles shell/session listing, interaction, and management commands."""

    def cmd_shells(self, args: List[str]) -> None:
        """List all sessions (unified view)"""
        # Try the unified SessionRegistry first
        try:
            from ..session_registry import get_session_registry, print_unified_sessions_table

            registry = get_session_registry()
            registry.refresh()
            sessions = registry.list()
            if not sessions:
                print(f"  {Style.warning('No active sessions')}")
                return
            print_unified_sessions_table(sessions)
            return
        except (ImportError, AttributeError):
            pass  # Fall back to legacy separate-table approach

        # Legacy: show shells, sliver, and tmux sessions separately
        has_sessions = False

        # List shell manager sessions
        shells = self.console.shell_manager.list_shells()
        if shells:
            print_shells_table(shells)
            has_sessions = True

        # List Sliver sessions/beacons
        sliver_sessions = self._list_sliver_sessions()
        if sliver_sessions:
            has_sessions = True
            print(f"\n  {Colors.NEON_GREEN}Sliver Sessions{Colors.RESET}")
            print(f"  {Colors.NEON_GREEN}{'='*75}{Colors.RESET}\n")
            print(f"  {'Type':<8} {'ID':<10} {'Name':<20} {'User@Host':<30} {'Remote'}")
            print(f"  {'-'*8} {'-'*10} {'-'*20} {'-'*30} {'-'*20}")
            for sess in sliver_sessions:
                sess_type = f"{Colors.NEON_GREEN}SESSION{Colors.RESET}" if sess['type'] == 'sliver' else f"{Colors.NEON_ORANGE}BEACON{Colors.RESET}"
                user_host = f"{sess['username']}@{sess['hostname']}"
                print(f"  {sess_type:<17} {Colors.NEON_CYAN}{sess['id']:<10}{Colors.RESET} {sess['name']:<20} {user_host:<30} {sess['remote']}")
            print()
            print(f"  {Colors.GRID}Use 'interact <id>' to connect via Sliver{Colors.RESET}")
            print()

        # List tmux sessions (uwu-* sessions from evil_winrm, etc.)
        tmux_sessions = self._list_tmux_sessions()
        if tmux_sessions:
            has_sessions = True
            from datetime import datetime
            print(f"\n  {Colors.NEON_PINK}Tmux Sessions{Colors.RESET}")
            print(f"  {Colors.NEON_PINK}{'='*65}{Colors.RESET}\n")
            print(f"  {'ID':<5} {'Name':<40} {'Status':<12} {'Created'}")
            print(f"  {'-'*5} {'-'*40} {'-'*12} {'-'*12}")
            for idx, sess in enumerate(tmux_sessions, 1):
                status = f"{Colors.NEON_GREEN}active{Colors.RESET}" if sess.get("attached") else f"{Colors.NEON_CYAN}detached{Colors.RESET}"
                # Format timestamp
                created = sess.get("created", "")
                try:
                    ts = datetime.fromtimestamp(int(created)).strftime("%m-%d %H:%M")
                except:
                    ts = created
                print(f"  {Colors.NEON_MAGENTA}{idx:<5}{Colors.RESET} {Colors.BRIGHT_WHITE}{sess['name']:<40}{Colors.RESET} {status:<22} {ts}")
            print()
            print(f"  {Colors.GRID}Use 'interact <id>' to attach, Ctrl+b d to detach{Colors.RESET}")
            print()

        if not has_sessions:
            print(Style.warning("No active sessions"))
            print(Style.info("Use 'sliver connect' for C2 sessions or evil_winrm module for WinRM"))

    def _list_tmux_sessions(self) -> list:
        """List tmux sessions starting with uwu-"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}:#{session_created}:#{session_attached}"],
                capture_output=True, text=True, timeout=5
            )
            sessions = []
            for line in result.stdout.strip().split('\n'):
                if line and line.startswith("uwu-"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        sessions.append({
                            "name": parts[0],
                            "created": parts[1],
                            "attached": parts[2] == "1"
                        })
            return sessions
        except:
            return []

    def _list_sliver_sessions(self) -> list:
        """List active Sliver sessions - disabled to avoid join/leave spam.
        Use 'sessions' inside Sliver console instead."""
        # Disabled: querying sliver-client causes "uwu joined/left the game" spam
        # Users should check sessions from within the Sliver tmux session
        return []

    def cmd_interact(self, args: List[str]) -> None:
        """Interact with a shell, tmux, or Sliver session"""
        # Try unified SessionRegistry first
        try:
            from ..session_registry import get_session_registry
            registry = get_session_registry()
            if args:
                identifier = args[0]
                session = registry.get(identifier)
                if session is not None:
                    registry.interact(identifier)
                    return
            # Fall through to legacy if registry doesn't have it
        except (ImportError, AttributeError):
            pass

        # Legacy interaction logic
        tmux_sessions = self._list_tmux_sessions()
        sliver_sessions = self._list_sliver_sessions()
        shells = self.console.shell_manager.list_shells()

        if not args:
            # Show all session types for selection
            if not shells and not tmux_sessions and not sliver_sessions:
                print(Style.warning("No active sessions"))
                return

            if shells:
                print_shells_table(shells)

            if sliver_sessions:
                print(f"\n  {Colors.NEON_GREEN}Sliver Sessions:{Colors.RESET}")
                for sess in sliver_sessions:
                    sess_type = "SESSION" if sess['type'] == 'sliver' else "BEACON"
                    print(f"    {Colors.NEON_CYAN}[{sess['id']}]{Colors.RESET} {sess['name']} - {sess['username']}@{sess['hostname']} ({sess_type})")

            if tmux_sessions:
                print(f"\n  {Colors.NEON_PINK}Tmux Sessions:{Colors.RESET}")
                for idx, sess in enumerate(tmux_sessions, 1):
                    status = "active" if sess.get("attached") else "detached"
                    print(f"    {Colors.NEON_MAGENTA}[{idx}]{Colors.RESET} {Colors.NEON_CYAN}{sess['name']}{Colors.RESET} ({status})")

            try:
                choice = input(f"\n  {Colors.NEON_CYAN}Enter session ID:{Colors.RESET} ").strip()
                if not choice:
                    return

                # Check if it's a Sliver session ID (8 hex chars)
                if len(choice) == 8 and all(c in '0123456789abcdef' for c in choice.lower()):
                    if any(s['id'] == choice for s in sliver_sessions):
                        self._interact_sliver_session(choice)
                        return

                # Try as numeric ID first (for tmux sessions)
                try:
                    session_id = int(choice)
                    if 1 <= session_id <= len(tmux_sessions):
                        self._attach_tmux_session(tmux_sessions[session_id - 1]["name"])
                    else:
                        # Try shell manager
                        self.console.shell_manager.interact(session_id)
                except ValueError:
                    # Try as session name or Sliver ID
                    if choice.startswith("uwu-"):
                        self._attach_tmux_session(choice)
                    elif any(s["name"] == choice for s in tmux_sessions):
                        self._attach_tmux_session(choice)
                    elif any(s['id'].startswith(choice) for s in sliver_sessions):
                        # Partial Sliver ID match
                        for s in sliver_sessions:
                            if s['id'].startswith(choice):
                                self._interact_sliver_session(s['id'])
                                return
                    else:
                        print(Style.error("Invalid session ID or name"))
            except KeyboardInterrupt:
                print()
                return
        else:
            identifier = args[0]

            # Check if it's a Sliver session ID
            if any(s['id'] == identifier or s['id'].startswith(identifier) for s in sliver_sessions):
                for s in sliver_sessions:
                    if s['id'] == identifier or s['id'].startswith(identifier):
                        self._interact_sliver_session(s['id'])
                        return

            # Try as numeric ID first
            try:
                session_id = int(identifier)
                if tmux_sessions and 1 <= session_id <= len(tmux_sessions):
                    self._attach_tmux_session(tmux_sessions[session_id - 1]["name"])
                else:
                    # Try shell manager
                    self.console.shell_manager.interact(session_id)
            except ValueError:
                # Try as session name
                tmux_names = [s["name"] for s in tmux_sessions]
                if identifier in tmux_names:
                    self._attach_tmux_session(identifier)
                elif f"uwu-{identifier}" in tmux_names:
                    self._attach_tmux_session(f"uwu-{identifier}")
                elif identifier.startswith("uwu-"):
                    self._attach_tmux_session(identifier)
                else:
                    print(Style.error(f"Session not found: {identifier}"))

    def _attach_tmux_session(self, session_name: str) -> None:
        """Attach to a tmux session"""
        print(Style.info(f"Attaching to tmux session: {session_name}"))
        print(Style.info("Use Ctrl+b d to detach"))
        os.system(f"tmux attach-session -t {session_name}")

    def _interact_sliver_session(self, session_id: str) -> None:
        """Connect to Sliver and interact with specified session"""
        from ..sliver import get_sliver_mode

        print(Style.info(f"Connecting to Sliver session: {session_id}"))

        # Get the Sliver mode instance
        sliver_mode = get_sliver_mode(self.config)

        # Set the active session so it auto-selects on connect
        sliver_mode.active_session = session_id

        # If already backgrounded, resume with the session
        if sliver_mode.is_backgrounded():
            sliver_mode.resume()
        else:
            # Start new Sliver connection
            sliver_mode.start()

    def cmd_kill_shell(self, args: List[str]) -> None:
        """Kill a shell or tmux session"""
        if not args:
            print(Style.error("Usage: kill <session_id> or kill <session_name>"))
            return

        identifier = args[0]
        tmux_sessions = self._list_tmux_sessions()
        tmux_names = [s["name"] for s in tmux_sessions]

        # Try as numeric ID first
        try:
            session_id = int(identifier)
            if tmux_sessions and 1 <= session_id <= len(tmux_sessions):
                session_name = tmux_sessions[session_id - 1]["name"]
                result = subprocess.run(
                    ["tmux", "kill-session", "-t", session_name],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    print(Style.success(f"Session {session_id} ({session_name}) killed"))
                else:
                    print(Style.error(f"Failed to kill session: {session_name}"))
                return
            else:
                # Try shell manager
                if self.console.shell_manager.kill_shell(session_id):
                    print(Style.success(f"Shell {session_id} killed"))
                else:
                    print(Style.error(f"Shell {session_id} not found"))
                return
        except ValueError:
            pass

        # Try as session name
        if identifier in tmux_names or f"uwu-{identifier}" in tmux_names:
            session_name = identifier if identifier in tmux_names else f"uwu-{identifier}"
            try:
                result = subprocess.run(
                    ["tmux", "kill-session", "-t", session_name],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    print(Style.success(f"Session '{session_name}' killed"))
                else:
                    print(Style.error(f"Failed to kill session: {session_name}"))
            except Exception as e:
                print(Style.error(f"Failed to kill session: {e}"))
        else:
            print(Style.error(f"Session not found: {identifier}"))

    def cmd_upgrade_shell(self, args: List[str]) -> None:
        """Upgrade a raw shell to PTY"""
        if not args:
            print(Style.error("Usage: upgrade <shell_id>"))
            return
        try:
            shell_id = int(args[0])
        except ValueError:
            print(Style.error("Shell ID must be a number"))
            return
        self.console.shell_manager.upgrade_shell(shell_id)

    def cmd_listen(self, args: List[str]) -> None:
        """Start a shell listener (nc or penelope)"""
        if not args:
            print(Style.error("Usage: listen <port> [type]"))
            print(Style.info("Types: nc (default), penelope"))
            return

        try:
            port = int(args[0])
        except ValueError:
            print(Style.error("Invalid port number"))
            return

        listener_type = args[1] if len(args) > 1 else "nc"

        if listener_type not in ("nc", "penelope"):
            print(Style.error(f"Unknown listener type: {listener_type}"))
            print(Style.info("Types: nc, penelope"))
            return

        print(Style.info(f"Starting {listener_type} listener on port {port}..."))
        if self.console.shell_manager.start_listener(port, listener_type):
            tmux_status.update_listener(port, "listening", 0)
            print(Style.success(f"Listener started. Shells will auto-register."))
            print(Style.info(f"Use 'sessions' to view connections, 'interact <id>' to interact"))
        else:
            print(Style.error("Failed to start listener"))
