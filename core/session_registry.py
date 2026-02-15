"""
Unified Session Registry for UwU Toolkit

Wraps all session tracking systems (ShellManager, SessionManager, tmux/Sliver)
under a single interface for unified session listing, interaction, and management.

Usage:
    registry = get_session_registry()
    registry.refresh()
    sessions = registry.list(status="active")
    print_unified_sessions_table(sessions)
    registry.interact(session_id=3)
"""

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .colors import Colors, Style

logger = logging.getLogger("uwu.session_registry")


# =============================================================================
# Enums
# =============================================================================

class UnifiedSessionType(Enum):
    """All possible session types across every subsystem."""
    # ShellManager types
    SHELL_REVERSE = "shell/reverse"
    SHELL_BIND = "shell/bind"
    SHELL_PENELOPE = "shell/penelope"
    SHELL_NC = "shell/nc"
    # SessionManager (Impacket) types
    IMPACKET_PSEXEC = "impacket/psexec"
    IMPACKET_WMIEXEC = "impacket/wmiexec"
    IMPACKET_SMBEXEC = "impacket/smbexec"
    IMPACKET_DCOMEXEC = "impacket/dcomexec"
    IMPACKET_ATEXEC = "impacket/atexec"
    # SessionManager protocol types
    WINRM = "winrm"
    SSH = "ssh"
    MSSQL = "mssql"
    LDAP = "ldap"
    # C2 / tmux types
    C2_SLIVER = "c2/sliver"
    C2_BEACON = "c2/beacon"
    TMUX = "tmux"


# =============================================================================
# Mapping tables between subsystem types and unified types
# =============================================================================

# ShellType (from shells.py) -> UnifiedSessionType
_SHELL_TYPE_MAP: Dict[str, UnifiedSessionType] = {
    "reverse": UnifiedSessionType.SHELL_REVERSE,
    "bind": UnifiedSessionType.SHELL_BIND,
    "penelope": UnifiedSessionType.SHELL_PENELOPE,
    "nc": UnifiedSessionType.SHELL_NC,
}

# SessionType (from sessions.py) -> UnifiedSessionType
_SESSION_TYPE_MAP: Dict[str, UnifiedSessionType] = {
    "psexec": UnifiedSessionType.IMPACKET_PSEXEC,
    "wmiexec": UnifiedSessionType.IMPACKET_WMIEXEC,
    "smbexec": UnifiedSessionType.IMPACKET_SMBEXEC,
    "dcomexec": UnifiedSessionType.IMPACKET_DCOMEXEC,
    "atexec": UnifiedSessionType.IMPACKET_ATEXEC,
    "winrm": UnifiedSessionType.WINRM,
    "ssh": UnifiedSessionType.SSH,
    "mssql": UnifiedSessionType.MSSQL,
    "ldap": UnifiedSessionType.LDAP,
    "reverse_shell": UnifiedSessionType.SHELL_REVERSE,
    "bind_shell": UnifiedSessionType.SHELL_BIND,
    "c2_beacon": UnifiedSessionType.C2_BEACON,
}


# =============================================================================
# UnifiedSession dataclass
# =============================================================================

@dataclass
class UnifiedSession:
    """A session from any subsystem, normalized into a common structure."""
    id: int                                     # Global unique ID
    session_type: UnifiedSessionType
    source: str                                 # "shell", "session", "tmux", "sliver"
    source_id: Any                              # Original ID in source system
    target: str                                 # IP/hostname
    port: int
    username: str = ""
    domain: str = ""
    hostname: str = ""
    os_info: str = ""
    status: str = "active"                      # Normalized: active, idle, dead, connecting, unknown
    created_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    notes: str = ""
    info: Dict[str, Any] = field(default_factory=dict)  # Extra metadata

    @property
    def age(self) -> str:
        """Human-readable age string."""
        delta = datetime.now() - self.created_at
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m"
        hours = minutes // 60
        if hours < 24:
            remaining_min = minutes % 60
            return f"{hours}h{remaining_min}m"
        days = hours // 24
        remaining_hrs = hours % 24
        return f"{days}d{remaining_hrs}h"

    @property
    def display_type(self) -> str:
        """Short display string for the session type."""
        return self.session_type.value

    @property
    def user_at_domain(self) -> str:
        """Format username with domain if available."""
        if self.domain and self.username:
            return f"{self.domain}\\{self.username}"
        return self.username or ""


# =============================================================================
# SessionRegistry (singleton)
# =============================================================================

class SessionRegistry:
    """Unified registry that aggregates sessions from ShellManager,
    SessionManager, and tmux into a single queryable interface.

    Thread-safe. Lazy initialization -- subsystem managers are not
    accessed until the first ``refresh()`` or ``list()`` call.
    """

    _instance: Optional["SessionRegistry"] = None

    @classmethod
    def get_instance(cls) -> "SessionRegistry":
        """Return the singleton SessionRegistry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (primarily for testing)."""
        cls._instance = None

    def __init__(self) -> None:
        self._sessions: Dict[int, UnifiedSession] = {}
        self._next_id: int = 1
        self._shell_manager: Any = None       # Lazy reference to ShellManager
        self._session_manager: Any = None      # Lazy reference to SessionManager
        self._lock = threading.Lock()
        self._last_refresh: float = 0.0
        self._cache_ttl: float = 2.0           # Seconds before auto-refresh

        # Stable mapping: (source, source_id) -> unified id
        # This prevents IDs from changing across refreshes.
        self._id_map: Dict[tuple, int] = {}

    # ------------------------------------------------------------------
    # Lazy subsystem accessors
    # ------------------------------------------------------------------

    def _get_shell_manager(self) -> Any:
        """Lazily import and return the ShellManager singleton."""
        if self._shell_manager is None:
            try:
                from .shells import get_shell_manager
                self._shell_manager = get_shell_manager()
            except ImportError:
                logger.debug("ShellManager not available (import failed)")
        return self._shell_manager

    def _get_session_manager(self) -> Any:
        """Lazily import and return the SessionManager singleton."""
        if self._session_manager is None:
            try:
                from .sessions import SessionManager
                self._session_manager = SessionManager.get_instance()
            except ImportError:
                logger.debug("SessionManager not available (import failed)")
        return self._session_manager

    # ------------------------------------------------------------------
    # ID management
    # ------------------------------------------------------------------

    def _get_or_assign_id(self, source: str, source_id: Any) -> int:
        """Return a stable unified ID for a (source, source_id) pair.

        If the pair has been seen before, the same ID is returned.
        Otherwise a new ID is allocated.
        """
        key = (source, source_id)
        if key not in self._id_map:
            self._id_map[key] = self._next_id
            self._next_id += 1
        return self._id_map[key]

    # ------------------------------------------------------------------
    # Refresh / Sync
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Synchronize from all source subsystems.

        Clears dead sessions that no longer exist in their source,
        and pulls current state from ShellManager, SessionManager, and tmux.
        """
        with self._lock:
            self._sessions.clear()
            self._sync_shells()
            self._sync_sessions()
            self._sync_tmux()
            self._last_refresh = time.monotonic()

    def _needs_refresh(self) -> bool:
        """Return True if the cache is stale."""
        return (time.monotonic() - self._last_refresh) > self._cache_ttl

    def _auto_refresh(self) -> None:
        """Refresh if the cache TTL has elapsed."""
        if self._needs_refresh():
            self.refresh()

    def _sync_shells(self) -> None:
        """Pull shells from ShellManager and register them."""
        sm = self._get_shell_manager()
        if sm is None:
            return

        try:
            shells = sm.list_shells()
        except Exception as exc:
            logger.debug("Failed to list shells: %s", exc)
            return

        for shell in shells:
            # Map ShellType enum value to UnifiedSessionType
            unified_type = _SHELL_TYPE_MAP.get(
                shell.shell_type.value,
                UnifiedSessionType.SHELL_REVERSE,
            )

            # Normalize status
            status = _normalize_shell_status(shell.status)

            uid = self._get_or_assign_id("shell", shell.id)
            session = UnifiedSession(
                id=uid,
                session_type=unified_type,
                source="shell",
                source_id=shell.id,
                target=shell.remote_ip,
                port=shell.remote_port,
                username=shell.user if shell.user != "Unknown" else "",
                hostname=shell.hostname if shell.hostname != "Unknown" else "",
                os_info=shell.os_info if shell.os_info != "Unknown" else "",
                status=status,
                created_at=shell.created_at,
                last_active=shell.last_active,
                notes=shell.notes,
                info={
                    "local_port": shell.local_port,
                    "shell_type": shell.shell_type.value,
                    "has_pty": shell.pty_fd is not None,
                },
            )
            self._sessions[uid] = session

    def _sync_sessions(self) -> None:
        """Pull sessions from SessionManager (async system)."""
        mgr = self._get_session_manager()
        if mgr is None:
            return

        try:
            # SessionManager._sessions is a dict of int -> SessionBase
            # We access the internal dict directly since list_all() returns
            # dicts, but we need the SessionBase objects for richer info.
            raw_sessions = getattr(mgr, "_sessions", {})
        except Exception as exc:
            logger.debug("Failed to access SessionManager sessions: %s", exc)
            return

        for sid, session_obj in raw_sessions.items():
            info = session_obj.info  # SessionInfo dataclass

            # Map SessionType enum value to UnifiedSessionType
            unified_type = _SESSION_TYPE_MAP.get(
                info.session_type.value,
                UnifiedSessionType.WINRM,
            )

            # Normalize status
            status = _normalize_session_status(info.status)

            uid = self._get_or_assign_id("session", info.id)
            session = UnifiedSession(
                id=uid,
                session_type=unified_type,
                source="session",
                source_id=info.id,
                target=info.target,
                port=info.port,
                username=info.username,
                domain=info.domain,
                hostname=info.hostname,
                os_info=info.os_info,
                status=status,
                created_at=info.created_at,
                last_active=info.last_active,
                notes=info.notes,
                info={
                    "arch": info.arch,
                    "privileges": list(info.privileges),
                    "pid": info.pid,
                    "session_type": info.session_type.value,
                },
            )
            self._sessions[uid] = session

    def _sync_tmux(self) -> None:
        """Discover tmux sessions matching the ``uwu-*`` naming pattern."""
        try:
            result = subprocess.run(
                [
                    "tmux", "list-sessions",
                    "-F", "#{session_name}:#{session_created}",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except FileNotFoundError:
            # tmux not installed
            return
        except subprocess.TimeoutExpired:
            logger.debug("tmux list-sessions timed out")
            return
        except Exception as exc:
            logger.debug("tmux list-sessions failed: %s", exc)
            return

        if result.returncode != 0:
            # No tmux server running or no sessions
            return

        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Parse "session_name:epoch_timestamp"
            parts = line.rsplit(":", 1)
            if len(parts) != 2:
                continue

            session_name = parts[0]
            try:
                created_epoch = int(parts[1])
                created_dt = datetime.fromtimestamp(created_epoch)
            except (ValueError, OSError):
                created_dt = datetime.now()

            # Only include uwu-* prefixed tmux sessions
            if not session_name.startswith("uwu-"):
                continue

            # Determine type: uwu-sliver-* -> C2_SLIVER, otherwise TMUX
            if session_name.startswith("uwu-sliver"):
                unified_type = UnifiedSessionType.C2_SLIVER
            else:
                unified_type = UnifiedSessionType.TMUX

            uid = self._get_or_assign_id("tmux", session_name)
            session = UnifiedSession(
                id=uid,
                session_type=unified_type,
                source="tmux",
                source_id=session_name,
                target="local",
                port=0,
                status="active",
                created_at=created_dt,
                last_active=created_dt,
                notes=f"tmux session: {session_name}",
                info={
                    "tmux_session": session_name,
                },
            )
            self._sessions[uid] = session

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def list(
        self,
        session_type: Optional[UnifiedSessionType] = None,
        target: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[UnifiedSession]:
        """List sessions with optional filtering.

        Args:
            session_type: Filter by UnifiedSessionType.
            target: Filter by target IP/hostname (exact match).
            status: Filter by normalized status string.
            source: Filter by source system ("shell", "session", "tmux").

        Returns:
            Matching sessions sorted by ID.
        """
        self._auto_refresh()

        with self._lock:
            sessions = list(self._sessions.values())

        # Apply filters
        if session_type is not None:
            sessions = [s for s in sessions if s.session_type == session_type]
        if target is not None:
            sessions = [s for s in sessions if s.target == target]
        if status is not None:
            sessions = [s for s in sessions if s.status == status]
        if source is not None:
            sessions = [s for s in sessions if s.source == source]

        sessions.sort(key=lambda s: s.id)
        return sessions

    def get(self, session_id: int) -> Optional[UnifiedSession]:
        """Get a session by its unified ID."""
        self._auto_refresh()
        with self._lock:
            return self._sessions.get(session_id)

    # ------------------------------------------------------------------
    # Interaction
    # ------------------------------------------------------------------

    def interact(self, session_id: int) -> bool:
        """Route interaction to the correct subsystem.

        - Shell -> ShellManager.interact(source_id)
        - Tmux  -> os.system("tmux attach-session -t <name>")
        - SessionManager sessions are not typically interactive
          (they use execute() calls), so this prints guidance instead.

        Returns:
            True if interaction was dispatched successfully.
        """
        session = self.get(session_id)
        if session is None:
            print(Style.error(f"Session {session_id} not found"))
            return False

        if session.status == "dead":
            print(Style.error(f"Session {session_id} is dead"))
            return False

        # --- Shell subsystem ---
        if session.source == "shell":
            sm = self._get_shell_manager()
            if sm is None:
                print(Style.error("ShellManager not available"))
                return False
            return sm.interact(session.source_id)

        # --- Tmux subsystem ---
        if session.source == "tmux":
            tmux_name = session.source_id
            print(Style.info(f"Attaching to tmux session: {tmux_name}"))
            print(Style.warning("Press Ctrl+B then D to detach"))
            rc = os.system(f"tmux attach-session -t {tmux_name}")
            return rc == 0

        # --- SessionManager subsystem ---
        if session.source == "session":
            print(Style.warning(
                f"Session {session_id} ({session.display_type}) is a command-execution "
                f"session, not an interactive shell."
            ))
            print(Style.info(
                f"Use the SessionManager to execute commands:\n"
                f"  mgr = SessionManager.get_instance()\n"
                f"  result = await mgr.execute({session.source_id}, 'whoami')"
            ))
            return False

        print(Style.error(f"Unknown session source: {session.source}"))
        return False

    # ------------------------------------------------------------------
    # Kill / Close
    # ------------------------------------------------------------------

    def kill(self, session_id: int) -> bool:
        """Kill/close a session via the appropriate subsystem.

        Returns:
            True if the session was successfully killed.
        """
        session = self.get(session_id)
        if session is None:
            print(Style.error(f"Session {session_id} not found"))
            return False

        # --- Shell subsystem ---
        if session.source == "shell":
            sm = self._get_shell_manager()
            if sm is None:
                print(Style.error("ShellManager not available"))
                return False
            result = sm.kill_shell(session.source_id)
            if result:
                print(Style.success(f"Shell {session.source_id} killed"))
                # Update local state
                with self._lock:
                    if session_id in self._sessions:
                        self._sessions[session_id].status = "dead"
            return result

        # --- Tmux subsystem ---
        if session.source == "tmux":
            tmux_name = session.source_id
            try:
                result = subprocess.run(
                    ["tmux", "kill-session", "-t", str(tmux_name)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    print(Style.success(f"Tmux session '{tmux_name}' killed"))
                    with self._lock:
                        self._sessions.pop(session_id, None)
                    return True
                else:
                    print(Style.error(f"Failed to kill tmux session: {result.stderr.strip()}"))
                    return False
            except Exception as exc:
                print(Style.error(f"Error killing tmux session: {exc}"))
                return False

        # --- SessionManager subsystem ---
        if session.source == "session":
            mgr = self._get_session_manager()
            if mgr is None:
                print(Style.error("SessionManager not available"))
                return False

            # SessionManager.close() is async -- try to run it
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # We are inside an async context; schedule as a task
                    # This is a best-effort approach for sync callers
                    print(Style.warning(
                        "SessionManager is async. Use "
                        "'await SessionManager.get_instance().close(source_id)' directly."
                    ))
                    return False
                else:
                    result = loop.run_until_complete(mgr.close(session.source_id))
            except RuntimeError:
                # No event loop exists; create one
                result = asyncio.run(mgr.close(session.source_id))

            if result:
                print(Style.success(f"Session {session.source_id} closed"))
                with self._lock:
                    if session_id in self._sessions:
                        self._sessions[session_id].status = "dead"
            return result

        print(Style.error(f"Unknown session source: {session.source}"))
        return False

    # ------------------------------------------------------------------
    # Summary / Stats
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict[str, int]:
        """Return counts grouped by source and status.

        Returns:
            Dict with keys like "shell:active", "session:dead", "total", etc.
        """
        self._auto_refresh()

        with self._lock:
            sessions = list(self._sessions.values())

        summary: Dict[str, int] = {
            "total": len(sessions),
            "active": 0,
            "dead": 0,
        }

        for s in sessions:
            # Count by status
            if s.status == "active":
                summary["active"] += 1
            elif s.status == "dead":
                summary["dead"] += 1

            # Count by source
            source_key = s.source
            summary[source_key] = summary.get(source_key, 0) + 1

            # Count by source:status
            compound_key = f"{s.source}:{s.status}"
            summary[compound_key] = summary.get(compound_key, 0) + 1

        return summary


# =============================================================================
# Module-level singleton accessor
# =============================================================================

def get_session_registry() -> SessionRegistry:
    """Return the global SessionRegistry singleton."""
    return SessionRegistry.get_instance()


# =============================================================================
# Status normalization helpers
# =============================================================================

def _normalize_shell_status(status: Any) -> str:
    """Normalize a ShellStatus enum to a plain string.

    Maps:
        ShellStatus.ACTIVE  -> "active"
        ShellStatus.DEAD    -> "dead"
        ShellStatus.UNKNOWN -> "unknown"
    """
    try:
        return status.value  # ShellStatus enum values are lowercase strings
    except AttributeError:
        return str(status).lower()


def _normalize_session_status(status: Any) -> str:
    """Normalize a SessionStatus enum to a plain string.

    Maps:
        SessionStatus.ACTIVE     -> "active"
        SessionStatus.IDLE       -> "idle"
        SessionStatus.DEAD       -> "dead"
        SessionStatus.CONNECTING -> "connecting"
    """
    try:
        return status.value  # SessionStatus enum values are lowercase strings
    except AttributeError:
        return str(status).lower()


# =============================================================================
# Table printer
# =============================================================================

# Status -> color mapping for the table
_STATUS_COLORS: Dict[str, str] = {
    "active": Colors.NEON_GREEN,
    "idle": Colors.NEON_YELLOW,
    "connecting": Colors.NEON_CYAN,
    "dead": Colors.NEON_RED,
    "unknown": Colors.GRID,
}

# Source -> display label
_SOURCE_LABELS: Dict[str, str] = {
    "shell": "Shell",
    "session": "Session",
    "tmux": "Tmux/C2",
}


def print_unified_sessions_table(sessions: List[UnifiedSession]) -> None:
    """Pretty-print sessions in a unified table.

    Columns: ID | Type | Target | User@Domain | Hostname | OS | Status | Age
    Color-coded by status. Grouped by source system.
    """
    if not sessions:
        print(Style.warning("No sessions"))
        return

    # Group sessions by source for display ordering: shell, session, tmux
    source_order = ["shell", "session", "tmux"]
    grouped: Dict[str, List[UnifiedSession]] = {}
    for s in sessions:
        grouped.setdefault(s.source, []).append(s)

    # Column widths
    col_id = 4
    col_type = 18
    col_target = 22
    col_user = 22
    col_host = 14
    col_os = 12
    col_status = 12
    col_age = 8
    total_width = col_id + col_type + col_target + col_user + col_host + col_os + col_status + col_age + 7  # 7 spaces between cols

    print()
    print(f"  {Colors.NEON_CYAN}Unified Sessions{Colors.RESET}")
    print(f"  {Colors.NEON_PINK}{'=' * total_width}{Colors.RESET}")
    print()

    # Header
    header = (
        f"  {Colors.BRIGHT_WHITE}"
        f"{'ID':<{col_id}} "
        f"{'Type':<{col_type}} "
        f"{'Target':<{col_target}} "
        f"{'User@Domain':<{col_user}} "
        f"{'Hostname':<{col_host}} "
        f"{'OS':<{col_os}} "
        f"{'Status':<{col_status}} "
        f"{'Age':<{col_age}}"
        f"{Colors.RESET}"
    )
    print(header)

    separator = (
        f"  {Colors.GRID}"
        f"{'-' * col_id} "
        f"{'-' * col_type} "
        f"{'-' * col_target} "
        f"{'-' * col_user} "
        f"{'-' * col_host} "
        f"{'-' * col_os} "
        f"{'-' * col_status} "
        f"{'-' * col_age}"
        f"{Colors.RESET}"
    )
    print(separator)

    for source_key in source_order:
        group = grouped.pop(source_key, [])
        if not group:
            continue

        # Source group label
        label = _SOURCE_LABELS.get(source_key, source_key.title())
        print(f"  {Colors.NEON_PURPLE}{label}{Colors.RESET}")

        for s in group:
            status_color = _STATUS_COLORS.get(s.status, Colors.GRID)
            status_display = s.status.upper()

            target_str = s.target
            if s.port and s.port > 0:
                target_str = f"{s.target}:{s.port}"
            target_str = target_str[:col_target]

            user_str = s.user_at_domain[:col_user]
            host_str = s.hostname[:col_host]
            os_str = s.os_info[:col_os]
            age_str = s.age

            print(
                f"  {Colors.NEON_CYAN}{s.id:<{col_id}}{Colors.RESET} "
                f"{s.display_type:<{col_type}} "
                f"{target_str:<{col_target}} "
                f"{user_str:<{col_user}} "
                f"{host_str:<{col_host}} "
                f"{os_str:<{col_os}} "
                f"{status_color}{status_display:<{col_status}}{Colors.RESET} "
                f"{Colors.GRID}{age_str:<{col_age}}{Colors.RESET}"
            )

    # Handle any remaining sources not in source_order
    for source_key, group in grouped.items():
        if not group:
            continue
        label = source_key.title()
        print(f"  {Colors.NEON_PURPLE}{label}{Colors.RESET}")
        for s in group:
            status_color = _STATUS_COLORS.get(s.status, Colors.GRID)
            status_display = s.status.upper()

            target_str = s.target
            if s.port and s.port > 0:
                target_str = f"{s.target}:{s.port}"
            target_str = target_str[:col_target]

            user_str = s.user_at_domain[:col_user]
            host_str = s.hostname[:col_host]
            os_str = s.os_info[:col_os]
            age_str = s.age

            print(
                f"  {Colors.NEON_CYAN}{s.id:<{col_id}}{Colors.RESET} "
                f"{s.display_type:<{col_type}} "
                f"{target_str:<{col_target}} "
                f"{user_str:<{col_user}} "
                f"{host_str:<{col_host}} "
                f"{os_str:<{col_os}} "
                f"{status_color}{status_display:<{col_status}}{Colors.RESET} "
                f"{Colors.GRID}{age_str:<{col_age}}{Colors.RESET}"
            )

    print()

    # Summary line
    active_count = sum(1 for s in sessions if s.status == "active")
    dead_count = sum(1 for s in sessions if s.status == "dead")
    total_count = len(sessions)

    summary_parts = [f"{Colors.BRIGHT_WHITE}{total_count} total{Colors.RESET}"]
    if active_count:
        summary_parts.append(f"{Colors.NEON_GREEN}{active_count} active{Colors.RESET}")
    if dead_count:
        summary_parts.append(f"{Colors.NEON_RED}{dead_count} dead{Colors.RESET}")

    print(f"  {' | '.join(summary_parts)}")
    print()
    print(f"  {Colors.GRID}Use 'interact <ID>' to interact with a session{Colors.RESET}")
    print(f"  {Colors.GRID}Use 'kill <ID>' to kill a session{Colors.RESET}")
    print()
