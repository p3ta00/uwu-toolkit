"""
Unified Session Abstraction Layer for UwU Toolkit

Replaces ad-hoc shell management with a proper session abstraction supporting
multiple transport types: WinRM, Impacket (psexec/wmiexec/smbexec/dcomexec/atexec),
SSH, MSSQL, reverse/bind shells, and C2 beacons.

All session classes are async-first using asyncio, with subprocess wrapping for
external tools (impacket, evil-winrm, ssh) since we run inside Exegol containers.

Usage:
    manager = SessionManager.get_instance()
    session = await manager.create_session(
        SessionType.WMIEXEC, "10.10.10.1", 445,
        username="admin", password="P@ss", domain="CORP"
    )
    result = await manager.execute(session.info.id, "whoami")
"""

import asyncio
import logging
import os
import shlex
import socket as socket_module
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

logger = logging.getLogger("uwu.sessions")

# Extended PATH for Exegol tools
EXTENDED_PATH = os.pathsep.join([
    "/opt/tools/Certipy/venv/bin",
    "/root/.local/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    os.environ.get("PATH", ""),
])


# =============================================================================
# Enums
# =============================================================================

class SessionType(Enum):
    """Supported session transport types."""
    WINRM = "winrm"
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    DCOMEXEC = "dcomexec"
    ATEXEC = "atexec"
    SSH = "ssh"
    MSSQL = "mssql"
    LDAP = "ldap"
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    C2_BEACON = "c2_beacon"


class SessionStatus(Enum):
    """Session lifecycle states."""
    CONNECTING = "connecting"
    ACTIVE = "active"
    IDLE = "idle"
    DEAD = "dead"


# Impacket session types share the same execution logic
_IMPACKET_TYPES = {
    SessionType.PSEXEC,
    SessionType.WMIEXEC,
    SessionType.SMBEXEC,
    SessionType.DCOMEXEC,
    SessionType.ATEXEC,
}

# Map SessionType to the impacket script name
_IMPACKET_TOOL_MAP: Dict[SessionType, str] = {
    SessionType.PSEXEC: "psexec.py",
    SessionType.WMIEXEC: "wmiexec.py",
    SessionType.SMBEXEC: "smbexec.py",
    SessionType.DCOMEXEC: "dcomexec.py",
    SessionType.ATEXEC: "atexec.py",
}


# =============================================================================
# SessionInfo dataclass
# =============================================================================

@dataclass
class SessionInfo:
    """Metadata describing a session."""
    id: int
    session_type: SessionType
    target: str
    port: int
    username: str
    domain: str = ""
    hostname: str = ""
    os_info: str = ""
    arch: str = ""
    privileges: List[str] = field(default_factory=list)
    status: SessionStatus = SessionStatus.CONNECTING
    created_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    pid: Optional[int] = None
    notes: str = ""

    def to_dict(self) -> dict:
        """Serialize session info to a plain dictionary."""
        return {
            "id": self.id,
            "session_type": self.session_type.value,
            "target": self.target,
            "port": self.port,
            "username": self.username,
            "domain": self.domain,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "arch": self.arch,
            "privileges": list(self.privileges),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "pid": self.pid,
            "notes": self.notes,
        }


# =============================================================================
# SessionBase (abstract)
# =============================================================================

class SessionBase(ABC):
    """Abstract base class for all session types.

    Every concrete session must implement the core lifecycle methods:
    connect, execute, upload, download, is_alive, close.
    """

    def __init__(
        self,
        session_id: int,
        session_type: SessionType,
        target: str,
        port: int,
        username: str,
        password: str = "",
        hashes: str = "",
        domain: str = "",
        **kwargs: Any,
    ) -> None:
        self._info = SessionInfo(
            id=session_id,
            session_type=session_type,
            target=target,
            port=port,
            username=username,
            domain=domain,
        )
        self.password: str = password
        self.hashes: str = hashes
        self.kwargs: Dict[str, Any] = kwargs

    @property
    def info(self) -> SessionInfo:
        """Return the session metadata."""
        return self._info

    # -- lifecycle ------------------------------------------------------------

    @abstractmethod
    async def connect(self) -> bool:
        """Establish the session. Returns True on success."""
        ...

    @abstractmethod
    async def execute(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute *command* and return (returncode, stdout, stderr)."""
        ...

    @abstractmethod
    async def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a file from *local_path* to *remote_path*."""
        ...

    @abstractmethod
    async def download(self, remote_path: str, local_path: str) -> bool:
        """Download a file from *remote_path* to *local_path*."""
        ...

    @abstractmethod
    async def is_alive(self) -> bool:
        """Return True if the session is still usable."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Tear down the session and release resources."""
        ...

    # -- helpers --------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize session state for display / JSON export."""
        d = self._info.to_dict()
        d["has_password"] = bool(self.password)
        d["has_hashes"] = bool(self.hashes)
        return d

    def _touch(self) -> None:
        """Update last_active timestamp."""
        self._info.last_active = datetime.now()

    @staticmethod
    def _make_env() -> Dict[str, str]:
        """Return a subprocess environment with the extended PATH."""
        env = os.environ.copy()
        env["PATH"] = EXTENDED_PATH
        return env

    @staticmethod
    async def _run_subprocess(
        cmd: List[str],
        timeout: int = 60,
        stdin_data: Optional[bytes] = None,
    ) -> Tuple[int, str, str]:
        """Run a command via asyncio subprocess and return (rc, stdout, stderr).

        Args:
            cmd: The command and its arguments.
            timeout: Maximum seconds to wait.
            stdin_data: Optional bytes to feed to stdin.

        Returns:
            Tuple of (return_code, stdout_text, stderr_text).
        """
        env = SessionBase._make_env()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
                env=env,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_data),
                timeout=timeout,
            )
            return (
                proc.returncode or 0,
                stdout_bytes.decode("utf-8", errors="replace"),
                stderr_bytes.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()  # type: ignore[union-attr]
            except ProcessLookupError:
                pass
            return (-1, "", "Command timed out")
        except FileNotFoundError as exc:
            return (-1, "", f"Command not found: {exc}")
        except Exception as exc:
            return (-1, "", f"Subprocess error: {exc}")


# =============================================================================
# ImpacketSession
# =============================================================================

class ImpacketSession(SessionBase):
    """Session backed by Impacket CLI tools (psexec, wmiexec, smbexec, dcomexec, atexec).

    Each ``execute()`` call spawns a new subprocess because the Impacket CLI tools
    do not maintain a persistent connection in non-interactive mode.
    """

    def __init__(self, session_id: int, session_type: SessionType, target: str,
                 port: int, username: str, password: str = "", hashes: str = "",
                 domain: str = "", **kwargs: Any) -> None:
        super().__init__(session_id, session_type, target, port, username,
                         password, hashes, domain, **kwargs)
        if session_type not in _IMPACKET_TYPES:
            raise ValueError(f"ImpacketSession does not support {session_type}")
        self._tool: str = _IMPACKET_TOOL_MAP[session_type]

    # -- credential string ----------------------------------------------------

    def _build_target_string(self) -> str:
        """Build the ``domain/user:pass@host`` or ``domain/user@host -hashes`` string."""
        parts: List[str] = []
        if self._info.domain:
            parts.append(shlex.quote(f"{self._info.domain}/"))
        else:
            parts.append("")
        parts_str = parts[0]

        user = shlex.quote(self._info.username)
        target = shlex.quote(self._info.target)

        if self.password:
            cred = f"{parts_str}{user}:{shlex.quote(self.password)}@{target}"
        else:
            cred = f"{parts_str}{user}@{target}"
        return cred

    def _build_base_cmd(self) -> List[str]:
        """Build the base command list for the impacket tool."""
        cmd: List[str] = [self._tool]

        # Build the target specification: domain/user:pass@host
        if self._info.domain:
            domain_prefix = f"{self._info.domain}/"
        else:
            domain_prefix = ""

        if self.password:
            target_spec = f"{domain_prefix}{self._info.username}:{self.password}@{self._info.target}"
        else:
            target_spec = f"{domain_prefix}{self._info.username}@{self._info.target}"

        cmd.append(target_spec)

        # Add hash authentication if provided
        if self.hashes:
            cmd.extend(["-hashes", self.hashes])

        # Add port if non-default
        if self._info.port != 445 and self._info.session_type != SessionType.ATEXEC:
            cmd.extend(["-port", str(self._info.port)])

        # DCOM-specific: object name
        if self._info.session_type == SessionType.DCOMEXEC:
            obj = self.kwargs.get("object_name", "MMC20")
            cmd.extend(["-object", obj])

        return cmd

    # -- lifecycle ------------------------------------------------------------

    async def connect(self) -> bool:
        """Validate connectivity by running a test command (whoami)."""
        self._info.status = SessionStatus.CONNECTING
        try:
            rc, stdout, stderr = await self.execute("whoami", timeout=30)
            if rc == 0 and stdout.strip():
                self._info.status = SessionStatus.ACTIVE
                # Try to extract hostname/user from whoami output
                whoami = stdout.strip().splitlines()[-1].strip()
                if "\\" in whoami:
                    parts = whoami.split("\\", 1)
                    self._info.hostname = parts[0]
                self._info.os_info = "Windows"
                return True
            # Some impacket tools return output even on rc != 0
            if stdout.strip():
                self._info.status = SessionStatus.ACTIVE
                return True
            self._info.status = SessionStatus.DEAD
            logger.warning("connect failed: rc=%d stderr=%s", rc, stderr.strip())
            return False
        except Exception as exc:
            self._info.status = SessionStatus.DEAD
            logger.error("connect exception: %s", exc)
            return False

    async def execute(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute *command* on the remote host via the impacket tool.

        Args:
            command: The Windows command to run.
            timeout: Maximum seconds to wait for the command.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        cmd = self._build_base_cmd()
        cmd.append(command)

        self._touch()
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
        self._touch()

        if rc != 0 and ("connection refused" in stderr.lower()
                        or "error" in stderr.lower()
                        or "timed out" in stderr.lower()):
            self._info.status = SessionStatus.DEAD

        return rc, stdout, stderr

    async def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a file using impacket-smbclient.

        Falls back to a ``put`` command through smbclient.py.
        """
        if not os.path.isfile(local_path):
            logger.error("upload: local file does not exist: %s", local_path)
            return False

        # Use smbclient.py to upload
        cmd: List[str] = ["smbclient.py"]
        if self._info.domain:
            target_spec = f"{self._info.domain}/{self._info.username}:{self.password}@{self._info.target}"
        else:
            target_spec = f"{self._info.username}:{self.password}@{self._info.target}"

        cmd.append(target_spec)
        if self.hashes:
            cmd.extend(["-hashes", self.hashes])

        # Build the put command — smbclient.py expects interactive input
        put_cmd = f"put {shlex.quote(local_path)} {shlex.quote(remote_path)}\nexit\n"
        rc, stdout, stderr = await self._run_subprocess(
            cmd, timeout=120, stdin_data=put_cmd.encode()
        )
        self._touch()
        return rc == 0

    async def download(self, remote_path: str, local_path: str) -> bool:
        """Download a file using impacket-smbclient."""
        cmd: List[str] = ["smbclient.py"]
        if self._info.domain:
            target_spec = f"{self._info.domain}/{self._info.username}:{self.password}@{self._info.target}"
        else:
            target_spec = f"{self._info.username}:{self.password}@{self._info.target}"

        cmd.append(target_spec)
        if self.hashes:
            cmd.extend(["-hashes", self.hashes])

        get_cmd = f"get {shlex.quote(remote_path)} {shlex.quote(local_path)}\nexit\n"
        rc, stdout, stderr = await self._run_subprocess(
            cmd, timeout=120, stdin_data=get_cmd.encode()
        )
        self._touch()
        return rc == 0 and os.path.isfile(local_path)

    async def is_alive(self) -> bool:
        """Check if we can still execute commands on the target."""
        try:
            rc, stdout, stderr = await self.execute("echo uwu_ping", timeout=15)
            alive = rc == 0 or bool(stdout.strip())
            if alive:
                self._info.status = SessionStatus.ACTIVE
            else:
                self._info.status = SessionStatus.DEAD
            return alive
        except Exception:
            self._info.status = SessionStatus.DEAD
            return False

    async def close(self) -> None:
        """Mark the session as dead (no persistent connection to tear down)."""
        self._info.status = SessionStatus.DEAD


# =============================================================================
# WinRMSession
# =============================================================================

class WinRMSession(SessionBase):
    """Session over WinRM using the ``pywinrm`` library.

    Falls back to wrapping ``evil-winrm`` via subprocess if pywinrm is not
    installed.
    """

    def __init__(self, session_id: int, session_type: SessionType, target: str,
                 port: int, username: str, password: str = "", hashes: str = "",
                 domain: str = "", **kwargs: Any) -> None:
        super().__init__(session_id, session_type, target, port, username,
                         password, hashes, domain, **kwargs)
        self._winrm_session: Any = None
        self._use_ssl: bool = kwargs.get("ssl", port == 5986)
        self._use_pywinrm: bool = False

    async def connect(self) -> bool:
        """Establish a WinRM connection.

        Tries pywinrm first; if unavailable, falls back to evil-winrm subprocess.
        """
        self._info.status = SessionStatus.CONNECTING

        # Attempt pywinrm import
        try:
            import winrm  # type: ignore[import-untyped]
            self._use_pywinrm = True
        except ImportError:
            self._use_pywinrm = False

        if self._use_pywinrm:
            return await self._connect_pywinrm()
        return await self._connect_evil_winrm()

    async def _connect_pywinrm(self) -> bool:
        """Connect using the pywinrm library."""
        try:
            import winrm  # type: ignore[import-untyped]

            scheme = "https" if self._use_ssl else "http"
            endpoint = f"{scheme}://{self._info.target}:{self._info.port}/wsman"

            transport = "ntlm"
            winrm_user = self._info.username
            if self._info.domain:
                winrm_user = f"{self._info.domain}\\{self._info.username}"

            # Hash-based auth requires kerberos or specific transport
            winrm_kwargs: Dict[str, Any] = {
                "transport": transport,
            }

            if self._use_ssl:
                winrm_kwargs["server_cert_validation"] = "ignore"

            self._winrm_session = winrm.Session(
                endpoint,
                auth=(winrm_user, self.password),
                **winrm_kwargs,
            )

            # Test connection
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self._winrm_session.run_cmd, "whoami"
            )
            if result.status_code == 0:
                self._info.status = SessionStatus.ACTIVE
                whoami = result.std_out.decode("utf-8", errors="replace").strip()
                if "\\" in whoami:
                    self._info.hostname = whoami.split("\\")[0]
                self._info.os_info = "Windows"
                return True
            self._info.status = SessionStatus.DEAD
            return False
        except Exception as exc:
            logger.error("pywinrm connect failed: %s", exc)
            self._info.status = SessionStatus.DEAD
            return False

    async def _connect_evil_winrm(self) -> bool:
        """Connect using evil-winrm subprocess as fallback."""
        try:
            rc, stdout, stderr = await self._evil_winrm_exec("whoami", timeout=30)
            if rc == 0 and stdout.strip():
                self._info.status = SessionStatus.ACTIVE
                self._info.os_info = "Windows"
                return True
            self._info.status = SessionStatus.DEAD
            return False
        except Exception as exc:
            logger.error("evil-winrm connect failed: %s", exc)
            self._info.status = SessionStatus.DEAD
            return False

    async def _evil_winrm_exec(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute a command through evil-winrm."""
        cmd: List[str] = [
            "evil-winrm",
            "-i", self._info.target,
            "-u", self._info.username,
            "-P", str(self._info.port),
        ]

        if self.password:
            cmd.extend(["-p", self.password])
        elif self.hashes:
            # evil-winrm uses -H for NT hash
            nt_hash = self.hashes.split(":")[-1] if ":" in self.hashes else self.hashes
            cmd.extend(["-H", nt_hash])

        if self._use_ssl:
            cmd.append("-S")

        # evil-winrm expects commands via -e (exec) or interactive mode
        # We use -c for single command execution
        cmd.extend(["-c", command])

        return await self._run_subprocess(cmd, timeout=timeout)

    async def execute(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute a command via WinRM.

        Args:
            command: The command to run. Prefix with ``ps:`` for PowerShell.
            timeout: Maximum seconds to wait.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        self._touch()

        if self._use_pywinrm and self._winrm_session is not None:
            return await self._execute_pywinrm(command, timeout)
        return await self._evil_winrm_exec(command, timeout)

    async def _execute_pywinrm(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute through pywinrm Session object."""
        try:
            loop = asyncio.get_event_loop()

            use_ps = command.startswith("ps:")
            if use_ps:
                command = command[3:].strip()
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, self._winrm_session.run_ps, command
                    ),
                    timeout=timeout,
                )
            else:
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, self._winrm_session.run_cmd, command
                    ),
                    timeout=timeout,
                )

            stdout = result.std_out.decode("utf-8", errors="replace")
            stderr = result.std_err.decode("utf-8", errors="replace")
            self._touch()
            return result.status_code, stdout, stderr

        except asyncio.TimeoutError:
            return -1, "", "Command timed out"
        except Exception as exc:
            self._info.status = SessionStatus.DEAD
            return -1, "", f"WinRM error: {exc}"

    async def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a file via WinRM (evil-winrm upload or pywinrm copy)."""
        if not os.path.isfile(local_path):
            return False

        if self._use_pywinrm and self._winrm_session is not None:
            # pywinrm does not have a native file upload; use PowerShell base64
            try:
                import base64
                with open(local_path, "rb") as f:
                    data = base64.b64encode(f.read()).decode()

                # Split into chunks for large files (max ~8000 chars per command)
                chunk_size = 8000
                chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

                # Write first chunk (overwrite)
                ps_cmd = (
                    f"[IO.File]::WriteAllBytes("
                    f"'{remote_path}', "
                    f"[Convert]::FromBase64String('{chunks[0]}'))"
                )
                rc, _, stderr = await self._execute_pywinrm(f"ps:{ps_cmd}", timeout=120)
                if rc != 0:
                    return False

                # Append remaining chunks
                for chunk in chunks[1:]:
                    ps_cmd = (
                        f"$bytes = [Convert]::FromBase64String('{chunk}'); "
                        f"$stream = [IO.File]::Open('{remote_path}', 'Append'); "
                        f"$stream.Write($bytes, 0, $bytes.Length); "
                        f"$stream.Close()"
                    )
                    rc, _, _ = await self._execute_pywinrm(f"ps:{ps_cmd}", timeout=120)
                    if rc != 0:
                        return False

                self._touch()
                return True
            except Exception as exc:
                logger.error("pywinrm upload failed: %s", exc)
                return False

        # evil-winrm fallback
        cmd: List[str] = [
            "evil-winrm",
            "-i", self._info.target,
            "-u", self._info.username,
            "-P", str(self._info.port),
        ]
        if self.password:
            cmd.extend(["-p", self.password])
        elif self.hashes:
            nt_hash = self.hashes.split(":")[-1] if ":" in self.hashes else self.hashes
            cmd.extend(["-H", nt_hash])
        if self._use_ssl:
            cmd.append("-S")

        cmd.extend(["-c", f"upload {shlex.quote(local_path)} {shlex.quote(remote_path)}"])
        rc, _, _ = await self._run_subprocess(cmd, timeout=120)
        self._touch()
        return rc == 0

    async def download(self, remote_path: str, local_path: str) -> bool:
        """Download a file via WinRM."""
        if self._use_pywinrm and self._winrm_session is not None:
            try:
                ps_cmd = (
                    f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{remote_path}'))"
                )
                rc, stdout, stderr = await self._execute_pywinrm(f"ps:{ps_cmd}", timeout=120)
                if rc != 0:
                    return False
                import base64
                data = base64.b64decode(stdout.strip())
                os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
                with open(local_path, "wb") as f:
                    f.write(data)
                self._touch()
                return True
            except Exception as exc:
                logger.error("pywinrm download failed: %s", exc)
                return False

        # evil-winrm fallback
        cmd: List[str] = [
            "evil-winrm",
            "-i", self._info.target,
            "-u", self._info.username,
            "-P", str(self._info.port),
        ]
        if self.password:
            cmd.extend(["-p", self.password])
        elif self.hashes:
            nt_hash = self.hashes.split(":")[-1] if ":" in self.hashes else self.hashes
            cmd.extend(["-H", nt_hash])
        if self._use_ssl:
            cmd.append("-S")

        cmd.extend(["-c", f"download {shlex.quote(remote_path)} {shlex.quote(local_path)}"])
        rc, _, _ = await self._run_subprocess(cmd, timeout=120)
        self._touch()
        return rc == 0 and os.path.isfile(local_path)

    async def is_alive(self) -> bool:
        """Check if WinRM is still reachable."""
        try:
            rc, stdout, _ = await self.execute("echo uwu_ping", timeout=15)
            alive = rc == 0 or "uwu_ping" in stdout
            self._info.status = SessionStatus.ACTIVE if alive else SessionStatus.DEAD
            return alive
        except Exception:
            self._info.status = SessionStatus.DEAD
            return False

    async def close(self) -> None:
        """Close the WinRM session."""
        self._winrm_session = None
        self._info.status = SessionStatus.DEAD


# =============================================================================
# SSHSession
# =============================================================================

class SSHSession(SessionBase):
    """Session over SSH using asyncio subprocess wrapping of the ``ssh`` command.

    Supports password auth (via ``sshpass``), key-based auth, and custom SSH options.
    """

    def __init__(self, session_id: int, session_type: SessionType, target: str,
                 port: int, username: str, password: str = "", hashes: str = "",
                 domain: str = "", **kwargs: Any) -> None:
        super().__init__(session_id, session_type, target, port, username,
                         password, hashes, domain, **kwargs)
        self._key_file: Optional[str] = kwargs.get("key_file")
        self._ssh_options: List[str] = kwargs.get("ssh_options", [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
        ])

    def _build_ssh_cmd(self, command: str) -> List[str]:
        """Build the full ssh command line."""
        cmd: List[str] = []

        # Use sshpass for password authentication
        if self.password and not self._key_file:
            cmd.extend(["sshpass", "-p", self.password])

        cmd.append("ssh")
        cmd.extend(self._ssh_options)

        if self._key_file:
            cmd.extend(["-i", self._key_file])

        cmd.extend(["-p", str(self._info.port)])
        cmd.append(f"{self._info.username}@{self._info.target}")
        cmd.append(command)

        return cmd

    async def connect(self) -> bool:
        """Verify SSH connectivity with a test command."""
        self._info.status = SessionStatus.CONNECTING
        try:
            rc, stdout, stderr = await self.execute("id", timeout=30)
            if rc == 0 and stdout.strip():
                self._info.status = SessionStatus.ACTIVE
                # Parse id output for user info
                id_output = stdout.strip()
                if "uid=" in id_output:
                    self._info.os_info = "Linux/Unix"
                return True
            self._info.status = SessionStatus.DEAD
            logger.warning("SSH connect failed: rc=%d stderr=%s", rc, stderr.strip())
            return False
        except Exception as exc:
            self._info.status = SessionStatus.DEAD
            logger.error("SSH connect exception: %s", exc)
            return False

    async def execute(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute a command over SSH.

        Args:
            command: The command to run on the remote host.
            timeout: Maximum seconds to wait.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        cmd = self._build_ssh_cmd(command)
        self._touch()
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
        self._touch()

        if rc != 0 and ("connection refused" in stderr.lower()
                        or "no route to host" in stderr.lower()
                        or "connection timed out" in stderr.lower()):
            self._info.status = SessionStatus.DEAD

        return rc, stdout, stderr

    async def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a file using ``scp``."""
        if not os.path.isfile(local_path):
            return False

        cmd: List[str] = []
        if self.password and not self._key_file:
            cmd.extend(["sshpass", "-p", self.password])

        cmd.extend(["scp"])
        cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])

        if self._key_file:
            cmd.extend(["-i", self._key_file])

        cmd.extend(["-P", str(self._info.port)])
        cmd.append(local_path)
        cmd.append(f"{self._info.username}@{self._info.target}:{remote_path}")

        rc, _, stderr = await self._run_subprocess(cmd, timeout=300)
        self._touch()
        if rc != 0:
            logger.error("scp upload failed: %s", stderr.strip())
        return rc == 0

    async def download(self, remote_path: str, local_path: str) -> bool:
        """Download a file using ``scp``."""
        cmd: List[str] = []
        if self.password and not self._key_file:
            cmd.extend(["sshpass", "-p", self.password])

        cmd.extend(["scp"])
        cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"])

        if self._key_file:
            cmd.extend(["-i", self._key_file])

        cmd.extend(["-P", str(self._info.port)])
        cmd.append(f"{self._info.username}@{self._info.target}:{remote_path}")
        cmd.append(local_path)

        rc, _, stderr = await self._run_subprocess(cmd, timeout=300)
        self._touch()
        if rc != 0:
            logger.error("scp download failed: %s", stderr.strip())
        return rc == 0 and os.path.isfile(local_path)

    async def is_alive(self) -> bool:
        """Check if SSH is still reachable."""
        try:
            rc, stdout, _ = await self.execute("echo uwu_ping", timeout=15)
            alive = rc == 0 and "uwu_ping" in stdout
            self._info.status = SessionStatus.ACTIVE if alive else SessionStatus.DEAD
            return alive
        except Exception:
            self._info.status = SessionStatus.DEAD
            return False

    async def close(self) -> None:
        """Mark the SSH session as dead."""
        self._info.status = SessionStatus.DEAD


# =============================================================================
# MSSQLSession
# =============================================================================

class MSSQLSession(SessionBase):
    """Session wrapping ``impacket-mssqlclient`` for SQL command execution.

    Each ``execute()`` call spawns ``mssqlclient.py`` with the ``-Q`` flag
    to run a single SQL query.
    """

    def __init__(self, session_id: int, session_type: SessionType, target: str,
                 port: int, username: str, password: str = "", hashes: str = "",
                 domain: str = "", **kwargs: Any) -> None:
        super().__init__(session_id, session_type, target, port, username,
                         password, hashes, domain, **kwargs)
        self._windows_auth: bool = kwargs.get("windows_auth", True)

    def _build_base_cmd(self) -> List[str]:
        """Build the mssqlclient.py base command."""
        cmd: List[str] = ["mssqlclient.py"]

        if self._info.domain:
            target_spec = f"{self._info.domain}/{self._info.username}"
        else:
            target_spec = self._info.username

        if self.password:
            target_spec += f":{self.password}"

        target_spec += f"@{self._info.target}"
        cmd.append(target_spec)

        if self.hashes:
            cmd.extend(["-hashes", self.hashes])

        if self._windows_auth:
            cmd.append("-windows-auth")

        if self._info.port != 1433:
            cmd.extend(["-port", str(self._info.port)])

        return cmd

    async def connect(self) -> bool:
        """Test MSSQL connectivity with a simple query."""
        self._info.status = SessionStatus.CONNECTING
        try:
            rc, stdout, stderr = await self.execute("SELECT @@version", timeout=30)
            if rc == 0 or "Microsoft SQL Server" in stdout:
                self._info.status = SessionStatus.ACTIVE
                self._info.os_info = "Windows (MSSQL)"
                # Try to extract version
                for line in stdout.splitlines():
                    if "Microsoft SQL Server" in line:
                        self._info.notes = line.strip()[:80]
                        break
                return True
            self._info.status = SessionStatus.DEAD
            logger.warning("MSSQL connect failed: rc=%d stderr=%s", rc, stderr.strip())
            return False
        except Exception as exc:
            self._info.status = SessionStatus.DEAD
            logger.error("MSSQL connect exception: %s", exc)
            return False

    async def execute(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute a SQL query via mssqlclient.py.

        Args:
            command: SQL query string. Prefix with ``xp:`` to run via ``xp_cmdshell``.
            timeout: Maximum seconds to wait.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        cmd = self._build_base_cmd()

        if command.startswith("xp:"):
            # Execute OS command via xp_cmdshell
            os_cmd = command[3:].strip()
            sql = f"EXEC xp_cmdshell '{os_cmd}'"
            cmd.extend(["-Q", sql])
        else:
            cmd.extend(["-Q", command])

        self._touch()
        rc, stdout, stderr = await self._run_subprocess(cmd, timeout=timeout)
        self._touch()
        return rc, stdout, stderr

    async def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a file via MSSQL xp_cmdshell + certutil or PowerShell.

        This starts an HTTP server, uses xp_cmdshell to download. Not
        implemented in this base layer -- returns False.
        """
        logger.warning("MSSQL upload not directly supported; use xp_cmdshell manually")
        return False

    async def download(self, remote_path: str, local_path: str) -> bool:
        """Download not directly supported via MSSQL session."""
        logger.warning("MSSQL download not directly supported; use xp_cmdshell manually")
        return False

    async def is_alive(self) -> bool:
        """Check MSSQL connectivity."""
        try:
            rc, stdout, _ = await self.execute("SELECT 1 AS uwu_ping", timeout=15)
            alive = "uwu_ping" in stdout or rc == 0
            self._info.status = SessionStatus.ACTIVE if alive else SessionStatus.DEAD
            return alive
        except Exception:
            self._info.status = SessionStatus.DEAD
            return False

    async def close(self) -> None:
        """Mark the MSSQL session as dead."""
        self._info.status = SessionStatus.DEAD


# =============================================================================
# ReverseShellSession
# =============================================================================

class ReverseShellSession(SessionBase):
    """Session wrapping a raw TCP socket for reverse/bind shell connections.

    The socket is expected to be already connected (e.g., from a listener).
    Commands are sent as text + newline, and output is read with a timeout.
    """

    def __init__(self, session_id: int, session_type: SessionType, target: str,
                 port: int, username: str, password: str = "", hashes: str = "",
                 domain: str = "", **kwargs: Any) -> None:
        super().__init__(session_id, session_type, target, port, username,
                         password, hashes, domain, **kwargs)
        self._sock: Optional[socket_module.socket] = kwargs.get("sock")
        self._read_timeout: float = kwargs.get("read_timeout", 5.0)
        self._encoding: str = kwargs.get("encoding", "utf-8")

    async def connect(self) -> bool:
        """Validate the socket connection.

        If ``sock`` was provided in kwargs, verifies it. For bind shells,
        connects to the target.
        """
        self._info.status = SessionStatus.CONNECTING

        if self._sock is not None:
            # Socket already connected (reverse shell from listener)
            try:
                self._sock.setblocking(False)
                self._info.status = SessionStatus.ACTIVE
                return True
            except Exception as exc:
                logger.error("Socket validation failed: %s", exc)
                self._info.status = SessionStatus.DEAD
                return False

        # Bind shell: connect to target
        if self._info.session_type == SessionType.BIND_SHELL:
            try:
                self._sock = socket_module.socket(
                    socket_module.AF_INET, socket_module.SOCK_STREAM
                )
                self._sock.settimeout(10)
                self._sock.connect((self._info.target, self._info.port))
                self._sock.setblocking(False)
                self._info.status = SessionStatus.ACTIVE
                return True
            except Exception as exc:
                logger.error("Bind shell connect failed: %s", exc)
                self._info.status = SessionStatus.DEAD
                if self._sock:
                    self._sock.close()
                    self._sock = None
                return False

        self._info.status = SessionStatus.DEAD
        return False

    async def execute(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Send a command and read the response from the socket.

        Args:
            command: Shell command to send (newline appended automatically).
            timeout: Maximum seconds to wait for output.

        Returns:
            Tuple of (0, output, "") on success, (-1, "", error) on failure.
        """
        if not self._sock:
            return -1, "", "No socket connection"

        try:
            # Send command
            payload = (command.rstrip("\n") + "\n").encode(self._encoding)
            loop = asyncio.get_event_loop()
            self._sock.setblocking(True)
            self._sock.settimeout(5)
            await loop.run_in_executor(None, self._sock.sendall, payload)

            # Read response with timeout
            self._sock.settimeout(self._read_timeout)
            output_chunks: List[bytes] = []
            deadline = time.monotonic() + min(timeout, self._read_timeout * 3)

            while time.monotonic() < deadline:
                try:
                    chunk = await asyncio.wait_for(
                        loop.run_in_executor(None, self._sock.recv, 4096),
                        timeout=self._read_timeout,
                    )
                    if not chunk:
                        # Connection closed
                        self._info.status = SessionStatus.DEAD
                        break
                    output_chunks.append(chunk)
                    # If we received data and there's a short pause, we're done
                    if len(chunk) < 4096:
                        break
                except (asyncio.TimeoutError, socket_module.timeout):
                    break
                except Exception:
                    break

            output = b"".join(output_chunks).decode(self._encoding, errors="replace")
            self._touch()
            return 0, output, ""

        except Exception as exc:
            self._info.status = SessionStatus.DEAD
            return -1, "", f"Socket error: {exc}"
        finally:
            if self._sock:
                self._sock.setblocking(False)

    async def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a file via base64 encoding through the shell.

        Encodes the file as base64, sends a decode command to the remote shell.
        """
        if not self._sock or not os.path.isfile(local_path):
            return False

        try:
            import base64
            with open(local_path, "rb") as f:
                data = base64.b64encode(f.read()).decode()

            # Try to detect if it's a Linux or Windows shell
            rc, stdout, _ = await self.execute("uname 2>/dev/null || echo WINDOWS", timeout=10)

            if "WINDOWS" in stdout.upper() or "not recognized" in stdout.lower():
                # Windows: use certutil
                cmd = (
                    f"echo {data} > %TEMP%\\b64.txt && "
                    f"certutil -decode %TEMP%\\b64.txt {shlex.quote(remote_path)} && "
                    f"del %TEMP%\\b64.txt"
                )
            else:
                # Linux: use base64 -d
                cmd = f"echo '{data}' | base64 -d > {shlex.quote(remote_path)}"

            rc, _, stderr = await self.execute(cmd, timeout=60)
            return rc == 0
        except Exception as exc:
            logger.error("Shell upload failed: %s", exc)
            return False

    async def download(self, remote_path: str, local_path: str) -> bool:
        """Download a file via base64 encoding through the shell."""
        if not self._sock:
            return False

        try:
            import base64

            # Try Linux first
            rc, stdout, _ = await self.execute(
                f"base64 {shlex.quote(remote_path)} 2>/dev/null || "
                f"certutil -encode {shlex.quote(remote_path)} CON",
                timeout=60,
            )

            if rc != 0 or not stdout.strip():
                return False

            # Clean up certutil markers if present
            clean_data = stdout.strip()
            clean_data = clean_data.replace("-----BEGIN CERTIFICATE-----", "")
            clean_data = clean_data.replace("-----END CERTIFICATE-----", "")
            clean_data = clean_data.strip()

            data = base64.b64decode(clean_data)
            os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(data)
            return True
        except Exception as exc:
            logger.error("Shell download failed: %s", exc)
            return False

    async def is_alive(self) -> bool:
        """Check if the socket is still connected."""
        if not self._sock:
            self._info.status = SessionStatus.DEAD
            return False

        try:
            rc, stdout, _ = await self.execute("echo uwu_ping", timeout=10)
            alive = "uwu_ping" in stdout
            self._info.status = SessionStatus.ACTIVE if alive else SessionStatus.DEAD
            return alive
        except Exception:
            self._info.status = SessionStatus.DEAD
            return False

    async def close(self) -> None:
        """Close the socket connection."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._info.status = SessionStatus.DEAD


# =============================================================================
# Session class mapping
# =============================================================================

_SESSION_CLASS_MAP: Dict[SessionType, Type[SessionBase]] = {
    SessionType.PSEXEC: ImpacketSession,
    SessionType.WMIEXEC: ImpacketSession,
    SessionType.SMBEXEC: ImpacketSession,
    SessionType.DCOMEXEC: ImpacketSession,
    SessionType.ATEXEC: ImpacketSession,
    SessionType.WINRM: WinRMSession,
    SessionType.SSH: SSHSession,
    SessionType.MSSQL: MSSQLSession,
    SessionType.REVERSE_SHELL: ReverseShellSession,
    SessionType.BIND_SHELL: ReverseShellSession,
}

# Default ports per session type
_DEFAULT_PORTS: Dict[SessionType, int] = {
    SessionType.PSEXEC: 445,
    SessionType.WMIEXEC: 445,
    SessionType.SMBEXEC: 445,
    SessionType.DCOMEXEC: 135,
    SessionType.ATEXEC: 445,
    SessionType.WINRM: 5985,
    SessionType.SSH: 22,
    SessionType.MSSQL: 1433,
    SessionType.REVERSE_SHELL: 0,
    SessionType.BIND_SHELL: 4444,
    SessionType.LDAP: 389,
    SessionType.C2_BEACON: 0,
}


# =============================================================================
# SessionManager (singleton)
# =============================================================================

class SessionManager:
    """Singleton manager for all active sessions.

    Provides a central registry for creating, tracking, and interacting with
    sessions across the framework. Thread-safe via asyncio.Lock.

    Usage::

        mgr = SessionManager.get_instance()
        session = await mgr.create_session(SessionType.WMIEXEC, "10.10.10.1", 445,
                                           username="admin", password="P@ss", domain="CORP")
        result = await mgr.execute(session.info.id, "whoami")
    """

    _instance: Optional["SessionManager"] = None

    def __init__(self) -> None:
        self._sessions: Dict[int, SessionBase] = {}
        self._next_id: int = 1
        self._lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> "SessionManager":
        """Return the singleton SessionManager instance.

        Creates the instance on first call.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (primarily for testing)."""
        cls._instance = None

    async def create_session(
        self,
        session_type: SessionType,
        target: str,
        port: int = 0,
        username: str = "",
        password: str = "",
        hashes: str = "",
        domain: str = "",
        **kwargs: Any,
    ) -> SessionBase:
        """Create and register a new session.

        Instantiates the appropriate session class, calls ``connect()``, and
        registers the session in the internal registry.

        Args:
            session_type: The transport type for the session.
            target: Target IP address or hostname.
            port: Target port (0 = use default for session type).
            username: Username for authentication.
            password: Password for authentication.
            hashes: NTLM hash in ``LM:NT`` format.
            domain: Active Directory domain.
            **kwargs: Additional arguments passed to the session constructor.

        Returns:
            The created SessionBase instance.

        Raises:
            ValueError: If the session type is not supported.
            ConnectionError: If the session fails to connect.
        """
        if session_type not in _SESSION_CLASS_MAP:
            raise ValueError(
                f"Unsupported session type: {session_type.value}. "
                f"Supported types: {', '.join(t.value for t in _SESSION_CLASS_MAP)}"
            )

        # Use default port if not specified
        if port == 0:
            port = _DEFAULT_PORTS.get(session_type, 0)

        async with self._lock:
            session_id = self._next_id
            self._next_id += 1

        session_cls = _SESSION_CLASS_MAP[session_type]
        session = session_cls(
            session_id=session_id,
            session_type=session_type,
            target=target,
            port=port,
            username=username,
            password=password,
            hashes=hashes,
            domain=domain,
            **kwargs,
        )

        connected = await session.connect()
        if not connected:
            raise ConnectionError(
                f"Failed to establish {session_type.value} session to "
                f"{target}:{port} as {domain}\\{username}" if domain
                else f"Failed to establish {session_type.value} session to "
                     f"{target}:{port} as {username}"
            )

        async with self._lock:
            self._sessions[session_id] = session

        logger.info(
            "Session %d created: %s -> %s:%d as %s\\%s",
            session_id, session_type.value, target, port,
            domain or ".", username,
        )
        return session

    def get(self, session_id: int) -> Optional[SessionBase]:
        """Retrieve a session by its ID.

        Args:
            session_id: The unique session identifier.

        Returns:
            The session, or None if not found.
        """
        return self._sessions.get(session_id)

    def list_all(self) -> List[dict]:
        """Return a list of dictionaries describing all sessions.

        Returns:
            List of session info dicts.
        """
        return [s.to_dict() for s in self._sessions.values()]

    async def execute(
        self,
        session_id: int,
        command: str,
        timeout: int = 60,
    ) -> dict:
        """Execute a command on a session.

        Args:
            session_id: The session to use.
            command: The command to execute.
            timeout: Maximum seconds to wait.

        Returns:
            Dict with keys: status, returncode, stdout, stderr.
        """
        session = self.get(session_id)
        if not session:
            return {
                "status": "error",
                "returncode": -1,
                "stdout": "",
                "stderr": f"Session {session_id} not found",
            }

        if session.info.status == SessionStatus.DEAD:
            return {
                "status": "error",
                "returncode": -1,
                "stdout": "",
                "stderr": f"Session {session_id} is dead",
            }

        try:
            rc, stdout, stderr = await session.execute(command, timeout=timeout)
            return {
                "status": "success" if rc == 0 else "error",
                "returncode": rc,
                "stdout": stdout,
                "stderr": stderr,
            }
        except Exception as exc:
            return {
                "status": "error",
                "returncode": -1,
                "stdout": "",
                "stderr": str(exc),
            }

    async def upload(self, session_id: int, local: str, remote: str) -> bool:
        """Upload a file through a session.

        Args:
            session_id: The session to use.
            local: Local file path.
            remote: Remote file path.

        Returns:
            True on success.
        """
        session = self.get(session_id)
        if not session:
            logger.error("Upload failed: session %d not found", session_id)
            return False
        if session.info.status == SessionStatus.DEAD:
            logger.error("Upload failed: session %d is dead", session_id)
            return False

        try:
            return await session.upload(local, remote)
        except Exception as exc:
            logger.error("Upload failed on session %d: %s", session_id, exc)
            return False

    async def download(self, session_id: int, remote: str, local: str) -> bool:
        """Download a file through a session.

        Args:
            session_id: The session to use.
            remote: Remote file path.
            local: Local file path.

        Returns:
            True on success.
        """
        session = self.get(session_id)
        if not session:
            logger.error("Download failed: session %d not found", session_id)
            return False
        if session.info.status == SessionStatus.DEAD:
            logger.error("Download failed: session %d is dead", session_id)
            return False

        try:
            return await session.download(remote, local)
        except Exception as exc:
            logger.error("Download failed on session %d: %s", session_id, exc)
            return False

    async def close(self, session_id: int) -> bool:
        """Close and deregister a session.

        Args:
            session_id: The session to close.

        Returns:
            True if the session was found and closed.
        """
        async with self._lock:
            session = self._sessions.pop(session_id, None)

        if not session:
            return False

        try:
            await session.close()
        except Exception as exc:
            logger.error("Error closing session %d: %s", session_id, exc)
        return True

    async def close_all(self) -> int:
        """Close all sessions.

        Returns:
            The number of sessions that were closed.
        """
        async with self._lock:
            sessions = list(self._sessions.values())
            session_ids = list(self._sessions.keys())
            self._sessions.clear()

        count = 0
        for session in sessions:
            try:
                await session.close()
                count += 1
            except Exception as exc:
                logger.error("Error closing session %d: %s", session.info.id, exc)
                count += 1  # Still count it as closed

        return count

    def get_by_target(self, target: str) -> List[SessionBase]:
        """Return all sessions targeting a specific host.

        Args:
            target: IP address or hostname to filter by.

        Returns:
            List of matching sessions.
        """
        return [
            s for s in self._sessions.values()
            if s.info.target == target
        ]

    def get_active(self) -> List[SessionBase]:
        """Return all sessions with ACTIVE or IDLE status.

        Returns:
            List of non-dead sessions.
        """
        return [
            s for s in self._sessions.values()
            if s.info.status in (SessionStatus.ACTIVE, SessionStatus.IDLE)
        ]
