"""
Background Job Manager for UwU Toolkit

Manages long-running operations like Responder, ntlmrelayx, listeners,
BloodHound collection, nmap scans -- anything that needs to run in the
background while the operator does other things.

Jobs run as asyncio subprocesses with output captured to both an in-memory
circular buffer (for fast tail) and a persistent log file on disk.

Usage:
    mgr = JobManager.get_instance()
    job = await mgr.create_job("responder", "responder -I eth0 -wFb", container="exegol-merry")
    output = mgr.get_output(job.id, last_n=20)
    await mgr.stop_job(job.id)
"""

import asyncio
import os
import re
import shlex
import signal
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Extended PATH for subprocess environments (Exegol, Kali, etc.)
# ---------------------------------------------------------------------------
EXTENDED_PATH = ":".join([
    "/opt/tools/Certipy/venv/bin",
    "/root/.local/bin",
    os.path.expanduser("~/.local/bin"),
    "/opt/tools/bin",
    "/opt/tools",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
])


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class JobStatus(Enum):
    """Lifecycle states for a background job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class JobInfo:
    """Serialisable snapshot of a job's state (returned to callers / MCP)."""
    id: int
    name: str
    command: str
    status: JobStatus
    pid: Optional[int]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    exit_code: Optional[int]
    output_lines: int       # count of lines captured so far
    error_summary: str      # last error/stderr line if any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_\-.]")


def _sanitize_name(name: str) -> str:
    """Sanitize a job name for safe use in filenames."""
    return _SANITIZE_RE.sub("_", name)[:64]


def _build_subprocess_env() -> dict:
    """Build an environment dict with extended PATH for tool discovery."""
    env = os.environ.copy()
    current = env.get("PATH", "")
    env["PATH"] = EXTENDED_PATH + ":" + current
    return env


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

class Job:
    """
    Represents a single background job backed by an asyncio subprocess.

    Each job streams combined stdout/stderr into:
      - An in-memory circular buffer (``_output_buffer``, capped at
        ``_max_buffer_lines``) for fast tail reads.
      - A persistent log file at ``~/.uwu-toolkit/jobs/{id}_{name}.log``
        so output survives buffer rotation and can be reviewed later.
    """

    def __init__(
        self,
        job_id: int,
        name: str,
        command: str,
        container: Optional[str] = None,
    ) -> None:
        self.id: int = job_id
        self.name: str = name
        self.command: str = command
        self.container: Optional[str] = container  # Exegol container name; None = local

        self.status: JobStatus = JobStatus.PENDING
        self.process: Optional[asyncio.subprocess.Process] = None
        self.pid: Optional[int] = None

        # Output buffering
        self._output_buffer: List[str] = []
        self._max_buffer_lines: int = 10000
        self._total_lines: int = 0
        self._last_error_line: str = ""

        # Persistent log file
        self._output_file: Optional[Path] = None
        self._output_fh = None  # file handle kept open during run

        # Timestamps
        self.created_at: datetime = datetime.now()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.exit_code: Optional[int] = None

        # Internal asyncio task that reads process output
        self._task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> bool:
        """Start the job as an asyncio subprocess.

        If ``container`` is set the command is wrapped with
        ``docker exec <container> bash -l -c '...'``.

        Returns:
            ``True`` if the process started successfully, ``False`` otherwise.
        """
        if self.status != JobStatus.PENDING:
            return False

        # Prepare log file
        jobs_dir = Path.home() / ".uwu-toolkit" / "jobs"
        jobs_dir.mkdir(parents=True, exist_ok=True)
        safe_name = _sanitize_name(self.name)
        self._output_file = jobs_dir / f"{self.id}_{safe_name}.log"

        try:
            self._output_fh = open(self._output_file, "w", buffering=1)  # line-buffered
        except OSError:
            self.status = JobStatus.FAILED
            self._last_error_line = f"Could not open log file: {self._output_file}"
            return False

        # Write header
        self._output_fh.write(
            f"# UwU Toolkit Job {self.id} — {self.name}\n"
            f"# Command: {self.command}\n"
            f"# Container: {self.container or 'local'}\n"
            f"# Started: {datetime.now().isoformat()}\n"
            f"{'#' * 72}\n"
        )
        self._output_fh.flush()

        # Build the actual shell command
        if self.container:
            # Wrap with docker exec, using login shell for pyenv/tool init
            inner = f"export PATH={EXTENDED_PATH}:$PATH && {self.command}"
            shell_cmd = (
                f"docker exec {shlex.quote(self.container)} "
                f"bash -l -c {shlex.quote(inner)}"
            )
        else:
            shell_cmd = self.command

        # Spawn the subprocess
        env = _build_subprocess_env()

        try:
            self.process = await asyncio.create_subprocess_shell(
                shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,  # merge stderr into stdout
                env=env,
            )
            self.pid = self.process.pid
            self.status = JobStatus.RUNNING
            self.started_at = datetime.now()
        except Exception as exc:
            self.status = JobStatus.FAILED
            self._last_error_line = str(exc)
            self._close_log()
            return False

        # Kick off the reader coroutine
        self._task = asyncio.ensure_future(self._reader_task())
        return True

    async def stop(self) -> bool:
        """Stop the job gracefully (SIGTERM, wait 5 s, then SIGKILL).

        Returns:
            ``True`` if the job was stopped, ``False`` if it was not running.
        """
        if self.status != JobStatus.RUNNING or self.process is None:
            return False

        try:
            self.process.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            # Already dead
            pass

        # Give it up to 5 seconds to terminate cleanly
        try:
            await asyncio.wait_for(self.process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            # Force kill
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(self.process.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                pass

        self.exit_code = self.process.returncode
        self.status = JobStatus.STOPPED
        self.completed_at = datetime.now()

        # Let the reader task finish naturally
        if self._task and not self._task.done():
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except asyncio.TimeoutError:
                self._task.cancel()

        self._write_footer()
        self._close_log()
        return True

    # ------------------------------------------------------------------
    # Output reader
    # ------------------------------------------------------------------

    async def _reader_task(self) -> None:
        """Read process output line-by-line into the buffer and log file.

        Runs until the process exits and all output has been consumed.
        """
        if self.process is None or self.process.stdout is None:
            return

        try:
            while True:
                line_bytes = await self.process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").rstrip("\n\r")
                self._append_line(line)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

        # Process has exited — update status
        if self.process.returncode is not None:
            self.exit_code = self.process.returncode
        else:
            try:
                await self.process.wait()
                self.exit_code = self.process.returncode
            except Exception:
                pass

        if self.status == JobStatus.RUNNING:
            if self.exit_code == 0:
                self.status = JobStatus.COMPLETED
            elif self.exit_code is not None and self.exit_code < 0:
                # Killed by signal — if we didn't request the stop, mark failed
                if self.status == JobStatus.RUNNING:
                    self.status = JobStatus.FAILED
            else:
                self.status = JobStatus.FAILED
            self.completed_at = datetime.now()

        self._write_footer()
        self._close_log()

    def _append_line(self, line: str) -> None:
        """Append a line to both the circular buffer and the log file."""
        self._output_buffer.append(line)
        self._total_lines += 1

        # Circular buffer enforcement
        if len(self._output_buffer) > self._max_buffer_lines:
            overflow = len(self._output_buffer) - self._max_buffer_lines
            self._output_buffer = self._output_buffer[overflow:]

        # Track last error-looking line
        lower = line.lower()
        if any(kw in lower for kw in ("error", "fail", "exception", "traceback", "[-]")):
            self._last_error_line = line

        # Write to persistent log
        if self._output_fh and not self._output_fh.closed:
            try:
                self._output_fh.write(line + "\n")
                self._output_fh.flush()
            except OSError:
                pass

    def _write_footer(self) -> None:
        """Write a footer line to the log file when the job finishes."""
        if self._output_fh and not self._output_fh.closed:
            try:
                self._output_fh.write(
                    f"\n{'#' * 72}\n"
                    f"# Finished: {datetime.now().isoformat()}\n"
                    f"# Status: {self.status.value}\n"
                    f"# Exit code: {self.exit_code}\n"
                    f"# Total lines: {self._total_lines}\n"
                )
                self._output_fh.flush()
            except OSError:
                pass

    def _close_log(self) -> None:
        """Close the log file handle if open."""
        if self._output_fh and not self._output_fh.closed:
            try:
                self._output_fh.close()
            except OSError:
                pass
            self._output_fh = None

    # ------------------------------------------------------------------
    # Output access
    # ------------------------------------------------------------------

    def get_output(self, last_n: int = 50) -> List[str]:
        """Get the last *last_n* lines from the in-memory circular buffer.

        Args:
            last_n: Number of most-recent lines to return.

        Returns:
            List of output lines (most recent at the end).
        """
        if last_n <= 0:
            return []
        return self._output_buffer[-last_n:]

    def get_all_output(self) -> str:
        """Read the full output from the persistent log file.

        Returns:
            Complete log contents as a string, or an empty string if the
            file is unavailable.
        """
        if self._output_file and self._output_file.exists():
            try:
                return self._output_file.read_text(errors="replace")
            except OSError:
                pass
        return ""

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def get_info(self) -> JobInfo:
        """Return a ``JobInfo`` snapshot of this job's current state."""
        return JobInfo(
            id=self.id,
            name=self.name,
            command=self.command,
            status=self.status,
            pid=self.pid,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            exit_code=self.exit_code,
            output_lines=self._total_lines,
            error_summary=self._last_error_line,
        )

    def to_dict(self) -> dict:
        """Serialize to a plain dict suitable for MCP/JSON responses."""
        return {
            "id": self.id,
            "name": self.name,
            "command": self.command,
            "status": self.status.value,
            "pid": self.pid,
            "container": self.container,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "exit_code": self.exit_code,
            "output_lines": self._total_lines,
            "error_summary": self._last_error_line,
            "log_file": str(self._output_file) if self._output_file else None,
        }


# ---------------------------------------------------------------------------
# JobManager (singleton)
# ---------------------------------------------------------------------------

class JobManager:
    """Singleton manager for all background jobs.

    Provides async-safe methods to create, start, stop, query, and clean up
    background jobs.  Log files persist at ``~/.uwu-toolkit/jobs/`` so they
    can be reviewed even after the MCP server restarts (though the ``Job``
    runtime objects themselves are ephemeral).
    """

    _instance: Optional["JobManager"] = None

    def __init__(self) -> None:
        self._jobs: Dict[int, Job] = {}
        self._next_id: int = 1
        self._lock: asyncio.Lock = asyncio.Lock()
        self._jobs_dir: Path = Path.home() / ".uwu-toolkit" / "jobs"
        self._jobs_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_instance(cls) -> "JobManager":
        """Return the singleton ``JobManager`` instance, creating it if needed."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (primarily useful for testing)."""
        cls._instance = None

    # ------------------------------------------------------------------
    # Job creation & lifecycle
    # ------------------------------------------------------------------

    async def create_job(
        self,
        name: str,
        command: str,
        container: Optional[str] = None,
        auto_start: bool = True,
    ) -> Job:
        """Create and optionally start a new background job.

        Args:
            name: Human-readable name (e.g. ``"responder"``, ``"nmap_10.10.10.1"``).
            command: Shell command string to execute.
            container: Exegol container name; ``None`` for local execution.
            auto_start: Whether to start the job immediately.

        Returns:
            The newly created ``Job`` instance.
        """
        async with self._lock:
            job = Job(self._next_id, name, command, container)
            self._jobs[self._next_id] = job
            self._next_id += 1

        if auto_start:
            await job.start()

        return job

    async def start_job(self, job_id: int) -> bool:
        """Start a pending job by ID.

        Args:
            job_id: The job identifier.

        Returns:
            ``True`` if the job was started, ``False`` otherwise.
        """
        job = self.get_job(job_id)
        if job is None:
            return False
        return await job.start()

    async def stop_job(self, job_id: int) -> bool:
        """Stop a running job by ID.

        Args:
            job_id: The job identifier.

        Returns:
            ``True`` if the job was stopped, ``False`` otherwise.
        """
        job = self.get_job(job_id)
        if job is None:
            return False
        return await job.stop()

    async def stop_all(self) -> int:
        """Stop all currently running jobs.

        Returns:
            The number of jobs that were stopped.
        """
        count = 0
        for job in list(self._jobs.values()):
            if job.status == JobStatus.RUNNING:
                if await job.stop():
                    count += 1
        return count

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_job(self, job_id: int) -> Optional[Job]:
        """Get a job by its ID.

        Args:
            job_id: The job identifier.

        Returns:
            The ``Job`` if found, otherwise ``None``.
        """
        return self._jobs.get(job_id)

    def list_jobs(self, status: Optional[JobStatus] = None) -> List[dict]:
        """List all jobs, optionally filtered by status.

        Args:
            status: If given, only return jobs with this status.

        Returns:
            List of job dicts (via ``Job.to_dict()``).
        """
        results = []
        for job in self._jobs.values():
            if status is not None and job.status != status:
                continue
            results.append(job.to_dict())
        return results

    def get_output(self, job_id: int, last_n: int = 50) -> Optional[List[str]]:
        """Get recent output lines from a job's in-memory buffer.

        Args:
            job_id: The job identifier.
            last_n: Number of most-recent lines to return.

        Returns:
            List of output lines, or ``None`` if the job does not exist.
        """
        job = self.get_job(job_id)
        if job is None:
            return None
        return job.get_output(last_n)

    def get_full_output(self, job_id: int) -> Optional[str]:
        """Get the full output from a job's persistent log file.

        Args:
            job_id: The job identifier.

        Returns:
            Complete log contents as a string, or ``None`` if the job
            does not exist.
        """
        job = self.get_job(job_id)
        if job is None:
            return None
        return job.get_all_output()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def remove_job(self, job_id: int) -> bool:
        """Remove a completed, failed, or stopped job from the manager.

        Running or pending jobs cannot be removed — stop them first.

        Args:
            job_id: The job identifier.

        Returns:
            ``True`` if the job was removed, ``False`` otherwise.
        """
        job = self.get_job(job_id)
        if job is None:
            return False
        if job.status in (JobStatus.RUNNING, JobStatus.PENDING):
            return False
        del self._jobs[job_id]
        return True

    def cleanup_completed(self) -> int:
        """Remove all completed, failed, and stopped jobs from the manager.

        Returns:
            Number of jobs removed.
        """
        to_remove = [
            jid for jid, job in self._jobs.items()
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.STOPPED)
        ]
        for jid in to_remove:
            del self._jobs[jid]
        return len(to_remove)

    # ------------------------------------------------------------------
    # Waiting
    # ------------------------------------------------------------------

    async def wait_for(self, job_id: int, timeout: Optional[float] = None) -> Optional[int]:
        """Wait for a job to complete.

        Polls the job status at short intervals until it leaves the
        ``RUNNING`` state or the timeout is reached.

        Args:
            job_id: The job identifier.
            timeout: Maximum seconds to wait; ``None`` for no limit.

        Returns:
            The process exit code, or ``None`` if the job was not found
            or the timeout expired.
        """
        job = self.get_job(job_id)
        if job is None:
            return None

        elapsed = 0.0
        poll_interval = 0.25

        while job.status in (JobStatus.PENDING, JobStatus.RUNNING):
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            if timeout is not None and elapsed >= timeout:
                return None

        return job.exit_code


# ---------------------------------------------------------------------------
# Convenience functions for common long-running tools
# ---------------------------------------------------------------------------

async def start_responder(
    interface: str = "eth0",
    container: Optional[str] = None,
) -> Job:
    """Start Responder in the background.

    Args:
        interface: Network interface to listen on.
        container: Exegol container name; ``None`` for local.

    Returns:
        The running ``Job``.
    """
    cmd = f"responder -I {shlex.quote(interface)} -wFb"
    mgr = JobManager.get_instance()
    return await mgr.create_job("responder", cmd, container)


async def start_ntlmrelayx(
    target: str,
    container: Optional[str] = None,
    extra_args: str = "",
) -> Job:
    """Start ntlmrelayx in the background.

    Args:
        target: Relay target (IP, URL, or targets file).
        container: Exegol container name; ``None`` for local.
        extra_args: Additional arguments appended to the command.

    Returns:
        The running ``Job``.
    """
    cmd = f"ntlmrelayx.py -t {shlex.quote(target)}"
    if extra_args:
        cmd += f" {extra_args}"
    mgr = JobManager.get_instance()
    return await mgr.create_job("ntlmrelayx", cmd, container)


async def start_listener(
    port: int,
    listener_type: str = "nc",
    container: Optional[str] = None,
) -> Job:
    """Start a network listener in the background.

    Args:
        port: Port number to listen on.
        listener_type: One of ``"nc"`` (netcat) or ``"penelope"``.
        container: Exegol container name; ``None`` for local.

    Returns:
        The running ``Job``.
    """
    if listener_type == "penelope":
        cmd = f"penelope {int(port)}"
    else:
        cmd = f"nc -nlvp {int(port)}"
    mgr = JobManager.get_instance()
    return await mgr.create_job(f"listener_{port}", cmd, container)


async def start_bloodhound(
    domain: str,
    username: str,
    password: str,
    dc_ip: str,
    collection: str = "All",
    container: Optional[str] = None,
) -> Job:
    """Start BloodHound collection in the background.

    Args:
        domain: AD domain name.
        username: Domain username.
        password: Domain password.
        dc_ip: Domain controller IP.
        collection: Collection method(s) — default ``"All"``.
        container: Exegol container name; ``None`` for local.

    Returns:
        The running ``Job``.
    """
    cmd = (
        f"bloodhound-python -d {shlex.quote(domain)} "
        f"-u {shlex.quote(username)} "
        f"-p {shlex.quote(password)} "
        f"--dc-ip {shlex.quote(dc_ip)} "
        f"-c {shlex.quote(collection)} "
        f"--zip"
    )
    mgr = JobManager.get_instance()
    return await mgr.create_job("bloodhound", cmd, container)


async def start_nmap(
    target: str,
    ports: str = "",
    scan_type: str = "-sV",
    container: Optional[str] = None,
    extra_args: str = "",
) -> Job:
    """Start an nmap scan in the background.

    Args:
        target: Target IP or range.
        ports: Port specification (e.g. ``"80,443"`` or ``"-"``).
        scan_type: Scan type flags (e.g. ``"-sV -sC"``).
        container: Exegol container name; ``None`` for local.
        extra_args: Additional nmap arguments.

    Returns:
        The running ``Job``.
    """
    cmd = f"nmap {scan_type}"
    if ports:
        cmd += f" -p {shlex.quote(ports)}"
    if extra_args:
        cmd += f" {extra_args}"
    cmd += f" {shlex.quote(target)}"
    mgr = JobManager.get_instance()
    safe_target = _sanitize_name(target)
    return await mgr.create_job(f"nmap_{safe_target}", cmd, container)
