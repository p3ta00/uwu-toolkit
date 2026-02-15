"""MCP tools for background job management."""

import asyncio
import sys
import os
from .common import _format_response, UWU_ROOT


def register(mcp):

    def _get_job_manager():
        if UWU_ROOT not in sys.path:
            sys.path.insert(0, UWU_ROOT)
        from core.jobs import JobManager
        return JobManager.get_instance()

    @mcp.tool()
    async def job_start(
        name: str,
        command: str,
        container: str = "",
    ) -> str:
        """Start a long-running background job (e.g., Responder, ntlmrelayx, nmap).

        Args:
            name: Human-readable job name
            command: Shell command to run
            container: Docker container to run in (optional, e.g., "exegol-merry")
        """
        try:
            mgr = _get_job_manager()
            job = await mgr.create_job(name, command, container=container if container else None)
            await mgr.start_job(job.id)
            return _format_response(
                data=job.to_dict(),
                success=True,
                message=f"Job {job.id} '{name}' started (PID {job.process.pid if job.process else '?'})"
            )
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def job_stop(job_id: int) -> str:
        """Stop a running background job.

        Args:
            job_id: Job ID to stop
        """
        try:
            mgr = _get_job_manager()
            ok = await mgr.stop_job(job_id)
            return _format_response(success=ok, message=f"Job {job_id} {'stopped' if ok else 'not found or already stopped'}")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def job_list() -> str:
        """List all background jobs and their status."""
        try:
            mgr = _get_job_manager()
            jobs = mgr.list_jobs()
            return _format_response(data={"jobs": jobs, "count": len(jobs)})
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def job_output(job_id: int, last_n: int = 50) -> str:
        """Get recent output from a background job.

        Args:
            job_id: Job ID
            last_n: Number of recent lines to return
        """
        try:
            mgr = _get_job_manager()
            lines = mgr.get_output(job_id, last_n=last_n)
            if lines is None:
                return _format_response(error=f"Job {job_id} not found")
            return _format_response(data={
                "job_id": job_id,
                "lines": lines,
                "count": len(lines),
            })
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def job_cleanup() -> str:
        """Remove all completed/failed/stopped jobs from the list."""
        try:
            mgr = _get_job_manager()
            count = mgr.cleanup_completed()
            return _format_response(success=True, message=f"Cleaned up {count} completed jobs")
        except Exception as e:
            return _format_response(error=str(e))
