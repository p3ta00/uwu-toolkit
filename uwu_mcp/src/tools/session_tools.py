"""MCP tools for session management."""

import asyncio
import json
import sys
import os
from .common import _format_response, UWU_ROOT


def register(mcp):

    def _get_session_manager():
        if UWU_ROOT not in sys.path:
            sys.path.insert(0, UWU_ROOT)
        from core.sessions import SessionManager
        return SessionManager.get_instance()

    @mcp.tool()
    async def session_create(
        session_type: str,
        target: str,
        port: int = 0,
        username: str = "",
        password: str = "",
        hashes: str = "",
        domain: str = "",
        key_file: str = "",
    ) -> str:
        """Create a new persistent session to a target.

        Args:
            session_type: Type of session (winrm, psexec, wmiexec, smbexec, dcomexec, atexec, ssh, mssql)
            target: Target IP or hostname
            port: Target port (0 for default)
            username: Username for authentication
            password: Password
            hashes: NTLM hash in LM:NT format
            domain: AD domain
            key_file: SSH private key path
        """
        try:
            mgr = _get_session_manager()
            from core.sessions import SessionType
            try:
                stype = SessionType(session_type.lower())
            except ValueError:
                return _format_response(error=f"Unknown session type: {session_type}. Valid: {[t.value for t in SessionType]}")

            session = await mgr.create_session(
                stype, target, port,
                username=username, password=password,
                hashes=hashes, domain=domain, key_file=key_file,
            )
            return _format_response(
                data=session.to_dict(),
                success=True,
                message=f"Session {session.info.id} created ({session_type} -> {target})"
            )
        except Exception as e:
            return _format_response(error=f"Session creation failed: {e}")

    @mcp.tool()
    async def session_exec(
        session_id: int,
        command: str,
        timeout: int = 60,
    ) -> str:
        """Execute a command on an existing session.

        Args:
            session_id: Session ID from session_create
            command: Command to execute on the remote target
            timeout: Command timeout in seconds
        """
        try:
            mgr = _get_session_manager()
            result = await mgr.execute(session_id, command, timeout)
            return _format_response(data={
                "session_id": session_id,
                "returncode": result["returncode"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            })
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def session_upload(
        session_id: int,
        local_path: str,
        remote_path: str,
    ) -> str:
        """Upload a file to a remote target via an existing session.

        Args:
            session_id: Session ID
            local_path: Local file path
            remote_path: Destination path on target
        """
        try:
            mgr = _get_session_manager()
            ok = await mgr.upload(session_id, local_path, remote_path)
            return _format_response(success=ok, message=f"Upload {'succeeded' if ok else 'failed'}")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def session_download(
        session_id: int,
        remote_path: str,
        local_path: str,
    ) -> str:
        """Download a file from a remote target via an existing session.

        Args:
            session_id: Session ID
            remote_path: File path on target
            local_path: Local destination path
        """
        try:
            mgr = _get_session_manager()
            ok = await mgr.download(session_id, remote_path, local_path)
            return _format_response(success=ok, message=f"Download {'succeeded' if ok else 'failed'}")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def session_list() -> str:
        """List all active sessions with their status and details."""
        try:
            mgr = _get_session_manager()
            sessions = mgr.list_all()
            return _format_response(data={"sessions": sessions, "count": len(sessions)})
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def session_close(session_id: int) -> str:
        """Close and clean up a session.

        Args:
            session_id: Session ID to close
        """
        try:
            mgr = _get_session_manager()
            ok = await mgr.close(session_id)
            return _format_response(success=ok, message=f"Session {session_id} {'closed' if ok else 'not found'}")
        except Exception as e:
            return _format_response(error=str(e))
