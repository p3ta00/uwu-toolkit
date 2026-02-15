"""
MCP Tool definitions for UwU Toolkit.
Split into domain-specific modules for maintainability.
"""

from .common import _run_cmd, _format_response, _build_impacket_cmd, _find_certipy_bin
from .common import DEFAULT_TIMEOUT, LONG_TIMEOUT, UWU_ROOT


def setup_tools(mcp):
    """Register ALL tools with the MCP server."""
    from . import impacket_tools, netexec_tools, certipy_tools, enum_tools
    from . import module_tools, session_tools, engagement_tools, job_tools, opsec_tools

    impacket_tools.register(mcp)
    netexec_tools.register(mcp)
    certipy_tools.register(mcp)
    enum_tools.register(mcp)
    module_tools.register(mcp)
    session_tools.register(mcp)
    engagement_tools.register(mcp)
    job_tools.register(mcp)
    opsec_tools.register(mcp)
