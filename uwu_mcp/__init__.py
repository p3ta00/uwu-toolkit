"""
Model Context Protocol (MCP) server for UwU Toolkit.

Exposes AD pentesting tools (Impacket, BloodyAD, Certipy, NetExec)
and module management to AI assistants via FastMCP.

Requires: pip install fastmcp
"""

try:
    from .server import MCPServer
    __all__ = ['MCPServer']
except ImportError:
    import logging
    logging.warning("MCP dependencies not installed. Install with: pip install fastmcp")

    class MCPServer:
        def __init__(self, *args, **kwargs):
            raise ImportError("MCP dependencies not installed. Install with: pip install fastmcp")

    __all__ = ['MCPServer']
