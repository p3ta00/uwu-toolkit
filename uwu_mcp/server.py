"""
MCP Server for UwU Toolkit.
Exposes AD pentesting tools and module management via Model Context Protocol.
"""

import logging
import sys
import socket
import time
import threading

from .src import tools, prompts, resources

try:
    from fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


class MCPServer:
    """
    MCP server exposing UwU Toolkit capabilities to AI assistants.

    Tools: impacket, bloodyAD, certipy, netexec, module management, shell exec
    Resources: module list, global variables, lab info
    Prompts: AD enumeration, attack planning, lateral movement
    """

    def __init__(self, host="0.0.0.0", port=9400, path="/uwu"):
        if not MCP_AVAILABLE:
            raise ImportError("fastmcp not installed. Install with: pip install fastmcp")

        self.host = host
        self.port = port
        self.path = path if path.startswith('/') else '/' + path
        self.mcp = FastMCP("UwU Toolkit MCP")
        self.status = False
        self.server_thread = None

        # Register all tools, resources, and prompts
        tools.setup_tools(self.mcp)
        resources.setup_resources(self.mcp)
        prompts.setup_prompts(self.mcp)

    def set_status(self, status):
        self.status = status

    def get_status(self):
        return self.status

    async def _server_started(self):
        self.set_status(True)
        logging.info("UwU MCP server ready")

    def start(self):
        """Start the MCP server in a background thread."""
        if self.server_thread and self.server_thread.is_alive():
            logging.warning("MCP server already running")
            return

        def run_server():
            logging.info(f"Starting UwU MCP on {self.host}:{self.port}")
            try:
                try:
                    self.mcp.run(
                        transport="http",
                        show_banner=False,
                        host=self.host,
                        port=self.port,
                        path=self.path,
                        log_level="error",
                        on_start=self._server_started
                    )
                except TypeError:
                    self.mcp.run(
                        transport="http",
                        show_banner=False,
                        host=self.host,
                        port=self.port,
                        path=self.path,
                        log_level="error"
                    )
            except Exception as e:
                self.set_status(False)
                logging.error(f"MCP server error: {e}")
                sys.exit(1)

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Probe port to confirm readiness
        start_time = time.time()
        while time.time() - start_time < 5.0 and not self.get_status():
            try:
                with socket.create_connection((self.host, int(self.port)), timeout=0.25):
                    self.set_status(True)
                    break
            except Exception:
                time.sleep(0.1)

        logging.debug(f"MCP server status: {self.get_status()}")

    def stop(self):
        """Stop the MCP server."""
        logging.info("Stopping UwU MCP server")
        try:
            if hasattr(self.mcp, 'stop') and callable(self.mcp.stop):
                self.mcp.stop()
        except Exception as e:
            logging.debug(f"MCP stop: {e}")
        self.set_status(False)


def main():
    """Standalone entrypoint."""
    import argparse
    parser = argparse.ArgumentParser(description="UwU Toolkit MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=9400, help="Bind port")
    parser.add_argument("--path", default="/uwu", help="HTTP path")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    server = MCPServer(host=args.host, port=args.port, path=args.path)
    print(f"[*] UwU Toolkit MCP Server starting on {args.host}:{args.port}{args.path}")

    # Run in foreground (not threaded) for standalone mode
    try:
        server.mcp.run(
            transport="http",
            show_banner=False,
            host=args.host,
            port=args.port,
            path=args.path,
            log_level="debug" if args.debug else "info"
        )
    except KeyboardInterrupt:
        print("\n[*] Server stopped")


if __name__ == "__main__":
    main()
