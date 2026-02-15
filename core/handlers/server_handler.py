"""
Server command handler for UwU Toolkit console.
Handles starting/stopping HTTP, PHP, and netcat servers/listeners.
"""

import os
import shutil
import subprocess
from typing import List, Optional

from . import HandlerBase
from ..colors import Colors, Style
from .. import tmux_status
from ..shells import print_listeners_table


class ServerHandler(HandlerBase):
    """Handles server/listener start, stop, and listing commands."""

    def cmd_start(self, args: List[str]) -> None:
        """Start a server/listener"""
        if not args:
            print(Style.error("Usage: start <http|php|nc> [port] [directory]"))
            print(Style.info("  start http           - Start HTTP server on port 8000"))
            print(Style.info("  start http 9000      - Start HTTP server on port 9000"))
            print(Style.info("  start http 8000 /tmp - Start HTTP server serving /tmp"))
            return

        service = args[0].lower()
        port = None
        directory = None

        # Parse args - could be port, directory, or both
        if len(args) > 1:
            if args[1].isdigit():
                port = int(args[1])
                if len(args) > 2:
                    directory = args[2]
            else:
                directory = args[1]

        if service in ("gosh", "http"):
            self._start_gosh(port, directory)
        elif service == "php":
            self._start_php(port, directory)
        elif service in ("nc", "listener"):
            if not port:
                print(Style.error("Port required for listener"))
                return
            self._start_nc(port)
        else:
            print(Style.error(f"Unknown service: {service}"))

    def _start_gosh(self, port: Optional[int] = None, directory: Optional[str] = None) -> None:
        """Start HTTP server from WORKING_DIR or specified directory"""
        port = port or self.config.get_config("gosh_default_port", 8000)

        # Use specified directory, or WORKING_DIR, or current directory
        serve_dir = directory or self.config.get_working_dir()

        # Verify directory exists
        if not os.path.isdir(serve_dir):
            print(Style.error(f"Directory not found: {serve_dir}"))
            return

        # Check if port is already in use
        name = f"http-{port}"
        if name in self.console.processes:
            proc = self.console.processes[name]
            if proc.poll() is None:
                print(Style.warning(f"HTTP server already running on port {port}"))
                print(Style.info(f"Use 'stop http {port}' to stop it first"))
                return

        # Use Python HTTP server with unbuffered output for logging
        cmd = ["python3", "-u", "-m", "http.server", str(port), "-d", serve_dir]

        print(Style.info(f"Starting HTTP server on port {port}..."))
        print(Style.info(f"Serving directory: {serve_dir}"))

        # Set unbuffered environment
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,  # Don't buffer stdout - prevents blocking
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,  # Daemonize properly
        )

        self.console.processes[name] = proc
        tmux_status.update_server(port, "http", "running")
        self.config.log_server_start("HTTP", str(port))
        print(Style.success(f"HTTP server started on http://0.0.0.0:{port} (ID: {name})"))

        # Start background thread to monitor HTTP requests and log them
        self._start_http_monitor(name, proc, port)

    def _start_php(self, port: Optional[int] = None, directory: Optional[str] = None) -> None:
        """Start PHP development server from WORKING_DIR or specified directory"""
        port = port or self.config.get_config("php_default_port", 8080)

        # Use specified directory, or WORKING_DIR, or current directory
        serve_dir = directory or self.config.get_working_dir()

        if not shutil.which("php"):
            print(Style.error("PHP not found in PATH"))
            return

        # Check if port is already in use
        name = f"php-{port}"
        if name in self.console.processes:
            proc = self.console.processes[name]
            if proc.poll() is None:
                print(Style.warning(f"PHP server already running on port {port}"))
                print(Style.info(f"Use 'stop php {port}' to stop it first"))
                return

        print(Style.info(f"Starting PHP server on port {port}..."))
        print(Style.info(f"Serving directory: {serve_dir}"))

        proc = subprocess.Popen(
            ["php", "-S", f"0.0.0.0:{port}", "-t", serve_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.console.processes[name] = proc
        tmux_status.update_server(port, "php", "running")
        self.config.log_server_start("PHP", str(port))
        print(Style.success(f"PHP server started on http://0.0.0.0:{port} (ID: {name})"))

    def _start_nc(self, port: int) -> None:
        """Start netcat listener with rlwrap"""
        use_rlwrap = self.config.get_config("nc_use_rlwrap", True)

        if use_rlwrap and shutil.which("rlwrap"):
            cmd = ["rlwrap", "nc", "-lvnp", str(port)]
        else:
            if use_rlwrap:
                print(Style.warning("rlwrap not found, using plain nc"))
            cmd = ["nc", "-lvnp", str(port)]

        print(Style.info(f"Starting listener on port {port}..."))
        print(Style.warning("Listener runs in foreground. Use Ctrl+C to stop."))

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print()
            print(Style.info("Listener stopped"))

    def _start_http_monitor(self, name: str, proc: subprocess.Popen, port: int) -> None:
        """Start background thread to monitor HTTP server output and log requests"""
        import threading
        import re

        def monitor():
            while proc.poll() is None:
                try:
                    line = proc.stderr.readline()
                    if line:
                        decoded = line.decode('utf-8', errors='ignore').strip()
                        # Parse HTTP request log line
                        # Format: 10.200.24.159 - - [19/Dec/2024 10:30:45] "GET /stager.ps1 HTTP/1.1" 200 -
                        match = re.search(r'^([\d.]+).*"(GET|POST|PUT|HEAD)\s+([^\s]+)', decoded)
                        if match:
                            ip = match.group(1)
                            method = match.group(2)
                            path = match.group(3)
                            self.config.log_event("http", f":{port} <- {ip} {method} {path}")
                except:
                    break

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()

    def cmd_stop(self, args: List[str]) -> None:
        """Stop a running service"""
        if not args:
            if not self.console.processes:
                print(Style.warning("No running services"))
            else:
                print(Style.error("Usage: stop <http|php|service_id> [port]"))
                print(Style.info("  stop http        - Stop HTTP server (default port 8000)"))
                print(Style.info("  stop http 9000   - Stop HTTP server on port 9000"))
                print(Style.info("  stop php         - Stop PHP server"))
                self.cmd_listeners([])
            return

        service = args[0].lower()
        port = int(args[1]) if len(args) > 1 and args[1].isdigit() else None

        # Build possible service names
        if service in ("http", "gosh"):
            port = port or 8000
            name = f"http-{port}"
        elif service == "php":
            port = port or 8080
            name = f"php-{port}"
        else:
            name = service  # Use as-is (e.g., "http-8000")

        if name in self.console.processes:
            proc = self.console.processes[name]
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except:
                proc.kill()
            del self.console.processes[name]
            # Update tmux status
            if "-" in name:
                parts = name.rsplit("-", 1)
                if parts[-1].isdigit():
                    p = int(parts[-1])
                    tmux_status.update_server(p, parts[0], "stopped")
            self.config.log_server_stop(name.split("-")[0].upper(), str(port or ""))
            print(Style.success(f"Stopped {name}"))
        else:
            # Try to find matching service
            matching = [k for k in self.console.processes.keys() if k.startswith(service)]
            if matching:
                print(Style.error(f"Service not found: {name}"))
                print(Style.info(f"Did you mean: {', '.join(matching)}?"))
            else:
                print(Style.error(f"Service not found: {name}"))
                if self.console.processes:
                    print(Style.info(f"Running services: {', '.join(self.console.processes.keys())}"))

    def cmd_listeners(self, args: List[str]) -> None:
        """List active listeners/servers"""
        # Show both old-style processes and shell manager listeners
        has_processes = bool(self.console.processes)
        listeners = self.console.shell_manager.list_listeners()

        if not has_processes and not listeners:
            print(Style.warning("No active services or listeners"))
            return

        if has_processes:
            print(f"\n  Active Services")
            print(f"  {'='*40}\n")
            print(f"  {'ID':<15} {'Status':<10} {'PID'}")
            print(f"  {'-'*15} {'-'*10} {'-'*10}")

            for name, proc in self.console.processes.items():
                status = "running" if proc.poll() is None else "stopped"
                print(f"  {name:<15} {status:<10} {proc.pid}")
            print()

        if listeners:
            print_listeners_table(listeners)
