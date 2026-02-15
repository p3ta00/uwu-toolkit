"""
Evil-WinRM Session Module
Create interactive WinRM sessions that can be backgrounded via tmux
"""

import os
import re
import shutil
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform


class EvilWinRM(ModuleBase):
    """
    Create Evil-WinRM sessions to Windows targets.
    Sessions run in tmux and can be backgrounded with Ctrl+b d.
    Supports both Ruby evil-winrm and Python evil-winrm-py.
    """

    def __init__(self):
        super().__init__()
        self.name = "evil_winrm"
        self.description = "Create Evil-WinRM session (tmux backgroundable)"
        self.author = "UwU Toolkit"
        self.version = "1.2.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "winrm", "shell", "session", "evil-winrm", "remote", "tmux"]
        self.references = [
            "https://github.com/Hackplayers/evil-winrm",
            "https://github.com/foxlox/evil-winrm-py"
        ]

        # Core options
        self.register_option("RHOSTS", "Target host IP", required=True)
        self.register_option("USER", "Username", required=True)
        self.register_option("PASS", "Password", default="")
        self.register_option("HASH", "NTLM hash (use instead of password)", default="")
        self.register_option("DOMAIN", "Domain name", default="")

        # Tool selection
        self.register_option("USE_PYTHON", "Use evil-winrm-py instead of Ruby version",
                           default="no", choices=["yes", "no"])

        # Advanced options
        self.register_option("PORT", "WinRM port", default="5985")
        self.register_option("SSL", "Use SSL (port 5986)",
                           default="no", choices=["yes", "no"])
        self.register_option("SCRIPTS", "PowerShell scripts path", default="")
        self.register_option("EXECUTABLES", "Executables path for upload", default="")

    @staticmethod
    def list_sessions():
        """List all uwu tmux sessions"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}:#{session_created}:#{session_attached}"],
                capture_output=True, text=True, timeout=5
            )
            sessions = []
            for line in result.stdout.strip().split('\n'):
                if line.startswith("uwu-"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        sessions.append({
                            "name": parts[0],
                            "created": parts[1],
                            "attached": parts[2] == "1"
                        })
            return sessions
        except:
            return []

    @staticmethod
    def attach_session(session_name: str) -> bool:
        """Attach to a tmux session"""
        try:
            os.system(f"tmux attach-session -t {session_name}")
            return True
        except:
            return False

    @staticmethod
    def kill_session(session_name: str) -> bool:
        """Kill a tmux session"""
        try:
            result = subprocess.run(
                ["tmux", "kill-session", "-t", session_name],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        ntlm_hash = self.get_option("HASH")
        domain = self.get_option("DOMAIN")
        use_python = self.get_option("USE_PYTHON") == "yes"
        port = self.get_option("PORT")
        use_ssl = self.get_option("SSL") == "yes"
        scripts_path = self.get_option("SCRIPTS")
        exec_path = self.get_option("EXECUTABLES")

        # Auto-detect hash if PASS looks like an NTLM hash
        if password and len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password):
            ntlm_hash = password
            password = ""

        # Display info
        self.print_status(f"Target: {target}:{port}")
        self.print_status(f"User: {user}")
        if domain:
            self.print_status(f"Domain: {domain}")
        self.print_status(f"Auth: {'hash' if ntlm_hash else 'password'}")
        self.print_status(f"Tool: {'evil-winrm-py' if use_python else 'evil-winrm (Ruby)'}")
        self.print_line()

        if use_python:
            return self._run_python(target, user, password, ntlm_hash, domain, port, use_ssl)
        else:
            return self._run_ruby(target, user, password, ntlm_hash, domain, port, use_ssl, scripts_path, exec_path)

    def _run_ruby(self, target, user, password, ntlm_hash, domain, port, use_ssl, scripts_path, exec_path) -> bool:
        """Run Ruby evil-winrm"""
        # Find evil-winrm - try multiple methods
        evil_winrm_path = shutil.which("evil-winrm")
        if not evil_winrm_path:
            for p in ["/usr/local/rvm/gems/ruby-3.1.2@evil-winrm/wrappers/evil-winrm", "/usr/local/bin/evil-winrm", "/usr/bin/evil-winrm", "/root/.local/bin/evil-winrm"]:
                if os.path.isfile(p):
                    evil_winrm_path = p
                    break
        
        if not evil_winrm_path:
            self.print_error("evil-winrm not found in PATH or common locations")
            return False

        cmd = [evil_winrm_path, "-i", target, "-u", user]
        
        if ntlm_hash:
            cmd.extend(["-H", ntlm_hash])
        elif password:
            cmd.extend(["-p", password])
        
        if use_ssl:
            cmd.append("-S")
            cmd.extend(["-P", "5986" if port == "5985" else port])
        elif port != "5985":
            cmd.extend(["-P", port])
        
        if scripts_path:
            cmd.extend(["-s", scripts_path])
        
        if exec_path:
            cmd.extend(["-e", exec_path])

        # Display command (hide secrets)
        display_cmd = " ".join(cmd)
        if password:
            display_cmd = display_cmd.replace(password, "[HIDDEN]")
        if ntlm_hash:
            display_cmd = display_cmd.replace(ntlm_hash, "[HASH]")
        self.print_status(f"Command: {display_cmd}")
        self.print_line()
        
        self.print_good("Starting Evil-WinRM session...")
        self.print_line()

        # Generate session name and run in tmux
        session_name = self._generate_session_name(target, user)
        return self._run_in_tmux(cmd, session_name)

    def _run_python(self, target, user, password, ntlm_hash, domain, port, use_ssl) -> bool:
        """Run Python evil-winrm-py"""
        # Find evil-winrm-py
        py_path = shutil.which("evil-winrm-py")
        if not py_path:
            for p in ["/usr/local/bin/evil-winrm-py", "/usr/bin/evil-winrm-py", "/root/.local/bin/evil-winrm-py"]:
                if os.path.isfile(p):
                    py_path = p
                    break
        
        if not py_path:
            self.print_error("evil-winrm-py not found. Try: pip install evil-winrm-py")
            return False

        cmd = [py_path, "-t", target, "-u", user]
        
        if ntlm_hash:
            cmd.extend(["-H", ntlm_hash])
        elif password:
            cmd.extend(["-p", password])
        
        if domain:
            cmd.extend(["-d", domain])
        
        if use_ssl:
            cmd.append("--ssl")
        
        if port != "5985":
            cmd.extend(["--port", port])

        # Display command (hide secrets)
        display_cmd = " ".join(cmd)
        if password:
            display_cmd = display_cmd.replace(password, "[HIDDEN]")
        if ntlm_hash:
            display_cmd = display_cmd.replace(ntlm_hash, "[HASH]")
        self.print_status(f"Command: {display_cmd}")
        self.print_line()
        
        self.print_good("Starting Evil-WinRM-py session...")
        self.print_line()

        # Generate session name and run in tmux
        session_name = self._generate_session_name(target, user)
        return self._run_in_tmux(cmd, session_name)

    def _generate_session_name(self, target: str, user: str) -> str:
        """Generate a unique tmux session name"""
        # Sanitize user for session name (remove domain prefix, special chars)
        safe_user = user.split("@")[0]
        if "\\" in safe_user:
            safe_user = safe_user.split("\\")[-1]
        safe_user = re.sub(r'[^a-zA-Z0-9_-]', '_', safe_user)

        # Sanitize target - tmux interprets dots as pane separators
        safe_target = target.replace(".", "-")

        # Create base session name
        base_name = f"uwu-{safe_user}@{safe_target}"

        # Check for existing sessions and append number if needed
        existing = self.list_sessions()
        existing_names = [s["name"] for s in existing]

        if base_name not in existing_names:
            return base_name

        # Find next available number
        counter = 2
        while f"{base_name}-{counter}" in existing_names:
            counter += 1
        return f"{base_name}-{counter}"

    def _apply_uwu_theme(self, session_name: str) -> None:
        """Apply UwU themed styling to tmux session"""
        # Find the status script
        script_paths = [
            "/opt/my-resources/tools/uwu-toolkit/scripts/uwu-tmux-status.sh",
            "/opt/tools/uwu-toolkit/scripts/uwu-tmux-status.sh",
            os.path.expanduser("~/.local/share/uwu-toolkit/scripts/uwu-tmux-status.sh"),
        ]
        status_script = None
        for p in script_paths:
            if os.path.isfile(p):
                status_script = p
                break

        # Build status-right with dynamic status if script exists
        if status_script:
            status_right = f"#(bash {status_script}) #[fg=#666666]Ctrl+b x #[fg=#ff00ff]| #[fg=#00ffff]%H:%M "
        else:
            status_right = "#[fg=#666666]Ctrl+b x = detach #[fg=#ff00ff]| #[fg=#00ffff]%H:%M "

        # UwU color scheme - pink/cyan/magenta theme
        theme_commands = [
            # Status bar styling
            ["tmux", "set-option", "-t", session_name, "status", "on"],
            ["tmux", "set-option", "-t", session_name, "status-style", "bg=#1a1a2e,fg=#ff6eb4"],
            ["tmux", "set-option", "-t", session_name, "status-left-length", "50"],
            ["tmux", "set-option", "-t", session_name, "status-right-length", "120"],
            # Left: UwU branding (pink background)
            ["tmux", "set-option", "-t", session_name, "status-left", "#[bg=#ff6eb4,fg=#1a1a2e,bold] UwU #[bg=#1a1a2e,fg=#ff6eb4] "],
            # Right: dynamic status + detach hint + time
            ["tmux", "set-option", "-t", session_name, "status-right", status_right],
            # Refresh status every 2 seconds
            ["tmux", "set-option", "-t", session_name, "status-interval", "2"],
            # Window styling
            ["tmux", "set-option", "-t", session_name, "window-status-current-style", "bg=#ff00ff,fg=#1a1a2e,bold"],
            ["tmux", "set-option", "-t", session_name, "window-status-style", "bg=#1a1a2e,fg=#888888"],
            # Pane border colors
            ["tmux", "set-option", "-t", session_name, "pane-border-style", "fg=#ff6eb4"],
            ["tmux", "set-option", "-t", session_name, "pane-active-border-style", "fg=#00ffff"],
            # Message styling
            ["tmux", "set-option", "-t", session_name, "message-style", "bg=#ff6eb4,fg=#1a1a2e,bold"],
            # Bind Ctrl+b x to detach (applied globally)
            ["tmux", "bind-key", "x", "detach-client"],
        ]
        for cmd in theme_commands:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except:
                pass

    def _run_in_tmux(self, cmd: list, session_name: str) -> bool:
        """Run command in a new tmux session"""
        # Build the command string
        cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)

        # Check if tmux is available
        if not shutil.which("tmux"):
            self.print_error("tmux not found - cannot create backgroundable session")
            self.print_status("Falling back to direct execution...")
            return self._run_direct(cmd)

        # Create new tmux session and attach to it
        try:
            self.print_good(f"Creating tmux session: {session_name}")
            self.print_status("Use Ctrl+b d to detach (background the session)")
            self.print_status("Use 'sessions' to list, 'interact <id>' to reattach")
            self.print_line()

            # Create detached session first, then attach (cleaner)
            create_result = subprocess.run(
                ["tmux", "new-session", "-d", "-s", session_name, cmd_str],
                capture_output=True, text=True, timeout=10
            )

            if create_result.returncode != 0:
                self.print_error(f"Failed to create tmux session: {create_result.stderr}")
                return False

            # Apply UwU theme to the session
            self._apply_uwu_theme(session_name)

            # Attach to the session
            os.system(f"tmux attach-session -t {session_name}")

            # Check if session still exists (user might have exited)
            check_result = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True, timeout=5
            )

            self.print_line()
            if check_result.returncode == 0:
                self.print_good(f"Session '{session_name}' is backgrounded")
                self.print_status("Use 'sessions' to list, 'interact <name>' to reattach")
            else:
                self.print_status("Session ended")

            return True

        except subprocess.TimeoutExpired:
            self.print_error("Timeout creating tmux session")
            return False
        except Exception as e:
            self.print_error(f"Failed to create tmux session: {e}")
            return False

    def _run_direct(self, cmd: list) -> bool:
        """Run command directly without tmux (fallback)"""
        try:
            cmd_str = " ".join(f'"{c}"' if " " in c else c for c in cmd)
            exit_code = os.system(cmd_str)

            self.print_line()
            if exit_code == 0:
                self.print_good("Session ended")
            else:
                self.print_warning(f"Session ended with code {exit_code >> 8}")
            return True
        except KeyboardInterrupt:
            self.print_line()
            self.print_warning("Session interrupted")
            return True

    def check(self) -> bool:
        """Check if evil-winrm is available"""
        use_python = self.get_option("USE_PYTHON") == "yes"
        tool = "evil-winrm-py" if use_python else "evil-winrm"

        if shutil.which(tool):
            return True

        # Check common paths
        paths = [
            "/usr/local/rvm/gems/ruby-3.1.2@evil-winrm/wrappers/evil-winrm",
            "/usr/local/bin/",
            "/usr/bin/",
            "/root/.local/bin/"
        ]
        for p in paths:
            check_path = p if p.endswith("evil-winrm") else p + tool
            if os.path.isfile(check_path):
                return True
        return False
