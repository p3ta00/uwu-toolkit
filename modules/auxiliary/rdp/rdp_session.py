from core.module_base import ModuleBase, ModuleType, Platform
import subprocess
import shutil


class RDPSession(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "rdp_session"
        self.description = "Establish RDP session using xfreerdp or rdesktop with provided credentials"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["rdp", "remote-desktop", "windows", "lateral-movement"]

        # Target options
        self.register_option("RHOSTS", "Target host", required=True)
        self.register_option("RPORT", "RDP port", required=True, default="3389")
        
        # Authentication options
        self.register_option("USERNAME", "Username for RDP authentication", required=True)
        self.register_option("PASSWORD", "Password for RDP authentication", required=False, default="")
        self.register_option("DOMAIN", "Domain for authentication", required=False, default="")
        self.register_option("NTLM_HASH", "NTLM hash for pass-the-hash authentication", required=False, default="")
        
        # Connection options
        self.register_option("CLIENT", "RDP client to use (xfreerdp, rdesktop, auto)", required=False, default="auto")
        self.register_option("FULLSCREEN", "Enable fullscreen mode", required=False, default="false")
        self.register_option("RESOLUTION", "Screen resolution (e.g., 1920x1080)", required=False, default="1280x720")
        self.register_option("DRIVE", "Local drive to share (path)", required=False, default="")
        self.register_option("CLIPBOARD", "Enable clipboard sharing", required=False, default="true")
        
        # Security options
        self.register_option("IGNORE_CERT", "Ignore certificate warnings", required=False, default="true")
        self.register_option("SECURITY", "Security protocol (rdp, tls, nla, auto)", required=False, default="auto")
        
        # Additional options
        self.register_option("EXTRA_ARGS", "Additional arguments to pass to the RDP client", required=False, default="")

    def _find_rdp_client(self) -> str:
        """Find available RDP client on the system."""
        client_pref = self.get_option("CLIENT").lower()
        
        if client_pref == "auto":
            # Prefer xfreerdp as it has more features
            if shutil.which("xfreerdp"):
                return "xfreerdp"
            elif shutil.which("xfreerdp3"):
                return "xfreerdp3"
            elif shutil.which("rdesktop"):
                return "rdesktop"
            else:
                return None
        elif client_pref in ["xfreerdp", "xfreerdp3"]:
            if shutil.which(client_pref):
                return client_pref
            # Try alternative xfreerdp version
            alt = "xfreerdp3" if client_pref == "xfreerdp" else "xfreerdp"
            if shutil.which(alt):
                return alt
            return None
        elif client_pref == "rdesktop":
            return "rdesktop" if shutil.which("rdesktop") else None
        else:
            return None

    def _build_xfreerdp_command(self) -> list:
        """Build xfreerdp command with options."""
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        ntlm_hash = self.get_option("NTLM_HASH")
        resolution = self.get_option("RESOLUTION")
        fullscreen = self.get_option("FULLSCREEN").lower() == "true"
        drive = self.get_option("DRIVE")
        clipboard = self.get_option("CLIPBOARD").lower() == "true"
        ignore_cert = self.get_option("IGNORE_CERT").lower() == "true"
        security = self.get_option("SECURITY").lower()
        extra_args = self.get_option("EXTRA_ARGS")
        
        client = self._find_rdp_client()
        cmd = [client]
        
        # Target
        cmd.append(f"/v:{target}:{port}")
        
        # Authentication
        cmd.append(f"/u:{username}")
        
        if ntlm_hash:
            cmd.append(f"/pth:{ntlm_hash}")
        elif password:
            cmd.append(f"/p:{password}")
        
        if domain:
            cmd.append(f"/d:{domain}")
        
        # Display settings
        if fullscreen:
            cmd.append("/f")
        else:
            cmd.append(f"/size:{resolution}")
        
        # Shared resources
        if clipboard:
            cmd.append("+clipboard")
        
        if drive:
            cmd.append(f"/drive:share,{drive}")
        
        # Security settings
        if ignore_cert:
            cmd.append("/cert:ignore")
        
        if security != "auto":
            cmd.append(f"/sec:{security}")
        
        # Common useful options
        cmd.append("/dynamic-resolution")
        cmd.append("+home-drive")
        
        # Extra arguments
        if extra_args:
            cmd.extend(extra_args.split())
        
        return cmd

    def _build_rdesktop_command(self) -> list:
        """Build rdesktop command with options."""
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        domain = self.get_option("DOMAIN")
        resolution = self.get_option("RESOLUTION")
        fullscreen = self.get_option("FULLSCREEN").lower() == "true"
        drive = self.get_option("DRIVE")
        clipboard = self.get_option("CLIPBOARD").lower() == "true"
        extra_args = self.get_option("EXTRA_ARGS")
        
        cmd = ["rdesktop"]
        
        # Target (rdesktop uses host:port format at the end)
        
        # Authentication
        cmd.extend(["-u", username])
        
        if password:
            cmd.extend(["-p", password])
        
        if domain:
            cmd.extend(["-d", domain])
        
        # Display settings
        if fullscreen:
            cmd.append("-f")
        else:
            cmd.extend(["-g", resolution])
        
        # Shared resources
        if clipboard:
            cmd.append("-r")
            cmd.append("clipboard:PRIMARYCLIPBOARD")
        
        if drive:
            cmd.append("-r")
            cmd.append(f"disk:share={drive}")
        
        # Extra arguments
        if extra_args:
            cmd.extend(extra_args.split())
        
        # Target at the end for rdesktop
        cmd.append(f"{target}:{port}")
        
        return cmd

    def _test_rdp_connection(self) -> bool:
        """Test if RDP port is accessible before attempting connection."""
        import socket
        
        target = self.get_option("RHOSTS")
        port = int(self.get_option("RPORT"))
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        username = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ntlm_hash = self.get_option("NTLM_HASH")
        
        self.print_status(f"Establishing RDP session to {target}:{port}")
        
        # Validate authentication options
        if not password and not ntlm_hash:
            self.print_warning("No password or NTLM hash provided - attempting connection anyway")
        
        # Find available RDP client
        client = self._find_rdp_client()
        if not client:
            self.print_error("No RDP client found. Please install xfreerdp or rdesktop")
            self.print_status("  Install xfreerdp: apt install freerdp2-x11")
            self.print_status("  Install rdesktop: apt install rdesktop")
            return False
        
        self.print_status(f"Using RDP client: {client}")
        
        # Test connectivity first
        self.print_status(f"Testing RDP port connectivity...")
        if not self._test_rdp_connection():
            self.print_warning(f"RDP port {port} may not be accessible on {target}")
            self.print_status("Attempting connection anyway...")
        else:
            self.print_good(f"RDP port {port} is open on {target}")
        
        # Build command based on client
        try:
            if "xfreerdp" in client:
                cmd = self._build_xfreerdp_command()
            else:
                cmd = self._build_rdesktop_command()
                if ntlm_hash:
                    self.print_warning("rdesktop does not support pass-the-hash, falling back to password auth")
        except Exception as e:
            self.print_error(f"Failed to build RDP command: {str(e)}")
            return False
        
        # Display connection info
        self.print_status(f"Connecting as: {username}")
        if ntlm_hash and "xfreerdp" in client:
            self.print_status("Authentication: Pass-the-Hash")
        elif password:
            self.print_status("Authentication: Password")
        else:
            self.print_status("Authentication: None/Prompt")
        
        # Log the command (hide password)
        safe_cmd = []
        skip_next = False
        for i, arg in enumerate(cmd):
            if skip_next:
                safe_cmd.append("********")
                skip_next = False
            elif arg == "-p" or arg.startswith("/p:") or arg.startswith("/pth:"):
                if arg == "-p":
                    safe_cmd.append(arg)
                    skip_next = True
                else:
                    # xfreerdp style /p:password
                    prefix = "/p:" if arg.startswith("/p:") else "/pth:"
                    safe_cmd.append(f"{prefix}********")
            else:
                safe_cmd.append(arg)
        
        self.print_status(f"Command: {' '.join(safe_cmd)}")
        
        # Execute RDP client
        try:
            self.print_good(f"Launching RDP session to {target}:{port}...")
            self.print_status("RDP window should open shortly. Close window to return.")
            
            # Run the RDP client (this will block until the session is closed)
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for process to complete
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.print_good("RDP session ended successfully")
                return True
            else:
                # Some error codes are not actual failures
                error_output = stderr.decode('utf-8', errors='ignore')
                
                if "ERRCONNECT_CONNECT_CANCELLED" in error_output:
                    self.print_status("RDP session was cancelled by user")
                    return True
                elif "disconnect" in error_output.lower():
                    self.print_status("RDP session disconnected")
                    return True
                elif "LOGON" in error_output or "authentication" in error_output.lower():
                    self.print_error("Authentication failed - check credentials")
                    return False
                elif "NLA" in error_output:
                    self.print_error("NLA authentication required but failed")
                    self.print_status("Try setting SECURITY=rdp to bypass NLA")
                    return False
                else:
                    self.print_warning(f"RDP client exited with code {process.returncode}")
                    if error_output:
                        self.print_error(f"Error: {error_output[:500]}")
                    return False
                    
        except FileNotFoundError:
            self.print_error(f"RDP client '{client}' not found in PATH")
            return False
        except KeyboardInterrupt:
            self.print_warning("RDP session interrupted by user")
            return True
        except Exception as e:
            self.print_error(f"Failed to establish RDP session: {str(e)}")
            return False
