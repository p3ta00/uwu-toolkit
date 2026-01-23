"""
NetExec Integration Module
Multi-protocol credential validation and enumeration
Runs inside Exegol container for tool availability
"""

import re
from typing import List, Dict, Optional, Tuple
from core.module_base import ModuleBase, ModuleType, Platform


class NetExec(ModuleBase):
    """
    NetExec (nxc) integration for credential validation and enumeration.
    Supports SMB, LDAP, WinRM, RDP, MSSQL, SSH protocols.
    Automatically runs inside Exegol container.
    """

    def __init__(self):
        super().__init__()
        self.name = "netexec"
        self.description = "NetExec credential validation and enumeration"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "credentials", "smb", "ldap", "winrm", "enumeration", "netexec", "nxc"]
        self.references = [
            "https://github.com/Pennyw0rth/NetExec",
            "https://www.netexec.wiki/"
        ]

        # Core options
        self.register_option("RHOSTS", "Target host(s) - IP, range, or CIDR", required=True)
        self.register_option("DOMAIN", "Domain name", default="")
        self.register_option("USER", "Username or user file (one per line)", default="")
        self.register_option("PASS", "Password, hash, or password file (one per line)", default="")

        # Authentication options
        self.register_option("AUTH_TYPE", "Authentication type",
                           default="password",
                           choices=["password", "hash", "aesKey"])
        self.register_option("PROTOCOL", "Protocol to use",
                           default="smb",
                           choices=["smb", "ldap", "winrm", "rdp", "mssql", "ssh", "wmi"])

        # Action options
        self.register_option("ACTION", "Action to perform",
                           default="check",
                           choices=["check", "shares", "users", "groups", "sessions",
                                   "disks", "loggedon", "localgroups", "pass-pol",
                                   "rid-brute", "spider", "execute", "sam", "lsa", "ntds",
                                   "laps", "gmsa", "dpapi", "bloodhound"])

        # Execution options (for ACTION=execute)
        self.register_option("EXEC_TYPE", "Execution type: cmd (-x) or powershell (-X)",
                           default="cmd",
                           choices=["cmd", "powershell", "ps"])
        self.register_option("EXECUTE", "Command to execute on target", default="")
        self.register_option("EXEC_METHOD", "Execution method (smbexec, wmiexec, atexec, mmcexec) - SMB only",
                           default="",
                           choices=["", "smbexec", "wmiexec", "atexec", "mmcexec"])

        # Spider options (for ACTION=spider)
        self.register_option("SPIDER_SHARE", "Share to spider", default="")
        self.register_option("SPIDER_CONTENT", "Spider for content matching regex", default="")

        # Module options
        self.register_option("NXC_MODULE", "NetExec module to run", default="")
        self.register_option("NXC_MODULE_OPTIONS", "Module options (key=value,key=value)", default="")

        # Output
        self.register_option("OUTPUT", "Output file for results", default="")


        # RDP options
        self.register_option("RDP_CONFIRM", "Auto-confirm RDP execution prompt",
                           default="yes", choices=["yes", "no"])

        # Streaming output
        self.register_option("STREAM", "Stream output in real-time",
                           default="yes", choices=["yes", "no"])

        # Continue on success (for spraying)
        self.register_option("CONTINUE_ON_SUCCESS", "Continue after finding valid creds",
                           default="no", choices=["yes", "no"])

        # Generate /etc/hosts entries
        self.register_option("GENERATE_HOSTS", "Generate /etc/hosts entries from discovered hosts",
                           default="no", choices=["yes", "no"])

        # LAPS options
        self.register_option("LAPS_ADMIN", "Custom LAPS admin account name (default: administrator)", default="")
        self.register_option("LAPS_COMPUTER", "Computer filter for LDAP LAPS module (e.g., WIN-*, DC01)", default="")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        auth_type = self.get_option("AUTH_TYPE")
        protocol = self.get_option("PROTOCOL")
        action = self.get_option("ACTION")
        # Auto-detect: if EXECUTE is set, switch to execute action
        execute_cmd = self.get_option("EXECUTE")
        if execute_cmd and action == "check":
            action = "execute"

        self.print_status(f"Target: {target}")
        if domain:
            self.print_status(f"Domain: {domain}")
        self.print_status(f"User: {user if user else '(null session)'}")
        self.print_status(f"Protocol: {protocol.upper()}")
        self.print_status(f"Action: {action}")
        self.print_line()

        # Build base command
        cmd_parts = ["NetExec", protocol, target]

        # Add authentication (support null/guest/anonymous sessions)
        # Check if user/pass are files (for spraying)
        # Uses WORKING_DIR from config (set with: setp WORKING_DIR /workspace)
        file_extensions = ('.txt', '.lst', '.list', '.users', '.passwords', '.wordlist')

        def resolve_file_path(val):
            """Check if value is a file and resolve path using WORKING_DIR"""
            if not val:
                return val, False
            # Check common file extensions for wordlists
            if val.lower().endswith(file_extensions):
                # Use config's resolve_path which respects WORKING_DIR
                resolved = self._config.resolve_path(val) if self._config else val
                return resolved, True
            # Already absolute path
            if val.startswith('/'):
                return val, True
            return val, False

        user, user_is_file = resolve_file_path(user)
        password, pass_is_file = resolve_file_path(password)

        if user_is_file:
            self.print_status(f"Using user file: {user}")
        if pass_is_file:
            self.print_status(f"Using password file: {password}")

        if user:
            cmd_parts.extend(["-u", user])
        else:
            cmd_parts.extend(["-u", "''"])  # Empty string for null session

        if auth_type == "hash" and password:
            cmd_parts.extend(["-H", password])
        elif auth_type == "aesKey" and password:
            cmd_parts.extend(["--aes-key", password])
        else:
            if password:
                # Don't quote if it's a file path, otherwise quote for special chars
                if pass_is_file:
                    cmd_parts.extend(["-p", password])
                else:
                    cmd_parts.extend(["-p", f"'{password}'"])
            else:
                cmd_parts.extend(["-p", "''"])  # Empty string for null session

        # Add domain if specified
        if domain:
            cmd_parts.extend(["-d", domain])

        # Continue on success (find all valid creds, not just first)
        if self.get_option("CONTINUE_ON_SUCCESS") == "yes":
            cmd_parts.append("--continue-on-success")

        # Build action-specific arguments
        action_args = self._build_action_args(action)
        cmd_parts.extend(action_args)

        # Add module if specified
        nxc_module = self.get_option("NXC_MODULE")
        if nxc_module:
            cmd_parts.extend(["-M", nxc_module])
            module_opts = self.get_option("NXC_MODULE_OPTIONS")
            if module_opts:
                # Parse options - support both comma and space separated
                # Also handle if user included -o in the value
                opts_clean = module_opts.replace(" -o ", " ").replace("-o ", "")
                # Split by comma or whitespace (nxc wants: -o OPT1=VAL1 OPT2=VAL2)
                opt_pairs = [o.strip() for o in re.split(r'[,\s]+', opts_clean) if o.strip() and '=' in o.strip()]
                if opt_pairs:
                    cmd_parts.append("-o")
                    cmd_parts.extend(opt_pairs)

        # Execute in Exegol
        cmd = " ".join(cmd_parts)

        # Auto-confirm RDP execution if enabled
        if protocol == "rdp" and action == "execute" and self.get_option("RDP_CONFIRM") == "yes":
            cmd = f"echo y | {cmd}"

        self.print_status(f"Executing: {cmd}")
        self.print_line()

        # Use streaming or buffered output
        if self.get_option("STREAM") == "yes":
            ret = self.run_in_exegol_stream(cmd)
            output = ""  # Output already printed
        else:
            ret, stdout, stderr = self.run_in_exegol(cmd)
            output = stdout + stderr
            if output:
                self._parse_and_display(output, action)

        # Save output if requested
        output_file = self.get_option("OUTPUT")
        if output_file and output:
            try:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.print_good(f"Output saved to: {output_file}")
            except Exception as e:
                self.print_warning(f"Could not save output: {e}")

        # Generate /etc/hosts entries if requested
        if self.get_option("GENERATE_HOSTS") == "yes":
            # For streaming mode, we need to capture output differently
            if self.get_option("STREAM") == "yes":
                # Re-run quietly to capture output for parsing
                ret2, stdout2, stderr2 = self.run_in_exegol(cmd, quiet=True)
                hosts_output = stdout2 + stderr2
            else:
                hosts_output = output
            self._generate_hosts_entries(hosts_output, target)

        # Determine success based on output
        if "[+]" in output or "Pwn3d!" in output:
            return True
        elif "[-]" in output and "STATUS_LOGON_FAILURE" in output:
            self.print_error("Authentication failed")
            return False

        return ret == 0

    def _build_action_args(self, action: str) -> List[str]:
        """Build action-specific command arguments"""
        args = []

        if action == "check":
            # Just validate credentials, no extra args needed
            pass
        elif action == "shares":
            args.append("--shares")
        elif action == "users":
            args.append("--users")
        elif action == "groups":
            args.append("--groups")
        elif action == "sessions":
            args.append("--sessions")
        elif action == "disks":
            args.append("--disks")
        elif action == "loggedon":
            args.append("--loggedon-users")
        elif action == "localgroups":
            args.append("--local-groups")
        elif action == "pass-pol":
            args.append("--pass-pol")
        elif action == "rid-brute":
            args.append("--rid-brute")
        elif action == "spider":
            share = self.get_option("SPIDER_SHARE")
            if share:
                args.extend(["--spider", share])
            content = self.get_option("SPIDER_CONTENT")
            if content:
                args.extend(["--content", "--pattern", content])
        elif action == "execute":
            execute_cmd = self.get_option("EXECUTE")
            if execute_cmd:
                exec_type = self.get_option("EXEC_TYPE")
                exec_flag = "-X" if exec_type in ["powershell", "ps"] else "-x"
                # Quote the command to handle special characters
                escaped_cmd = execute_cmd.replace("'", "'\\''")
                args.extend([exec_flag, f"'{escaped_cmd}'"])
                # --exec-method only works with SMB protocol and only if specified
                protocol = self.get_option("PROTOCOL")
                exec_method = self.get_option("EXEC_METHOD")
                if protocol == "smb" and exec_method:
                    args.extend(["--exec-method", exec_method])
        elif action == "sam":
            args.append("--sam")
        elif action == "lsa":
            args.append("--lsa")
        elif action == "ntds":
            args.append("--ntds")
        elif action == "laps":
            protocol = self.get_option("PROTOCOL")
            laps_admin = self.get_option("LAPS_ADMIN")
            laps_computer = self.get_option("LAPS_COMPUTER")

            if protocol == "ldap":
                # Use LDAP -M laps module for reading LAPS passwords
                args.extend(["-M", "laps"])
                if laps_computer:
                    args.extend(["-o", f"COMPUTER={laps_computer}"])
            else:
                # SMB --laps for authentication with LAPS password
                if laps_admin:
                    args.extend(["--laps", laps_admin])
                else:
                    args.append("--laps")
        elif action == "gmsa":
            args.append("--gmsa")
        elif action == "dpapi":
            args.append("--dpapi")
        elif action == "bloodhound":
            args.append("--bloodhound")
            args.append("-c")
            args.append("All")

        return args

    def _parse_and_display(self, output: str, action: str) -> None:
        """Parse NetExec output and display with highlighting"""
        for line in output.split('\n'):
            if not line.strip():
                continue

            # Highlight important findings
            if "Pwn3d!" in line:
                self.print_good(f"🎯 ADMIN ACCESS: {line}")
            elif "[+]" in line:
                # Check for specific important findings
                if "STATUS_ACCOUNT_DISABLED" in line:
                    self.print_warning(line)
                elif "Administrator" in line or "Domain Admin" in line:
                    self.print_good(f"⭐ {line}")
                else:
                    self.print_good(line)
            elif "[-]" in line:
                self.print_error(line)
            elif "[*]" in line:
                self.print_status(line.replace("[*]", "").strip())
            elif "READ" in line or "WRITE" in line:
                # Share access
                self.print_good(f"📁 {line}")
            else:
                self.print_line(f"    {line}")

    def _generate_hosts_entries(self, output: str, target: str) -> None:
        """Parse NetExec output and generate /etc/hosts entries"""
        import re

        hosts_entries = []
        seen = set()

        # Pattern to match NetExec SMB/LDAP output lines
        # Example: SMB  10.1.61.93  445  DC01  Windows... (name:DC01) (domain:BUILDINGMAGIC.LOCAL)
        for line in output.split('\n'):
            # Extract IP address from the line
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            # Extract hostname from (name:HOSTNAME) pattern
            name_match = re.search(r'\(name:([^)]+)\)', line)
            hostname = name_match.group(1) if name_match else None

            # Extract domain from (domain:DOMAIN) pattern
            domain_match = re.search(r'\(domain:([^)]+)\)', line)
            domain = domain_match.group(1) if domain_match else None

            if not hostname and not domain:
                continue

            # Build unique key to avoid duplicates
            key = f"{ip}:{hostname}:{domain}"
            if key in seen:
                continue
            seen.add(key)

            # Build hosts entry
            names = []
            if hostname:
                names.append(hostname)
                if domain:
                    # Add FQDN
                    fqdn = f"{hostname}.{domain}"
                    names.append(fqdn)
            if domain:
                # Add domain itself (useful for DC)
                names.append(domain)

            if names:
                entry = f"{ip}\t{' '.join(names)}"
                hosts_entries.append(entry)

        if not hosts_entries:
            self.print_warning("No hosts discovered to add")
            return

        # Display the entries
        self.print_line()
        self.print_good("Generated /etc/hosts entries:")
        self.print_line()
        for entry in hosts_entries:
            print(f"  {entry}")
        self.print_line()

        # Ask to append to /etc/hosts
        try:
            confirm = input("[?] Append to /etc/hosts? [Y/n]: ").strip().lower()
            if confirm != 'n':
                with open('/etc/hosts', 'a') as f:
                    f.write(f"\n# Added by UwU Toolkit - {target}\n")
                    for entry in hosts_entries:
                        f.write(f"{entry}\n")
                self.print_good("Entries added to /etc/hosts")
        except PermissionError:
            self.print_error("Permission denied. Run with sudo or manually add:")
            for entry in hosts_entries:
                print(f"  echo '{entry}' | sudo tee -a /etc/hosts")
        except Exception as e:
            self.print_error(f"Could not write to /etc/hosts: {e}")

    def check(self) -> bool:
        """Verify NetExec is available in Exegol"""
        ret, stdout, stderr = self.run_in_exegol("which NetExec || which nxc")
        return ret == 0
