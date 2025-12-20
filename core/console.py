"""
Main console interface for UwU Toolkit
Provides Metasploit-like interactive CLI
"""

import os
import sys
import readline
import subprocess
import shutil
import signal
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime

from .config import Config
from .colors import Colors, Style, BANNER, MINI_BANNER, MINI_BANNER_PROMPT
from . import tmux_status
from .module_loader import ModuleLoader, ModuleInfo
from .module_base import ModuleBase, ModuleType
from .claude import ClaudeAssistant, ClaudeMode, get_claude_help
from .sliver import SliverClient, SliverMode, SliverServer, get_sliver_help
from .penelope import PenelopeClient, PenelopeMode, get_penelope_mode, get_penelope_help
from .ligolo import LigoloClient, LigoloMode, get_ligolo_mode, get_ligolo_help, print_agents_table
from .shells import (ShellManager, get_shell_manager, print_shells_table,
                     print_listeners_table, ShellType, ShellStatus)
from .creds import CredentialManager, print_creds_table


class Completer:
    """Tab completion handler"""

    def __init__(self, console: "UwUConsole"):
        self.console = console
        self.matches: List[str] = []

    def complete(self, text: str, state: int) -> Optional[str]:
        """Main completion function"""
        if state == 0:
            line = readline.get_line_buffer()
            self.matches = self._get_matches(line, text)
        try:
            return self.matches[state]
        except IndexError:
            return None

    def _get_matches(self, line: str, text: str) -> List[str]:
        """Get completion matches based on context"""
        parts = line.split()

        if not parts:
            # Complete commands
            return [c + " " for c in self.console.commands.keys() if c.startswith(text)]

        cmd = parts[0].lower()

        if len(parts) == 1 and not line.endswith(" "):
            # Still completing command
            return [c + " " for c in self.console.commands.keys() if c.startswith(text)]

        # Command-specific completion
        if cmd == "use":
            return self._complete_modules(text)
        elif cmd in ("set", "setg"):
            if len(parts) == 2 and not line.endswith(" "):
                # Completing variable name
                return self._complete_variables(text)
            elif len(parts) >= 2:
                # Completing value - show history
                var_name = parts[1].upper()
                return self._complete_history(var_name, text)
        elif cmd in ("unset", "unsetg"):
            return self._complete_variables(text)
        elif cmd == "search":
            return self._complete_search(text)
        elif cmd in ("show",):
            options = ["options", "info", "vars", "globals", "history", "modules"]
            return [o for o in options if o.startswith(text)]
        elif cmd == "start":
            services = ["gosh", "php", "nc", "listener"]
            return [s for s in services if s.startswith(text)]
        elif cmd in ("claude", "ai"):
            subcmds = ["mode", "resume", "fg", "sessions", "analyze", "debug", "ask", "model", "status", "help"]
            return [s for s in subcmds if s.startswith(text)]
        elif cmd == "sliver":
            subcmds = ["start", "stop", "connect", "resume", "fg", "status", "configs", "help"]
            return [s for s in subcmds if s.startswith(text)]
        elif cmd == "penelope":
            subcmds = ["resume", "fg", "status", "help"]
            return [s for s in subcmds if s.startswith(text)]
        elif cmd == "ligolo":
            subcmds = ["resume", "fg", "status", "agents", "route", "routes", "help"]
            return [s for s in subcmds if s.startswith(text)]

        return []

    def _complete_modules(self, text: str) -> List[str]:
        """Complete module paths - matches name anywhere"""
        modules = self.console.loader.get_all_modules()
        matches = []
        text_lower = text.lower()
        
        for path, info in modules.items():
            # Match full path from start
            if path.lower().startswith(text_lower):
                matches.append(path)
            # Match module name from start (e.g., "blood" matches "bloodhound_collect")
            elif info.name.lower().startswith(text_lower):
                matches.append(info.name)
            # Match if text appears anywhere in name
            elif text_lower in info.name.lower():
                matches.append(info.name)
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                unique.append(m)
        
        return unique

    def _complete_variables(self, text: str) -> List[str]:
        """Complete variable names"""
        text = text.upper()
        all_vars = set(self.console.config.known_variables.keys())
        all_vars.update(self.console.config.get_all_vars().keys())
        all_vars.update(self.console.config.get_all_history().keys())

        if self.console.current_module:
            all_vars.update(self.console.current_module.get_options().keys())

        return [v for v in all_vars if v.startswith(text)]

    def _complete_history(self, var_name: str, text: str) -> List[str]:
        """Complete from variable history"""
        history = self.console.config.get_history_values(var_name)
        return [str(v) for v in history if str(v).startswith(text)]

    def _complete_search(self, text: str) -> List[str]:
        """Complete search terms"""
        # Common search terms
        terms = ["smb", "rdp", "ssh", "http", "web", "linux", "windows",
                 "enumeration", "scanner", "exploit", "auxiliary"]
        return [t for t in terms if t.startswith(text.lower())]


class UwUConsole:
    """Main interactive console"""

    def __init__(self, config: Config, quiet: bool = False):
        self.config = config
        self.loader = ModuleLoader(config.get_config("modules_path"))
        self.current_module: Optional[ModuleBase] = None
        self.running = False
        self.quiet = quiet

        # Command registry
        self.commands: Dict[str, Callable] = {
            # Core commands
            "help": self.cmd_help,
            "?": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
            "clear": self.cmd_clear,
            "banner": self.cmd_banner,

            # Module commands
            "use": self.cmd_use,
            "back": self.cmd_back,
            "info": self.cmd_info,
            "options": self.cmd_options,
            "run": self.cmd_run,
            "exploit": self.cmd_run,
            "check": self.cmd_check,
            "search": self.cmd_search,
            "reload": self.cmd_reload,

            # Variable commands
            "set": self.cmd_set,
            "get": self.cmd_get,
            "setg": self.cmd_setg,
            "getg": self.cmd_getg,
            "setp": self.cmd_setp,
            "getp": self.cmd_getp,
            "unset": self.cmd_unset,
            "unsetg": self.cmd_unsetg,
            "unsetp": self.cmd_unsetp,
            "show": self.cmd_show,
            "showp": self.cmd_showp,
            "vars": self.cmd_vars,
            "globals": self.cmd_globals,
            "history": self.cmd_history,
            "cleang": self.cmd_cleang,
            "cleanp": self.cmd_cleanp,

            # Server utilities
            "start": self.cmd_start,
            "stop": self.cmd_stop,
            "listeners": self.cmd_listeners,

            # Shell management (Sliver-like)
            "sessions": self.cmd_shells,  # List all sessions
            "session": self.cmd_interact,  # session <id> to connect
            "interact": self.cmd_interact,  # alias for session
            "kill": self.cmd_kill_shell,
            "listen": self.cmd_listen,

            # Shell escape
            "shell": self.cmd_shell,
            "!": self.cmd_shell,

            # Export
            "export": self.cmd_export,

            # Claude AI
            "claude": self.cmd_claude,
            "ai": self.cmd_claude,

            # Sliver C2
            "sliver": self.cmd_sliver,

            # Penelope shell handler
            "penelope": self.cmd_penelope,

            # Ligolo-ng tunneling
            "ligolo": self.cmd_ligolo,

            # Potato exploits
            "potatoes": self.cmd_potatoes,

            # NXC module help
            "nxc": self.cmd_nxc,

            # Credential management
            "creds": self.cmd_creds,

            # Hosts file / domain discovery
            "hosts": self.cmd_hosts,

            # Status overview
            "status": self.cmd_status,
        }

        # Credential manager
        self.cred_manager = CredentialManager(str(config.config_dir))

        # Active background processes
        self.processes: Dict[str, subprocess.Popen] = {}

        # Claude AI assistant and interactive mode
        self.claude = ClaudeAssistant(config)
        self.claude_mode = ClaudeMode(self.claude, config)

        # Sliver C2 integration
        self.sliver_client = SliverClient(config)
        self.sliver_mode = SliverMode(self.sliver_client, config)
        self.sliver_server = SliverServer(self.sliver_client)

        # Penelope shell handler integration
        self.penelope_mode = get_penelope_mode(config)

        # Ligolo-ng tunneling integration
        self.ligolo_mode = get_ligolo_mode(config)

        # Shell manager (Sliver-like shell handling)
        self.shell_manager = get_shell_manager()

        # Setup readline
        self._setup_readline()

        # Discover modules
        self.loader.discover_modules()

    def _setup_readline(self) -> None:
        """Configure readline for tab completion and history"""
        # History file
        history_file = self.config.config_dir / "command_history"
        try:
            readline.read_history_file(history_file)
        except FileNotFoundError:
            pass

        readline.set_history_length(1000)

        # Save history on exit
        import atexit
        atexit.register(lambda: readline.write_history_file(history_file))

        # Tab completion
        completer = Completer(self)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t\n")

    def _find_exegol_container(self) -> Optional[str]:
        """Auto-detect a running Exegol container"""
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5
            )
            for name in result.stdout.strip().split('\n'):
                if name.startswith("exegol-"):
                    return name
        except:
            pass
        return None

    def _is_inside_exegol(self) -> bool:
        """Check if we're running inside an Exegol container"""
        return os.path.exists("/.exegol") or os.path.exists("/opt/.exegol_aliases")

    def _get_nxc_module_help(self, module_name: Optional[str] = None) -> Optional[str]:
        """
        Get NXC module options.
        Args:
            module_name: NXC module name (uses NXC_MODULE from config if not provided)
        Returns formatted help text or None.
        """
        from core.colors import Colors

        # Get module name from argument or config
        nxc_module = module_name or self.config.getg("NXC_MODULE") or self.config.get("NXC_MODULE")
        if not nxc_module:
            return f"\n{Colors.NEON_RED}NXC_MODULE not set. Use: set NXC_MODULE <module_name>{Colors.RESET}\n"

        # Get protocol (default to smb)
        protocol = (self.config.getg("PROTOCOL") or
                    self.config.get("PROTOCOL") or
                    self.config.getg("NXC_PROTOCOL") or
                    self.config.get("NXC_PROTOCOL") or
                    "smb")

        # Build command to get module options
        exegol_path = "/root/.local/bin:/opt/tools/bin:/opt/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        nxc_cmd = f"netexec {protocol} -M {nxc_module} --options 2>&1"

        try:
            # Check if we're inside Exegol - run directly
            if self._is_inside_exegol():
                result = subprocess.run(
                    ["bash", "-c", f"export PATH={exegol_path}:$PATH && {nxc_cmd}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                # Get container for docker exec
                container = (self.config.getg("EXEGOL_CONTAINER") or
                             self.config.get("EXEGOL_CONTAINER") or
                             self._find_exegol_container())

                if not container:
                    return f"\n{Colors.NEON_ORANGE}NXC Module Help{Colors.RESET}\n{Colors.NEON_ORANGE}==============={Colors.RESET}\n  {Colors.NEON_RED}No Exegol container found. Start one to see module options.{Colors.RESET}\n"

                result = subprocess.run(
                    ["docker", "exec", container, "bash", "-ic", f"export PATH={exegol_path}:$PATH && {nxc_cmd}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

            output = result.stdout + result.stderr

            # Parse the output to extract module options
            lines = output.strip().split('\n')
            option_lines = []
            capture = False

            for line in lines:
                # Start capturing after "module options:" line
                if "module options:" in line.lower():
                    capture = True
                    continue
                # Skip initialization messages
                if line.startswith("[*]") and ("Adding" in line or "Creating" in line or "Initializing" in line):
                    continue
                # Skip bash error/noise messages
                if line.startswith("bash:") or "ioctl" in line or "job control" in line:
                    continue
                if capture and line.strip():
                    option_lines.append(line)

            if not option_lines:
                return f"\n{Colors.NEON_ORANGE}NXC Module: {nxc_module}{Colors.RESET}\n{Colors.NEON_ORANGE}{'=' * (12 + len(nxc_module))}{Colors.RESET}\n  {Colors.NEON_RED}No options found or module not available.{Colors.RESET}\n"

            # Format output
            help_text = f"\n{Colors.NEON_ORANGE}NXC Module: {nxc_module} ({protocol}){Colors.RESET}\n"
            help_text += f"{Colors.NEON_ORANGE}{'=' * (13 + len(nxc_module) + len(protocol) + 3)}{Colors.RESET}\n"
            help_text += f"  {Colors.BRIGHT_WHITE}Set options with:{Colors.RESET} {Colors.NEON_CYAN}set NXC_MODULE_OPTIONS \"KEY=value,KEY2=value2\"{Colors.RESET}\n\n"

            for line in option_lines:
                # Parse option name and description
                parts = line.strip().split(None, 1)
                if len(parts) >= 2:
                    opt_name, opt_desc = parts[0], parts[1]
                    help_text += f"  {Colors.NEON_CYAN}{opt_name:<15}{Colors.RESET} {opt_desc}\n"
                elif parts:
                    help_text += f"  {Colors.NEON_CYAN}{parts[0]}{Colors.RESET}\n"

            return help_text

        except subprocess.TimeoutExpired:
            return f"\n{Colors.NEON_ORANGE}NXC Module Help{Colors.RESET}\n{Colors.NEON_ORANGE}==============={Colors.RESET}\n  {Colors.NEON_RED}Timeout fetching module options.{Colors.RESET}\n"
        except Exception as e:
            return f"\n{Colors.NEON_ORANGE}NXC Module Help{Colors.RESET}\n{Colors.NEON_ORANGE}==============={Colors.RESET}\n  {Colors.NEON_RED}Error: {e}{Colors.RESET}\n"

    def cmd_nxc(self, args: List[str]) -> None:
        """Show NXC module options"""
        # If argument provided, use it as module name
        module_name = args[0] if args else None
        result = self._get_nxc_module_help(module_name)
        if result:
            print(result)

    def cmd_creds(self, args: List[str]) -> None:
        """
        Manage pwned credentials

        Usage:
            creds                      - List all credentials
            creds add <user> <pass>    - Add user with password
            creds add <user> -h <hash> - Add user with NTLM hash
            creds add <user> -d <domain> <pass> - Add with domain
            creds del <user>           - Delete credential
            creds use <user>           - Set USER/PASS from cred
            creds search <query>       - Search credentials
            creds show                 - Show with secrets visible
            creds clear                - Clear all credentials
            creds import <file>        - Import from secretsdump
        """
        if not args:
            # List all creds (hidden secrets)
            creds = self.cred_manager.list_all()
            print_creds_table(creds, show_secrets=False)
            return

        subcmd = args[0].lower()

        if subcmd in ("help", "info", "?"):
            from core.colors import Colors
            print(f"""
{Colors.NEON_PINK}Credential Commands{Colors.RESET}
{Colors.NEON_PINK}==================={Colors.RESET}

  {Colors.NEON_CYAN}creds{Colors.RESET}                       List all credentials (secrets hidden)
  {Colors.NEON_CYAN}creds show{Colors.RESET}                  List all credentials (secrets visible)

{Colors.BRIGHT_WHITE}Adding Credentials:{Colors.RESET}
  {Colors.NEON_CYAN}creds add <user> <pass>{Colors.RESET}     Add user with password
  {Colors.NEON_CYAN}creds add <user> -h <hash>{Colors.RESET}  Add user with NTLM hash
  {Colors.NEON_CYAN}creds add <user> -d <domain> <pass>{Colors.RESET}
                                Add user with domain

{Colors.BRIGHT_WHITE}Using Credentials:{Colors.RESET}
  {Colors.NEON_CYAN}creds use <id>{Colors.RESET}              Load credential by ID (e.g., creds use 1)
  {Colors.NEON_CYAN}creds use <user>{Colors.RESET}            Load credential by username
  {Colors.NEON_CYAN}creds use domain\\\\user{Colors.RESET}      Load specific domain user

{Colors.BRIGHT_WHITE}Managing Credentials:{Colors.RESET}
  {Colors.NEON_CYAN}creds del <id|user>{Colors.RESET}         Delete credential by ID or username
  {Colors.NEON_CYAN}creds search <query>{Colors.RESET}        Search by username/domain
  {Colors.NEON_CYAN}creds clear{Colors.RESET}                 Delete all credentials

{Colors.BRIGHT_WHITE}Import/Export:{Colors.RESET}
  {Colors.NEON_CYAN}creds import <file>{Colors.RESET}         Import from secretsdump output
  {Colors.NEON_CYAN}creds export hashcat{Colors.RESET}        Export hashes for hashcat
  {Colors.NEON_CYAN}creds export secretsdump{Colors.RESET}    Export in secretsdump format

{Colors.BRIGHT_WHITE}Related:{Colors.RESET}
  {Colors.NEON_CYAN}hosts{Colors.RESET}                       Generate /etc/hosts & auto-set DOMAIN
  {Colors.NEON_CYAN}hosts -u{Colors.RESET}                    Also update creds without domain
""")
            return

        if subcmd == "add":
            # Parse: creds add <user> [options] <pass_or_hash>
            if len(args) < 2:
                print(Style.error("Usage: creds add <user> [-d domain] [-h hash | password]"))
                return

            username = args[1]
            password = None
            ntlm_hash = None
            domain = None
            source = None
            notes = None

            i = 2
            while i < len(args):
                if args[i] == "-d" and i + 1 < len(args):
                    domain = args[i + 1]
                    i += 2
                elif args[i] == "-h" and i + 1 < len(args):
                    ntlm_hash = args[i + 1]
                    i += 2
                elif args[i] == "-s" and i + 1 < len(args):
                    source = args[i + 1]
                    i += 2
                elif args[i] == "-n" and i + 1 < len(args):
                    notes = args[i + 1]
                    i += 2
                elif not args[i].startswith("-"):
                    password = args[i]
                    i += 1
                else:
                    i += 1

            if not password and not ntlm_hash:
                print(Style.error("Must provide password or hash (-h)"))
                return

            self.cred_manager.add(
                username=username,
                password=password,
                ntlm_hash=ntlm_hash,
                domain=domain,
                source=source,
                notes=notes
            )

            display = f"{domain}\\{username}" if domain else username
            print(Style.success(f"Added credential: {display}"))

        elif subcmd in ("del", "delete", "rm"):
            if len(args) < 2:
                print(Style.error("Usage: creds del <id|user>"))
                return

            # Check if arg is a numeric ID
            if args[1].isdigit():
                cred_id = int(args[1])
                cred = self.cred_manager.get_by_id(cred_id)
                if cred and self.cred_manager.delete_by_id(cred_id):
                    print(Style.success(f"Deleted credential #{cred_id}: {cred.get('username')}"))
                else:
                    print(Style.error(f"Credential ID {cred_id} not found"))
            else:
                username = args[1]
                domain = None
                if "\\" in username:
                    domain, username = username.split("\\", 1)

                if self.cred_manager.delete(username, domain):
                    print(Style.success(f"Deleted credential: {args[1]}"))
                else:
                    print(Style.error(f"Credential not found: {args[1]}"))

        elif subcmd == "use":
            if len(args) < 2:
                print(Style.error("Usage: creds use <id|user>"))
                return

            # Check if arg is a numeric ID
            if args[1].isdigit():
                cred_id = int(args[1])
                cred = self.cred_manager.get_by_id(cred_id)
                if not cred:
                    print(Style.error(f"Credential ID {cred_id} not found"))
                    return
            else:
                username = args[1]
                domain = None
                if "\\" in username:
                    domain, username = username.split("\\", 1)

                cred = self.cred_manager.get(username, domain)
                if not cred:
                    print(Style.error(f"Credential not found: {args[1]}"))
                    return

            # Set variables from credential (config + module)
            if cred.get("username"):
                self.config.set("USER", cred["username"])
                if self.current_module:
                    self.current_module.set_option("USER", cred["username"])
                print(Style.info(f"USER => {cred['username']}"))

            if cred.get("password"):
                self.config.set("PASS", cred["password"])
                if self.current_module:
                    self.current_module.set_option("PASS", cred["password"])
                print(Style.info(f"PASS => {cred['password']}"))
            elif cred.get("ntlm_hash"):
                self.config.set("PASS", cred["ntlm_hash"])
                if self.current_module:
                    self.current_module.set_option("PASS", cred["ntlm_hash"])
                print(Style.info(f"PASS => {cred['ntlm_hash']} (hash)"))

            if cred.get("domain"):
                self.config.set("DOMAIN", cred["domain"])
                if self.current_module:
                    self.current_module.set_option("DOMAIN", cred["domain"])
                print(Style.info(f"DOMAIN => {cred['domain']}"))

            print(Style.success(f"Loaded credential: {args[1]}"))

        elif subcmd == "search":
            if len(args) < 2:
                print(Style.error("Usage: creds search <query>"))
                return

            results = self.cred_manager.search(args[1])
            print_creds_table(results, show_secrets=False)

        elif subcmd in ("show", "list"):
            # Show all creds with secrets visible
            show_secrets = subcmd == "show" or (len(args) > 1 and args[1] == "-s")
            creds = self.cred_manager.list_all()
            print_creds_table(creds, show_secrets=show_secrets)

        elif subcmd == "clear":
            count = self.cred_manager.clear_all()
            print(Style.success(f"Cleared {count} credential(s)"))

        elif subcmd == "import":
            if len(args) < 2:
                print(Style.error("Usage: creds import <secretsdump_file>"))
                return

            filepath = args[1]
            if not os.path.exists(filepath):
                print(Style.error(f"File not found: {filepath}"))
                return

            count = self.cred_manager.import_secretsdump(filepath)
            print(Style.success(f"Imported {count} credential(s) from {filepath}"))

        elif subcmd == "export":
            fmt = args[1] if len(args) > 1 else "hashcat"
            output = args[2] if len(args) > 2 else None

            if fmt == "hashcat":
                content = self.cred_manager.export_hashcat(output)
            else:
                content = self.cred_manager.export_secretsdump(output)

            if output:
                print(Style.success(f"Exported to {output}"))
            else:
                print(content)

        else:
            print(Style.error(f"Unknown subcommand: {subcmd}"))
            print("Usage: creds [add|del|use|search|show|clear|import|export]")

    def cmd_hosts(self, args: List[str]) -> None:
        """
        Generate /etc/hosts from target and auto-discover domain

        Usage:
            hosts              - Use RHOSTS to generate hosts file
            hosts <ip>         - Use specified IP
            hosts -u           - Also update all creds without domain
        """
        import re
        import tempfile

        # Get target IP
        target = None
        update_creds = False

        for arg in args:
            if arg == "-u":
                update_creds = True
            elif not arg.startswith("-"):
                target = arg

        if not target:
            target = self.config.getg("RHOSTS") or self.config.get("RHOSTS")

        if not target:
            print(Style.error("No target. Set RHOSTS or provide IP: hosts <ip>"))
            return

        # Build command - write to temp file first to check for duplicates
        exegol_path = "/root/.local/bin:/opt/tools/bin:/opt/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        tmp_hosts = "/tmp/.uwu_hosts_tmp"
        nxc_cmd = f"netexec smb {target} --generate-hosts-file {tmp_hosts} 2>&1"

        print(Style.info(f"Discovering hosts for {target}..."))

        try:
            if self._is_inside_exegol():
                # Run nxc to temp file
                result = subprocess.run(
                    ["bash", "-c", f"export PATH={exegol_path}:$PATH && rm -f {tmp_hosts} && {nxc_cmd}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout + result.stderr
                print(output)

                # Read the temp hosts file
                try:
                    with open(tmp_hosts, 'r') as f:
                        new_entry = f.read().strip()
                except FileNotFoundError:
                    new_entry = None

                # Read current /etc/hosts
                with open('/etc/hosts', 'r') as f:
                    current_hosts = f.read()

                # Check if entry already exists (check by IP)
                if new_entry:
                    new_ip = new_entry.split()[0] if new_entry else None
                    if new_ip and new_ip in current_hosts:
                        print(Style.warning(f"Entry for {new_ip} already exists in /etc/hosts"))
                    else:
                        # Append new entry
                        with open('/etc/hosts', 'a') as f:
                            f.write(new_entry + '\n')
                        print(Style.success(f"Added to /etc/hosts: {new_entry}"))

            else:
                container = (self.config.getg("EXEGOL_CONTAINER") or
                             self.config.get("EXEGOL_CONTAINER") or
                             self._find_exegol_container())

                if not container:
                    print(Style.error("No Exegol container found"))
                    return

                # Run nxc to temp file
                result = subprocess.run(
                    ["docker", "exec", container, "bash", "-ic",
                     f"export PATH={exegol_path}:$PATH && rm -f {tmp_hosts} && {nxc_cmd}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout + result.stderr
                print(output)

                # Read the temp hosts file from container
                tmp_result = subprocess.run(
                    ["docker", "exec", container, "cat", tmp_hosts],
                    capture_output=True, text=True, timeout=5
                )
                new_entry = tmp_result.stdout.strip() if tmp_result.returncode == 0 else None

                # Read current /etc/hosts from container
                hosts_result = subprocess.run(
                    ["docker", "exec", container, "cat", "/etc/hosts"],
                    capture_output=True, text=True, timeout=5
                )
                current_hosts = hosts_result.stdout

                # Check if entry already exists
                if new_entry:
                    new_ip = new_entry.split()[0] if new_entry else None
                    if new_ip and new_ip in current_hosts:
                        print(Style.warning(f"Entry for {new_ip} already exists in /etc/hosts"))
                    else:
                        # Append new entry
                        subprocess.run(
                            ["docker", "exec", container, "bash", "-c",
                             f"echo '{new_entry}' >> /etc/hosts"],
                            timeout=5
                        )
                        print(Style.success(f"Added to /etc/hosts: {new_entry}"))

            # Parse domain from output: (domain:hack.smarter)
            domain_match = re.search(r'\(domain:([^\)]+)\)', output)
            if domain_match:
                domain = domain_match.group(1)
                self.config.setg("DOMAIN", domain)
                print(Style.success(f"DOMAIN => {domain} (global)"))

                # Update creds without domain if requested
                if update_creds:
                    updated = 0
                    for key, cred in self.cred_manager.credentials.items():
                        if not cred.get("domain"):
                            cred["domain"] = domain
                            updated += 1
                    if updated:
                        self.cred_manager._save()
                        print(Style.success(f"Updated {updated} credential(s) with domain {domain}"))
            else:
                print(Style.warning("Could not parse domain from output"))

            # Parse hostname: (name:DC01)
            name_match = re.search(r'\(name:([^\)]+)\)', output)
            if name_match:
                hostname = name_match.group(1)
                self.config.setg("DC", hostname)
                print(Style.info(f"DC => {hostname} (global)"))

        except subprocess.TimeoutExpired:
            print(Style.error("Command timed out"))
        except Exception as e:
            print(Style.error(f"Error: {e}"))

    def get_prompt(self) -> str:
        """Generate the command prompt (readline-safe with proper ANSI wrapping)"""
        if self.current_module:
            module_name = Style.module_prompt(self.current_module.name)
            return f"{MINI_BANNER_PROMPT} {module_name} > "
        return f"{MINI_BANNER_PROMPT} > "

    def run(self) -> None:
        """Main interactive loop"""
        self.running = True

        # Print banner unless quiet mode
        if not self.quiet:
            print(BANNER)

            # Print module stats
            counts = self.loader.get_module_types()
            total = sum(counts.values())
            print(f"  {total} modules loaded")
            for mtype, count in counts.items():
                if count > 0:
                    print(f"    - {count} {mtype}")

            # Show working directory if set
            working_dir = self.config.get_working_dir()
            if working_dir and working_dir != os.getcwd():
                print(f"\n  {Style.info(f'Working directory: {working_dir}')}")
            print()

        # Signal handler for Ctrl+C
        def sigint_handler(sig, frame):
            print("\n" + Style.info("Use 'exit' to quit"))

        signal.signal(signal.SIGINT, sigint_handler)

        while self.running:
            try:
                line = input(self.get_prompt()).strip()
                if line:
                    self.execute_command(line)
            except EOFError:
                print()
                self.cmd_exit([])
            except KeyboardInterrupt:
                print()
                continue

    def execute_command(self, line: str) -> None:
        """Execute a command line"""
        # Handle shell escape
        if line.startswith("!"):
            self.cmd_shell(line[1:].split())
            return

        parts = line.split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in self.commands:
            try:
                self.commands[cmd](args)
            except Exception as e:
                print(Style.error(f"Command error: {e}"))
                import traceback
                traceback.print_exc()
        else:
            print(Style.error(f"Unknown command: {cmd}"))
            print(Style.info("Type 'help' for available commands"))

    # =========================================================================
    # Core Commands
    # =========================================================================

    def cmd_help(self, args: List[str]) -> None:
        """Show help information"""
        from core.colors import Colors

        # Colorized help with gradient titles like UWU logo
        print(f"""
{Colors.NEON_PINK}Core Commands{Colors.RESET}
{Colors.NEON_PINK}============={Colors.RESET}
  {Colors.NEON_CYAN}help, ?{Colors.RESET}            Show this help message
  {Colors.NEON_CYAN}exit, quit{Colors.RESET}         Exit the console
  {Colors.NEON_CYAN}clear{Colors.RESET}              Clear the screen
  {Colors.NEON_CYAN}banner{Colors.RESET}             Display the banner

{Colors.NEON_MAGENTA}Module Commands{Colors.RESET}
{Colors.NEON_MAGENTA}==============={Colors.RESET}
  {Colors.NEON_CYAN}use <module>{Colors.RESET}       Select a module to use
  {Colors.NEON_CYAN}back{Colors.RESET}               Deselect the current module
  {Colors.NEON_CYAN}info{Colors.RESET}               Display information about the current module
  {Colors.NEON_CYAN}options{Colors.RESET}            Display module options
  {Colors.NEON_CYAN}run, exploit{Colors.RESET}       Execute the current module
  {Colors.NEON_CYAN}check{Colors.RESET}              Check if target is vulnerable
  {Colors.NEON_CYAN}search <term>{Colors.RESET}      Search for modules
  {Colors.NEON_CYAN}reload{Colors.RESET}             Reload the current module

{Colors.NEON_PURPLE}Variable Commands{Colors.RESET}
{Colors.NEON_PURPLE}================={Colors.RESET}
  {Colors.NEON_CYAN}set <var> <val>{Colors.RESET}    Set a module variable
  {Colors.NEON_CYAN}setg <var> <val>{Colors.RESET}   Set a global variable (persists)
  {Colors.NEON_CYAN}unset <var>{Colors.RESET}        Unset a module variable
  {Colors.NEON_CYAN}unsetg <var>{Colors.RESET}       Unset a global variable
  {Colors.NEON_CYAN}show <what>{Colors.RESET}        Show vars/globals/options/history/modules
  {Colors.NEON_CYAN}vars{Colors.RESET}               Show all current variables
  {Colors.NEON_CYAN}globals{Colors.RESET}            Show global variables
  {Colors.NEON_CYAN}history [var]{Colors.RESET}      Show variable history

{Colors.NEON_BLUE}Server Utilities{Colors.RESET}
{Colors.NEON_BLUE}================{Colors.RESET}
  {Colors.NEON_CYAN}start gosh [port]{Colors.RESET}  Start Gosh HTTP server (default: 8000)
  {Colors.NEON_CYAN}start php [port]{Colors.RESET}   Start PHP server (default: 8080)
  {Colors.NEON_CYAN}start nc <port>{Colors.RESET}    Start netcat listener with rlwrap
  {Colors.NEON_CYAN}stop <id>{Colors.RESET}          Stop a running service
  {Colors.NEON_CYAN}listeners{Colors.RESET}          List active listeners/servers

{Colors.NEON_ORANGE}Shell Management{Colors.RESET}
{Colors.NEON_ORANGE}================{Colors.RESET}
  {Colors.NEON_CYAN}listen <port> [type]{Colors.RESET}  Start listener (nc/penelope)
  {Colors.NEON_CYAN}shells, sessions{Colors.RESET}      List active shell sessions
  {Colors.NEON_CYAN}interact <id>{Colors.RESET}         Interact with shell (Ctrl+D to return)
  {Colors.NEON_CYAN}kill <id>{Colors.RESET}             Kill a shell session

{Colors.NEON_GREEN}Claude AI{Colors.RESET}
{Colors.NEON_GREEN}========={Colors.RESET}
  {Colors.NEON_CYAN}claude mode{Colors.RESET}            Enter interactive Claude mode
  {Colors.NEON_CYAN}claude resume, fg{Colors.RESET}      Resume backgrounded Claude session
  {Colors.NEON_CYAN}claude sessions{Colors.RESET}        List Claude sessions
  {Colors.NEON_CYAN}claude analyze <path>{Colors.RESET}  Scan code for vulnerabilities
  {Colors.NEON_CYAN}claude debug <path>{Colors.RESET}    Debug code for errors
  {Colors.NEON_CYAN}claude ask "question"{Colors.RESET}  Ask Claude a question
  {Colors.NEON_CYAN}claude help{Colors.RESET}            Full Claude command help

{Colors.NEON_ORANGE}Sliver C2{Colors.RESET}
{Colors.NEON_ORANGE}========={Colors.RESET}
  {Colors.NEON_CYAN}sliver start{Colors.RESET}           Start Sliver server (background)
  {Colors.NEON_CYAN}sliver stop{Colors.RESET}            Stop Sliver server
  {Colors.NEON_CYAN}sliver connect{Colors.RESET}         Connect to server (client)
  {Colors.NEON_CYAN}sliver resume, fg{Colors.RESET}      Resume backgrounded client
  {Colors.NEON_CYAN}sliver status{Colors.RESET}          Check server/client status
  {Colors.NEON_CYAN}sliver help{Colors.RESET}            Full Sliver command help

{Colors.NEON_PINK}Penelope Shell Handler{Colors.RESET}
{Colors.NEON_PINK}======================{Colors.RESET}
  {Colors.NEON_CYAN}penelope [port]{Colors.RESET}        Start Penelope listener (default: 4444)
  {Colors.NEON_CYAN}penelope resume, fg{Colors.RESET}    Resume backgrounded session
  {Colors.NEON_CYAN}penelope status{Colors.RESET}        Check Penelope status
  {Colors.NEON_CYAN}penelope help{Colors.RESET}          Full Penelope command help

{Colors.NEON_PURPLE}Ligolo-ng Tunneling{Colors.RESET}
{Colors.NEON_PURPLE}==================={Colors.RESET}
  {Colors.NEON_CYAN}ligolo [port]{Colors.RESET}          Start Ligolo proxy (default: 11601)
  {Colors.NEON_CYAN}ligolo download{Colors.RESET}        Download latest agents from GitHub
  {Colors.NEON_CYAN}ligolo resume, fg{Colors.RESET}      Resume backgrounded session
  {Colors.NEON_CYAN}ligolo agents{Colors.RESET}          List connected agents
  {Colors.NEON_CYAN}ligolo route add <net>{Colors.RESET} Add route through tunnel
  {Colors.NEON_CYAN}ligolo status{Colors.RESET}          Check Ligolo status
  {Colors.NEON_CYAN}ligolo info{Colors.RESET}            Full Ligolo command info

{Colors.NEON_RED}Credentials{Colors.RESET}
{Colors.NEON_RED}==========={Colors.RESET}
  {Colors.NEON_CYAN}creds{Colors.RESET}                  List pwned credentials
  {Colors.NEON_CYAN}creds add <user> <pass>{Colors.RESET} Add credential (use -h for hash, -d for domain)
  {Colors.NEON_CYAN}creds del <user>{Colors.RESET}       Delete credential
  {Colors.NEON_CYAN}creds use <user>{Colors.RESET}       Load cred into USER/PASS/DOMAIN
  {Colors.NEON_CYAN}creds show{Colors.RESET}             Show creds with secrets visible
  {Colors.NEON_CYAN}creds import <file>{Colors.RESET}    Import from secretsdump output

{Colors.DIGITAL_RAIN}Other{Colors.RESET}
{Colors.DIGITAL_RAIN}====={Colors.RESET}
  {Colors.NEON_CYAN}shell, !<cmd>{Colors.RESET}      Execute shell command
  {Colors.NEON_CYAN}export{Colors.RESET}             Export variables for shell use
  {Colors.NEON_CYAN}nxc [module]{Colors.RESET}       Show NXC module options (uses NXC_MODULE if not specified)
  {Colors.NEON_CYAN}hosts [ip]{Colors.RESET}         Generate /etc/hosts & auto-set DOMAIN (-u to update creds)
""")

    def cmd_exit(self, args: List[str]) -> None:
        """Exit the console"""
        # Stop all background processes
        for name, proc in self.processes.items():
            print(Style.info(f"Stopping {name}..."))
            proc.terminate()

        print(Style.success("Goodbye!"))
        self.running = False

    def cmd_clear(self, args: List[str]) -> None:
        """Clear the screen"""
        os.system("clear" if os.name != "nt" else "cls")

    def cmd_banner(self, args: List[str]) -> None:
        """Display the banner"""
        print(BANNER)

    # =========================================================================
    # Module Commands
    # =========================================================================

    def cmd_use(self, args: List[str]) -> None:
        """Select a module"""
        if not args:
            print(Style.error("Usage: use <module_path>"))
            return

        module_path = args[0].lower()

        # Common aliases
        aliases = {
            "nxc": "netexec",
            "cme": "netexec",
            "crackmapexec": "netexec",
            "e4l": "enum4linux",
            "enum4linux-ng": "enum4linux",
        }
        if module_path in aliases:
            module_path = aliases[module_path]

        # Try to load the module directly
        module = self.loader.load_module(module_path)
        if not module:
            # Try partial match
            matches = self.loader.search(module_path)

            # Prioritize: exact name > name contains > tag matches
            exact_matches = [m for m in matches if m.name.lower() == module_path]
            name_matches = [m for m in matches if module_path in m.name.lower()]

            if len(exact_matches) == 1:
                module = self.loader.load_module(exact_matches[0].path)
            elif exact_matches:
                module = self.loader.load_module(exact_matches[0].path)
            elif len(name_matches) == 1:
                module = self.loader.load_module(name_matches[0].path)
            elif name_matches:
                # Multiple name matches - show selection menu
                module = self._select_module(name_matches, module_path)
            elif len(matches) == 1:
                module = self.loader.load_module(matches[0].path)
            elif len(matches) > 1:
                # Multiple matches - show selection menu
                module = self._select_module(matches, module_path)
            else:
                print(Style.error(f"Module not found: {module_path}"))
                return

        if module:
            module.set_config(self.config)
            self.current_module = module
            print(Style.module_selected(module.full_path))

    def _select_module(self, matches: list, search_term: str):
        """Show numbered selection menu for multiple module matches"""
        print(Style.warning(f"Multiple modules match '{search_term}':"))
        print()

        # Limit to 15 matches
        display_matches = matches[:15]

        for i, m in enumerate(display_matches, 1):
            # Highlight the matching part in the name
            desc = m.description[:50] + "..." if len(m.description) > 50 else m.description
            print(f"  {Colors.NEON_CYAN}[{i}]{Colors.RESET} {m.path}")
            print(f"      {Colors.DIM}{desc}{Colors.RESET}")

        if len(matches) > 15:
            print(f"\n  {Colors.DIM}... and {len(matches) - 15} more matches{Colors.RESET}")

        print()
        try:
            choice = input(f"{Colors.NEON_MAGENTA}Select module [1-{len(display_matches)}] or Enter to cancel: {Colors.RESET}").strip()
            if not choice:
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(display_matches):
                return self.loader.load_module(display_matches[idx].path)
            else:
                print(Style.error("Invalid selection"))
                return None
        except ValueError:
            print(Style.error("Invalid input"))
            return None
        except (KeyboardInterrupt, EOFError):
            print()
            return None

    def cmd_back(self, args: List[str]) -> None:
        """Deselect current module"""
        if self.current_module:
            self.current_module = None
            self.config.clear_session()
            print(Style.info("Module deselected"))

    def cmd_info(self, args: List[str]) -> None:
        """Show module information"""
        if not self.current_module:
            print(Style.error("No module selected"))
            return
        print(self.current_module.info())

    def cmd_options(self, args: List[str]) -> None:
        """Show module options"""
        if not self.current_module:
            print(Style.error("No module selected"))
            return
        print(self.current_module.options_table())

    def cmd_run(self, args: List[str]) -> None:
        """Run the current module"""
        if not self.current_module:
            print(Style.error("No module selected"))
            return

        # Validate options
        valid, errors = self.current_module.validate_options()
        if not valid:
            print(Style.error("Required options not set:"))
            for err in errors:
                print(f"  - {err}")
            return

        print(Style.info(f"Running {self.current_module.name}..."))
        print()

        try:
            success = self.current_module.run()
            print()
            if success:
                print(Style.success("Module completed successfully"))
            else:
                print(Style.warning("Module completed with errors"))
        except KeyboardInterrupt:
            print()
            print(Style.warning("Module interrupted"))
        except Exception as e:
            print(Style.error(f"Module failed: {e}"))
            import traceback
            traceback.print_exc()
        finally:
            self.current_module.cleanup()

    def cmd_check(self, args: List[str]) -> None:
        """Run module check"""
        if not self.current_module:
            print(Style.error("No module selected"))
            return

        print(Style.info("Running check..."))
        if self.current_module.check():
            print(Style.success("Target appears to be vulnerable"))
        else:
            print(Style.warning("Target does not appear vulnerable"))

    def cmd_search(self, args: List[str]) -> None:
        """Search for modules"""
        if not args:
            print(Style.error("Usage: search <term>"))
            return

        query = " ".join(args)
        results = self.loader.search(query)

        if not results:
            print(Style.warning(f"No modules found matching '{query}'"))
            return

        print(f"\n  {Style.highlight('Matching Modules')} ({len(results)} found)")
        print(f"  {Style.uwu('='*50)}\n")

        # Group by type
        by_type: Dict[str, List[ModuleInfo]] = {}
        for info in results:
            type_name = info.module_type.value
            if type_name not in by_type:
                by_type[type_name] = []
            by_type[type_name].append(info)

        for type_name, modules in sorted(by_type.items()):
            print(f"  {Style.title(type_name.upper())}")
            for m in modules:
                desc = m.description[:50] + "..." if len(m.description) > 50 else m.description
                print(f"    {Style.module_path(m.path)}")
                print(f"      {Style.dim(desc)}")
            print()

    def cmd_reload(self, args: List[str]) -> None:
        """Reload current module"""
        if not self.current_module:
            print(Style.error("No module selected"))
            return

        path = self.current_module.full_path
        module = self.loader.reload_module(path)
        if module:
            module.set_config(self.config)
            self.current_module = module
            print(Style.success(f"Module reloaded: {path}"))

    # =========================================================================
    # Variable Commands
    # =========================================================================

    def cmd_set(self, args: List[str]) -> None:
        """Set a session variable"""
        if len(args) < 1:
            print(Style.error("Usage: set <variable> [value]"))
            return

        var_name = args[0].upper()

        if not self._validate_var_name(var_name):
            return

        if len(args) < 2:
            # Show history for selection
            self._interactive_set(var_name, global_var=False)
            return

        value = " ".join(args[1:])

        # Set in module if active - validate option exists
        if self.current_module:
            if not self.current_module.has_option(var_name):
                # Show error and suggest similar options
                options = list(self.current_module.get_options().keys())
                print(Style.error(f"Unknown option: {var_name}"))
                # Find similar options (simple substring match)
                similar = [o for o in options if var_name[:3] in o or o[:3] in var_name]
                if similar:
                    print(Style.info(f"Did you mean: {', '.join(similar)}?"))
                print(Style.info(f"Use 'options' to see available options"))
                return
            self.current_module.set_option(var_name, value)

        # Set in session (only if no module active, or if it's a valid module option)
        self.config.set(var_name, value)
        print(f"{Style.varname(var_name)} => {Style.value(value)}")

        # Auto-populate PASS/DOMAIN from creds when setting USER
        if var_name == "USER" and hasattr(self, 'cred_manager'):
            # Check if user exists in creds
            username = value
            domain = None
            if "\\" in value:
                domain, username = value.split("\\", 1)

            cred = self.cred_manager.get(username, domain)
            if cred:
                # Auto-set PASS
                if cred.get("password"):
                    self.config.set("PASS", cred["password"])
                    if self.current_module:
                        self.current_module.set_option("PASS", cred["password"])
                    print(f"{Style.varname('PASS')} => {Style.value(cred['password'])} (from creds)")
                elif cred.get("ntlm_hash"):
                    self.config.set("PASS", cred["ntlm_hash"])
                    if self.current_module:
                        self.current_module.set_option("PASS", cred["ntlm_hash"])
                    print(f"{Style.varname('PASS')} => {Style.value(cred['ntlm_hash'])} (hash from creds)")

                # Auto-set DOMAIN if cred has it and not already in username
                if cred.get("domain") and "\\" not in value:
                    self.config.set("DOMAIN", cred["domain"])
                    if self.current_module:
                        self.current_module.set_option("DOMAIN", cred["domain"])
                    print(f"{Style.varname('DOMAIN')} => {Style.value(cred['domain'])} (from creds)")

    def _validate_var_name(self, name: str) -> bool:
        """Validate variable name - must be alphanumeric with underscores only"""
        import re
        if not name:
            return False
        if not re.match(r'^[A-Z][A-Z0-9_]*$', name.upper()):
            print(Style.error(f"Invalid variable name: {name}"))
            print(Style.info("Variable names must be alphanumeric with underscores (e.g., RHOSTS, MY_VAR)"))
            return False
        return True

    def cmd_setg(self, args: List[str]) -> None:
        """Set a global variable"""
        if len(args) < 1:
            print(Style.error("Usage: setg <variable> [value]"))
            return

        var_name = args[0].upper()

        if not self._validate_var_name(var_name):
            return

        if len(args) < 2:
            # Show history for selection
            self._interactive_set(var_name, global_var=True)
            return

        value = " ".join(args[1:])
        self.config.setg(var_name, value)
        print(f"{Style.varname(var_name)} => {Style.value(value)} (global)")

        # Auto-populate PASS/DOMAIN from creds when setting USER
        if var_name == "USER" and hasattr(self, 'cred_manager'):
            username = value
            domain = None
            if "\\" in value:
                domain, username = value.split("\\", 1)

            cred = self.cred_manager.get(username, domain)
            if cred:
                if cred.get("password"):
                    self.config.setg("PASS", cred["password"])
                    print(f"{Style.varname('PASS')} => {Style.value(cred['password'])} (from creds, global)")
                elif cred.get("ntlm_hash"):
                    self.config.setg("PASS", cred["ntlm_hash"])
                    print(f"{Style.varname('PASS')} => {Style.value(cred['ntlm_hash'])} (hash from creds, global)")

                if cred.get("domain") and "\\" not in value:
                    self.config.setg("DOMAIN", cred["domain"])
                    print(f"{Style.varname('DOMAIN')} => {Style.value(cred['domain'])} (from creds, global)")

    def cmd_get(self, args: List[str]) -> None:
        """Get a variable value (checks session > global > permanent)"""
        if len(args) < 1:
            print(Style.error("Usage: get <variable>"))
            print(Style.info("Shows the effective value from session, global, or permanent vars"))
            return

        var_name = args[0].upper()
        value = self.config.get(var_name)

        if value is not None:
            print(f"{Style.varname(var_name)} = {Style.value(value)}")
        else:
            print(Style.warning(f"{var_name} is not set"))

    def cmd_getg(self, args: List[str]) -> None:
        """Get a global variable value"""
        if len(args) < 1:
            # Show all globals
            self.cmd_globals([])
            return

        var_name = args[0].upper()
        value = self.config.getg(var_name)

        if value is not None:
            print(f"{Style.varname(var_name)} = {Style.value(value)} (global)")
        else:
            print(Style.warning(f"{var_name} is not set as a global"))

    def cmd_getp(self, args: List[str]) -> None:
        """Get a permanent variable value"""
        if len(args) < 1:
            # Show all permanent vars
            self.cmd_showp([])
            return

        var_name = args[0].upper()
        value = self.config.getp(var_name)

        if value is not None:
            print(f"{Style.varname(var_name)} = {Style.value(value)} (permanent)")
        else:
            print(Style.warning(f"{var_name} is not set as permanent"))

    def cmd_setp(self, args: List[str]) -> None:
        """Set a permanent variable (persists forever)"""
        if len(args) < 2:
            print(Style.error("Usage: setp <variable> <value>"))
            print(Style.info("Permanent variables persist across all sessions"))
            print(Style.info("Special: setp WORKING_DIR /workspace - sets default path for file variables"))
            return

        var_name = args[0].upper()

        if not self._validate_var_name(var_name):
            return

        value = " ".join(args[1:])
        self.config.setp(var_name, value)
        print(f"{Style.varname(var_name)} => {Style.value(value)} (permanent)")

    def cmd_unsetp(self, args: List[str]) -> None:
        """Unset a permanent variable"""
        if not args:
            print(Style.error("Usage: unsetp <variable>"))
            return

        var_name = args[0].upper()
        if self.config.unsetp(var_name):
            print(Style.success(f"Permanent variable {var_name} unset"))
        else:
            print(Style.warning(f"Permanent variable {var_name} not found"))

    def cmd_showp(self, args: List[str]) -> None:
        """Show all permanent variables"""
        perm_vars = self.config.get_all_permanent()
        if not perm_vars:
            print(Style.info("No permanent variables set"))
            print(Style.info("Use 'setp <variable> <value>' to set permanent variables"))
            return

        print(f"\n  Permanent Variables:")
        print(f"  {'-'*50}")
        for name, value in sorted(perm_vars.items()):
            print(f"  {Style.varname(name):<20} {Style.value(str(value))}")
        print()

    def cmd_cleang(self, args: List[str]) -> None:
        """Clean up corrupted global variables"""
        import re
        globals_dict = self.config.get_all_globals()
        cleaned = 0
        valid_pattern = re.compile(r'^[A-Z][A-Z0-9_]*$')

        for name in list(globals_dict.keys()):
            if not valid_pattern.match(name):
                self.config.unsetg(name)
                print(Style.warning(f"Removed invalid global: {name}"))
                cleaned += 1

        if cleaned:
            print(Style.success(f"Cleaned {cleaned} invalid global variable(s)"))
        else:
            print(Style.info("No corrupted globals found"))

    def cmd_cleanp(self, args: List[str]) -> None:
        """Clean up corrupted permanent variables"""
        import re
        perm_dict = self.config.get_all_permanent()
        cleaned = 0
        valid_pattern = re.compile(r'^[A-Z][A-Z0-9_]*$')

        for name in list(perm_dict.keys()):
            if not valid_pattern.match(name):
                self.config.unsetp(name)
                print(Style.warning(f"Removed invalid permanent: {name}"))
                cleaned += 1

        if cleaned:
            print(Style.success(f"Cleaned {cleaned} invalid permanent variable(s)"))
        else:
            print(Style.info("No corrupted permanent variables found"))

    def _interactive_set(self, var_name: str, global_var: bool = False) -> None:
        """Interactive variable selection from history"""
        history = self.config.get_history_values(var_name)

        if not history:
            print(Style.warning(f"No history for {var_name}"))
            value = input(f"Enter value for {var_name}: ").strip()
            if value:
                if global_var:
                    self.config.setg(var_name, value)
                else:
                    self.config.set(var_name, value)
                print(f"{Style.varname(var_name)} => {Style.value(value)}")
            return

        print(f"\n  History for {Style.varname(var_name)}:")
        print(f"  {'-'*40}")
        for i, val in enumerate(history[:20], 1):
            print(f"  [{i:2}] {val}")
        print(f"  [ 0] Enter new value")
        print()

        try:
            choice = input("Select [1]: ").strip()
            if not choice:
                choice = "1"

            idx = int(choice)
            if idx == 0:
                value = input(f"Enter value for {var_name}: ").strip()
            elif 1 <= idx <= len(history):
                value = history[idx - 1]
            else:
                print(Style.error("Invalid selection"))
                return

            if value:
                if global_var:
                    self.config.setg(var_name, value)
                else:
                    self.config.set(var_name, value)
                    if self.current_module:
                        self.current_module.set_option(var_name, value)
                print(f"{Style.varname(var_name)} => {Style.value(value)}")

        except (ValueError, KeyboardInterrupt):
            print()
            return

    def cmd_unset(self, args: List[str]) -> None:
        """Unset a variable (clears session, module option, and global)"""
        if not args:
            print(Style.error("Usage: unset <variable>"))
            return

        var_name = args[0].upper()
        unset_any = False

        # Clear session variable
        if self.config.unset(var_name):
            unset_any = True

        # Clear the module's internal option value
        if self.current_module and var_name in self.current_module._options:
            self.current_module._options[var_name].value = None
            unset_any = True

        # Also clear global if set
        if self.config.unsetg(var_name):
            unset_any = True

        # Also clear permanent if set
        if self.config.unsetp(var_name):
            unset_any = True

        if unset_any:
            print(Style.success(f"Unset {var_name}"))
        else:
            print(Style.warning(f"{var_name} was not set"))

    def cmd_unsetg(self, args: List[str]) -> None:
        """Unset a global variable"""
        if not args:
            print(Style.error("Usage: unsetg <variable>"))
            return

        var_name = args[0].upper()
        if self.config.unsetg(var_name):
            print(Style.success(f"Unset global {var_name}"))
        else:
            print(Style.warning(f"{var_name} was not set globally"))

    def cmd_show(self, args: List[str]) -> None:
        """Show various information"""
        if not args:
            args = ["options"] if self.current_module else ["globals"]

        what = args[0].lower()

        if what == "options":
            self.cmd_options([])
        elif what == "info":
            self.cmd_info([])
        elif what == "vars":
            self.cmd_vars([])
        elif what == "globals":
            self.cmd_globals([])
        elif what == "history":
            self.cmd_history(args[1:] if len(args) > 1 else [])
        elif what == "modules":
            self._show_modules()
        else:
            print(Style.error(f"Unknown: {what}"))
            print(Style.info("Options: options, info, vars, globals, history, modules"))

    def _show_modules(self) -> None:
        """Show all loaded modules"""
        modules = self.loader.get_all_modules()
        if not modules:
            print(Style.warning("No modules loaded"))
            return

        print(f"\n  {Style.highlight('Loaded Modules')} ({len(modules)} total)")
        print(f"  {Style.uwu('='*50)}\n")

        by_type: Dict[str, List[ModuleInfo]] = {}
        for info in modules.values():
            type_name = info.module_type.value
            if type_name not in by_type:
                by_type[type_name] = []
            by_type[type_name].append(info)

        for type_name, mods in sorted(by_type.items()):
            print(f"  {Style.title(type_name.upper())} ({len(mods)})")
            for m in mods[:10]:
                print(f"    {Style.module_path(m.path)}")
            if len(mods) > 10:
                print(f"    ... and {len(mods) - 10} more")
            print()

    def cmd_vars(self, args: List[str]) -> None:
        """Show all current variables"""
        all_vars = self.config.get_all_vars()

        if not all_vars:
            print(Style.warning("No variables set"))
            return

        print(f"\n  {'Variable':<20} {'Value':<30} {'Source'}")
        print(f"  {'-'*20} {'-'*30} {'-'*10}")

        globals_set = self.config.get_all_globals()

        for name, value in sorted(all_vars.items()):
            val_str = str(value)[:28] + ".." if len(str(value)) > 30 else str(value)
            source = "global" if name in globals_set else "session"
            print(f"  {Style.varname(name):<20} {Style.value(val_str):<30} {source}")

        print()

    def cmd_globals(self, args: List[str]) -> None:
        """Show global variables"""
        globals_set = self.config.get_all_globals()

        if not globals_set:
            print(Style.warning("No global variables set"))
            return

        print(f"\n  Global Variables")
        print(f"  {'='*50}\n")
        print(f"  {'Variable':<20} {'Value':<40}")
        print(f"  {'-'*20} {'-'*40}")

        for name, value in sorted(globals_set.items()):
            val_str = str(value)[:38] + ".." if len(str(value)) > 40 else str(value)
            desc = self.config.get_variable_description(name)
            print(f"  {Style.varname(name):<20} {Style.value(val_str):<40}")
            print(f"  {'':<20} {Style.dim(desc)}")

        print()

    def cmd_history(self, args: List[str]) -> None:
        """Show variable history"""
        if args:
            # Show history for specific variable
            var_name = args[0].upper()
            history = self.config.get_history(var_name)

            if not history:
                print(Style.warning(f"No history for {var_name}"))
                return

            print(f"\n  History for {Style.varname(var_name)}")
            print(f"  {'-'*50}")

            for entry in history[:20]:
                ts = entry.get("timestamp", "")[:19]
                val = entry.get("value", "")
                print(f"  [{Style.dim(ts)}] {val}")

            print()
        else:
            # Show all variables with history
            all_history = self.config.get_all_history()

            if not all_history:
                print(Style.warning("No variable history"))
                return

            print(f"\n  Variable History")
            print(f"  {'='*50}\n")

            for name, entries in sorted(all_history.items()):
                recent = entries[0]["value"] if entries else ""
                count = len(entries)
                print(f"  {Style.varname(name):<20} ({count} entries) - Recent: {recent}")

            print(f"\n  Use 'history <var>' for detailed history\n")

    # =========================================================================
    # Server Utilities
    # =========================================================================

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
        if name in self.processes:
            proc = self.processes[name]
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

        self.processes[name] = proc
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
        if name in self.processes:
            proc = self.processes[name]
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

        self.processes[name] = proc
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
            if not self.processes:
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

        if name in self.processes:
            proc = self.processes[name]
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except:
                proc.kill()
            del self.processes[name]
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
            matching = [k for k in self.processes.keys() if k.startswith(service)]
            if matching:
                print(Style.error(f"Service not found: {name}"))
                print(Style.info(f"Did you mean: {', '.join(matching)}?"))
            else:
                print(Style.error(f"Service not found: {name}"))
                if self.processes:
                    print(Style.info(f"Running services: {', '.join(self.processes.keys())}"))

    def cmd_listeners(self, args: List[str]) -> None:
        """List active listeners/servers"""
        # Show both old-style processes and shell manager listeners
        has_processes = bool(self.processes)
        listeners = self.shell_manager.list_listeners()

        if not has_processes and not listeners:
            print(Style.warning("No active services or listeners"))
            return

        if has_processes:
            print(f"\n  Active Services")
            print(f"  {'='*40}\n")
            print(f"  {'ID':<15} {'Status':<10} {'PID'}")
            print(f"  {'-'*15} {'-'*10} {'-'*10}")

            for name, proc in self.processes.items():
                status = "running" if proc.poll() is None else "stopped"
                print(f"  {name:<15} {status:<10} {proc.pid}")
            print()

        if listeners:
            print_listeners_table(listeners)

    # =========================================================================
    # Shell Management Commands (Sliver-like)
    # =========================================================================

    def cmd_shells(self, args: List[str]) -> None:
        """List active shell sessions (including tmux and Sliver sessions)"""
        has_sessions = False

        # List shell manager sessions
        shells = self.shell_manager.list_shells()
        if shells:
            print_shells_table(shells)
            has_sessions = True

        # List Sliver sessions/beacons
        sliver_sessions = self._list_sliver_sessions()
        if sliver_sessions:
            has_sessions = True
            print(f"\n  {Colors.NEON_GREEN}Sliver Sessions{Colors.RESET}")
            print(f"  {Colors.NEON_GREEN}{'='*75}{Colors.RESET}\n")
            print(f"  {'Type':<8} {'ID':<10} {'Name':<20} {'User@Host':<30} {'Remote'}")
            print(f"  {'-'*8} {'-'*10} {'-'*20} {'-'*30} {'-'*20}")
            for sess in sliver_sessions:
                sess_type = f"{Colors.NEON_GREEN}SESSION{Colors.RESET}" if sess['type'] == 'sliver' else f"{Colors.NEON_ORANGE}BEACON{Colors.RESET}"
                user_host = f"{sess['username']}@{sess['hostname']}"
                print(f"  {sess_type:<17} {Colors.NEON_CYAN}{sess['id']:<10}{Colors.RESET} {sess['name']:<20} {user_host:<30} {sess['remote']}")
            print()
            print(f"  {Colors.GRID}Use 'interact <id>' to connect via Sliver{Colors.RESET}")
            print()

        # List tmux sessions (uwu-* sessions from evil_winrm, etc.)
        tmux_sessions = self._list_tmux_sessions()
        if tmux_sessions:
            has_sessions = True
            from datetime import datetime
            print(f"\n  {Colors.NEON_PINK}Tmux Sessions{Colors.RESET}")
            print(f"  {Colors.NEON_PINK}{'='*65}{Colors.RESET}\n")
            print(f"  {'ID':<5} {'Name':<40} {'Status':<12} {'Created'}")
            print(f"  {'-'*5} {'-'*40} {'-'*12} {'-'*12}")
            for idx, sess in enumerate(tmux_sessions, 1):
                status = f"{Colors.NEON_GREEN}active{Colors.RESET}" if sess.get("attached") else f"{Colors.NEON_CYAN}detached{Colors.RESET}"
                # Format timestamp
                created = sess.get("created", "")
                try:
                    ts = datetime.fromtimestamp(int(created)).strftime("%m-%d %H:%M")
                except:
                    ts = created
                print(f"  {Colors.NEON_MAGENTA}{idx:<5}{Colors.RESET} {Colors.BRIGHT_WHITE}{sess['name']:<40}{Colors.RESET} {status:<22} {ts}")
            print()
            print(f"  {Colors.GRID}Use 'interact <id>' to attach, Ctrl+b d to detach{Colors.RESET}")
            print()

        if not has_sessions:
            print(Style.warning("No active sessions"))
            print(Style.info("Use 'sliver connect' for C2 sessions or evil_winrm module for WinRM"))

    def _list_tmux_sessions(self) -> list:
        """List tmux sessions starting with uwu-"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}:#{session_created}:#{session_attached}"],
                capture_output=True, text=True, timeout=5
            )
            sessions = []
            for line in result.stdout.strip().split('\n'):
                if line and line.startswith("uwu-"):
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

    def _list_sliver_sessions(self) -> list:
        """List active Sliver sessions - disabled to avoid join/leave spam.
        Use 'sessions' inside Sliver console instead."""
        # Disabled: querying sliver-client causes "uwu joined/left the game" spam
        # Users should check sessions from within the Sliver tmux session
        return []

    def cmd_interact(self, args: List[str]) -> None:
        """Interact with a shell, tmux, or Sliver session"""
        tmux_sessions = self._list_tmux_sessions()
        sliver_sessions = self._list_sliver_sessions()
        shells = self.shell_manager.list_shells()

        if not args:
            # Show all session types for selection
            if not shells and not tmux_sessions and not sliver_sessions:
                print(Style.warning("No active sessions"))
                return

            if shells:
                print_shells_table(shells)

            if sliver_sessions:
                print(f"\n  {Colors.NEON_GREEN}Sliver Sessions:{Colors.RESET}")
                for sess in sliver_sessions:
                    sess_type = "SESSION" if sess['type'] == 'sliver' else "BEACON"
                    print(f"    {Colors.NEON_CYAN}[{sess['id']}]{Colors.RESET} {sess['name']} - {sess['username']}@{sess['hostname']} ({sess_type})")

            if tmux_sessions:
                print(f"\n  {Colors.NEON_PINK}Tmux Sessions:{Colors.RESET}")
                for idx, sess in enumerate(tmux_sessions, 1):
                    status = "active" if sess.get("attached") else "detached"
                    print(f"    {Colors.NEON_MAGENTA}[{idx}]{Colors.RESET} {Colors.NEON_CYAN}{sess['name']}{Colors.RESET} ({status})")

            try:
                choice = input(f"\n  {Colors.NEON_CYAN}Enter session ID:{Colors.RESET} ").strip()
                if not choice:
                    return

                # Check if it's a Sliver session ID (8 hex chars)
                if len(choice) == 8 and all(c in '0123456789abcdef' for c in choice.lower()):
                    if any(s['id'] == choice for s in sliver_sessions):
                        self._interact_sliver_session(choice)
                        return

                # Try as numeric ID first (for tmux sessions)
                try:
                    session_id = int(choice)
                    if 1 <= session_id <= len(tmux_sessions):
                        self._attach_tmux_session(tmux_sessions[session_id - 1]["name"])
                    else:
                        # Try shell manager
                        self.shell_manager.interact(session_id)
                except ValueError:
                    # Try as session name or Sliver ID
                    if choice.startswith("uwu-"):
                        self._attach_tmux_session(choice)
                    elif any(s["name"] == choice for s in tmux_sessions):
                        self._attach_tmux_session(choice)
                    elif any(s['id'].startswith(choice) for s in sliver_sessions):
                        # Partial Sliver ID match
                        for s in sliver_sessions:
                            if s['id'].startswith(choice):
                                self._interact_sliver_session(s['id'])
                                return
                    else:
                        print(Style.error("Invalid session ID or name"))
            except KeyboardInterrupt:
                print()
                return
        else:
            identifier = args[0]

            # Check if it's a Sliver session ID
            if any(s['id'] == identifier or s['id'].startswith(identifier) for s in sliver_sessions):
                for s in sliver_sessions:
                    if s['id'] == identifier or s['id'].startswith(identifier):
                        self._interact_sliver_session(s['id'])
                        return

            # Try as numeric ID first
            try:
                session_id = int(identifier)
                if tmux_sessions and 1 <= session_id <= len(tmux_sessions):
                    self._attach_tmux_session(tmux_sessions[session_id - 1]["name"])
                else:
                    # Try shell manager
                    self.shell_manager.interact(session_id)
            except ValueError:
                # Try as session name
                tmux_names = [s["name"] for s in tmux_sessions]
                if identifier in tmux_names:
                    self._attach_tmux_session(identifier)
                elif f"uwu-{identifier}" in tmux_names:
                    self._attach_tmux_session(f"uwu-{identifier}")
                elif identifier.startswith("uwu-"):
                    self._attach_tmux_session(identifier)
                else:
                    print(Style.error(f"Session not found: {identifier}"))

    def _attach_tmux_session(self, session_name: str) -> None:
        """Attach to a tmux session"""
        print(Style.info(f"Attaching to tmux session: {session_name}"))
        print(Style.info("Use Ctrl+b d to detach"))
        os.system(f"tmux attach-session -t {session_name}")

    def _interact_sliver_session(self, session_id: str) -> None:
        """Connect to Sliver and interact with specified session"""
        from .sliver import get_sliver_mode

        print(Style.info(f"Connecting to Sliver session: {session_id}"))

        # Get the Sliver mode instance
        sliver_mode = get_sliver_mode(self.config)

        # Set the active session so it auto-selects on connect
        sliver_mode.active_session = session_id

        # If already backgrounded, resume with the session
        if sliver_mode.is_backgrounded():
            sliver_mode.resume()
        else:
            # Start new Sliver connection
            sliver_mode.start()

    def cmd_kill_shell(self, args: List[str]) -> None:
        """Kill a shell or tmux session"""
        if not args:
            print(Style.error("Usage: kill <session_id> or kill <session_name>"))
            return

        identifier = args[0]
        tmux_sessions = self._list_tmux_sessions()
        tmux_names = [s["name"] for s in tmux_sessions]

        # Try as numeric ID first
        try:
            session_id = int(identifier)
            if tmux_sessions and 1 <= session_id <= len(tmux_sessions):
                session_name = tmux_sessions[session_id - 1]["name"]
                result = subprocess.run(
                    ["tmux", "kill-session", "-t", session_name],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    print(Style.success(f"Session {session_id} ({session_name}) killed"))
                else:
                    print(Style.error(f"Failed to kill session: {session_name}"))
                return
            else:
                # Try shell manager
                if self.shell_manager.kill_shell(session_id):
                    print(Style.success(f"Shell {session_id} killed"))
                else:
                    print(Style.error(f"Shell {session_id} not found"))
                return
        except ValueError:
            pass

        # Try as session name
        if identifier in tmux_names or f"uwu-{identifier}" in tmux_names:
            session_name = identifier if identifier in tmux_names else f"uwu-{identifier}"
            try:
                result = subprocess.run(
                    ["tmux", "kill-session", "-t", session_name],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    print(Style.success(f"Session '{session_name}' killed"))
                else:
                    print(Style.error(f"Failed to kill session: {session_name}"))
            except Exception as e:
                print(Style.error(f"Failed to kill session: {e}"))
        else:
            print(Style.error(f"Session not found: {identifier}"))

    def cmd_listen(self, args: List[str]) -> None:
        """Start a shell listener (nc or penelope)"""
        if not args:
            print(Style.error("Usage: listen <port> [type]"))
            print(Style.info("Types: nc (default), penelope"))
            return

        try:
            port = int(args[0])
        except ValueError:
            print(Style.error("Invalid port number"))
            return

        listener_type = args[1] if len(args) > 1 else "nc"

        if listener_type not in ("nc", "penelope"):
            print(Style.error(f"Unknown listener type: {listener_type}"))
            print(Style.info("Types: nc, penelope"))
            return

        print(Style.info(f"Starting {listener_type} listener on port {port}..."))
        if self.shell_manager.start_listener(port, listener_type):
            tmux_status.update_listener(port, "listening", 0)
            print(Style.success(f"Listener started. Shells will auto-register."))
            print(Style.info(f"Use 'sessions' to view connections, 'interact <id>' to interact"))
        else:
            print(Style.error("Failed to start listener"))

    # =========================================================================
    # Other Commands
    # =========================================================================

    def cmd_shell(self, args: List[str]) -> None:
        """Execute shell command"""
        if not args:
            # Start interactive shell
            shell = os.environ.get("SHELL", "/bin/bash")
            subprocess.run([shell])
        else:
            cmd = " ".join(args)
            subprocess.run(cmd, shell=True)

    def cmd_export(self, args: List[str]) -> None:
        """Export variables for shell use"""
        if args and args[0] == "--script":
            # Output shell script
            script = self.config.get_env_script()
            print(script)
        else:
            # Show environment variables
            env_vars = self.config.export_to_env()

            print(f"\n  Export Variables for Shell")
            print(f"  {'='*40}")
            print(f"\n  To export variables, run:")
            print(f"  {Style.highlight('eval $(uwu export --script)')}\n")

            print(f"  Or copy these exports:\n")
            for name, value in sorted(env_vars.items()):
                print(f"  export {name}='{value}'")
            print()

    # =========================================================================
    # Claude AI Commands
    # =========================================================================

    def cmd_claude(self, args: List[str]) -> None:
        """Claude AI assistant commands"""
        if not args:
            # Default: enter Claude mode
            self.claude_mode.start()
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "help":
            print(get_claude_help())

        elif subcmd == "mode":
            # Enter interactive Claude mode
            self.claude_mode.start()

        elif subcmd in ("resume", "fg"):
            # Resume backgrounded Claude session
            self.claude_mode.resume()

        elif subcmd == "sessions":
            # List all Claude sessions
            sessions = self.claude_mode.session_manager.list_sessions()
            if not sessions:
                print(Style.warning("No Claude sessions"))
                return

            active = self.claude_mode.session_manager.get_active_session()
            print(f"\n  {Style.highlight('Claude Sessions')}")
            print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}\n")

            for session in sessions:
                marker = f"{Colors.NEON_GREEN}*{Colors.RESET}" if session == active else " "
                msg_count = len(session.messages)
                user_msgs = sum(1 for m in session.messages if m["role"] == "user")
                created = session.created_at.strftime("%H:%M:%S")
                print(f"  {marker} {Colors.NEON_CYAN}{session.id}{Colors.RESET}  {session.name}")
                print(f"      {Colors.GRID}{user_msgs} prompts, created {created}{Colors.RESET}")
            print()
            print(Style.dim("  Use 'claude mode' to enter interactive mode"))

        elif subcmd == "status":
            available, msg = self.claude.is_available()
            if available:
                print(Style.success(msg))
                print(Style.info(f"Model: {self.claude.model}"))
            else:
                print(Style.error(msg))

        elif subcmd == "model":
            if not subargs:
                print(Style.info(f"Current model: {self.claude.model}"))
                print(Style.dim("Usage: claude model <model_name>"))
            else:
                self.claude.set_model(subargs[0])

        elif subcmd == "analyze":
            if not subargs:
                print(Style.error("Usage: claude analyze <path> [--focus <area>]"))
                return

            # Parse arguments
            paths = []
            focus = None
            i = 0
            while i < len(subargs):
                if subargs[i] == "--focus" and i + 1 < len(subargs):
                    focus = subargs[i + 1]
                    i += 2
                else:
                    paths.append(subargs[i])
                    i += 1

            if not paths:
                print(Style.error("No path specified"))
                return

            result = self.claude.analyze_vulnerabilities(paths, focus)
            print(result)

        elif subcmd == "debug":
            if not subargs:
                print(Style.error("Usage: claude debug <path> [--error \"message\"]"))
                return

            # Parse arguments
            paths = []
            error_msg = None
            i = 0
            while i < len(subargs):
                if subargs[i] == "--error" and i + 1 < len(subargs):
                    error_msg = subargs[i + 1]
                    i += 2
                else:
                    paths.append(subargs[i])
                    i += 1

            if not paths:
                print(Style.error("No path specified"))
                return

            result = self.claude.debug_code(paths, error_msg)
            print(result)

        elif subcmd == "ask":
            if not subargs:
                print(Style.error("Usage: claude ask \"question\" [--context <path>]"))
                return

            # Parse arguments - handle quoted strings
            question_parts = []
            context_paths = []
            i = 0
            while i < len(subargs):
                if subargs[i] == "--context" and i + 1 < len(subargs):
                    context_paths.append(subargs[i + 1])
                    i += 2
                else:
                    question_parts.append(subargs[i])
                    i += 1

            question = " ".join(question_parts)
            if not question:
                print(Style.error("No question provided"))
                return

            result = self.claude.ask(question, context_paths if context_paths else None)
            print(result)

        else:
            print(Style.error(f"Unknown subcommand: {subcmd}"))
            print(Style.info("Use 'claude help' for usage"))

    # =========================================================================
    # Sliver C2 Commands
    # =========================================================================

    def cmd_sliver(self, args: List[str]) -> None:
        """Sliver C2 commands"""
        if not args:
            print(get_sliver_help())
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "help":
            print(get_sliver_help())

        elif subcmd == "start":
            # Start Sliver server AND connect with client in tmux (all-in-one)
            self._start_sliver_full()

        elif subcmd == "stop":
            # Stop Sliver server
            self.sliver_server.stop()

        elif subcmd == "connect":
            # Connect with Sliver client in tmux (like ligolo/evil-winrm)
            config_name = subargs[0] if subargs else None
            self._start_sliver_tmux(config_name)

        elif subcmd in ("resume", "fg", "attach"):
            # Attach to tmux Sliver session
            self._attach_sliver_tmux()

        elif subcmd == "kill":
            # Kill Sliver tmux session
            self._kill_sliver_tmux()

        elif subcmd == "pty":
            # Old PTY mode (non-tmux)
            config_name = subargs[0] if subargs else None
            self.sliver_mode.start(config_name)

        elif subcmd == "configs":
            # List available configs
            configs = self.sliver_client.get_configs()
            if not configs:
                print(Style.warning("No Sliver configs found"))
                print(Style.info(f"Import with: sliver-client import <config.cfg>"))
                return

            print(f"\n  {Style.highlight('Sliver Client Configs')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")
            for cfg in configs:
                print(f"    {Colors.NEON_CYAN}{cfg.stem}{Colors.RESET}")
                print(f"      {Colors.GRID}{cfg}{Colors.RESET}")
            print()

        elif subcmd == "status":
            # Check Sliver status
            print(f"\n  {Style.highlight('Sliver Status')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")

            # Server status
            if self.sliver_server.is_running():
                print(f"  {Colors.NEON_GREEN}Server:{Colors.RESET}  Running")
            else:
                print(f"  {Colors.NEON_ORANGE}Server:{Colors.RESET}  Stopped")

            # Client status
            if self.sliver_mode.is_backgrounded():
                print(f"  {Colors.NEON_GREEN}Client:{Colors.RESET}  Backgrounded (use 'sliver resume')")
            else:
                print(f"  {Colors.GRID}Client:{Colors.RESET}  Not connected")

            # Configs
            configs = self.sliver_client.get_configs()
            print(f"  {Colors.GRID}Configs:{Colors.RESET} {len(configs)} available")

            # Binary paths
            if self.sliver_client.sliver_path:
                print(f"  {Colors.GRID}Client:{Colors.RESET}  {self.sliver_client.sliver_path}")
            if self.sliver_client.server_path:
                print(f"  {Colors.GRID}Server:{Colors.RESET}  {self.sliver_client.server_path}")
            print()

        else:
            print(Style.error(f"Unknown command: sliver {subcmd}"))
            print(Style.info("Use 'sliver help' for usage"))

    # =========================================================================
    # PENELOPE SHELL HANDLER COMMANDS
    # =========================================================================

    def cmd_penelope(self, args: List[str]) -> None:
        """Penelope shell handler commands"""
        if not args:
            # Start Penelope with default port
            self.penelope_mode.start(port=4444)
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "help":
            print(get_penelope_help())

        elif subcmd in ("resume", "fg"):
            # Resume backgrounded Penelope session
            self.penelope_mode.resume()

        elif subcmd == "status":
            # Check Penelope status
            status = self.penelope_mode.status()
            print(f"\n  {Style.highlight('Penelope Status')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")

            if status["process_alive"]:
                if status["backgrounded"]:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}  Backgrounded (use 'penelope resume')")
                else:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}  Running")
                print(f"  {Colors.GRID}Port:{Colors.RESET}    {status['port']}")
                print(f"  {Colors.GRID}Sessions:{Colors.RESET} {status['sessions']}")
            else:
                print(f"  {Colors.GRID}Status:{Colors.RESET}  Not running")

            # Check if penelope is available
            available, msg = self.penelope_mode.client.is_available()
            if available:
                print(f"  {Colors.GRID}Binary:{Colors.RESET}  {self.penelope_mode.client.penelope_path}")
            else:
                print(f"  {Colors.NEON_ORANGE}Binary:{Colors.RESET}  Not found")
            print()

        elif subcmd.isdigit():
            # Start on specified port
            port = int(subcmd)
            self.penelope_mode.start(port=port)

        elif subcmd == "-i" and len(subargs) >= 2:
            # Start with specific interface
            interface = subargs[0]
            port = int(subargs[1])
            self.penelope_mode.start(port=port, interface=interface)

        else:
            print(Style.error(f"Unknown command: penelope {subcmd}"))
            print(Style.info("Use 'penelope help' for usage"))

    # =========================================================================
    # LIGOLO-NG TUNNELING COMMANDS
    # =========================================================================

    def cmd_ligolo(self, args: List[str]) -> None:
        """Ligolo-ng proxy commands"""
        if not args:
            # Start Ligolo in tmux by default (like evil-winrm)
            self._start_ligolo_tmux(port=11601)
            return

        subcmd = args[0].lower()
        subargs = args[1:]

        if subcmd == "info":
            print(get_ligolo_help())

        elif subcmd in ("resume", "fg"):
            # Resume backgrounded Ligolo session
            self.ligolo_mode.resume()

        elif subcmd == "agents":
            # List connected agents
            agents = self.ligolo_mode.get_agents()
            print_agents_table(agents)

        elif subcmd == "status":
            # Check Ligolo status
            status = self.ligolo_mode.status()
            print(f"\n  {Style.highlight('Ligolo-ng Status')}")
            print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")

            if status["process_alive"]:
                if status["backgrounded"]:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}    Backgrounded (use 'ligolo resume')")
                else:
                    print(f"  {Colors.NEON_GREEN}Status:{Colors.RESET}    Running")
                print(f"  {Colors.GRID}Port:{Colors.RESET}      {status['port']}")
                print(f"  {Colors.GRID}TUN:{Colors.RESET}       {status['tun_interface']}")
                print(f"  {Colors.GRID}Agents:{Colors.RESET}    {status['agents']}")
            else:
                print(f"  {Colors.GRID}Status:{Colors.RESET}    Not running")

            # Check if ligolo is available
            available, msg = self.ligolo_mode.client.is_available()
            if available:
                print(f"  {Colors.GRID}Binary:{Colors.RESET}    {self.ligolo_mode.client.proxy_path}")
            else:
                print(f"  {Colors.NEON_ORANGE}Binary:{Colors.RESET}    Not found")

            # Show routes
            routes = self.ligolo_mode.list_routes()
            if routes:
                print(f"  {Colors.GRID}Routes:{Colors.RESET}    {', '.join(routes)}")
            print()

        elif subcmd == "routes":
            # List active routes
            routes = self.ligolo_mode.list_routes()
            if routes:
                print(f"\n  {Style.highlight('Ligolo Routes')}")
                print(f"  {Colors.NEON_ORANGE}{'='*40}{Colors.RESET}\n")
                for route in routes:
                    print(f"    {Colors.NEON_GREEN}{route}{Colors.RESET} via {self.ligolo_mode.tun_interface}")
                print()
            else:
                print(Style.warning("No routes configured"))
                print(Style.info("Use 'ligolo route add <network>' to add a route"))

        elif subcmd == "route":
            if not subargs:
                # Show current routes
                routes = self.ligolo_mode.list_routes()
                if routes:
                    print(f"\n  {Style.highlight('Ligolo Routes')}")
                    for route in routes:
                        print(f"    {Colors.NEON_GREEN}{route}{Colors.RESET}")
                    print()
                else:
                    print(Style.warning("No routes configured"))
                print(Style.info("Usage: ligolo route <network> [interface]"))
                print(Style.info("       ligolo route del <network>"))
                return

            first_arg = subargs[0]

            # Check if first arg is a network (contains /)
            if '/' in first_arg:
                # ligolo route 240.0.0.1/32 [interface]
                network = first_arg
                interface = subargs[1] if len(subargs) > 1 else "ligolo"

                try:
                    result = subprocess.run(
                        ["sudo", "ip", "route", "add", network, "dev", interface],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        print(Style.success(f"Route added: {network} via {interface}"))
                    elif "File exists" in result.stderr:
                        print(Style.warning(f"Route already exists: {network}"))
                    else:
                        print(Style.error(f"Failed: {result.stderr.strip()}"))
                except Exception as e:
                    print(Style.error(f"Failed to add route: {e}"))

            elif first_arg.lower() == "del" and len(subargs) >= 2:
                # ligolo route del <network>
                network = subargs[1]
                if self.ligolo_mode.client.remove_route(network):
                    print(Style.success(f"Route removed: {network}"))
                else:
                    print(Style.error(f"Failed to remove route: {network}"))

            elif first_arg.lower() == "add" and len(subargs) >= 2:
                # Legacy: ligolo route add <network> [interface]
                network = subargs[1]
                interface = subargs[2] if len(subargs) > 2 else "ligolo"
                try:
                    result = subprocess.run(
                        ["sudo", "ip", "route", "add", network, "dev", interface],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        print(Style.success(f"Route added: {network} via {interface}"))
                    elif "File exists" in result.stderr:
                        print(Style.warning(f"Route already exists: {network}"))
                    else:
                        print(Style.error(f"Failed: {result.stderr.strip()}"))
                except Exception as e:
                    print(Style.error(f"Failed to add route: {e}"))
            else:
                print(Style.error("Usage: ligolo route <network> [interface]"))
                print(Style.info("Examples:"))
                print(Style.info("  ligolo route 10.10.10.0/24        # uses 'ligolo' interface"))
                print(Style.info("  ligolo route 10.10.10.0/24 tun0   # uses 'tun0' interface"))

        elif subcmd == "download":
            # Download latest ligolo-ng agents from GitHub
            self._download_ligolo_agents()

        elif subcmd == "persistent":
            # Alias for starting in tmux (now the default)
            port = int(subargs[0]) if subargs and subargs[0].isdigit() else 11601
            self._start_ligolo_tmux(port)

        elif subcmd in ("attach", "resume", "fg"):
            # Attach to tmux ligolo session
            self._attach_ligolo_tmux()

        elif subcmd == "kill":
            # Kill ligolo tmux session
            self._kill_ligolo_tmux()

        elif subcmd == "pty":
            # Old PTY mode (non-tmux, exits with UwU)
            port = int(subargs[0]) if subargs and subargs[0].isdigit() else 11601
            self.ligolo_mode.start(port=port)

        elif subcmd.isdigit():
            # Start on specified port (in tmux by default)
            port = int(subcmd)
            self._start_ligolo_tmux(port=port)

        elif subcmd == "-tun" and subargs:
            # Start with specific TUN interface
            tun = subargs[0]
            port = int(subargs[1]) if len(subargs) > 1 else 11601
            self.ligolo_mode.start(port=port, tun=tun)

        else:
            print(Style.error(f"Unknown command: ligolo {subcmd}"))
            print(Style.info("Use 'ligolo info' for usage"))

    def _download_ligolo_agents(self) -> bool:
        """Download latest ligolo-ng agents from GitHub releases"""
        import urllib.request
        import json
        import zipfile
        import tarfile
        import io

        print(Style.info("Fetching latest ligolo-ng release info..."))

        # GitHub API for latest release
        api_url = "https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest"

        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "UwU-Toolkit"})
            with urllib.request.urlopen(req, timeout=30) as response:
                release_data = json.loads(response.read().decode())
        except Exception as e:
            print(Style.error(f"Failed to fetch release info: {e}"))
            return False

        version = release_data.get("tag_name", "unknown")
        print(Style.success(f"Latest version: {version}"))

        # Find agent assets (Windows and Linux amd64)
        assets = release_data.get("assets", [])
        agent_files = {
            "windows": None,
            "linux": None,
        }

        for asset in assets:
            name = asset.get("name", "").lower()
            url = asset.get("browser_download_url", "")

            # Match agent files (not proxy) - format: ligolo-ng_agent_X.X.X_os_arch
            if "_agent_" in name and "amd64" in name:
                if "windows" in name and "arm" not in name:
                    agent_files["windows"] = (asset.get("name"), url)
                elif "linux" in name and "arm" not in name:
                    agent_files["linux"] = (asset.get("name"), url)

        if not agent_files["windows"] and not agent_files["linux"]:
            print(Style.error("Could not find agent binaries in release"))
            return False

        # Create output directory
        output_dir = Path("/opt/tools/ligolo-ng")
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            # Test write access
            test_file = output_dir / ".write_test"
            test_file.touch()
            test_file.unlink()
        except (PermissionError, OSError):
            # Try user directory instead
            output_dir = Path.home() / ".local" / "share" / "ligolo-ng"
            output_dir.mkdir(parents=True, exist_ok=True)
            print(Style.warning(f"Using user directory: {output_dir}"))

        downloaded = []

        for os_type, asset_info in agent_files.items():
            if not asset_info:
                continue

            asset_name, download_url = asset_info
            print(Style.info(f"Downloading {asset_name}..."))

            try:
                req = urllib.request.Request(download_url, headers={"User-Agent": "UwU-Toolkit"})
                with urllib.request.urlopen(req, timeout=120) as response:
                    data = response.read()

                # Determine output filename
                if os_type == "windows":
                    out_name = "agent.exe"
                else:
                    out_name = "agent_linux_amd64"

                out_path = output_dir / out_name

                # Handle zip files (Windows)
                if asset_name.endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        # Find and extract agent binary
                        for zinfo in zf.namelist():
                            if "agent" in zinfo.lower() and not zinfo.endswith('/'):
                                with open(out_path, "wb") as f:
                                    f.write(zf.read(zinfo))
                                downloaded.append(str(out_path))
                                print(Style.success(f"  Saved: {out_path}"))
                                break

                # Handle tar.gz files (Linux)
                elif asset_name.endswith(".tar.gz") or asset_name.endswith(".tgz"):
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                        # Find and extract agent binary
                        for member in tf.getmembers():
                            if "agent" in member.name.lower() and member.isfile():
                                # Extract file content
                                extracted = tf.extractfile(member)
                                if extracted:
                                    with open(out_path, "wb") as f:
                                        f.write(extracted.read())
                                    out_path.chmod(0o755)
                                    downloaded.append(str(out_path))
                                    print(Style.success(f"  Saved: {out_path}"))
                                    break

                else:
                    # Direct binary (unlikely but handle it)
                    with open(out_path, "wb") as f:
                        f.write(data)
                    if os_type == "linux":
                        out_path.chmod(0o755)
                    downloaded.append(str(out_path))
                    print(Style.success(f"  Saved: {out_path}"))

            except Exception as e:
                print(Style.error(f"Failed to download {asset_name}: {e}"))

        if downloaded:
            print()
            print(Style.success(f"Downloaded {len(downloaded)} agent(s) to {output_dir}"))
            print(Style.info("Use 'ligolo_pivot' module to deploy agents to targets"))
            return True
        else:
            print(Style.error("No agents were downloaded"))
            return False

    def _find_ligolo_tmux_session(self) -> Optional[str]:
        """Find existing ligolo tmux session (uwu-ligolo-*)"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if line.startswith("uwu-ligolo"):
                    return line
            return None
        except:
            return None

    def _start_ligolo_tmux(self, port: int = 11601) -> bool:
        """Start ligolo in a tmux session (like evil-winrm)"""
        import subprocess

        # Check if a ligolo session already exists
        existing = self._find_ligolo_tmux_session()
        if existing:
            print(Style.warning(f"Ligolo session already exists: {existing}"))
            print(Style.info(f"Use 'ligolo attach' to connect"))
            print(Style.info(f"Use 'ligolo kill' to stop it"))
            return False

        session_name = f"uwu-ligolo-{port}"

        # Find ligolo binary
        available, msg = self.ligolo_mode.client.is_available()
        if not available:
            print(Style.error("Ligolo-ng proxy not found"))
            return False

        proxy_path = self.ligolo_mode.client.proxy_path

        # Setup TUN interface first
        print(Style.info("Setting up TUN interface..."))
        self.ligolo_mode.client.create_tun_interface("ligolo")

        # Build ligolo command
        ligolo_cmd = f"{proxy_path} -laddr 0.0.0.0:{port} -selfcert"

        # Create tmux session
        result = subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_name, ligolo_cmd],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            # Apply UwU theme to the session
            status_right = "#[fg=#00ffff]LIGOLO #[fg=#ff6eb4]| #[fg=#ffffff]Port: {} #[fg=#ff6eb4]| #[fg=#666666]Ctrl+b x to detach".format(port)
            theme_cmds = [
                ["tmux", "set-option", "-t", session_name, "status", "on"],
                ["tmux", "set-option", "-t", session_name, "status-style", "bg=#1a1a2e,fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "status-left-length", "50"],
                ["tmux", "set-option", "-t", session_name, "status-right-length", "120"],
                ["tmux", "set-option", "-t", session_name, "status-left", "#[bg=#ff6eb4,fg=#1a1a2e,bold] UwU #[bg=#1a1a2e,fg=#ff6eb4] "],
                ["tmux", "set-option", "-t", session_name, "status-right", status_right],
                ["tmux", "set-option", "-t", session_name, "status-interval", "2"],
                ["tmux", "set-option", "-t", session_name, "window-status-current-style", "bg=#ff00ff,fg=#1a1a2e,bold"],
                ["tmux", "set-option", "-t", session_name, "window-status-style", "bg=#1a1a2e,fg=#888888"],
                ["tmux", "set-option", "-t", session_name, "pane-border-style", "fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "pane-active-border-style", "fg=#00ffff"],
                ["tmux", "set-option", "-t", session_name, "message-style", "bg=#ff6eb4,fg=#1a1a2e,bold"],
                # Bind Ctrl+b x to detach (applied globally)
                ["tmux", "bind-key", "x", "detach-client"],
            ]
            for cmd in theme_cmds:
                subprocess.run(cmd, capture_output=True)

            print(Style.success(f"Starting Ligolo-ng session..."))
            print(Style.info(f"Port: {port} | TUN: ligolo"))
            print(Style.info("Use Ctrl+b d to detach (background the session)"))
            print(Style.info("Use 'sessions' to list, 'interact' to reattach"))
            print()

            # Attach to session immediately (like evil-winrm does)
            os.system(f"tmux attach-session -t {session_name}")

            # Check if session still exists (user might have exited)
            check_result = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True, timeout=5
            )

            print()
            if check_result.returncode == 0:
                print(Style.info(f"Session '{session_name}' is backgrounded"))
                print(Style.info("Use 'sessions' to list, 'interact' to reattach"))
            else:
                print(Style.info("Session ended"))

            return True
        else:
            print(Style.error(f"Failed to start session: {result.stderr}"))
            return False

    def _attach_ligolo_tmux(self) -> None:
        """Attach to ligolo tmux session"""
        import subprocess

        session_name = self._find_ligolo_tmux_session()

        if not session_name:
            print(Style.error("No ligolo session found"))
            print(Style.info("Use 'ligolo [port]' to start one"))
            return

        print(Style.info(f"Attaching to {session_name}..."))
        print(Style.info("Press Ctrl+b d to detach and return to UwU"))
        print()

        # Attach to session (this will take over the terminal)
        subprocess.run(["tmux", "attach-session", "-t", session_name])

        print()
        print(Style.info("Detached from ligolo session"))
        print(Style.info("Ligolo is still running in background"))

    def _kill_ligolo_tmux(self) -> None:
        """Kill ligolo tmux session"""
        import subprocess

        session_name = self._find_ligolo_tmux_session()

        if not session_name:
            print(Style.warning("No ligolo session found"))
            return

        # Kill the session
        result = subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            capture_output=True
        )

        if result.returncode == 0:
            print(Style.success(f"Session '{session_name}' killed"))
        else:
            print(Style.error("Failed to kill session"))

    # =========================================================================
    # SLIVER TMUX HELPERS
    # =========================================================================

    def _start_sliver_full(self) -> bool:
        """Start Sliver server AND connect with client - all in one command"""
        import time

        # Check if tmux session already exists
        existing = self._find_sliver_tmux_session()
        if existing:
            print(Style.warning(f"Sliver session already exists: {existing}"))
            print(Style.info(f"Use 'sliver attach' to connect"))
            print(Style.info(f"Use 'sliver kill' to stop it"))
            return False

        # Step 1: Start server if not running
        if not self.sliver_server.is_running():
            print(Style.info("Starting Sliver server..."))
            if not self.sliver_server.start(daemon=True, auto_setup=True):
                print(Style.error("Failed to start server"))
                return False
            # Give it a moment to fully initialize
            time.sleep(1)
        else:
            print(Style.info("Sliver server already running"))

        # Step 2: Start client in tmux
        print(Style.info("Launching Sliver client in tmux..."))
        return self._start_sliver_tmux()

    def _find_sliver_tmux_session(self) -> Optional[str]:
        """Find existing Sliver tmux session (uwu-sliver)"""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if line.startswith("uwu-sliver"):
                    return line
            return None
        except:
            return None

    def _start_sliver_tmux(self, config_name: str = None) -> bool:
        """Start Sliver client in a tmux session (like ligolo/evil-winrm)"""
        import subprocess

        # Check if a Sliver session already exists
        existing = self._find_sliver_tmux_session()
        if existing:
            print(Style.warning(f"Sliver session already exists: {existing}"))
            print(Style.info(f"Use 'sliver attach' to connect"))
            print(Style.info(f"Use 'sliver kill' to stop it"))
            return False

        session_name = "uwu-sliver"

        # Find sliver-client binary
        if not self.sliver_client.sliver_path:
            print(Style.error("Sliver client not found"))
            return False

        sliver_cmd = self.sliver_client.sliver_path

        # Create tmux session
        result = subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_name, sliver_cmd],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            # Apply UwU theme to the session
            status_right = "#[fg=#00ffff]SLIVER C2 #[fg=#ff6eb4]| #[fg=#666666]Ctrl+b x to detach"
            theme_cmds = [
                ["tmux", "set-option", "-t", session_name, "status", "on"],
                ["tmux", "set-option", "-t", session_name, "status-style", "bg=#1a1a2e,fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "status-left-length", "50"],
                ["tmux", "set-option", "-t", session_name, "status-right-length", "120"],
                ["tmux", "set-option", "-t", session_name, "status-left", "#[bg=#ff6eb4,fg=#1a1a2e,bold] UwU #[bg=#1a1a2e,fg=#ff6eb4] "],
                ["tmux", "set-option", "-t", session_name, "status-right", status_right],
                ["tmux", "set-option", "-t", session_name, "status-interval", "2"],
                ["tmux", "set-option", "-t", session_name, "window-status-current-style", "bg=#ff00ff,fg=#1a1a2e,bold"],
                ["tmux", "set-option", "-t", session_name, "window-status-style", "bg=#1a1a2e,fg=#888888"],
                ["tmux", "set-option", "-t", session_name, "pane-border-style", "fg=#ff6eb4"],
                ["tmux", "set-option", "-t", session_name, "pane-active-border-style", "fg=#00ffff"],
                ["tmux", "set-option", "-t", session_name, "message-style", "bg=#ff6eb4,fg=#1a1a2e,bold"],
                # Bind Ctrl+b x to detach (applied globally)
                ["tmux", "bind-key", "x", "detach-client"],
            ]
            for cmd in theme_cmds:
                subprocess.run(cmd, capture_output=True)

            print(Style.success(f"Starting Sliver C2 session..."))
            print(Style.info("Use Ctrl+b x to detach (background the session)"))
            print(Style.info("Use 'sessions' to list, 'interact' to reattach"))
            print()

            # Attach to session immediately
            os.system(f"tmux attach-session -t {session_name}")

            # Check if session still exists
            check_result = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True, timeout=5
            )

            print()
            if check_result.returncode == 0:
                print(Style.info(f"Session '{session_name}' is backgrounded"))
                print(Style.info("Use 'sessions' to list, 'sliver attach' to reattach"))
            else:
                print(Style.info("Session ended"))

            return True
        else:
            print(Style.error(f"Failed to start session: {result.stderr}"))
            return False

    def _attach_sliver_tmux(self) -> None:
        """Attach to Sliver tmux session"""
        import subprocess

        session_name = self._find_sliver_tmux_session()

        if not session_name:
            print(Style.error("No Sliver session found"))
            print(Style.info("Use 'sliver connect' to start one"))
            return

        print(Style.info(f"Attaching to {session_name}..."))
        print(Style.info("Press Ctrl+b x to detach and return to UwU"))
        print()

        subprocess.run(["tmux", "attach-session", "-t", session_name])

        print()
        print(Style.info("Detached from Sliver session"))
        print(Style.info("Sliver is still running in background"))

    def _kill_sliver_tmux(self) -> None:
        """Kill Sliver tmux session"""
        import subprocess

        session_name = self._find_sliver_tmux_session()

        if not session_name:
            print(Style.warning("No Sliver session found"))
            return

        result = subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            capture_output=True
        )

        if result.returncode == 0:
            print(Style.success(f"Session '{session_name}' killed"))
        else:
            print(Style.error("Failed to kill session"))

    # =========================================================================
    # POTATO EXPLOITS COMMAND
    # =========================================================================

    def cmd_potatoes(self, args: List[str]) -> None:
        """Manage potato exploits for SeImpersonate privilege escalation"""
        if not args:
            self._potatoes_help()
            return

        subcmd = args[0].lower()

        if subcmd in ("download", "update"):
            self._download_potatoes()
        elif subcmd == "list":
            self._list_potatoes()
        elif subcmd == "path":
            if len(args) > 1:
                new_path = args[1]
                self.config.setg("POTATO_PATH", new_path)
                print(Style.success(f"POTATO_PATH => {new_path}"))
            else:
                current = self.config.get("POTATO_PATH", "/opt/my-resources/tools/potatoes")
                print(Style.info(f"Current POTATO_PATH: {current}"))
        elif subcmd == "info":
            self._potatoes_info()
        else:
            self._potatoes_help()

    def _potatoes_help(self) -> None:
        """Show potatoes help"""
        print(f"""
{Colors.NEON_ORANGE}Potato Exploit Manager{Colors.RESET}
{Colors.NEON_ORANGE}======================{Colors.RESET}

{Colors.NEON_CYAN}potatoes download{Colors.RESET}     Download all potato exploits
{Colors.NEON_CYAN}potatoes list{Colors.RESET}         List available/downloaded potatoes
{Colors.NEON_CYAN}potatoes path [dir]{Colors.RESET}   Show or set potato directory
{Colors.NEON_CYAN}potatoes info{Colors.RESET}         Show detailed info about each potato

{Colors.NEON_PURPLE}Usage with seimpersonate module:{Colors.RESET}
  use post/windows/seimpersonate
  set POTATO godpotato
  set SESSION 1
  set EXECUTE "whoami"
  run
""")

    def _potatoes_info(self) -> None:
        """Show detailed potato info"""
        potatoes = {
            "GodPotato": "Windows 8-11, Server 2012-2022. Most reliable modern option.",
            "PrintSpoofer": "Abuses print spooler. Fast and simple.",
            "SweetPotato": "Combines multiple techniques. Good fallback.",
            "JuicyPotato": "Classic exploit. Works on older Windows (pre-2019).",
            "RoguePotato": "Requires external listener. For restricted environments.",
        }
        print(f"\n  {Colors.NEON_ORANGE}Potato Exploits Info{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}{'='*50}{Colors.RESET}\n")
        for name, desc in potatoes.items():
            print(f"  {Colors.NEON_GREEN}{name}{Colors.RESET}")
            print(f"    {desc}\n")

    def _list_potatoes(self) -> None:
        """List available potatoes"""
        potato_dir = Path(self.config.get("POTATO_PATH", "/opt/my-resources/tools/potatoes"))

        potatoes = {
            "GodPotato.exe": "godpotato",
            "PrintSpoofer.exe": "printspoofer",
            "SweetPotato.exe": "sweetpotato",
            "JuicyPotato.exe": "juicypotato",
            "RoguePotato.exe": "roguepotato",
        }

        print(f"\n  {Colors.NEON_ORANGE}Potato Exploits{Colors.RESET}")
        print(f"  {Colors.NEON_ORANGE}{'='*50}{Colors.RESET}")
        print(f"  Directory: {potato_dir}\n")

        for filename, module_name in potatoes.items():
            filepath = potato_dir / filename
            if filepath.exists() and filepath.stat().st_size > 1000:
                size_kb = filepath.stat().st_size // 1024
                print(f"  {Colors.NEON_GREEN}[OK]{Colors.RESET}  {filename} ({size_kb}KB)")
            else:
                print(f"  {Colors.NEON_RED}[--]{Colors.RESET}  {filename} (not found)")

        print(f"\n  Run {Colors.NEON_CYAN}potatoes download{Colors.RESET} to download missing exploits")

    def _download_potatoes(self) -> bool:
        """Download all potato exploits"""
        import urllib.request
        import zipfile
        import io

        # Potato sources
        potatoes = {
            "GodPotato.exe": {
                "url": "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe",
            },
            "PrintSpoofer.exe": {
                "url": "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe",
            },
            "JuicyPotato.exe": {
                "url": "https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe",
            },
            "RoguePotato.exe": {
                "url": "https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip",
                "zip_extract": "RoguePotato.exe",
            },
            "SweetPotato.exe": {
                "url": "https://raw.githubusercontent.com/uknowsec/SweetPotato/master/SweetPotato-Webshell-new/bin/Release/SweetPotato.exe",
            },
        }

        # Determine output directory
        output_dir = Path(self.config.get("POTATO_PATH", "/opt/my-resources/tools/potatoes"))

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            test_file = output_dir / ".write_test"
            test_file.touch()
            test_file.unlink()
        except (PermissionError, OSError):
            output_dir = Path.home() / ".local" / "share" / "potatoes"
            output_dir.mkdir(parents=True, exist_ok=True)
            print(Style.warning(f"Using fallback directory: {output_dir}"))
            self.config.setg("POTATO_PATH", str(output_dir))

        print(Style.info(f"Downloading potatoes to: {output_dir}"))
        print()

        downloaded = []
        skipped = []
        failed = []

        for filename, info in potatoes.items():
            dest_path = output_dir / filename

            # Skip if exists
            if dest_path.exists() and dest_path.stat().st_size > 1000:
                print(Style.success(f"Already exists: {filename}"))
                skipped.append(filename)
                continue

            print(Style.info(f"Downloading {filename}..."))

            try:
                req = urllib.request.Request(info["url"], headers={"User-Agent": "UwU-Toolkit"})
                with urllib.request.urlopen(req, timeout=60) as response:
                    data = response.read()

                # Handle zip extraction
                if info.get("zip_extract"):
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        for name in zf.namelist():
                            if info["zip_extract"].lower() in name.lower():
                                with open(dest_path, "wb") as f:
                                    f.write(zf.read(name))
                                break
                else:
                    with open(dest_path, "wb") as f:
                        f.write(data)

                if dest_path.exists() and dest_path.stat().st_size > 1000:
                    print(Style.success(f"  Saved: {dest_path}"))
                    downloaded.append(filename)
                else:
                    print(Style.error(f"  Download failed or corrupt"))
                    failed.append(filename)

            except Exception as e:
                print(Style.error(f"  Error: {e}"))
                failed.append(filename)

        # Summary
        print()
        print(f"Downloaded: {len(downloaded)}, Existing: {len(skipped)}, Failed: {len(failed)}")
        if downloaded or skipped:
            print(Style.success(f"Potatoes ready in: {output_dir}"))
            print(Style.info("Use: use post/windows/seimpersonate"))
        return len(failed) == 0

    # =========================================================================
    # STATUS OVERVIEW COMMAND
    # =========================================================================

    def cmd_status(self, args: List[str]) -> None:
        """Show status of all services, listeners, and sessions"""
        from datetime import datetime

        print(f"\n  {Colors.NEON_PINK}UwU Toolkit Status{Colors.RESET}")
        print(f"  {Colors.NEON_PINK}{'='*60}{Colors.RESET}\n")

        # ---- HTTP Servers / Services ----
        print(f"  {Colors.NEON_CYAN}Web Servers{Colors.RESET}")
        print(f"  {'-'*50}")
        if self.processes:
            for name, proc in self.processes.items():
                # Parse port from name (e.g., "http-8000" -> 8000)
                port = "?"
                if "-" in name:
                    parts = name.rsplit("-", 1)
                    if parts[-1].isdigit():
                        port = parts[-1]
                server_type = name.split("-")[0].upper()

                if proc.poll() is None:
                    print(f"  {Colors.NEON_GREEN}[RUNNING]{Colors.RESET}  {server_type:<6} Port {Colors.NEON_MAGENTA}{port}{Colors.RESET}  (PID: {proc.pid})")
                    print(f"             {Colors.GRID}http://0.0.0.0:{port}{Colors.RESET}")
                else:
                    print(f"  {Colors.NEON_ORANGE}[STOPPED]{Colors.RESET}  {server_type:<6} Port {port}")
        else:
            print(f"  {Colors.GRID}No web servers running{Colors.RESET}")
            print(f"  {Colors.GRID}Start with: start gosh [port] | start php [port]{Colors.RESET}")
        print()

        # ---- Listeners (Reverse Shell Catchers) ----
        print(f"  {Colors.NEON_CYAN}Listeners (Reverse Shell){Colors.RESET}")
        print(f"  {'-'*50}")
        listeners = self.shell_manager.list_listeners()
        if listeners:
            for listener in listeners:
                port = listener.get("port", "?")
                ltype = listener.get("type", "nc").upper()
                connections = listener.get("connections", 0)
                if listener.get("active"):
                    status_icon = f"{Colors.NEON_GREEN}[LISTENING]{Colors.RESET}"
                    if connections > 0:
                        status_icon = f"{Colors.NEON_MAGENTA}[{connections} SHELL(S)]{Colors.RESET}"
                else:
                    status_icon = f"{Colors.NEON_ORANGE}[INACTIVE]{Colors.RESET}"
                print(f"  {status_icon}  Port {Colors.NEON_MAGENTA}{port}{Colors.RESET} ({ltype})")
        else:
            print(f"  {Colors.GRID}No listeners active{Colors.RESET}")
            print(f"  {Colors.GRID}Start with: listen <port> [nc|penelope]{Colors.RESET}")
        print()

        # ---- Tmux Sessions ----
        print(f"  {Colors.NEON_CYAN}Sessions{Colors.RESET}")
        print(f"  {'-'*40}")
        tmux_sessions = self._list_tmux_sessions()
        shells = self.shell_manager.list_shells()
        if tmux_sessions:
            for idx, sess in enumerate(tmux_sessions, 1):
                status = f"{Colors.NEON_GREEN}[ACTIVE]{Colors.RESET}" if sess.get("attached") else f"{Colors.NEON_CYAN}[DETACHED]{Colors.RESET}"
                try:
                    ts = datetime.fromtimestamp(int(sess.get("created", 0))).strftime("%H:%M")
                except:
                    ts = "?"
                print(f"  {Colors.NEON_MAGENTA}[{idx}]{Colors.RESET} {status}  {sess['name']} ({ts})")
        if shells:
            for shell in shells:
                sid = shell.get("id", "?")
                target = shell.get("remote", "unknown")
                status = f"{Colors.NEON_GREEN}[CONNECTED]{Colors.RESET}"
                print(f"  {Colors.NEON_MAGENTA}[S{sid}]{Colors.RESET} {status}  Shell from {target}")
        if not tmux_sessions and not shells:
            print(f"  {Colors.GRID}No active sessions{Colors.RESET}")
            print(f"  {Colors.GRID}Create with: use evil_winrm{Colors.RESET}")
        print()

        # ---- Penelope Status ----
        try:
            pen_status = self.penelope_mode.status()
            if pen_status.get("process_alive"):
                sessions = pen_status.get("sessions", 0)
                port = pen_status.get("port", "?")
                if pen_status.get("backgrounded"):
                    print(f"  {Colors.NEON_CYAN}Penelope{Colors.RESET}: {Colors.NEON_GREEN}Backgrounded{Colors.RESET} (port {port}, {sessions} sessions)")
                else:
                    print(f"  {Colors.NEON_CYAN}Penelope{Colors.RESET}: {Colors.NEON_GREEN}Running{Colors.RESET} (port {port}, {sessions} sessions)")
        except:
            pass

        # ---- Ligolo Status ----
        try:
            lig_status = self.ligolo_mode.status()
            if lig_status.get("process_alive"):
                agents = lig_status.get("agents", 0)
                if lig_status.get("backgrounded"):
                    print(f"  {Colors.NEON_CYAN}Ligolo{Colors.RESET}:   {Colors.NEON_GREEN}Backgrounded{Colors.RESET} ({agents} agents)")
                else:
                    print(f"  {Colors.NEON_CYAN}Ligolo{Colors.RESET}:   {Colors.NEON_GREEN}Running{Colors.RESET} ({agents} agents)")
        except:
            pass

        # ---- Quick Commands ----
        print(f"\n  {Colors.GRID}Quick commands: sessions | interact <id> | listeners | start gosh{Colors.RESET}")
        print()
