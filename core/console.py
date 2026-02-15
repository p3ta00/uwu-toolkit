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
import time
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
from .targets import TargetManager, print_targets_table
from .opsec import get_opsec_info, format_opsec_warning, OpsecRating
from .engagement_db import EngagementDB
from .macros import get_macro_manager
from .handlers import (ModuleHandler, VariableHandler, ServerHandler,
                       ShellHandler, C2Handler, ToolsHandler)


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
                # Completing variable name — include "target" and "dc" pseudo-vars
                matches = self._complete_variables(text)
                for pseudo in ("target", "dc"):
                    if pseudo.startswith(text.lower()):
                        matches.append(pseudo)
                return matches
            elif len(parts) >= 2:
                var_name = parts[1].lower()
                # Tab-complete target IDs for 'set target <TAB>'
                if var_name == "target":
                    ids = [str(i) for i in self.console.target_manager.get_target_ids()]
                    return [i for i in ids if i.startswith(text)]
                # Tab-complete DC IDs for 'set dc <TAB>'
                elif var_name == "dc":
                    ids = [str(i) for i in self.console.target_manager.get_dc_ids()]
                    return [i for i in ids if i.startswith(text)]
                # Normal history completion
                return self._complete_history(var_name.upper(), text)
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
        elif cmd == "target":
            if len(parts) == 2 and not line.endswith(" "):
                subcmds = ["list", "del", "vhost", "domain", "notes", "clear", "help"]
                return [s for s in subcmds if s.startswith(text)]
            elif len(parts) >= 2:
                # Complete target IDs for subcommands that take one
                sub = parts[1].lower()
                if sub in ("del", "delete", "rm", "vhost", "domain", "notes"):
                    ids = [str(i) for i in self.console.target_manager.get_target_ids()]
                    return [i for i in ids if i.startswith(text)]
        elif cmd == "uwu-clear":
            subcmds = ["all", "db", "creds", "targets", "globals", "permanent", "history", "events"]
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

        # Credential manager
        self.cred_manager = CredentialManager(str(config.config_dir))

        # Target manager
        self.target_manager = TargetManager(str(config.config_dir))

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

        # Command handlers
        self._module_handler = ModuleHandler(self)
        self._variable_handler = VariableHandler(self)
        self._server_handler = ServerHandler(self)
        self._shell_handler = ShellHandler(self)
        self._c2_handler = C2Handler(self)
        self._tools_handler = ToolsHandler(self)

        # Backward-compat aliases for code that calls self.cmd_xxx directly
        self.cmd_options = self._module_handler.cmd_options
        self.cmd_info = self._module_handler.cmd_info
        self.cmd_run = self._module_handler.cmd_run

        # Command registry
        self.commands: Dict[str, Callable] = {
            # Core commands (stay in console.py)
            "help": self.cmd_help,
            "?": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
            "clear": self.cmd_clear,
            "banner": self.cmd_banner,

            # Module commands (ModuleHandler)
            "use": self._module_handler.cmd_use,
            "back": self._module_handler.cmd_back,
            "info": self._module_handler.cmd_info,
            "options": self._module_handler.cmd_options,
            "run": self._module_handler.cmd_run,
            "exploit": self._module_handler.cmd_run,
            "check": self._module_handler.cmd_check,
            "search": self._module_handler.cmd_search,
            "reload": self._module_handler.cmd_reload,
            "reloadall": self._module_handler.cmd_reloadall,

            # Variable commands (VariableHandler)
            "set": self._variable_handler.cmd_set,
            "get": self._variable_handler.cmd_get,
            "setg": self._variable_handler.cmd_setg,
            "getg": self._variable_handler.cmd_getg,
            "setp": self._variable_handler.cmd_setp,
            "getp": self._variable_handler.cmd_getp,
            "unset": self._variable_handler.cmd_unset,
            "unsetg": self._variable_handler.cmd_unsetg,
            "unsetp": self._variable_handler.cmd_unsetp,
            "show": self._variable_handler.cmd_show,
            "showp": self._variable_handler.cmd_showp,
            "vars": self._variable_handler.cmd_vars,
            "globals": self._variable_handler.cmd_globals,
            "history": self._variable_handler.cmd_history,
            "cleang": self._variable_handler.cmd_cleang,
            "cleanp": self._variable_handler.cmd_cleanp,

            # Server utilities (ServerHandler)
            "start": self._server_handler.cmd_start,
            "stop": self._server_handler.cmd_stop,
            "listeners": self._server_handler.cmd_listeners,

            # Shell management (ShellHandler)
            "shells": self._shell_handler.cmd_shells,
            "sessions": self._shell_handler.cmd_shells,
            "session": self._shell_handler.cmd_interact,
            "interact": self._shell_handler.cmd_interact,
            "kill": self._shell_handler.cmd_kill_shell,
            "upgrade": self._shell_handler.cmd_upgrade_shell,
            "listen": self._shell_handler.cmd_listen,

            # Shell escape & export (ToolsHandler)
            "shell": self._tools_handler.cmd_shell,
            "!": self._tools_handler.cmd_shell,
            "export": self._tools_handler.cmd_export,

            # Claude AI (C2Handler)
            "claude": self._c2_handler.cmd_claude,
            "ai": self._c2_handler.cmd_claude,

            # Sliver C2 (C2Handler)
            "sliver": self._c2_handler.cmd_sliver,

            # Penelope (C2Handler)
            "penelope": self._c2_handler.cmd_penelope,

            # Ligolo (C2Handler)
            "ligolo": self._c2_handler.cmd_ligolo,

            # Tools (ToolsHandler)
            "potatoes": self._tools_handler.cmd_potatoes,
            "nxc": self._tools_handler.cmd_nxc,
            "creds": self._tools_handler.cmd_creds,
            "target": self._tools_handler.cmd_target,
            "clocksync": self._tools_handler.cmd_clocksync,
            "hosts": self._tools_handler.cmd_hosts,
            "status": self._tools_handler.cmd_status,
            "timeline": self._tools_handler.cmd_timeline,
            "report": self._tools_handler.cmd_report,
            "macro": self._tools_handler.cmd_macro,
            "hashcrack_setup": self._tools_handler.cmd_hashcrack_setup,
            "uwu-clear": self._tools_handler.cmd_uwu_clear,
        }

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

    # =========================================================================
    # Prompt, Main Loop, Command Dispatch
    # =========================================================================

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
            self._tools_handler.cmd_shell(line[1:].split())
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
  {Colors.NEON_CYAN}reload{Colors.RESET}             Reload the current module (preserves options)
  {Colors.NEON_CYAN}reload all{Colors.RESET}         Reload all modules and discover new ones

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

{Colors.NEON_GREEN}Target Management{Colors.RESET}
{Colors.NEON_GREEN}================={Colors.RESET}
  {Colors.NEON_CYAN}set target <ip> <host> [dc]{Colors.RESET}  Register target (dc = domain controller)
  {Colors.NEON_CYAN}set target <id>{Colors.RESET}              Select target => RHOSTS, RHOST
  {Colors.NEON_CYAN}set dc <id>{Colors.RESET}                  Select DC => DC_IP, DC_HOST, DOMAIN
  {Colors.NEON_CYAN}target{Colors.RESET}                       List all targets
  {Colors.NEON_CYAN}target del <id>{Colors.RESET}              Delete a target
  {Colors.NEON_CYAN}target vhost <id> <host>{Colors.RESET}     Add vhost (updates /etc/hosts)
  {Colors.NEON_CYAN}target domain <id> <dom>{Colors.RESET}     Set domain
  {Colors.NEON_CYAN}target notes <id> <text>{Colors.RESET}     Set notes
  {Colors.NEON_CYAN}target help{Colors.RESET}                  Full target command help

{Colors.NEON_RED}Credentials{Colors.RESET}
{Colors.NEON_RED}==========={Colors.RESET}
  {Colors.NEON_CYAN}creds{Colors.RESET}                  List pwned credentials
  {Colors.NEON_CYAN}creds add <user> <pass>{Colors.RESET} Add credential (use -h for hash, -d for domain)
  {Colors.NEON_CYAN}creds del <user>{Colors.RESET}       Delete credential
  {Colors.NEON_CYAN}creds use <user>{Colors.RESET}       Load cred into USER/PASS/DOMAIN
  {Colors.NEON_CYAN}creds show{Colors.RESET}             Show creds with secrets visible
  {Colors.NEON_CYAN}creds import <file>{Colors.RESET}    Import from secretsdump output

{Colors.DIGITAL_RAIN}Setup & Config{Colors.RESET}
{Colors.DIGITAL_RAIN}=============={Colors.RESET}
  {Colors.NEON_CYAN}hashcrack_setup{Colors.RESET}         Configure remote hashcat cracking host
  {Colors.NEON_CYAN}hashcrack_setup --show{Colors.RESET}  Show current hashcrack config
  {Colors.NEON_CYAN}hashcrack_setup --test{Colors.RESET}  Test SSH connection to cracker
  {Colors.NEON_CYAN}hashcrack_setup --add-key{Colors.RESET}  Add SSH key (run on HOST)
  {Colors.NEON_CYAN}uwu-clear <what>{Colors.RESET}       Clear data (all/db/creds/targets/globals/permanent/history/events)

{Colors.NEON_ORANGE}Clock Skew Fix{Colors.RESET}
{Colors.NEON_ORANGE}=============={Colors.RESET}
  {Colors.NEON_CYAN}clocksync{Colors.RESET}                  Auto-sync time with DC (uses DC_IP)
  {Colors.NEON_CYAN}clocksync <dc_ip>{Colors.RESET}          Sync with specific DC
  {Colors.NEON_CYAN}clocksync --status{Colors.RESET}         Show current FAKETIME setting
  {Colors.NEON_CYAN}clocksync --clear{Colors.RESET}          Clear FAKETIME (real system time)
  {Colors.NEON_CYAN}setg FAKETIME '<time>'{Colors.RESET}     Manual: set spoofed time globally

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
