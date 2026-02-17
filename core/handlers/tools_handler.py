"""
Tools handler for UwU Toolkit console.
Handles NXC, credentials, targets, clocksync, hosts, potatoes, status,
timeline, report, macro, hashcrack_setup, shell escape, and export commands.
"""

import os
import re
import subprocess
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from . import HandlerBase
from ..colors import Colors, Style
from ..creds import CredentialManager, print_creds_table
from ..targets import TargetManager, print_targets_table
from ..engagement_db import EngagementDB
from ..macros import get_macro_manager
from ..opsec import get_opsec_info, format_opsec_warning, OpsecRating
from ..module_base import EXEGOL_PATH, KALI_PATH
from .. import tmux_status


def _find_exegol_container() -> Optional[str]:
    """Auto-detect a running Exegol container"""
    if not shutil.which("docker"):
        return None
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


def _is_inside_exegol() -> bool:
    """Check if we're running inside an Exegol container"""
    return os.path.exists("/.exegol") or os.path.exists("/opt/.exegol_aliases")


def _is_native_linux() -> bool:
    """Check if we're on a native Linux host (Kali, etc.) — not inside Exegol"""
    if _is_inside_exegol():
        return False
    return os.path.exists("/etc/os-release")


class ToolsHandler(HandlerBase):
    """Handles NXC, credentials, targets, clocksync, hosts, potatoes, status,
    timeline, report, macro, hashcrack_setup, shell escape, and export commands."""

    # =========================================================================
    # NXC Module Help
    # =========================================================================

    def _get_nxc_module_help(self, module_name: Optional[str] = None) -> Optional[str]:
        """
        Get NXC module options.
        Args:
            module_name: NXC module name (uses NXC_MODULE from config if not provided)
        Returns formatted help text or None.
        """
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
        nxc_cmd = f"netexec {protocol} -M {nxc_module} --options 2>&1"

        try:
            # Check if we're inside Exegol - run directly
            if _is_inside_exegol():
                result = subprocess.run(
                    ["bash", "-c", f"export PATH={EXEGOL_PATH}:$PATH && {nxc_cmd}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                # Get container for docker exec
                container = (self.config.getg("EXEGOL_CONTAINER") or
                             self.config.get("EXEGOL_CONTAINER") or
                             _find_exegol_container())

                if container:
                    result = subprocess.run(
                        ["docker", "exec", container, "bash", "-ic", f"export PATH={EXEGOL_PATH}:$PATH && {nxc_cmd}"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                elif _is_native_linux():
                    result = subprocess.run(
                        ["bash", "-c", f"export PATH={KALI_PATH}:$PATH && {nxc_cmd}"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                else:
                    return f"\n{Colors.NEON_ORANGE}NXC Module Help{Colors.RESET}\n{Colors.NEON_ORANGE}==============={Colors.RESET}\n  {Colors.NEON_RED}No Exegol container found. Start one to see module options.{Colors.RESET}\n"

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

    # =========================================================================
    # Credential Management
    # =========================================================================

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
            creds = self.console.cred_manager.list_all()
            print_creds_table(creds, show_secrets=False)
            return

        subcmd = args[0].lower()

        if subcmd in ("help", "info", "?"):
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

            self.console.cred_manager.add(
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
                cred = self.console.cred_manager.get_by_id(cred_id)
                if cred and self.console.cred_manager.delete_by_id(cred_id):
                    print(Style.success(f"Deleted credential #{cred_id}: {cred.get('username')}"))
                else:
                    print(Style.error(f"Credential ID {cred_id} not found"))
            else:
                username = args[1]
                domain = None
                if "\\" in username:
                    domain, username = username.split("\\", 1)

                if self.console.cred_manager.delete(username, domain):
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
                cred = self.console.cred_manager.get_by_id(cred_id)
                if not cred:
                    print(Style.error(f"Credential ID {cred_id} not found"))
                    return
            else:
                username = args[1]
                domain = None
                if "\\" in username:
                    domain, username = username.split("\\", 1)

                cred = self.console.cred_manager.get(username, domain)
                if not cred:
                    print(Style.error(f"Credential not found: {args[1]}"))
                    return

            # Set variables from credential (config + module + global)
            if cred.get("username"):
                self.config.set("USER", cred["username"])
                self.config.setg("USER", cred["username"])
                if self.current_module:
                    self.current_module.set_option("USER", cred["username"])
                print(Style.info(f"USER => {cred['username']} (global)"))

            if cred.get("password"):
                self.config.set("PASS", cred["password"])
                self.config.setg("PASS", cred["password"])
                if self.current_module:
                    self.current_module.set_option("PASS", cred["password"])
                # Clear HASHES when using password auth
                self.config.set("HASHES", "")
                self.config.setg("HASHES", "")
                if self.current_module and self.current_module.has_option("HASHES"):
                    self.current_module.set_option("HASHES", "")
                print(Style.info(f"PASS => {cred['password']} (global)"))
            elif cred.get("ntlm_hash"):
                ntlm = cred["ntlm_hash"]
                # Set PASS for modules that use PASS for everything (bloodyAD, etc.)
                self.config.set("PASS", ntlm)
                self.config.setg("PASS", ntlm)
                if self.current_module:
                    self.current_module.set_option("PASS", ntlm)
                # Set HASHES in LM:NT format for impacket modules
                hashes_val = f":{ntlm}" if ":" not in ntlm else ntlm
                self.config.set("HASHES", hashes_val)
                self.config.setg("HASHES", hashes_val)
                if self.current_module and self.current_module.has_option("HASHES"):
                    self.current_module.set_option("HASHES", hashes_val)
                print(Style.info(f"PASS => {ntlm} (hash, global)"))
                print(Style.info(f"HASHES => {hashes_val} (global)"))

            if cred.get("domain"):
                self.config.set("DOMAIN", cred["domain"])
                self.config.setg("DOMAIN", cred["domain"])
                if self.current_module:
                    self.current_module.set_option("DOMAIN", cred["domain"])
                print(Style.info(f"DOMAIN => {cred['domain']} (global)"))

            print(Style.success(f"Loaded credential: {args[1]}"))

        elif subcmd == "search":
            if len(args) < 2:
                print(Style.error("Usage: creds search <query>"))
                return

            results = self.console.cred_manager.search(args[1])
            print_creds_table(results, show_secrets=False)

        elif subcmd in ("show", "list"):
            # Show all creds with secrets visible
            show_secrets = subcmd == "show" or (len(args) > 1 and args[1] == "-s")
            creds = self.console.cred_manager.list_all()
            print_creds_table(creds, show_secrets=show_secrets)

        elif subcmd == "clear":
            count = self.console.cred_manager.clear_all()
            print(Style.success(f"Cleared {count} credential(s)"))

        elif subcmd == "import":
            if len(args) < 2:
                print(Style.error("Usage: creds import <secretsdump_file>"))
                return

            filepath = args[1]
            if not os.path.exists(filepath):
                print(Style.error(f"File not found: {filepath}"))
                return

            count = self.console.cred_manager.import_secretsdump(filepath)
            print(Style.success(f"Imported {count} credential(s) from {filepath}"))

        elif subcmd == "export":
            fmt = args[1] if len(args) > 1 else "hashcat"
            output = args[2] if len(args) > 2 else None

            if fmt == "hashcat":
                content = self.console.cred_manager.export_hashcat(output)
            else:
                content = self.console.cred_manager.export_secretsdump(output)

            if output:
                print(Style.success(f"Exported to {output}"))
            else:
                print(content)

        else:
            print(Style.error(f"Unknown subcommand: {subcmd}"))
            print("Usage: creds [add|del|use|search|show|clear|import|export]")

    # =========================================================================
    # Target Management
    # =========================================================================

    def cmd_target(self, args: List[str]) -> None:
        """
        Target management command

        Usage:
            target                          List all targets
            target list                     List all targets
            target del <id>                 Delete a target
            target vhost <id> <hostname>    Add vhost to target
            target vhost del <id> <vhost>   Remove vhost from target
            target domain <id> <domain>     Set domain for a target
            target notes <id> <text>        Set notes
            target clear                    Clear all targets
        """
        if not args or args[0].lower() in ("list", "ls"):
            targets = self.console.target_manager.list_all()
            print_targets_table(targets)
            return

        subcmd = args[0].lower()

        if subcmd in ("del", "delete", "rm"):
            if len(args) < 2 or not args[1].isdigit():
                print(Style.error("Usage: target del <id>"))
                return
            target_id = int(args[1])
            target = self.console.target_manager.get(target_id)
            if target and self.console.target_manager.delete(target_id):
                print(Style.success(f"Deleted target #{target_id}: {target['ip']}"))
            else:
                print(Style.error(f"Target #{target_id} not found"))

        elif subcmd == "vhost":
            if len(args) >= 3 and args[1].lower() == "del":
                # target vhost del <id> <vhost>
                if len(args) < 4 or not args[2].isdigit():
                    print(Style.error("Usage: target vhost del <id> <vhost>"))
                    return
                target_id = int(args[2])
                vhost = args[3]
                if self.console.target_manager.del_vhost(target_id, vhost):
                    target = self.console.target_manager.get(target_id)
                    if target:
                        self._update_etc_hosts_for_target(target)
                    print(Style.success(f"Removed vhost {vhost} from target #{target_id}"))
                else:
                    print(Style.error(f"VHost {vhost} not found on target #{target_id}"))
            elif len(args) >= 3 and args[1].isdigit():
                # target vhost <id> <hostname>
                if len(args) < 3:
                    print(Style.error("Usage: target vhost <id> <hostname>"))
                    return
                target_id = int(args[1])
                vhost = args[2]
                if self.console.target_manager.add_vhost(target_id, vhost):
                    target = self.console.target_manager.get(target_id)
                    if target:
                        self._update_etc_hosts_for_target(target)
                    print(Style.success(f"Added vhost {vhost} to target #{target_id}"))
                else:
                    print(Style.error(f"Target #{target_id} not found"))
            else:
                print(Style.error("Usage: target vhost <id> <hostname>"))
                print(Style.error("       target vhost del <id> <vhost>"))

        elif subcmd == "domain":
            if len(args) < 3 or not args[1].isdigit():
                print(Style.error("Usage: target domain <id> <domain>"))
                return
            target_id = int(args[1])
            domain = args[2]
            if self.console.target_manager.set_domain(target_id, domain):
                print(Style.success(f"Target #{target_id} domain => {domain}"))
            else:
                print(Style.error(f"Target #{target_id} not found"))

        elif subcmd == "notes":
            if len(args) < 3 or not args[1].isdigit():
                print(Style.error("Usage: target notes <id> <text>"))
                return
            target_id = int(args[1])
            notes = " ".join(args[2:])
            if self.console.target_manager.set_notes(target_id, notes):
                print(Style.success(f"Target #{target_id} notes => {notes}"))
            else:
                print(Style.error(f"Target #{target_id} not found"))

        elif subcmd == "clear":
            count = self.console.target_manager.clear_all()
            print(Style.success(f"Cleared {count} target(s)"))

        elif subcmd in ("help", "info", "?"):
            print(f"""
{Colors.NEON_PINK}Target Commands{Colors.RESET}
{Colors.NEON_PINK}==============={Colors.RESET}

{Colors.BRIGHT_WHITE}Registration & Selection:{Colors.RESET}
  {Colors.NEON_CYAN}set target <ip> <hostname> [dc]{Colors.RESET}   Register target (dc flag marks as DC)
  {Colors.NEON_CYAN}set target <id>{Colors.RESET}                   Select target => sets RHOSTS, RHOST
  {Colors.NEON_CYAN}set dc <id>{Colors.RESET}                       Select DC => sets DC_IP, DC_HOST, DOMAIN

{Colors.BRIGHT_WHITE}Listing:{Colors.RESET}
  {Colors.NEON_CYAN}target{Colors.RESET}                             List all targets
  {Colors.NEON_CYAN}target list{Colors.RESET}                        List all targets

{Colors.BRIGHT_WHITE}Managing:{Colors.RESET}
  {Colors.NEON_CYAN}target del <id>{Colors.RESET}                    Delete a target
  {Colors.NEON_CYAN}target domain <id> <domain>{Colors.RESET}        Set domain
  {Colors.NEON_CYAN}target notes <id> <text>{Colors.RESET}           Set notes
  {Colors.NEON_CYAN}target vhost <id> <hostname>{Colors.RESET}       Add vhost (updates /etc/hosts)
  {Colors.NEON_CYAN}target vhost del <id> <vhost>{Colors.RESET}      Remove vhost
  {Colors.NEON_CYAN}target clear{Colors.RESET}                       Clear all targets
""")

        else:
            print(Style.error(f"Unknown target subcommand: {subcmd}"))
            print(Style.info("Use 'target help' for usage"))

    def _update_etc_hosts_for_target(self, target: Dict[str, Any]) -> None:
        """Update /etc/hosts with target IP -> hostname + vhosts"""
        ip = target["ip"]
        hostname = target.get("hostname", "")
        vhosts = target.get("vhosts", [])

        # Build hostnames list
        names = []
        if hostname:
            names.append(hostname)
        for vh in vhosts:
            if vh not in names:
                names.append(vh)

        if not names:
            return

        hosts_line = f"{ip}\t{' '.join(names)}"

        try:
            if _is_inside_exegol():
                self._update_hosts_file_direct(ip, hosts_line)
            elif _is_native_linux():
                self._update_hosts_file_native(ip, hosts_line)
            else:
                container = (self.config.getg("EXEGOL_CONTAINER") or
                             self.config.get("EXEGOL_CONTAINER") or
                             _find_exegol_container())
                if container:
                    self._update_hosts_file_docker(container, ip, hosts_line)
                else:
                    print(Style.warning("No Exegol container found -- /etc/hosts not updated"))
        except Exception as e:
            print(Style.warning(f"Could not update /etc/hosts: {e}"))

    def _update_hosts_file_direct(self, ip: str, hosts_line: str) -> None:
        """Update /etc/hosts directly (when inside Exegol)"""
        # Check if IP already has an entry -- replace it; otherwise append
        with open('/etc/hosts', 'r') as f:
            lines = f.readlines()

        found = False
        new_lines = []
        for line in lines:
            if line.strip() and line.split()[0] == ip:
                new_lines.append(hosts_line + '\n')
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(hosts_line + '\n')

        with open('/etc/hosts', 'w') as f:
            f.writelines(new_lines)

        print(Style.success(f"/etc/hosts: {hosts_line}"))

    def _update_hosts_file_native(self, ip: str, hosts_line: str) -> None:
        """Update /etc/hosts on native Linux via sudo"""
        with open('/etc/hosts', 'r') as f:
            lines = f.readlines()

        found = False
        new_lines = []
        for line in lines:
            if line.strip() and line.split()[0] == ip:
                new_lines.append(hosts_line + '\n')
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(hosts_line + '\n')

        content = ''.join(new_lines)
        proc = subprocess.run(
            ["sudo", "tee", "/etc/hosts"],
            input=content, capture_output=True, text=True, timeout=5
        )
        if proc.returncode == 0:
            print(Style.success(f"/etc/hosts: {hosts_line}"))
        else:
            print(Style.error(f"Failed to update /etc/hosts: {proc.stderr}"))

    def _update_hosts_file_docker(self, container: str, ip: str, hosts_line: str) -> None:
        """Update /etc/hosts via docker exec"""
        # Read current hosts
        result = subprocess.run(
            ["docker", "exec", container, "cat", "/etc/hosts"],
            capture_output=True, text=True, timeout=5
        )
        current = result.stdout

        if ip in current:
            # Replace existing line via sed
            escaped_line = hosts_line.replace('/', '\\/')
            subprocess.run(
                ["docker", "exec", container, "sed", "-i",
                 f"/^{ip}\\b/c\\{escaped_line}", "/etc/hosts"],
                timeout=5
            )
        else:
            # Append
            subprocess.run(
                ["docker", "exec", container, "bash", "-c",
                 f"echo '{hosts_line}' >> /etc/hosts"],
                timeout=5
            )

        print(Style.success(f"/etc/hosts ({container}): {hosts_line}"))

    # =========================================================================
    # Clock Sync
    # =========================================================================

    def cmd_clocksync(self, args: List[str]) -> None:
        """
        Sync time with Domain Controller to fix Kerberos clock skew (KRB_AP_ERR_SKEW).

        Usage:
            clocksync                Auto-detect DC time and set FAKETIME
            clocksync <dc_ip>        Sync with specific DC IP
            clocksync --clear        Clear FAKETIME (use real system time)
            clocksync --status       Show current FAKETIME setting and time delta
        """
        # Handle --clear
        if args and args[0] == "--clear":
            self.config.unsetg("FAKETIME")
            print(Style.success("FAKETIME cleared -- using real system time"))
            return

        # Handle --status
        if args and args[0] == "--status":
            ft = self.config.getg("FAKETIME")
            if ft:
                print(Style.info(f"FAKETIME = {ft}"))
                print(Style.info("All Kerberos commands will use spoofed time"))
            else:
                print(Style.info("FAKETIME not set -- using real system time"))
            return

        # Get DC IP
        dc_ip = args[0] if args else (self.config.get("DC_IP") or self.config.get("RHOSTS"))
        if not dc_ip:
            print(Style.error("No DC_IP set. Usage: clocksync <dc_ip>"))
            return

        print(Style.info(f"Querying time from {dc_ip}..."))

        # Method 1: Try net time (samba-common-bin)
        faketime_val = self._clocksync_net_time(dc_ip)

        # Method 2: Try rdate
        if not faketime_val:
            faketime_val = self._clocksync_rdate(dc_ip)

        # Method 3: Parse SMB NTLM timestamp via DumpNTLMInfo
        if not faketime_val:
            faketime_val = self._clocksync_smb(dc_ip)

        if not faketime_val:
            print(Style.error("Could not determine DC time"))
            print(Style.info("Install net, rdate, or try manually:"))
            print(Style.info("  setg FAKETIME '2026-02-15 00:09:00'"))
            return

        # Check if time is already close enough (< 5 min)
        try:
            dc_time = datetime.strptime(faketime_val, "%Y-%m-%d %H:%M:%S")
            local_time = datetime.now()
            delta = abs((dc_time - local_time).total_seconds())
            if delta < 300:
                print(Style.success(f"Clock is within tolerance ({int(delta)}s delta)"))
                print(Style.info("No FAKETIME needed -- Kerberos allows +/-5 minutes"))
                return
            print(Style.warning(f"Clock delta: {int(delta)}s ({int(delta/60)}m {int(delta%60)}s)"))
        except Exception:
            pass

        # Store as global FAKETIME
        self.config.setg("FAKETIME", faketime_val)
        print(Style.success(f"FAKETIME => {faketime_val} (global)"))
        print(Style.info("All impacket/bloodyAD Kerberos commands will now use this time"))
        print(Style.info("Clear with: clocksync --clear"))

    def _clocksync_net_time(self, dc_ip: str) -> str:
        """Try to get DC time via 'net time' (samba-common-bin)."""
        try:
            cmd = f"net time -S {dc_ip}"
            if _is_inside_exegol():
                result = subprocess.run(
                    ["bash", "-c", cmd],
                    capture_output=True, text=True, timeout=10
                )
            else:
                container = self.config.get("EXEGOL_CONTAINER")
                if container:
                    result = subprocess.run(
                        ["docker", "exec", container, "bash", "-c", cmd],
                        capture_output=True, text=True, timeout=10
                    )
                else:
                    result = subprocess.run(
                        ["bash", "-c", cmd],
                        capture_output=True, text=True, timeout=10
                    )
            if result.returncode == 0 and result.stdout.strip():
                # Parse "Thu Feb 15 00:09:00 2026" or similar
                # net time output: "Thu Feb 15 00:09:00 UTC 2026"
                # Extract the time part
                line = result.stdout.strip().split('\n')[0]
                # Try to parse with dateutil or manual
                parts = line.split()
                for i, p in enumerate(parts):
                    if ':' in p and len(p.split(':')) >= 2:
                        # Found time component, reconstruct
                        try:
                            dt = datetime.strptime(line, "%a %b %d %H:%M:%S %Z %Y")
                            return dt.strftime("%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            try:
                                dt = datetime.strptime(line, "%a %b %d %H:%M:%S %Y")
                                return dt.strftime("%Y-%m-%d %H:%M:%S")
                            except ValueError:
                                pass
        except Exception:
            pass
        return ""

    def _clocksync_rdate(self, dc_ip: str) -> str:
        """Try to get DC time via rdate."""
        try:
            cmd = f"rdate -n {dc_ip} -p"
            if _is_inside_exegol():
                result = subprocess.run(
                    ["bash", "-c", cmd],
                    capture_output=True, text=True, timeout=10
                )
            else:
                container = self.config.get("EXEGOL_CONTAINER")
                if container:
                    result = subprocess.run(
                        ["docker", "exec", container, "bash", "-c", cmd],
                        capture_output=True, text=True, timeout=10
                    )
                else:
                    result = subprocess.run(
                        ["bash", "-c", cmd],
                        capture_output=True, text=True, timeout=10
                    )
            if result.returncode == 0 and result.stdout.strip():
                # rdate output: "Thu Feb 15 00:09:00 2026"
                line = result.stdout.strip().split('\n')[0].strip()
                # Parse with awk piped to date
                cmd2 = f"rdate -n {dc_ip} -p 2>/dev/null | awk '{{print $2, $3, $4}}' | date -f - '+%Y-%m-%d %H:%M:%S' 2>/dev/null"
                if _is_inside_exegol():
                    result2 = subprocess.run(
                        ["bash", "-c", cmd2],
                        capture_output=True, text=True, timeout=10
                    )
                else:
                    container = self.config.get("EXEGOL_CONTAINER")
                    if container:
                        result2 = subprocess.run(
                            ["docker", "exec", container, "bash", "-c", cmd2],
                            capture_output=True, text=True, timeout=10
                        )
                    else:
                        result2 = subprocess.run(
                            ["bash", "-c", cmd2],
                            capture_output=True, text=True, timeout=10
                        )
                if result2.returncode == 0 and result2.stdout.strip():
                    return result2.stdout.strip()
        except Exception:
            pass
        return ""

    def _clocksync_smb(self, dc_ip: str) -> str:
        """Get DC time from SMB NTLM info (always available)."""
        try:
            from ..module_base import find_tool
            tool = find_tool("DumpNTLMInfo.py")
            if tool:
                cmd = f"{tool} {dc_ip}"
            else:
                cmd = f"DumpNTLMInfo.py {dc_ip}"

            if _is_inside_exegol():
                result = subprocess.run(
                    ["bash", "-l", "-c", f"export PATH={EXEGOL_PATH}:$PATH && {cmd}"],
                    capture_output=True, text=True, timeout=15
                )
            else:
                container = self.config.get("EXEGOL_CONTAINER")
                if container:
                    result = subprocess.run(
                        ["docker", "exec", container,
                         "bash", "-l", "-c", f"export PATH={EXEGOL_PATH}:$PATH && {cmd}"],
                        capture_output=True, text=True, timeout=15
                    )
                else:
                    result = subprocess.run(
                        ["bash", "-c", f"export PATH={KALI_PATH}:$PATH && {cmd}"],
                        capture_output=True, text=True, timeout=15
                    )
            output = result.stdout + result.stderr
            # Parse "Current Time    : 2026-02-15 00:08:57.555185+00:00"
            match = re.search(r'Current Time\s*:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', output)
            if match:
                return match.group(1)
        except Exception:
            pass
        return ""

    # =========================================================================
    # Hosts Generation
    # =========================================================================

    def cmd_hosts(self, args: List[str]) -> None:
        """
        Generate /etc/hosts from target and auto-discover domain

        Usage:
            hosts              - Use RHOSTS to generate hosts file
            hosts <ip>         - Use specified IP
            hosts -u           - Also update all creds without domain
        """
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
        tmp_hosts = "/tmp/.uwu_hosts_tmp"
        nxc_cmd = f"netexec smb {target} --generate-hosts-file {tmp_hosts} 2>&1"

        print(Style.info(f"Discovering hosts for {target}..."))

        try:
            if _is_inside_exegol() or _is_native_linux():
                # Run nxc locally (inside Exegol or native Linux)
                run_path = EXEGOL_PATH if _is_inside_exegol() else KALI_PATH
                result = subprocess.run(
                    ["bash", "-c", f"export PATH={run_path}:$PATH && rm -f {tmp_hosts} && {nxc_cmd}"],
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
                        # Append new entry — use sudo on native Linux
                        if _is_native_linux():
                            subprocess.run(
                                ["sudo", "bash", "-c", f"echo '{new_entry}' >> /etc/hosts"],
                                timeout=5
                            )
                        else:
                            with open('/etc/hosts', 'a') as f:
                                f.write(new_entry + '\n')
                        print(Style.success(f"Added to /etc/hosts: {new_entry}"))

            else:
                container = (self.config.getg("EXEGOL_CONTAINER") or
                             self.config.get("EXEGOL_CONTAINER") or
                             _find_exegol_container())

                if not container:
                    print(Style.error("No Exegol container found"))
                    return

                # Run nxc to temp file
                result = subprocess.run(
                    ["docker", "exec", container, "bash", "-ic",
                     f"export PATH={EXEGOL_PATH}:$PATH && rm -f {tmp_hosts} && {nxc_cmd}"],
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
                    for key, cred in self.console.cred_manager.credentials.items():
                        if not cred.get("domain"):
                            cred["domain"] = domain
                            updated += 1
                    if updated:
                        self.console.cred_manager._save()
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

    # =========================================================================
    # Potato Exploits
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
    # Status Overview
    # =========================================================================

    def cmd_status(self, args: List[str]) -> None:
        """Show status of all services, listeners, and sessions"""

        print(f"\n  {Colors.NEON_PINK}UwU Toolkit Status{Colors.RESET}")
        print(f"  {Colors.NEON_PINK}{'='*60}{Colors.RESET}\n")

        # ---- HTTP Servers / Services ----
        print(f"  {Colors.NEON_CYAN}Web Servers{Colors.RESET}")
        print(f"  {'-'*50}")
        if self.console.processes:
            for name, proc in self.console.processes.items():
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
        listeners = self.console.shell_manager.list_listeners()
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
        shells = self.console.shell_manager.list_shells()
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
            pen_status = self.console.penelope_mode.status()
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
            lig_status = self.console.ligolo_mode.status()
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

    # =========================================================================
    # Timeline
    # =========================================================================

    def cmd_timeline(self, args: List[str]) -> None:
        """Show engagement timeline"""
        try:
            db = EngagementDB.get_instance()
        except Exception as e:
            print(Style.error(f"Database error: {e}"))
            return

        limit = 20
        target_filter = None
        tool_filter = None

        i = 0
        while i < len(args):
            if args[i] == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 2
            elif args[i] == "--target" and i + 1 < len(args):
                target_filter = args[i + 1]
                i += 2
            elif args[i] == "--tool" and i + 1 < len(args):
                tool_filter = args[i + 1]
                i += 2
            else:
                i += 1

        entries = db.get_timeline(limit=limit, target=target_filter, tool=tool_filter)

        if not entries:
            print(Style.warning("No timeline entries"))
            return

        print()
        print(f"  {Colors.NEON_CYAN}Engagement Timeline{Colors.RESET}")
        print(f"  {Colors.NEON_PINK}{'=' * 80}{Colors.RESET}")
        print()
        print(f"  {Colors.BRIGHT_WHITE}{'Time':<20} {'Action':<30} {'Target':<18} {'Result':<12}{Colors.RESET}")
        print(f"  {Colors.GRID}{'-' * 20} {'-' * 30} {'-' * 18} {'-' * 12}{Colors.RESET}")

        for entry in entries:
            ts = entry.get("timestamp", "")[:19]
            action = (entry.get("action", ""))[:30]
            target = (entry.get("target", ""))[:18]
            result = entry.get("result", "")[:12]

            if result == "success":
                result_color = Colors.NEON_GREEN
            elif result in ("failed", "error"):
                result_color = Colors.RED
            elif result == "interrupted":
                result_color = Colors.YELLOW
            else:
                result_color = Colors.RESET

            opsec = entry.get("opsec_rating", "")
            if opsec in ("high", "loud"):
                action_color = Colors.NEON_ORANGE
            else:
                action_color = Colors.RESET

            print(f"  {Colors.GRID}{ts:<20}{Colors.RESET} "
                  f"{action_color}{action:<30}{Colors.RESET} "
                  f"{target:<18} "
                  f"{result_color}{result:<12}{Colors.RESET}")

        dur_entries = [e for e in entries if e.get("duration_ms", 0) > 0]
        if dur_entries:
            total_ms = sum(e.get("duration_ms", 0) for e in dur_entries)
            print()
            print(f"  {Colors.GRID}Total time: {total_ms / 1000:.1f}s across {len(dur_entries)} operations{Colors.RESET}")
        print()

    # =========================================================================
    # Report Generation
    # =========================================================================

    def cmd_report(self, args: List[str]) -> None:
        """Generate engagement report"""
        try:
            db = EngagementDB.get_instance()
        except Exception as e:
            print(Style.error(f"Database error: {e}"))
            return

        output_file = args[0] if args else None

        # Gather data
        targets = db.list_targets()
        creds = db.list_credentials()
        findings = db.list_findings()
        timeline = db.get_timeline(limit=500)
        loot = db.list_loot()
        edges = db.list_edges()

        lines = []
        lines.append("# Engagement Report")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append(f"- Targets: {len(targets)}")
        lines.append(f"- Credentials: {len(creds)}")
        lines.append(f"- Findings: {len(findings)}")
        lines.append(f"- Timeline entries: {len(timeline)}")
        lines.append(f"- Loot files: {len(loot)}")
        lines.append(f"- Attack graph edges: {len(edges)}")
        lines.append("")

        # Findings by severity
        if findings:
            lines.append("## Findings")
            for sev in ("critical", "high", "medium", "low", "info"):
                sev_findings = [f for f in findings if f.get("severity") == sev]
                if sev_findings:
                    lines.append(f"### {sev.upper()} ({len(sev_findings)})")
                    for f in sev_findings:
                        lines.append(f"- **{f.get('title', 'Untitled')}**")
                        if f.get("description"):
                            lines.append(f"  {f['description']}")
                        if f.get("evidence"):
                            lines.append(f"  Evidence: `{f['evidence'][:200]}`")
                        if f.get("remediation"):
                            lines.append(f"  Remediation: {f['remediation']}")
                    lines.append("")

        # Targets
        if targets:
            lines.append("## Targets")
            lines.append("| IP | Hostname | Domain | OS | DC |")
            lines.append("|---|---|---|---|---|")
            for t in targets:
                dc = "Yes" if t.get("is_dc") else ""
                lines.append(f"| {t.get('ip','')} | {t.get('hostname','')} | {t.get('domain','')} | {t.get('os_info','')} | {dc} |")
            lines.append("")

        # Credentials
        if creds:
            lines.append("## Credentials")
            lines.append("| Username | Domain | Type | Source | Cracked |")
            lines.append("|---|---|---|---|---|")
            for c in creds:
                cracked = "Yes" if c.get("cracked") else ""
                lines.append(f"| {c.get('username','')} | {c.get('domain','')} | {c.get('cred_type','')} | {c.get('source','')} | {cracked} |")
            lines.append("")

        # Attack Graph
        if edges:
            lines.append("## Attack Graph")
            for e in edges:
                exploited = " [EXPLOITED]" if e.get("exploited") else ""
                lines.append(f"- {e.get('source_node')} --[{e.get('edge_type')}]--> {e.get('target_node')}{exploited}")
            lines.append("")

        # Timeline
        if timeline:
            lines.append("## Timeline (Last 50)")
            lines.append("| Time | Action | Target | Result | OPSEC |")
            lines.append("|---|---|---|---|---|")
            for t in timeline[:50]:
                lines.append(f"| {t.get('timestamp','')} | {t.get('action','')} | {t.get('target','')} | {t.get('result','')} | {t.get('opsec_rating','')} |")
            lines.append("")

        report_text = "\n".join(lines)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(report_text)
                print(Style.success(f"Report saved to: {output_file}"))
            except Exception as e:
                print(Style.error(f"Failed to save report: {e}"))
        else:
            print(report_text)

    # =========================================================================
    # Macro Management
    # =========================================================================

    def cmd_macro(self, args: List[str]) -> None:
        """Macro management: macro list|run|define|delete|import|show"""
        mgr = get_macro_manager(str(self.config.config_dir))

        if not args:
            args = ["list"]

        subcmd = args[0].lower()

        if subcmd == "list":
            macros = mgr.list_macros()
            if not macros:
                print(Style.warning("No macros defined"))
                return
            print()
            print(f"  {Colors.NEON_CYAN}Available Macros{Colors.RESET}")
            print(f"  {Colors.NEON_PINK}{'=' * 60}{Colors.RESET}")
            print()
            print(f"  {Colors.BRIGHT_WHITE}{'Name':<25} {'Commands':<10} {'Vars':<15} Description{Colors.RESET}")
            print(f"  {Colors.GRID}{'-' * 25} {'-' * 10} {'-' * 15} {'-' * 30}{Colors.RESET}")
            for name, macro in macros.items():
                n_cmds = len(macro.commands)
                req_vars = ", ".join(macro.get_required_vars()) or "-"
                print(f"  {Colors.NEON_GREEN}{name:<25}{Colors.RESET} {n_cmds:<10} {req_vars:<15} {macro.description}")
            print()

        elif subcmd == "show" and len(args) > 1:
            macro = mgr.get(args[1])
            if not macro:
                print(Style.error(f"Macro not found: {args[1]}"))
                return
            print()
            print(f"  {Colors.NEON_CYAN}Macro: {macro.name}{Colors.RESET}")
            if macro.description:
                print(f"  {macro.description}")
            print()
            req_vars = macro.get_required_vars()
            if req_vars:
                print(f"  {Colors.YELLOW}Variables: {', '.join(req_vars)}{Colors.RESET}")
            print(f"  {Colors.BRIGHT_WHITE}Commands:{Colors.RESET}")
            for i, cmd in enumerate(macro.commands, 1):
                print(f"    {Colors.GRID}[{i}]{Colors.RESET} {cmd}")
            print()

        elif subcmd == "run" and len(args) > 1:
            macro_name = args[1]
            # Parse variable assignments: macro run name VAR=val VAR2=val2
            variables = {}
            for arg in args[2:]:
                if "=" in arg:
                    k, v = arg.split("=", 1)
                    variables[k] = v

            # Also pull from global config as fallback
            macro = mgr.get(macro_name)
            if not macro:
                print(Style.error(f"Macro not found: {macro_name}"))
                return

            for var in macro.get_required_vars():
                if var not in variables:
                    # Check global config
                    global_val = self.config.get_global(var)
                    if global_val:
                        variables[var] = global_val

            # Check for --dry-run
            dry_run = "--dry-run" in args

            try:
                print(Style.info(f"Running macro: {macro_name}"))
                if dry_run:
                    print(Style.warning("DRY RUN - commands will not execute"))
                print()
                success = mgr.run(macro_name, variables, self.console.execute_command, dry_run=dry_run)
                if success:
                    print(Style.success(f"Macro '{macro_name}' completed"))
                else:
                    print(Style.warning(f"Macro '{macro_name}' failed"))
            except ValueError as e:
                print(Style.error(str(e)))
                print(Style.info("Usage: macro run <name> VAR1=value1 VAR2=value2"))

        elif subcmd == "define" and len(args) > 1:
            macro_name = args[1]
            print(Style.info(f"Defining macro: {macro_name}"))
            print(Style.info("Enter commands one per line. Use {{VARIABLE}} for placeholders."))
            print(Style.info("Enter an empty line to finish."))
            print()
            commands = []
            while True:
                try:
                    line = input(f"  {Colors.GRID}[{len(commands)+1}]{Colors.RESET} ")
                    if not line.strip():
                        break
                    commands.append(line.strip())
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
            if commands:
                desc = input(f"  Description: ").strip() if commands else ""
                macro = mgr.define(macro_name, commands, description=desc)
                print(Style.success(f"Macro '{macro_name}' defined with {len(commands)} commands"))
            else:
                print(Style.warning("No commands entered, macro not created"))

        elif subcmd == "delete" and len(args) > 1:
            if mgr.delete(args[1]):
                print(Style.success(f"Macro '{args[1]}' deleted"))
            else:
                print(Style.error(f"Cannot delete macro '{args[1]}' (not found or builtin)"))

        elif subcmd == "import" and len(args) > 1:
            filepath = args[1]
            name = args[2] if len(args) > 2 else None
            macro = mgr.import_rc(filepath, name)
            if macro:
                print(Style.success(f"Imported '{macro.name}' with {len(macro.commands)} commands from {filepath}"))
            else:
                print(Style.error(f"Failed to import: {filepath}"))

        else:
            print(Style.info("Usage: macro <list|show|run|define|delete|import>"))
            print(Style.info("  macro list                          - List all macros"))
            print(Style.info("  macro show <name>                   - Show macro details"))
            print(Style.info("  macro run <name> [VAR=val ...]      - Run a macro"))
            print(Style.info("  macro run <name> --dry-run          - Preview without executing"))
            print(Style.info("  macro define <name>                 - Define new macro interactively"))
            print(Style.info("  macro delete <name>                 - Delete a user macro"))
            print(Style.info("  macro import <file.rc> [name]       - Import .rc file as macro"))

    # =========================================================================
    # Hashcrack Setup
    # =========================================================================

    def cmd_hashcrack_setup(self, args: List[str]) -> None:
        """Configure remote hashcat cracking host"""

        # Check for --show flag
        if args and args[0] in ("--show", "-s", "show"):
            self._hashcrack_show()
            return

        # Check for --test flag
        if args and args[0] in ("--test", "-t", "test"):
            self._hashcrack_test()
            return

        # Check for --add-key flag (run from HOST to add Exegol's key)
        if args and args[0] in ("--add-key", "-k", "add-key"):
            self._hashcrack_add_key()
            return

        print(f"\n  {Colors.NEON_PINK}Hashcat Remote Cracking Setup{Colors.RESET}")
        print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}")
        print(f"  {Colors.GRID}Configure SSH connection to a machine with hashcat/GPU{Colors.RESET}\n")

        # Show/generate SSH public key for easy copy-paste
        ssh_dir = os.path.expanduser("~/.ssh")
        pubkey_path = os.path.join(ssh_dir, "id_ed25519.pub")
        privkey_path = os.path.join(ssh_dir, "id_ed25519")

        # Generate key if it doesn't exist
        if not os.path.exists(pubkey_path):
            print(f"  {Colors.NEON_CYAN}[*] Generating SSH key...{Colors.RESET}")
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            result = subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", privkey_path, "-q"],
                capture_output=True
            )
            if result.returncode != 0:
                print(f"  {Colors.NEON_ORANGE}[!] Could not generate SSH key{Colors.RESET}")

        # Display public key with copy-paste one-liner for host
        if os.path.exists(pubkey_path):
            with open(pubkey_path, "r") as f:
                pubkey = f.read().strip()

            print(f"  {Colors.NEON_ORANGE}-> Run this on your HOST to authorize this key:{Colors.RESET}")
            print(f"  {Colors.NEON_PINK}{'-'*60}{Colors.RESET}")
            print(f"  {Colors.NEON_GREEN}echo '{pubkey}' >> ~/.ssh/authorized_keys{Colors.RESET}")
            print(f"  {Colors.NEON_PINK}{'-'*60}{Colors.RESET}\n")

        print(f"  {Colors.GRID}Press Enter to keep current value, or type new value{Colors.RESET}\n")

        # Get current values
        current_host = self.config.getg("SSH_HOST") or ""
        current_port = self.config.getg("SSH_PORT") or "22"
        current_user = self.config.getg("SSH_USER") or ""
        current_wordlist = self.config.getg("WORDLIST") or ""
        current_rules = self.config.getg("RULES") or ""

        try:
            # SSH Host
            prompt = f"  {Colors.NEON_CYAN}SSH Host{Colors.RESET}"
            if current_host:
                prompt += f" [{Colors.NEON_GREEN}{current_host}{Colors.RESET}]"
            prompt += ": "
            new_host = input(prompt).strip()
            ssh_host = new_host if new_host else current_host

            if not ssh_host:
                print(Style.error("SSH Host is required"))
                return

            # SSH Port
            prompt = f"  {Colors.NEON_CYAN}SSH Port{Colors.RESET} [{Colors.NEON_GREEN}{current_port}{Colors.RESET}]: "
            new_port = input(prompt).strip()
            ssh_port = new_port if new_port else current_port

            # SSH User
            prompt = f"  {Colors.NEON_CYAN}SSH User{Colors.RESET}"
            if current_user:
                prompt += f" [{Colors.NEON_GREEN}{current_user}{Colors.RESET}]"
            else:
                prompt += f" [{Colors.GRID}current user{Colors.RESET}]"
            prompt += ": "
            new_user = input(prompt).strip()
            ssh_user = new_user if new_user else current_user

            # Wordlist path
            prompt = f"  {Colors.NEON_CYAN}Wordlist path (on remote host){Colors.RESET}"
            if current_wordlist:
                prompt += f"\n  [{Colors.NEON_GREEN}{current_wordlist}{Colors.RESET}]"
            prompt += ": "
            new_wordlist = input(prompt).strip()
            wordlist = new_wordlist if new_wordlist else current_wordlist

            # Rules file
            prompt = f"  {Colors.NEON_CYAN}Rules file (optional, on remote host){Colors.RESET}"
            if current_rules:
                prompt += f"\n  [{Colors.NEON_GREEN}{current_rules}{Colors.RESET}]"
            prompt += ": "
            new_rules = input(prompt).strip()
            rules = new_rules if new_rules else current_rules

            print()

            # Test connection
            print(f"  {Colors.NEON_CYAN}Testing SSH connection...{Colors.RESET}")

            ssh_target = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host
            # Auto-accept new host keys for seamless setup
            ssh_opts = [
                "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "BatchMode=yes",
            ]
            test_cmd = ["ssh", "-p", ssh_port] + ssh_opts + [ssh_target, "which hashcat && hashcat --version"]

            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                hashcat_info = result.stdout.strip().split('\n')
                print(f"  {Colors.NEON_GREEN}[+] Connection successful!{Colors.RESET}")
                if len(hashcat_info) >= 2:
                    print(f"  {Colors.NEON_GREEN}[+] Hashcat: {hashcat_info[0]}{Colors.RESET}")
                    print(f"  {Colors.NEON_GREEN}[+] Version: {hashcat_info[1]}{Colors.RESET}")

                # Check for GPU
                gpu_cmd = ["ssh", "-p", ssh_port] + ssh_opts + [ssh_target, "hashcat -I 2>/dev/null | head -20"]
                gpu_result = subprocess.run(gpu_cmd, capture_output=True, text=True, timeout=15, shell=False)
                if "Device" in gpu_result.stdout:
                    for line in gpu_result.stdout.split('\n'):
                        if 'Device' in line or 'Type' in line or 'Name' in line:
                            print(f"  {Colors.NEON_MAGENTA}    {line.strip()}{Colors.RESET}")

            else:
                print(f"  {Colors.NEON_ORANGE}[!] Connection failed or hashcat not found{Colors.RESET}")
                if result.stderr:
                    stderr = result.stderr.strip()
                    print(f"  {Colors.GRID}{stderr}{Colors.RESET}")
                    # Detect permission denied and suggest --add-key
                    if "Permission denied" in stderr or "publickey" in stderr:
                        print(f"\n  {Colors.NEON_CYAN}SSH key not authorized. To fix:{Colors.RESET}")
                        print(f"  {Colors.NEON_GREEN}1. On HOST: hashcrack_setup --add-key{Colors.RESET}")
                        print(f"  {Colors.GRID}   (paste your Exegol public key when prompted){Colors.RESET}")
                        print(f"  {Colors.NEON_GREEN}2. Then retry: hashcrack_setup --test{Colors.RESET}")
                else:
                    print(f"  {Colors.GRID}Settings will still be saved. Fix connection and run 'hashcrack_setup --test'{Colors.RESET}")

            # Save to globals
            print(f"\n  {Colors.NEON_CYAN}Saving to globals...{Colors.RESET}")
            self.config.setg("SSH_HOST", ssh_host)
            self.config.setg("SSH_PORT", ssh_port)
            if ssh_user:
                self.config.setg("SSH_USER", ssh_user)
            if wordlist:
                self.config.setg("WORDLIST", wordlist)
            if rules:
                self.config.setg("RULES", rules)

            print(f"  {Colors.NEON_GREEN}[+] Configuration saved!{Colors.RESET}")
            print(f"\n  {Colors.GRID}Run 'hashcrack_setup --show' to view current config{Colors.RESET}")
            print(f"  {Colors.GRID}Run 'hashcrack_setup --test' to test connection{Colors.RESET}")
            print()

        except KeyboardInterrupt:
            print(f"\n  {Colors.NEON_ORANGE}Setup cancelled{Colors.RESET}\n")
        except subprocess.TimeoutExpired:
            print(f"  {Colors.NEON_ORANGE}[!] SSH connection timed out{Colors.RESET}")
            print(f"  {Colors.GRID}Check host and try again{Colors.RESET}\n")
        except Exception as e:
            print(f"  {Colors.NEON_ORANGE}[!] Error: {e}{Colors.RESET}\n")

    def _hashcrack_show(self) -> None:
        """Show current hashcrack configuration"""

        print(f"\n  {Colors.NEON_PINK}Hashcat Remote Cracking Config{Colors.RESET}")
        print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}\n")

        settings = [
            ("SSH_HOST", self.config.getg("SSH_HOST")),
            ("SSH_PORT", self.config.getg("SSH_PORT") or "22"),
            ("SSH_USER", self.config.getg("SSH_USER") or "(current user)"),
            ("WORDLIST", self.config.getg("WORDLIST")),
            ("RULES", self.config.getg("RULES")),
        ]

        for name, value in settings:
            if value:
                print(f"  {Colors.NEON_CYAN}{name:<12}{Colors.RESET} {Colors.NEON_GREEN}{value}{Colors.RESET}")
            else:
                print(f"  {Colors.NEON_CYAN}{name:<12}{Colors.RESET} {Colors.GRID}(not set){Colors.RESET}")

        print(f"\n  {Colors.GRID}Run 'hashcrack_setup' to configure{Colors.RESET}")
        print(f"  {Colors.GRID}Run 'hashcrack_setup --test' to test connection{Colors.RESET}\n")

    def _hashcrack_test(self) -> None:
        """Test hashcrack SSH connection"""

        ssh_host = self.config.getg("SSH_HOST")
        ssh_port = self.config.getg("SSH_PORT") or "22"
        ssh_user = self.config.getg("SSH_USER")

        if not ssh_host:
            print(Style.error("SSH_HOST not configured. Run 'hashcrack_setup' first."))
            return

        print(f"\n  {Colors.NEON_CYAN}Testing SSH connection to {ssh_host}...{Colors.RESET}")

        ssh_target = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host

        # Auto-accept new host keys for seamless setup
        ssh_opts = [
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
        ]

        try:
            # Test SSH + hashcat
            test_cmd = ["ssh", "-p", ssh_port] + ssh_opts + [
                ssh_target, "which hashcat && hashcat --version && hashcat -I 2>/dev/null | head -10"
            ]

            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                print(f"  {Colors.NEON_GREEN}[+] Connection successful!{Colors.RESET}")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        print(f"      {line}")
            else:
                print(f"  {Colors.NEON_ORANGE}[!] Connection failed{Colors.RESET}")
                if result.stderr:
                    print(f"  {Colors.GRID}{result.stderr.strip()}{Colors.RESET}")

        except subprocess.TimeoutExpired:
            print(f"  {Colors.NEON_ORANGE}[!] Connection timed out{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.NEON_ORANGE}[!] Error: {e}{Colors.RESET}")

        print()

    def _hashcrack_add_key(self) -> None:
        """Add SSH public key to authorized_keys for remote cracking access"""

        print(f"\n  {Colors.NEON_PINK}Add SSH Key for Hashcat Access{Colors.RESET}")
        print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}")
        print(f"  {Colors.GRID}This adds a public key to ~/.ssh/authorized_keys{Colors.RESET}")
        print(f"  {Colors.GRID}Run this on your HOST machine (with hashcat/GPU){Colors.RESET}\n")

        print(f"  {Colors.NEON_CYAN}In your Exegol container, run:{Colors.RESET}")
        print(f"  {Colors.NEON_GREEN}cat ~/.ssh/id_ed25519.pub{Colors.RESET}")
        print(f"  {Colors.GRID}(or: ssh-keygen -t ed25519 && cat ~/.ssh/id_ed25519.pub){Colors.RESET}\n")

        try:
            print(f"  {Colors.NEON_CYAN}Paste your SSH public key (ssh-ed25519 or ssh-rsa):{Colors.RESET}")
            pubkey = input("  ").strip()

            if not pubkey:
                print(f"  {Colors.NEON_ORANGE}[!] No key provided, cancelled{Colors.RESET}\n")
                return

            # Validate it looks like a public key
            if not (pubkey.startswith("ssh-ed25519 ") or pubkey.startswith("ssh-rsa ") or
                    pubkey.startswith("ecdsa-sha2-") or pubkey.startswith("ssh-dss ")):
                print(f"  {Colors.NEON_ORANGE}[!] Invalid public key format{Colors.RESET}")
                print(f"  {Colors.GRID}Key should start with: ssh-ed25519, ssh-rsa, ecdsa-sha2-, or ssh-dss{Colors.RESET}\n")
                return

            # Ensure .ssh directory exists with correct permissions
            ssh_dir = os.path.expanduser("~/.ssh")
            auth_keys = os.path.join(ssh_dir, "authorized_keys")

            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

            # Check if key already exists
            existing_keys = ""
            if os.path.exists(auth_keys):
                with open(auth_keys, "r") as f:
                    existing_keys = f.read()

            if pubkey in existing_keys:
                print(f"  {Colors.NEON_GREEN}[+] Key already in authorized_keys{Colors.RESET}\n")
                return

            # Append key
            with open(auth_keys, "a") as f:
                if existing_keys and not existing_keys.endswith("\n"):
                    f.write("\n")
                f.write(pubkey + "\n")

            # Ensure correct permissions
            os.chmod(auth_keys, 0o600)

            print(f"  {Colors.NEON_GREEN}[+] Key added to {auth_keys}{Colors.RESET}")
            print(f"\n  {Colors.NEON_CYAN}Now in Exegol, run:{Colors.RESET}")
            print(f"  {Colors.NEON_GREEN}hashcrack_setup --test{Colors.RESET}\n")

        except KeyboardInterrupt:
            print(f"\n  {Colors.NEON_ORANGE}Cancelled{Colors.RESET}\n")
        except Exception as e:
            print(f"  {Colors.NEON_ORANGE}[!] Error: {e}{Colors.RESET}\n")

    # =========================================================================
    # uwu-clear: Reset Data Stores
    # =========================================================================

    def cmd_uwu_clear(self, args: List[str]) -> None:
        """Clear UwU Toolkit data stores"""
        valid = ["all", "db", "creds", "targets", "globals", "permanent", "history", "events"]

        if not args:
            print(f"\n  {Colors.NEON_PINK}uwu-clear{Colors.RESET} - Reset data stores\n")
            print(f"  {Colors.NEON_CYAN}Usage:{Colors.RESET} uwu-clear <what>\n")
            for sub in valid:
                desc = {
                    "all": "Clear everything (db + globals + permanent + history + events)",
                    "db": "Clear all engagement DB tables",
                    "creds": "Clear credentials table only",
                    "targets": "Clear targets table only",
                    "globals": "Clear global variables (globals.json)",
                    "permanent": "Clear permanent variables (permanent.json)",
                    "history": "Clear variable history + command history",
                    "events": "Clear dashboard events",
                }.get(sub, "")
                print(f"    {Colors.NEON_GREEN}{sub:12s}{Colors.RESET}  {desc}")
            print(f"\n  {Colors.NEON_ORANGE}Note:{Colors.RESET} config.json is NEVER cleared.\n")
            return

        subcmd = args[0].lower()
        if subcmd not in valid:
            print(Style.error(f"Unknown target: {subcmd}"))
            print(Style.info(f"Valid: {', '.join(valid)}"))
            return

        # Confirmation
        label = "ALL data stores" if subcmd == "all" else subcmd
        try:
            answer = input(f"  Clear {Colors.NEON_ORANGE}{label}{Colors.RESET}? Type 'yes' to confirm: ")
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {Colors.NEON_ORANGE}Cancelled{Colors.RESET}")
            return

        if answer.strip().lower() != "yes":
            print(f"  {Colors.NEON_ORANGE}Cancelled{Colors.RESET}")
            return

        if subcmd == "all":
            self._clear_db_all()
            self._clear_globals()
            self._clear_permanent()
            self._clear_history()
            self._clear_events()
            print(Style.success("All data stores cleared"))
        elif subcmd == "db":
            self._clear_db_all()
            print(Style.success("Engagement database cleared"))
        elif subcmd == "creds":
            self._clear_db_table("credentials")
            print(Style.success("Credentials table cleared"))
        elif subcmd == "targets":
            self._clear_db_table("targets")
            print(Style.success("Targets table cleared"))
        elif subcmd == "globals":
            self._clear_globals()
            print(Style.success("Global variables cleared"))
        elif subcmd == "permanent":
            self._clear_permanent()
            print(Style.success("Permanent variables cleared"))
        elif subcmd == "history":
            self._clear_history()
            print(Style.success("History cleared"))
        elif subcmd == "events":
            self._clear_events()
            print(Style.success("Dashboard events cleared"))

    def _clear_db_all(self) -> None:
        """Clear all engagement DB tables (child tables first for FK constraints)"""
        try:
            db = EngagementDB.get_instance()
            tables = [
                "timeline", "attack_graph", "loot", "findings",
                "sessions", "credentials", "targets", "engagement_config",
            ]
            with db._write_lock:
                for table in tables:
                    db._conn.execute(f"DELETE FROM {table}")
                db._conn.execute("VACUUM")
                db._conn.commit()
        except Exception as e:
            print(Style.error(f"DB clear failed: {e}"))

    def _clear_db_table(self, table: str) -> None:
        """Clear a single DB table"""
        try:
            db = EngagementDB.get_instance()
            # Clear dependent tables first if clearing targets
            dependent = {
                "targets": ["timeline", "findings", "loot", "sessions"],
                "credentials": ["timeline", "sessions"],
            }
            with db._write_lock:
                for dep in dependent.get(table, []):
                    if table == "targets":
                        db._conn.execute(f"UPDATE {dep} SET target_id = NULL WHERE target_id IS NOT NULL")
                    elif table == "credentials":
                        db._conn.execute(f"UPDATE {dep} SET credential_id = NULL WHERE credential_id IS NOT NULL")
                db._conn.execute(f"DELETE FROM {table}")
                db._conn.commit()
        except Exception as e:
            print(Style.error(f"Table clear failed: {e}"))

    def _clear_globals(self) -> None:
        """Clear global variables (not config.json)"""
        self.config._globals.clear()
        self.config._session_vars.clear()
        self.config._save_json(self.config.globals_file, {})

    def _clear_permanent(self) -> None:
        """Clear permanent variables"""
        self.config._permanent.clear()
        self.config._save_json(self.config.permanent_file, {})

    def _clear_history(self) -> None:
        """Clear variable history and command history"""
        import readline as _rl

        # Variable history
        self.config._history.clear()
        self.config._save_json(self.config.history_file, {})

        # Command history (readline buffer + file)
        try:
            _rl.clear_history()
        except Exception:
            pass

        cmd_history = self.config.config_dir / "command_history"
        try:
            cmd_history.write_text("")
        except IOError:
            pass

    def _clear_events(self) -> None:
        """Clear dashboard events"""
        events_file = self.config.config_dir / "dashboard_events.json"
        try:
            events_file.write_text("[]")
        except IOError:
            pass

    # =========================================================================
    # Shell Escape
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

    # =========================================================================
    # Export Variables
    # =========================================================================

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
