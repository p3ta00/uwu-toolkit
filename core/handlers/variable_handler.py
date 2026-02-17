"""Variable management command handlers."""

import os
import re
import subprocess
from typing import Dict, List, Optional, Any

from . import HandlerBase
from ..colors import Colors, Style
from ..module_base import ModuleType
from ..module_loader import ModuleInfo
from ..targets import print_targets_table


class VariableHandler(HandlerBase):
    """Handles all variable get/set/show commands."""

    # =========================================================================
    # cmd_set — main set command with target/DC intercept
    # =========================================================================

    def cmd_set(self, args: List[str]) -> None:
        """Set a session variable"""
        if len(args) < 1:
            print(Style.error("Usage: set <variable> [value]"))
            return

        # --- Target / DC intercept ---
        # Only intercept if no active module has this as an option
        if args[0].lower() == "target":
            if not (self.current_module and self.current_module.has_option("TARGET")):
                self._handle_set_target(args[1:])
                return
        if args[0].lower() == "dc":
            if not (self.current_module and self.current_module.has_option("DC")):
                self._handle_set_dc(args[1:])
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

        # Auto-promote credential options to global so they persist across modules
        _GLOBAL_CRED_VARS = {"USER", "PASS", "DOMAIN", "RHOSTS", "DC_IP", "DC_HOST", "HASHES"}
        if var_name in _GLOBAL_CRED_VARS:
            self.config.setg(var_name, value)
            print(f"{Style.varname(var_name)} => {Style.value(value)} (global)")
        else:
            print(f"{Style.varname(var_name)} => {Style.value(value)}")

        # Auto-populate PASS/DOMAIN from creds when setting USER
        if var_name == "USER" and hasattr(self.console, 'cred_manager'):
            # Check if user exists in creds
            username = value
            domain = None
            if "\\" in value:
                domain, username = value.split("\\", 1)

            cred = self.console.cred_manager.get(username, domain)
            if cred:
                # Auto-set PASS (and HASHES for hash creds)
                if cred.get("password"):
                    self.config.set("PASS", cred["password"])
                    self.config.setg("PASS", cred["password"])
                    if self.current_module:
                        self.current_module.set_option("PASS", cred["password"])
                    self.config.set("HASHES", "")
                    self.config.setg("HASHES", "")
                    if self.current_module and self.current_module.has_option("HASHES"):
                        self.current_module.set_option("HASHES", "")
                    print(f"{Style.varname('PASS')} => {Style.value(cred['password'])} (from creds, global)")
                elif cred.get("ntlm_hash"):
                    ntlm = cred["ntlm_hash"]
                    self.config.set("PASS", ntlm)
                    self.config.setg("PASS", ntlm)
                    if self.current_module:
                        self.current_module.set_option("PASS", ntlm)
                    hashes_val = f":{ntlm}" if ":" not in ntlm else ntlm
                    self.config.set("HASHES", hashes_val)
                    self.config.setg("HASHES", hashes_val)
                    if self.current_module and self.current_module.has_option("HASHES"):
                        self.current_module.set_option("HASHES", hashes_val)
                    print(f"{Style.varname('PASS')} => {Style.value(ntlm)} (hash from creds, global)")
                    print(f"{Style.varname('HASHES')} => {Style.value(hashes_val)} (global)")

                # Auto-set DOMAIN if cred has it and not already in username
                if cred.get("domain") and "\\" not in value:
                    self.config.set("DOMAIN", cred["domain"])
                    self.config.setg("DOMAIN", cred["domain"])
                    if self.current_module:
                        self.current_module.set_option("DOMAIN", cred["domain"])
                    print(f"{Style.varname('DOMAIN')} => {Style.value(cred['domain'])} (from creds, global)")

    # =========================================================================
    # Target Management Helpers
    # =========================================================================

    def _handle_set_target(self, args: List[str]) -> None:
        """Handle 'set target ...' — register or select a target"""
        if not args:
            print(Style.error("Usage: set target <ip> <hostname> [dc]  — register"))
            print(Style.error("       set target <id>                  — select"))
            return

        # Selection mode: 'set target <n>'
        if args[0].isdigit():
            target_id = int(args[0])
            target = self.console.target_manager.get(target_id)
            if not target:
                print(Style.error(f"Target #{target_id} not found"))
                return
            self._apply_target_vars(target)
            return

        # Registration mode: 'set target <ip> <hostname> [dc]'
        ip = args[0]
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            print(Style.error(f"Invalid IP address: {ip}"))
            return

        hostname = args[1] if len(args) >= 2 else ""
        is_dc = len(args) >= 3 and args[2].lower() == "dc"

        target = self.console.target_manager.add(ip=ip, hostname=hostname, is_dc=is_dc)
        existing = self.console.target_manager.get_by_ip(ip)
        tid = target["id"]

        dc_str = " (DC)" if is_dc else ""
        host_str = f" {hostname}" if hostname else ""
        print(Style.success(f"Target #{tid}: {ip}{host_str}{dc_str}"))

        if target.get("domain"):
            print(Style.info(f"  Domain inferred: {target['domain']}"))

        # Update /etc/hosts
        if hostname:
            self._update_etc_hosts_for_target(target)

    def _handle_set_dc(self, args: List[str]) -> None:
        """Handle 'set dc <n>' — select a DC target"""
        if not args or not args[0].isdigit():
            print(Style.error("Usage: set dc <id>"))
            dc_targets = self.console.target_manager.list_dcs()
            if dc_targets:
                print(Style.info("Available DCs:"))
                for t in dc_targets:
                    print(f"  #{t['id']}  {t['ip']}  {t.get('hostname', '')}")
            else:
                print(Style.warning("No DCs registered. Use: set target <ip> <hostname> dc"))
            return

        target_id = int(args[0])
        target = self.console.target_manager.get(target_id)
        if not target:
            print(Style.error(f"Target #{target_id} not found"))
            return

        if not target.get("is_dc"):
            print(Style.warning(f"Target #{target_id} is not marked as DC — setting DC vars anyway"))

        self._apply_dc_vars(target)

    def _apply_target_vars(self, target: Dict[str, Any]) -> None:
        """Populate variables from a target selection"""
        tid = target["id"]
        ip = target["ip"]

        # RHOSTS + RHOST
        for var in ("RHOSTS", "RHOST"):
            self.config.set(var, ip)
            self.config.setg(var, ip)
            if self.current_module and self.current_module.has_option(var):
                self.current_module.set_option(var, ip)
        print(f"{Style.varname('RHOSTS')} => {Style.value(ip)} (from target #{tid}, global)")

        # If DC, also set DC_IP / DC_HOST
        if target.get("is_dc"):
            self._apply_dc_vars(target, quiet=True)

        # If domain present, set DOMAIN
        if target.get("domain"):
            domain = target["domain"]
            self.config.set("DOMAIN", domain)
            self.config.setg("DOMAIN", domain)
            if self.current_module and self.current_module.has_option("DOMAIN"):
                self.current_module.set_option("DOMAIN", domain)
            if not target.get("is_dc"):
                print(f"{Style.varname('DOMAIN')} => {Style.value(domain)} (from target #{tid}, global)")

    def _apply_dc_vars(self, target: Dict[str, Any], quiet: bool = False) -> None:
        """Populate DC-specific variables from a target"""
        tid = target["id"]
        ip = target["ip"]
        hostname = target.get("hostname", "")
        domain = target.get("domain", "")

        # DC_IP
        self.config.set("DC_IP", ip)
        self.config.setg("DC_IP", ip)
        if self.current_module and self.current_module.has_option("DC_IP"):
            self.current_module.set_option("DC_IP", ip)
        print(f"{Style.varname('DC_IP')} => {Style.value(ip)} (from target #{tid}, global)")

        # DC_HOST
        if hostname:
            self.config.set("DC_HOST", hostname)
            self.config.setg("DC_HOST", hostname)
            if self.current_module and self.current_module.has_option("DC_HOST"):
                self.current_module.set_option("DC_HOST", hostname)
            print(f"{Style.varname('DC_HOST')} => {Style.value(hostname)} (from target #{tid}, global)")

        # DOMAIN
        if domain:
            self.config.set("DOMAIN", domain)
            self.config.setg("DOMAIN", domain)
            if self.current_module and self.current_module.has_option("DOMAIN"):
                self.current_module.set_option("DOMAIN", domain)
            print(f"{Style.varname('DOMAIN')} => {Style.value(domain)} (from target #{tid}, global)")

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
            if self.console._is_inside_exegol():
                self._update_hosts_file_direct(ip, hosts_line)
            elif self.console._is_native_linux():
                self._update_hosts_file_native(ip, hosts_line)
            else:
                container = (self.config.getg("EXEGOL_CONTAINER") or
                             self.config.get("EXEGOL_CONTAINER") or
                             self.console._find_exegol_container())
                if container:
                    self._update_hosts_file_docker(container, ip, hosts_line)
                else:
                    print(Style.warning("No Exegol container found — /etc/hosts not updated"))
        except Exception as e:
            print(Style.warning(f"Could not update /etc/hosts: {e}"))

    def _update_hosts_file_direct(self, ip: str, hosts_line: str) -> None:
        """Update /etc/hosts directly (when inside Exegol)"""
        # Check if IP already has an entry — replace it; otherwise append
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
    # Validation
    # =========================================================================

    def _validate_var_name(self, name: str) -> bool:
        """Validate variable name - must be alphanumeric with underscores only"""
        if not name:
            return False
        if not re.match(r'^[A-Z][A-Z0-9_]*$', name.upper()):
            print(Style.error(f"Invalid variable name: {name}"))
            print(Style.info("Variable names must be alphanumeric with underscores (e.g., RHOSTS, MY_VAR)"))
            return False
        return True

    # =========================================================================
    # cmd_setg — set global variable
    # =========================================================================

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
        if var_name == "USER" and hasattr(self.console, 'cred_manager'):
            username = value
            domain = None
            if "\\" in value:
                domain, username = value.split("\\", 1)

            cred = self.console.cred_manager.get(username, domain)
            if cred:
                if cred.get("password"):
                    self.config.setg("PASS", cred["password"])
                    self.config.setg("HASHES", "")
                    print(f"{Style.varname('PASS')} => {Style.value(cred['password'])} (from creds, global)")
                elif cred.get("ntlm_hash"):
                    ntlm = cred["ntlm_hash"]
                    self.config.setg("PASS", ntlm)
                    hashes_val = f":{ntlm}" if ":" not in ntlm else ntlm
                    self.config.setg("HASHES", hashes_val)
                    print(f"{Style.varname('PASS')} => {Style.value(ntlm)} (hash from creds, global)")
                    print(f"{Style.varname('HASHES')} => {Style.value(hashes_val)} (global)")

                if cred.get("domain") and "\\" not in value:
                    self.config.setg("DOMAIN", cred["domain"])
                    print(f"{Style.varname('DOMAIN')} => {Style.value(cred['domain'])} (from creds, global)")

    # =========================================================================
    # cmd_get / cmd_getg / cmd_getp — retrieve variable values
    # =========================================================================

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

    # =========================================================================
    # cmd_setp / cmd_unsetp / cmd_showp — permanent variables
    # =========================================================================

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

    # =========================================================================
    # cmd_cleang / cmd_cleanp — clean corrupted variables
    # =========================================================================

    def cmd_cleang(self, args: List[str]) -> None:
        """Clean up corrupted global variables"""
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

    # =========================================================================
    # _interactive_set — history-based variable picker
    # =========================================================================

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

    # =========================================================================
    # cmd_unset / cmd_unsetg — unset variables
    # =========================================================================

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

    # =========================================================================
    # cmd_show — dispatcher for show subcommands
    # =========================================================================

    def cmd_show(self, args: List[str]) -> None:
        """Show various information"""
        if not args:
            args = ["options"] if self.current_module else ["globals"]

        what = args[0].lower()

        if what == "options":
            self.console.cmd_options([])
        elif what == "info":
            self.console.cmd_info([])
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

    # =========================================================================
    # cmd_vars / cmd_globals / cmd_history — display commands
    # =========================================================================

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
