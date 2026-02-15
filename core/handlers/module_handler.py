"""
Module command handler for UwU Toolkit console.
Handles module selection, execution, search, and reload commands.
"""

import time
from typing import Dict, List, Optional

from . import HandlerBase
from ..colors import Colors, Style
from ..module_loader import ModuleInfo
from ..module_base import ModuleType
from ..opsec import get_opsec_info, format_opsec_warning, OpsecRating
from ..engagement_db import EngagementDB


class ModuleHandler(HandlerBase):
    """Handles module selection, execution, and search commands."""

    def cmd_use(self, args: List[str]) -> None:
        """Select a module"""
        if not args:
            print(Style.error("Usage: use <module_path>"))
            return

        module_path = args[0].lower()

        # Resolve numeric shortcut from current module's suggestions
        if module_path.isdigit() and self.current_module:
            suggestions = getattr(self.current_module, '_suggested_modules', [])
            idx = int(module_path) - 1  # 1-indexed display -> 0-indexed list
            if 0 <= idx < len(suggestions):
                resolved_path = suggestions[idx][0]
                print(Style.info(f"Resolved [{args[0]}] -> {resolved_path}"))
                module_path = resolved_path.lower()
            elif suggestions:
                print(Style.error(f"Invalid suggestion index: {args[0]} (valid: 1-{len(suggestions)})"))
                return

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

        # OPSEC warning check
        opsec_rating = self.current_module.opsec_rating
        opsec_info = None
        if not opsec_rating:
            # Try looking up by module name
            opsec_info = get_opsec_info(self.current_module.name)
            if opsec_info:
                opsec_rating = opsec_info.rating.value
        else:
            opsec_info = get_opsec_info(self.current_module.name)

        if opsec_rating in ("high", "loud"):
            print()
            print(format_opsec_warning(self.current_module.name))
            print()
            try:
                confirm = input(f"{Colors.NEON_ORANGE}[!] Continue with OPSEC {opsec_rating.upper()} operation? [y/N]: {Colors.RESET}")
                if confirm.lower() not in ("y", "yes"):
                    print(Style.warning("Aborted"))
                    return
            except (EOFError, KeyboardInterrupt):
                print()
                print(Style.warning("Aborted"))
                return
        elif opsec_rating == "medium":
            opsec_desc = opsec_info.description if opsec_info else "moderately detectable"
            print(f"  {Colors.NEON_ORANGE}[!] OPSEC MEDIUM: {opsec_desc}{Colors.RESET}")

        print(Style.info(f"Running {self.current_module.name}..."))
        print()

        target = self.current_module.get_option("RHOSTS") or ""
        start_ts = time.time()

        try:
            success = self.current_module.run()
            duration_ms = int((time.time() - start_ts) * 1000)
            print()
            if success:
                print(Style.success("Module completed successfully"))
            else:
                print(Style.warning("Module completed with errors"))

            # Log to EngagementDB timeline
            try:
                db = EngagementDB.get_instance()
                db.log_action(
                    action=f"run {self.current_module.name}",
                    tool=self.current_module.name,
                    target=str(target),
                    result="success" if success else "failed",
                    opsec_rating=opsec_rating or "",
                    duration_ms=duration_ms,
                )
            except Exception:
                pass  # Don't fail module run because of DB logging

        except KeyboardInterrupt:
            duration_ms = int((time.time() - start_ts) * 1000)
            print()
            print(Style.warning("Module interrupted"))
            try:
                db = EngagementDB.get_instance()
                db.log_action(
                    action=f"run {self.current_module.name}",
                    tool=self.current_module.name,
                    target=str(target),
                    result="interrupted",
                    opsec_rating=opsec_rating or "",
                    duration_ms=duration_ms,
                )
            except Exception:
                pass
        except Exception as e:
            print(Style.error(f"Module failed: {e}"))
            import traceback
            traceback.print_exc()
            try:
                db = EngagementDB.get_instance()
                db.log_action(
                    action=f"run {self.current_module.name}",
                    tool=self.current_module.name,
                    target=str(target),
                    result=f"error: {e}",
                    opsec_rating=opsec_rating or "",
                )
            except Exception:
                pass
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
                print(f"      {Colors.CP_FG}{desc}{Colors.RESET}")
            print()

    def cmd_reload(self, args: List[str]) -> None:
        """Reload current module or all modules. Usage: reload [all]"""
        if args and args[0].lower() == "all":
            return self.cmd_reloadall([])

        if not self.current_module:
            print(Style.error("No module selected. Use 'reload all' to reload everything."))
            return

        # Preserve current options
        saved_options = {}
        if hasattr(self.current_module, '_options'):
            for name, opt in self.current_module._options.items():
                if opt.value != opt.default:
                    saved_options[name] = opt.value

        path = self.current_module.full_path
        module = self.loader.reload_module(path)
        if module:
            module.set_config(self.config)
            # Restore options that were set
            for name, value in saved_options.items():
                try:
                    module.set_option(name, value)
                except Exception:
                    pass
            self.current_module = module
            print(Style.success(f"Module reloaded: {path}"))
        else:
            print(Style.error(f"Failed to reload module: {path}"))

    def cmd_reloadall(self, args: List[str]) -> None:
        """Reload all modules - rediscover and clear all caches"""
        old_count = len(self.loader.get_all_modules())
        count = self.loader.reload_all()
        new_modules = count - old_count
        msg = f"Reloaded {count} modules"
        if new_modules > 0:
            msg += f" ({new_modules} new)"
        print(Style.success(msg))

        # Re-select current module if one was active
        if self.current_module:
            path = self.current_module.full_path
            module = self.loader.load_module(path)
            if module:
                module.set_config(self.config)
                self.current_module = module
