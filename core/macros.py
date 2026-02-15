"""
Macro system for UwU Toolkit
Define and run reusable command sequences and attack workflows.

Usage:
    from core.macros import MacroManager

    mgr = MacroManager()
    mgr.define("kerberoast_chain", [
        "setg DOMAIN {domain}",
        "setg RHOSTS {dc_ip}",
        "use ad/kerberoast",
        "set USER {user}",
        "set PASS {pass}",
        "run",
    ])
    mgr.run("kerberoast_chain", {"domain": "CORP.LOCAL", "dc_ip": "10.10.10.1", ...}, execute_func)
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime


class Macro:
    """A named sequence of commands with optional variable placeholders"""

    def __init__(self, name: str, commands: List[str], description: str = "",
                 author: str = "", variables: Optional[Dict[str, str]] = None):
        self.name = name
        self.commands = commands
        self.description = description
        self.author = author
        self.variables = variables or {}  # {name: description}
        self.created = datetime.now().isoformat()

    def get_required_vars(self) -> List[str]:
        """Extract all {variable} placeholders from commands"""
        vars_found = set()
        for cmd in self.commands:
            vars_found.update(re.findall(r'\{(\w+)\}', cmd))
        return sorted(vars_found)

    def render(self, variables: Dict[str, str]) -> List[str]:
        """Render commands with variable substitution"""
        rendered = []
        for cmd in self.commands:
            rendered_cmd = cmd
            for key, value in variables.items():
                rendered_cmd = rendered_cmd.replace(f"{{{key}}}", str(value))
            rendered.append(rendered_cmd)
        return rendered

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "commands": self.commands,
            "description": self.description,
            "author": self.author,
            "variables": self.variables,
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Macro":
        m = cls(
            name=data["name"],
            commands=data["commands"],
            description=data.get("description", ""),
            author=data.get("author", ""),
            variables=data.get("variables", {}),
        )
        m.created = data.get("created", "")
        return m


class MacroManager:
    """Manages macro definitions, persistence, and execution"""

    # Built-in workflow templates
    BUILTIN_MACROS = {
        "kerberoast_crack": Macro(
            name="kerberoast_crack",
            commands=[
                "setg DOMAIN {domain}",
                "setg RHOSTS {dc_ip}",
                "use ad/kerberoast",
                "set USER {user}",
                "set PASS {pass}",
                "run",
            ],
            description="Kerberoast service accounts and extract hashes for cracking",
            variables={"domain": "AD domain", "dc_ip": "Domain Controller IP",
                       "user": "Username", "pass": "Password"},
        ),
        "adcs_exploit": Macro(
            name="adcs_exploit",
            commands=[
                "setg DOMAIN {domain}",
                "setg RHOSTS {dc_ip}",
                "use ad/adcs_auto",
                "set USER {user}",
                "set PASS {pass}",
                "set ACTION full",
                "run",
            ],
            description="Auto-scan and exploit ADCS vulnerabilities (ESC1-ESC15)",
            variables={"domain": "AD domain", "dc_ip": "Domain Controller IP",
                       "user": "Username", "pass": "Password"},
        ),
        "smb_enum": Macro(
            name="smb_enum",
            commands=[
                "setg RHOSTS {target}",
                "use auxiliary/smb/smb_enum",
                "run",
                "use ad/sid_lookup",
                "set RHOSTS {target}",
                "run",
            ],
            description="Full SMB enumeration: shares, users, SIDs",
            variables={"target": "Target IP"},
        ),
        "full_recon": Macro(
            name="full_recon",
            commands=[
                "setg RHOSTS {target}",
                "use enumeration/auto_enumerator",
                "set SCAN_TYPE full",
                "run",
            ],
            description="Full port scan and service enumeration",
            variables={"target": "Target IP or range"},
        ),
        "ntlm_coerce_chain": Macro(
            name="ntlm_coerce_chain",
            commands=[
                "setg RHOSTS {dc_ip}",
                "setg DOMAIN {domain}",
                "use auxiliary/smb/ntlm_coerce",
                "set LISTENER_IP {listener_ip}",
                "set USER {user}",
                "set PASS {pass}",
                "set FILE_TYPES lnk,scf,url",
                "set SHARE {share}",
                "run",
            ],
            description="Generate and deploy NTLM coercion files to a writable share",
            variables={"domain": "AD domain", "dc_ip": "DC IP", "listener_ip": "Responder IP",
                       "user": "Username", "pass": "Password", "share": "Writable share path"},
        ),
    }

    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            config_dir = os.path.expanduser("~/.uwu-toolkit")
        self._config_dir = Path(config_dir)
        self._macros_file = self._config_dir / "macros.json"
        self._macros: Dict[str, Macro] = {}

        # Load builtins
        self._macros.update(self.BUILTIN_MACROS)

        # Load user-defined macros
        self._load()

    def _load(self) -> None:
        """Load user macros from disk"""
        if self._macros_file.exists():
            try:
                with open(self._macros_file) as f:
                    data = json.load(f)
                for name, macro_data in data.items():
                    self._macros[name] = Macro.from_dict(macro_data)
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

    def _save(self) -> None:
        """Save user macros to disk (excludes builtins)"""
        self._config_dir.mkdir(parents=True, exist_ok=True)
        user_macros = {
            name: m.to_dict() for name, m in self._macros.items()
            if name not in self.BUILTIN_MACROS
        }
        with open(self._macros_file, "w") as f:
            json.dump(user_macros, f, indent=2)

    def define(self, name: str, commands: List[str], description: str = "",
               variables: Optional[Dict[str, str]] = None) -> Macro:
        """Define a new macro"""
        macro = Macro(name=name, commands=commands, description=description,
                      variables=variables or {})
        self._macros[name] = macro
        self._save()
        return macro

    def delete(self, name: str) -> bool:
        """Delete a macro (can't delete builtins)"""
        if name in self.BUILTIN_MACROS:
            return False
        if name in self._macros:
            del self._macros[name]
            self._save()
            return True
        return False

    def get(self, name: str) -> Optional[Macro]:
        """Get a macro by name"""
        return self._macros.get(name)

    def list_macros(self) -> Dict[str, Macro]:
        """List all macros"""
        return self._macros.copy()

    def search(self, query: str) -> Dict[str, Macro]:
        """Search macros by name or description"""
        query = query.lower()
        return {
            name: m for name, m in self._macros.items()
            if query in name.lower() or query in m.description.lower()
        }

    def run(self, name: str, variables: Dict[str, str],
            execute_func: Callable[[str], None],
            dry_run: bool = False) -> bool:
        """
        Run a macro with variable substitution.

        Args:
            name: Macro name
            variables: Variable values for placeholders
            execute_func: Function to execute each command (console.execute_command)
            dry_run: If True, print commands without executing
        """
        macro = self.get(name)
        if not macro:
            return False

        # Check required variables
        required = macro.get_required_vars()
        missing = [v for v in required if v not in variables]
        if missing:
            raise ValueError(f"Missing variables: {', '.join(missing)}")

        commands = macro.render(variables)

        if dry_run:
            for i, cmd in enumerate(commands, 1):
                print(f"  [{i}] {cmd}")
            return True

        for cmd in commands:
            try:
                execute_func(cmd)
            except KeyboardInterrupt:
                print("\nMacro interrupted")
                return False
            except Exception as e:
                print(f"Macro step failed: {e}")
                return False

        return True

    def import_rc(self, filepath: str, name: Optional[str] = None) -> Optional[Macro]:
        """Import a .rc resource file as a macro"""
        try:
            with open(filepath) as f:
                commands = [
                    line.strip() for line in f
                    if line.strip() and not line.strip().startswith("#")
                ]
        except OSError:
            return None

        if not name:
            name = Path(filepath).stem

        return self.define(name, commands, description=f"Imported from {filepath}")


# Module-level singleton
_manager: Optional[MacroManager] = None


def get_macro_manager(config_dir: Optional[str] = None) -> MacroManager:
    """Get global MacroManager instance"""
    global _manager
    if _manager is None:
        _manager = MacroManager(config_dir)
    return _manager
