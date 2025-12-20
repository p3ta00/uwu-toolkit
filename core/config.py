"""
Configuration and global variable management for UwU Toolkit
Handles persistent storage of variables with history tracking
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class Config:
    """Manages global configuration and variable persistence"""

    def __init__(self):
        self.config_dir = Path.home() / ".uwu-toolkit"
        self.config_file = self.config_dir / "config.json"
        self.history_file = self.config_dir / "var_history.json"
        self.globals_file = self.config_dir / "globals.json"
        self.permanent_file = self.config_dir / "permanent.json"

        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Load configurations
        self._config = self._load_json(self.config_file, self._default_config())
        self._globals = self._load_json(self.globals_file, {})
        self._history = self._load_json(self.history_file, {})
        self._permanent = self._load_json(self.permanent_file, {})

        # Current session variables (can override globals)
        self._session_vars: Dict[str, Any] = {}

        # Auto-detect environment and set WORKING_DIR if not already set
        self._auto_detect_working_dir()

        # Standard variable names with descriptions
        self.known_variables = {
            "RHOSTS": "Target host(s) - IP address or hostname",
            "RHOST": "Target host - single IP address or hostname",
            "RPORT": "Target port number",
            "LHOST": "Local host for reverse connections",
            "LPORT": "Local port for listeners",
            "USER": "Username for authentication",
            "PASS": "Password for authentication",
            "DOMAIN": "Domain name for Windows environments",
            "WORDLIST": "Path to wordlist file",
            "THREADS": "Number of concurrent threads",
            "TIMEOUT": "Connection timeout in seconds",
            "OUTPUT": "Output directory for results",
            "INTERFACE": "Network interface to use",
            "EXEGOL_CONTAINER": "Default exegol container name",
            "PROXY": "Proxy URL (e.g., http://127.0.0.1:8080)",
            "USER_AGENT": "Custom User-Agent string",
            "COOKIES": "Session cookies",
            "HEADERS": "Custom HTTP headers (JSON format)",
            "TARGET_URL": "Target URL for web attacks",
            "WORKSPACE": "Current workspace name",
            "WORKING_DIR": "Default working directory for file paths",
        }

        # Path-type variables that should use WORKING_DIR resolution
        # Path variables that should be resolved with WORKING_DIR (local paths only)
        self.path_variables = {
            "HASHFILE", "OUTPUT", "RULES", "LOOT_DIR",
            "SCRIPT", "PAYLOAD", "TARGET_FILE", "INPUT_FILE", "OUTPUT_FILE"
        }

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration values"""
        return {
            "prompt_style": "uwu",
            "color_enabled": True,
            "log_commands": True,
            "default_threads": 10,
            "default_timeout": 30,
            "exegol_image": "local_full",
            "gosh_default_port": 8000,
            "php_default_port": 8080,
            "nc_use_rlwrap": True,
            "history_max_per_var": 50,
            "modules_path": str(Path(__file__).parent.parent / "modules"),
            "workspace": "default",
        }

    def _load_json(self, path: Path, default: Any) -> Any:
        """Load JSON file or return default"""
        try:
            if path.exists():
                with open(path, "r") as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
        return default

    def _save_json(self, path: Path, data: Any) -> None:
        """Save data to JSON file"""
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except IOError as e:
            print(f"[!] Error saving {path}: {e}")

    def _auto_detect_working_dir(self) -> None:
        """
        Auto-detect environment and set WORKING_DIR if not already configured.

        Detection priority:
        1. If WORKING_DIR is already set (permanent/global), use that
        2. If in Exegol container -> /workspace
        3. If in Kali with ~/htb existing -> ~/htb
        4. Otherwise -> current directory
        """
        # Check if already set
        if self._permanent.get("WORKING_DIR") or self._globals.get("WORKING_DIR"):
            return

        working_dir = None

        # Check for Exegol environment
        if os.path.exists("/.exegol") or (
            os.path.exists("/opt/tools") and os.path.exists("/root/.exegol")
        ):
            # We're in Exegol - use /workspace
            if os.path.exists("/workspace"):
                working_dir = "/workspace"

        # Check for common pentest directories
        if not working_dir:
            common_dirs = [
                os.path.expanduser("~/htb"),
                os.path.expanduser("~/ctf"),
                os.path.expanduser("~/pentests"),
                os.path.expanduser("~/engagements"),
            ]
            for d in common_dirs:
                if os.path.isdir(d):
                    working_dir = d
                    break

        # Set the detected working directory as a session default (not persistent)
        if working_dir:
            self._globals["WORKING_DIR"] = working_dir

    def get_working_dir(self) -> str:
        """Get the current working directory setting"""
        return (
            self._session_vars.get("WORKING_DIR") or
            self._globals.get("WORKING_DIR") or
            self._permanent.get("WORKING_DIR") or
            os.getcwd()
        )

    # =========================================================================
    # Dashboard Event Logging
    # =========================================================================

    def log_event(self, event_type: str, message: str) -> None:
        """
        Log an event for the dashboard to display.

        Args:
            event_type: Type of event (info, connection, server, listener, error)
            message: Event message
        """
        events_file = self.config_dir / "dashboard_events.json"
        events = []

        try:
            if events_file.exists():
                with open(events_file, 'r') as f:
                    events = json.load(f)
        except (json.JSONDecodeError, IOError):
            events = []

        # Add new event
        events.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": event_type,
            "message": message
        })

        # Keep only last 50 events
        events = events[-50:]

        try:
            with open(events_file, 'w') as f:
                json.dump(events, f, indent=2)
        except IOError:
            pass

    def log_connection(self, remote: str, local_port: str) -> None:
        """Log a new connection event"""
        self.log_event("connection", f"New connection from {remote} on port {local_port}")

    def log_server_start(self, server_type: str, port: str) -> None:
        """Log server start event"""
        self.log_event("server", f"{server_type} started on port {port}")

    def log_server_stop(self, server_type: str, port: str) -> None:
        """Log server stop event"""
        self.log_event("server", f"{server_type} stopped (port {port})")

    def log_listener_start(self, listener_type: str, port: str) -> None:
        """Log listener start event"""
        self.log_event("listener", f"{listener_type} listening on port {port}")

    def save(self) -> None:
        """Save all configurations to disk"""
        self._save_json(self.config_file, self._config)
        self._save_json(self.globals_file, self._globals)
        self._save_json(self.history_file, self._history)
        self._save_json(self.permanent_file, self._permanent)

    # =========================================================================
    # Global Variable Management
    # =========================================================================

    def setg(self, name: str, value: Any) -> None:
        """Set a global variable (persists across sessions)"""
        name = name.upper()
        self._globals[name] = value
        self._add_to_history(name, value)
        self.save()

    def getg(self, name: str, default: Any = None) -> Any:
        """Get a global variable"""
        name = name.upper()
        return self._globals.get(name, default)

    def unsetg(self, name: str) -> bool:
        """Unset a global variable"""
        name = name.upper()
        if name in self._globals:
            del self._globals[name]
            self.save()
            return True
        return False

    def get_all_globals(self) -> Dict[str, Any]:
        """Get all global variables"""
        return self._globals.copy()

    # =========================================================================
    # Permanent Variable Management (setp)
    # =========================================================================

    def setp(self, name: str, value: Any) -> None:
        """Set a permanent variable (persists forever, highest priority)"""
        name = name.upper()
        self._permanent[name] = value
        self._add_to_history(name, value)
        self.save()

    def getp(self, name: str, default: Any = None) -> Any:
        """Get a permanent variable"""
        name = name.upper()
        return self._permanent.get(name, default)

    def unsetp(self, name: str) -> bool:
        """Unset a permanent variable"""
        name = name.upper()
        if name in self._permanent:
            del self._permanent[name]
            self.save()
            return True
        return False

    def get_all_permanent(self) -> Dict[str, Any]:
        """Get all permanent variables"""
        return self._permanent.copy()

    def resolve_path(self, path: str, var_name: str = None) -> str:
        """
        Resolve a path using WORKING_DIR if path is relative.

        - If path starts with '/' or '~', use it as-is
        - Otherwise, prepend WORKING_DIR if set
        """
        if not path:
            return path

        # Expand ~ to home directory
        if path.startswith('~'):
            return os.path.expanduser(path)

        # Absolute path - use as-is
        if path.startswith('/'):
            return path

        # Relative path - prepend WORKING_DIR if set
        working_dir = self.getp("WORKING_DIR") or self.getg("WORKING_DIR")
        if working_dir:
            working_dir = os.path.expanduser(working_dir)
            return os.path.join(working_dir, path)

        return path

    def is_path_variable(self, name: str) -> bool:
        """Check if a variable is a path-type variable"""
        return name.upper() in self.path_variables

    # =========================================================================
    # Session Variable Management
    # =========================================================================

    def set(self, name: str, value: Any) -> None:
        """Set a session variable (module-specific, doesn't persist)"""
        name = name.upper()
        self._session_vars[name] = value
        self._add_to_history(name, value)
        self.save()  # Save history

    def get(self, name: str, default: Any = None) -> Any:
        """Get a variable (session > global > permanent)"""
        name = name.upper()
        if name in self._session_vars:
            return self._session_vars[name]
        if name in self._globals:
            return self._globals[name]
        if name in self._permanent:
            return self._permanent[name]
        return default

    def unset(self, name: str) -> bool:
        """Unset a session variable"""
        name = name.upper()
        if name in self._session_vars:
            del self._session_vars[name]
            return True
        return False

    def get_all_vars(self) -> Dict[str, Any]:
        """Get all variables (merged, session overrides global)"""
        merged = self._globals.copy()
        merged.update(self._session_vars)
        return merged

    def clear_session(self) -> None:
        """Clear all session variables"""
        self._session_vars.clear()

    # =========================================================================
    # Variable History Management
    # =========================================================================

    def _add_to_history(self, name: str, value: Any) -> None:
        """Add a value to variable history"""
        name = name.upper()
        if name not in self._history:
            self._history[name] = []

        # Create history entry
        entry = {
            "value": value,
            "timestamp": datetime.now().isoformat(),
        }

        # Remove duplicates (keep most recent)
        self._history[name] = [
            h for h in self._history[name] if h["value"] != value
        ]

        # Add new entry at the beginning
        self._history[name].insert(0, entry)

        # Limit history size
        max_history = self._config.get("history_max_per_var", 50)
        self._history[name] = self._history[name][:max_history]

    def get_history(self, name: str) -> List[Dict[str, Any]]:
        """Get history for a specific variable"""
        name = name.upper()
        return self._history.get(name, [])

    def get_history_values(self, name: str) -> List[Any]:
        """Get just the values from history (for completion)"""
        return [h["value"] for h in self.get_history(name)]

    def get_all_history(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get complete history for all variables"""
        return self._history.copy()

    def search_history(self, query: str) -> Dict[str, List[Any]]:
        """Search history for values matching query"""
        query = query.lower()
        results = {}
        for name, entries in self._history.items():
            matches = [
                h["value"] for h in entries
                if query in str(h["value"]).lower()
            ]
            if matches:
                results[name] = matches
        return results

    # =========================================================================
    # Configuration Management
    # =========================================================================

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self._config.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        """Set a configuration value"""
        self._config[key] = value
        self.save()

    def get_variable_description(self, name: str) -> str:
        """Get description for a known variable"""
        return self.known_variables.get(name.upper(), "User-defined variable")

    # =========================================================================
    # Export for shell environment
    # =========================================================================

    def export_to_env(self) -> Dict[str, str]:
        """Export all variables as environment variables"""
        env_vars = {}
        for name, value in self.get_all_vars().items():
            env_key = f"UWU_{name}"
            env_vars[env_key] = str(value)
        return env_vars

    def get_env_script(self) -> str:
        """Generate shell script to export variables"""
        lines = ["#!/bin/bash", "# UwU Toolkit Environment Variables", ""]
        for name, value in self.get_all_vars().items():
            # Escape special characters
            escaped = str(value).replace("'", "'\\''")
            lines.append(f"export UWU_{name}='{escaped}'")
        return "\n".join(lines)
