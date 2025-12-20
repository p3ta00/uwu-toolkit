"""
Base class for all UwU Toolkit modules
All custom modules should inherit from this class
"""

import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


# Extended PATH for finding tools (exegol, kali, etc.)
EXTRA_PATHS = [
    os.path.expanduser("~/.local/bin"),
    "/root/.local/bin",  # Exegol installs tools here
    "/opt/tools",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
]


def find_tool(name: str) -> Optional[str]:
    """Find a tool in extended PATH"""
    # First try standard which
    result = shutil.which(name)
    if result:
        return result

    # Search in extra paths
    for path in EXTRA_PATHS:
        full_path = os.path.join(path, name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path

    return None


class ModuleType(Enum):
    """Types of modules available"""
    EXPLOIT = "exploits"
    AUXILIARY = "auxiliary"
    ENUMERATION = "enumeration"
    POST = "post"
    PAYLOAD = "payloads"


class Platform(Enum):
    """Target platforms"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    MULTI = "multi"
    WEB = "web"
    NETWORK = "network"


@dataclass
class ModuleOption:
    """Represents a configurable option for a module"""
    name: str
    description: str
    required: bool = False
    default: Any = None
    value: Any = None
    choices: List[Any] = field(default_factory=list)

    def get_value(self) -> Any:
        """Get the current value or default"""
        if self.value is not None:
            return self.value
        return self.default

    def is_set(self) -> bool:
        """Check if value is set (including default)"""
        return self.get_value() is not None

    def validate(self) -> Tuple[bool, str]:
        """Validate the option value"""
        if self.required and not self.is_set():
            return False, f"{self.name} is required but not set"
        if self.choices and self.get_value() not in self.choices:
            return False, f"{self.name} must be one of: {', '.join(map(str, self.choices))}"
        return True, ""


class ModuleBase(ABC):
    """
    Base class for all UwU Toolkit modules

    To create a new module, inherit from this class and implement:
    - __init__: Set metadata and options
    - run(): Main execution logic

    Example:
        class MyScanner(ModuleBase):
            def __init__(self):
                super().__init__()
                self.name = "my_scanner"
                self.description = "Scans for XYZ vulnerabilities"
                self.author = "YourName"
                self.module_type = ModuleType.ENUMERATION
                self.platform = Platform.MULTI

                self.register_option("RHOSTS", "Target hosts", required=True)
                self.register_option("RPORT", "Target port", default=80)

            def run(self) -> bool:
                target = self.get_option("RHOSTS")
                port = self.get_option("RPORT")
                # ... scanning logic ...
                return True
    """

    def __init__(self):
        # Module metadata
        self.name: str = "unnamed_module"
        self.description: str = "No description"
        self.author: str = "Unknown"
        self.version: str = "1.0.0"
        self.module_type: ModuleType = ModuleType.AUXILIARY
        self.platform: Platform = Platform.MULTI
        self.references: List[str] = []
        self.tags: List[str] = []

        # Module options
        self._options: Dict[str, ModuleOption] = {}

        # Runtime
        self._config = None  # Will be set by console
        self._output: List[str] = []

    @property
    def full_path(self) -> str:
        """Full module path (e.g., auxiliary/scanner/smb/smb_version)"""
        return f"{self.module_type.value}/{self.name}"

    def set_config(self, config) -> None:
        """Set the config reference (called by console)"""
        self._config = config
        # Load global values for options
        self._load_global_values()

    def _load_global_values(self) -> None:
        """Load global variable values into options"""
        if not self._config:
            return
        for name, opt in self._options.items():
            global_val = self._config.get(name)
            if global_val is not None and opt.value is None:
                opt.value = global_val

    # =========================================================================
    # Option Management
    # =========================================================================

    def register_option(
        self,
        name: str,
        description: str,
        required: bool = False,
        default: Any = None,
        choices: List[Any] = None
    ) -> None:
        """Register a configurable option"""
        self._options[name.upper()] = ModuleOption(
            name=name.upper(),
            description=description,
            required=required,
            default=default,
            choices=choices or []
        )

    def set_option(self, name: str, value: Any) -> bool:
        """Set an option value. Returns False if option doesn't exist."""
        name = name.upper()
        if name not in self._options:
            return False
        self._options[name].value = value
        return True

    def has_option(self, name: str) -> bool:
        """Check if an option exists"""
        return name.upper() in self._options

    def get_option(self, name: str, default: Any = None) -> Any:
        """Get an option value"""
        name = name.upper()
        value = None

        if name in self._options:
            opt = self._options[name]
            # Module-specific value takes precedence
            if opt.value is not None:
                value = opt.value
            # Then check config (globals/session vars/permanent)
            elif self._config:
                config_val = self._config.get(name)
                if config_val is not None:
                    value = config_val
                else:
                    value = opt.default
            else:
                value = opt.default
        # Fall back to config for unknown options
        elif self._config:
            value = self._config.get(name, default)
        else:
            value = default

        # Resolve paths using WORKING_DIR for path-type variables
        if value and self._config and self._config.is_path_variable(name):
            value = self._config.resolve_path(str(value), name)

        return value

    def get_options(self) -> Dict[str, ModuleOption]:
        """Get all options"""
        return self._options.copy()

    def validate_options(self) -> Tuple[bool, List[str]]:
        """Validate all required options are set"""
        errors = []
        for name, opt in self._options.items():
            # Check if value is set (option value, global, or default)
            value = self.get_option(name)
            if opt.required and value is None:
                errors.append(f"{name} is required but not set")
            elif opt.choices and value is not None and value not in opt.choices:
                errors.append(f"{name} must be one of: {', '.join(map(str, opt.choices))}")
        return len(errors) == 0, errors

    # =========================================================================
    # Output Helpers
    # =========================================================================

    def print_status(self, msg: str) -> None:
        """Print status message"""
        print(f"[*] {msg}")
        self._output.append(f"[*] {msg}")

    def print_good(self, msg: str) -> None:
        """Print success message"""
        print(f"\033[32m[+]\033[0m {msg}")
        self._output.append(f"[+] {msg}")

    def print_error(self, msg: str) -> None:
        """Print error message"""
        print(f"\033[31m[-]\033[0m {msg}")
        self._output.append(f"[-] {msg}")

    def print_warning(self, msg: str) -> None:
        """Print warning message"""
        print(f"\033[33m[!]\033[0m {msg}")
        self._output.append(f"[!] {msg}")

    def print_line(self, msg: str = "") -> None:
        """Print a line of text"""
        print(msg)
        self._output.append(msg)

    # =========================================================================
    # Execution Helpers
    # =========================================================================

    def run_command(
        self,
        cmd: List[str],
        capture: bool = True,
        timeout: Optional[int] = None
    ) -> Tuple[int, str, str]:
        """
        Run a shell command

        Returns: (return_code, stdout, stderr)
        """
        timeout = timeout or self.get_option("TIMEOUT", 30)
        try:
            env = os.environ.copy()
            # Add common tool paths (exegol, kali, etc.)
            extra_paths = [
                os.path.expanduser("~/.local/bin"),
                "/opt/tools",
                "/usr/local/bin",
            ]
            current_path = env.get("PATH", "")
            env["PATH"] = ":".join(extra_paths) + ":" + current_path

            if self._config:
                env.update(self._config.export_to_env())

            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout,
                env=env
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _is_inside_exegol(self) -> bool:
        """Check if we're already running inside an Exegol container"""
        return os.path.exists("/.exegol") or (
            os.path.exists("/opt/tools") and os.path.exists("/root/.exegol")
        )

    def run_in_exegol(
        self,
        cmd: str,
        container: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Tuple[int, str, str]:
        """
        Run a command inside an exegol container

        Args:
            cmd: Command to execute
            container: Container name (uses EXEGOL_CONTAINER option if not specified)
            timeout: Command timeout in seconds

        Returns: (return_code, stdout, stderr)
        """
        timeout = timeout or self.get_option("TIMEOUT", 120)

        # If already inside Exegol, run directly
        if self._is_inside_exegol():
            exegol_path = "/root/.local/bin:/opt/tools/bin:/opt/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            full_cmd = ["bash", "-c", f"export PATH={exegol_path}:$PATH && {cmd}"]
            try:
                result = subprocess.run(
                    full_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                return -1, "", "Command timed out"
            except Exception as e:
                return -1, "", str(e)

        # Otherwise, use docker exec
        container = container or self.get_option("EXEGOL_CONTAINER")

        # Auto-detect container if not specified
        if not container:
            container = self._find_exegol_container()
            if not container:
                return -1, "", "No Exegol container found. Set EXEGOL_CONTAINER option."

        # Use docker exec for reliable output capture
        # Set PATH to include common tool locations in Exegol
        exegol_path = "/root/.local/bin:/opt/tools/bin:/opt/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        full_cmd = [
            "docker", "exec", container,
            "bash", "-c", f"export PATH={exegol_path}:$PATH && {cmd}"
        ]

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def run_in_exegol_stream(
        self,
        cmd: str,
        container: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> int:
        """
        Run a command inside an exegol container with streaming output.
        Output is printed in real-time as it's received.

        Args:
            cmd: Command to execute
            container: Container name (uses EXEGOL_CONTAINER option if not specified)
            timeout: Command timeout in seconds

        Returns: return_code
        """
        import select

        timeout = timeout or self.get_option("TIMEOUT", 120)
        exegol_path = "/root/.local/bin:/opt/tools/bin:/opt/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

        # Build command
        if self._is_inside_exegol():
            full_cmd = ["bash", "-c", f"export PATH={exegol_path}:$PATH && {cmd}"]
        else:
            container = container or self.get_option("EXEGOL_CONTAINER")
            if not container:
                container = self._find_exegol_container()
                if not container:
                    self.print_error("No Exegol container found. Set EXEGOL_CONTAINER option.")
                    return -1

            full_cmd = [
                "docker", "exec", container,
                "bash", "-c", f"export PATH={exegol_path}:$PATH && {cmd}"
            ]

        try:
            process = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            # Stream output line by line
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    line = line.rstrip()
                    # Apply highlighting
                    if "Pwn3d!" in line:
                        self.print_good(f"🎯 {line}")
                    elif "[+]" in line:
                        self.print_good(line)
                    elif "[-]" in line:
                        self.print_error(line)
                    elif "[*]" in line:
                        self.print_status(line.replace("[*]", "").strip())
                    else:
                        self.print_line(f"    {line}")

            return process.returncode

        except Exception as e:
            self.print_error(f"Error: {e}")
            return -1

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

    def exegol_tool(
        self,
        tool: str,
        args: List[str],
        container: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Tuple[int, str, str]:
        """
        Run a specific tool inside Exegol with arguments

        Args:
            tool: Tool name (e.g., 'NetExec', 'GetUserSPNs.py')
            args: List of arguments
            container: Container name
            timeout: Command timeout

        Returns: (return_code, stdout, stderr)
        """
        # Build command string with proper quoting
        escaped_args = []
        for arg in args:
            if ' ' in arg or '"' in arg or "'" in arg:
                escaped_args.append(f"'{arg}'")
            else:
                escaped_args.append(arg)

        cmd = f"{tool} {' '.join(escaped_args)}"
        return self.run_in_exegol(cmd, container, timeout)

    # =========================================================================
    # Abstract Methods
    # =========================================================================

    @abstractmethod
    def run(self) -> bool:
        """
        Main execution method - must be implemented by subclasses

        Returns:
            True if execution was successful, False otherwise
        """
        pass

    def check(self) -> bool:
        """
        Optional check method to verify target is vulnerable
        before running the exploit

        Returns:
            True if target appears vulnerable, False otherwise
        """
        return True

    def cleanup(self) -> None:
        """
        Optional cleanup method called after run()
        Use for cleaning up resources, temporary files, etc.
        """
        pass

    # =========================================================================
    # Module Info
    # =========================================================================

    def info(self) -> str:
        """Get formatted module information"""
        lines = [
            "",
            f"       Name: {self.name}",
            f"     Module: {self.full_path}",
            f"   Platform: {self.platform.value}",
            f"     Author: {self.author}",
            f"    Version: {self.version}",
            "",
            f"Description:",
            f"  {self.description}",
            "",
        ]

        if self.references:
            lines.append("References:")
            for ref in self.references:
                lines.append(f"  - {ref}")
            lines.append("")

        if self.tags:
            lines.append(f"Tags: {', '.join(self.tags)}")
            lines.append("")

        return "\n".join(lines)

    def options_table(self) -> str:
        """Get formatted options table"""
        if not self._options:
            return "No options available for this module"

        # Calculate dynamic column widths
        name_width = max(len(name) for name in self._options.keys())
        name_width = max(name_width, 4) + 2  # Minimum "Name" + padding

        # Calculate max value width
        max_val_len = 7  # Minimum "Current"
        for name in self._options:
            value = self.get_option(name)
            if value is not None:
                max_val_len = max(max_val_len, len(str(value)))
        val_width = min(max_val_len + 2, 40)  # Cap at 40

        req_width = 10

        lines = [
            "",
            "Module options:",
            "",
            f"{'Name':<{name_width}} {'Current':<{val_width}} {'Required':<{req_width}} Description",
            f"{'-'*name_width} {'-'*val_width} {'-'*req_width} {'-'*45}",
        ]

        for name, opt in sorted(self._options.items()):
            value = self.get_option(name)
            current = str(value) if value is not None else ""
            if len(current) > val_width - 2:
                current = current[:val_width - 5] + "..."
            required = "yes" if opt.required else "no"
            lines.append(f"{name:<{name_width}} {current:<{val_width}} {required:<{req_width}} {opt.description}")

        lines.append("")
        return "\n".join(lines)
