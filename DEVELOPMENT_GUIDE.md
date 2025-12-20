# UwU Toolkit - Development Guide

## Overview

UwU Toolkit is a Metasploit-inspired modular penetration testing framework designed to run inside Exegol containers. It provides a unified interface for executing various security tools with persistent variable management, colorized output, and module discovery.

**Key Design Principles:**
- Modular architecture for easy extension
- Metasploit-like command syntax (`use`, `set`, `run`)
- Persistent variable history for quick recall
- Cyberpunk Neon color theme for visibility
- Resource file support for automation

---

## Architecture

```
uwu-toolkit/
├── uwu                         # Main entry point (executable)
├── core/
│   ├── __init__.py
│   ├── console.py              # Interactive console (command handling, UI)
│   ├── config.py               # Configuration & variable persistence
│   ├── module_base.py          # Base class for all modules
│   ├── module_loader.py        # Module discovery & loading
│   ├── colors.py               # Color definitions, Style helpers, Banner
│   └── wordlists.py            # Wordlist path helpers
├── modules/
│   ├── auxiliary/              # Scanning, enumeration modules
│   │   ├── ad/                 # Active Directory modules
│   │   ├── smb/                # SMB enumeration
│   │   ├── ssh/                # SSH enumeration
│   │   ├── rdp/                # RDP checking
│   │   └── web/                # Web scanning
│   ├── enumeration/            # Host enumeration modules
│   ├── exploits/               # Exploit modules
│   ├── post/                   # Post-exploitation modules
│   └── payloads/               # Payload generators
├── scripts/                    # PowerShell scripts for remote execution
├── cyberpunk_demo.rc           # Demo resource file
└── DEVELOPMENT_GUIDE.md        # This file
```

---

## Core Components

### 1. Entry Point (`uwu`)

The main executable that bootstraps the framework.

**Command Line Arguments:**
```bash
python3 uwu                     # Interactive mode
python3 uwu -r file.rc          # Execute resource file
python3 uwu -x "cmd1;cmd2"      # Execute commands and exit
python3 uwu -q                  # Quiet mode (no banner)
```

**Flow:**
1. Parse arguments
2. Create `Config` instance (loads persistent data)
3. Create `UwUConsole` instance
4. Either run batch commands or start interactive loop

### 2. Console (`core/console.py`)

The interactive console handles all user interaction.

**Key Components:**

```python
class UwUConsole:
    def __init__(self, config: Config, quiet: bool = False):
        self.config = config                    # Variable storage
        self.loader = ModuleLoader(...)         # Module discovery
        self.current_module = None              # Currently selected module
        self.commands = {...}                   # Command dispatch table
        self.processes = {}                     # Background process tracking
```

**Command Dispatch:**
```python
self.commands = {
    "help": self.cmd_help,
    "use": self.cmd_use,
    "set": self.cmd_set,
    "run": self.cmd_run,
    # ... etc
}
```

**Module Selection Flow:**
1. `use auxiliary/ad/powerview_remote_exec`
2. `cmd_use()` calls `loader.load_module(path)`
3. Module instantiated, stored in `self.current_module`
4. Module receives config reference via `module.set_config(self.config)`
5. Global variables auto-populate module options

### 3. Configuration (`core/config.py`)

Handles persistent storage and variable management.

**Storage Locations (`~/.uwu-toolkit/`):**
- `config.json` - Framework settings
- `globals.json` - Global variables (persist across sessions)
- `var_history.json` - Variable history for recall

**Variable Types:**
```python
# Session variables (cleared on exit)
config.set("RHOSTS", "10.10.10.1")

# Global variables (persist forever)
config.setg("DOMAIN", "CORP.LOCAL")

# Get value (session overrides global)
config.get("RHOSTS")
```

**History System:**
- Every `set`/`setg` adds to history
- History preserves timestamps
- Up to 50 entries per variable
- Used for tab completion (future feature)

### 4. Module Base (`core/module_base.py`)

Abstract base class all modules inherit from.

**Module Metadata:**
```python
class MyModule(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "my_module"
        self.description = "Description here"
        self.author = "Author Name"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "enumeration"]
        self.references = ["https://example.com"]
```

**Option Registration:**
```python
self.register_option("RHOSTS", "Target host", required=True)
self.register_option("RPORT", "Target port", default=445)
self.register_option("METHOD", "Execution method",
                     choices=["winrm", "smb", "wmi"])
```

**Required Methods:**
```python
def run(self) -> bool:
    """Main execution - MUST implement"""
    target = self.get_option("RHOSTS")
    # ... do work ...
    return True  # Success

def check(self) -> bool:
    """Optional: verify target is vulnerable"""
    return True
```

**Helper Methods:**
```python
self.print_status("Working...")     # [*] Working...
self.print_good("Found it!")        # [+] Found it! (green)
self.print_error("Failed")          # [-] Failed (red)
self.print_warning("Caution")       # [!] Caution (orange)
self.print_line("Raw text")         # Raw text

# Run external commands
ret, stdout, stderr = self.run_command(["nmap", "-sV", target])
```

### 5. Module Loader (`core/module_loader.py`)

Handles module discovery and instantiation.

**Discovery Process:**
1. Scan `modules/` directory recursively
2. Find all `.py` files (skip `__init__.py`, `_*.py`)
3. Parse file to extract metadata WITHOUT importing
4. Store `ModuleInfo` objects in cache

**Loading Process:**
1. `load_module("auxiliary/ad/kerberoast")`
2. Find file path from cache
3. Use `importlib` to load module
4. Find `ModuleBase` subclass in module
5. Instantiate and return

**Search:**
```python
# Search by name, description, tags, path
results = loader.search("kerberos")
results = loader.search("ad")
```

### 6. Colors (`core/colors.py`)

Cyberpunk Neon color scheme and styling helpers.

**Color Palette (True RGB):**
```python
NEON_PINK = "\033[38;2;255;16;240m"      # #ff10f0
NEON_MAGENTA = "\033[38;2;255;0;110m"    # #ff006e
NEON_PURPLE = "\033[38;2;182;32;224m"    # #b620e0
NEON_BLUE = "\033[38;2;0;162;255m"       # #00a2ff
NEON_CYAN = "\033[38;2;0;232;255m"       # #00e8ff
NEON_GREEN = "\033[38;2;0;255;159m"      # #00ff9f
DIGITAL_RAIN = "\033[38;2;0;255;65m"     # #00ff41 (Matrix green)
NEON_YELLOW = "\033[38;2;255;234;0m"     # #ffea00
NEON_ORANGE = "\033[38;2;255;124;0m"     # #ff7c00
```

**Style Helpers:**
```python
Style.success("Done")       # [+] Done (green)
Style.error("Failed")       # [-] Failed (red)
Style.warning("Warning")    # [!] Warning (orange)
Style.info("Info")          # [*] Info (blue)
Style.module("path")        # path (neon pink)
Style.title("HEADER")       # HEADER (dark pink, bold)
Style.uwu("text")           # text (hot pink)
Style.varname("VAR")        # VAR (yellow)
Style.value("val")          # val (green)
```

---

## Creating New Modules

### Step 1: Create Module File

Create `modules/auxiliary/mycat/my_module.py`:

```python
"""
My Custom Module
Does something useful
"""

from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class MyModule(ModuleBase):
    def __init__(self):
        super().__init__()

        # Metadata
        self.name = "my_module"
        self.description = "Description of what it does"
        self.author = "Your Name"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["category", "tags", "here"]
        self.references = [
            "https://documentation.url"
        ]

        # Options
        self.register_option("RHOSTS", "Target host(s)", required=True)
        self.register_option("RPORT", "Target port", default=80)
        self.register_option("THREADS", "Concurrent threads", default=10)

    def check(self) -> bool:
        """Verify required tools exist"""
        tool = find_tool("mytool")
        if not tool:
            self.print_error("mytool not found")
            return False
        return True

    def run(self) -> bool:
        """Main execution logic"""
        target = self.get_option("RHOSTS")
        port = self.get_option("RPORT")

        self.print_status(f"Scanning {target}:{port}")

        # Run external tool
        ret, stdout, stderr = self.run_command(
            ["mytool", "-h", target, "-p", str(port)]
        )

        if ret == 0:
            self.print_good("Scan complete!")
            self.print_line(stdout)
            return True
        else:
            self.print_error(f"Scan failed: {stderr}")
            return False
```

### Step 2: Test Module

```bash
# Inside Exegol
cd /workspace/uwu-toolkit
python3 uwu
> search my_module
> use auxiliary/mycat/my_module
> info
> options
> set RHOSTS 10.10.10.1
> run
```

---

## Key Workflows

### Variable Flow

```
User: set RHOSTS 10.10.10.1
          │
          ▼
    console.cmd_set()
          │
          ├──► config.set("RHOSTS", "10.10.10.1")
          │         │
          │         ├──► _session_vars["RHOSTS"] = "10.10.10.1"
          │         └──► _add_to_history("RHOSTS", "10.10.10.1")
          │
          └──► current_module.set_option("RHOSTS", "10.10.10.1")
                      │
                      └──► module._options["RHOSTS"].value = "10.10.10.1"
```

### Module Execution Flow

```
User: run
   │
   ▼
console.cmd_run()
   │
   ├──► module.validate_options()
   │         │
   │         └──► Check all required options are set
   │
   ├──► module.run()
   │         │
   │         ├──► get_option("RHOSTS")  ──► Check module option
   │         │                               │
   │         │                               └──► Fall back to config.get()
   │         │
   │         ├──► run_command([...])
   │         │         │
   │         │         └──► subprocess.run() with env vars
   │         │
   │         └──► Return True/False
   │
   └──► module.cleanup()
```

---

## Resource Files

Resource files (`.rc`) allow automated execution:

```bash
# mytest.rc
# Comments start with #

# Set global variables
setg DOMAIN CORP.LOCAL
setg USER admin

# Use a module
use auxiliary/ad/powerview_remote_exec
set RHOSTS 10.10.10.100
set PASS SuperSecret123
set METHOD netexec
run

# Use another module
use auxiliary/ad/kerberoast
set RHOSTS 10.10.10.100
run

exit
```

Execute:
```bash
python3 uwu -r mytest.rc
```

---

## Adding New Commands

To add a new console command:

1. Add to command dispatch table in `console.py`:
```python
self.commands = {
    # ...existing...
    "mycommand": self.cmd_mycommand,
}
```

2. Implement the command:
```python
def cmd_mycommand(self, args: List[str]) -> None:
    """Description shown in help"""
    if not args:
        print(Style.error("Usage: mycommand <arg>"))
        return

    # Do something
    print(Style.success(f"Did something with {args[0]}"))
```

3. Add to help menu in `cmd_help()`:
```python
{Colors.NEON_CYAN}mycommand <arg>{Colors.RESET}  Description here
```

---

## Color Theme Guidelines

**Section Headers (over ===):**
- Use `Style.title()` (dark pink #c71585, bold)

**Module Paths:**
- Use `Style.module()` (neon pink #ff10f0)

**Variable Names:**
- Use `Style.varname()` (yellow #ffea00)

**Variable Values:**
- Use `Style.value()` (green #00ff9f)

**Status Messages:**
- Success: `Style.success()` (green)
- Error: `Style.error()` (red-pink)
- Warning: `Style.warning()` (orange)
- Info: `Style.info()` (blue)

**Help Menu Gradient:**
- Core Commands: Neon Pink
- Module Commands: Magenta
- Variable Commands: Purple
- Server Utilities: Blue
- Other: Matrix Green

---

## PowerShell Scripts

The `scripts/` directory contains PowerShell scripts for remote execution:

**Invoke-UwUEnum.ps1:**
- Full AD enumeration script
- Uses PowerView functions
- Outputs to files and console
- Run locally on compromised Windows host

**UwU-QuickEnum.ps1:**
- Compact enumeration for remote execution
- Console output only
- For use via WMI/WinRM/NetExec

---

## Testing Inside Exegol

Always test the tool inside your Exegol container:

```bash
# From host
docker exec -it exegol-uwu-toolkit bash

# Inside container
cd /workspace/uwu-toolkit
python3 uwu

# Or sync files and test
docker cp /home/p3ta/dev/uwu-toolkit/core/colors.py exegol-uwu-toolkit:/workspace/uwu-toolkit/core/colors.py
```

---

## Claude AI Integration

UwU Toolkit includes built-in Claude AI integration for code analysis and debugging.

### Setup

```bash
# Install anthropic package (inside Exegol)
pip3 install anthropic --break-system-packages

# Set API key (persists across sessions)
setg ANTHROPIC_API_KEY sk-ant-api03-...
```

### Core Component (`core/claude.py`)

The `ClaudeAssistant` class handles all AI interactions:

```python
class ClaudeAssistant:
    # Specialized system prompts for different tasks
    VULN_ANALYSIS_PROMPT = "..."  # Security vulnerability analysis
    DEBUG_PROMPT = "..."          # Code debugging
    GENERAL_PROMPT = "..."        # General Q&A

    def analyze_vulnerabilities(paths, focus=None)  # Scan code for vulns
    def debug_code(paths, error_msg=None)           # Debug syntax/logic
    def ask(question, context_paths=None)           # Ask questions
```

### Commands

| Command | Description |
|---------|-------------|
| `claude analyze <path>` | Scan code for security vulnerabilities |
| `claude analyze <path> --focus <area>` | Focus on specific vuln type |
| `claude debug <path>` | Debug code for errors |
| `claude debug <path> --error "msg"` | Debug with error context |
| `claude ask "question"` | Ask security-related question |
| `claude ask "question" --context <path>` | Ask with code context |
| `claude model <name>` | Change AI model |
| `claude status` | Check integration status |

### File Analysis

The analyzer supports:
- Single files or entire directories
- Recursive scanning for source code
- Common extensions: `.py`, `.js`, `.php`, `.java`, `.c`, `.ps1`, etc.
- Large file handling (skips files > 100KB)

### Example Use Cases

```bash
# Analyze dumped web app source
claude analyze /tmp/webapp/

# Focus on specific vulnerability type
claude analyze /tmp/api.py --focus "sql injection"

# Debug with error context
claude debug /tmp/broken.py --error "TypeError on line 42"

# Ask about exploitation
claude ask "how do I exploit SSRF in this code" --context /tmp/app.py
```

---

## Future Development Ideas

1. **Workspace Support** - Separate variable sets per engagement
2. **Results Database** - SQLite storage for findings
3. **Web Interface** - Optional Flask/FastAPI dashboard
4. **Plugin System** - Dynamic module loading from external repos
5. **Report Generation** - Export findings to markdown/HTML/PDF
6. **Integration with BloodHound** - Direct data import/export
7. **Session Management** - Save/restore complete state
8. **Claude Streaming** - Stream responses for long analyses

---

## File Locations

**Configuration:**
- `~/.uwu-toolkit/config.json` - Framework settings
- `~/.uwu-toolkit/globals.json` - Persistent global variables
- `~/.uwu-toolkit/var_history.json` - Variable history

**Inside Exegol:**
- `/workspace/uwu-toolkit/` - Tool installation
- `/root/.uwu-toolkit/` - Config directory

---

## Troubleshooting

**Module not found:**
- Check file is in correct `modules/` subdirectory
- Ensure class inherits from `ModuleBase`
- Check for Python syntax errors

**Tool not found:**
- Use `find_tool("toolname")` which searches extended PATH
- Exegol tools in `~/.local/bin` are included

**Colors not showing:**
- Ensure terminal supports true color (24-bit)
- Check `TERM` environment variable

**Banner not showing in batch mode:**
- By design: `-r` and `-x` modes skip banner
- Use `banner` command in resource file if needed

---

*Last Updated: December 2024*
*Author: UwU Toolkit Development Team*
