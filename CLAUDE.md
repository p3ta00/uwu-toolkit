# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

UwU Toolkit is a modular penetration testing framework inspired by Metasploit. It provides a CLI interface with persistent variable management, module discovery, and integrations with security tools. Designed to run inside Exegol containers.

## Commands

```bash
# Run interactively
python3 uwu

# Execute resource file (batch mode)
python3 uwu -r script.rc

# Execute commands directly
python3 uwu -x "use auxiliary/ad/kerberoast; set RHOSTS 10.10.10.1; run"

# Quiet mode (no banner)
python3 uwu -q
```

**Installation:**
```bash
./setup.sh  # Creates symlink to ~/.local/bin/uwu
```

## Architecture

### Core Components (`core/`)

| File | Purpose |
|------|---------|
| `console.py` | Interactive console, command dispatch, tab completion |
| `config.py` | Variable persistence, history tracking, configuration storage |
| `module_base.py` | Abstract base class all modules inherit from |
| `module_loader.py` | Module discovery, loading, and search |
| `colors.py` | Cyberpunk neon color theme, styling helpers |
| `claude.py` | Claude AI integration for code analysis |
| `sliver.py` | Sliver C2 client/server integration |
| `wordlists.py` | Wordlist path resolution helpers |

### Module Types (`modules/`)

Modules are organized by type in subdirectories:
- `auxiliary/` - Scanning, enumeration (AD, SMB, SSH, RDP, web)
- `enumeration/` - Host enumeration (nmap, port scanning, autoenum)
- `exploits/` - Exploit modules
- `post/` - Post-exploitation modules
- `payloads/` - Payload generators

### Data Flow

```
User Input → UwUConsole.execute_command() → Command Handler
                                              ↓
                                        Module.run()
                                              ↓
                                    Config (variable lookup)
                                              ↓
                                    External Tools (subprocess)
```

**Variable Resolution:**
1. Module option value (set via `set`)
2. Global config value (set via `setg`)
3. Default value from option registration

## Creating Modules

Modules inherit from `ModuleBase` and implement `run()`:

```python
from core.module_base import ModuleBase, ModuleType, Platform, find_tool

class MyModule(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "my_module"
        self.description = "What it does"
        self.author = "Author Name"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["category", "tags"]

        # Register options
        self.register_option("RHOSTS", "Target host", required=True)
        self.register_option("RPORT", "Target port", default=80)

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        # Module logic here
        self.print_status("Working...")
        self.print_good("Success!")
        return True

    def check(self) -> bool:
        """Optional: verify prerequisites"""
        return find_tool("required_tool") is not None
```

**Module Types:** `EXPLOIT`, `AUXILIARY`, `ENUMERATION`, `POST`, `PAYLOAD`
**Platforms:** `WINDOWS`, `LINUX`, `MACOS`, `MULTI`, `WEB`, `NETWORK`

### Output Helpers

```python
self.print_status("Info message")     # [*] Info message (blue)
self.print_good("Success message")    # [+] Success message (green)
self.print_error("Error message")     # [-] Error message (red)
self.print_warning("Warning message") # [!] Warning message (orange)
self.print_line("Raw text")           # Raw text
```

### Running External Commands

```python
# Simple command execution
ret, stdout, stderr = self.run_command(["tool", "-arg", value])

# Find tool in extended PATH (includes ~/.local/bin, /opt/tools)
tool_path = find_tool("GetUserSPNs.py")
```

## Configuration Storage

Config files are stored in `~/.uwu-toolkit/`:
- `config.json` - Framework settings
- `globals.json` - Persistent global variables
- `var_history.json` - Variable history for recall
- `command_history` - Readline command history

## Console Commands

**Core:** `help`, `exit`, `clear`, `banner`
**Modules:** `use <path>`, `back`, `info`, `options`, `run`, `check`, `search <term>`, `reload`
**Variables:** `set <var> <val>`, `setg <var> <val>`, `unset`, `unsetg`, `show`, `vars`, `globals`, `history`
**Servers:** `start gosh|php|nc [port]`, `stop <id>`, `listeners`
**AI:** `claude mode`, `claude analyze <path>`, `claude debug <path>`, `claude ask "question"`
**C2:** `sliver start|stop|connect|resume|status`
**Shell:** `shell`, `!<cmd>`

## Color Theme

The toolkit uses a Cyberpunk Neon color palette (true 24-bit RGB):

```python
from core.colors import Colors, Style

# Status styling
Style.success("message")  # Green
Style.error("message")    # Red
Style.warning("message")  # Orange
Style.info("message")     # Blue

# Element styling
Style.module("name")      # Neon pink
Style.varname("VAR")      # Yellow
Style.value("val")        # Green
Style.title("HEADER")     # Dark pink, bold
```

## Resource Files

Resource files (`.rc`) automate command sequences:

```bash
# example.rc
setg DOMAIN CORP.LOCAL
use auxiliary/ad/kerberoast
set RHOSTS 10.10.10.100
run
```

Execute with: `python3 uwu -r example.rc`

## Module Loading

The `ModuleLoader` discovers modules by:
1. Scanning `modules/` recursively for `.py` files
2. Extracting metadata (name, description, tags) via regex parsing without importing
3. Full module loading only when `use <path>` is called
4. Finding the first `ModuleBase` subclass in the file

Module paths follow: `<type>/<subcategory>/<name>` (e.g., `auxiliary/ad/kerberoast`)

## Claude AI Integration

Requires `pip install anthropic` and `setg ANTHROPIC_API_KEY <key>`.

**Interactive mode:** `claude` or `claude mode` - full conversation with session management
**Quick commands:** `claude analyze|debug|ask` - one-shot queries

## Sliver C2 Integration

Interactive client with PTY support allowing backgrounding (`Ctrl+D`) and resuming (`sliver resume`).

Requires Sliver client binary and config files in `~/.sliver-client/`.
