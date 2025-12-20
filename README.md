# UwU Toolkit

A modular penetration testing framework designed for Active Directory and network assessments. Built for use with Exegol, Kali, and similar security-focused environments.

## Features

- **Modular Architecture**: Easily extensible module system for enumeration, exploitation, and post-exploitation
- **Session Management**: Background shells via tmux with interactive reattachment
- **Global Variables**: Persistent target configuration across modules
- **Integrated Pivoting**: Built-in Ligolo-ng integration for network pivoting
- **Payload Generation**: Sliver C2 integration and custom payload builders
- **Real-time Dashboard**: HTTP request monitoring and loot organization

## Installation

```bash
git clone https://github.com/p3ta00/uwu-toolkit.git
cd uwu-toolkit
./setup.sh
```

The setup script will:
- Check and install required dependencies
- Install Python packages (prompt_toolkit, rich, requests, pyyaml, donut-shellcode)
- Create symlinks for `uwu` and `uwu-dashboard` commands
- Set up shell integration

## Quick Start

```bash
# Start the toolkit
uwu

# Set global target
setg RHOSTS 10.10.10.10
setg DOMAIN corp.local

# Search for modules
search smb
search ad

# Use a module
use enumeration/smb_enum
run

# Start a listener
start nc 4444

# Manage sessions
sessions
interact <session-name>
```

## Module Categories

| Category | Description |
|----------|-------------|
| `enumeration/` | Network and service enumeration (SMB, DNS, FTP, NFS, web fuzzing) |
| `auxiliary/` | AD attacks (Evil-WinRM, BloodHound, Kerberoasting, DCSync) |
| `exploits/` | Exploitation modules |
| `payloads/` | Payload generation (Sliver, shellcode, PowerShell) |
| `post/` | Post-exploitation (privilege escalation, credential harvesting) |

## Key Commands

| Command | Description |
|---------|-------------|
| `setg <VAR> <value>` | Set global variable |
| `sessions` | List active tmux sessions |
| `interact <name>` | Attach to a backgrounded session |
| `ligolo` | Enter Ligolo pivoting mode |
| `potatoes download` | Download privilege escalation tools |
| `sliver` | Enter Sliver C2 integration mode |
| `start nc <port>` | Quick netcat listener |
| `start http <port>` | Quick HTTP server |

## Session Management

Sessions run in tmux and can be backgrounded:
- `Ctrl+b d` or `Ctrl+b x`: Detach (background) the session
- `sessions`: List all active sessions
- `interact <name>`: Reattach to a session
- `kill <name>`: Terminate a session

## Dashboard

The `uwu-dashboard` provides real-time monitoring:
- HTTP request logging from file servers
- Loot organization by target
- Session status overview

```bash
uwu-dashboard
```

## Dependencies

### Required
- Python 3.8+
- tmux
- nmap
- netcat/socat

### Recommended Tools
- NetExec / CrackMapExec
- Evil-WinRM
- Impacket suite
- BloodHound.py
- Ligolo-ng
- Sliver C2
- Donut (shellcode generator)

## Directory Structure

```
uwu-toolkit/
├── core/           # Framework core (console, module base, utilities)
├── modules/        # Enumeration, exploitation, and post-ex modules
├── scripts/        # Helper scripts
├── data/           # Static data files
├── loot/           # Engagement loot (gitignored)
├── logs/           # Session logs (gitignored)
└── reports/        # Generated reports (gitignored)
```

## Configuration

Global variables are stored in `~/.uwu-toolkit/globals.json` and persist across sessions.

Common variables:
- `RHOSTS`: Target IP/hostname
- `DOMAIN`: Active Directory domain
- `USER`: Username for authentication
- `PASS`: Password
- `HASH`: NTLM hash for pass-the-hash
- `LHOST`: Local IP for reverse connections
- `LPORT`: Local port for listeners

## License

This tool is intended for authorized security testing only. Use responsibly.
