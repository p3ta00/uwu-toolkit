"""
UwU Toolkit - Tmux Status Bar Integration
Manages status files for dynamic tmux status bar updates
"""

import os
import json
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

# Status file location
STATUS_DIR = Path("/tmp/uwu-status")
LISTENERS_FILE = STATUS_DIR / "listeners.json"
SERVERS_FILE = STATUS_DIR / "servers.json"


def ensure_status_dir():
    """Ensure status directory exists"""
    STATUS_DIR.mkdir(parents=True, exist_ok=True)


def update_listener(port: int, status: str = "listening", shell_count: int = 0):
    """
    Update listener status
    status: 'listening' (red/waiting), 'connected' (green/shell received), 'stopped'
    """
    ensure_status_dir()

    try:
        if LISTENERS_FILE.exists():
            data = json.loads(LISTENERS_FILE.read_text())
        else:
            data = {}
    except:
        data = {}

    if status == "stopped":
        data.pop(str(port), None)
    else:
        data[str(port)] = {
            "status": status,
            "shells": shell_count,
            "updated": datetime.now().isoformat()
        }

    LISTENERS_FILE.write_text(json.dumps(data))


def update_server(port: int, server_type: str = "http", status: str = "running"):
    """
    Update HTTP server status
    status: 'running', 'stopped'
    """
    ensure_status_dir()

    try:
        if SERVERS_FILE.exists():
            data = json.loads(SERVERS_FILE.read_text())
        else:
            data = {}
    except:
        data = {}

    if status == "stopped":
        data.pop(str(port), None)
    else:
        data[str(port)] = {
            "type": server_type,
            "status": status,
            "updated": datetime.now().isoformat()
        }

    SERVERS_FILE.write_text(json.dumps(data))


def get_listeners() -> Dict:
    """Get all listener statuses"""
    try:
        if LISTENERS_FILE.exists():
            return json.loads(LISTENERS_FILE.read_text())
    except:
        pass
    return {}


def get_servers() -> Dict:
    """Get all server statuses"""
    try:
        if SERVERS_FILE.exists():
            return json.loads(SERVERS_FILE.read_text())
    except:
        pass
    return {}


def get_tmux_status_string() -> str:
    """
    Generate status string for tmux status bar
    Returns formatted string with colors
    """
    parts = []

    # Check servers
    servers = get_servers()
    for port, info in servers.items():
        stype = info.get("type", "HTTP").upper()
        # Green for running servers
        parts.append(f"#[fg=#00ff00]{stype}={port}#[fg=default]")

    # Check listeners
    listeners = get_listeners()
    for port, info in listeners.items():
        status = info.get("status", "listening")
        shells = info.get("shells", 0)

        if status == "connected" or shells > 0:
            # Green - shell received!
            parts.append(f"#[fg=#00ff00,bold]SHELL={port}({shells})#[fg=default,nobold]")
        else:
            # Red - waiting for connection
            parts.append(f"#[fg=#ff0000]LISTEN={port}#[fg=default]")

    if parts:
        return " #[fg=#ff00ff]|#[fg=default] " + " ".join(parts)
    return ""


def clear_all():
    """Clear all status files"""
    try:
        if LISTENERS_FILE.exists():
            LISTENERS_FILE.unlink()
        if SERVERS_FILE.exists():
            SERVERS_FILE.unlink()
    except:
        pass


# Script entry point for tmux to call
if __name__ == "__main__":
    print(get_tmux_status_string())
