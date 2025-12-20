#!/bin/bash
# UwU Toolkit - Tmux Status Bar Script
# Uses Python for reliable JSON parsing

# Try to find Python
PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)

if [ -z "$PYTHON" ]; then
    exit 0
fi

$PYTHON << 'PYEOF'
import json
from pathlib import Path

STATUS_DIR = Path("/tmp/uwu-status")
LISTENERS_FILE = STATUS_DIR / "listeners.json"
SERVERS_FILE = STATUS_DIR / "servers.json"

parts = []

# Check servers
try:
    if SERVERS_FILE.exists():
        data = json.loads(SERVERS_FILE.read_text())
        for port, info in data.items():
            stype = info.get("type", "HTTP").upper()
            if info.get("status") == "running":
                # Green for running servers
                parts.append(f"#[fg=#00ff00]{stype}={port}#[fg=default]")
except:
    pass

# Check listeners
try:
    if LISTENERS_FILE.exists():
        data = json.loads(LISTENERS_FILE.read_text())
        for port, info in data.items():
            status = info.get("status", "listening")
            shells = info.get("shells", 0)

            if status == "connected" or shells > 0:
                # Green - shell received!
                parts.append(f"#[fg=#00ff00,bold]SHELL={port}#[fg=default,nobold]")
            else:
                # Red - waiting for connection
                parts.append(f"#[fg=#ff6666]LISTEN={port}#[fg=default]")
except:
    pass

if parts:
    print("#[fg=#ff00ff]|#[fg=default] " + " ".join(parts) + " ")
PYEOF
