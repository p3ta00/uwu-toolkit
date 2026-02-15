"""Shared helpers for all MCP tool modules."""

import json
import os
import shlex
import shutil
import subprocess
import time
import logging

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120
LONG_TIMEOUT = 300
UWU_ROOT = os.environ.get("UWU_ROOT", "/opt/my-resources/tools/uwu-toolkit")

# Extended PATH for Exegol tool discovery
EXTENDED_PATH = ":".join([
    "/opt/tools/impacket-og/venv/bin",
    "/opt/tools/Certipy/venv/bin",
    "/root/.local/share/pipx/venvs/bloodyad/bin",
    "/root/.local/bin",
    os.path.expanduser("~/.local/bin"),
    "/opt/tools/bin",
    "/opt/tools",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
])

# Faketime clock sync state
_faketime_cache = {
    "dc_ip": None,
    "faketime_str": None,
    "synced_at": 0,
    "ttl": 300,  # Re-sync every 5 minutes
}

FAKETIME_LIB = "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"


def _get_dc_time_via_smb(dc_ip: str) -> str:
    """Get DC time via SMB (net time), returns time string or raises."""
    r = subprocess.run(
        ["net", "time", "-S", dc_ip],
        capture_output=True, text=True, timeout=10
    )
    # Output like: "Sat Feb 14 14:36:45 2026"
    time_str = r.stdout.strip()
    if not time_str or r.returncode != 0:
        raise RuntimeError(f"net time failed: {r.stderr.strip()}")
    return time_str


def _get_dc_time_via_rdate(dc_ip: str) -> str:
    """Get DC time via rdate (NTP or RFC 868), returns time string or raises."""
    for flag in ["-n", ""]:
        args = ["rdate", dc_ip, "-p"]
        if flag:
            args.insert(1, flag)
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    raise RuntimeError("rdate failed on all protocols")


def sync_clock(dc_ip: str) -> dict:
    """Sync container clock to a DC using faketime.

    Tries SMB (net time) first, then rdate NTP/RFC868.
    Caches the result so all _run_cmd calls auto-inject faketime.
    """
    try:
        # Try SMB first (most reliable, works on all DCs)
        dc_time_raw = None
        method = None
        try:
            dc_time_raw = _get_dc_time_via_smb(dc_ip)
            method = "smb"
        except Exception:
            try:
                dc_time_raw = _get_dc_time_via_rdate(dc_ip)
                method = "rdate"
            except Exception as e:
                return {"status": "error", "error": f"Could not get DC time: {e}"}

        # Parse to faketime format: "YYYY-MM-DD HH:MM:SS"
        r2 = subprocess.run(
            ["date", "-d", dc_time_raw, "+%Y-%m-%d %H:%M:%S"],
            capture_output=True, text=True
        )
        faketime_str = r2.stdout.strip()
        if not faketime_str:
            return {"status": "error", "error": f"Could not parse DC time: {dc_time_raw}"}

        _faketime_cache["dc_ip"] = dc_ip
        _faketime_cache["faketime_str"] = faketime_str
        _faketime_cache["synced_at"] = time.time()

        logger.info(f"Clock synced to DC {dc_ip} via {method}: {faketime_str}")
        return {
            "status": "success",
            "dc_ip": dc_ip,
            "dc_time": dc_time_raw,
            "faketime": faketime_str,
            "method": method,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _get_faketime_env() -> dict:
    """Return faketime env vars if clock sync is active, else empty dict."""
    if not _faketime_cache["faketime_str"]:
        return {}
    if not os.path.isfile(FAKETIME_LIB):
        return {}
    # Check TTL — re-sync if stale
    elapsed = time.time() - _faketime_cache["synced_at"]
    if elapsed > _faketime_cache["ttl"] and _faketime_cache["dc_ip"]:
        sync_clock(_faketime_cache["dc_ip"])
    return {
        "LD_PRELOAD": FAKETIME_LIB,
        "FAKETIME": _faketime_cache["faketime_str"],
    }


def _run_cmd(cmd: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute a shell command and return structured result.

    Automatically applies faketime if clock sync is active.
    """
    try:
        env = {**os.environ, "PATH": EXTENDED_PATH}
        env.update(_get_faketime_env())
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
            env=env
        )
        return {
            "status": "success" if result.returncode == 0 else "error",
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _format_response(data=None, error=None, success=None, message=None) -> str:
    """Format response as JSON string for MCP."""
    response = {}
    if error:
        response["status"] = "error"
        response["error"] = str(error)
    elif success is True:
        response["status"] = "success"
        response["message"] = message or "Operation successful"
        if data is not None:
            response["data"] = data
    elif success is False:
        response["status"] = "failure"
        response["error"] = message or "Operation failed"
    elif data is not None:
        response["status"] = "success"
        response["data"] = data
    else:
        response["status"] = "no_content"
        response["message"] = message or "No output"

    try:
        return json.dumps(response, default=str, indent=2)
    except TypeError as e:
        return json.dumps({"status": "error", "error": f"Serialization error: {e}"})


def _build_impacket_cmd(
    tool: str, target: str, domain: str = "", username: str = "",
    password: str = "", hashes: str = "", dc_ip: str = "",
) -> str:
    """Build standard Impacket command string."""
    if domain and username:
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    elif username:
        identity = shlex.quote(username)
    else:
        identity = "''"
    if password:
        identity += f":{shlex.quote(password)}"
    cmd = f"{tool} {identity}@{shlex.quote(target)}"
    if hashes:
        cmd += f" -hashes {shlex.quote(hashes)}"
    if dc_ip:
        cmd += f" -dc-ip {shlex.quote(dc_ip)}"
    return cmd


def _find_certipy_bin() -> str:
    """Find certipy binary in known locations."""
    search_paths = [
        "/opt/tools/Certipy/venv/bin/certipy",
        "/root/.local/share/pipx/venvs/certipy/bin/certipy",
        "/root/.local/share/pipx/venvs/netexec/bin/certipy",
        "/root/.local/share/pipx/venvs/certsync/bin/certipy",
        "/root/.local/bin/certipy",
    ]
    for path in search_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    found = shutil.which("certipy")
    return found or "certipy"
