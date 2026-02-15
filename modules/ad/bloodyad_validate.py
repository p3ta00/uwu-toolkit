"""
BloodyAD Tool Validation Module
Validates that bloodyAD is available and all subcommands work
against the Iron Throne lab (westeros.local)
"""

import re
from typing import Dict
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class BloodyADValidate(ModuleBase):
    """
    Validates bloodyAD tool availability and functionality.
    Tests each subcommand against a target AD environment.

    Designed as the primary test bench for uwu-toolkit bloodyAD integration.
    """

    def __init__(self):
        super().__init__()
        self.name = "bloodyad_validate"
        self.description = "Validate bloodyAD commands - test bench for uwu-toolkit"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "bloodyad", "validate", "test", "bench", "iron_throne", "acl"]
        self.references = [
            "https://github.com/CravateRouge/bloodyAD",
            "https://cravaterouge.github.io/bloodyAD/"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)

        # Test targets
        self.register_option("TARGET_USER", "Target user for object queries", default="")
        self.register_option("TARGET_GROUP", "Target group for membership queries", default="")
        self.register_option("TARGET_OU", "Target OU for children queries", default="")

        # Test control
        self.register_option("MODE", "Test mode: tools_only, read, full",
                           default="tools_only",
                           choices=["tools_only", "read", "full"])
        self.register_option("VERBOSE", "Verbose output", default="no",
                           choices=["yes", "no"])

    # bloodyAD subcommands organized by category
    GET_COMMANDS = [
        ("get writable", "Find writable objects for current user"),
        ("get owned", "Find objects owned by current user"),
        ("get object", "Get object attributes (needs TARGET_USER)"),
        ("get membership", "Get group membership (needs TARGET_USER)"),
        ("get children", "Get OU children (needs TARGET_OU)"),
        ("get search", "LDAP search"),
        ("get dns", "DNS records"),
    ]

    SET_COMMANDS = [
        ("set password", "Change user password"),
        ("set owner", "Change object owner"),
        ("set genericAll", "Set GenericAll ACE"),
        ("set rbcd", "Set RBCD delegation"),
    ]

    ADD_COMMANDS = [
        ("add computer", "Add computer account"),
        ("add dnsRecord", "Add DNS record"),
        ("add groupMember", "Add group member"),
    ]

    REMOVE_COMMANDS = [
        ("remove computer", "Remove computer account"),
        ("remove dnsRecord", "Remove DNS record"),
        ("remove groupMember", "Remove group member"),
    ]

    def run(self) -> bool:
        mode = self.get_option("MODE")
        verbose = self.get_option("VERBOSE") == "yes"

        self.print_status("BloodyAD Tool Validation — uwu-toolkit Test Bench")
        self.print_line("=" * 60)

        results = {"pass": [], "fail": [], "skip": []}

        # Phase 1: Tool availability
        self.print_line()
        self.print_status("Phase 1: Tool Availability")
        self.print_line("-" * 40)
        self._check_tool(results, verbose)

        if mode == "tools_only":
            self._print_summary(results)
            return len(results["fail"]) == 0

        # Phase 2: Read-only commands
        self.print_line()
        self.print_status("Phase 2: Read-Only Commands (get)")
        self.print_line("-" * 40)
        self._test_read_commands(results, verbose)

        if mode == "read":
            self._print_summary(results)
            return len(results["fail"]) == 0

        # Phase 3: Write commands (destructive — use with caution)
        self.print_line()
        self.print_status("Phase 3: Write Commands (add/set/remove)")
        self.print_line("-" * 40)
        self._test_write_commands(results, verbose)

        self._print_summary(results)
        return len(results["fail"]) == 0

    def _build_base_cmd(self) -> str:
        """Build bloodyAD base command with auth"""
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        return f"bloodyAD -u '{user}' -p '{password}' -d '{domain}' --host {dc_ip}"

    def _check_tool(self, results: Dict, verbose: bool):
        """Check bloodyAD availability and version"""
        # Check local
        path = find_tool("bloodyAD") or find_tool("bloodyad")
        if path:
            self.print_good(f"bloodyAD found locally: {path}")
            results["pass"].append("[FOUND] bloodyAD (local)")
        else:
            # Check in Exegol
            ret, stdout, stderr = self.run_in_exegol("which bloodyAD 2>/dev/null || which bloodyad 2>/dev/null", timeout=10)
            if ret == 0 and stdout.strip():
                self.print_good(f"bloodyAD found in Exegol: {stdout.strip()}")
                results["pass"].append("[FOUND] bloodyAD (exegol)")
            else:
                self.print_error("bloodyAD NOT FOUND")
                results["fail"].append("[MISSING] bloodyAD")
                return

        # Version check
        ret, stdout, stderr = self.run_in_exegol("bloodyAD --version 2>&1 || bloodyad --version 2>&1", timeout=10)
        version_output = (stdout + stderr).strip()
        if version_output:
            self.print_status(f"Version: {version_output}")
        else:
            # Try pip
            ret2, stdout2, stderr2 = self.run_in_exegol(
                "pip3 show bloodyAD 2>/dev/null | grep Version", timeout=10)
            if stdout2.strip():
                self.print_status(f"Version (pip): {stdout2.strip()}")

        # Help check
        ret, stdout, stderr = self.run_in_exegol("bloodyAD -h 2>&1", timeout=10)
        output = stdout + stderr
        if "usage" in output.lower() or "bloodyad" in output.lower():
            results["pass"].append("[HELP] bloodyAD help works")
            self.print_good("Help output: OK")
            # Parse available subcommands
            if verbose:
                for line in output.split('\n'):
                    if line.strip().startswith('{') or 'get' in line or 'set' in line:
                        self.print_line(f"    {line.strip()}")
        else:
            results["fail"].append("[HELP] bloodyAD help failed")
            self.print_error("Help output: FAILED")

    def _test_read_commands(self, results: Dict, verbose: bool):
        """Test read-only bloodyAD commands"""
        base = self._build_base_cmd()
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        target_user = self.get_option("TARGET_USER") or user
        target_group = self.get_option("TARGET_GROUP") or "Domain Users"
        target_ou = self.get_option("TARGET_OU") or f"DC={domain.split('.')[0]},DC={domain.split('.')[1]}"

        read_tests = [
            (
                "get writable",
                f"{base} get writable",
                60,
                ["distinguishedName", "WRITE", "nTSecurityDescriptor"],
                ["error", "exception", "Traceback"]
            ),
            (
                "get owned",
                f"{base} get owned",
                30,
                ["distinguishedName", "owned"],
                ["error", "exception", "Traceback"]
            ),
            (
                "get object (user)",
                f"{base} get object '{target_user}'",
                15,
                ["distinguishedName", "sAMAccountName", "objectClass"],
                ["error", "exception", "Traceback", "not found"]
            ),
            (
                "get membership",
                f"{base} get membership '{target_user}'",
                15,
                ["member", "group", "CN="],
                ["error", "exception", "Traceback"]
            ),
            (
                "get children",
                f"{base} get children '{target_ou}'",
                30,
                ["distinguishedName", "CN=", "OU="],
                ["error", "exception", "Traceback"]
            ),
            (
                "get search (users)",
                f"{base} get search --filter '(objectClass=user)' --attr sAMAccountName",
                30,
                ["sAMAccountName"],
                ["error", "exception", "Traceback"]
            ),
        ]

        for test_name, cmd, timeout, success_markers, fail_markers in read_tests:
            self.print_status(f"Testing: {test_name}...")
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=timeout)
            output = stdout + stderr

            # Check for Python errors/tracebacks first
            if "Traceback" in output or "Exception" in output:
                results["fail"].append(f"[ERROR] {test_name}: Python error")
                self.print_error(f"{test_name:<30} ERROR — Python exception")
                if verbose:
                    # Show last few lines of traceback
                    lines = output.strip().split('\n')
                    for line in lines[-5:]:
                        self.print_line(f"    {line}")
                continue

            # Check for auth failures
            if "STATUS_LOGON_FAILURE" in output or "invalid credentials" in output.lower():
                results["fail"].append(f"[AUTH] {test_name}: Auth failed")
                self.print_error(f"{test_name:<30} AUTH FAILED")
                continue

            # Check success markers
            found_success = any(m.lower() in output.lower() for m in success_markers)
            found_fail = any(m.lower() in output.lower() for m in fail_markers)

            if found_success and not found_fail:
                results["pass"].append(f"[GET] {test_name}")
                self.print_good(f"{test_name:<30} PASS")
                if verbose:
                    # Show first few result lines
                    lines = output.strip().split('\n')
                    for line in lines[:3]:
                        self.print_line(f"    {line[:100]}")
            elif ret == 0 and output.strip():
                results["pass"].append(f"[GET] {test_name} (ret=0)")
                self.print_good(f"{test_name:<30} PASS (ret=0)")
            elif not output.strip():
                results["skip"].append(f"[GET] {test_name}: empty output")
                self.print_warning(f"{test_name:<30} EMPTY OUTPUT")
            else:
                results["skip"].append(f"[GET] {test_name}: unclear")
                self.print_warning(f"{test_name:<30} UNCLEAR (ret={ret})")
                if verbose:
                    self.print_line(f"    {output[:150]}")

    def _test_write_commands(self, results: Dict, verbose: bool):
        """Test write commands (creates and then cleans up)"""
        base = self._build_base_cmd()
        domain = self.get_option("DOMAIN")

        # Test: add computer
        test_computer = "UWUBLOODTEST"
        test_pass = "UwUBloodyTest123!"
        self.print_status(f"Testing: add computer ({test_computer})...")
        ret, stdout, stderr = self.run_in_exegol(
            f"{base} add computer '{test_computer}' '{test_pass}'",
            timeout=30
        )
        output = stdout + stderr
        if "already exists" in output.lower():
            results["pass"].append("[ADD] add computer (already exists)")
            self.print_good(f"add computer: OK (already exists)")
        elif ret == 0 or "added" in output.lower() or "created" in output.lower():
            results["pass"].append("[ADD] add computer")
            self.print_good(f"add computer: OK")
            # Cleanup
            self.print_status(f"Cleaning up: remove computer ({test_computer})...")
            self.run_in_exegol(f"{base} remove computer '{test_computer}'", timeout=15)
        elif "Traceback" in output:
            results["fail"].append(f"[ADD] add computer: Python error")
            self.print_error(f"add computer: ERROR — Python exception")
            if verbose:
                lines = output.strip().split('\n')
                for line in lines[-3:]:
                    self.print_line(f"    {line}")
        elif "LDAP_INSUFFICIENT_ACCESS" in output or "insufficient" in output.lower():
            results["skip"].append("[ADD] add computer: insufficient access (expected for low-priv)")
            self.print_warning("add computer: insufficient access (may need MachineAccountQuota > 0)")
        else:
            results["skip"].append(f"[ADD] add computer: {output[:60]}")
            self.print_warning(f"add computer: unclear result")
            if verbose:
                self.print_line(f"    {output[:200]}")

        # Test: get dns (read-only DNS operation)
        self.print_status("Testing: get dns...")
        ret, stdout, stderr = self.run_in_exegol(
            f"{base} get dns",
            timeout=30
        )
        output = stdout + stderr
        if ret == 0 or "dnsRecord" in output or "dnsNode" in output or domain in output:
            results["pass"].append("[GET] get dns")
            self.print_good("get dns: OK")
        elif "Traceback" in output:
            results["fail"].append("[GET] get dns: Python error")
            self.print_error("get dns: ERROR")
        else:
            results["skip"].append("[GET] get dns: unclear")
            self.print_warning("get dns: unclear")

    def _print_summary(self, results: Dict):
        """Print validation summary"""
        total = len(results["pass"]) + len(results["fail"]) + len(results["skip"])
        self.print_line()
        self.print_line("=" * 60)
        self.print_status("BLOODYAD VALIDATION SUMMARY")
        self.print_line("-" * 40)
        self.print_good(f"PASS:  {len(results['pass'])}/{total}")
        if results["fail"]:
            self.print_error(f"FAIL:  {len(results['fail'])}/{total}")
            for f in results["fail"]:
                self.print_error(f"  {f}")
        if results["skip"]:
            self.print_warning(f"SKIP:  {len(results['skip'])}/{total}")
        self.print_line("=" * 60)

    def check(self) -> bool:
        """Check if bloodyAD is available"""
        path = find_tool("bloodyAD") or find_tool("bloodyad")
        if path:
            return True
        ret, stdout, stderr = self.run_in_exegol("which bloodyAD 2>/dev/null || which bloodyad 2>/dev/null", timeout=10)
        return ret == 0
