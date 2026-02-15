"""
SID Lookup Module - Convert between usernames and SIDs
Uses impacket's lookupsid.py or rpcclient for lookups
"""

import subprocess
import shutil
import re
from typing import Optional, List, Tuple
from core.module_base import ModuleBase, ModuleType, Platform


class SIDLookup(ModuleBase):
    """
    SID Lookup module for Active Directory
    - Convert username to SID
    - Convert SID to username
    - Enumerate domain SIDs (bruteforce RIDs)
    """

    def __init__(self):
        super().__init__()
        self.name = "sid_lookup"
        self.description = "Convert between usernames and SIDs using RPC/LDAP"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "sid", "lookup", "enumeration", "rpc"]

        self.register_option("RHOSTS", "Target DC or domain-joined host", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)
        self.register_option("MODE", "Lookup mode",
                           default="name_to_sid",
                           choices=["name_to_sid", "sid_to_name", "enum_rids"])
        self.register_option("TARGET_USER", "Username to lookup (for name_to_sid)", default="")
        self.register_option("TARGET_SID", "SID to lookup (for sid_to_name)", default="")
        self.register_option("MAX_RID", "Maximum RID to enumerate (for enum_rids)", default="5000")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        mode = self.get_option("MODE")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  SID Lookup")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Mode: {mode}")
        self.print_line()

        if mode == "name_to_sid":
            return self._name_to_sid(target, domain, user, password)
        elif mode == "sid_to_name":
            return self._sid_to_name(target, domain, user, password)
        elif mode == "enum_rids":
            return self._enum_rids(target, domain, user, password)

        return False

    def _name_to_sid(self, target: str, domain: str, user: str, password: str) -> bool:
        """Convert username to SID using rpcclient or lookupsid"""
        target_user = self.get_option("TARGET_USER")
        if not target_user:
            self.print_error("TARGET_USER is required for name_to_sid mode")
            return False

        self.print_status(f"Looking up SID for: {target_user}")

        # Try rpcclient first (more reliable for single lookups)
        if shutil.which("rpcclient"):
            result = self._rpcclient_lookup(target, domain, user, password, target_user)
            if result:
                return True

        # Fallback to lookupsid.py with enumeration
        if shutil.which("lookupsid.py"):
            result = self._lookupsid_search(target, domain, user, password, target_user)
            if result:
                return True

        # Try NetExec RID cycling
        result = self._netexec_rid_brute(target, domain, user, password, target_user)
        if result:
            return True

        self.print_error("Could not resolve SID - all methods failed")
        return False

    def _sid_to_name(self, target: str, domain: str, user: str, password: str) -> bool:
        """Convert SID to username"""
        target_sid = self.get_option("TARGET_SID")
        if not target_sid:
            self.print_error("TARGET_SID is required for sid_to_name mode")
            return False

        self.print_status(f"Looking up name for SID: {target_sid}")

        # Extract RID from SID
        rid_match = re.search(r'-(\d+)$', target_sid)
        if not rid_match:
            self.print_error("Invalid SID format")
            return False

        rid = rid_match.group(1)

        # Try lookupsid.py
        if shutil.which("lookupsid.py"):
            result = self._lookupsid_single(target, domain, user, password, rid)
            if result:
                return True

        # Try rpcclient
        if shutil.which("rpcclient"):
            result = self._rpcclient_sid_lookup(target, domain, user, password, target_sid)
            if result:
                return True

        self.print_error("Could not resolve username - all methods failed")
        return False

    def _enum_rids(self, target: str, domain: str, user: str, password: str) -> bool:
        """Enumerate domain users by RID cycling"""
        max_rid = int(self.get_option("MAX_RID"))

        self.print_status(f"Enumerating RIDs 500-{max_rid}...")

        if shutil.which("lookupsid.py"):
            creds = f"{domain}/{user}:{password}"
            cmd = ["lookupsid.py", creds + f"@{target}", str(max_rid)]

            self.print_status(f"Command: lookupsid.py {domain}/{user}:***@{target} {max_rid}")

            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, bufsize=1)

                for line in iter(process.stdout.readline, ''):
                    line = line.rstrip()
                    if line and 'SidTypeUser' in line:
                        self.print_good(line)
                    elif line and 'SidTypeGroup' in line:
                        self.print_status(line)

                process.wait()
                return process.returncode == 0

            except Exception as e:
                self.print_error(f"Error: {e}")

        return False

    def _rpcclient_lookup(self, target: str, domain: str, user: str, password: str,
                          target_user: str) -> bool:
        """Use rpcclient to lookup username to SID"""
        cmd = [
            "rpcclient", "-U", f"{domain}/{user}%{password}", target,
            "-c", f"lookupnames {target_user}"
        ]

        self.print_status(f"Using rpcclient lookupnames...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and result.stdout:
                # Parse: username S-1-5-21-xxx-xxx-xxx-xxxx (SidType)
                match = re.search(r'(S-1-5-21-[\d-]+)', result.stdout)
                if match:
                    sid = match.group(1)
                    self.print_line()
                    self.print_good(f"User: {target_user}")
                    self.print_good(f"SID:  {sid}")
                    return True

            if result.stderr:
                self.print_warning(f"rpcclient: {result.stderr.strip()}")

        except subprocess.TimeoutExpired:
            self.print_warning("rpcclient timed out")
        except Exception as e:
            self.print_warning(f"rpcclient error: {e}")

        return False

    def _rpcclient_sid_lookup(self, target: str, domain: str, user: str, password: str,
                              target_sid: str) -> bool:
        """Use rpcclient to lookup SID to username"""
        cmd = [
            "rpcclient", "-U", f"{domain}/{user}%{password}", target,
            "-c", f"lookupsids {target_sid}"
        ]

        self.print_status(f"Using rpcclient lookupsids...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and result.stdout:
                # Parse output for username
                self.print_line()
                for line in result.stdout.split('\n'):
                    if target_sid in line:
                        self.print_good(line)
                        # Extract just the username
                        match = re.search(r'\\([^\s\(]+)', line)
                        if match:
                            self.print_good(f"Username: {match.group(1)}")
                return True

        except Exception as e:
            self.print_warning(f"rpcclient error: {e}")

        return False

    def _lookupsid_search(self, target: str, domain: str, user: str, password: str,
                          target_user: str) -> bool:
        """Use lookupsid.py to enumerate and find specific user"""
        creds = f"{domain}/{user}:{password}"
        cmd = ["lookupsid.py", creds + f"@{target}", "5000"]

        self.print_status(f"Using lookupsid.py to enumerate (searching for {target_user})...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.stdout:
                for line in result.stdout.split('\n'):
                    if target_user.lower() in line.lower():
                        self.print_line()
                        self.print_good(line)
                        # Extract SID
                        match = re.search(r'(S-1-5-21-[\d-]+)', line)
                        if match:
                            self.print_good(f"SID: {match.group(1)}")
                        return True

            self.print_warning(f"User {target_user} not found in RID enumeration")

        except subprocess.TimeoutExpired:
            self.print_warning("lookupsid.py timed out")
        except Exception as e:
            self.print_warning(f"lookupsid.py error: {e}")

        return False

    def _lookupsid_single(self, target: str, domain: str, user: str, password: str,
                          rid: str) -> bool:
        """Use lookupsid.py to lookup a single RID"""
        creds = f"{domain}/{user}:{password}"
        cmd = ["lookupsid.py", creds + f"@{target}", rid]

        self.print_status(f"Using lookupsid.py for RID {rid}...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.stdout:
                for line in result.stdout.split('\n'):
                    if rid in line:
                        self.print_line()
                        self.print_good(line)
                        return True

        except Exception as e:
            self.print_warning(f"lookupsid.py error: {e}")

        return False

    def _netexec_rid_brute(self, target: str, domain: str, user: str, password: str,
                           target_user: str) -> bool:
        """Use NetExec RID bruteforce to find user"""
        netexec = shutil.which("netexec") or shutil.which("nxc") or "/root/.local/bin/NetExec"

        cmd = [netexec, "smb", target, "-u", user, "-p", password, "-d", domain, "--rid-brute"]

        self.print_status(f"Using NetExec RID brute (searching for {target_user})...")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.stdout:
                for line in result.stdout.split('\n'):
                    if target_user.lower() in line.lower():
                        self.print_line()
                        self.print_good(line)
                        # Extract SID from NetExec output
                        match = re.search(r'SidTypeUser.*?(\d+):', line)
                        if match:
                            rid = match.group(1)
                            self.print_status(f"RID: {rid}")
                        return True

        except subprocess.TimeoutExpired:
            self.print_warning("NetExec timed out")
        except Exception as e:
            self.print_warning(f"NetExec error: {e}")

        return False

    def check(self) -> bool:
        """Check if required tools are available"""
        tools = ["rpcclient", "lookupsid.py"]
        found = any(shutil.which(t) for t in tools)
        if not found:
            self.print_warning("Neither rpcclient nor lookupsid.py found")
        return found
