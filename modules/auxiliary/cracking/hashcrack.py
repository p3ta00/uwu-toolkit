"""
Hash Cracking Module
Cracks hashes on host system via SSH using hashcat
"""

import subprocess
import os
import re
from typing import Optional, Tuple, List
from core.module_base import ModuleBase, ModuleType, Platform


class HashCrack(ModuleBase):
    """
    Hash cracking module that uses SSH to crack hashes on host system.
    Reads hashes from Exegol and cracks them using hashcat on the host.
    """

    def __init__(self):
        super().__init__()
        self.name = "hashcrack"
        self.description = "Crack hashes on host system via SSH using hashcat"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["cracking", "hashcat", "password", "ssh"]
        self.references = [
            "https://hashcat.net/wiki/",
            "https://hashcat.net/wiki/doku.php?id=example_hashes"
        ]

        # SSH connection
        self.register_option("SSH_HOST", "SSH host to connect to", default="omarchy")
        self.register_option("SSH_USER", "SSH username", default="")
        self.register_option("SSH_PORT", "SSH port", default=22)

        # Hash options
        self.register_option("HASHFILE", "Path to hash file (in Exegol)", required=True)
        self.register_option("HASHTYPE", "Hashcat hash type (e.g., 1000 for NTLM)", default="")

        # Wordlist and rules
        self.register_option("WORDLIST", "Path to wordlist on remote host", default="$HOME/tools/rockyou.txt")
        self.register_option("RULES", "Path to rules file on host (optional)", default="")

        # Additional options
        self.register_option("EXTRA_ARGS", "Extra hashcat arguments", default="")
        self.register_option("SHOW_ONLY", "Only show cracked hashes (don't crack)", default="no",
                           choices=["yes", "no"])

        # Hash type mappings for common types
        self.hash_types = {
            "MD5": 0,
            "SHA1": 100,
            "SHA256": 1400,
            "SHA512": 1700,
            "NTLM": 1000,
            "NetNTLMv1": 5500,
            "NetNTLMv2": 5600,
            "Kerberos 5 TGS-REP (etype 23)": 13100,
            "Kerberos 5 AS-REP (etype 23)": 18200,
            "bcrypt": 3200,
            "sha512crypt": 1800,
            "md5crypt": 500,
            "MSSQL (2012, 2014)": 1731,
            "MySQL323": 200,
            "MySQL4.1/MySQL5": 300,
            "WPA-PBKDF2-PMKID+EAPOL": 22000,
            "LM": 3000,
            "Domain Cached Credentials 2": 2100,
        }

    def run(self) -> bool:
        hashfile = self.get_option("HASHFILE")
        hashtype = self.get_option("HASHTYPE")
        wordlist = self.get_option("WORDLIST")
        rules = self.get_option("RULES")
        ssh_host = self.get_option("SSH_HOST")
        ssh_user = self.get_option("SSH_USER")
        ssh_port = self.get_option("SSH_PORT")
        show_only = self.get_option("SHOW_ONLY") == "yes"
        extra_args = self.get_option("EXTRA_ARGS")

        # Check if hash file exists
        if not os.path.exists(hashfile):
            self.print_error(f"Hash file not found: {hashfile}")
            return False

        # Read hash file
        with open(hashfile, 'r') as f:
            hashes = f.read().strip()

        if not hashes:
            self.print_error("Hash file is empty")
            return False

        self.print_status(f"Loaded hashes from: {hashfile}")

        # Get first hash for type detection
        first_hash = hashes.split('\n')[0].strip()

        # Auto-detect hash type if not provided
        if not hashtype:
            self.print_status("No hash type specified, attempting to identify...")
            detected_type, detected_name = self._identify_hash(first_hash)

            if detected_type:
                self.print_good(f"Detected hash type: {detected_name} (mode: {detected_type})")
                self.print_status(f"Sample hash: {first_hash[:50]}...")

                # Ask for confirmation
                confirm = input(f"\n[?] Use hash type {detected_type} ({detected_name})? [Y/n]: ").strip().lower()
                if confirm == 'n':
                    hashtype = input("[?] Enter hash type manually: ").strip()
                    if not hashtype:
                        self.print_error("No hash type provided")
                        return False
                else:
                    hashtype = str(detected_type)
            else:
                self.print_error("Could not identify hash type")
                hashtype = input("[?] Enter hash type manually: ").strip()
                if not hashtype:
                    self.print_error("No hash type provided")
                    return False

        # Build SSH command
        ssh_target = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host
        ssh_opts = f"-o StrictHostKeyChecking=accept-new -o BatchMode=no -p {ssh_port}"

        # Create temp file on host with hashes
        import random
        temp_hash_file = f"/tmp/uwu_hashes_{random.randint(10000,99999)}.txt"

        self.print_status(f"Transferring hashes to {ssh_host}...")

        # Clean hashes - remove empty lines, CRLF, and normalize
        clean_lines = []
        for line in hashes.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
            stripped = line.strip()
            if stripped:
                clean_lines.append(stripped)
        clean_hashes = '\n'.join(clean_lines)

        # Use base64 encoding to safely transfer hashes
        import base64
        encoded = base64.b64encode(clean_hashes.encode()).decode()

        # Transfer hash file via SSH using base64 decode
        transfer_cmd = f"ssh {ssh_opts} {ssh_target} 'echo {encoded} | base64 -d > {temp_hash_file}'"
        try:
            proc = subprocess.run(
                transfer_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            if proc.returncode != 0:
                self.print_error(f"Failed to transfer hashes: {proc.stderr}")
                return False
        except subprocess.TimeoutExpired:
            self.print_error("SSH connection timed out")
            return False

        # Build hashcat command
        if show_only:
            hashcat_cmd = f"hashcat -m {hashtype} {temp_hash_file} --show"
        else:
            hashcat_cmd = f"hashcat -m {hashtype} {temp_hash_file} {wordlist}"
            if rules:
                hashcat_cmd += f" -r {rules}"
            if extra_args:
                hashcat_cmd += f" {extra_args}"

        # Run hashcat via SSH
        self.print_status(f"Running hashcat on {ssh_host}...")
        self.print_status(f"Command: {hashcat_cmd}")
        self.print_line()

        full_cmd = f"ssh {ssh_opts} -t {ssh_target} '{hashcat_cmd}; echo; echo \"=== CRACKED ===\"; hashcat -m {hashtype} {temp_hash_file} --show 2>/dev/null; rm -f {temp_hash_file}'"

        try:
            # Run interactively so user can see progress
            result = subprocess.run(
                full_cmd,
                shell=True,
                timeout=None  # No timeout for cracking
            )
            self.print_line()
            return result.returncode == 0
        except KeyboardInterrupt:
            self.print_warning("Interrupted - cleaning up...")
            # Cleanup temp file
            subprocess.run(
                f"ssh {ssh_opts} {ssh_target} 'rm -f {temp_hash_file}'",
                shell=True,
                capture_output=True
            )
            return False

    def _identify_hash(self, hash_str: str) -> Tuple[Optional[int], Optional[str]]:
        """Identify hash type using hashid or pattern matching"""

        # Try hashid first
        try:
            result = subprocess.run(
                ["hashid", "-m", hash_str],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout:
                # Parse hashid output
                for line in result.stdout.split('\n'):
                    if '[Hashcat Mode:' in line:
                        # Extract mode number
                        match = re.search(r'\[Hashcat Mode: (\d+)\]', line)
                        if match:
                            mode = int(match.group(1))
                            # Extract name
                            name = line.split('[')[0].strip().lstrip('[+] ')
                            return mode, name
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback to pattern matching
        return self._pattern_match_hash(hash_str)

    def _pattern_match_hash(self, hash_str: str) -> Tuple[Optional[int], Optional[str]]:
        """Pattern match common hash types"""

        # Check NetNTLM FIRST (before any modifications)
        # Format: user::domain:challenge:NTProofStr:blob
        if '::' in hash_str and hash_str.count(':') >= 5:
            parts = hash_str.split(':')
            # NetNTLMv2: challenge is 16 hex chars, NTProofStr is 32 hex chars
            if len(parts) >= 6 and len(parts[3]) == 16 and len(parts[4]) == 32:
                return 5600, "NetNTLMv2"
            # NetNTLMv1: response is 48 hex chars
            if len(parts) >= 6 and len(parts[5]) == 48:
                return 5500, "NetNTLMv1"
            # Generic NetNTLM detection
            return 5600, "NetNTLMv2"

        # Kerberos (check before other $ formats)
        if '$krb5tgs$' in hash_str:
            return 13100, "Kerberos 5 TGS-REP etype 23"
        if '$krb5asrep$' in hash_str:
            return 18200, "Kerberos 5 AS-REP etype 23"

        # Check for bcrypt/crypt formats
        if hash_str.startswith('$2'):
            return 3200, "bcrypt"
        if hash_str.startswith('$6$'):
            return 1800, "sha512crypt"
        if hash_str.startswith('$5$'):
            return 7400, "sha256crypt"
        if hash_str.startswith('$1$'):
            return 500, "md5crypt"
        if hash_str.startswith('$apr1$'):
            return 1600, "Apache apr1"

        # MSCACHE2 / Domain Cached Credentials 2
        if hash_str.startswith('$DCC2$'):
            return 2100, "Domain Cached Credentials 2"

        # secretsdump format: user:rid:lmhash:nthash
        if ':' in hash_str and hash_str.count(':') == 3:
            parts = hash_str.split(':')
            if len(parts[3]) == 32 and re.match(r'^[a-fA-F0-9]+$', parts[3]):
                return 1000, "NTLM (secretsdump format)"

        # Extract hash if it's in user:hash format (simple)
        clean_hash = hash_str
        if ':' in hash_str and not hash_str.startswith('$'):
            parts = hash_str.split(':')
            # Simple user:hash where hash is 32 hex chars
            if len(parts) == 2 and len(parts[1]) == 32:
                clean_hash = parts[1]

        hash_len = len(clean_hash)

        # By length (hex hashes)
        if re.match(r'^[a-fA-F0-9]+$', clean_hash):
            if hash_len == 32:
                return 1000, "NTLM (or MD5 - mode 0)"
            elif hash_len == 40:
                return 100, "SHA1"
            elif hash_len == 64:
                return 1400, "SHA256"
            elif hash_len == 128:
                return 1700, "SHA512"
            elif hash_len == 16:
                return 3000, "LM"

        return None, None

    def check(self) -> bool:
        """Verify SSH connectivity and hashcat availability"""
        ssh_host = self.get_option("SSH_HOST")
        ssh_user = self.get_option("SSH_USER")
        ssh_port = self.get_option("SSH_PORT")

        ssh_target = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host
        ssh_opts = f"-o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -p {ssh_port}"

        try:
            result = subprocess.run(
                f"ssh {ssh_opts} {ssh_target} 'which hashcat'",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
