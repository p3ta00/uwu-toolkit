"""
Cisco Type 5 Password Hash Cracker
Cracks Cisco Type 5 (MD5-based) password hashes using hashcat
"""

from core.module_base import ModuleBase, ModuleType, Platform, find_tool
import os


class CiscoType5Crack(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "cisco_type5_crack"
        self.description = "Crack Cisco Type 5 password hashes (MD5-based)"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.NETWORK
        self.tags = ["cisco", "password", "crack", "hashcat", "md5"]
        self.references = [
            "https://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/107614-64.html",
            "https://hashcat.net/wiki/doku.php?id=example_hashes"
        ]

        # Options
        self.register_option("HASH", "Cisco Type 5 hash to crack (format: $1$SALT$HASH)", required=True)
        self.register_option("WORDLIST", "Wordlist for cracking", default="/usr/share/wordlists/rockyou.txt")
        self.register_option("HASHFILE", "File containing hash (alternative to HASH option)", default=None)
        self.register_option("OUTPUT", "Output file for cracked passwords", default="/tmp/cisco_cracked.txt")
        self.register_option("SHOW", "Show previously cracked passwords", default=False)

    def check(self) -> bool:
        """Check if hashcat is available"""
        hashcat = find_tool("hashcat")
        if not hashcat:
            self.print_error("hashcat not found in PATH")
            self.print_error("Install with: apt install hashcat")
            return False
        return True

    def run(self) -> bool:
        """Execute the hash cracking"""
        if not self.check():
            return False

        hash_value = self.get_option("HASH")
        hash_file = self.get_option("HASHFILE")
        wordlist = self.get_option("WORDLIST")
        output = self.get_option("OUTPUT")
        show_mode = self.get_option("SHOW")

        # Determine hash source
        temp_hash_file = None
        if hash_file and os.path.exists(hash_file):
            target_hash_file = hash_file
            self.print_status(f"Using hash file: {hash_file}")
        elif hash_value:
            # Create temporary hash file
            temp_hash_file = "/tmp/cisco_hash.txt"
            with open(temp_hash_file, 'w') as f:
                f.write(hash_value.strip() + "\n")
            target_hash_file = temp_hash_file
            self.print_status(f"Hash: {hash_value}")
        else:
            self.print_error("Must specify HASH or HASHFILE")
            return False

        # Show mode - display previously cracked
        if show_mode:
            self.print_status("Showing previously cracked hashes...")
            ret, stdout, stderr = self.run_command(
                ["hashcat", "-m", "500", target_hash_file, "--show"],
                timeout=10
            )
            if ret == 0 and stdout.strip():
                self.print_good("Previously cracked:")
                for line in stdout.strip().split('\n'):
                    if ':' in line:
                        hash_part, password = line.split(':', 1)
                        self.print_good(f"  Password: {password}")
            else:
                self.print_warning("No previously cracked hashes found")

            if temp_hash_file and os.path.exists(temp_hash_file):
                os.remove(temp_hash_file)
            return True

        # Validate wordlist
        if not os.path.exists(wordlist):
            self.print_error(f"Wordlist not found: {wordlist}")
            if temp_hash_file and os.path.exists(temp_hash_file):
                os.remove(temp_hash_file)
            return False

        self.print_status(f"Wordlist: {wordlist}")
        self.print_status(f"Hashcat mode: 500 (md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5))")
        self.print_line()

        # Run hashcat
        hashcat_cmd = [
            "hashcat",
            "-m", "500",  # Cisco Type 5 / md5crypt
            "-a", "0",     # Straight attack mode
            target_hash_file,
            wordlist,
            "-o", output,
            "--force"      # Force run even if not optimal
        ]

        self.print_status("Starting hashcat...")
        self.print_status(f"Command: {' '.join(hashcat_cmd)}")
        self.print_line()

        ret, stdout, stderr = self.run_command(hashcat_cmd, timeout=300)

        # Clean up temp file
        if temp_hash_file and os.path.exists(temp_hash_file):
            os.remove(temp_hash_file)

        # Check results
        if ret == 0 or "Cracked" in stdout or "Cracked" in stderr:
            self.print_good("Hashcat completed!")

            # Try to extract cracked password
            ret_show, stdout_show, _ = self.run_command(
                ["hashcat", "-m", "500", target_hash_file, "--show"],
                timeout=10
            )

            if ret_show == 0 and stdout_show.strip():
                self.print_line()
                self.print_good("=" * 60)
                self.print_good("CRACKED PASSWORD(S):")
                self.print_good("=" * 60)
                for line in stdout_show.strip().split('\n'):
                    if ':' in line:
                        hash_part, password = line.split(':', 1)
                        self.print_good(f"Hash: {hash_part}")
                        self.print_good(f"Password: {password}")
                        self.print_line()

                # Save to output file
                if output:
                    with open(output, 'w') as f:
                        f.write(stdout_show)
                    self.print_good(f"Results saved to: {output}")

                return True

            # Check output file
            if os.path.exists(output):
                with open(output, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.print_good("Cracked password found in output file!")
                        self.print_good(f"Check: {output}")
                        return True

        # Not cracked
        if "Exhausted" in stdout or "Exhausted" in stderr:
            self.print_warning("Wordlist exhausted - password not found")
            self.print_warning("Try a different wordlist or add rules")
        else:
            self.print_error("Hashcat failed or password not cracked")
            if stderr:
                self.print_error(f"Error: {stderr[:200]}")

        return False


# Module instantiation
module = CiscoType5Crack()
