"""
UAC Decoder/Encoder - Active Directory UserAccountControl Flag Utility
Decode UAC values to flags or calculate UAC from flags
"""

from core.module_base import ModuleBase, ModuleType, Platform


class UACDecoder(ModuleBase):
    """
    Active Directory UserAccountControl (UAC) Flag Decoder/Encoder
    Converts between UAC decimal values and flag names
    """

    # UAC Flag definitions from Microsoft KB305144
    UAC_FLAGS = {
        "SCRIPT": 1,
        "ACCOUNTDISABLE": 2,
        "HOMEDIR_REQUIRED": 8,
        "LOCKOUT": 16,
        "PASSWD_NOTREQD": 32,
        "PASSWD_CANT_CHANGE": 64,  # Cannot be set via LDAP
        "ENCRYPTED_TEXT_PWD_ALLOWED": 128,
        "TEMP_DUPLICATE_ACCOUNT": 256,
        "NORMAL_ACCOUNT": 512,
        "INTERDOMAIN_TRUST_ACCOUNT": 2048,
        "WORKSTATION_TRUST_ACCOUNT": 4096,
        "SERVER_TRUST_ACCOUNT": 8192,
        "DONT_EXPIRE_PASSWORD": 65536,
        "MNS_LOGON_ACCOUNT": 131072,
        "SMARTCARD_REQUIRED": 262144,
        "TRUSTED_FOR_DELEGATION": 524288,
        "NOT_DELEGATED": 1048576,
        "USE_DES_KEY_ONLY": 2097152,
        "DONT_REQ_PREAUTH": 4194304,
        "PASSWORD_EXPIRED": 8388608,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": 16777216,
        "NO_AUTH_DATA_REQUIRED": 33554432,
        "PARTIAL_SECRETS_ACCOUNT": 67108864,
    }

    # Common UAC combinations
    COMMON_COMBOS = {
        512: "Normal enabled account",
        514: "Normal disabled account",
        544: "Normal enabled, password not required",
        546: "Normal disabled, password not required",
        66048: "Normal enabled, password never expires",
        66050: "Normal disabled, password never expires",
        66080: "Normal enabled, password never expires, password not required",
        262656: "Normal enabled, smart card required (512 + 262144)",
        262658: "Normal disabled, smart card required",
        328192: "Normal enabled, password never expires, smart card required",
        4260352: "Normal enabled, don't require preauth (ASREPRoastable)",
        532480: "Normal enabled, trusted for delegation (unconstrained)",
        590336: "Normal enabled, password never expires, trusted for delegation",
    }

    def __init__(self):
        super().__init__()
        self.name = "uac_decoder"
        self.description = "Decode/encode Active Directory UserAccountControl (UAC) values"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["ad", "uac", "useraccountcontrol", "utility", "decoder"]

        # Register options
        self.register_option("MODE", "Operation mode",
                           default="decode",
                           choices=["decode", "encode", "search", "list"])
        self.register_option("VALUE", "UAC decimal value to decode", default="")
        self.register_option("FLAGS", "Comma-separated flag names to encode", default="")
        self.register_option("SEARCH", "Search for flag by name or value", default="")

    def run(self) -> bool:
        mode = self.get_option("MODE")

        if mode == "decode":
            return self._decode_uac()
        elif mode == "encode":
            return self._encode_uac()
        elif mode == "search":
            return self._search_flags()
        elif mode == "list":
            return self._list_flags()

        return False

    def _decode_uac(self) -> bool:
        """Decode a UAC value into its component flags"""
        value_str = self.get_option("VALUE")
        if not value_str:
            self.print_error("VALUE is required for decode mode")
            self.print_status("Example: set VALUE 262656")
            return False

        try:
            uac_value = int(value_str)
        except ValueError:
            self.print_error(f"Invalid UAC value: {value_str}")
            return False

        self.print_line()
        self.print_good(f"UAC Value: {uac_value} (0x{uac_value:X})")
        self.print_line("=" * 60)

        # Check for common combo
        if uac_value in self.COMMON_COMBOS:
            self.print_warning(f"Common combo: {self.COMMON_COMBOS[uac_value]}")
            self.print_line()

        # Decode flags
        found_flags = []
        remaining = uac_value

        self.print_status("Active Flags:")
        for flag_name, flag_value in sorted(self.UAC_FLAGS.items(), key=lambda x: x[1]):
            if uac_value & flag_value:
                found_flags.append((flag_name, flag_value))
                remaining -= flag_value
                self.print_line(f"  [{flag_value:>8}] {flag_name}")

        self.print_line()

        # Verification
        calculated = sum(f[1] for f in found_flags)
        if calculated == uac_value:
            self.print_good(f"Verification: {' + '.join(str(f[1]) for f in found_flags)} = {calculated}")
        else:
            self.print_warning(f"Unknown bits remain: {remaining}")

        # Security implications
        self.print_line()
        self._print_security_implications(found_flags)

        return True

    def _encode_uac(self) -> bool:
        """Encode flag names into a UAC value"""
        flags_str = self.get_option("FLAGS")
        if not flags_str:
            self.print_error("FLAGS is required for encode mode")
            self.print_status("Example: set FLAGS NORMAL_ACCOUNT,DONT_REQ_PREAUTH")
            return False

        flag_names = [f.strip().upper() for f in flags_str.split(",")]
        total = 0
        valid_flags = []

        self.print_line()
        self.print_status("Encoding flags:")

        for flag_name in flag_names:
            if flag_name in self.UAC_FLAGS:
                value = self.UAC_FLAGS[flag_name]
                valid_flags.append((flag_name, value))
                total += value
                self.print_line(f"  + {flag_name} = {value}")
            else:
                self.print_warning(f"  Unknown flag: {flag_name}")

        self.print_line()
        self.print_line("=" * 60)
        self.print_good(f"Total UAC Value: {total} (0x{total:X})")

        # LDAP filter
        self.print_line()
        self.print_status("LDAP Filters:")
        self.print_line(f"  Exact match: (userAccountControl={total})")
        self.print_line(f"  Has all flags: (userAccountControl:1.2.840.113556.1.4.803:={total})")

        return True

    def _search_flags(self) -> bool:
        """Search for flags by name or value"""
        search = self.get_option("SEARCH")
        if not search:
            self.print_error("SEARCH is required for search mode")
            return False

        self.print_line()
        self.print_status(f"Searching for: {search}")
        self.print_line("=" * 60)

        found = False

        # Try as number first
        try:
            search_val = int(search)
            for flag_name, flag_value in self.UAC_FLAGS.items():
                if flag_value == search_val:
                    self.print_good(f"{flag_name} = {flag_value}")
                    found = True
        except ValueError:
            pass

        # Search by name
        search_upper = search.upper()
        for flag_name, flag_value in sorted(self.UAC_FLAGS.items(), key=lambda x: x[1]):
            if search_upper in flag_name:
                self.print_good(f"{flag_name} = {flag_value}")
                found = True

        if not found:
            self.print_warning("No matching flags found")

        return True

    def _list_flags(self) -> bool:
        """List all UAC flags"""
        self.print_line()
        self.print_good("UserAccountControl (UAC) Flags")
        self.print_line("=" * 70)
        self.print_line(f"{'Flag Name':<40} {'Decimal':>10} {'Hex':>12}")
        self.print_line("-" * 70)

        for flag_name, flag_value in sorted(self.UAC_FLAGS.items(), key=lambda x: x[1]):
            self.print_line(f"{flag_name:<40} {flag_value:>10} {hex(flag_value):>12}")

        self.print_line()
        self.print_status("Common Combinations:")
        self.print_line("-" * 70)
        for value, desc in sorted(self.COMMON_COMBOS.items()):
            self.print_line(f"  {value:>8} - {desc}")

        self.print_line()
        self.print_status("LDAP Matching Rule OIDs:")
        self.print_line("  1.2.840.113556.1.4.803 - Bitwise AND (has all flags)")
        self.print_line("  1.2.840.113556.1.4.804 - Bitwise OR (has any flag)")
        self.print_line()
        self.print_status("Example LDAP queries:")
        self.print_line("  Find disabled: (userAccountControl:1.2.840.113556.1.4.803:=2)")
        self.print_line("  Find ASREPRoastable: (userAccountControl:1.2.840.113556.1.4.803:=4194304)")
        self.print_line("  Find exact UAC: (userAccountControl=262656)")

        return True

    def _print_security_implications(self, flags: list) -> None:
        """Print security implications for identified flags"""
        implications = {
            "DONT_REQ_PREAUTH": "ASREPRoastable - can obtain TGT without pre-authentication",
            "TRUSTED_FOR_DELEGATION": "Unconstrained delegation - can impersonate any user",
            "TRUSTED_TO_AUTH_FOR_DELEGATION": "Constrained delegation - can impersonate to specific services",
            "PASSWD_NOTREQD": "Password not required - account may have blank password",
            "ENCRYPTED_TEXT_PWD_ALLOWED": "Reversible encryption - password stored insecurely",
            "ACCOUNTDISABLE": "Account is disabled",
            "DONT_EXPIRE_PASSWORD": "Password never expires - may be stale",
            "PASSWORD_EXPIRED": "Password has expired",
            "SMARTCARD_REQUIRED": "Smart card required for interactive logon",
            "NOT_DELEGATED": "Account is protected from delegation attacks",
            "USE_DES_KEY_ONLY": "DES-only - weak encryption",
        }

        security_flags = [(f, implications[f[0]]) for f in flags if f[0] in implications]

        if security_flags:
            self.print_status("Security Implications:")
            for flag, implication in security_flags:
                if flag[0] in ["DONT_REQ_PREAUTH", "TRUSTED_FOR_DELEGATION", "PASSWD_NOTREQD",
                              "ENCRYPTED_TEXT_PWD_ALLOWED", "USE_DES_KEY_ONLY"]:
                    self.print_warning(f"  {flag[0]}: {implication}")
                else:
                    self.print_status(f"  {flag[0]}: {implication}")

    def check(self) -> bool:
        return True
