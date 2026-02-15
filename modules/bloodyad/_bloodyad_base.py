"""
BloodyAD Module Base Class and Tool Registry for UwU Toolkit

Provides a shared base class for all bloodyAD tool wrappers.
Handles connection string building, auth mode detection, and execution
via local tools or Exegol container fallback.
"""

import shlex
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


# =============================================================================
# Tool Registry - All bloodyAD functions with metadata
# =============================================================================

BLOODY_TOOLS = {
    # -------------------------------------------------------------------------
    # ACL Abuse
    # -------------------------------------------------------------------------
    "genericall": {
        "command": ["add", "genericAll"],
        "description": "Grant full control (GenericAll) on target to trustee",
        "category_tag": "acl_abuse",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object (sAMAccountName)", "required": True},
            {"name": "TRUSTEE", "desc": "Principal to grant GenericAll to", "required": True},
        ],
        "positional": ["TARGET", "TRUSTEE"],
        "reversible": "remove_genericall",
    },
    "writedacl": {
        "command": ["add", "genericAll"],
        "description": "WriteDACL abuse - grant GenericAll on target to trustee",
        "category_tag": "acl_abuse",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object to modify DACL on", "required": True},
            {"name": "TRUSTEE", "desc": "Principal to grant GenericAll to", "required": True},
        ],
        "positional": ["TARGET", "TRUSTEE"],
        "reversible": "remove_genericall",
    },
    "remove_genericall": {
        "command": ["remove", "genericAll"],
        "description": "Remove full control (GenericAll) from trustee on target",
        "category_tag": "acl_abuse",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object (sAMAccountName)", "required": True},
            {"name": "TRUSTEE", "desc": "Principal to remove GenericAll from", "required": True},
        ],
        "positional": ["TARGET", "TRUSTEE"],
    },
    "setowner": {
        "command": ["set", "owner"],
        "description": "Change object ownership (WriteOwner abuse)",
        "category_tag": "acl_abuse",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object to take ownership of", "required": True},
            {"name": "NEW_OWNER", "desc": "New owner (sAMAccountName)", "required": True},
        ],
        "positional": ["TARGET", "NEW_OWNER"],
    },
    "dcsync": {
        "command": ["add", "dcsync"],
        "description": "Add DCSync (replication) rights on domain for trustee",
        "category_tag": "acl_abuse",
        "extra_options": [
            {"name": "TRUSTEE", "desc": "Principal to grant DCSync to", "required": True},
        ],
        "positional": ["TRUSTEE"],
    },
    "remove_dcsync": {
        "command": ["remove", "dcsync"],
        "description": "Remove DCSync rights for trustee",
        "category_tag": "acl_abuse",
        "extra_options": [
            {"name": "TRUSTEE", "desc": "Principal to remove DCSync from", "required": True},
        ],
        "positional": ["TRUSTEE"],
    },
    # -------------------------------------------------------------------------
    # Group Operations
    # -------------------------------------------------------------------------
    "addmember": {
        "command": ["add", "groupMember"],
        "description": "Add member to group",
        "category_tag": "group",
        "extra_options": [
            {"name": "GROUP", "desc": "Target group (sAMAccountName)", "required": True},
            {"name": "MEMBER", "desc": "Member to add (sAMAccountName)", "required": True},
        ],
        "positional": ["GROUP", "MEMBER"],
    },
    "removemember": {
        "command": ["remove", "groupMember"],
        "description": "Remove member from group",
        "category_tag": "group",
        "extra_options": [
            {"name": "GROUP", "desc": "Target group (sAMAccountName)", "required": True},
            {"name": "MEMBER", "desc": "Member to remove (sAMAccountName)", "required": True},
        ],
        "positional": ["GROUP", "MEMBER"],
    },
    # -------------------------------------------------------------------------
    # Credential Abuse
    # -------------------------------------------------------------------------
    "setpassword": {
        "command": ["set", "password"],
        "description": "Reset user/computer password (ForceChangePassword abuse)",
        "category_tag": "credential",
        "extra_options": [
            {"name": "TARGET", "desc": "Target user/computer", "required": True},
            {"name": "NEW_PASS", "desc": "New password to set", "required": True},
        ],
        "positional": ["TARGET", "NEW_PASS"],
    },
    "shadowcreds": {
        "command": ["add", "shadowCredentials"],
        "description": "Add shadow credentials (Key Credentials) to target",
        "category_tag": "credential",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object", "required": True},
        ],
        "positional": ["TARGET"],
    },
    "remove_shadowcreds": {
        "command": ["remove", "shadowCredentials"],
        "description": "Remove shadow credentials from target",
        "category_tag": "credential",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object", "required": True},
        ],
        "positional": ["TARGET"],
    },
    # -------------------------------------------------------------------------
    # RBCD (Resource-Based Constrained Delegation)
    # -------------------------------------------------------------------------
    "rbcd": {
        "command": ["add", "rbcd"],
        "description": "Add RBCD delegation on target for attacker service",
        "category_tag": "delegation",
        "extra_options": [
            {"name": "TARGET", "desc": "Target computer to delegate to", "required": True},
            {"name": "SERVICE", "desc": "Attacker-controlled service/computer", "required": True},
        ],
        "positional": ["TARGET", "SERVICE"],
    },
    "remove_rbcd": {
        "command": ["remove", "rbcd"],
        "description": "Remove RBCD delegation on target",
        "category_tag": "delegation",
        "extra_options": [
            {"name": "TARGET", "desc": "Target computer", "required": True},
            {"name": "SERVICE", "desc": "Service/computer to remove", "required": True},
        ],
        "positional": ["TARGET", "SERVICE"],
    },
    # -------------------------------------------------------------------------
    # Object Management
    # -------------------------------------------------------------------------
    "addcomputer": {
        "command": ["add", "computer"],
        "description": "Add a new computer account to the domain",
        "category_tag": "object",
        "extra_options": [
            {"name": "COMPUTER_NAME", "desc": "Computer name to create", "required": True},
            {"name": "COMPUTER_PASS", "desc": "Password for the computer", "required": True},
        ],
        "positional": ["COMPUTER_NAME", "COMPUTER_PASS"],
    },
    "adduser": {
        "command": ["add", "user"],
        "description": "Add a new user account to the domain",
        "category_tag": "object",
        "extra_options": [
            {"name": "NEW_USER", "desc": "Username to create", "required": True},
            {"name": "NEW_PASS", "desc": "Password for the new user", "required": True},
        ],
        "positional": ["NEW_USER", "NEW_PASS"],
    },
    # -------------------------------------------------------------------------
    # Object Attribute Manipulation
    # -------------------------------------------------------------------------
    "setobject": {
        "command": ["set", "object"],
        "description": "Set/modify attribute on AD object (e.g., SPN, description)",
        "category_tag": "attribute",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object (sAMAccountName)", "required": True},
            {"name": "ATTRIBUTE", "desc": "Attribute name (e.g., servicePrincipalName)", "required": True},
            {"name": "VALUE", "desc": "Value to set", "required": True},
            {"name": "APPEND", "desc": "Append value instead of replace", "default": "yes", "choices": ["yes", "no"]},
        ],
        "positional": ["TARGET", "ATTRIBUTE"],
    },
    # -------------------------------------------------------------------------
    # UAC Manipulation
    # -------------------------------------------------------------------------
    "adduac": {
        "command": ["add", "uac"],
        "description": "Add UAC property flag (e.g., DONT_REQ_PREAUTH for ASREProast)",
        "category_tag": "uac",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object", "required": True},
            {"name": "FLAG", "desc": "UAC flag to add (e.g., DONT_REQ_PREAUTH, TRUSTED_FOR_DELEGATION)", "required": True},
        ],
        "positional": ["TARGET"],
    },
    "removeuac": {
        "command": ["remove", "uac"],
        "description": "Remove UAC property flag",
        "category_tag": "uac",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object", "required": True},
            {"name": "FLAG", "desc": "UAC flag to remove", "required": True},
        ],
        "positional": ["TARGET"],
    },
    # -------------------------------------------------------------------------
    # Enumeration / Info
    # -------------------------------------------------------------------------
    "getobject": {
        "command": ["get", "object"],
        "description": "Retrieve LDAP attributes for an AD object",
        "category_tag": "enum",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object (sAMAccountName)", "required": True},
            {"name": "ATTR", "desc": "Specific attribute to retrieve (blank for all)", "required": False},
        ],
        "positional": ["TARGET"],
    },
    "getmembership": {
        "command": ["get", "membership"],
        "description": "Retrieve group memberships for a target",
        "category_tag": "enum",
        "extra_options": [
            {"name": "TARGET", "desc": "Target object (sAMAccountName)", "required": True},
        ],
        "positional": ["TARGET"],
    },
    "getwritable": {
        "command": ["get", "writable"],
        "description": "Find objects writable by the authenticated user",
        "category_tag": "enum",
        "extra_options": [],
        "positional": [],
    },
    "getsearch": {
        "command": ["get", "search"],
        "description": "Search LDAP database with custom filter",
        "category_tag": "enum",
        "extra_options": [
            {"name": "FILTER", "desc": "LDAP filter (e.g., (sAMAccountName=admin*))", "required": True},
            {"name": "ATTR", "desc": "Attributes to retrieve (comma-separated)", "required": False},
        ],
        "positional": [],
    },
    # -------------------------------------------------------------------------
    # DNS
    # -------------------------------------------------------------------------
    "adddns": {
        "command": ["add", "dnsRecord"],
        "description": "Add a DNS record to AD-integrated DNS",
        "category_tag": "dns",
        "extra_options": [
            {"name": "RECORD_NAME", "desc": "DNS record name", "required": True},
            {"name": "RECORD_DATA", "desc": "Record data (IP for A record)", "required": True},
        ],
        "positional": ["RECORD_NAME", "RECORD_DATA"],
    },
    "removedns": {
        "command": ["remove", "dnsRecord"],
        "description": "Remove a DNS record from AD-integrated DNS",
        "category_tag": "dns",
        "extra_options": [
            {"name": "RECORD_NAME", "desc": "DNS record name to remove", "required": True},
            {"name": "RECORD_DATA", "desc": "Record data to match", "required": True},
        ],
        "positional": ["RECORD_NAME", "RECORD_DATA"],
    },
    "dnsdump": {
        "command": ["get", "dnsDump"],
        "description": "Dump all DNS records from AD",
        "category_tag": "dns",
        "extra_options": [],
        "positional": [],
    },
}


# =============================================================================
# Base Class
# =============================================================================

class BloodyADModule(ModuleBase):
    """
    Base class for all bloodyAD modules.

    Subclasses only need to call super().__init__(tool_key) with the
    key from BLOODY_TOOLS. Everything else (options, auth, command building,
    execution, error checking) is handled automatically.
    """

    # Error patterns that indicate failure regardless of exit code
    _ERROR_PATTERNS = [
        "invalidcredentials", "access denied", "insufficient access",
        "unwilling to perform", "no such object", "connection error",
        "connection refused", "entry already exists", "constraint violation",
        "server is unwilling", "operations error",
    ]

    def __init__(self, tool_key: str):
        super().__init__()
        if tool_key not in BLOODY_TOOLS:
            raise ValueError(f"Unknown bloodyAD tool key: {tool_key}")

        self._tool_key = tool_key
        self._tool_config = BLOODY_TOOLS[tool_key]

        self.name = f"bloody_{tool_key}"
        self.description = self._tool_config["description"]
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "bloodyad", self._tool_config.get("category_tag", "")]
        self.references = ["https://github.com/CravateRouge/bloodyAD"]

        # Standard auth options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DC_HOST", "DC hostname/FQDN (overrides RHOSTS for connection)", default="")
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Username", required=True)
        self.register_option("PASS", "Password or LM:NT hash", default="")
        self.register_option("HASHES", "NTLM hashes (LM:NT format)", default="")
        self.register_option("DC_IP", "Domain Controller IP (for host resolution)", default="")
        self.register_option("SECURE", "Use LDAPS (--secure)", default="no", choices=["yes", "no"])
        self.register_option("KERBEROS", "Use Kerberos authentication", default="no", choices=["yes", "no"])
        self.register_option("FAKETIME", "Spoofed time for Kerberos clock skew (e.g. '2026-02-15 00:09:00')")

        # Register tool-specific options
        for opt in self._tool_config.get("extra_options", []):
            self.register_option(
                opt["name"],
                opt["desc"],
                required=opt.get("required", False),
                default=opt.get("default", ""),
                choices=opt.get("choices"),
            )

    def _get_host(self) -> str:
        """Get the connection host - prefer DC_HOST, fall back to RHOSTS."""
        dc_host = self.get_option("DC_HOST")
        return dc_host if dc_host else self.get_option("RHOSTS")

    def _build_auth_args(self) -> list:
        """Build the authentication arguments."""
        args = [
            "bloodyAD",
            "-d", self.get_option("DOMAIN"),
            "-u", self.get_option("USER"),
        ]

        hashes = self.get_option("HASHES")
        password = self.get_option("PASS")

        if hashes:
            args.extend(["-p", hashes])
        elif password:
            args.extend(["-p", password])

        if self.get_option("KERBEROS") == "yes":
            args.append("-k")

        if self.get_option("SECURE") == "yes":
            args.append("--secure")

        args.extend(["--host", self._get_host()])

        # Add -i dc-ip for host resolution (prefer DC_IP over RHOSTS)
        dc_host = self.get_option("DC_HOST")
        dc_ip = self.get_option("DC_IP")  # Falls back to config/globals
        rhosts = self.get_option("RHOSTS")
        resolve_ip = dc_ip if dc_ip else rhosts
        if dc_host and resolve_ip and dc_host != resolve_ip:
            args.extend(["-i", resolve_ip])

        return args

    def _build_command_args(self) -> list:
        """Build the bloodyAD subcommand and its arguments."""
        config = self._tool_config
        args = list(config["command"])  # e.g., ["add", "genericAll"]

        # Add positional arguments in order
        for opt_name in config.get("positional", []):
            val = self.get_option(opt_name)
            if val:
                args.append(val)

        # Handle tool-specific flags
        tk = self._tool_key

        if tk == "setobject":
            val = self.get_option("VALUE")
            append = self.get_option("APPEND") == "yes"
            if append:
                args.extend(["-v", val, "--append"])
            else:
                args.extend(["-v", val])

        elif tk == "getsearch":
            filt = self.get_option("FILTER")
            if filt:
                args.extend(["--filter", filt])
            attr = self.get_option("ATTR")
            if attr:
                args.extend(["--attr", attr])

        elif tk == "getobject":
            attr = self.get_option("ATTR")
            if attr:
                args.extend(["--attr", attr])

        elif tk in ("adduac", "removeuac"):
            flag = self.get_option("FLAG")
            if flag:
                args.extend(["-f", flag])

        return args

    def _build_display_cmd(self, full_args: list) -> str:
        """Build display command with password hidden."""
        display = full_args.copy()
        password = self.get_option("PASS")
        hashes = self.get_option("HASHES")
        secret = hashes if hashes else password
        if secret and "-p" in display:
            idx = display.index("-p")
            if idx + 1 < len(display):
                display[idx + 1] = "[HIDDEN]"
        return " ".join(display)

    def run(self) -> bool:
        """Execute the bloodyAD command."""
        # Validate options
        valid, errors = self.validate_options()
        if not valid:
            for err in errors:
                self.print_error(err)
            return False

        # Build full command
        auth_args = self._build_auth_args()
        cmd_args = self._build_command_args()
        full_args = auth_args + cmd_args

        # Display info
        host = self._get_host()
        self.print_status(f"Host: {host}")
        self.print_status(f"Domain: {self.get_option('DOMAIN')}")
        self.print_status(f"User: {self.get_option('USER')}")

        # Show tool-specific info
        for opt in self._tool_config.get("extra_options", []):
            val = self.get_option(opt["name"])
            if val:
                self.print_status(f"{opt['name']}: {val}")
        self.print_line()

        # Display command
        self.print_status(f"Command: {self._build_display_cmd(full_args)}")
        self.print_line()

        # Build shell-safe command
        shell_cmd = " ".join(shlex.quote(p) for p in full_args)

        # Apply faketime wrapper if set (fixes Kerberos clock skew)
        faketime_val = self.get_option("FAKETIME")
        if faketime_val:
            full_args = ["faketime", faketime_val] + full_args
            shell_cmd = f"faketime {shlex.quote(faketime_val)} {shell_cmd}"

        # Try local first, then Exegol
        tool_path = find_tool("bloodyAD") or find_tool("bloodyad")

        if tool_path:
            self.print_status("Using local bloodyAD")
            ret, stdout, stderr = self.run_command(full_args, timeout=120)
            output = stdout + stderr
        else:
            self.print_status("Using Exegol for bloodyAD")
            ret, stdout, stderr = self.run_in_exegol(shell_cmd, timeout=120)
            output = stdout + stderr

        # Display output
        for line in output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("[+]"):
                self.print_good(stripped)
            elif stripped.startswith("[-]"):
                self.print_error(stripped)
            elif stripped.startswith("[!]"):
                self.print_warning(stripped)
            elif stripped.startswith("[*]"):
                self.print_status(stripped.replace("[*]", "").strip())
            else:
                self.print_line(f"    {stripped}")

        # Check for errors
        output_lower = output.lower()
        has_error = any(pat in output_lower for pat in self._ERROR_PATTERNS)

        if has_error:
            if "invalidcredentials" in output_lower and self.get_option("SECURE") != "yes":
                self.print_line()
                self.print_warning("Tip: try 'set SECURE yes' (LDAP channel binding may be enforced)")
            return False

        success = ret == 0 or "[+]" in output
        if not success:
            return False

        # Show cleanup hint only on actual success
        rev = self._tool_config.get("reversible")
        if rev and rev in BLOODY_TOOLS:
            self.print_line()
            self.print_status(f"To undo: use bloodyad/{rev}")

        return True

    def check(self) -> bool:
        """Check if bloodyAD is available."""
        if find_tool("bloodyAD") or find_tool("bloodyad"):
            return True
        ret, _, _ = self.run_in_exegol("which bloodyAD", timeout=10)
        return ret == 0


# =============================================================================
# Virtual Module Registry
# =============================================================================

VIRTUAL_MODULES = {
    f"bloodyad/{key}": {
        "name": f"bloody_{key}",
        "description": config["description"],
        "tags": ["ad", "bloodyad", config.get("category_tag", "")],
        "platform": "windows",
        "author": "UwU Toolkit",
        "tool_key": key,
        "alias": f"auxiliary/bloodyad/{key}",
    }
    for key, config in BLOODY_TOOLS.items()
}
