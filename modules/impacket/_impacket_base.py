"""
Impacket Module Base Class and Tool Registry for UwU Toolkit

Provides a shared base class for all impacket tool wrappers.
Handles connection string building, auth mode detection, and execution
via local tools or Exegol container fallback.
"""

import os
import re
import shlex
import shutil
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


# =============================================================================
# Tool Registry - All impacket tools with metadata
# =============================================================================

IMPACKET_TOOLS = {
    # -------------------------------------------------------------------------
    # Remote Execution
    # -------------------------------------------------------------------------
    "psexec": {
        "script": "psexec.py",
        "description": "Remote execution via RemComSvc (creates service)",
        "category_tag": "exec",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "COMMAND", "desc": "Command to execute", "required": False},
            {"name": "SERVICE_NAME", "desc": "Custom service name", "required": False},
            {"name": "CODEC", "desc": "Output encoding", "default": "437"},
        ],
    },
    "smbexec": {
        "script": "smbexec.py",
        "description": "Exec via SMB services (no binary upload)",
        "category_tag": "exec",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "SHARE", "desc": "Writable share for output", "default": "C$"},
            {"name": "CODEC", "desc": "Output encoding", "default": "437"},
            {"name": "SERVICE_NAME", "desc": "Custom service name", "required": False},
        ],
    },
    "wmiexec": {
        "script": "wmiexec.py",
        "description": "Semi-interactive shell via WMI (stealthier)",
        "category_tag": "exec",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "COMMAND", "desc": "Command to execute", "required": False},
            {"name": "CODEC", "desc": "Output encoding", "default": "437"},
            {"name": "SHARE", "desc": "Writable share for output", "default": "ADMIN$"},
            {"name": "SHELL_TYPE", "desc": "Shell type (cmd/powershell)", "required": False},
        ],
    },
    "dcomexec": {
        "script": "dcomexec.py",
        "description": "Exec via DCOM (MMC20, ShellWindows, ShellBrowserWindow)",
        "category_tag": "exec",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "COMMAND", "desc": "Command to execute", "required": False},
            {"name": "OBJECT", "desc": "DCOM object (MMC20/ShellWindows/ShellBrowserWindow)", "required": False},
            {"name": "CODEC", "desc": "Output encoding", "default": "437"},
            {"name": "SHARE", "desc": "Writable share for output", "default": "ADMIN$"},
        ],
    },
    "atexec": {
        "script": "atexec.py",
        "description": "Exec via Task Scheduler (creates scheduled task)",
        "category_tag": "exec",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "COMMAND", "desc": "Command to execute", "required": True},
            {"name": "CODEC", "desc": "Output encoding", "default": "437"},
        ],
    },
    # -------------------------------------------------------------------------
    # SMB Tools
    # -------------------------------------------------------------------------
    "smbclient": {
        "script": "smbclient.py",
        "description": "SMB client - list shares, upload/download files",
        "category_tag": "smb",
        "interactive": True,
        "domain_required": False,
        "extra_options": [],
    },
    "smbserver": {
        "script": "smbserver.py",
        "description": "Host files via SMB server (for file transfers)",
        "category_tag": "smb",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "SHARE_NAME", "desc": "SMB share name", "default": "share"},
            {"name": "SHARE_PATH", "desc": "Local path to share", "default": "."},
            {"name": "SMB2", "desc": "Enable SMB2 support (yes/no)", "default": "yes"},
        ],
        "no_target_string": True,
    },
    "smbpasswd": {
        "script": "smbpasswd.py",
        "description": "Change SMB password remotely",
        "category_tag": "smb",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "NEWPASS", "desc": "New password to set", "required": True},
            {"name": "NEWHASHES", "desc": "New NTLM hash (LM:NT format)", "required": False},
        ],
    },
    # -------------------------------------------------------------------------
    # Credentials / Dumping
    # -------------------------------------------------------------------------
    "secretsdump": {
        "script": "secretsdump.py",
        "description": "Dump SAM/LSA/NTDS secrets remotely",
        "category_tag": "credentials",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "JUST_DC", "desc": "Extract only NTDS.DIT via DRSUAPI (yes/no)", "required": False},
            {"name": "JUST_DC_NTLM", "desc": "Only NTLM hashes from NTDS (yes/no)", "required": False},
            {"name": "JUST_DC_USER", "desc": "DCSync specific user only", "required": False},
            {"name": "EXEC_METHOD", "desc": "Exec method for VSS (smbexec/wmiexec/mmcexec)", "required": False},
            {"name": "OUTPUT_FILE", "desc": "Output file base name", "required": False},
            {"name": "USE_VSS", "desc": "Use VSS method (yes/no)", "required": False},
            {"name": "HISTORY", "desc": "Dump password history (yes/no)", "required": False},
        ],
    },
    "mimikatz": {
        "script": "mimikatz.py",
        "description": "Remote mimikatz execution via RPC",
        "category_tag": "credentials",
        "interactive": True,
        "domain_required": False,
        "extra_options": [],
    },
    # -------------------------------------------------------------------------
    # Kerberos
    # -------------------------------------------------------------------------
    "GetUserSPNs": {
        "script": "GetUserSPNs.py",
        "description": "Kerberoasting - request SPN tickets for offline cracking",
        "category_tag": "kerberos",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "REQUEST", "desc": "Request TGS tickets (yes/no)", "default": "yes"},
            {"name": "OUTPUT_FILE", "desc": "Output file for hashes", "required": False},
            {"name": "TARGET_USER", "desc": "Specific user to kerberoast", "required": False},
        ],
    },
    "GetNPUsers": {
        "script": "GetNPUsers.py",
        "description": "AS-REP Roast - extract hashes from no-preauth accounts",
        "category_tag": "kerberos",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "USERFILE", "desc": "File with usernames to test", "required": False},
            {"name": "FORMAT", "desc": "Output format (hashcat/john)", "default": "hashcat"},
            {"name": "OUTPUT_FILE", "desc": "Output file for hashes", "required": False},
        ],
    },
    "getTGT": {
        "script": "getTGT.py",
        "description": "Request a TGT ticket and save as ccache",
        "category_tag": "kerberos",
        "interactive": False,
        "domain_required": True,
        "extra_options": [],
    },
    "getST": {
        "script": "getST.py",
        "description": "Request a service ticket (TGS) given a TGT",
        "category_tag": "kerberos",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "SPN", "desc": "Service Principal Name to request", "required": True},
            {"name": "IMPERSONATE", "desc": "User to impersonate (S4U2Self/S4U2Proxy)", "required": False},
        ],
    },
    "ticketer": {
        "script": "ticketer.py",
        "description": "Create golden/silver Kerberos tickets",
        "category_tag": "kerberos",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "NTHASH", "desc": "NTLM hash of krbtgt/service account", "required": True},
            {"name": "DOMAIN_SID", "desc": "Domain SID", "required": True},
            {"name": "SPN", "desc": "SPN for silver ticket", "required": False},
        ],
        "no_target_string": True,
    },
    "ticketConverter": {
        "script": "ticketConverter.py",
        "description": "Convert tickets between ccache and kirbi formats",
        "category_tag": "kerberos",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "INPUT_FILE", "desc": "Input ticket file", "required": True},
            {"name": "OUTPUT_FILE_TC", "desc": "Output ticket file", "required": True},
        ],
        "no_target_string": True,
    },
    "describeTicket": {
        "script": "describeTicket.py",
        "description": "Parse and describe Kerberos ticket contents",
        "category_tag": "kerberos",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "TICKET_FILE", "desc": "Ticket file to describe", "required": True},
        ],
        "no_target_string": True,
    },
    # -------------------------------------------------------------------------
    # LDAP / AD Enumeration
    # -------------------------------------------------------------------------
    "GetADUsers": {
        "script": "GetADUsers.py",
        "description": "Enumerate Active Directory users via LDAP",
        "category_tag": "ad_enum",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "ALL", "desc": "Return all users (yes/no)", "default": "yes"},
        ],
    },
    "findDelegation": {
        "script": "findDelegation.py",
        "description": "Find delegation relationships in AD",
        "category_tag": "ad_enum",
        "interactive": False,
        "domain_required": True,
        "extra_options": [],
    },
    "Get-GPPPassword": {
        "script": "Get-GPPPassword.py",
        "description": "Extract Group Policy Preferences passwords",
        "category_tag": "ad_enum",
        "interactive": False,
        "domain_required": False,
        "extra_options": [],
    },
    # -------------------------------------------------------------------------
    # RPC / Network Enumeration
    # -------------------------------------------------------------------------
    "rpcdump": {
        "script": "rpcdump.py",
        "description": "Dump RPC endpoints on a target",
        "category_tag": "enum",
        "interactive": False,
        "domain_required": False,
        "extra_options": [],
    },
    "samrdump": {
        "script": "samrdump.py",
        "description": "Enumerate SAM users and groups via MSRPC",
        "category_tag": "enum",
        "interactive": False,
        "domain_required": False,
        "extra_options": [],
    },
    "lookupsid": {
        "script": "lookupsid.py",
        "description": "SID brute-force to enumerate users and groups",
        "category_tag": "enum",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "MAX_RID", "desc": "Maximum RID to brute-force", "default": "4000"},
        ],
    },
    "DumpNTLMInfo": {
        "script": "DumpNTLMInfo.py",
        "description": "Dump NTLM authentication info from target",
        "category_tag": "enum",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "RHOSTS", "desc": "Target host/IP", "required": True},
        ],
        "no_target_string": True,
    },
    "getArch": {
        "script": "getArch.py",
        "description": "Detect remote host architecture (32/64-bit)",
        "category_tag": "enum",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "RHOSTS", "desc": "Target host/IP", "required": True},
        ],
        "no_target_string": True,
    },
    "netview": {
        "script": "netview.py",
        "description": "Enumerate sessions and shares on remote hosts",
        "category_tag": "enum",
        "interactive": False,
        "domain_required": True,
        "extra_options": [],
    },
    # -------------------------------------------------------------------------
    # MSSQL
    # -------------------------------------------------------------------------
    "mssqlclient": {
        "script": "mssqlclient.py",
        "description": "Interactive MSSQL client with command execution",
        "category_tag": "mssql",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "WINDOWS_AUTH", "desc": "Use Windows authentication (yes/no)", "required": False},
            {"name": "DB", "desc": "MSSQL database instance", "required": False},
        ],
    },
    "mssqlinstance": {
        "script": "mssqlinstance.py",
        "description": "Discover MSSQL instances via browser service",
        "category_tag": "mssql",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "RHOSTS", "desc": "Target host/IP", "required": True},
        ],
        "no_target_string": True,
    },
    # -------------------------------------------------------------------------
    # Relay / MiTM
    # -------------------------------------------------------------------------
    "ntlmrelayx": {
        "script": "ntlmrelayx.py",
        "description": "NTLM relay attack tool (relay captured auth)",
        "category_tag": "relay",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "RELAY_TARGET", "desc": "Single relay target (-t)", "required": False},
            {"name": "TARGETS_FILE", "desc": "File with relay targets (-tf)", "required": False},
            {"name": "COMMAND", "desc": "Command to execute on relay", "required": False},
            {"name": "ENUM_SHARES", "desc": "Enumerate shares on relay (yes/no)", "required": False},
            {"name": "DUMP_LSASS", "desc": "Dump LSASS on relay (yes/no)", "required": False},
            {"name": "SOCKS", "desc": "Enable SOCKS proxy (yes/no)", "required": False},
        ],
        "no_target_string": True,
    },
    "smbrelayx": {
        "script": "smbrelayx.py",
        "description": "SMB relay attack (simpler than ntlmrelayx)",
        "category_tag": "relay",
        "interactive": True,
        "domain_required": False,
        "extra_options": [
            {"name": "RELAY_TARGET", "desc": "Host to relay to", "required": True},
            {"name": "COMMAND", "desc": "Command to execute on relay", "required": False},
        ],
        "no_target_string": True,
    },
    "karmaSMB": {
        "script": "karmaSMB.py",
        "description": "SMB server that auto-responds to any auth request",
        "category_tag": "relay",
        "interactive": True,
        "domain_required": False,
        "extra_options": [],
        "no_target_string": True,
    },
    # -------------------------------------------------------------------------
    # Password / Auth
    # -------------------------------------------------------------------------
    "changepasswd": {
        "script": "changepasswd.py",
        "description": "Change user password via multiple protocols",
        "category_tag": "password",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "NEWPASS", "desc": "New password to set", "required": True},
            {"name": "OLDPASS", "desc": "Old password (if different from PASS)", "required": False},
        ],
    },
    "rdp_check": {
        "script": "rdp_check.py",
        "description": "Check valid RDP credentials on target",
        "category_tag": "password",
        "interactive": False,
        "domain_required": False,
        "extra_options": [],
    },
    # -------------------------------------------------------------------------
    # AD ACL / Abuse
    # -------------------------------------------------------------------------
    "addcomputer": {
        "script": "addcomputer.py",
        "description": "Add a computer account to the domain",
        "category_tag": "ad_abuse",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "COMPUTER_NAME", "desc": "Computer name to add", "required": False},
            {"name": "COMPUTER_PASS", "desc": "Password for computer account", "required": False},
        ],
    },
    "rbcd": {
        "script": "rbcd.py",
        "description": "Resource-Based Constrained Delegation abuse",
        "category_tag": "ad_abuse",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "DELEGATE_TO", "desc": "Target to delegate to", "required": True},
            {"name": "DELEGATE_FROM", "desc": "Account to delegate from", "required": True},
            {"name": "ACTION", "desc": "Action (read/write/remove/flush)", "default": "write"},
        ],
    },
    "dacledit": {
        "script": "dacledit.py",
        "description": "Edit DACLs on AD objects",
        "category_tag": "ad_abuse",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "TARGET_DN", "desc": "Target distinguished name", "required": False},
            {"name": "PRINCIPAL", "desc": "Principal to grant/revoke", "required": False},
            {"name": "ACTION", "desc": "Action (read/write/remove)", "default": "read"},
        ],
    },
    "owneredit": {
        "script": "owneredit.py",
        "description": "Edit object ownership in AD",
        "category_tag": "ad_abuse",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "TARGET", "desc": "Target object (sAMAccountName, DN, or SID)", "required": True},
            {"name": "NEW_OWNER", "desc": "New owner (sAMAccountName, DN, or SID)", "required": True},
            {"name": "ACTION", "desc": "Action (read/write)", "default": "write"},
        ],
    },
    # -------------------------------------------------------------------------
    # Services / Registry
    # -------------------------------------------------------------------------
    "services": {
        "script": "services.py",
        "description": "Manage Windows services remotely (start/stop/create/delete)",
        "category_tag": "services",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "SVC_ACTION", "desc": "Action (list/start/stop/create/delete/status)", "default": "list"},
            {"name": "SERVICE_NAME", "desc": "Service name for action", "required": False},
        ],
    },
    "reg": {
        "script": "reg.py",
        "description": "Remote Windows registry operations",
        "category_tag": "services",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "REG_ACTION", "desc": "Action (query/add/delete)", "default": "query"},
            {"name": "KEYNAME", "desc": "Registry key name", "required": False},
        ],
    },
    # -------------------------------------------------------------------------
    # WMI
    # -------------------------------------------------------------------------
    "wmiquery": {
        "script": "wmiquery.py",
        "description": "Execute WQL queries via WMI",
        "category_tag": "wmi",
        "interactive": True,
        "domain_required": False,
        "extra_options": [],
    },
    "wmipersist": {
        "script": "wmipersist.py",
        "description": "WMI event subscription persistence",
        "category_tag": "wmi",
        "interactive": False,
        "domain_required": False,
        "extra_options": [],
    },
    # -------------------------------------------------------------------------
    # Exchange / Domain Escalation
    # -------------------------------------------------------------------------
    "exchanger": {
        "script": "exchanger.py",
        "description": "Exchange Web Services (EWS) interaction",
        "category_tag": "exchange",
        "interactive": False,
        "domain_required": True,
        "extra_options": [],
    },
    "raiseChild": {
        "script": "raiseChild.py",
        "description": "Escalate from child to parent domain via trust",
        "category_tag": "ad_abuse",
        "interactive": False,
        "domain_required": True,
        "extra_options": [
            {"name": "CHILD_DOMAIN", "desc": "Child domain name", "required": True},
        ],
    },
    "goldenPac": {
        "script": "goldenPac.py",
        "description": "MS14-068 exploit - forge Kerberos PAC for domain admin",
        "category_tag": "ad_abuse",
        "interactive": True,
        "domain_required": True,
        "extra_options": [
            {"name": "COMMAND", "desc": "Command to execute after exploit", "required": False},
        ],
    },
    # -------------------------------------------------------------------------
    # Local / File Tools
    # -------------------------------------------------------------------------
    "esentutl": {
        "script": "esentutl.py",
        "description": "Parse ESE database files (NTDS.dit, etc.)",
        "category_tag": "local",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "DB_FILE", "desc": "ESE database file to parse", "required": True},
        ],
        "no_target_string": True,
    },
    "ntfs_read": {
        "script": "ntfs-read.py",
        "description": "Read files from NTFS volumes",
        "category_tag": "local",
        "interactive": False,
        "domain_required": False,
        "extra_options": [
            {"name": "VOLUME", "desc": "NTFS volume to read from", "required": True},
        ],
        "no_target_string": True,
    },
}


# =============================================================================
# ImpacketModule Base Class
# =============================================================================

class ImpacketModule(ModuleBase):
    """
    Base class for all impacket tool wrappers in UwU Toolkit.

    Handles:
    - Connection string building: [domain/]user[:pass]@target
    - Auth mode auto-detection (Kerberos > Hashes > Password)
    - Tool resolution (local find_tool → Exegol fallback)
    - Interactive vs captured execution

    Subclasses only need:
        class MyTool(ImpacketModule):
            def __init__(self):
                super().__init__("tool_key")
    """

    def __init__(self, tool_key: str):
        super().__init__()

        self._tool_key = tool_key
        self._tool_config = IMPACKET_TOOLS[tool_key]

        # Module metadata
        self.name = f"impacket_{tool_key}"
        self.description = self._tool_config["description"]
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["impacket", self._tool_config["category_tag"], tool_key]

        # Register options
        self._register_impacket_options()

    def _register_impacket_options(self):
        """Register common + tool-specific options from the registry."""
        config = self._tool_config
        is_no_target = config.get("no_target_string", False)

        # Common options for tools that use target connection strings
        if not is_no_target:
            self.register_option("RHOSTS", "Target host/IP", required=True)
            self.register_option("USER", "Username for authentication", required=True)
            self.register_option("PASS", "Password", required=False)
            self.register_option("DOMAIN", "Domain name",
                                 required=config.get("domain_required", False))
            self.register_option("HASHES", "NTLM hashes (LM:NT format)", required=False)
            self.register_option("KERBEROS", "Use Kerberos authentication (yes/no)",
                                 default="no", choices=["yes", "no"])
            self.register_option("AES_KEY", "AES key for Kerberos authentication",
                                 required=False)
            self.register_option("DC_IP", "Domain controller IP", required=False)
            self.register_option("TARGET_IP", "Target IP (when target is a hostname)",
                                 required=False)
            self.register_option("PORT", "Target port (override default)", required=False)
        else:
            # Some no_target_string tools still need USER/DOMAIN (e.g. ticketer)
            if self._tool_key in ("ticketer",):
                self.register_option("USER", "Username for ticket", required=True)
                self.register_option("DOMAIN", "Domain name", required=True)

        # Tool-specific options from registry
        for opt in config.get("extra_options", []):
            self.register_option(
                opt["name"],
                opt.get("desc", ""),
                required=opt.get("required", False),
                default=opt.get("default", None),
            )

        # EXTRA_ARGS always available for pass-through
        self.register_option("EXTRA_ARGS", "Additional arguments (passed directly to tool)")

        # FAKETIME for clock skew fix (set globally with setg FAKETIME)
        self.register_option("FAKETIME", "Spoofed time for Kerberos clock skew (e.g. '2026-02-15 00:09:00')")

    # =========================================================================
    # Auth Detection
    # =========================================================================

    def _detect_auth_mode(self) -> str:
        """Auto-detect auth mode based on which options are set."""
        kerberos = self.get_option("KERBEROS")
        hashes = self.get_option("HASHES")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")

        if kerberos and kerberos.lower() == "yes":
            return "Kerberos"
        elif hashes:
            return "Pass-the-Hash (Domain)" if domain else "Pass-the-Hash"
        elif password:
            return "Password (Domain)" if domain else "Password"
        return "No Password"

    # =========================================================================
    # Command Building
    # =========================================================================

    def _build_target_string(self) -> str:
        """Build [domain/]user[:pass]@target connection string (shell-safe).

        For domain-required LDAP tools (GetADUsers, findDelegation, etc.),
        omit @target to avoid LDAP bind issues - use -dc-ip instead.
        """
        user = self.get_option("USER")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")
        rhosts = self.get_option("RHOSTS")
        hashes = self.get_option("HASHES")
        kerberos = self.get_option("KERBEROS")

        identity = ""
        if domain:
            identity += f"{domain}/"
        identity += user or ""

        # Password in connection string only for password auth
        if password and not hashes and not (kerberos and kerberos.lower() == "yes"):
            identity += f":{password}"

        # For domain-query tools (LDAP-based), omit @target.
        # These tools use -dc-ip for targeting instead.
        # Including @target causes LDAP NTLM bind failures on some DCs.
        config = self._tool_config
        if config.get("domain_required", False) and self.get_option("DC_IP"):
            return shlex.quote(identity)

        # Shell-quote the whole string to protect $ and special chars
        return shlex.quote(f"{identity}@{rhosts}")

    def _build_auth_flags(self) -> list:
        """Build authentication CLI flags."""
        flags = []
        hashes = self.get_option("HASHES")
        kerberos = self.get_option("KERBEROS")
        aes_key = self.get_option("AES_KEY")

        if hashes:
            flags.extend(["-hashes", hashes])
        if kerberos and kerberos.lower() == "yes":
            flags.extend(["-k", "-no-pass"])
        if aes_key:
            flags.extend(["-aesKey", aes_key])
        return flags

    # Tools that do NOT support the -dc-ip flag
    _NO_DC_IP_TOOLS = {
        "rpcdump", "lookupsid", "rdp_check",
    }

    def _build_connection_flags(self) -> list:
        """Build connection CLI flags."""
        flags = []
        dc_ip = self.get_option("DC_IP")
        target_ip = self.get_option("TARGET_IP")
        port = self.get_option("PORT")

        if dc_ip and self._tool_key not in self._NO_DC_IP_TOOLS:
            flags.extend(["-dc-ip", dc_ip])
        if target_ip:
            flags.extend(["-target-ip", target_ip])
        if port:
            flags.extend(["-port", str(port)])
        return flags

    def _build_tool_flags(self) -> list:
        """Build tool-specific CLI flags from option values."""
        flags = []
        tk = self._tool_key

        if tk == "secretsdump":
            if self._yes("JUST_DC"):
                flags.append("-just-dc")
            if self._yes("JUST_DC_NTLM"):
                flags.append("-just-dc-ntlm")
            jdu = self.get_option("JUST_DC_USER")
            if jdu:
                flags.extend(["-just-dc-user", jdu])
            em = self.get_option("EXEC_METHOD")
            if em:
                flags.extend(["-exec-method", em])
            of = self.get_option("OUTPUT_FILE")
            if of:
                flags.extend(["-outputfile", of])
            if self._yes("USE_VSS"):
                flags.append("-use-vss")
            if self._yes("HISTORY"):
                flags.append("-history")

        elif tk == "GetUserSPNs":
            if self._yes("REQUEST"):
                flags.append("-request")
            tu = self.get_option("TARGET_USER")
            if tu:
                flags.extend(["-request-user", tu])
            of = self.get_option("OUTPUT_FILE")
            if of:
                flags.extend(["-outputfile", of])

        elif tk == "GetNPUsers":
            uf = self.get_option("USERFILE")
            if uf:
                flags.extend(["-usersfile", uf])
            fmt = self.get_option("FORMAT")
            if fmt:
                flags.extend(["-format", fmt])
            of = self.get_option("OUTPUT_FILE")
            if of:
                flags.extend(["-outputfile", of])
            # No-pass for unauthenticated mode
            if not self.get_option("PASS") and not self.get_option("HASHES"):
                kerb = self.get_option("KERBEROS")
                if not (kerb and kerb.lower() == "yes"):
                    flags.append("-no-pass")

        elif tk in ("psexec", "smbexec", "wmiexec", "dcomexec"):
            codec = self.get_option("CODEC")
            if codec:
                flags.extend(["-codec", codec])
            if tk == "dcomexec":
                obj = self.get_option("OBJECT")
                if obj:
                    flags.extend(["-object", obj])
            if tk in ("psexec", "smbexec"):
                sn = self.get_option("SERVICE_NAME")
                if sn:
                    flags.extend(["-service-name", sn])
            if tk in ("smbexec", "wmiexec", "dcomexec"):
                share = self.get_option("SHARE")
                if share:
                    flags.extend(["-share", share])
            if tk == "wmiexec":
                st = self.get_option("SHELL_TYPE")
                if st:
                    flags.extend(["-shell-type", st])
            # COMMAND is added in _build_command_string() after target

        elif tk == "atexec":
            codec = self.get_option("CODEC")
            if codec:
                flags.extend(["-codec", codec])
            # COMMAND is added in _build_command_string() after target

        elif tk == "lookupsid":
            mr = self.get_option("MAX_RID")
            if mr:
                # MAX_RID is a positional argument, not a flag
                flags.append(str(mr))

        elif tk == "GetADUsers":
            if self._yes("ALL"):
                flags.append("-all")

        elif tk == "getST":
            spn = self.get_option("SPN")
            if spn:
                flags.extend(["-spn", spn])
            imp = self.get_option("IMPERSONATE")
            if imp:
                flags.extend(["-impersonate", imp])

        elif tk == "addcomputer":
            cn = self.get_option("COMPUTER_NAME")
            if cn:
                flags.extend(["-computer-name", cn])
            cp = self.get_option("COMPUTER_PASS")
            if cp:
                flags.extend(["-computer-pass", cp])

        elif tk == "rbcd":
            dt = self.get_option("DELEGATE_TO")
            if dt:
                flags.extend(["-delegate-to", dt])
            df = self.get_option("DELEGATE_FROM")
            if df:
                flags.extend(["-delegate-from", df])
            act = self.get_option("ACTION")
            if act:
                flags.extend(["-action", act])

        elif tk == "dacledit":
            tdn = self.get_option("TARGET_DN")
            if tdn:
                flags.extend(["-target-dn", tdn])
            pr = self.get_option("PRINCIPAL")
            if pr:
                flags.extend(["-principal", pr])
            act = self.get_option("ACTION")
            if act:
                flags.extend(["-action", act])

        elif tk == "owneredit":
            target = self.get_option("TARGET")
            if target:
                if target.upper().startswith("CN=") or target.upper().startswith("DC="):
                    flags.extend(["-target-dn", target])
                elif target.startswith("S-1-"):
                    flags.extend(["-target-sid", target])
                else:
                    flags.extend(["-target", target])
            no = self.get_option("NEW_OWNER")
            if no:
                if no.upper().startswith("CN=") or no.upper().startswith("DC="):
                    flags.extend(["-new-owner-dn", no])
                elif no.startswith("S-1-"):
                    flags.extend(["-new-owner-sid", no])
                else:
                    flags.extend(["-new-owner", no])
            act = self.get_option("ACTION")
            if act:
                flags.extend(["-action", act])

        elif tk == "services":
            act = self.get_option("SVC_ACTION")
            if act:
                flags.append(act)
            sn = self.get_option("SERVICE_NAME")
            if sn:
                flags.extend(["-name", sn])

        elif tk == "reg":
            act = self.get_option("REG_ACTION")
            if act:
                flags.append(act)
            kn = self.get_option("KEYNAME")
            if kn:
                flags.extend(["-keyName", shlex.quote(kn)])

        elif tk == "mssqlclient":
            if self._yes("WINDOWS_AUTH"):
                flags.append("-windows-auth")
            db = self.get_option("DB")
            if db:
                flags.extend(["-db", db])

        elif tk == "changepasswd":
            np = self.get_option("NEWPASS")
            if np:
                flags.extend(["-newpass", np])
            op = self.get_option("OLDPASS")
            if op:
                flags.extend(["-oldpass", op])

        elif tk == "smbpasswd":
            np = self.get_option("NEWPASS")
            if np:
                flags.extend(["-newpass", np])
            nh = self.get_option("NEWHASHES")
            if nh:
                flags.extend(["-newhashes", nh])

        elif tk == "goldenPac":
            cmd = self.get_option("COMMAND")
            if cmd:
                flags.append(cmd)

        elif tk == "raiseChild":
            cd = self.get_option("CHILD_DOMAIN")
            if cd:
                flags.append(cd)

        elif tk == "ntlmrelayx":
            rt = self.get_option("RELAY_TARGET")
            if rt:
                flags.extend(["-t", rt])
            tf = self.get_option("TARGETS_FILE")
            if tf:
                flags.extend(["-tf", tf])
            cmd = self.get_option("COMMAND")
            if cmd:
                flags.extend(["-c", cmd])
            if self._yes("ENUM_SHARES"):
                flags.append("--enum-shares")
            if self._yes("DUMP_LSASS"):
                flags.append("--dump-lsass")
            if self._yes("SOCKS"):
                flags.append("-socks")

        elif tk == "smbrelayx":
            rt = self.get_option("RELAY_TARGET")
            if rt:
                flags.extend(["-h", rt])
            cmd = self.get_option("COMMAND")
            if cmd:
                flags.extend(["-c", cmd])

        return flags

    def _build_no_target_args(self) -> list:
        """Build args for tools that don't use standard target connection strings."""
        args = []
        tk = self._tool_key

        if tk == "smbserver":
            sn = self.get_option("SHARE_NAME") or "share"
            sp = self.get_option("SHARE_PATH") or "."
            args.extend([sn, sp])
            if self._yes("SMB2"):
                args.append("-smb2support")

        elif tk == "ticketer":
            nh = self.get_option("NTHASH")
            if nh:
                args.extend(["-nthash", nh])
            ds = self.get_option("DOMAIN_SID")
            if ds:
                args.extend(["-domain-sid", ds])
            domain = self.get_option("DOMAIN")
            if domain:
                args.extend(["-domain", domain])
            spn = self.get_option("SPN")
            if spn:
                args.extend(["-spn", spn])
            user = self.get_option("USER")
            if user:
                args.append(user)

        elif tk == "ticketConverter":
            inf = self.get_option("INPUT_FILE")
            outf = self.get_option("OUTPUT_FILE_TC")
            if inf:
                args.append(inf)
            if outf:
                args.append(outf)

        elif tk == "describeTicket":
            tf = self.get_option("TICKET_FILE")
            if tf:
                args.append(tf)

        elif tk == "esentutl":
            dbf = self.get_option("DB_FILE")
            if dbf:
                args.append(dbf)

        elif tk == "ntfs_read":
            vol = self.get_option("VOLUME")
            if vol:
                args.append(vol)

        elif tk == "DumpNTLMInfo":
            rh = self.get_option("RHOSTS")
            if rh:
                args.append(rh)

        elif tk == "getArch":
            rh = self.get_option("RHOSTS")
            if rh:
                args.extend(["-target", rh])

        elif tk == "mssqlinstance":
            rh = self.get_option("RHOSTS")
            if rh:
                args.append(rh)

        return args

    def _build_command_string(self) -> str:
        """Build the full command string for this tool."""
        config = self._tool_config
        script = config["script"]
        is_no_target = config.get("no_target_string", False)

        parts = [script]

        if is_no_target:
            parts.extend(self._build_no_target_args())
        else:
            parts.append(self._build_target_string())

            # For exec tools, command positional must come immediately after
            # target (Exegol fork v0.14 argparse requires positionals before
            # optional flags).
            if self._tool_key in ("psexec", "wmiexec", "dcomexec",
                                  "atexec", "goldenPac"):
                cmd = self.get_option("COMMAND")
                if cmd:
                    parts.append(shlex.quote(cmd))

            parts.extend(self._build_auth_flags())
            parts.extend(self._build_connection_flags())

        parts.extend(self._build_tool_flags())

        extra = self.get_option("EXTRA_ARGS")
        if extra:
            parts.append(extra)

        return " ".join(parts)

    def _yes(self, option_name: str) -> bool:
        """Check if a yes/no option is set to yes."""
        val = self.get_option(option_name)
        return val is not None and str(val).lower() == "yes"

    # =========================================================================
    # Faketime Support (clock skew fix)
    # =========================================================================

    def _apply_faketime(self, cmd_str: str) -> str:
        """Wrap command with faketime if FAKETIME is set (fixes KRB_AP_ERR_SKEW)."""
        faketime_val = self.get_option("FAKETIME")
        if faketime_val:
            return f"faketime {shlex.quote(faketime_val)} {cmd_str}"
        return cmd_str

    # =========================================================================
    # Tmux Session Management (interactive tools)
    # =========================================================================

    @staticmethod
    def _list_uwu_sessions():
        """List all uwu tmux session names."""
        try:
            result = subprocess.run(
                ["tmux", "list-sessions", "-F", "#{session_name}"],
                capture_output=True, text=True, timeout=5
            )
            return [s for s in result.stdout.strip().split('\n') if s.startswith("uwu-")]
        except Exception:
            return []

    def _generate_session_name(self) -> str:
        """Generate a unique tmux session name for this tool."""
        tool = self._tool_key
        user = (self.get_option("USER") or "anon")
        rhosts = (self.get_option("RHOSTS") or "local")

        # Sanitize: remove domain prefix, strip special chars
        safe_user = re.sub(r'[^a-zA-Z0-9_-]', '_', user.split("\\")[-1].split("@")[0])
        safe_target = rhosts.replace(".", "-")

        base = f"uwu-{tool}-{safe_user}@{safe_target}"

        existing = self._list_uwu_sessions()
        if base not in existing:
            return base
        counter = 2
        while f"{base}-{counter}" in existing:
            counter += 1
        return f"{base}-{counter}"

    def _apply_uwu_theme(self, session_name: str) -> None:
        """Apply UwU themed styling to tmux session."""
        script_paths = [
            "/opt/my-resources/tools/uwu-toolkit/scripts/uwu-tmux-status.sh",
            "/opt/tools/uwu-toolkit/scripts/uwu-tmux-status.sh",
            os.path.expanduser("~/.local/share/uwu-toolkit/scripts/uwu-tmux-status.sh"),
        ]
        status_script = None
        for p in script_paths:
            if os.path.isfile(p):
                status_script = p
                break

        if status_script:
            status_right = f"#(bash {status_script}) #[fg=#666666]Ctrl+b x #[fg=#ff00ff]| #[fg=#00ffff]%H:%M "
        else:
            status_right = "#[fg=#666666]Ctrl+b x = detach #[fg=#ff00ff]| #[fg=#00ffff]%H:%M "

        theme_commands = [
            ["tmux", "set-option", "-t", session_name, "status", "on"],
            ["tmux", "set-option", "-t", session_name, "status-style", "bg=#1a1a2e,fg=#ff6eb4"],
            ["tmux", "set-option", "-t", session_name, "status-left-length", "50"],
            ["tmux", "set-option", "-t", session_name, "status-right-length", "120"],
            ["tmux", "set-option", "-t", session_name, "status-left",
             "#[bg=#ff6eb4,fg=#1a1a2e,bold] UwU #[bg=#1a1a2e,fg=#ff6eb4] "],
            ["tmux", "set-option", "-t", session_name, "status-right", status_right],
            ["tmux", "set-option", "-t", session_name, "status-interval", "2"],
            ["tmux", "set-option", "-t", session_name, "window-status-current-style",
             "bg=#ff00ff,fg=#1a1a2e,bold"],
            ["tmux", "set-option", "-t", session_name, "window-status-style",
             "bg=#1a1a2e,fg=#888888"],
            ["tmux", "set-option", "-t", session_name, "pane-border-style", "fg=#ff6eb4"],
            ["tmux", "set-option", "-t", session_name, "pane-active-border-style", "fg=#00ffff"],
            ["tmux", "set-option", "-t", session_name, "message-style",
             "bg=#ff6eb4,fg=#1a1a2e,bold"],
            ["tmux", "bind-key", "x", "detach-client"],
        ]
        for cmd in theme_commands:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass

    def _run_in_tmux(self, cmd_str: str, session_name: str) -> bool:
        """Run command in a new tmux session (backgroundable with Ctrl+b d)."""
        if not shutil.which("tmux"):
            self.print_warning("tmux not found — falling back to direct execution")
            return self._run_direct_interactive(cmd_str)

        self.print_good(f"Creating tmux session: {session_name}")
        self.print_status("Use Ctrl+b d to detach (background the session)")
        self.print_status("Use 'sessions' to list, 'interact <name>' to reattach")
        self.print_line()

        try:
            create = subprocess.run(
                ["tmux", "new-session", "-d", "-s", session_name, cmd_str],
                capture_output=True, text=True, timeout=10
            )
            if create.returncode != 0:
                self.print_error(f"Failed to create tmux session: {create.stderr}")
                return False

            self._apply_uwu_theme(session_name)
            os.system(f"tmux attach-session -t {shlex.quote(session_name)}")

            # Check if session still exists (user might have exited vs detached)
            check = subprocess.run(
                ["tmux", "has-session", "-t", session_name],
                capture_output=True, timeout=5
            )
            self.print_line()
            if check.returncode == 0:
                self.print_good(f"Session '{session_name}' is backgrounded")
                self.print_status("Use 'sessions' to list, 'interact <name>' to reattach")
            else:
                self.print_status("Session ended")
            return True

        except subprocess.TimeoutExpired:
            self.print_error("Timeout creating tmux session")
            return False
        except Exception as e:
            self.print_error(f"Failed to create tmux session: {e}")
            return False

    def _run_direct_interactive(self, cmd_str: str) -> bool:
        """Fallback: run interactively without tmux."""
        self.print_good("Starting interactive session...")
        self.print_status("Type 'exit' or Ctrl+C to close")
        self.print_line()
        try:
            result = subprocess.run(shlex.split(cmd_str))
            self.print_line()
            return result.returncode == 0
        except KeyboardInterrupt:
            self.print_line()
            self.print_warning("Session interrupted")
            return True
        except Exception as e:
            self.print_error(f"Session failed: {e}")
            return False

    # =========================================================================
    # Execution
    # =========================================================================

    def run(self) -> bool:
        """Execute the impacket tool. Tries local first, falls back to Exegol."""
        config = self._tool_config
        is_no_target = config.get("no_target_string", False)

        # Validate options
        valid, errors = self.validate_options()
        if not valid:
            for err in errors:
                self.print_error(err)
            return False

        # Build command
        cmd_str = self._build_command_string()
        cmd_str = self._apply_faketime(cmd_str)
        script = config["script"]

        # Display info
        if not is_no_target:
            auth_mode = self._detect_auth_mode()
            self.print_status(f"Auth mode: {auth_mode}")

        # Determine if interactive
        interactive = config.get("interactive", False) and not self._has_noninteractive_args()

        # Try local tool first
        tool_path = find_tool(script)

        if tool_path:
            self.print_status("Using local impacket tools")
            # Build display command (hide password)
            display_cmd = cmd_str
            password = self.get_option("PASS") if not is_no_target else None
            if password:
                display_cmd = display_cmd.replace(password, "[HIDDEN]")
            self.print_status(f"Executing: {display_cmd}")
            self.print_line()

            if interactive:
                return self._run_local_interactive(cmd_str, tool_path)
            else:
                return self._run_local_captured(cmd_str, tool_path)
        else:
            self.print_status("Using Exegol container for impacket tools")
            display_cmd = cmd_str
            password = self.get_option("PASS") if not is_no_target else None
            if password:
                display_cmd = display_cmd.replace(password, "[HIDDEN]")
            self.print_status(f"Executing: {display_cmd}")
            self.print_line()

            if interactive:
                # Build docker exec command for tmux session
                container = self.get_option("EXEGOL_CONTAINER")
                if not container:
                    container = self._find_exegol_container()
                if not container:
                    self.print_error("No Exegol container found. Set EXEGOL_CONTAINER option.")
                    return False
                exegol_path = "/root/.local/bin:/opt/tools/bin:/opt/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                docker_cmd = f"docker exec -it {shlex.quote(container)} bash -l -c {shlex.quote(f'export PATH={exegol_path}:$PATH && {cmd_str}')}"
                session_name = self._generate_session_name()
                return self._run_in_tmux(docker_cmd, session_name)
            else:
                ret = self.run_in_exegol_stream(cmd_str, timeout=300)
                return ret == 0

    def _has_noninteractive_args(self) -> bool:
        """Check if args indicate non-interactive mode (e.g., COMMAND set on exec tools)."""
        if self._tool_key in ("psexec", "wmiexec", "dcomexec", "atexec"):
            return bool(self.get_option("COMMAND"))
        return False

    def _run_local_interactive(self, cmd_str: str, tool_path: str) -> bool:
        """Run tool interactively in a tmux session (backgroundable)."""
        script = self._tool_config["script"]
        full_cmd = cmd_str.replace(script, tool_path, 1)
        session_name = self._generate_session_name()
        return self._run_in_tmux(full_cmd, session_name)

    # Known impacket error patterns that indicate failure regardless of exit code
    _ERROR_PATTERNS = [
        "invalid server address", "invalidcredentials", "error occurred",
        "kdc_err_preauth_failed", "connection refused", "login failed",
        "failure to authenticate", "could not authenticate",
        "access denied", "status_logon_failure", "status_access_denied",
        "unknown error code", "rpc_s_access_denied",
    ]

    def _run_local_captured(self, cmd_str: str, tool_path: str) -> bool:
        """Run tool and capture + stream output."""
        script = self._tool_config["script"]
        full_cmd = cmd_str.replace(script, tool_path, 1)

        try:
            process = subprocess.Popen(
                shlex.split(full_cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            has_error = False
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    line = line.rstrip()
                    line_lower = line.lower()
                    if any(pat in line_lower for pat in self._ERROR_PATTERNS):
                        has_error = True
                    if "[+]" in line or "Pwn3d!" in line:
                        self.print_good(line)
                    elif "[-]" in line:
                        self.print_error(line)
                    elif "[*]" in line:
                        self.print_status(line.replace("[*]", "").strip())
                    elif "[!]" in line:
                        self.print_warning(line.replace("[!]", "").strip())
                    else:
                        self.print_line(f"    {line}")

            if has_error:
                return False
            return process.returncode == 0

        except Exception as e:
            self.print_error(f"Error: {e}")
            return False

    def check(self) -> bool:
        """Check if impacket tool is available locally or via Exegol."""
        script = self._tool_config["script"]
        if find_tool(script):
            return True
        # Check Exegol
        ret, stdout, stderr = self.run_in_exegol(f"which {script}", timeout=10)
        return ret == 0


# =============================================================================
# Virtual Module Registry
# =============================================================================
# Auto-registers all IMPACKET_TOOLS entries as modules so individual stub
# files are unnecessary. The ModuleLoader detects this dict and creates
# ModuleInfo entries with virtual_key set, then instantiates ImpacketModule
# with the tool_key at load time.

VIRTUAL_MODULES = {
    f"impacket/{key}": {
        "name": f"impacket_{key}",
        "description": config["description"],
        "tags": ["impacket", config["category_tag"], key],
        "platform": "windows",
        "author": "UwU Toolkit",
        "tool_key": key,
        "alias": f"auxiliary/impacket/{key}",
    }
    for key, config in IMPACKET_TOOLS.items()
}
