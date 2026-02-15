"""
OPSEC Rating System for UwU Toolkit

Provides detection awareness so operators (and AI agents) can make informed
decisions about which tools and techniques to use during engagements.

Each tool/technique is mapped to a DetectionInfo profile containing:
- OPSEC rating (STEALTH through LOUD)
- Artifacts left behind (files, services, registry keys, log entries)
- Windows Event IDs generated
- Known detection rules (Sigma, YARA, vendor)
- Quieter alternatives
- Risk mitigation advice

Usage:
    from core.opsec import get_opsec_info, format_opsec_warning, compare_tools

    # Quick warning before running a tool
    print(format_opsec_warning("psexec"))

    # Compare alternatives
    print(compare_tools(["psexec", "wmiexec", "dcomexec", "atexec"]))

    # Programmatic lookup
    info = get_opsec_info("secretsdump")
    if info and info.rating in (OpsecRating.HIGH, OpsecRating.LOUD):
        print("Consider a quieter approach")
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class OpsecRating(Enum):
    """Operational security rating for tools and techniques.

    Ratings reflect the likelihood of detection by a mature SOC with
    standard EDR/SIEM tooling deployed.
    """
    STEALTH = "stealth"   # Passive/read-only, no network artifacts beyond normal traffic
    LOW = "low"           # Minimal artifacts, blends with normal traffic patterns
    MEDIUM = "medium"     # Some artifacts, moderately detectable with tuned rules
    HIGH = "high"         # Creates services/files, generates security events
    LOUD = "loud"         # Mass scanning, relay attacks, obvious IOCs


@dataclass
class DetectionInfo:
    """Detection profile for a tool or technique.

    Attributes:
        rating:          Overall OPSEC rating.
        description:     Human-readable summary of detection characteristics.
        artifacts:       What gets left behind (files, services, registry, logs).
        event_ids:       Windows Event IDs generated (e.g. "4624", "7045").
        detection_rules: Known Sigma/YARA/vendor rules that catch this.
        alternatives:    List of (tool_name, rating, notes) for quieter options.
        mitigations:     How to reduce detection risk when using this tool.
    """
    rating: OpsecRating
    description: str
    artifacts: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    detection_rules: List[str] = field(default_factory=list)
    alternatives: List[Tuple[str, OpsecRating, str]] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Alias Table
# ---------------------------------------------------------------------------
# Maps common name variants to canonical keys in OPSEC_REGISTRY.
# Lookup is case-insensitive; aliases are stored lowercase.

_ALIASES: Dict[str, str] = {
    # LDAP
    "ldapsearch": "ldap_query",
    "ldap": "ldap_query",
    "ldap_search": "ldap_query",
    "ldap_queries": "ldap_query",
    "ldap query": "ldap_query",
    "ldap queries": "ldap_query",

    # BloodHound
    "bloodhound": "bloodhound_collection",
    "sharphound": "bloodhound_collection",
    "bloodhound-python": "bloodhound_collection",
    "bloodhound.py": "bloodhound_collection",
    "bh": "bloodhound_collection",

    # Kerberoasting
    "kerberoast": "kerberoasting",
    "getuserspns": "kerberoasting",
    "getuserspns.py": "kerberoasting",
    "impacket_getuserspns": "kerberoasting",
    "impacket-getuserspns": "kerberoasting",
    "invoke-kerberoast": "kerberoasting",
    "rubeus_kerberoast": "kerberoasting",

    # AS-REP Roasting
    "asreproast": "asrep_roasting",
    "asrep_roast": "asrep_roasting",
    "as-rep roasting": "asrep_roasting",
    "getnpusers": "asrep_roasting",
    "getnpusers.py": "asrep_roasting",
    "impacket_getnpusers": "asrep_roasting",
    "impacket-getnpusers": "asrep_roasting",

    # Nmap SYN
    "nmap": "nmap_syn",
    "nmap_syn": "nmap_syn",
    "nmap syn": "nmap_syn",
    "nmap syn scan": "nmap_syn",
    "nmap -ss": "nmap_syn",

    # Nmap version
    "nmap_version": "nmap_version",
    "nmap version scan": "nmap_version",
    "nmap -sv": "nmap_version",
    "nmap version": "nmap_version",
    "nmap_service": "nmap_version",

    # NetExec SMB
    "netexec": "netexec_smb",
    "nxc": "netexec_smb",
    "nxc_smb": "netexec_smb",
    "netexec smb": "netexec_smb",
    "netexec_smb": "netexec_smb",
    "crackmapexec": "netexec_smb",
    "cme": "netexec_smb",

    # Pass-the-Hash
    "pth": "pass_the_hash",
    "pass the hash": "pass_the_hash",
    "pass-the-hash": "pass_the_hash",
    "overpass-the-hash": "pass_the_hash",

    # WMI exec
    "wmiexec": "wmi_exec",
    "wmiexec.py": "wmi_exec",
    "impacket_wmiexec": "wmi_exec",
    "impacket-wmiexec": "wmi_exec",
    "wmi exec": "wmi_exec",
    "wmi": "wmi_exec",

    # DCOM exec
    "dcomexec": "dcom_exec",
    "dcomexec.py": "dcom_exec",
    "impacket_dcomexec": "dcom_exec",
    "impacket-dcomexec": "dcom_exec",
    "dcom exec": "dcom_exec",
    "dcom": "dcom_exec",

    # SMB exec
    "smbexec": "smb_exec",
    "smbexec.py": "smb_exec",
    "impacket_smbexec": "smb_exec",
    "impacket-smbexec": "smb_exec",
    "smb exec": "smb_exec",

    # PsExec
    "psexec": "psexec",
    "psexec.py": "psexec",
    "impacket_psexec": "psexec",
    "impacket-psexec": "psexec",
    "sysinternals_psexec": "psexec",
    "paexec": "psexec",

    # Secretsdump remote
    "secretsdump": "secretsdump_remote",
    "secretsdump.py": "secretsdump_remote",
    "impacket_secretsdump": "secretsdump_remote",
    "impacket-secretsdump": "secretsdump_remote",
    "secretsdump remote": "secretsdump_remote",
    "secretsdump_drsuapi": "secretsdump_remote",
    "ntds dump": "secretsdump_remote",
    "ntds": "secretsdump_remote",

    # Secretsdump local
    "secretsdump local": "secretsdump_local",
    "secretsdump_local": "secretsdump_local",
    "secretsdump sam": "secretsdump_local",
    "sam dump": "secretsdump_local",
    "sam": "secretsdump_local",
    "reg save": "secretsdump_local",

    # Evil-WinRM
    "evil-winrm": "evil_winrm",
    "evilwinrm": "evil_winrm",
    "evil_winrm": "evil_winrm",
    "winrm": "evil_winrm",

    # Certipy find
    "certipy": "certipy_find",
    "certipy find": "certipy_find",
    "certipy_find": "certipy_find",
    "adcs enum": "certipy_find",
    "adcs_enum": "certipy_find",

    # Certipy request
    "certipy req": "certipy_request",
    "certipy_req": "certipy_request",
    "certipy request": "certipy_request",
    "certipy_request": "certipy_request",
    "adcs request": "certipy_request",
    "esc1": "certipy_request",
    "esc2": "certipy_request",
    "esc3": "certipy_request",

    # Shadow Credentials
    "shadow_credentials": "shadow_credentials",
    "shadow credentials": "shadow_credentials",
    "shadow creds": "shadow_credentials",
    "certipy shadow": "shadow_credentials",
    "certipy_shadow": "shadow_credentials",
    "whisker": "shadow_credentials",
    "pywhisker": "shadow_credentials",

    # NTLM Relay
    "ntlm_relay": "ntlm_relay",
    "ntlm relay": "ntlm_relay",
    "ntlmrelayx": "ntlm_relay",
    "ntlmrelayx.py": "ntlm_relay",
    "impacket_ntlmrelayx": "ntlm_relay",
    "relay": "ntlm_relay",

    # Responder
    "responder": "responder",
    "responder.py": "responder",

    # DCSync
    "dcsync": "dcsync",
    "dc sync": "dcsync",
    "mimikatz dcsync": "dcsync",
    "lsadump::dcsync": "dcsync",

    # Golden Ticket
    "golden_ticket": "golden_ticket",
    "golden ticket": "golden_ticket",
    "kerberos::golden": "golden_ticket",
    "ticketer.py": "golden_ticket",
    "impacket_ticketer": "golden_ticket",

    # Silver Ticket
    "silver_ticket": "silver_ticket",
    "silver ticket": "silver_ticket",
    "kerberos::silver": "silver_ticket",

    # RBCD
    "rbcd": "rbcd_abuse",
    "rbcd abuse": "rbcd_abuse",
    "rbcd_abuse": "rbcd_abuse",
    "resource-based constrained delegation": "rbcd_abuse",
    "impacket_rbcd": "rbcd_abuse",

    # GPO Abuse
    "gpo_abuse": "gpo_abuse",
    "gpo abuse": "gpo_abuse",
    "gpo": "gpo_abuse",
    "sharpgpoabuse": "gpo_abuse",
    "pygpoabuse": "gpo_abuse",

    # Password Spraying
    "password_spray": "password_spraying",
    "password spray": "password_spraying",
    "password spraying": "password_spraying",
    "spray": "password_spraying",
    "kerbrute": "password_spraying",
    "spray_passwords": "password_spraying",

    # SSH Brute Force
    "ssh_brute": "ssh_bruteforce",
    "ssh brute": "ssh_bruteforce",
    "ssh brute force": "ssh_bruteforce",
    "ssh bruteforce": "ssh_bruteforce",
    "hydra ssh": "ssh_bruteforce",
    "medusa ssh": "ssh_bruteforce",

    # Port Forwarding
    "ligolo": "port_forwarding",
    "chisel": "port_forwarding",
    "port forwarding": "port_forwarding",
    "port_forwarding": "port_forwarding",
    "tunnel": "port_forwarding",
    "tunneling": "port_forwarding",
    "socat": "port_forwarding",
    "ssh tunnel": "port_forwarding",
    "ssh -l": "port_forwarding",

    # BloodyAD read
    "bloodyad": "bloodyad_read",
    "bloodyad read": "bloodyad_read",
    "bloodyad_read": "bloodyad_read",
    "bloodyad enum": "bloodyad_read",
    "bloodyad acl enum": "bloodyad_read",

    # BloodyAD write
    "bloodyad write": "bloodyad_write",
    "bloodyad_write": "bloodyad_write",
    "bloodyad acl write": "bloodyad_write",
    "bloodyad set": "bloodyad_write",

    # atexec
    "atexec": "atexec",
    "atexec.py": "atexec",
    "impacket_atexec": "atexec",
    "impacket-atexec": "atexec",

    # Mimikatz
    "mimikatz": "mimikatz",
    "sekurlsa::logonpasswords": "mimikatz",
    "logonpasswords": "mimikatz",

    # Rubeus
    "rubeus": "rubeus",

    # DACL edit
    "dacledit": "dacl_edit",
    "dacledit.py": "dacl_edit",
    "impacket_dacledit": "dacl_edit",
    "impacket-dacledit": "dacl_edit",
    "acl edit": "dacl_edit",
    "acl abuse": "dacl_edit",
}


# ---------------------------------------------------------------------------
# OPSEC Registry
# ---------------------------------------------------------------------------

OPSEC_REGISTRY: Dict[str, DetectionInfo] = {

    # -----------------------------------------------------------------------
    # STEALTH
    # -----------------------------------------------------------------------

    "ldap_query": DetectionInfo(
        rating=OpsecRating.STEALTH,
        description=(
            "Standard LDAP queries against Active Directory. Indistinguishable "
            "from normal domain-joined workstation traffic. Every domain member "
            "performs LDAP lookups routinely."
        ),
        artifacts=[
            "LDAP bind on port 389/636",
            "Directory service access log (if verbose audit enabled)",
        ],
        event_ids=[
            "1644 (only with expensive LDAP diagnostics enabled)",
        ],
        detection_rules=[
            "Sigma: ldap_query_with_high_result_count (rarely deployed)",
        ],
        alternatives=[],
        mitigations=[
            "Use paged queries to avoid single large result sets",
            "Space out queries to blend with normal LDAP polling intervals",
            "Query from a domain-joined host for maximum blending",
        ],
    ),

    "bloodyad_read": DetectionInfo(
        rating=OpsecRating.STEALTH,
        description=(
            "BloodyAD ACL enumeration uses standard LDAP queries to read "
            "security descriptors and DACLs. Functionally identical to LDAP "
            "browsing tools like ADExplorer or PowerView Get-ObjectAcl."
        ),
        artifacts=[
            "LDAP bind on port 389/636",
            "nTSecurityDescriptor attribute reads",
        ],
        event_ids=[
            "1644 (only with Field Engineering LDAP diagnostics)",
        ],
        detection_rules=[],
        alternatives=[],
        mitigations=[
            "Run from a domain-joined host",
            "Avoid requesting all ACLs domain-wide in a short burst",
        ],
    ),

    # -----------------------------------------------------------------------
    # LOW
    # -----------------------------------------------------------------------

    "bloodhound_collection": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "BloodHound/SharpHound collection performs LDAP, SAMR, and "
            "NetSessionEnum queries in high volume. Individually each query "
            "is benign, but the volume and pattern is distinctive."
        ),
        artifacts=[
            "High-volume LDAP queries (users, groups, ACLs, trusts)",
            "SAMR enumeration of local groups on multiple hosts",
            "NetSessionEnum / NetWkstaUserEnum RPC calls",
            "SMB connections to each enumerated host",
        ],
        event_ids=[
            "4624 (Type 3 - network logon to each host)",
            "4661 (SAM object access, if audited)",
            "5145 (network share access for session enum)",
        ],
        detection_rules=[
            "Sigma: win_bloodhound_collection",
            "Sigma: win_sharphound_indicators",
            "MDI: Account enumeration reconnaissance",
            "MDI: Network-mapping reconnaissance (DNS/SMB)",
            "CrowdStrike: BloodHound activity detection",
        ],
        alternatives=[
            ("ldap_query", OpsecRating.STEALTH, "Manual LDAP queries for specific objects"),
            ("bloodyad_read", OpsecRating.STEALTH, "Targeted ACL reads via BloodyAD"),
        ],
        mitigations=[
            "Use --collectionmethod DCOnly to avoid touching workstations",
            "Use --stealth flag in SharpHound (queries one DC at a time)",
            "Limit collection to specific OUs with --ou",
            "Use bloodhound-python from Linux to avoid dropping .exe on disk",
            "Stagger collection over hours/days",
        ],
    ),

    "kerberoasting": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "Requests TGS tickets for accounts with SPNs. Each request is a "
            "legitimate Kerberos operation, but requesting RC4 (type 0x17) "
            "tickets is unusual in modern environments using AES."
        ),
        artifacts=[
            "TGS-REQ for service accounts (Kerberos port 88)",
            "Offline hash cracking activity (not visible to target)",
        ],
        event_ids=[
            "4769 (Kerberos Service Ticket Operation - ticket type 0x17 for RC4)",
        ],
        detection_rules=[
            "Sigma: win_kerberoasting_rc4_ticket_request",
            "Sigma: win_susp_kerberos_rc4_downgrade",
            "MDI: Kerberoasting suspicious activity",
            "Elastic: Kerberos Traffic from Unusual Process",
            "CrowdStrike: Kerberoasting activity",
        ],
        alternatives=[
            ("ldap_query", OpsecRating.STEALTH, "Enumerate SPNs via LDAP only (no ticket request)"),
        ],
        mitigations=[
            "Request AES256 (type 0x12) tickets instead of RC4 where possible",
            "Kerberoast only high-value targets, not all SPNs at once",
            "Space out requests over time",
            "Use a domain-joined host so TGS requests look normal",
        ],
    ),

    "asrep_roasting": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "Requests AS-REP responses for accounts without Kerberos "
            "pre-authentication. Similar to Kerberoasting, the RC4 encryption "
            "type is the main detection signal."
        ),
        artifacts=[
            "AS-REQ without pre-auth data (Kerberos port 88)",
            "Offline hash cracking activity (not visible to target)",
        ],
        event_ids=[
            "4768 (Kerberos Authentication Ticket - RC4 encryption type 0x17)",
        ],
        detection_rules=[
            "Sigma: win_asrep_roasting",
            "Sigma: win_kerberos_rc4_as_rep",
            "MDI: AS-REP Roasting suspicious activity",
        ],
        alternatives=[
            ("ldap_query", OpsecRating.STEALTH, "Enumerate DONT_REQ_PREAUTH via LDAP only"),
        ],
        mitigations=[
            "Target only specific accounts, not bulk enumeration",
            "Request from a domain-joined host",
        ],
    ),

    "nmap_syn": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "SYN scan (half-open) sends SYN packets and analyzes responses "
            "without completing the TCP handshake. Faster and slightly less "
            "visible than full connect scans, but still creates network "
            "anomalies detectable by IDS/IPS."
        ),
        artifacts=[
            "Half-open TCP connections (SYN without completing handshake)",
            "RST packets from scanner after receiving SYN-ACK",
            "High volume of connection attempts from single source",
        ],
        event_ids=[
            "5156 (Windows Filtering Platform connection allowed)",
            "5157 (Windows Filtering Platform connection blocked)",
        ],
        detection_rules=[
            "Snort/Suricata: portscan preprocessor / detect",
            "Sigma: net_connection_portscan",
            "Zeek: scan.log detection",
        ],
        alternatives=[
            ("ldap_query", OpsecRating.STEALTH, "Query AD for computer objects and SPNs to infer open ports"),
        ],
        mitigations=[
            "Scan only specific ports (-p 445,3389,5985) not all 65535",
            "Use --scan-delay or -T2 to slow scan rate",
            "Scan from an expected network segment",
            "Avoid scanning entire subnets; target specific hosts",
        ],
    ),

    "nmap_version": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Version detection (-sV) completes TCP connections and sends "
            "protocol-specific probes to identify services. Creates full "
            "connection logs and may trigger application-level alerts."
        ),
        artifacts=[
            "Full TCP connections to each probed port",
            "Protocol-specific probe strings in service logs",
            "HTTP requests with nmap user-agent or probe patterns",
            "Banner grabbing visible in application logs",
        ],
        event_ids=[
            "4624 (Type 3 for authenticated services)",
            "5156 (WFP connections)",
        ],
        detection_rules=[
            "Snort/Suricata: nmap service detection signatures",
            "Sigma: net_connection_portscan",
            "WAF rules detecting nmap HTTP probes",
            "Zeek: known scanner detection",
        ],
        alternatives=[
            ("nmap_syn", OpsecRating.LOW, "SYN scan for port discovery without service probing"),
            ("ldap_query", OpsecRating.STEALTH, "Query SPNs for service info passively"),
        ],
        mitigations=[
            "Use --version-intensity 0 for minimal probing",
            "Scan only ports you need version info on",
            "Avoid default scripts (-sC) which add more noise",
        ],
    ),

    "netexec_smb": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "NetExec (formerly CrackMapExec) SMB enumeration performs "
            "SMB authentication and can enumerate shares, users, sessions. "
            "Individual authentications are normal; mass enumeration across "
            "many hosts is more suspicious."
        ),
        artifacts=[
            "SMB authentication attempts (NTLM or Kerberos)",
            "Failed logon events if credentials are wrong",
            "Share enumeration via SRVSVC",
        ],
        event_ids=[
            "4624 (Type 3 - successful network logon)",
            "4625 (failed logon if wrong creds)",
            "4634 (logoff)",
            "5140/5145 (share access)",
        ],
        detection_rules=[
            "Sigma: win_multiple_logon_from_single_source",
            "Sigma: win_pass_the_hash_logon",
            "MDI: Lateral movement via pass-the-hash/pass-the-ticket",
        ],
        alternatives=[
            ("ldap_query", OpsecRating.STEALTH, "Enumerate computer accounts and shares via LDAP"),
            ("bloodyad_read", OpsecRating.STEALTH, "ACL checks without SMB authentication"),
        ],
        mitigations=[
            "Authenticate to only a few targeted hosts, not entire subnets",
            "Use Kerberos auth (-k) instead of NTLM to avoid pass-the-hash alerts",
            "Avoid --continue-on-success with password spraying",
        ],
    ),

    "certipy_find": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "Certipy find enumerates ADCS certificate templates, CAs, and "
            "configurations via LDAP. Queries the PKI containers in the "
            "Configuration naming context, which is normal AD admin activity."
        ),
        artifacts=[
            "LDAP queries to CN=Public Key Services,CN=Services,CN=Configuration",
            "Certificate template attribute reads",
        ],
        event_ids=[
            "1644 (expensive LDAP query, rarely enabled)",
        ],
        detection_rules=[
            "Sigma: win_adcs_enumeration (high false positive rate)",
        ],
        alternatives=[],
        mitigations=[
            "Run from a domain-joined host",
            "Normal ADCS admin activity looks identical",
        ],
    ),

    "port_forwarding": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "Port forwarding tools (ligolo-ng, chisel, socat, SSH tunnels) "
            "create encrypted tunnels for pivoting. The tunnel traffic itself "
            "is encrypted and hard to inspect, but the outbound connection "
            "pattern may be unusual."
        ),
        artifacts=[
            "Outbound connection to attacker infrastructure",
            "Persistent TCP/TLS connection (long-lived session)",
            "Process running on pivot host (ligolo-agent, chisel, socat)",
            "Unusual listening ports on pivot host",
        ],
        event_ids=[
            "5156 (WFP outbound connection)",
            "4688 (process creation for tunnel binary)",
            "3 (Sysmon network connection)",
        ],
        detection_rules=[
            "Sigma: proc_creation_win_chisel",
            "Sigma: proc_creation_win_ligolo",
            "Zeek: long-lived encrypted session detection",
            "EDR: unknown binary establishing outbound tunnel",
        ],
        alternatives=[],
        mitigations=[
            "Use common ports (443, 8443) to blend with HTTPS traffic",
            "Rename tunnel binary to something innocuous",
            "Use SSH tunnels where SSH access is expected",
            "Clean up tunnel processes after use",
        ],
    ),

    "atexec": DetectionInfo(
        rating=OpsecRating.LOW,
        description=(
            "atexec.py creates a scheduled task via the ATSVC named pipe "
            "to execute a command. The task is short-lived and auto-deletes, "
            "leaving fewer artifacts than PsExec or smbexec. Output is "
            "written to a temp file on the target."
        ),
        artifacts=[
            "Scheduled task creation and deletion",
            "Temp file in C:\\Windows\\Temp for command output",
            "SMB connection for task registration and output retrieval",
        ],
        event_ids=[
            "4624 (Type 3 - network logon)",
            "4698 (scheduled task created)",
            "4699 (scheduled task deleted)",
            "4688 (process creation: cmd.exe)",
        ],
        detection_rules=[
            "Sigma: win_task_creation_from_remote",
            "Sigma: win_susp_scheduled_task_creation",
        ],
        alternatives=[
            ("wmi_exec", OpsecRating.MEDIUM, "WMI execution without scheduled tasks"),
            ("dcom_exec", OpsecRating.MEDIUM, "DCOM execution, different artifact profile"),
        ],
        mitigations=[
            "Output file is auto-cleaned but verify removal",
            "Task name can be randomized",
        ],
    ),

    # -----------------------------------------------------------------------
    # MEDIUM
    # -----------------------------------------------------------------------

    "pass_the_hash": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Pass-the-Hash uses NTLM authentication with a stolen hash "
            "instead of a plaintext password. The authentication itself is "
            "legitimate NTLM, but the absence of a corresponding interactive "
            "logon (4648) is a detection signal."
        ),
        artifacts=[
            "NTLM authentication (Type 3 network logon)",
            "No corresponding Type 2 (interactive) or Type 10 (RDP) logon",
            "Logon from unexpected source for the account",
        ],
        event_ids=[
            "4624 (Type 3 - network logon with NTLM, NtLmSsp package)",
            "4672 (special privileges assigned - if admin account)",
        ],
        detection_rules=[
            "Sigma: win_pass_the_hash",
            "Sigma: win_susp_ntlm_logon_type3",
            "MDI: Pass-the-Hash lateral movement",
            "CrowdStrike: Pass-the-Hash activity",
            "Elastic: PtH Activity",
        ],
        alternatives=[
            ("kerberoasting", OpsecRating.LOW, "If target has SPN, crack hash offline instead"),
        ],
        mitigations=[
            "Use Kerberos authentication (overpass-the-hash) instead of raw NTLM",
            "Use the hash from expected source workstations for the account",
            "Avoid using built-in Administrator (RID 500) which stands out in logs",
        ],
    ),

    "wmi_exec": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "WMI-based remote execution uses DCOM/WMI to create processes. "
            "Does not create a service or drop a binary, but WMI process "
            "creation is logged and WMI activity is monitored by EDR."
        ),
        artifacts=[
            "WMI process creation via Win32_Process.Create",
            "DCOM connection on port 135 + high ephemeral port",
            "wmiprvse.exe spawning child process on target",
            "Command output written to temp file (Impacket wmiexec)",
        ],
        event_ids=[
            "4624 (Type 3 - network logon)",
            "4688 (process creation under wmiprvse.exe)",
            "4672 (special privileges)",
            "1 (Sysmon process creation - parent: wmiprvse.exe)",
            "5857/5858 (WMI-Activity operational log)",
        ],
        detection_rules=[
            "Sigma: win_wmi_process_creation",
            "Sigma: win_wmiprvse_spawning_process",
            "MDI: Remote code execution over WMI",
            "Elastic: WMI Command Execution",
            "CrowdStrike: WMI lateral movement",
        ],
        alternatives=[
            ("atexec", OpsecRating.LOW, "Scheduled task-based, different artifact profile"),
            ("dcom_exec", OpsecRating.MEDIUM, "DCOM objects, avoids WMI-specific logging"),
            ("evil_winrm", OpsecRating.MEDIUM, "WinRM if port 5985/5986 is available"),
        ],
        mitigations=[
            "Semi-interactive mode leaves fewer artifacts than full shell",
            "Use Kerberos auth to avoid NTLM pass-the-hash signatures",
            "Output file cleanup (Impacket handles this automatically)",
        ],
    ),

    "dcom_exec": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "DCOM-based execution leverages COM objects (MMC20.Application, "
            "ShellWindows, ShellBrowserWindow) for remote process creation. "
            "Uses DCOM on port 135 + ephemeral ports. Less commonly monitored "
            "than WMI or PsExec."
        ),
        artifacts=[
            "DCOM connection on port 135 + high ephemeral port",
            "COM object instantiation on target (mmc.exe, explorer.exe)",
            "Process creation under DCOM server process",
        ],
        event_ids=[
            "4624 (Type 3 - network logon)",
            "4688 (process creation)",
            "4672 (special privileges)",
            "1 (Sysmon process creation - parent depends on DCOM object)",
        ],
        detection_rules=[
            "Sigma: win_dcom_lateral_movement",
            "Sigma: win_mmc_process_creation",
            "Elastic: Execution via DCOM",
        ],
        alternatives=[
            ("wmi_exec", OpsecRating.MEDIUM, "WMI execution, similar noise level"),
            ("atexec", OpsecRating.LOW, "Scheduled tasks, fewer persistent artifacts"),
            ("evil_winrm", OpsecRating.MEDIUM, "WinRM if available, more expected protocol"),
        ],
        mitigations=[
            "ShellBrowserWindow and ShellWindows are less monitored than MMC20",
            "Use Kerberos authentication",
            "DCOM is less commonly included in detection rules than WMI/PsExec",
        ],
    ),

    "smb_exec": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "smbexec creates a Windows service that pipes commands through "
            "cmd.exe. Similar to PsExec but does not upload a binary -- it "
            "uses the built-in cmd.exe. Service creation generates 7045 events."
        ),
        artifacts=[
            "Windows service creation (name is random/configurable)",
            "Service runs cmd.exe /Q /c with echo-based output redirection",
            "Temp file in C:\\Windows\\Temp for output (named __output)",
            "Service deletion after command execution",
        ],
        event_ids=[
            "4624 (Type 3 - network logon)",
            "7045 (new service installed)",
            "4697 (service installed in the system, if enabled)",
            "4688 (process creation: cmd.exe, services.exe)",
            "7036 (service state change)",
        ],
        detection_rules=[
            "Sigma: win_service_creation_cmd",
            "Sigma: win_smbexec_service",
            "Sigma: win_susp_service_path_cmd",
            "EDR: service running cmd.exe with echo-pipe pattern",
        ],
        alternatives=[
            ("wmi_exec", OpsecRating.MEDIUM, "No service creation, uses WMI"),
            ("dcom_exec", OpsecRating.MEDIUM, "No service creation, uses DCOM"),
            ("atexec", OpsecRating.LOW, "Scheduled tasks instead of services"),
        ],
        mitigations=[
            "Service creation is a strong IOC -- prefer alternatives when possible",
            "Use a plausible service name if you must use smbexec",
        ],
    ),

    "evil_winrm": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Evil-WinRM connects via WinRM (WS-Management) on port 5985 "
            "(HTTP) or 5986 (HTTPS). WinRM is a legitimate management "
            "protocol and connections may blend with admin traffic. However, "
            "PowerShell script block logging captures all commands."
        ),
        artifacts=[
            "WinRM connection on port 5985/5986",
            "PowerShell session creation",
            "PowerShell script block logging captures all commands",
            "PowerShell module logging",
        ],
        event_ids=[
            "4624 (Type 3 - network logon)",
            "4648 (explicit credential logon)",
            "91 (WSMan session creation)",
            "4103 (PowerShell module logging)",
            "4104 (PowerShell script block logging)",
            "6 (WSMan creating new shell)",
        ],
        detection_rules=[
            "Sigma: win_winrm_remote_session",
            "Sigma: posh_script_block_suspicious",
            "MDI: Remote code execution via WinRM",
            "Elastic: Incoming WinRM Connection",
        ],
        alternatives=[
            ("wmi_exec", OpsecRating.MEDIUM, "WMI execution avoids PowerShell logging"),
            ("dcom_exec", OpsecRating.MEDIUM, "DCOM avoids WinRM/PowerShell artifacts"),
        ],
        mitigations=[
            "Use HTTPS (5986) to encrypt traffic on the wire",
            "Commands are logged in ScriptBlock -- keep operations minimal",
            "Use built-in PowerShell cmdlets to blend with admin activity",
            "Clear PowerShell event logs if post-exploitation cleanup is needed",
        ],
    ),

    "certipy_request": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Certificate enrollment request to ADCS. Requesting a certificate "
            "with an alternative UPN/SAN (for ESC1/ESC2/ESC3) triggers "
            "enrollment events that are logged by the CA. Certificate-based "
            "auth that follows is harder to detect."
        ),
        artifacts=[
            "Certificate enrollment request to CA",
            "Certificate with alternative identity (UPN/DNS) in subject",
            "PFX file stored locally (attacker side)",
        ],
        event_ids=[
            "4886 (Certificate Services received a certificate request)",
            "4887 (Certificate Services approved/issued a certificate request)",
            "4768 (Kerberos TGT request using PKINIT after cert auth)",
        ],
        detection_rules=[
            "Sigma: win_adcs_certificate_request_alternative_name",
            "Sigma: win_adcs_esc1_template_abuse",
            "MDI: Suspicious certificate enrollment",
            "Elastic: ADCS Certificate Request with Alternate Name",
        ],
        alternatives=[
            ("shadow_credentials", OpsecRating.MEDIUM, "Shadow Credentials if you have write access to target"),
        ],
        mitigations=[
            "The CA logs record the requesting user and template -- be aware of audit trails",
            "Post-exploitation: certificate-based auth (PKINIT) is less monitored than NTLM",
            "Certificates have validity periods -- shorter validity = less exposure time",
        ],
    ),

    "shadow_credentials": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Shadow Credentials attack writes to the msDS-KeyCredentialLink "
            "attribute of a target account, enabling certificate-based auth "
            "(PKINIT) as that account. The LDAP modification is logged if "
            "AD object change auditing is enabled."
        ),
        artifacts=[
            "msDS-KeyCredentialLink attribute modification on target object",
            "LDAP modify operation",
            "Subsequent PKINIT authentication with generated certificate",
        ],
        event_ids=[
            "5136 (directory service object modification - msDS-KeyCredentialLink)",
            "4768 (Kerberos TGT with PKINIT)",
            "4662 (AD object access)",
        ],
        detection_rules=[
            "Sigma: win_shadow_credentials",
            "Sigma: win_keycredentiallink_modification",
            "MDI: Shadow Credential addition",
            "Elastic: Key Credential Link Added to AD Account",
        ],
        alternatives=[
            ("certipy_request", OpsecRating.MEDIUM, "ADCS abuse if vulnerable template exists"),
            ("pass_the_hash", OpsecRating.MEDIUM, "If you already have the target hash"),
        ],
        mitigations=[
            "Clean up: remove the added KeyCredentialLink value after use",
            "Verify target account does not already have KeyCredentialLink values (modifications are more notable)",
            "Use Certipy shadow --auto for atomic add/auth/cleanup",
        ],
    ),

    "rbcd_abuse": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Resource-Based Constrained Delegation abuse modifies the "
            "msDS-AllowedToActOnBehalfOfOtherIdentity attribute on a target "
            "computer to allow delegation from an attacker-controlled account. "
            "Requires write permission to the target computer object."
        ),
        artifacts=[
            "msDS-AllowedToActOnBehalfOfOtherIdentity modification",
            "Computer account creation (if adding new machine account)",
            "S4U2Self and S4U2Proxy Kerberos requests",
        ],
        event_ids=[
            "5136 (directory service object modification)",
            "4662 (AD object access)",
            "4741 (computer account created, if addcomputer used)",
            "4769 (Kerberos service ticket for S4U2Proxy)",
        ],
        detection_rules=[
            "Sigma: win_rbcd_delegation_modification",
            "Sigma: win_ad_object_attribute_modification",
            "MDI: Resource-based constrained delegation modification",
            "Elastic: RBCD Delegation Attribute Change",
        ],
        alternatives=[
            ("shadow_credentials", OpsecRating.MEDIUM, "Shadow Credentials if ADCS is available"),
            ("certipy_request", OpsecRating.MEDIUM, "ADCS ESC1 if vulnerable template exists"),
        ],
        mitigations=[
            "Clean up: remove the RBCD attribute after obtaining access",
            "Clean up: remove the added computer account if no longer needed",
            "Use existing machine account instead of creating new one",
        ],
    ),

    "silver_ticket": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Silver Ticket forges a TGS (service ticket) using a service "
            "account's NTLM hash. Since the ticket is presented directly to "
            "the service without KDC involvement, there is no 4769 event on "
            "the DC. Detection requires service-side logging."
        ),
        artifacts=[
            "Forged TGS ticket presented to target service",
            "No KDC interaction (no 4769 on DC)",
            "Possible PAC validation failure if PAC validation is enabled",
        ],
        event_ids=[
            "4624 (Type 3 on target host with Kerberos auth)",
            "4672 (special privileges if admin ticket)",
        ],
        detection_rules=[
            "Sigma: win_silver_ticket (limited, requires PAC validation)",
            "MDI: Silver ticket usage (if PAC validation enabled)",
            "Service-side: ticket without matching TGT",
        ],
        alternatives=[],
        mitigations=[
            "Silver tickets bypass DC logging -- detection is service-side only",
            "Set realistic ticket lifetimes",
            "Match the SID and domain info exactly to avoid PAC mismatches",
            "PAC validation (rare in practice) can catch forged tickets",
        ],
    ),

    "secretsdump_local": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Local SAM/LSA secrets extraction via registry hive access. "
            "Reads SYSTEM, SAM, and SECURITY hives from the registry or "
            "saved files. Requires local admin but does not contact a DC."
        ),
        artifacts=[
            "Registry hive access (HKLM\\SAM, HKLM\\SECURITY, HKLM\\SYSTEM)",
            "reg.exe or reg save commands (if saving hives to disk)",
            "Hive files on disk (SAM, SYSTEM, SECURITY) if exported",
        ],
        event_ids=[
            "4656 (handle to SAM registry key)",
            "4663 (access to SAM registry key)",
            "4688 (process creation: reg.exe save)",
        ],
        detection_rules=[
            "Sigma: win_sam_registry_hive_access",
            "Sigma: win_reg_save_sam",
            "EDR: Registry hive dump detection",
            "Elastic: SAM Registry Hive Access",
        ],
        alternatives=[],
        mitigations=[
            "Use Volume Shadow Copy access instead of direct registry reads",
            "Clean up any saved .hiv files immediately",
            "Run from memory without touching disk (mimikatz, in-process)",
        ],
    ),

    "bloodyad_write": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "BloodyAD ACL write operations modify DACLs or object attributes "
            "in Active Directory. Writes to security descriptors, group "
            "membership, or object attributes are logged by directory service "
            "change auditing."
        ),
        artifacts=[
            "LDAP modify operation on target object",
            "DACL/ACE modification on AD object",
            "Attribute changes (group membership, passwords, etc.)",
        ],
        event_ids=[
            "5136 (directory service object modification)",
            "4662 (AD object access - write)",
            "4728/4732/4756 (member added to group)",
        ],
        detection_rules=[
            "Sigma: win_ad_dacl_modification",
            "Sigma: win_ad_object_attribute_modification",
            "MDI: Suspicious DACL changes",
        ],
        alternatives=[],
        mitigations=[
            "Revert DACL changes after exploitation to reduce forensic trail",
            "Make targeted changes rather than broad permission grants",
            "Changes to high-value objects (Domain Admins, DCs) are more scrutinized",
        ],
    ),

    "dacl_edit": DetectionInfo(
        rating=OpsecRating.MEDIUM,
        description=(
            "Impacket dacledit.py modifies DACLs on AD objects to grant "
            "permissions (GenericAll, WriteDACL, DCSync rights, etc.). "
            "DACL changes on sensitive objects are a strong detection signal."
        ),
        artifacts=[
            "DACL/ACE modification via LDAP",
            "New ACE added to object security descriptor",
        ],
        event_ids=[
            "5136 (directory service object modification)",
            "4662 (AD object access)",
        ],
        detection_rules=[
            "Sigma: win_ad_dacl_modification",
            "Sigma: win_suspicious_dacl_change",
            "MDI: Suspicious DACL modification",
            "Elastic: AD Object Permission Change",
        ],
        alternatives=[
            ("bloodyad_write", OpsecRating.MEDIUM, "BloodyAD for same operation, same detection"),
        ],
        mitigations=[
            "Revert ACL changes immediately after achieving objective",
            "Target specific rights (e.g., WriteProperty) instead of GenericAll",
            "Changes to domain root, AdminSDHolder, or DA group are highly monitored",
        ],
    ),

    # -----------------------------------------------------------------------
    # HIGH
    # -----------------------------------------------------------------------

    "psexec": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "PsExec (Sysinternals or Impacket) uploads a service binary to "
            "the ADMIN$ share, creates and starts a Windows service, and "
            "communicates via named pipes. This is one of the most detected "
            "lateral movement techniques."
        ),
        artifacts=[
            "Binary uploaded to \\\\target\\ADMIN$ (e.g., PSEXESVC.exe or random name)",
            "Windows service creation and start (services.exe spawning child)",
            "Named pipe communication (\\\\pipe\\svcctl, \\\\pipe\\RemCom*)",
            "Service binary remains on disk until cleanup",
            "Service entry in SYSTEM registry hive",
        ],
        event_ids=[
            "4624 (Type 3 - network logon)",
            "7045 (new service installed in the system)",
            "4697 (service installed, if auditing enabled)",
            "4688 (process creation: services.exe -> service binary)",
            "5145 (network share access: ADMIN$)",
            "7036 (service state change: running/stopped)",
            "17/18 (Sysmon named pipe created/connected)",
        ],
        detection_rules=[
            "Sigma: win_psexec_service_installation",
            "Sigma: win_susp_service_binary_upload",
            "Sigma: win_admin_share_access",
            "Sigma: win_psexec_named_pipe",
            "MDI: Remote code execution via PsExec",
            "CrowdStrike: PsExec lateral movement",
            "SentinelOne: PsExec execution pattern",
            "Elastic: PsExec Service Created",
            "YARA: Sysinternals PsExec binary",
        ],
        alternatives=[
            ("wmi_exec", OpsecRating.MEDIUM, "No service creation, no binary upload"),
            ("dcom_exec", OpsecRating.MEDIUM, "No service creation, uses DCOM objects"),
            ("atexec", OpsecRating.LOW, "Scheduled task-based, self-cleaning"),
            ("evil_winrm", OpsecRating.MEDIUM, "WinRM if port 5985 available"),
        ],
        mitigations=[
            "Use -servicename to set a legitimate-looking service name",
            "Impacket psexec -file to use custom binary instead of default",
            "Clean up service and binary immediately after use",
            "Consider alternatives -- psexec is the #1 detected lateral movement tool",
        ],
    ),

    "secretsdump_remote": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "Remote secretsdump uses DRSUAPI (Directory Replication Service) "
            "to replicate password hashes from a Domain Controller -- the same "
            "protocol as DCSync. Non-DC machines requesting replication is a "
            "critical alert in any mature SOC."
        ),
        artifacts=[
            "DRSUAPI RPC calls (DRSGetNCChanges)",
            "Replication request from non-DC source",
            "Full domain hash dump transferred over network",
        ],
        event_ids=[
            "4662 (DS-Replication-Get-Changes / DS-Replication-Get-Changes-All)",
            "4624 (Type 3 - network logon to DC)",
            "4672 (special privileges: replication rights)",
        ],
        detection_rules=[
            "Sigma: win_dcsync_replication",
            "Sigma: win_ad_replication_non_dc",
            "MDI: Suspected DCSync attack",
            "CrowdStrike: DCSync replication activity",
            "Elastic: DRSR Replication from Non-DC",
            "Splunk: DCSync detection rule",
        ],
        alternatives=[
            ("secretsdump_local", OpsecRating.MEDIUM, "Dump locally with SYSTEM access on DC"),
            ("kerberoasting", OpsecRating.LOW, "Crack service account hashes offline"),
        ],
        mitigations=[
            "This technique is very likely to trigger alerts -- use as last resort",
            "If you have SYSTEM on the DC, use local extraction instead",
            "Target specific users with --just-dc-user to minimize replication volume",
            "Use --just-dc-ntlm to skip Kerberos keys and reduce data transfer",
        ],
    ),

    "dcsync": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "DCSync uses the MS-DRSR protocol to simulate domain controller "
            "replication and extract password hashes. Functionally identical "
            "to secretsdump remote. Any non-DC requesting replication rights "
            "is a critical indicator."
        ),
        artifacts=[
            "DRSUAPI RPC calls (DRSGetNCChanges)",
            "Replication request from non-DC source IP",
            "DS-Replication-Get-Changes-All extended right usage",
        ],
        event_ids=[
            "4662 (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)",
            "4624 (Type 3 - logon to DC)",
        ],
        detection_rules=[
            "Sigma: win_dcsync_replication",
            "Sigma: win_ad_replication_non_dc",
            "MDI: Suspected DCSync attack (replication from non-machine account)",
            "CrowdStrike: DCSync activity",
            "Elastic: Potential Credential Dumping via DCSync",
        ],
        alternatives=[
            ("secretsdump_local", OpsecRating.MEDIUM, "Local SAM/NTDS dump if you have SYSTEM on DC"),
            ("kerberoasting", OpsecRating.LOW, "Offline cracking for service accounts"),
        ],
        mitigations=[
            "Target specific accounts with --just-dc-user to reduce noise",
            "If possible, dump NTDS.dit locally on the DC instead",
            "Expect this to trigger alerts in any monitored environment",
        ],
    ),

    "golden_ticket": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "Golden Ticket forges a TGT using the krbtgt hash, providing "
            "unrestricted domain access. The forged TGT may have anomalous "
            "properties (lifetime, encryption type, PAC) that can be detected "
            "by the KDC during TGS requests."
        ),
        artifacts=[
            "Forged TGT with krbtgt encryption",
            "TGS requests using the forged TGT",
            "Anomalous ticket properties (lifetime, groups, SID history)",
        ],
        event_ids=[
            "4768 (TGT request -- anomalous if forged ticket used for TGS without prior AS-REQ)",
            "4769 (TGS request using forged TGT)",
            "4672 (special privileges from forged PAC)",
        ],
        detection_rules=[
            "Sigma: win_golden_ticket_usage",
            "Sigma: win_kerberos_anomalous_ticket",
            "MDI: Golden Ticket activity",
            "MDI: Suspicious Kerberos ticket (ticket lifetime anomaly)",
            "CrowdStrike: Golden Ticket forge",
            "Elastic: Potential Golden Ticket Attack",
        ],
        alternatives=[
            ("silver_ticket", OpsecRating.MEDIUM, "Silver ticket for specific service, no KDC interaction"),
            ("dcsync", OpsecRating.HIGH, "Extract specific hashes instead of persistent access"),
        ],
        mitigations=[
            "Set realistic ticket lifetimes matching domain policy",
            "Include correct group memberships (don't add extra groups)",
            "Rotate krbtgt twice after engagement to invalidate golden tickets",
            "Use diamond ticket (modify legitimate TGT) for harder detection",
        ],
    ),

    "gpo_abuse": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "GPO abuse modifies Group Policy Objects to push malicious "
            "configurations (scheduled tasks, scripts, user rights) to "
            "domain computers. GPO modifications are heavily logged and "
            "monitored in mature environments."
        ),
        artifacts=[
            "GPO modification in SYSVOL (GptTmpl.inf, ScheduledTasks.xml, etc.)",
            "AD object modification (gPCFileSysPath, versionNumber)",
            "SYSVOL replication of modified files",
            "Policy application on target machines",
        ],
        event_ids=[
            "5136 (directory service object modification - GPO object)",
            "5145 (SYSVOL share access for GPO file modification)",
            "4688 (gpupdate process on targets)",
            "4698 (scheduled task created via GPO)",
        ],
        detection_rules=[
            "Sigma: win_gpo_modification",
            "Sigma: win_gpo_scheduledtask",
            "MDI: Suspicious GPO modification",
            "Elastic: Group Policy Modification",
            "Splunk: GPO Permission Change",
        ],
        alternatives=[
            ("wmi_exec", OpsecRating.MEDIUM, "Direct execution without modifying group policy"),
            ("psexec", OpsecRating.HIGH, "Direct execution (still high, but no GPO changes)"),
        ],
        mitigations=[
            "Revert GPO changes immediately after exploitation",
            "Target a GPO linked to minimal OUs to limit scope",
            "GPO changes replicate -- harder to hide than other techniques",
        ],
    ),

    "password_spraying": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "Password spraying tries a small number of passwords against "
            "many accounts. Generates failed logon events and can trigger "
            "account lockout policies. Even slow sprays are detectable via "
            "aggregate analysis."
        ),
        artifacts=[
            "Multiple authentication attempts across many accounts",
            "Failed logon events for non-existent or locked accounts",
            "Account lockout events",
            "Pattern of same password across different users",
        ],
        event_ids=[
            "4625 (failed logon - wrong password)",
            "4771 (Kerberos pre-auth failed)",
            "4776 (NTLM credential validation)",
            "4740 (account lockout)",
        ],
        detection_rules=[
            "Sigma: win_password_spray",
            "Sigma: win_multiple_failed_logon",
            "Sigma: win_account_lockout_burst",
            "MDI: Password spray activity",
            "CrowdStrike: Brute force / password spray",
            "Elastic: Multiple Authentication Failures from Single Source",
        ],
        alternatives=[
            ("kerberoasting", OpsecRating.LOW, "Offline cracking of service accounts"),
            ("asrep_roasting", OpsecRating.LOW, "Offline cracking of no-preauth accounts"),
        ],
        mitigations=[
            "Use Kerberos pre-auth (kerbrute) to test passwords -- fewer logs than NTLM",
            "Stay well below lockout threshold (spray 1 password per 30+ minutes)",
            "Check lockout policy first: net accounts /domain",
            "Spray with known-valid usernames only to avoid unnecessary 4625s",
            "Use --jitter with kerbrute to randomize timing",
        ],
    ),

    "ssh_bruteforce": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "SSH brute force / credential stuffing generates high volumes "
            "of failed authentication attempts. SSH servers log every attempt "
            "and tools like fail2ban can auto-ban attacking IPs."
        ),
        artifacts=[
            "Failed SSH authentication attempts in auth.log/secure",
            "Connection attempts from single source IP",
            "fail2ban/DenyHosts bans",
        ],
        event_ids=[
            "4625 (failed logon on Windows SSH server)",
        ],
        detection_rules=[
            "Sigma: linux_ssh_bruteforce",
            "Sigma: linux_auth_failed_many",
            "fail2ban: sshd jail",
            "OSSEC: SSH brute force rule",
            "CrowdStrike: SSH brute force",
        ],
        alternatives=[
            ("password_spraying", OpsecRating.HIGH, "Still high, but Kerberos-based spray leaves fewer SSH artifacts"),
        ],
        mitigations=[
            "Use credential stuffing (known valid creds) instead of brute force",
            "Check for key-based auth first (keys don't trigger password failures)",
            "Extremely slow rate (1 attempt/minute+) to avoid fail2ban",
            "Use different source IPs if possible",
        ],
    ),

    "mimikatz": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "Mimikatz is extensively signatured by every major EDR/AV vendor. "
            "Memory access to LSASS, debug privilege usage, and the binary "
            "itself are all strong IOCs. Even in-memory execution is often "
            "caught by behavioral detection."
        ),
        artifacts=[
            "Process accessing lsass.exe memory",
            "SeDebugPrivilege usage",
            "Mimikatz binary on disk (if not in-memory)",
            "Credential material extracted from LSASS",
        ],
        event_ids=[
            "4688 (process creation: mimikatz.exe)",
            "4672 (SeDebugPrivilege assigned)",
            "10 (Sysmon process access to lsass.exe)",
            "4624/4648 (logon events from extracted credentials)",
        ],
        detection_rules=[
            "Sigma: win_mimikatz_process",
            "Sigma: win_lsass_access",
            "Sigma: win_debug_privilege",
            "YARA: mimikatz binary / strings",
            "Every major EDR/AV has mimikatz signatures",
            "CrowdStrike: Credential dumping via LSASS",
            "SentinelOne: Mimikatz credential theft",
        ],
        alternatives=[
            ("secretsdump_local", OpsecRating.MEDIUM, "Registry-based SAM dump, no LSASS touch"),
            ("kerberoasting", OpsecRating.LOW, "Offline cracking instead of credential extraction"),
        ],
        mitigations=[
            "Use alternatives when possible -- mimikatz is the most detected tool",
            "If required, use in-memory execution (PowerShell, BOF)",
            "Use LSASS dump via comsvcs.dll MiniDump and process offline",
            "nanodump or direct syscall tools evade some detections",
        ],
    ),

    "rubeus": DetectionInfo(
        rating=OpsecRating.HIGH,
        description=(
            "Rubeus is a C# Kerberos abuse toolkit. While individual Kerberos "
            "operations are legitimate, Rubeus is heavily signatured by EDR "
            "vendors. The .NET assembly loading and AMSI interaction create "
            "additional detection opportunities."
        ),
        artifacts=[
            "CLR/.NET assembly loading in unusual process",
            "Kerberos ticket requests and manipulation",
            "AMSI detection of Rubeus assembly",
            "In-memory .NET execution patterns",
        ],
        event_ids=[
            "4768/4769 (Kerberos operations)",
            "4688 (process creation)",
        ],
        detection_rules=[
            "Sigma: win_rubeus_activity",
            "YARA: Rubeus .NET assembly",
            "AMSI: Rubeus string detection",
            "EDR: .NET assembly loading in suspicious process",
            "CrowdStrike: Kerberos abuse via Rubeus",
        ],
        alternatives=[
            ("kerberoasting", OpsecRating.LOW, "Impacket GetUserSPNs.py from Linux"),
            ("asrep_roasting", OpsecRating.LOW, "Impacket GetNPUsers.py from Linux"),
        ],
        mitigations=[
            "Run from Linux using Impacket equivalents when possible",
            "If Rubeus is needed on Windows, use obfuscated builds",
            "BOF (Beacon Object File) versions bypass some detections",
        ],
    ),

    # -----------------------------------------------------------------------
    # LOUD
    # -----------------------------------------------------------------------

    "ntlm_relay": DetectionInfo(
        rating=OpsecRating.LOUD,
        description=(
            "NTLM Relay intercepts NTLM authentication and relays it to "
            "another service. Often combined with Responder or coercion "
            "techniques (PetitPotam, PrinterBug). Creates obvious network "
            "anomalies: authentication from unexpected sources, LLMNR/NBNS "
            "responses, forced authentication patterns."
        ),
        artifacts=[
            "NTLM authentication relayed from attacker IP to target",
            "Authentication from unexpected source (coerced machine account)",
            "LLMNR/NBNS/WPAD responses (if combined with Responder)",
            "SMB signing bypass attempts",
            "Network traffic between victim -> attacker -> target",
        ],
        event_ids=[
            "4624 (Type 3 from unexpected source IP)",
            "4625 (failed relay attempts)",
            "4648 (explicit credential from relayed auth)",
        ],
        detection_rules=[
            "Sigma: win_ntlm_relay",
            "Sigma: win_susp_logon_source",
            "Sigma: net_llmnr_nbt_ns_poisoning",
            "MDI: NTLM relay attack",
            "MDI: Suspected NTLM authentication tampering",
            "Zeek: LLMNR/NBNS anomaly detection",
            "CrowdStrike: NTLM relay lateral movement",
        ],
        alternatives=[
            ("pass_the_hash", OpsecRating.MEDIUM, "Direct hash use if you have the hash"),
            ("kerberoasting", OpsecRating.LOW, "Offline cracking if service accounts available"),
        ],
        mitigations=[
            "NTLM relay is inherently noisy -- use only when necessary",
            "Prefer targeted coercion over broadcast poisoning",
            "Use PetitPotam/PrinterBug (targeted) instead of Responder (broadcast)",
            "Relay to services that don't require SMB signing",
        ],
    ),

    "responder": DetectionInfo(
        rating=OpsecRating.LOUD,
        description=(
            "Responder poisons LLMNR, NBT-NS, and WPAD requests on the "
            "local network to capture NTLMv2 hashes. Broadcast poisoning "
            "affects all hosts on the segment and is trivially detectable "
            "by network monitoring."
        ),
        artifacts=[
            "LLMNR/NBT-NS/WPAD responses from attacker IP",
            "NTLM authentication to attacker-controlled service",
            "Captured NTLMv2 hashes (attacker side)",
            "Rogue WPAD/proxy configuration",
            "Multicast DNS responses",
        ],
        event_ids=[
            "4624 (Type 3 to attacker IP -- captured hash)",
            "4625 (failed auth if hash relay attempted)",
        ],
        detection_rules=[
            "Sigma: net_llmnr_nbt_ns_poisoning",
            "Sigma: net_responder_detected",
            "MDI: LLMNR/NBT-NS poisoning",
            "Zeek: LLMNR/NBNS response from unauthorized host",
            "CrowdStrike: Name resolution poisoning",
            "Elastic: LLMNR/NBT-NS Response from Unauthorized Host",
        ],
        alternatives=[
            ("kerberoasting", OpsecRating.LOW, "Offline cracking without network poisoning"),
            ("password_spraying", OpsecRating.HIGH, "Still noisy, but doesn't poison the network"),
        ],
        mitigations=[
            "Responder is very loud -- use analyze mode (-A) first to assess",
            "Disable WPAD poisoning if not needed (--wpad off)",
            "Target specific protocols only (e.g., only LLMNR)",
            "Run for short periods during high-traffic hours to blend",
            "Use Inveigh on Windows for more targeted poisoning",
        ],
    ),
}


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _resolve_name(tool_name: str) -> Optional[str]:
    """Resolve a tool name to its canonical OPSEC_REGISTRY key.

    Performs case-insensitive matching against:
    1. Exact canonical keys
    2. Alias table
    3. Fuzzy substring matching
    """
    if not tool_name:
        return None

    normalized = tool_name.strip().lower()

    # 1. Direct match in registry
    if normalized in OPSEC_REGISTRY:
        return normalized

    # 2. Alias lookup
    if normalized in _ALIASES:
        return _ALIASES[normalized]

    # 3. Try with common separators normalized
    for sep_from, sep_to in [("-", "_"), (".", "_"), (" ", "_")]:
        variant = normalized.replace(sep_from, sep_to)
        if variant in OPSEC_REGISTRY:
            return variant
        if variant in _ALIASES:
            return _ALIASES[variant]

    # 4. Fuzzy: check if the input is a substring of any canonical key or alias
    for key in OPSEC_REGISTRY:
        if normalized in key or key in normalized:
            return key
    for alias, canonical in _ALIASES.items():
        if normalized in alias or alias in normalized:
            return canonical

    return None


def get_opsec_info(tool_name: str) -> Optional[DetectionInfo]:
    """Look up OPSEC info for a tool. Case-insensitive, supports aliases.

    Args:
        tool_name: Tool or technique name (e.g., "psexec", "PsExec",
                   "impacket_psexec", "psexec.py").

    Returns:
        DetectionInfo if found, None otherwise.
    """
    key = _resolve_name(tool_name)
    if key is None:
        return None
    return OPSEC_REGISTRY.get(key)


def get_alternatives(tool_name: str) -> List[Tuple[str, OpsecRating, str]]:
    """Get quieter alternatives for a given tool.

    Args:
        tool_name: Tool or technique name.

    Returns:
        List of (tool_name, OpsecRating, notes) tuples, sorted by rating
        from quietest to loudest. Empty list if tool not found or has no
        alternatives.
    """
    info = get_opsec_info(tool_name)
    if info is None:
        return []

    rating_order = {
        OpsecRating.STEALTH: 0,
        OpsecRating.LOW: 1,
        OpsecRating.MEDIUM: 2,
        OpsecRating.HIGH: 3,
        OpsecRating.LOUD: 4,
    }
    return sorted(info.alternatives, key=lambda x: rating_order.get(x[1], 99))


def get_rating_color(rating: OpsecRating) -> str:
    """Return ANSI color code for an OPSEC rating level.

    Colors align with the cyberpunk neon theme in colors.py:
        STEALTH = neon green
        LOW     = neon cyan (blue)
        MEDIUM  = electric yellow
        HIGH    = neon red
        LOUD    = bright red bold
    """
    _RATING_COLORS = {
        OpsecRating.STEALTH: "\033[38;2;0;255;159m",          # Neon green
        OpsecRating.LOW:     "\033[38;2;0;232;255m",          # Neon cyan
        OpsecRating.MEDIUM:  "\033[1;38;2;255;234;0m",        # Electric yellow bold
        OpsecRating.HIGH:    "\033[1;38;2;255;41;117m",       # Neon red bold
        OpsecRating.LOUD:    "\033[1;5;38;2;255;41;117m",     # Neon red bold blink
    }
    return _RATING_COLORS.get(rating, "\033[0m")


def _format_rating_badge(rating: OpsecRating) -> str:
    """Format a colored rating badge string."""
    RESET = "\033[0m"
    color = get_rating_color(rating)
    return f"{color}{rating.value.upper()}{RESET}"


def format_opsec_warning(tool_name: str) -> str:
    """Format a human-readable OPSEC warning string for display.

    Returns a multi-line warning including the rating, description,
    key artifacts, event IDs, and quieter alternatives.

    If the tool is not found in the registry, returns a notice.
    """
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[38;2;60;40;90m"
    CYAN = "\033[38;2;0;232;255m"
    YELLOW = "\033[1;38;2;255;234;0m"
    PINK = "\033[38;2;255;16;240m"

    info = get_opsec_info(tool_name)
    if info is None:
        return f"{DIM}[opsec]{RESET} No OPSEC data for '{tool_name}'"

    color = get_rating_color(info.rating)
    badge = _format_rating_badge(info.rating)

    lines = []

    # Header
    if info.rating in (OpsecRating.HIGH, OpsecRating.LOUD):
        icon = "!!"
    elif info.rating == OpsecRating.MEDIUM:
        icon = "!"
    else:
        icon = "*"

    lines.append(f"{color}[{icon}] OPSEC {badge}: {info.description}{RESET}")

    # Artifacts
    if info.artifacts:
        lines.append(f"  {PINK}Artifacts:{RESET}")
        for artifact in info.artifacts:
            lines.append(f"    {DIM}-{RESET} {artifact}")

    # Event IDs
    if info.event_ids:
        lines.append(f"  {YELLOW}Event IDs:{RESET}")
        for eid in info.event_ids:
            lines.append(f"    {DIM}-{RESET} {eid}")

    # Detection rules
    if info.detection_rules:
        lines.append(f"  {CYAN}Detection Rules:{RESET}")
        for rule in info.detection_rules[:5]:  # Show top 5
            lines.append(f"    {DIM}-{RESET} {rule}")
        if len(info.detection_rules) > 5:
            lines.append(f"    {DIM}  ... and {len(info.detection_rules) - 5} more{RESET}")

    # Alternatives
    alts = get_alternatives(tool_name)
    if alts:
        alt_strs = []
        for alt_name, alt_rating, alt_notes in alts:
            alt_badge = _format_rating_badge(alt_rating)
            alt_strs.append(f"{alt_name} ({alt_badge})")
        lines.append(f"  {BOLD}Quieter alternatives:{RESET} {', '.join(alt_strs)}")

    # Mitigations
    if info.mitigations:
        lines.append(f"  {BOLD}Mitigations:{RESET}")
        for m in info.mitigations:
            lines.append(f"    {DIM}-{RESET} {m}")

    return "\n".join(lines)


def compare_tools(tool_names: List[str]) -> str:
    """Compare OPSEC profiles of multiple tools, return formatted table.

    Args:
        tool_names: List of tool/technique names to compare.

    Returns:
        Formatted comparison table string with ANSI colors.
    """
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[38;2;60;40;90m"
    CYAN = "\033[38;2;0;232;255m"
    PINK = "\033[38;2;255;16;240m"
    YELLOW = "\033[1;38;2;255;234;0m"

    # Resolve all tools
    resolved = []
    for name in tool_names:
        key = _resolve_name(name)
        if key and key in OPSEC_REGISTRY:
            resolved.append((name, key, OPSEC_REGISTRY[key]))
        else:
            resolved.append((name, None, None))

    if not resolved:
        return f"{DIM}No tools to compare.{RESET}"

    # Sort by rating (quietest first)
    rating_order = {
        OpsecRating.STEALTH: 0,
        OpsecRating.LOW: 1,
        OpsecRating.MEDIUM: 2,
        OpsecRating.HIGH: 3,
        OpsecRating.LOUD: 4,
    }
    resolved.sort(key=lambda x: rating_order.get(x[2].rating, 99) if x[2] else 99)

    # Build table
    lines = []
    lines.append("")
    lines.append(f"  {PINK}{BOLD}OPSEC Comparison{RESET}")
    lines.append(f"  {DIM}{'=' * 74}{RESET}")

    # Column headers
    col_tool = "Tool"
    col_rating = "Rating"
    col_events = "Key Events"
    col_artifacts = "Primary Artifact"

    lines.append(
        f"  {CYAN}{col_tool:<22}{RESET} "
        f"{CYAN}{col_rating:<10}{RESET} "
        f"{CYAN}{col_events:<20}{RESET} "
        f"{CYAN}{col_artifacts}{RESET}"
    )
    lines.append(f"  {DIM}{'-' * 22} {'-' * 10} {'-' * 20} {'-' * 24}{RESET}")

    for display_name, key, info in resolved:
        if info is None:
            lines.append(f"  {display_name:<22} {DIM}(not found){RESET}")
            continue

        badge = _format_rating_badge(info.rating)

        # Pick the most important event IDs (first 3)
        events = ", ".join(
            eid.split(" ")[0] for eid in info.event_ids[:3]
        ) if info.event_ids else "-"

        # Pick primary artifact (first one, truncated)
        artifact = info.artifacts[0][:24] if info.artifacts else "-"

        # Pad badge manually since ANSI codes mess up string width
        # badge_raw_len = len(info.rating.value.upper())
        # badge_padding = 10 - badge_raw_len
        lines.append(
            f"  {display_name:<22} "
            f"{badge:<24} "  # Extra space for ANSI codes
            f"{events:<20} "
            f"{artifact}"
        )

    lines.append(f"  {DIM}{'=' * 74}{RESET}")

    # Recommendation
    if resolved and resolved[0][2] is not None:
        best = resolved[0]
        best_badge = _format_rating_badge(best[2].rating)
        lines.append(
            f"  {BOLD}Recommended:{RESET} {PINK}{best[0]}{RESET} ({best_badge})"
        )

    lines.append("")
    return "\n".join(lines)


def list_by_rating(rating: OpsecRating) -> List[Tuple[str, DetectionInfo]]:
    """List all tools with a specific OPSEC rating.

    Args:
        rating: The OpsecRating to filter by.

    Returns:
        List of (canonical_name, DetectionInfo) tuples.
    """
    return [
        (name, info)
        for name, info in sorted(OPSEC_REGISTRY.items())
        if info.rating == rating
    ]


def list_all_ratings() -> str:
    """Return a formatted summary of all tools grouped by OPSEC rating."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[38;2;60;40;90m"

    lines = []
    for rating in OpsecRating:
        color = get_rating_color(rating)
        tools = list_by_rating(rating)
        lines.append(f"\n  {color}{BOLD}{rating.value.upper()}{RESET} ({len(tools)} tools):")
        for name, info in tools:
            lines.append(f"    {DIM}-{RESET} {name}: {info.description[:70]}...")

    return "\n".join(lines)
