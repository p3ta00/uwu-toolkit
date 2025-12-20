"""
Color and styling utilities for UwU Toolkit
Cyberpunk Neon / Las Vegas theme - Neon lights in the digital rain
"""

import re
from typing import Optional, List, Tuple


class Colors:
    """ANSI color codes - Cyberpunk Neon / Las Vegas theme"""

    # Reset and modifiers
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"

    # Cyberpunk Neon palette (True RGB colors)
    # Hot neon pinks, electric blues, toxic greens

    # Core Cyberpunk Neon colors
    CP_BG = "\033[48;2;13;2;33m"              # #0d0221 - Deep purple-black bg
    CP_FG = "\033[38;2;230;230;250m"           # #e6e6fa - Soft lavender fg

    # Neon Colors - Las Vegas Lights
    NEON_PINK = "\033[38;2;255;16;240m"        # #ff10f0 - Hot pink neon
    NEON_MAGENTA = "\033[38;2;255;0;110m"      # #ff006e - Magenta neon
    NEON_RED = "\033[38;2;255;41;117m"         # #ff2975 - Neon red-pink
    NEON_ORANGE = "\033[38;2;255;124;0m"       # #ff7c00 - Neon orange
    NEON_YELLOW = "\033[38;2;255;234;0m"       # #ffea00 - Electric yellow
    NEON_GREEN = "\033[38;2;0;255;159m"        # #00ff9f - Toxic neon green
    NEON_CYAN = "\033[38;2;0;232;255m"         # #00e8ff - Electric cyan
    NEON_BLUE = "\033[38;2;0;162;255m"         # #00a2ff - Neon blue
    NEON_PURPLE = "\033[38;2;182;32;224m"      # #b620e0 - Neon purple
    NEON_VIOLET = "\033[38;2;148;0;211m"       # #9400d3 - Dark violet
    DARK_PINK = "\033[38;2;199;21;133m"        # #c71585 - Medium violet red (darker pink)

    # Accent colors
    CHROME = "\033[38;2;192;192;192m"          # #c0c0c0 - Chrome/silver
    GOLD = "\033[38;2;255;215;0m"              # #ffd700 - Gold
    HOLOGRAM = "\033[38;2;127;255;212m"        # #7fffd4 - Hologram aqua
    DIGITAL_RAIN = "\033[38;2;0;255;65m"       # #00ff41 - Matrix green

    # Dark accents
    DARK_PURPLE = "\033[38;2;75;0;130m"        # #4b0082 - Indigo
    SHADOW = "\033[38;2;40;20;60m"             # #28143c - Shadow purple
    GRID = "\033[38;2;60;40;90m"               # #3c285a - Grid lines

    # Fallback standard colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright standard colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background colors - Neon glow style
    BG_PINK = "\033[48;2;255;16;240m"          # Hot pink bg
    BG_GREEN = "\033[48;2;0;255;159m"          # Neon green bg
    BG_CYAN = "\033[48;2;0;232;255m"           # Electric cyan bg
    BG_PURPLE = "\033[48;2;182;32;224m"        # Neon purple bg
    BG_RED = "\033[48;2;255;41;117m"           # Neon red bg
    BG_DARK = "\033[48;2;13;2;33m"             # Dark purple bg

    # UwU Toolkit theme colors
    UWU_PINK = NEON_PINK
    UWU_PURPLE = NEON_PURPLE
    UWU_CYAN = NEON_CYAN

    # Severity colors - Cyberpunk style
    CRITICAL = "\033[1;48;2;255;41;117;38;2;255;255;255m"    # White on neon red
    HIGH = "\033[1;38;2;255;41;117m"            # Neon red bold
    MEDIUM = "\033[1;38;2;255;234;0m"           # Electric yellow bold
    LOW = "\033[1;38;2;0;232;255m"              # Neon cyan bold
    INFO = "\033[1;38;2;0;162;255m"             # Neon blue bold
    INTERESTING = "\033[1;38;2;182;32;224m"     # Neon purple bold

    # Special highlight colors
    PASSWORD = "\033[1;48;2;255;16;240;38;2;0;0;0m"         # Black on hot pink
    HASH = "\033[1;48;2;182;32;224;38;2;255;255;255m"       # White on purple
    CREDENTIAL = "\033[1;48;2;255;41;117;38;2;255;234;0m"   # Yellow on red
    VULNERABLE = "\033[1;5;38;2;255;16;240m"                 # Blinking hot pink
    PRIVESC = "\033[1;48;2;0;255;159;38;2;0;0;0m"           # Black on neon green


class Style:
    """Styled output helpers - Cyberpunk Neon theme"""

    _enabled = True

    @classmethod
    def enable(cls) -> None:
        cls._enabled = True

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False

    @classmethod
    def _wrap(cls, text: str, color: str) -> str:
        if cls._enabled:
            return f"{color}{text}{Colors.RESET}"
        return text

    # Status indicators
    @classmethod
    def success(cls, text: str) -> str:
        return cls._wrap(f"[+] {text}", Colors.NEON_GREEN)

    @classmethod
    def error(cls, text: str) -> str:
        return cls._wrap(f"[-] {text}", Colors.NEON_RED)

    @classmethod
    def warning(cls, text: str) -> str:
        return cls._wrap(f"[!] {text}", Colors.NEON_ORANGE)

    @classmethod
    def info(cls, text: str) -> str:
        return cls._wrap(f"[*] {text}", Colors.NEON_CYAN)

    @classmethod
    def debug(cls, text: str) -> str:
        return cls._wrap(f"[D] {text}", Colors.GRID)

    @classmethod
    def prompt(cls, text: str) -> str:
        return cls._wrap(f"[?] {text}", Colors.NEON_CYAN)

    # Text styling
    @classmethod
    def bold(cls, text: str) -> str:
        return cls._wrap(text, Colors.BOLD + Colors.CP_FG)

    @classmethod
    def dim(cls, text: str) -> str:
        return cls._wrap(text, Colors.GRID)

    @classmethod
    def highlight(cls, text: str) -> str:
        return cls._wrap(text, Colors.NEON_CYAN)

    @classmethod
    def value(cls, text: str) -> str:
        """Style for variable values"""
        return cls._wrap(text, Colors.NEON_GREEN)

    @classmethod
    def varname(cls, text: str) -> str:
        """Style for variable names"""
        return cls._wrap(text, Colors.NEON_YELLOW)

    @classmethod
    def module(cls, text: str) -> str:
        """Style for module names - neon pink for visibility"""
        return cls._wrap(text, Colors.NEON_PINK)

    @classmethod
    def module_prompt(cls, text: str) -> str:
        """Readline-safe style for module names in prompts"""
        return f"\001{Colors.NEON_PINK}\002{text}\001{Colors.RESET}\002"

    @classmethod
    def module_path(cls, path: str) -> str:
        """Style module path: category in dim, module name in neon pink
        e.g., auxiliary/ad/asreproast -> dim(auxiliary/ad/) + pink(asreproast)
        """
        if "/" in path:
            parts = path.rsplit("/", 1)
            category = parts[0] + "/"
            name = parts[1]
            return f"{Colors.GRID}{category}{Colors.RESET}{Colors.NEON_PINK}{name}{Colors.RESET}"
        return cls._wrap(path, Colors.NEON_PINK)

    @classmethod
    def path(cls, text: str) -> str:
        """Style for file paths"""
        return cls._wrap(text, Colors.NEON_BLUE)

    @classmethod
    def uwu(cls, text: str) -> str:
        """UwU pink styling"""
        return cls._wrap(text, Colors.NEON_PINK)

    @classmethod
    def module_selected(cls, text: str) -> str:
        """Module selection - hot pink to match UWU logo"""
        return cls._wrap(f"[+] Using module: {text}", Colors.NEON_PINK)

    @classmethod
    def title(cls, text: str) -> str:
        """Title/header styling - darker pink for section headers"""
        return cls._wrap(text, Colors.BOLD + Colors.DARK_PINK)

    # Severity methods
    @classmethod
    def critical(cls, text: str) -> str:
        return cls._wrap(f" {text} ", Colors.CRITICAL)

    @classmethod
    def high(cls, text: str) -> str:
        return cls._wrap(text, Colors.HIGH)

    @classmethod
    def medium(cls, text: str) -> str:
        return cls._wrap(text, Colors.MEDIUM)

    @classmethod
    def low(cls, text: str) -> str:
        return cls._wrap(text, Colors.LOW)

    @classmethod
    def interesting(cls, text: str) -> str:
        return cls._wrap(text, Colors.INTERESTING)

    @classmethod
    def password_found(cls, text: str) -> str:
        return cls._wrap(f" PASSWORD: {text} ", Colors.PASSWORD)

    @classmethod
    def hash_found(cls, text: str) -> str:
        return cls._wrap(f" HASH: {text} ", Colors.HASH)

    @classmethod
    def credential(cls, text: str) -> str:
        return cls._wrap(f" CRED: {text} ", Colors.CREDENTIAL)

    @classmethod
    def privesc(cls, text: str) -> str:
        return cls._wrap(f" PRIVESC: {text} ", Colors.PRIVESC)

    @classmethod
    def vulnerable(cls, text: str) -> str:
        return cls._wrap(f"[VULN] {text}", Colors.VULNERABLE)

    # =========================================================================
    # Output Highlighting - Matches website JS highlighting
    # =========================================================================

    @classmethod
    def ip(cls, text: str) -> str:
        """Highlight IP address - Blue"""
        return cls._wrap(text, Colors.NEON_BLUE)

    @classmethod
    def port(cls, text: str) -> str:
        """Highlight port number - Yellow"""
        return cls._wrap(text, Colors.NEON_YELLOW)

    @classmethod
    def port_open(cls, text: str = "open") -> str:
        """Highlight open port state - Green"""
        return cls._wrap(text, Colors.NEON_GREEN)

    @classmethod
    def port_closed(cls, text: str = "closed") -> str:
        """Highlight closed port state - Red"""
        return cls._wrap(text, Colors.NEON_RED)

    @classmethod
    def port_filtered(cls, text: str = "filtered") -> str:
        """Highlight filtered port state - Orange"""
        return cls._wrap(text, Colors.NEON_ORANGE)

    @classmethod
    def domain(cls, text: str) -> str:
        """Highlight domain name - Cyan"""
        return cls._wrap(text, Colors.NEON_CYAN)

    @classmethod
    def service(cls, text: str) -> str:
        """Highlight service name - Purple"""
        return cls._wrap(text, Colors.NEON_PURPLE)

    @classmethod
    def user(cls, text: str) -> str:
        """Highlight username - Cyan"""
        return cls._wrap(text, Colors.NEON_CYAN)

    @classmethod
    def admin(cls, text: str) -> str:
        """Highlight admin/privileged account - Orange bold"""
        return cls._wrap(text, Colors.BOLD + Colors.NEON_ORANGE)

    @classmethod
    def dangerous_acl(cls, text: str) -> str:
        """Highlight dangerous ACL - Red bold"""
        return cls._wrap(text, Colors.BOLD + Colors.NEON_RED)

    @classmethod
    def hash_value(cls, text: str) -> str:
        """Highlight hash value - Purple"""
        return cls._wrap(text, Colors.NEON_PURPLE)

    @classmethod
    def pwned(cls, text: str) -> str:
        """Highlight pwned/success - Green bold"""
        return cls._wrap(text, Colors.BOLD + Colors.NEON_GREEN)

    @classmethod
    def command(cls, text: str) -> str:
        """Highlight command - Green"""
        return cls._wrap(text, Colors.NEON_GREEN)

    @classmethod
    def flag(cls, text: str) -> str:
        """Highlight flag/option - Orange"""
        return cls._wrap(text, Colors.NEON_ORANGE)

    @classmethod
    def file_path(cls, text: str) -> str:
        """Highlight file path - Blue"""
        return cls._wrap(text, Colors.NEON_BLUE)

    @classmethod
    def format_port_line(cls, port: str, state: str, service: str, version: str = "") -> str:
        """Format a port line like nmap output with proper colors"""
        port_colored = cls._wrap(port, Colors.NEON_YELLOW)

        if state.lower() == "open":
            state_colored = cls._wrap(state, Colors.NEON_GREEN)
        elif state.lower() == "closed":
            state_colored = cls._wrap(state, Colors.NEON_RED)
        else:
            state_colored = cls._wrap(state, Colors.NEON_ORANGE)

        service_colored = cls._wrap(service, Colors.NEON_PURPLE)

        if version:
            return f"{port_colored}  {state_colored}  {service_colored}  {version}"
        return f"{port_colored}  {state_colored}  {service_colored}"


class SecurityHighlighter:
    """
    LinPEAS-style automatic highlighting for security-relevant content
    Cyberpunk Neon color scheme
    """

    PATTERNS: List[Tuple[str, str, str]] = [
        # CRITICAL - Passwords and credentials
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']+)', Colors.PASSWORD, 'PASSWORD'),
        (r'(?i)(pass|cred|secret)\s*[=:]\s*["\']?([^\s"\']+)', Colors.PASSWORD, 'CREDENTIAL'),

        # HIGH - Hashes
        (r'[a-fA-F0-9]{32}', Colors.HASH, 'MD5/NTLM'),
        (r'[a-fA-F0-9]{64}', Colors.HASH, 'SHA256'),
        (r'\$krb5tgs\$[^\s]+', Colors.HASH, 'KERBEROS'),
        (r'\$krb5asrep\$[^\s]+', Colors.HASH, 'ASREP'),

        # HIGH - Kerberoasting/ASREPRoasting targets
        (r'(?i)(serviceprincipalname|spn)\s*[=:]\s*([^\s]+)', Colors.HIGH, 'SPN'),
        (r'(?i)DONT_REQ_PREAUTH', Colors.HIGH, 'ASREPROAST'),

        # HIGH - Delegation
        (r'(?i)TRUSTED_FOR_DELEGATION', Colors.HIGH, 'UNCONSTRAINED'),
        (r'(?i)msds-allowedtodelegateto', Colors.HIGH, 'CONSTRAINED'),
        (r'(?i)msds-allowedtoactonbehalfofotheridentity', Colors.HIGH, 'RBCD'),

        # HIGH - Admin accounts
        (r'(?i)(domain\s*admins?|enterprise\s*admins?|administrators)', Colors.HIGH, 'ADMIN_GROUP'),
        (r'(?i)(admincount\s*[=:]\s*1)', Colors.HIGH, 'PROTECTED'),

        # MEDIUM - Interesting users/groups
        (r'(?i)(backup\s*operators?|account\s*operators?|server\s*operators?)', Colors.MEDIUM, 'OPERATOR'),
        (r'(?i)(dnsadmins?|exchange)', Colors.MEDIUM, 'ESCALATION'),
        (r'(?i)(managedby|owner)', Colors.MEDIUM, 'OWNERSHIP'),

        # MEDIUM - ACL abuse
        (r'(?i)(genericall|genericwrite|writedacl|writeowner)', Colors.HIGH, 'DANGEROUS_ACL'),
        (r'(?i)(forcechangepassword|addmember)', Colors.MEDIUM, 'ABUSABLE_ACL'),
        (r'(?i)(replication-get|dcsync)', Colors.CRITICAL, 'DCSYNC'),

        # LOW - Interesting info
        (r'(?i)(description)\s*[=:]\s*([^\n]+)', Colors.LOW, 'DESCRIPTION'),
        (r'S-1-5-21-[\d-]+', Colors.INFO, 'SID'),

        # Shares
        (r'(?i)(READ|WRITE)\s*(,\s*(READ|WRITE))?', Colors.INTERESTING, 'SHARE_ACCESS'),
        (r'(?i)(ADMIN\$|C\$|IPC\$)', Colors.LOW, 'DEFAULT_SHARE'),
        (r'(?i)\\\\[^\s]+\\[^\s]+', Colors.INTERESTING, 'UNC_PATH'),

        # Trust info
        (r'(?i)(bidirectional|inbound|outbound)', Colors.INTERESTING, 'TRUST_DIR'),
        (r'(?i)(forest_transitive|within_forest)', Colors.MEDIUM, 'TRUST_TYPE'),
    ]

    CRITICAL_KEYWORDS = [
        'password', 'passwd', 'pwd', 'secret', 'credential', 'cred',
        'dcsync', 'replication', 'genericall', 'writedacl',
        'domain admin', 'enterprise admin', 'administrator',
        'unconstrained', 'delegation',
    ]

    HIGH_KEYWORDS = [
        'kerberoast', 'asreproast', 'spn', 'preauth',
        'hash', 'ntlm', 'lm hash',
        'backup operator', 'server operator',
        'genericwrite', 'writeowner', 'forcechangepassword',
    ]

    @classmethod
    def highlight(cls, text: str) -> str:
        if not text:
            return text

        result = text
        for pattern, color, label in cls.PATTERNS:
            def replace_match(m):
                matched = m.group(0)
                return f"{color}{matched}{Colors.RESET}"
            result = re.sub(pattern, replace_match, result)

        return result

    @classmethod
    def highlight_line(cls, line: str) -> str:
        if not line.strip():
            return line

        lower = line.lower()

        for kw in cls.CRITICAL_KEYWORDS:
            if kw in lower:
                return f"{Colors.HIGH}[!] {line}{Colors.RESET}"

        for kw in cls.HIGH_KEYWORDS:
            if kw in lower:
                return f"{Colors.MEDIUM}[*] {line}{Colors.RESET}"

        return line

    @classmethod
    def format_finding(cls, severity: str, category: str, finding: str, details: str = "") -> str:
        severity_colors = {
            'CRITICAL': Colors.CRITICAL,
            'HIGH': Colors.HIGH,
            'MEDIUM': Colors.MEDIUM,
            'LOW': Colors.LOW,
            'INFO': Colors.INFO,
        }

        color = severity_colors.get(severity.upper(), Colors.RESET)

        output = f"{color}[{severity}]{Colors.RESET} "
        output += f"{Colors.BOLD}{Colors.CP_FG}{category}{Colors.RESET}: "
        output += f"{Colors.CP_FG}{finding}{Colors.RESET}"

        if details:
            output += f"\n    {Colors.GRID}{details}{Colors.RESET}"

        return output

    @classmethod
    def section_header(cls, title: str, icon: str = "═") -> str:
        width = 70
        padding = (width - len(title) - 4) // 2
        line = icon * padding
        return f"\n{Colors.NEON_CYAN}{line}[ {Colors.NEON_PINK}{title}{Colors.NEON_CYAN} ]{line}{Colors.RESET}\n"

    @classmethod
    def subsection_header(cls, title: str) -> str:
        return f"\n{Colors.NEON_PURPLE}╔══════════╣ {title}{Colors.RESET}"

    @classmethod
    def finding_bullet(cls, text: str, severity: str = "INFO") -> str:
        severity_icons = {
            'CRITICAL': f"{Colors.CRITICAL} !! {Colors.RESET}",
            'HIGH': f"{Colors.HIGH}►{Colors.RESET}",
            'MEDIUM': f"{Colors.MEDIUM}►{Colors.RESET}",
            'LOW': f"{Colors.LOW}►{Colors.RESET}",
            'INFO': f"{Colors.INFO}•{Colors.RESET}",
        }
        icon = severity_icons.get(severity.upper(), "•")
        return f"  {icon} {text}"

    @classmethod
    def auto_highlight_output(cls, text: str) -> str:
        """
        Auto-highlight security tool output matching website JS patterns.
        Use this for nmap, netexec, and other tool output.
        """
        if not text:
            return text

        result = text

        # IP addresses - Blue
        result = re.sub(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            f'{Colors.NEON_BLUE}\\1{Colors.RESET}',
            result
        )

        # Port numbers like 445/tcp - Yellow port, muted protocol
        result = re.sub(
            r'\b(\d+)/(tcp|udp)\b',
            f'{Colors.NEON_YELLOW}\\1{Colors.RESET}/{Colors.GRID}\\2{Colors.RESET}',
            result
        )

        # Port states
        result = re.sub(r'\b(open)\b', f'{Colors.NEON_GREEN}\\1{Colors.RESET}', result, flags=re.IGNORECASE)
        result = re.sub(r'\b(closed)\b', f'{Colors.NEON_RED}\\1{Colors.RESET}', result, flags=re.IGNORECASE)
        result = re.sub(r'\b(filtered)\b', f'{Colors.NEON_ORANGE}\\1{Colors.RESET}', result, flags=re.IGNORECASE)

        # Domain names
        result = re.sub(
            r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(local|htb|thm|smarter|corp))\b',
            f'{Colors.NEON_CYAN}\\1{Colors.RESET}',
            result,
            flags=re.IGNORECASE
        )

        # Services - Purple
        services = r'\b(smb|ldap|kerberos|http|https|ssh|ftp|rdp|mssql|mysql|winrm|dns|netbios-ssn|microsoft-ds|msrpc)\b'
        result = re.sub(services, f'{Colors.NEON_PURPLE}\\1{Colors.RESET}', result, flags=re.IGNORECASE)

        # Admin keywords - Orange bold
        result = re.sub(
            r'\b(Administrator|SYSTEM|NT AUTHORITY|Domain Admins?)\b',
            f'{Colors.BOLD}{Colors.NEON_ORANGE}\\1{Colors.RESET}',
            result
        )

        # Dangerous ACLs - Red bold
        result = re.sub(
            r'\b(GenericAll|GenericWrite|WriteDACL|WriteOwner|DCSync|SeImpersonatePrivilege)\b',
            f'{Colors.BOLD}{Colors.NEON_RED}\\1{Colors.RESET}',
            result,
            flags=re.IGNORECASE
        )

        # NTLM hashes (32 hex chars) - Purple
        result = re.sub(
            r'\b([a-fA-F0-9]{32})\b',
            f'{Colors.NEON_PURPLE}\\1{Colors.RESET}',
            result
        )

        # Success indicators - Green bold
        result = re.sub(
            r'\b(Pwn3d!|PWNED|Pwned|SUCCESS)\b',
            f'{Colors.BOLD}{Colors.NEON_GREEN}\\1{Colors.RESET}',
            result,
            flags=re.IGNORECASE
        )

        return result


# Cyberpunk Neon Banner with anime waifu braille art
BANNER = f"""
{Colors.NEON_PINK}              ██╗   ██╗██╗    ██╗██╗   ██╗{Colors.RESET}
{Colors.NEON_PINK}              ██║   ██║██║    ██║██║   ██║{Colors.RESET}
{Colors.NEON_MAGENTA}              ██║   ██║██║ █╗ ██║██║   ██║{Colors.RESET}
{Colors.NEON_PURPLE}              ██║   ██║██║███╗██║██║   ██║{Colors.RESET}
{Colors.NEON_BLUE}              ╚██████╔╝╚███╔███╔╝╚██████╔╝{Colors.RESET}
{Colors.NEON_CYAN}               ╚═════╝  ╚══╝╚══╝  ╚═════╝ {Colors.NEON_PINK}Toolkit{Colors.RESET}
{Colors.GRID}═══════════════════════════════════════════════════════════{Colors.RESET}
{Colors.NEON_PINK}              ⢸⣇⢹⣿⣿⣿⣿⣿⣿⣿⢿⡟⣿⣻⢿⣿⡷⢉⣾⣿⣮⡙⣿⣿⣿⡿⣿⣷⡈{Colors.RESET}
{Colors.NEON_PINK}              ⠸⣿⡆⢻⣿⣿⡿⣏⢻⣟⡾⣽⣳⣯⣿⣥⠰⣇⣿⣿⣿⠟⣬⢳⣿⣷⢹⣿⣧{Colors.RESET}
{Colors.NEON_MAGENTA}              ⡇⣿⣿⣆⢻⣿⡽⣻⣆⠹⣿⣽⣿⣽⣷⣿⢆⣿⠜⠛⠋⠈⠛⠃⠙⣺⠼⣷⢿{Colors.RESET}
{Colors.NEON_MAGENTA}              ⣷⢨⣭⣭⣥⡡⣶⣟⣾⣰⡹⣿⣿⣿⣿⣿⢾⠁⣠⣶⠾⠿⢷⣶⣄⠈⢫⣟⣿{Colors.RESET}
{Colors.NEON_PURPLE}              ⢿⡆⣿⣿⣿⣷⡝⣿⣿⣧⣗⣿⡿⣟⣿⣾⡇⣸⡟⣡⡐⡲⢦⡌⢻⣷⡀⢸⣿{Colors.RESET}
{Colors.NEON_PURPLE}              ⣿⣿⡜⠘⠛⠛⠛⠋⢽⣷⣿⣯⣿⣿⣿⣿⣷⣿⡇⣿⠷⣻⣦⡭⢂⢿⣇⠈⣿{Colors.RESET}
{Colors.NEON_BLUE}              ⣿⠊⠀⣠⣤⡶⠶⣤⣤⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡜⣩⢿⣶⡟⣸⣿⣆⡉{Colors.RESET}
{Colors.NEON_BLUE}              ⠇⠀⣼⣿⢁⠰⠰⣤⢍⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡜⠯⢿⠻⢃⣟⢬⣭⣶{Colors.RESET}
{Colors.NEON_CYAN}              ⠄⢸⣿⡧⣿⣷⢻⣤⡯⢆⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣿⣿⣏⣚⣳⣵{Colors.RESET}
{Colors.NEON_CYAN}              ⠀⢸⣿⣿⡈⠤⠿⣻⣧⣿⠆⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{Colors.RESET}
{Colors.NEON_CYAN}              ⣦⠠⣻⣿⣷⣌⠹⣯⢿⡟⢣⣿⣿⣿⣿⣿⣿⣿⢛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿{Colors.RESET}
{Colors.NEON_BLUE}              ⣿⣧⡙⣿⣿⡿⢷⢶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣯⢸⣳⡜⢿⣿⣿⣿⣿⣿⣿⠇{Colors.RESET}
{Colors.NEON_PURPLE}              ⣿⡛⣿⢦⡹⣓⣯⣭⡝⣿⣿⣿⣿⣿⣿⣿⣿⣿⡔⢧⣛⣸⣿⣿⣿⣿⡿⠃⣠{Colors.RESET}
{Colors.NEON_MAGENTA}              ⣾⡽⡆⢿⠼⡻⠞⣣⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣿⣿⣿⣿⠿⠋⠀⣈⠁{Colors.RESET}
{Colors.NEON_PINK}              ⣿⣽⣷⠀⠓⠷⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⣡⠴⢮⡽⡹⢧{Colors.RESET}
{Colors.GRID}═══════════════════════════════════════════════════════════{Colors.RESET}
{Colors.NEON_PINK}              ⚡ {Colors.DIGITAL_RAIN}H A C K  T H E  P L A N E T{Colors.NEON_PINK} ⚡{Colors.RESET}
{Colors.GRID}═══════════════════════════════════════════════════════════{Colors.RESET}
{Colors.NEON_GREEN}    ╔═══════════════════════════════════════════════════╗{Colors.RESET}
{Colors.NEON_GREEN}    ║{Colors.NEON_CYAN}      Modular Penetration Testing Framework          {Colors.NEON_GREEN}║{Colors.RESET}
{Colors.NEON_GREEN}    ╚═══════════════════════════════════════════════════╝{Colors.RESET}
{Colors.GRID}            Type '{Colors.NEON_YELLOW}help{Colors.GRID}' for available commands{Colors.RESET}
"""

MINI_BANNER = f"{Colors.NEON_PINK}UwU{Colors.NEON_CYAN} Toolkit{Colors.RESET}"

# Readline-safe version for prompts (wraps ANSI codes with \001 and \002)
# This prevents readline from miscounting prompt length during history navigation
def _rl_wrap(code: str) -> str:
    """Wrap ANSI code for readline"""
    return f"\001{code}\002"

MINI_BANNER_PROMPT = f"{_rl_wrap(Colors.NEON_PINK)}UwU{_rl_wrap(Colors.NEON_CYAN)} Toolkit{_rl_wrap(Colors.RESET)}"
