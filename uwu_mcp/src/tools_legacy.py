"""
MCP tool definitions for UwU Toolkit.
Exposes AD pentesting operations as MCP tools.
"""

import json
import logging
import os
import shlex
import subprocess
from typing import Optional


# Timeout for command execution (seconds)
DEFAULT_TIMEOUT = 120
LONG_TIMEOUT = 300

# UwU toolkit root (auto-detect)
UWU_ROOT = os.environ.get("UWU_ROOT", "/opt/my-resources/tools/uwu-toolkit")


def _run_cmd(cmd: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute a shell command and return structured result."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PATH": f"/opt/tools/Certipy/venv/bin:/root/.local/bin:{os.environ.get('PATH', '')}" }
        )
        return {
            "status": "success" if result.returncode == 0 else "error",
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _format_response(data=None, error=None, success=None, message=None) -> str:
    """Format response as JSON string for MCP."""
    response = {}
    if error:
        response["status"] = "error"
        response["error"] = str(error)
    elif success is True:
        response["status"] = "success"
        response["message"] = message or "Operation successful"
        if data is not None:
            response["data"] = data
    elif success is False:
        response["status"] = "failure"
        response["error"] = message or "Operation failed"
    elif data is not None:
        response["status"] = "success"
        response["data"] = data
    else:
        response["status"] = "no_content"
        response["message"] = message or "No output"

    try:
        return json.dumps(response, default=str, indent=2)
    except TypeError as e:
        return json.dumps({"status": "error", "error": f"Serialization error: {e}"})


def setup_tools(mcp):
    """Register all UwU Toolkit tools with the MCP server."""

    # ========================================================================
    # SHELL EXECUTION
    # ========================================================================

    @mcp.tool()
    async def run_shell(command: str, timeout: int = DEFAULT_TIMEOUT) -> str:
        """
        Execute a shell command directly in the Exegol container.
        Use for arbitrary commands not covered by specific tools.

        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds (default 120)
        """
        result = _run_cmd(command, timeout)
        return _format_response(data=result)

    # ========================================================================
    # IMPACKET TOOLS
    # ========================================================================

    @mcp.tool()
    async def impacket_secretsdump(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        just_dc: bool = False,
        just_dc_user: str = "",
        outputfile: str = "",
    ) -> str:
        """
        Run Impacket secretsdump for credential extraction (SAM, LSA, NTDS).
        Supports password, hash (LM:NT), and Kerberos authentication.

        Args:
            target: Target IP or hostname
            domain: AD domain name
            username: Username for authentication
            password: Password (mutually exclusive with hashes)
            hashes: NTLM hash in LM:NT format
            dc_ip: Domain controller IP (for Kerberos)
            just_dc: Only extract NTDS.dit hashes via DRSUAPI
            just_dc_user: Extract hash for specific user only
            outputfile: Save output to file
        """
        cmd = _build_impacket_cmd(
            "secretsdump.py", target, domain, username, password, hashes, dc_ip
        )
        if just_dc:
            cmd += " -just-dc"
        if just_dc_user:
            cmd += f" -just-dc-user {shlex.quote(just_dc_user)}"
        if outputfile:
            cmd += f" -outputfile {shlex.quote(outputfile)}"

        result = _run_cmd(cmd, LONG_TIMEOUT)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_psexec(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        command: str = "",
    ) -> str:
        """
        Run Impacket psexec for remote command execution via SMB service.

        Args:
            target: Target IP or hostname
            domain: AD domain name
            username: Username
            password: Password
            hashes: NTLM hash LM:NT
            command: Command to execute (empty for interactive shell)
        """
        cmd = _build_impacket_cmd(
            "psexec.py", target, domain, username, password, hashes
        )
        if command:
            cmd += f" {shlex.quote(command)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_wmiexec(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        command: str = "",
    ) -> str:
        """
        Run Impacket wmiexec for remote command execution via WMI.

        Args:
            target: Target IP or hostname
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash LM:NT
            command: Command to execute
        """
        cmd = _build_impacket_cmd(
            "wmiexec.py", target, domain, username, password, hashes
        )
        if command:
            cmd += f" {shlex.quote(command)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_smbexec(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        command: str = "",
    ) -> str:
        """
        Run Impacket smbexec for remote command execution via SMB.

        Args:
            target: Target IP or hostname
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash LM:NT
            command: Command to execute
        """
        cmd = _build_impacket_cmd(
            "smbexec.py", target, domain, username, password, hashes
        )
        if command:
            cmd += f" {shlex.quote(command)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_dcomexec(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        command: str = "",
        object_name: str = "MMC20",
    ) -> str:
        """
        Run Impacket dcomexec for remote command execution via DCOM.

        Args:
            target: Target IP or hostname
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash LM:NT
            command: Command to execute
            object_name: DCOM object (MMC20, ShellWindows, ShellBrowserWindow)
        """
        cmd = _build_impacket_cmd(
            "dcomexec.py", target, domain, username, password, hashes
        )
        cmd += f" -object {shlex.quote(object_name)}"
        if command:
            cmd += f" {shlex.quote(command)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_getTGT(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        aesKey: str = "",
    ) -> str:
        """
        Request a Kerberos TGT for a user.

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            dc_ip: DC IP address
            aesKey: AES key for authentication
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"getTGT.py {identity}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if aesKey:
            cmd += f" -aesKey {shlex.quote(aesKey)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_getST(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        spn: str = "",
        impersonate: str = "",
        dc_ip: str = "",
        aesKey: str = "",
    ) -> str:
        """
        Request a Kerberos service ticket (S4U2Self/S4U2Proxy for delegation attacks).

        Args:
            domain: AD domain
            username: Username (of the delegating account)
            password: Password
            hashes: NTLM hash
            spn: Target SPN (e.g., cifs/DC.domain.local)
            impersonate: User to impersonate
            dc_ip: DC IP address
            aesKey: AES key
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"getST.py {identity}"
        if spn:
            cmd += f" -spn {shlex.quote(spn)}"
        if impersonate:
            cmd += f" -impersonate {shlex.quote(impersonate)}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if aesKey:
            cmd += f" -aesKey {shlex.quote(aesKey)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_GetUserSPNs(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        request: bool = True,
        target_domain: str = "",
        outputfile: str = "",
    ) -> str:
        """
        Kerberoast - find and request service tickets for accounts with SPNs.

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            dc_ip: DC IP address
            request: Request TGS tickets (for cracking)
            target_domain: Target domain for cross-domain
            outputfile: Save hashes to file
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"GetUserSPNs.py {identity}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if request:
            cmd += " -request"
        if target_domain:
            cmd += f" -target-domain {shlex.quote(target_domain)}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if outputfile:
            cmd += f" -outputfile {shlex.quote(outputfile)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_GetNPUsers(
        domain: str,
        username: str = "",
        usersfile: str = "",
        dc_ip: str = "",
        outputfile: str = "",
        no_pass: bool = False,
    ) -> str:
        """
        AS-REP Roast - find users without Kerberos pre-authentication.

        Args:
            domain: AD domain
            username: Username to check (or empty for usersfile)
            usersfile: File with usernames to check
            dc_ip: DC IP address
            outputfile: Save hashes to file
            no_pass: Don't supply password (for unauthenticated)
        """
        cmd = f"GetNPUsers.py {shlex.quote(domain)}/"
        if username:
            cmd += shlex.quote(username)
        if no_pass:
            cmd += " -no-pass"
        if usersfile:
            cmd += f" -usersfile {shlex.quote(usersfile)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if outputfile:
            cmd += f" -outputfile {shlex.quote(outputfile)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_addcomputer(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        computer_name: str = "",
        computer_pass: str = "",
        dc_ip: str = "",
    ) -> str:
        """
        Add a computer account to the domain (for RBCD attacks).

        Args:
            domain: AD domain
            username: Username with MachineAccountQuota > 0
            password: Password
            hashes: NTLM hash
            computer_name: Name for new computer (with or without $)
            computer_pass: Password for new computer
            dc_ip: DC IP address
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"addcomputer.py {identity}"
        if computer_name:
            cmd += f" -computer-name {shlex.quote(computer_name)}"
        if computer_pass:
            cmd += f" -computer-pass {shlex.quote(computer_pass)}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_rbcd(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        action: str = "write",
        delegate_from: str = "",
        delegate_to: str = "",
        dc_ip: str = "",
    ) -> str:
        """
        Manage Resource-Based Constrained Delegation (RBCD).

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            action: Action (read, write, remove, flush)
            delegate_from: Computer to delegate FROM (attacker-controlled)
            delegate_to: Computer to delegate TO (target)
            dc_ip: DC IP address
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"rbcd.py {identity} -action {shlex.quote(action)}"
        if delegate_from:
            cmd += f" -delegate-from {shlex.quote(delegate_from)}"
        if delegate_to:
            cmd += f" -delegate-to {shlex.quote(delegate_to)}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_dacledit(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        action: str = "read",
        rights: str = "",
        principal: str = "",
        target_obj: str = "",
        dc_ip: str = "",
    ) -> str:
        """
        Edit DACLs (Discretionary Access Control Lists) on AD objects.

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            action: Action (read, write, remove)
            rights: Rights to set (FullControl, WriteMembers, DCSync, etc.)
            principal: Security principal to grant rights to
            target_obj: Target AD object
            dc_ip: DC IP address
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"dacledit.py {identity} -action {shlex.quote(action)}"
        if rights:
            cmd += f" -rights {shlex.quote(rights)}"
        if principal:
            cmd += f" -principal {shlex.quote(principal)}"
        if target_obj:
            cmd += f" -target {shlex.quote(target_obj)}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_findDelegation(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
    ) -> str:
        """
        Find all delegation configurations in the domain.

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            dc_ip: DC IP address
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"findDelegation.py {identity}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_mssqlclient(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        windows_auth: bool = True,
        query: str = "",
    ) -> str:
        """
        Connect to MSSQL and optionally execute a query.

        Args:
            target: MSSQL server IP
            domain: AD domain
            username: Username
            password: Password
            windows_auth: Use Windows authentication
            query: SQL query to execute (empty for interactive)
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}" if domain else shlex.quote(username)
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"mssqlclient.py {identity}@{shlex.quote(target)}"
        if windows_auth:
            cmd += " -windows-auth"
        if query:
            cmd += f" -query {shlex.quote(query)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_smbclient(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
    ) -> str:
        """
        Connect to SMB shares and list available shares.

        Args:
            target: Target IP
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
        """
        cmd = _build_impacket_cmd(
            "smbclient.py", target, domain, username, password, hashes
        )
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_lookupsid(
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        max_rid: int = 4000,
    ) -> str:
        """
        SID brute-forcing / RID cycling to enumerate domain users.

        Args:
            target: Target IP
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            max_rid: Maximum RID to enumerate
        """
        cmd = _build_impacket_cmd(
            "lookupsid.py", target, domain, username, password, hashes
        )
        cmd += f" {max_rid}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_GetLAPSPassword(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        computer: str = "",
    ) -> str:
        """
        Read LAPS passwords from Active Directory.

        Args:
            domain: AD domain
            username: Username with ReadLAPSPassword rights
            password: Password
            hashes: NTLM hash
            dc_ip: DC IP address
            computer: Specific computer to query
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"getLAPSPassword.py {identity}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if computer:
            cmd += f" -computer {shlex.quote(computer)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def impacket_GetGPPPassword(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
    ) -> str:
        """
        Extract Group Policy Preferences passwords from SYSVOL.

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            dc_ip: DC IP (target)
        """
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"
        cmd = f"Get-GPPPassword.py {identity}@{shlex.quote(dc_ip) if dc_ip else ''}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        result = _run_cmd(cmd)
        return _format_response(data=result)

    # ========================================================================
    # NETEXEC
    # ========================================================================

    @mcp.tool()
    async def netexec(
        target: str,
        protocol: str = "smb",
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
        action: str = "",
        module: str = "",
        module_options: str = "",
        execute: str = "",
        exec_type: str = "cmd",
        local_auth: bool = False,
        continue_on_success: bool = False,
        extra_args: str = "",
    ) -> str:
        """
        Run NetExec (nxc) for multi-protocol credential validation and enumeration.
        Supports SMB, LDAP, WinRM, RDP, MSSQL, SSH, WMI protocols.

        Args:
            target: Target IP, range, or CIDR
            protocol: Protocol (smb, ldap, winrm, rdp, mssql, ssh, wmi)
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            action: Action flag (--shares, --users, --groups, --sessions, --sam, --lsa, --ntds, --rid-brute, --pass-pol, etc.)
            module: NXC module to run (-M)
            module_options: Module options (-o KEY=VAL)
            execute: Command to execute (-x for cmd, -X for PS)
            exec_type: Execution type (cmd or powershell)
            local_auth: Use local authentication
            continue_on_success: Continue after finding valid creds
            extra_args: Additional arguments
        """
        cmd = f"NetExec {shlex.quote(protocol)} {shlex.quote(target)}"

        if username:
            cmd += f" -u {shlex.quote(username)}"
        else:
            cmd += " -u ''"

        if hashes:
            cmd += f" -H {shlex.quote(hashes)}"
        elif password:
            cmd += f" -p {shlex.quote(password)}"
        else:
            cmd += " -p ''"

        if domain:
            cmd += f" -d {shlex.quote(domain)}"
        if local_auth:
            cmd += " --local-auth"
        if continue_on_success:
            cmd += " --continue-on-success"
        if action:
            # action should be a flag like --shares, --users, etc.
            if not action.startswith("--"):
                action = f"--{action}"
            cmd += f" {action}"
        if execute:
            flag = "-X" if exec_type in ("powershell", "ps") else "-x"
            cmd += f" {flag} {shlex.quote(execute)}"
        if module:
            cmd += f" -M {shlex.quote(module)}"
            if module_options:
                cmd += f" -o {module_options}"
        if extra_args:
            cmd += f" {extra_args}"

        result = _run_cmd(cmd, LONG_TIMEOUT)
        return _format_response(data=result)

    # ========================================================================
    # BLOODYAD
    # ========================================================================

    @mcp.tool()
    async def bloodyad(
        dc_ip: str,
        domain: str,
        username: str,
        password: str,
        action: str = "get",
        subcommand: str = "writable",
        target_obj: str = "",
        extra_args: str = "",
    ) -> str:
        """
        Run BloodyAD for ACL enumeration and abuse in Active Directory.
        Finds writable objects, dangerous permissions, and enables ACL attacks.

        Args:
            dc_ip: Domain Controller IP
            domain: AD domain
            username: Username
            password: Password
            action: Action (get, set, add, remove)
            subcommand: Subcommand (writable, owned, object, membership, children, search, groupMember, etc.)
            target_obj: Target object for queries
            extra_args: Additional arguments
        """
        cmd = (
            f"bloodyAD -u {shlex.quote(username)} "
            f"-p {shlex.quote(password)} "
            f"-d {shlex.quote(domain)} "
            f"--host {shlex.quote(dc_ip)} "
            f"{shlex.quote(action)} {shlex.quote(subcommand)}"
        )
        if target_obj:
            cmd += f" {shlex.quote(target_obj)}"
        if extra_args:
            cmd += f" {extra_args}"

        result = _run_cmd(cmd)
        return _format_response(data=result)

    # ========================================================================
    # CERTIPY
    # ========================================================================

    @mcp.tool()
    async def certipy_find(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        vulnerable: bool = True,
        output: str = "",
    ) -> str:
        """
        Run Certipy to enumerate ADCS certificate templates and find vulnerabilities.
        Detects ESC1-ESC16, misconfigured templates, CA misconfigurations.

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            dc_ip: DC IP address
            vulnerable: Only show vulnerable templates
            output: Output file prefix
        """
        certipy = _find_certipy_bin()
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"

        cmd = f"{certipy} find -u {identity}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if vulnerable:
            cmd += " -vulnerable"
        if output:
            cmd += f" -output {shlex.quote(output)}"

        result = _run_cmd(cmd, LONG_TIMEOUT)
        return _format_response(data=result)

    @mcp.tool()
    async def certipy_req(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        ca: str = "",
        template: str = "",
        upn: str = "",
        dns: str = "",
    ) -> str:
        """
        Request a certificate from ADCS (for ESC1/ESC2/ESC3 exploitation).

        Args:
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash
            dc_ip: DC IP
            ca: Certificate Authority name
            template: Certificate template name
            upn: Alternative UPN for the certificate
            dns: Alternative DNS name for the certificate
        """
        certipy = _find_certipy_bin()
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"

        cmd = f"{certipy} req -u {identity}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if hashes:
            cmd += f" -hashes {shlex.quote(hashes)}"
        if ca:
            cmd += f" -ca {shlex.quote(ca)}"
        if template:
            cmd += f" -template {shlex.quote(template)}"
        if upn:
            cmd += f" -upn {shlex.quote(upn)}"
        if dns:
            cmd += f" -dns {shlex.quote(dns)}"

        result = _run_cmd(cmd, LONG_TIMEOUT)
        return _format_response(data=result)

    @mcp.tool()
    async def certipy_auth(
        domain: str,
        username: str,
        pfx: str,
        dc_ip: str = "",
    ) -> str:
        """
        Authenticate using a certificate (PFX file) to get NT hash or TGT.

        Args:
            domain: AD domain
            username: Username
            pfx: Path to PFX certificate file
            dc_ip: DC IP address
        """
        certipy = _find_certipy_bin()
        cmd = (
            f"{certipy} auth -pfx {shlex.quote(pfx)} "
            f"-username {shlex.quote(username)} "
            f"-domain {shlex.quote(domain)}"
        )
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"

        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def certipy_shadow(
        domain: str,
        username: str,
        password: str = "",
        account: str = "",
        dc_ip: str = "",
        auto: bool = True,
    ) -> str:
        """
        Shadow Credentials attack - add key credentials to a target account.

        Args:
            domain: AD domain
            username: Attacking username
            password: Password
            account: Target account to add shadow credentials to
            dc_ip: DC IP
            auto: Auto mode (adds cred, requests cert, authenticates)
        """
        certipy = _find_certipy_bin()
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
        if password:
            identity += f":{shlex.quote(password)}"

        cmd = f"{certipy} shadow"
        if auto:
            cmd += " auto"
        cmd += f" -u {identity}"
        if account:
            cmd += f" -account {shlex.quote(account)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"

        result = _run_cmd(cmd, LONG_TIMEOUT)
        return _format_response(data=result)

    # ========================================================================
    # ENUMERATION / RECON
    # ========================================================================

    @mcp.tool()
    async def nmap_scan(
        target: str,
        ports: str = "",
        scan_type: str = "-sV",
        scripts: str = "",
        extra_args: str = "",
    ) -> str:
        """
        Run nmap port scan.

        Args:
            target: Target IP or range
            ports: Port specification (-p 80,443 or -p-)
            scan_type: Scan type flags (e.g., -sV, -sC, -sS)
            scripts: NSE scripts (e.g., smb-enum-shares)
            extra_args: Additional nmap arguments
        """
        cmd = f"nmap {scan_type}"
        if ports:
            cmd += f" -p {shlex.quote(ports)}"
        if scripts:
            cmd += f" --script={shlex.quote(scripts)}"
        if extra_args:
            cmd += f" {extra_args}"
        cmd += f" {shlex.quote(target)}"

        result = _run_cmd(cmd, LONG_TIMEOUT)
        return _format_response(data=result)

    @mcp.tool()
    async def ldap_search(
        dc_ip: str,
        base_dn: str,
        bind_dn: str = "",
        password: str = "",
        filter_str: str = "(objectClass=*)",
        attributes: str = "",
        scope: str = "sub",
    ) -> str:
        """
        Run LDAP search query against Active Directory.

        Args:
            dc_ip: Domain controller IP
            base_dn: Search base DN (e.g., DC=westeros,DC=local)
            bind_dn: Bind DN (e.g., CN=ned,OU=Stark,DC=westeros,DC=local)
            password: Bind password
            filter_str: LDAP filter
            attributes: Attributes to return (space-separated)
            scope: Search scope (base, one, sub)
        """
        cmd = f"ldapsearch -x -H ldap://{shlex.quote(dc_ip)}"
        if bind_dn:
            cmd += f" -D {shlex.quote(bind_dn)}"
        if password:
            cmd += f" -w {shlex.quote(password)}"
        cmd += f" -b {shlex.quote(base_dn)}"
        cmd += f" -s {shlex.quote(scope)}"
        cmd += f" {shlex.quote(filter_str)}"
        if attributes:
            cmd += f" {attributes}"

        result = _run_cmd(cmd)
        return _format_response(data=result)

    # ========================================================================
    # UWU MODULE MANAGEMENT
    # ========================================================================

    @mcp.tool()
    async def uwu_list_modules(
        search: str = "",
        module_type: str = "",
    ) -> str:
        """
        List available UwU Toolkit modules. Optionally search by name/tag.

        Args:
            search: Search query (matches name, description, tags)
            module_type: Filter by type (auxiliary, exploit, enumeration, post, payloads)
        """
        modules_path = os.path.join(UWU_ROOT, "modules")
        if not os.path.isdir(modules_path):
            return _format_response(error=f"Modules path not found: {modules_path}")

        try:
            # Use uwu-toolkit's ModuleLoader
            import sys
            if UWU_ROOT not in sys.path:
                sys.path.insert(0, UWU_ROOT)

            from core.module_loader import ModuleLoader
            loader = ModuleLoader(modules_path)
            discovered = loader.discover_modules()

            results = []
            for path, info in sorted(discovered.items()):
                # Apply search filter
                if search:
                    query = search.lower()
                    searchable = f"{info.name} {info.description} {' '.join(info.tags)} {info.path}".lower()
                    if query not in searchable:
                        continue
                # Apply type filter
                if module_type and info.module_type.value != module_type:
                    continue

                results.append({
                    "path": info.path,
                    "name": info.name,
                    "description": info.description,
                    "type": info.module_type.value,
                    "platform": str(info.platform),
                    "tags": info.tags,
                })

            return _format_response(
                data={"modules": results, "count": len(results)},
                message=f"Found {len(results)} modules"
            )
        except Exception as e:
            return _format_response(error=f"Failed to list modules: {e}")

    @mcp.tool()
    async def uwu_run_module(
        module_path: str,
        options: str = "{}",
    ) -> str:
        """
        Load and run a UwU Toolkit module with given options.

        Args:
            module_path: Module path (e.g., auxiliary/ad/kerberoast)
            options: JSON object of option name -> value pairs
        """
        modules_path = os.path.join(UWU_ROOT, "modules")
        try:
            import sys
            if UWU_ROOT not in sys.path:
                sys.path.insert(0, UWU_ROOT)

            from core.module_loader import ModuleLoader
            from core.config import Config

            loader = ModuleLoader(modules_path)
            module = loader.load_module(module_path)
            if not module:
                return _format_response(error=f"Module not found: {module_path}")

            # Set up config
            config = Config()
            module.set_config(config)

            # Set options
            opts = json.loads(options) if isinstance(options, str) else options
            for name, value in opts.items():
                module.set_option(name.upper(), str(value))

            # Validate
            valid, missing = module.validate_options()
            if not valid:
                return _format_response(
                    error=f"Missing required options: {', '.join(missing)}"
                )

            # Capture output
            import io
            from contextlib import redirect_stdout, redirect_stderr
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()

            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                success = module.run()

            output = stdout_buf.getvalue() + stderr_buf.getvalue()
            return _format_response(
                data={
                    "success": success,
                    "output": output,
                    "module": module_path,
                },
                success=success,
                message=f"Module {module_path} {'completed' if success else 'failed'}"
            )
        except Exception as e:
            return _format_response(error=f"Module execution error: {e}")

    @mcp.tool()
    async def uwu_module_info(module_path: str) -> str:
        """
        Get detailed information about a UwU Toolkit module including options.

        Args:
            module_path: Module path (e.g., auxiliary/ad/kerberoast)
        """
        modules_path = os.path.join(UWU_ROOT, "modules")
        try:
            import sys
            if UWU_ROOT not in sys.path:
                sys.path.insert(0, UWU_ROOT)

            from core.module_loader import ModuleLoader
            loader = ModuleLoader(modules_path)
            module = loader.load_module(module_path)
            if not module:
                return _format_response(error=f"Module not found: {module_path}")

            options = {}
            for name, opt in module._options.items():
                options[name] = {
                    "description": opt.description,
                    "required": opt.required,
                    "default": opt.default,
                    "choices": opt.choices if opt.choices else None,
                    "value": opt.value,
                }

            info = {
                "name": module.name,
                "description": module.description,
                "author": module.author,
                "version": module.version,
                "type": module.module_type.value if module.module_type else "",
                "platform": module.platform.value if module.platform else "",
                "tags": module.tags,
                "references": module.references,
                "options": options,
            }
            return _format_response(data=info)
        except Exception as e:
            return _format_response(error=f"Failed to get module info: {e}")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _build_impacket_cmd(
    tool: str,
    target: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    hashes: str = "",
    dc_ip: str = "",
) -> str:
    """Build standard Impacket command string."""
    if domain and username:
        identity = f"{shlex.quote(domain)}/{shlex.quote(username)}"
    elif username:
        identity = shlex.quote(username)
    else:
        identity = "''"

    if password:
        identity += f":{shlex.quote(password)}"

    cmd = f"{tool} {identity}@{shlex.quote(target)}"
    if hashes:
        cmd += f" -hashes {shlex.quote(hashes)}"
    if dc_ip:
        cmd += f" -dc-ip {shlex.quote(dc_ip)}"
    return cmd


def _find_certipy_bin() -> str:
    """Find certipy binary in known locations."""
    search_paths = [
        "/opt/tools/Certipy/venv/bin/certipy",
        "/root/.local/share/pipx/venvs/certipy/bin/certipy",
        "/root/.local/share/pipx/venvs/netexec/bin/certipy",
        "/root/.local/share/pipx/venvs/certsync/bin/certipy",
        "/root/.local/bin/certipy",
    ]
    for path in search_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    # Fallback to PATH
    import shutil
    found = shutil.which("certipy")
    return found or "certipy"
