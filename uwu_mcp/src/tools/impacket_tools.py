"""MCP tools for Impacket-based operations."""

import shlex
from .common import _run_cmd, _format_response, _build_impacket_cmd, DEFAULT_TIMEOUT, LONG_TIMEOUT


def register(mcp):

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
        # GetLAPSPassword uses positional target: domain/user:pass@host
        target_host = dc_ip or "127.0.0.1"
        cmd = _build_impacket_cmd(
            "GetLAPSPassword.py", target_host, domain, username, password, hashes, dc_ip
        )
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
