"""MCP tools for NetExec and BloodyAD operations."""

import shlex
from .common import _run_cmd, _format_response, LONG_TIMEOUT


def register(mcp):

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

    @mcp.tool()
    async def bloodyad(
        dc_ip: str,
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
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
            hashes: NTLM hash in LM:NT format (passed via -p, mutually exclusive with password)
            action: Action (get, set, add, remove)
            subcommand: Subcommand (writable, owned, object, membership, children, search, groupMember, etc.)
            target_obj: Target object for queries
            extra_args: Additional arguments
        """
        auth_val = hashes if hashes else password
        cmd = (
            f"bloodyAD -u {shlex.quote(username)} "
            f"-p {shlex.quote(auth_val)} "
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
