"""MCP tools for enumeration and reconnaissance."""

import shlex
from .common import _run_cmd, _format_response, sync_clock as _sync_clock, DEFAULT_TIMEOUT, LONG_TIMEOUT


def register(mcp):

    @mcp.tool()
    async def clock_sync(dc_ip: str) -> str:
        """
        Sync container clock to a Domain Controller using faketime.

        Fixes Kerberos KRB_AP_ERR_SKEW errors caused by clock skew between
        the Exegol container and the target DC. Once synced, all subsequent
        tool calls automatically use the correct time.

        Args:
            dc_ip: Domain Controller IP to sync time from
        """
        result = _sync_clock(dc_ip)
        return _format_response(data=result)

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
