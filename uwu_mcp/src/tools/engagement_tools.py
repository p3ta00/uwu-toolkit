"""MCP tools for engagement database management."""

import json
import sys
import os
from .common import _format_response, UWU_ROOT


def register(mcp):

    def _get_db():
        if UWU_ROOT not in sys.path:
            sys.path.insert(0, UWU_ROOT)
        from core.engagement_db import EngagementDB
        return EngagementDB.get_instance()

    @mcp.tool()
    async def engagement_add_target(
        ip: str,
        hostname: str = "",
        domain: str = "",
        os_info: str = "",
        is_dc: bool = False,
        notes: str = "",
    ) -> str:
        """Add or update a target in the engagement database.

        Args:
            ip: Target IP address
            hostname: Target hostname/FQDN
            domain: Domain name
            os_info: Operating system info
            is_dc: Whether this is a Domain Controller
            notes: Additional notes
        """
        try:
            db = _get_db()
            target_id = db.add_target(ip, hostname=hostname, domain=domain,
                                       os_info=os_info, is_dc=is_dc, notes=notes)
            target = db.get_target(target_id)
            return _format_response(data=target, success=True, message=f"Target {ip} added/updated (ID {target_id})")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_list_targets(domain: str = "") -> str:
        """List all targets in the engagement database.

        Args:
            domain: Filter by domain (optional)
        """
        try:
            db = _get_db()
            targets = db.list_targets(domain=domain if domain else None)
            return _format_response(data={"targets": targets, "count": len(targets)})
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_add_credential(
        username: str,
        domain: str = "",
        password: str = "",
        ntlm_hash: str = "",
        aes_key: str = "",
        cred_type: str = "password",
        source: str = "",
        notes: str = "",
    ) -> str:
        """Add a credential to the engagement database.

        Args:
            username: Account username
            domain: Domain/realm
            password: Cleartext password
            ntlm_hash: NT hash
            aes_key: Kerberos AES key
            cred_type: Type (password, hash, ticket, certificate)
            source: How the credential was obtained (kerberoast, secretsdump, etc.)
            notes: Additional notes
        """
        try:
            db = _get_db()
            cred_id = db.add_credential(
                username, domain=domain, password=password,
                ntlm_hash=ntlm_hash, aes_key=aes_key,
                cred_type=cred_type, source=source, notes=notes,
            )
            cred = db.get_credential(cred_id)
            return _format_response(data=cred, success=True, message=f"Credential for {domain}\\{username} added (ID {cred_id})")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_list_credentials(
        domain: str = "",
        cred_type: str = "",
        source: str = "",
        cracked_only: bool = False,
    ) -> str:
        """List credentials in the engagement database.

        Args:
            domain: Filter by domain
            cred_type: Filter by type (password, hash, ticket)
            source: Filter by source
            cracked_only: Only show cracked credentials
        """
        try:
            db = _get_db()
            creds = db.list_credentials(
                domain=domain if domain else None,
                cred_type=cred_type if cred_type else None,
                source=source if source else None,
                cracked_only=cracked_only,
            )
            return _format_response(data={"credentials": creds, "count": len(creds)})
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_add_finding(
        title: str,
        severity: str = "info",
        description: str = "",
        evidence: str = "",
        target_ip: str = "",
        module_used: str = "",
        remediation: str = "",
    ) -> str:
        """Record a security finding.

        Args:
            title: Finding title
            severity: Severity (critical, high, medium, low, info)
            description: Detailed description
            evidence: Proof/evidence text
            target_ip: Related target IP
            module_used: Module/tool that found this
            remediation: Suggested fix
        """
        try:
            db = _get_db()
            target_id = None
            if target_ip:
                target = db.get_target_by_ip(target_ip)
                if target:
                    target_id = target["id"]
            finding_id = db.add_finding(
                title=title, severity=severity, description=description,
                evidence=evidence, target_id=target_id,
                module_used=module_used, remediation=remediation,
            )
            return _format_response(success=True, message=f"Finding '{title}' recorded (ID {finding_id})")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_add_loot(
        filepath: str,
        loot_type: str = "file",
        description: str = "",
        target_ip: str = "",
    ) -> str:
        """Record a loot file.

        Args:
            filepath: Path to the loot file
            loot_type: Type (file, hash_dump, config, secret, screenshot)
            description: What this loot is
            target_ip: Related target IP
        """
        try:
            db = _get_db()
            target_id = None
            if target_ip:
                target = db.get_target_by_ip(target_ip)
                if target:
                    target_id = target["id"]
            loot_id = db.add_loot(
                filepath=filepath, loot_type=loot_type,
                description=description, target_id=target_id,
            )
            return _format_response(success=True, message=f"Loot recorded (ID {loot_id})")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_timeline(
        action_type: str = "",
        last_n: int = 50,
    ) -> str:
        """Get the engagement timeline -- chronological log of all actions.

        Args:
            action_type: Filter by action type (tool_run, session_opened, credential_found, etc.)
            last_n: Number of recent entries to return
        """
        try:
            db = _get_db()
            entries = db.get_timeline(
                action_type=action_type if action_type else None,
                limit=last_n,
            )
            return _format_response(data={"timeline": entries, "count": len(entries)})
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_attack_graph(
        source: str = "",
        target: str = "",
    ) -> str:
        """Query the attack graph for paths between objects.

        Args:
            source: Source node (user, computer, group)
            target: Target node
        """
        try:
            db = _get_db()
            if source or target:
                paths = db.get_attack_paths(
                    source=source if source else None,
                    target=target if target else None,
                )
            else:
                paths = db.list_edges()
            return _format_response(data={"edges": paths, "count": len(paths)})
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_add_edge(
        source: str,
        target: str,
        edge_type: str,
        notes: str = "",
    ) -> str:
        """Add an edge to the attack graph.

        Args:
            source: Source node (e.g., "ned@westeros.local")
            target: Target node (e.g., "cersei@westeros.local")
            edge_type: Relationship type (GenericAll, ForceChangePassword, AdminTo, etc.)
            notes: Additional context
        """
        try:
            db = _get_db()
            edge_id = db.add_edge(source=source, target=target,
                                   edge_type=edge_type, notes=notes)
            return _format_response(success=True, message=f"Edge {source} -[{edge_type}]-> {target} added (ID {edge_id})")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_summary() -> str:
        """Get a summary of the current engagement -- counts of targets, credentials, findings, etc."""
        try:
            db = _get_db()
            summary = db.get_engagement_summary()
            return _format_response(data=summary)
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_import_secretsdump(filepath: str) -> str:
        """Import credentials from a secretsdump output file.

        Args:
            filepath: Path to secretsdump output file
        """
        try:
            db = _get_db()
            count = db.import_secretsdump(filepath)
            return _format_response(success=True, message=f"Imported {count} credentials from secretsdump")
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def engagement_export_hashcat(filepath: str = "") -> str:
        """Export NT hashes in hashcat format for cracking.

        Args:
            filepath: Output file path (optional, returns data if empty)
        """
        try:
            db = _get_db()
            result = db.export_hashcat(filepath if filepath else None)
            return _format_response(data={"output": result}, success=True, message="Exported hashes")
        except Exception as e:
            return _format_response(error=str(e))
