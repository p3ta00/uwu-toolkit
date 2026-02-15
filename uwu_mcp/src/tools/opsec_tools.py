"""MCP tools for OPSEC awareness."""

import sys
import os
from .common import _format_response, UWU_ROOT


def register(mcp):

    def _import_opsec():
        if UWU_ROOT not in sys.path:
            sys.path.insert(0, UWU_ROOT)
        import core.opsec as opsec
        return opsec

    @mcp.tool()
    async def opsec_check(tool_name: str) -> str:
        """Check the OPSEC rating and detection info for a tool before using it.

        Args:
            tool_name: Tool name (e.g., "psexec", "secretsdump", "certipy", "bloodhound")
        """
        try:
            opsec = _import_opsec()
            info = opsec.get_opsec_info(tool_name)
            if not info:
                return _format_response(error=f"No OPSEC data for '{tool_name}'")
            return _format_response(data={
                "tool": tool_name,
                "rating": info.rating.value,
                "description": info.description,
                "artifacts": info.artifacts,
                "event_ids": info.event_ids,
                "detection_rules": info.detection_rules,
                "alternatives": [
                    {"tool": t, "rating": r.value, "notes": n}
                    for t, r, n in info.alternatives
                ],
                "mitigations": info.mitigations,
            })
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def opsec_compare(tool_names: str) -> str:
        """Compare OPSEC profiles of multiple tools side-by-side.

        Args:
            tool_names: Comma-separated tool names (e.g., "psexec,wmiexec,smbexec,atexec")
        """
        try:
            opsec = _import_opsec()
            names = [n.strip() for n in tool_names.split(",") if n.strip()]
            comparison = opsec.compare_tools(names)
            return _format_response(data={"comparison": comparison})
        except Exception as e:
            return _format_response(error=str(e))

    @mcp.tool()
    async def opsec_list(rating: str = "") -> str:
        """List all tools and their OPSEC ratings, optionally filtered.

        Args:
            rating: Filter by rating (stealth, low, medium, high, loud). Empty for all.
        """
        try:
            opsec = _import_opsec()
            if rating:
                try:
                    r = opsec.OpsecRating(rating.lower())
                except ValueError:
                    return _format_response(error=f"Invalid rating '{rating}'. Valid: stealth, low, medium, high, loud")
                tools = opsec.list_by_rating(r)
                result = [{"tool": name, "rating": info.rating.value, "description": info.description}
                          for name, info in tools]
                return _format_response(data={"tools": result, "count": len(result)})
            else:
                all_ratings = opsec.list_all_ratings()
                return _format_response(data={"ratings": all_ratings})
        except Exception as e:
            return _format_response(error=str(e))
