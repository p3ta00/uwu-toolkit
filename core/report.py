"""
Report generator for UwU Toolkit
Generates Markdown and HTML reports from EngagementDB data.

Usage:
    from core.report import generate_report
    generate_report("report.md", format="markdown")
    generate_report("report.html", format="html")
"""

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from .engagement_db import EngagementDB


def generate_report(
    output_path: str,
    fmt: str = "markdown",
    engagement_name: str = "",
    author: str = "",
) -> bool:
    """
    Generate a report from the engagement database.

    Args:
        output_path: File path for the report
        fmt: Format - "markdown" or "html"
        engagement_name: Name for the report title
        author: Author name

    Returns:
        True on success
    """
    db = EngagementDB.get_instance()

    targets = db.list_targets()
    creds = db.list_credentials()
    findings = db.list_findings()
    timeline = db.get_timeline(limit=1000)
    loot = db.list_loot()
    edges = db.list_edges()

    if fmt == "html":
        content = _generate_html(engagement_name, author, targets, creds,
                                  findings, timeline, loot, edges)
    else:
        content = _generate_markdown(engagement_name, author, targets, creds,
                                      findings, timeline, loot, edges)

    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(content)
        return True
    except OSError:
        return False


def _generate_markdown(name, author, targets, creds, findings, timeline, loot, edges) -> str:
    lines = []
    title = name or "Penetration Test Report"
    lines.append(f"# {title}")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if author:
        lines.append(f"**Author:** {author}")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    crit_high = len([f for f in findings if f.get("severity") in ("critical", "high")])
    lines.append(f"- **{len(targets)}** targets assessed")
    lines.append(f"- **{len(findings)}** findings ({crit_high} critical/high)")
    lines.append(f"- **{len(creds)}** credentials obtained")
    lines.append(f"- **{len(edges)}** attack paths identified")
    lines.append("")

    # Findings
    if findings:
        lines.append("## Findings")
        for sev in ("critical", "high", "medium", "low", "info"):
            sev_findings = [f for f in findings if f.get("severity") == sev]
            if not sev_findings:
                continue
            lines.append(f"### {sev.upper()} ({len(sev_findings)})")
            for f in sev_findings:
                lines.append(f"#### {f.get('title', 'Untitled')}")
                if f.get("description"):
                    lines.append(f"{f['description']}")
                if f.get("evidence"):
                    lines.append(f"\n**Evidence:**\n```\n{f['evidence'][:500]}\n```")
                if f.get("remediation"):
                    lines.append(f"\n**Remediation:** {f['remediation']}")
                if f.get("module_used"):
                    lines.append(f"\n*Discovered via:* `{f['module_used']}`")
                lines.append("")

    # Targets
    if targets:
        lines.append("## Targets")
        lines.append("| # | IP | Hostname | Domain | OS | DC | Ports |")
        lines.append("|---|---|---|---|---|---|---|")
        for t in targets:
            ports = t.get("ports", [])
            port_str = ", ".join(str(p.get("port", "")) for p in ports[:5]) if isinstance(ports, list) else ""
            if isinstance(ports, list) and len(ports) > 5:
                port_str += f" (+{len(ports)-5})"
            dc = "DC" if t.get("is_dc") else ""
            lines.append(f"| {t.get('id','')} | {t.get('ip','')} | {t.get('hostname','')} | "
                        f"{t.get('domain','')} | {t.get('os_info','')} | {dc} | {port_str} |")
        lines.append("")

    # Credentials
    if creds:
        lines.append("## Credentials")
        lines.append("| # | Username | Domain | Type | Source | Password/Hash | Admin On |")
        lines.append("|---|---|---|---|---|---|---|")
        for c in creds:
            secret = c.get("password", "") or (c.get("ntlm_hash", "")[:16] + "..." if c.get("ntlm_hash") else "")
            admin_on = c.get("admin_on", [])
            admin_str = ", ".join(admin_on[:3]) if isinstance(admin_on, list) else ""
            lines.append(f"| {c.get('id','')} | {c.get('username','')} | {c.get('domain','')} | "
                        f"{c.get('cred_type','')} | {c.get('source','')} | `{secret}` | {admin_str} |")
        lines.append("")

    # Attack Graph
    if edges:
        lines.append("## Attack Graph")
        exploited = [e for e in edges if e.get("exploited")]
        unexploited = [e for e in edges if not e.get("exploited")]
        if exploited:
            lines.append("### Exploited Paths")
            for e in exploited:
                lines.append(f"- **{e.get('source_node')}** --[{e.get('edge_type')}]--> "
                            f"**{e.get('target_node')}** *(via {e.get('module_used', 'manual')})*")
        if unexploited:
            lines.append("### Identified (Not Exploited)")
            for e in unexploited:
                lines.append(f"- {e.get('source_node')} --[{e.get('edge_type')}]--> {e.get('target_node')}")
        lines.append("")

    # Loot
    if loot:
        lines.append("## Loot")
        for l in loot:
            lines.append(f"- **{l.get('loot_type', 'file')}**: `{l.get('filepath', '')}` — {l.get('description', '')}")
        lines.append("")

    # Timeline
    if timeline:
        lines.append("## Activity Timeline")
        lines.append("| Time | Action | Target | Result | OPSEC |")
        lines.append("|---|---|---|---|---|")
        for t in timeline[:100]:
            opsec = t.get("opsec_rating", "")
            opsec_mark = f"**{opsec.upper()}**" if opsec in ("high", "loud") else opsec
            lines.append(f"| {t.get('timestamp','')[:19]} | {t.get('action','')} | "
                        f"{t.get('target','')} | {t.get('result','')} | {opsec_mark} |")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by UwU Toolkit*")

    return "\n".join(lines)


def _generate_html(name, author, targets, creds, findings, timeline, loot, edges) -> str:
    """Generate HTML report with embedded CSS"""
    title = name or "Penetration Test Report"
    md_content = _generate_markdown(name, author, targets, creds, findings, timeline, loot, edges)

    # Simple markdown-to-HTML conversion
    html_body = _md_to_html(md_content)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0a0a1a; color: #e0e0e0; }}
h1 {{ color: #ff10f0; border-bottom: 2px solid #ff10f0; padding-bottom: 10px; }}
h2 {{ color: #00e8ff; margin-top: 30px; }}
h3 {{ color: #ff7c00; }}
h4 {{ color: #b620e0; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th {{ background: #1a1a3a; color: #00e8ff; padding: 8px; text-align: left; border: 1px solid #333; }}
td {{ padding: 8px; border: 1px solid #333; }}
tr:nth-child(even) {{ background: #111130; }}
code {{ background: #1a1a3a; padding: 2px 6px; border-radius: 3px; color: #00ff9f; font-family: 'Cascadia Code', monospace; }}
pre {{ background: #1a1a3a; padding: 15px; border-radius: 5px; overflow-x: auto; border-left: 3px solid #ff10f0; }}
pre code {{ background: none; padding: 0; }}
strong {{ color: #ff10f0; }}
ul, ol {{ padding-left: 25px; }}
li {{ margin: 4px 0; }}
hr {{ border: 1px solid #333; margin: 20px 0; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""


def _md_to_html(md: str) -> str:
    """Basic markdown to HTML converter"""
    lines = md.split("\n")
    html_lines = []
    in_table = False
    in_code = False
    in_list = False

    for line in lines:
        # Code blocks
        if line.strip().startswith("```"):
            if in_code:
                html_lines.append("</code></pre>")
                in_code = False
            else:
                html_lines.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            html_lines.append(line)
            continue

        # Headers
        if line.startswith("#### "):
            html_lines.append(f"<h4>{_inline_md(line[5:])}</h4>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{_inline_md(line[4:])}</h3>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{_inline_md(line[3:])}</h2>")
        elif line.startswith("# "):
            html_lines.append(f"<h1>{_inline_md(line[2:])}</h1>")
        # Table
        elif "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= {"-", " ", ":"} for c in cells):
                continue  # Skip separator row
            if not in_table:
                html_lines.append("<table><thead><tr>")
                for c in cells:
                    html_lines.append(f"<th>{_inline_md(c)}</th>")
                html_lines.append("</tr></thead><tbody>")
                in_table = True
            else:
                html_lines.append("<tr>")
                for c in cells:
                    html_lines.append(f"<td>{_inline_md(c)}</td>")
                html_lines.append("</tr>")
        else:
            if in_table:
                html_lines.append("</tbody></table>")
                in_table = False
            # List items
            if line.strip().startswith("- "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                html_lines.append(f"<li>{_inline_md(line.strip()[2:])}</li>")
            else:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                if line.strip() == "---":
                    html_lines.append("<hr>")
                elif line.strip():
                    html_lines.append(f"<p>{_inline_md(line)}</p>")

    if in_table:
        html_lines.append("</tbody></table>")
    if in_list:
        html_lines.append("</ul>")
    if in_code:
        html_lines.append("</code></pre>")

    return "\n".join(html_lines)


def _inline_md(text: str) -> str:
    """Convert inline markdown (bold, code, italic)"""
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    return text
