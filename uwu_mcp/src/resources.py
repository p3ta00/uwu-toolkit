"""
MCP resource definitions for UwU Toolkit.
Exposes module catalog, variables, and lab information.
"""

import json
import os
import sys

UWU_ROOT = os.environ.get("UWU_ROOT", "/opt/my-resources/tools/uwu-toolkit")


def setup_resources(mcp):
    """Register all resources with the MCP server."""

    @mcp.resource("uwu://modules")
    async def get_modules_catalog() -> str:
        """Complete catalog of all UwU Toolkit modules with paths and descriptions."""
        try:
            if UWU_ROOT not in sys.path:
                sys.path.insert(0, UWU_ROOT)
            from core.module_loader import ModuleLoader

            modules_path = os.path.join(UWU_ROOT, "modules")
            loader = ModuleLoader(modules_path)
            discovered = loader.discover_modules()

            catalog = {}
            for path, info in sorted(discovered.items()):
                mod_type = info.module_type.value
                if mod_type not in catalog:
                    catalog[mod_type] = []
                catalog[mod_type].append({
                    "path": info.path,
                    "name": info.name,
                    "description": info.description,
                    "tags": info.tags,
                    "platform": str(info.platform),
                })

            return json.dumps({
                "total": sum(len(v) for v in catalog.values()),
                "by_type": catalog,
            }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.resource("uwu://lab/iron_throne")
    async def get_iron_throne_info() -> str:
        """Iron Throne AD lab configuration - domain, users, credentials, attack paths."""
        lab_info = {
            "domain": "westeros.local",
            "netbios": "WESTEROS",
            "dc": {
                "hostname": "KINGSLANDING",
                "fqdn": "KINGSLANDING.westeros.local",
                "ip_external": "10.2.10.1",
                "ip_internal": "192.168.2.1",
                "services": ["LDAP", "LDAPS", "Kerberos", "SMB", "DNS", "WinRM", "MSSQL", "ADCS", "HTTP"],
            },
            "workstation": {
                "hostname": "WINTERFELL",
                "fqdn": "WINTERFELL.westeros.local",
                "ip_external": "10.2.10.20",
                "ip_internal": "192.168.2.20",
            },
            "linux": {
                "hostname": "DRAGONSTONE",
                "fqdn": "DRAGONSTONE.westeros.local",
                "ip_external": "10.2.10.10",
                "ip_internal": "192.168.2.10",
            },
            "ca": "WESTEROS-KINGSLANDING-CA",
            "users": {
                "stark": {
                    "ned": {"pass": "Winter123!", "notes": "AS-REP Roastable, HasSession on WINTERFELL"},
                    "arya": {"pass": "Needle123!", "notes": "GenericWrite on cersei, WriteAccountRestrictions on WINTERFELL$ (RBCD)"},
                    "sansa": {"pass": "Lemon123!", "notes": "GenericAll on svc_ravens, ForceChangePassword on ned, WriteOwner OU=Stark"},
                    "jon": {"pass": "Ghost1234!", "notes": "DCSync (GetChanges + GetChangesAll)"},
                    "bran": {"pass": "ThreeEyed1!", "notes": "WriteDACL on Northmen, AddMember on Maesters"},
                },
                "lannister": {
                    "cersei": {"pass": "Wildfire1!", "notes": "AllExtendedRights OU=Lannister, ManageCertificates (ESC7), WriteDACL on jaime"},
                    "jaime": {"pass": "Kingslayer1!", "notes": "AdminTo WINTERFELL, WriteSPN on svc_goldcloaks, CanPSRemote WINTERFELL"},
                    "tyrion": {"pass": "Imp12345!", "notes": "ExecuteDCOM on WINTERFELL, SQLAdmin MSSQL, WritePKIEnrollmentFlag (ESC4)"},
                    "tywin": {"pass": "GoldMine1!", "notes": "Domain Admin, AddAllowedToAct on KINGSLANDING$"},
                    "joffrey": {"pass": "Crown1234!", "notes": "AddMember on Kingsguard, WriteGPLink OU=Lannister"},
                },
                "targaryen": {
                    "daenerys": {"pass": "Dracarys1!", "notes": "GenericAll on Domain object"},
                    "viserys": {"pass": "Dragon123!", "notes": "DumpSMSAPassword, WritePKINameFlag, Enroll on vuln templates"},
                    "missandei": {"pass": "Freedom1!", "notes": "CanRDP WINTERFELL, AddSelf Unsullied, ReadLAPSPassword"},
                    "jorah": {"pass": "Khaleesi1!", "notes": "Constrained Delegation cifs/KINGSLANDING, Owns svc_ravens"},
                    "greyworm": {"pass": "Spear1234!", "notes": "ForceChangePassword on viserys, GenericAll on theon"},
                },
                "greyjoy": {
                    "theon": {"pass": "Reek12345!", "notes": "GenericWrite on KINGSLANDING$ (RBCD), WriteOwner DRAGONSTONE$"},
                    "euron": {"pass": "Silence1!", "notes": "AddKeyCredentialLink on tywin (Shadow Creds), WriteOwner Ironborn"},
                    "yara": {"pass": "IronPrice1!", "notes": "CanPSRemote DRAGONSTONE, GenericAll cersei, ManageCA (ESC7)"},
                    "balon": {"pass": "Pyke12345!", "notes": "HasSIDHistory, Owns GPOs"},
                    "victarion": {"pass": "Kraken123!", "notes": "WriteDACL cert templates (ESC4), AddMember Ironborn"},
                },
            },
            "service_accounts": {
                "svc_goldcloaks": {"pass": "GoldCloak1!", "spn": "HTTP/goldcloaks.westeros.local", "notes": "Kerberoastable"},
                "svc_maesters": {"pass": "Oldtown1!", "spn": "HTTP/maesters.westeros.local", "notes": "Kerberoastable"},
                "svc_wildfire": {"pass": "BurnThemAll!", "spn": "MSSQLSvc/KINGSLANDING:1433", "notes": "Kerberoastable, AdminTo KINGSLANDING, Unconstrained Deleg"},
                "svc_kingsguard": {"pass": "Protect1!", "spn": "HTTP/kingsguard.westeros.local", "notes": "Kerberoastable, GenericAll DRAGONSTONE$"},
                "svc_faceless": {"pass": "Valar1234!", "spn": "HTTP/faceless.westeros.local", "notes": "Kerberoastable, Constrained Deleg ldap/KINGSLANDING"},
                "svc_nightswatch": {"pass": "TheWall1!", "spn": "HTTP/nightswatch.westeros.local", "notes": "Kerberoastable, CanPSRemote DRAGONSTONE"},
                "svc_sqlfire": {"pass": "Dragonfire1!", "spn": "MSSQLSvc/KINGSLANDING:1433", "notes": "Kerberoastable, runs MSSQL"},
                "svc_backup": {"pass": "Backup123!", "notes": "Backup Operators"},
            },
            "admin_accounts": {
                "admin_throne": {"pass": "IronThrone1!", "notes": "Domain Admin"},
                "sa": {"pass": "Dragonfire1!", "notes": "SQL sysadmin"},
            },
            "adcs_templates": [
                {"name": "KingsRoad", "esc": "ESC1", "enrollers": "NightsWatch, Domain Computers"},
                {"name": "WildFire", "esc": "ESC2", "enrollers": "Domain Users"},
                {"name": "FacelessMen-Agent + FacelessMen-Enroll", "esc": "ESC3", "enrollers": "FacelessMen / Domain Users"},
                {"name": "Citadel", "esc": "ESC4", "enrollers": "victarion WriteDACL, tyrion WritePKIEnrollmentFlag"},
                {"name": "WhiteWalker", "esc": "ESC9", "enrollers": "Domain Users"},
                {"name": "WinterIsComing", "esc": "ESC10", "enrollers": "Domain Users"},
                {"name": "NightsWatchOath", "esc": "ESC13", "enrollers": "Domain Users"},
                {"name": "Valyria", "esc": "ESC15", "enrollers": "Domain Users"},
                {"name": "DoomOfValyria", "esc": "ESC16", "enrollers": "Domain Users"},
            ],
            "kerberoastable": ["svc_goldcloaks", "svc_maesters", "svc_wildfire", "svc_kingsguard",
                               "svc_faceless", "svc_nightswatch", "svc_sqlfire", "balon"],
            "asreproastable": ["ned"],
        }
        return json.dumps(lab_info, indent=2)

    @mcp.resource("uwu://tools")
    async def get_available_tools() -> str:
        """List of security tools available in the Exegol container."""
        import shutil
        import subprocess

        tools = [
            "secretsdump.py", "psexec.py", "smbexec.py", "wmiexec.py",
            "dcomexec.py", "atexec.py", "getTGT.py", "getST.py",
            "GetUserSPNs.py", "GetNPUsers.py", "findDelegation.py",
            "addcomputer.py", "rbcd.py", "dacledit.py", "owneredit.py",
            "ticketer.py", "ticketConverter.py", "lookupsid.py",
            "samrdump.py", "rpcdump.py", "smbclient.py", "mssqlclient.py",
            "Get-GPPPassword.py", "getLAPSPassword.py", "dpapi.py",
            "ntlmrelayx.py", "bloodyAD", "NetExec", "nxc",
            "nmap", "ldapsearch", "smbclient", "rpcclient",
            "chisel", "proxychains4",
        ]

        # Extended PATH for tool discovery (same as module_base)
        extended_path = "/opt/tools/Certipy/venv/bin:/root/.local/bin:/root/.local/share/pipx/venvs/netexec/bin:" + os.environ.get("PATH", "")

        certipy_paths = [
            "/opt/tools/Certipy/venv/bin/certipy",
            "/root/.local/share/pipx/venvs/certipy/bin/certipy",
        ]

        available = {}
        for tool in tools:
            path = shutil.which(tool, path=extended_path)
            available[tool] = path or "NOT FOUND"

        available["certipy"] = next((p for p in certipy_paths if os.path.isfile(p)), "NOT FOUND")

        found = sum(1 for v in available.values() if v != "NOT FOUND")
        return json.dumps({
            "total": len(available),
            "found": found,
            "missing": len(available) - found,
            "tools": available,
        }, indent=2)
