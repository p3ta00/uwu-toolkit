"""
Target Manager for UwU Toolkit
Track and quickly switch between target machines
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


class TargetManager:
    """
    Manage target machines during engagements

    Features:
    - Store target IPs, hostnames, DC flags, domains, vhosts
    - Stable IDs (monotonic counter, IDs don't shift on deletion)
    - Persist across sessions
    - Quick variable population via 'set target <n>' / 'set dc <n>'
    """

    def __init__(self, config_dir: str = "~/.uwu-toolkit"):
        self.config_dir = Path(os.path.expanduser(config_dir))
        self.targets_file = self.config_dir / "targets.json"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self._data: Dict[str, Any] = {"next_id": 1, "targets": {}}
        self._load()

    def _load(self) -> None:
        """Load targets from file"""
        if self.targets_file.exists():
            try:
                with open(self.targets_file, 'r') as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._data = {"next_id": 1, "targets": {}}

    def _save(self) -> None:
        """Save targets to file"""
        with open(self.targets_file, 'w') as f:
            json.dump(self._data, f, indent=2, default=str)

    def add(
        self,
        ip: str,
        hostname: str = "",
        is_dc: bool = False,
        domain: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Add a target. If IP already exists, update it instead.

        Returns:
            The target dict (with 'id' key)
        """
        # Check if IP already registered
        existing = self.get_by_ip(ip)
        if existing:
            # Update existing target
            tid = str(existing["id"])
            if hostname:
                self._data["targets"][tid]["hostname"] = hostname
            if is_dc:
                self._data["targets"][tid]["is_dc"] = True
            if domain:
                self._data["targets"][tid]["domain"] = domain
            if notes:
                self._data["targets"][tid]["notes"] = notes
            # Merge vhosts if hostname is new
            if hostname and hostname not in self._data["targets"][tid].get("vhosts", []):
                pass  # hostname is the primary, not a vhost
            self._save()
            return self._data["targets"][tid]

        # Auto-detect domain from hostname (2+ dots => everything after first dot)
        if not domain and hostname and hostname.count('.') >= 2:
            domain = hostname.split('.', 1)[1]

        tid = self._data["next_id"]
        target = {
            "id": tid,
            "ip": ip,
            "hostname": hostname,
            "is_dc": is_dc,
            "domain": domain or "",
            "vhosts": [],
            "notes": notes or "",
            "added": datetime.now().isoformat(),
        }
        self._data["targets"][str(tid)] = target
        self._data["next_id"] = tid + 1
        self._save()
        return target

    def delete(self, target_id: int) -> bool:
        """Delete a target by ID"""
        tid = str(target_id)
        if tid in self._data["targets"]:
            del self._data["targets"][tid]
            self._save()
            return True
        return False

    def get(self, target_id: int) -> Optional[Dict[str, Any]]:
        """Get a target by ID"""
        return self._data["targets"].get(str(target_id))

    def get_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get a target by IP address"""
        for t in self._data["targets"].values():
            if t["ip"] == ip:
                return t
        return None

    def list_all(self) -> List[Dict[str, Any]]:
        """List all targets, sorted by ID"""
        return sorted(self._data["targets"].values(), key=lambda t: t["id"])

    def list_dcs(self) -> List[Dict[str, Any]]:
        """List targets marked as DCs"""
        return [t for t in self.list_all() if t.get("is_dc")]

    def add_vhost(self, target_id: int, vhost: str) -> bool:
        """Add a vhost to a target"""
        tid = str(target_id)
        target = self._data["targets"].get(tid)
        if not target:
            return False
        if vhost not in target.get("vhosts", []):
            target.setdefault("vhosts", []).append(vhost)
            self._save()
        return True

    def del_vhost(self, target_id: int, vhost: str) -> bool:
        """Remove a vhost from a target"""
        tid = str(target_id)
        target = self._data["targets"].get(tid)
        if not target:
            return False
        vhosts = target.get("vhosts", [])
        if vhost in vhosts:
            vhosts.remove(vhost)
            self._save()
            return True
        return False

    def set_domain(self, target_id: int, domain: str) -> bool:
        """Set domain for a target"""
        tid = str(target_id)
        target = self._data["targets"].get(tid)
        if not target:
            return False
        target["domain"] = domain
        self._save()
        return True

    def set_notes(self, target_id: int, notes: str) -> bool:
        """Set notes for a target"""
        tid = str(target_id)
        target = self._data["targets"].get(tid)
        if not target:
            return False
        target["notes"] = notes
        self._save()
        return True

    def clear_all(self) -> int:
        """Clear all targets, return count deleted"""
        count = len(self._data["targets"])
        self._data = {"next_id": 1, "targets": {}}
        self._save()
        return count

    def get_target_ids(self) -> List[int]:
        """Get all target IDs (for tab completion)"""
        return sorted(int(k) for k in self._data["targets"].keys())

    def get_dc_ids(self) -> List[int]:
        """Get IDs of DC targets (for tab completion)"""
        return [t["id"] for t in self.list_dcs()]


def print_targets_table(targets: List[Dict[str, Any]]) -> None:
    """Print targets in a formatted table"""
    from core.colors import Colors

    if not targets:
        print(f"{Colors.NEON_ORANGE}[!] No targets registered{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}    Use: set target <ip> <hostname> [dc]{Colors.RESET}")
        return

    print()
    print(f"{Colors.NEON_PINK}Targets{Colors.RESET}")
    print(f"{Colors.NEON_PINK}======={Colors.RESET}")
    print()

    # Header
    print(f"{Colors.BRIGHT_WHITE}{'ID':<4} {'IP':<17} {'Hostname':<26} {'DC':<4} {'Domain':<22} {'VHosts':<20} {'Notes'}{Colors.RESET}")
    print(f"{'-'*4} {'-'*17} {'-'*26} {'-'*4} {'-'*22} {'-'*20} {'-'*20}")

    for t in targets:
        tid = t.get("id", "?")
        ip = t.get("ip", "?")[:15]
        hostname = (t.get("hostname") or "-")[:24]
        is_dc = f"{Colors.NEON_GREEN}DC{Colors.RESET}" if t.get("is_dc") else "  "
        domain = (t.get("domain") or "-")[:20]
        vhosts = ", ".join(t.get("vhosts", []))[:18] or "-"
        notes = (t.get("notes") or "-")[:20]

        print(f"{Colors.NEON_ORANGE}{tid:<4}{Colors.RESET} {Colors.NEON_CYAN}{ip:<17}{Colors.RESET} {hostname:<26} {is_dc:<13} {domain:<22} {vhosts:<20} {notes}")

    print()
    print(f"{Colors.BRIGHT_WHITE}Total: {len(targets)} target(s){Colors.RESET}")

    # Show DC count
    dc_count = sum(1 for t in targets if t.get("is_dc"))
    if dc_count:
        print(f"{Colors.BRIGHT_WHITE}DCs: {dc_count}{Colors.RESET}")
    print()
