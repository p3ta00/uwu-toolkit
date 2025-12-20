"""
Credential Manager for UwU Toolkit
Track pwned users and their credentials
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


class CredentialManager:
    """
    Manage pwned credentials during engagements

    Features:
    - Store usernames with passwords/hashes
    - Track credential source and notes
    - Persist across sessions
    - Export for use with tools
    """

    def __init__(self, config_dir: str = "~/.uwu-toolkit"):
        self.config_dir = Path(os.path.expanduser(config_dir))
        self.creds_file = self.config_dir / "creds.json"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        """Load credentials from file"""
        if self.creds_file.exists():
            try:
                with open(self.creds_file, 'r') as f:
                    self.credentials = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.credentials = {}

    def _save(self) -> None:
        """Save credentials to file"""
        with open(self.creds_file, 'w') as f:
            json.dump(self.credentials, f, indent=2, default=str)

    def add(
        self,
        username: str,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        domain: Optional[str] = None,
        source: Optional[str] = None,
        notes: Optional[str] = None
    ) -> bool:
        """
        Add or update a pwned credential

        Args:
            username: The username
            password: Cleartext password (optional)
            ntlm_hash: NTLM hash (optional)
            domain: Domain for the user (optional)
            source: Where the cred was found (optional)
            notes: Additional notes (optional)

        Returns:
            True if added/updated successfully
        """
        # Create unique key (domain\user or just user)
        key = f"{domain}\\{username}".lower() if domain else username.lower()

        existing = self.credentials.get(key, {})

        self.credentials[key] = {
            "username": username,
            "domain": domain or existing.get("domain"),
            "password": password or existing.get("password"),
            "ntlm_hash": ntlm_hash or existing.get("ntlm_hash"),
            "source": source or existing.get("source"),
            "notes": notes or existing.get("notes"),
            "added": existing.get("added", datetime.now().isoformat()),
            "updated": datetime.now().isoformat(),
            "pwned": True
        }

        self._save()
        return True

    def delete(self, username: str, domain: Optional[str] = None) -> bool:
        """Delete a credential"""
        key = f"{domain}\\{username}".lower() if domain else username.lower()

        # Try with domain prefix first, then without
        if key in self.credentials:
            del self.credentials[key]
            self._save()
            return True

        # Try to find partial match
        for k in list(self.credentials.keys()):
            if username.lower() in k:
                del self.credentials[k]
                self._save()
                return True

        return False

    def get(self, username: str, domain: Optional[str] = None) -> Optional[Dict]:
        """Get a specific credential"""
        key = f"{domain}\\{username}".lower() if domain else username.lower()

        if key in self.credentials:
            return self.credentials[key]

        # Try partial match
        for k, v in self.credentials.items():
            if username.lower() in k:
                return v

        return None

    def get_by_id(self, cred_id: int) -> Optional[Dict]:
        """Get a credential by its ID (1-based index)"""
        creds = self.list_all()
        if 1 <= cred_id <= len(creds):
            return creds[cred_id - 1]
        return None

    def delete_by_id(self, cred_id: int) -> bool:
        """Delete a credential by its ID (1-based index)"""
        creds = self.list_all()
        if 1 <= cred_id <= len(creds):
            key = creds[cred_id - 1].get("key")
            if key and key in self.credentials:
                del self.credentials[key]
                self._save()
                return True
        return False

    def list_all(self) -> List[Dict]:
        """List all credentials"""
        return [
            {"key": k, **v}
            for k, v in sorted(self.credentials.items())
        ]

    def search(self, query: str) -> List[Dict]:
        """Search credentials by username, domain, or notes"""
        query = query.lower()
        results = []

        for key, cred in self.credentials.items():
            if (query in key or
                query in (cred.get("notes") or "").lower() or
                query in (cred.get("source") or "").lower()):
                results.append({"key": key, **cred})

        return results

    def clear_all(self) -> int:
        """Clear all credentials"""
        count = len(self.credentials)
        self.credentials = {}
        self._save()
        return count

    def export_hashcat(self, output_file: Optional[str] = None) -> str:
        """Export hashes in hashcat format"""
        lines = []
        for cred in self.credentials.values():
            if cred.get("ntlm_hash"):
                user = cred["username"]
                domain = cred.get("domain", "")
                hash_val = cred["ntlm_hash"]
                if domain:
                    lines.append(f"{domain}\\{user}:{hash_val}")
                else:
                    lines.append(f"{user}:{hash_val}")

        content = "\n".join(lines)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)

        return content

    def export_secretsdump(self, output_file: Optional[str] = None) -> str:
        """Export in secretsdump format (user:rid:lmhash:nthash:::)"""
        lines = []
        for cred in self.credentials.values():
            if cred.get("ntlm_hash"):
                user = cred["username"]
                hash_val = cred["ntlm_hash"]
                # Format: user:rid:lmhash:nthash:::
                lines.append(f"{user}:1001:aad3b435b51404eeaad3b435b51404ee:{hash_val}:::")

        content = "\n".join(lines)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)

        return content

    def import_secretsdump(self, filepath: str) -> int:
        """Import credentials from secretsdump output"""
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Format: domain\user:rid:lmhash:nthash::: or user:rid:lmhash:nthash:::
                    parts = line.split(':')
                    if len(parts) >= 4:
                        user_part = parts[0]
                        nt_hash = parts[3]

                        # Skip empty/disabled hashes
                        if nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0":
                            continue

                        domain = None
                        username = user_part
                        if '\\' in user_part:
                            domain, username = user_part.split('\\', 1)

                        self.add(
                            username=username,
                            domain=domain,
                            ntlm_hash=nt_hash,
                            source=f"secretsdump:{filepath}"
                        )
                        count += 1
        except Exception:
            pass

        return count


def print_creds_table(creds: List[Dict], show_secrets: bool = False) -> None:
    """Print credentials in a formatted table"""
    from core.colors import Colors

    if not creds:
        print(f"{Colors.NEON_ORANGE}[!] No credentials found{Colors.RESET}")
        return

    print()
    print(f"{Colors.NEON_PINK}Pwned Credentials{Colors.RESET}")
    print(f"{Colors.NEON_PINK}================={Colors.RESET}")
    print()

    # Header
    if show_secrets:
        print(f"{Colors.BRIGHT_WHITE}{'ID':<4} {'User':<22} {'Domain':<18} {'Password':<22} {'Hash':<33}{Colors.RESET}")
        print(f"{'-'*4} {'-'*22} {'-'*18} {'-'*22} {'-'*33}")
    else:
        print(f"{Colors.BRIGHT_WHITE}{'ID':<4} {'User':<22} {'Domain':<18} {'Has Pass':<10} {'Has Hash':<10}{Colors.RESET}")
        print(f"{'-'*4} {'-'*22} {'-'*18} {'-'*10} {'-'*10}")

    for idx, cred in enumerate(creds, 1):
        user = cred.get("username", "?")[:20]
        domain = (cred.get("domain") or "-")[:16]

        if show_secrets:
            password = (cred.get("password") or "-")[:20]
            ntlm = (cred.get("ntlm_hash") or "-")[:31]
            print(f"{Colors.NEON_ORANGE}{idx:<4}{Colors.RESET} {Colors.NEON_CYAN}{user:<22}{Colors.RESET} {domain:<18} {Colors.NEON_GREEN}{password:<22}{Colors.RESET} {ntlm:<33}")
        else:
            has_pass = f"{Colors.NEON_GREEN}Yes{Colors.RESET}" if cred.get("password") else f"{Colors.DARK_PINK}No{Colors.RESET}"
            has_hash = f"{Colors.NEON_GREEN}Yes{Colors.RESET}" if cred.get("ntlm_hash") else f"{Colors.DARK_PINK}No{Colors.RESET}"
            # Pad for ANSI codes
            print(f"{Colors.NEON_ORANGE}{idx:<4}{Colors.RESET} {Colors.NEON_CYAN}{user:<22}{Colors.RESET} {domain:<18} {has_pass:<19} {has_hash:<19}")

    print()
    print(f"{Colors.BRIGHT_WHITE}Total: {len(creds)} credential(s){Colors.RESET}")
    print()
