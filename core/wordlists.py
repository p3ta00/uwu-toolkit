"""
Wordlist Resolver - Cross-platform wordlist path detection
Works on Kali, Parrot, Exegol, BlackArch, and custom installations
"""

import os
from typing import Optional, Dict, List


class WordlistResolver:
    """
    Resolves wordlist names to actual file paths.
    Checks multiple common locations for compatibility across different pentesting distros.
    """

    # Common wordlist base directories (in order of preference)
    WORDLIST_BASES = [
        "/opt/lists/seclists",           # Exegol
        "/usr/share/seclists",           # Kali/Parrot default
        "/usr/share/wordlists/seclists", # Some distros
        "/opt/seclists",                 # Custom install
        "~/.local/share/seclists",       # User install
        "/opt/lists",                    # Exegol additional
        "/usr/share/wordlists",          # General wordlists
    ]

    # Wordlist mappings: name -> relative paths to try
    WORDLISTS = {
        # Web Content
        "dir_small": [
            "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
            "Discovery/Web-Content/directory-list-2.3-small.txt",
            "dirbuster/directory-list-2.3-small.txt",
        ],
        "dir_medium": [
            "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
            "Discovery/Web-Content/directory-list-2.3-medium.txt",
            "dirbuster/directory-list-2.3-medium.txt",
        ],
        "dir_big": [
            "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
            "Discovery/Web-Content/directory-list-2.3-big.txt",
            "dirbuster/directory-list-2.3-big.txt",
        ],
        "common": [
            "Discovery/Web-Content/common.txt",
            "dirb/common.txt",
        ],
        "raft_dirs": [
            "Discovery/Web-Content/raft-large-directories.txt",
        ],
        "raft_files": [
            "Discovery/Web-Content/raft-large-files.txt",
        ],
        "raft_dirs_small": [
            "Discovery/Web-Content/raft-small-directories.txt",
        ],
        "quickhits": [
            "Discovery/Web-Content/quickhits.txt",
        ],
        "big": [
            "Discovery/Web-Content/big.txt",
            "dirb/big.txt",
        ],

        # DNS/Subdomains
        "subdomains_small": [
            "Discovery/DNS/subdomains-top1million-5000.txt",
            "Discovery/DNS/fierce-hostlist.txt",
        ],
        "subdomains": [
            "Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "subdomains_medium": [
            "Discovery/DNS/subdomains-top1million-20000.txt",
        ],
        "subdomains_large": [
            "Discovery/DNS/subdomains-top1million-110000.txt",
        ],
        "vhosts": [
            "Discovery/DNS/namelist.txt",
            "Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "dns_fierce": [
            "Discovery/DNS/fierce-hostlist.txt",
        ],
        "bitquark": [
            "Discovery/DNS/bitquark-subdomains-top100000.txt",
        ],

        # Passwords
        "rockyou": [
            "rockyou.txt",
            "Passwords/Leaked-Databases/rockyou.txt",
        ],
        "passwords_common": [
            "Passwords/Common-Credentials/10k-most-common.txt",
            "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
        ],
        "passwords_default": [
            "Passwords/Default-Credentials/default-passwords.txt",
        ],

        # Usernames
        "usernames": [
            "Usernames/Names/names.txt",
            "Usernames/top-usernames-shortlist.txt",
        ],
        "usernames_top": [
            "Usernames/top-usernames-shortlist.txt",
        ],

        # Fuzzing
        "burp_params": [
            "Discovery/Web-Content/burp-parameter-names.txt",
        ],
        "api_endpoints": [
            "Discovery/Web-Content/api/api-endpoints.txt",
        ],
    }

    # Additional standalone wordlists (full paths)
    STANDALONE = {
        "rockyou": [
            "/usr/share/wordlists/rockyou.txt",
            "/opt/lists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",  # Kali compressed
        ],
        "onelistmicro": [
            "/opt/lists/onelistforallmicro.txt",
        ],
        "onelistshort": [
            "/opt/lists/onelistforallshort.txt",
        ],
    }

    @classmethod
    def resolve(cls, name: str) -> Optional[str]:
        """
        Resolve a wordlist name to an actual file path.

        Args:
            name: Wordlist name (e.g., 'dir_medium') or direct path

        Returns:
            Full path to wordlist file, or None if not found
        """
        # If it's already a valid path, return it
        expanded = os.path.expanduser(name)
        if os.path.isfile(expanded):
            return expanded

        # Check standalone wordlists first
        if name in cls.STANDALONE:
            for path in cls.STANDALONE[name]:
                expanded = os.path.expanduser(path)
                if os.path.isfile(expanded):
                    return expanded
                # Handle .gz files (common for rockyou on Kali)
                if expanded.endswith('.gz') and os.path.isfile(expanded):
                    return expanded

        # Look up in WORDLISTS mapping
        if name not in cls.WORDLISTS:
            # Try as a relative path in common bases
            for base in cls.WORDLIST_BASES:
                base = os.path.expanduser(base)
                full_path = os.path.join(base, name)
                if os.path.isfile(full_path):
                    return full_path
            return None

        # Try each relative path in each base directory
        for rel_path in cls.WORDLISTS[name]:
            for base in cls.WORDLIST_BASES:
                base = os.path.expanduser(base)
                full_path = os.path.join(base, rel_path)
                if os.path.isfile(full_path):
                    return full_path

        return None

    @classmethod
    def resolve_with_fallback(cls, name: str, fallback: str = None) -> Optional[str]:
        """
        Resolve wordlist with fallback to another wordlist or path.

        Args:
            name: Primary wordlist name
            fallback: Fallback wordlist name or path

        Returns:
            Path to wordlist or None
        """
        result = cls.resolve(name)
        if result:
            return result

        if fallback:
            return cls.resolve(fallback)

        return None

    @classmethod
    def list_available(cls) -> Dict[str, Optional[str]]:
        """
        List all known wordlists and their resolved paths.

        Returns:
            Dict mapping wordlist names to paths (None if not found)
        """
        available = {}
        for name in cls.WORDLISTS:
            available[name] = cls.resolve(name)
        for name in cls.STANDALONE:
            if name not in available:
                available[name] = cls.resolve(name)
        return available

    @classmethod
    def find_seclists_base(cls) -> Optional[str]:
        """Find the SecLists base directory."""
        for base in cls.WORDLIST_BASES:
            base = os.path.expanduser(base)
            # Check if it looks like a seclists directory
            if os.path.isdir(base) and os.path.isdir(os.path.join(base, "Discovery")):
                return base
        return None

    @classmethod
    def get_category_wordlists(cls, category: str) -> List[str]:
        """
        Get all wordlist names in a category.

        Args:
            category: Category prefix (e.g., 'dir', 'subdomains', 'passwords')

        Returns:
            List of wordlist names matching the category
        """
        return [name for name in cls.WORDLISTS if name.startswith(category)]


def resolve_wordlist(name: str, fallback: str = None) -> Optional[str]:
    """Convenience function for resolving wordlists."""
    return WordlistResolver.resolve_with_fallback(name, fallback)
