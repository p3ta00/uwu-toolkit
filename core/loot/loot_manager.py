"""
Loot Manager and Viewer
Manage and display captured loot with ANSI color support
"""

import os
import sys
import re
import shutil
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from pathlib import Path


class LootManager:
    """
    Manage loot files from engagements

    Features:
    - Organize loot by target/date
    - Search through loot
    - Export/archive loot
    - Track loot metadata
    """

    def __init__(self, loot_dir: str = "~/.uwu-toolkit/loot"):
        self.loot_dir = os.path.expanduser(loot_dir)
        os.makedirs(self.loot_dir, exist_ok=True)

    def list_loot(self, pattern: str = "*") -> List[Dict]:
        """List all loot files matching pattern"""
        import glob

        files = []
        search_path = os.path.join(self.loot_dir, f"**/{pattern}")

        for filepath in glob.glob(search_path, recursive=True):
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    'path': filepath,
                    'name': os.path.basename(filepath),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'type': self._detect_type(filepath)
                })

        # Sort by modified time (newest first)
        files.sort(key=lambda x: x['modified'], reverse=True)
        return files

    def _detect_type(self, filepath: str) -> str:
        """Detect loot file type"""
        name = os.path.basename(filepath).lower()

        if 'linpeas' in name:
            return 'linpeas'
        elif 'pspy' in name:
            return 'pspy'
        elif 'bloodhound' in name or name.endswith('.json'):
            return 'bloodhound'
        elif 'hash' in name or 'ntlm' in name:
            return 'hashes'
        elif 'cred' in name or 'pass' in name:
            return 'credentials'
        elif name.endswith('.log'):
            return 'log'
        elif name.endswith('.txt'):
            return 'text'
        else:
            return 'other'

    def search_loot(self, query: str, file_pattern: str = "*") -> List[Tuple[str, int, str]]:
        """Search through loot files for a pattern"""
        results = []

        for loot in self.list_loot(file_pattern):
            try:
                with open(loot['path'], 'r', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # Strip ANSI for search
                        clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                        if query.lower() in clean_line.lower():
                            results.append((loot['path'], line_num, line.strip()))
            except Exception:
                pass

        return results

    def get_loot_path(self, name: str) -> Optional[str]:
        """Get full path to a loot file by name"""
        # First try exact match
        exact_path = os.path.join(self.loot_dir, name)
        if os.path.exists(exact_path):
            return exact_path

        # Try finding by partial name
        for loot in self.list_loot():
            if name in loot['name']:
                return loot['path']

        return None

    def archive_loot(self, target: str, archive_name: Optional[str] = None) -> str:
        """Archive loot for a specific target"""
        import tarfile

        if not archive_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"loot_{target}_{timestamp}.tar.gz"

        archive_path = os.path.join(self.loot_dir, "archives", archive_name)
        os.makedirs(os.path.dirname(archive_path), exist_ok=True)

        with tarfile.open(archive_path, "w:gz") as tar:
            for loot in self.list_loot(f"*{target}*"):
                tar.add(loot['path'], arcname=loot['name'])

        return archive_path

    def delete_loot(self, name: str) -> bool:
        """Delete a loot file"""
        path = self.get_loot_path(name)
        if path and os.path.exists(path):
            os.remove(path)
            return True
        return False


class LootViewer:
    """
    View loot files with ANSI color support

    Features:
    - Display with original ANSI colors
    - Pager support for large files
    - Search within file
    - Line numbers
    - Filtering
    """

    def __init__(self):
        self.term_width = shutil.get_terminal_size().columns
        self.term_height = shutil.get_terminal_size().lines

    def view(self, filepath: str, use_pager: bool = True, line_numbers: bool = False) -> None:
        """View a loot file with colors"""
        if not os.path.exists(filepath):
            print(f"\033[31m[-] File not found: {filepath}\033[0m")
            return

        try:
            with open(filepath, 'r', errors='replace') as f:
                content = f.read()

            # Check if file has ANSI codes
            has_ansi = bool(re.search(r'\x1b\[', content))

            if use_pager and self._should_use_pager(content):
                self._view_with_pager(content, filepath, has_ansi, line_numbers)
            else:
                self._view_direct(content, line_numbers)

        except Exception as e:
            print(f"\033[31m[-] Error reading file: {e}\033[0m")

    def _should_use_pager(self, content: str) -> bool:
        """Determine if pager should be used"""
        lines = content.count('\n')
        return lines > self.term_height - 5

    def _view_direct(self, content: str, line_numbers: bool) -> None:
        """Print content directly to terminal"""
        if line_numbers:
            lines = content.split('\n')
            width = len(str(len(lines)))
            for i, line in enumerate(lines, 1):
                print(f"\033[90m{i:>{width}}\033[0m {line}")
        else:
            print(content)

    def _view_with_pager(self, content: str, filepath: str, has_ansi: bool, line_numbers: bool) -> None:
        """View content with an interactive pager"""
        import subprocess

        # Add line numbers if requested
        if line_numbers:
            lines = content.split('\n')
            width = len(str(len(lines)))
            numbered_lines = []
            for i, line in enumerate(lines, 1):
                numbered_lines.append(f"\033[90m{i:>{width}}\033[0m {line}")
            content = '\n'.join(numbered_lines)

        # Try to use less with color support
        try:
            # less -R preserves ANSI colors
            proc = subprocess.Popen(
                ['less', '-R', '-S', '+G'],  # -S: chop long lines, +G: start at end then go to start
                stdin=subprocess.PIPE,
                env={**os.environ, 'TERM': 'xterm-256color'}
            )
            proc.communicate(input=content.encode('utf-8', errors='replace'))
        except FileNotFoundError:
            # Fall back to more or direct output
            try:
                proc = subprocess.Popen(['more'], stdin=subprocess.PIPE)
                proc.communicate(input=content.encode('utf-8', errors='replace'))
            except FileNotFoundError:
                self._view_direct(content, False)

    def view_summary(self, filepath: str) -> None:
        """View a summary of a loot file"""
        if not os.path.exists(filepath):
            print(f"\033[31m[-] File not found: {filepath}\033[0m")
            return

        try:
            with open(filepath, 'r', errors='replace') as f:
                content = f.read()

            # File info
            stat = os.stat(filepath)
            lines = content.count('\n')
            has_ansi = bool(re.search(r'\x1b\[', content))

            print()
            print(f"\033[1;36m{'='*60}\033[0m")
            print(f"\033[1;36m  Loot File Summary\033[0m")
            print(f"\033[1;36m{'='*60}\033[0m")
            print()
            print(f"  \033[1mFile:\033[0m {os.path.basename(filepath)}")
            print(f"  \033[1mPath:\033[0m {filepath}")
            print(f"  \033[1mSize:\033[0m {self._format_size(stat.st_size)}")
            print(f"  \033[1mLines:\033[0m {lines}")
            print(f"  \033[1mModified:\033[0m {datetime.fromtimestamp(stat.st_mtime)}")
            print(f"  \033[1mColors:\033[0m {'Yes' if has_ansi else 'No'}")
            print()

            # Show first 20 and last 10 lines
            content_lines = content.split('\n')

            print(f"\033[1;33m  First 20 lines:\033[0m")
            print(f"  {'-'*56}")
            for line in content_lines[:20]:
                # Truncate long lines
                if len(line) > self.term_width - 4:
                    line = line[:self.term_width - 7] + "..."
                print(f"  {line}")

            if len(content_lines) > 30:
                print(f"\n  \033[90m... ({len(content_lines) - 30} lines omitted) ...\033[0m\n")

                print(f"\033[1;33m  Last 10 lines:\033[0m")
                print(f"  {'-'*56}")
                for line in content_lines[-10:]:
                    if len(line) > self.term_width - 4:
                        line = line[:self.term_width - 7] + "..."
                    print(f"  {line}")

            print()

        except Exception as e:
            print(f"\033[31m[-] Error: {e}\033[0m")

    def search(self, filepath: str, pattern: str, context: int = 2) -> None:
        """Search within a loot file and display matches with context"""
        if not os.path.exists(filepath):
            print(f"\033[31m[-] File not found: {filepath}\033[0m")
            return

        try:
            with open(filepath, 'r', errors='replace') as f:
                lines = f.readlines()

            matches = []
            for i, line in enumerate(lines):
                # Strip ANSI for search
                clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                if pattern.lower() in clean_line.lower():
                    matches.append(i)

            if not matches:
                print(f"\033[33m[!] No matches found for '{pattern}'\033[0m")
                return

            print(f"\033[32m[+] Found {len(matches)} matches\033[0m")
            print()

            for match_idx in matches[:20]:  # Limit to first 20 matches
                start = max(0, match_idx - context)
                end = min(len(lines), match_idx + context + 1)

                print(f"\033[1;36m--- Line {match_idx + 1} ---\033[0m")
                for i in range(start, end):
                    prefix = ">>>" if i == match_idx else "   "
                    line = lines[i].rstrip()
                    if i == match_idx:
                        # Highlight the match line
                        print(f"\033[1;33m{prefix} {i+1:>5}: {line}\033[0m")
                    else:
                        print(f"\033[90m{prefix} {i+1:>5}:\033[0m {line}")
                print()

            if len(matches) > 20:
                print(f"\033[90m... and {len(matches) - 20} more matches\033[0m")

        except Exception as e:
            print(f"\033[31m[-] Error: {e}\033[0m")

    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def filter_view(self, filepath: str, patterns: List[str], invert: bool = False) -> None:
        """View file filtered by patterns"""
        if not os.path.exists(filepath):
            print(f"\033[31m[-] File not found: {filepath}\033[0m")
            return

        try:
            with open(filepath, 'r', errors='replace') as f:
                lines = f.readlines()

            filtered = []
            for line in lines:
                clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                match = any(p.lower() in clean_line.lower() for p in patterns)

                if (match and not invert) or (not match and invert):
                    filtered.append(line)

            content = ''.join(filtered)

            if self._should_use_pager(content):
                self._view_with_pager(content, filepath, True, False)
            else:
                print(content)

        except Exception as e:
            print(f"\033[31m[-] Error: {e}\033[0m")


def print_loot_table(loot_list: List[Dict]) -> None:
    """Print a formatted table of loot files"""
    if not loot_list:
        print("\033[33m[!] No loot files found\033[0m")
        return

    print()
    print(f"\033[1;36m{'Name':<50} {'Type':<12} {'Size':<10} {'Modified'}\033[0m")
    print(f"{'-'*50} {'-'*12} {'-'*10} {'-'*20}")

    for loot in loot_list:
        name = loot['name']
        if len(name) > 48:
            name = name[:45] + "..."

        size = loot['size']
        if size < 1024:
            size_str = f"{size}B"
        elif size < 1024 * 1024:
            size_str = f"{size/1024:.1f}KB"
        else:
            size_str = f"{size/1024/1024:.1f}MB"

        modified = loot['modified'].strftime("%Y-%m-%d %H:%M")

        # Color by type
        type_colors = {
            'linpeas': '\033[32m',
            'pspy': '\033[33m',
            'bloodhound': '\033[35m',
            'hashes': '\033[31m',
            'credentials': '\033[31m',
        }
        color = type_colors.get(loot['type'], '\033[0m')

        print(f"{color}{name:<50}\033[0m {loot['type']:<12} {size_str:<10} {modified}")

    print()
    print(f"\033[90mTotal: {len(loot_list)} files\033[0m")
    print()
