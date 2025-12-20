"""
Windows LNK File Parser and Credential Extractor
Parses Windows shortcut (.lnk) files to extract embedded credentials
Often used for PuTTY, RDP, and other tools with saved credentials
"""

from core.module_base import ModuleBase, ModuleType, Platform, find_tool
import os
import re
import struct


class LnkParser(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "lnk_parser"
        self.description = "Parse Windows LNK files and extract credentials from command arguments"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["windows", "lnk", "credentials", "shortcut", "parser"]
        self.references = [
            "https://github.com/lcorneliussen/LnkParser",
            "https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5BMS-SHLLINK%5D.pdf"
        ]

        # Options
        self.register_option("LNKFILE", "Path to LNK file to parse", required=True)
        self.register_option("DIRECTORY", "Directory containing multiple LNK files", default=None)
        self.register_option("EXTRACT_CREDS", "Extract credentials from command arguments", default=True)

    def check(self) -> bool:
        """Check if lnkinfo is available"""
        lnkinfo = find_tool("lnkinfo")
        if not lnkinfo:
            self.print_warning("lnkinfo not found - will use basic parsing")
            self.print_warning("Install with: apt install liblnk-utils")
        return True

    def parse_lnk_basic(self, lnk_path: str) -> dict:
        """Basic LNK parsing without lnkinfo"""
        result = {
            'path': lnk_path,
            'target': None,
            'arguments': None,
            'working_dir': None,
            'credentials': []
        }

        try:
            with open(lnk_path, 'rb') as f:
                data = f.read()

            # Look for common patterns in binary data
            # Extract printable strings
            strings = re.findall(b'[ -~]{4,}', data)

            for s in strings:
                try:
                    text = s.decode('ascii', errors='ignore')

                    # Look for executable paths
                    if '.exe' in text.lower() or '.bat' in text.lower():
                        if not result['target']:
                            result['target'] = text

                    # Look for credentials patterns
                    cred_matches = self.extract_credentials_from_string(text)
                    result['credentials'].extend(cred_matches)

                except:
                    pass

            # Also try UTF-16LE (common in LNK files)
            try:
                text_utf16 = data.decode('utf-16le', errors='ignore')
                cred_matches = self.extract_credentials_from_string(text_utf16)
                result['credentials'].extend(cred_matches)

                # Extract command line arguments
                if '-pw' in text_utf16 or '/password' in text_utf16.lower():
                    result['arguments'] = text_utf16

            except:
                pass

        except Exception as e:
            self.print_error(f"Error parsing {lnk_path}: {str(e)}")

        return result

    def parse_lnk_with_lnkinfo(self, lnk_path: str) -> dict:
        """Parse LNK using lnkinfo tool"""
        result = {
            'path': lnk_path,
            'target': None,
            'arguments': None,
            'working_dir': None,
            'description': None,
            'credentials': []
        }

        lnkinfo = find_tool("lnkinfo")
        if not lnkinfo:
            return self.parse_lnk_basic(lnk_path)

        ret, stdout, stderr = self.run_command([lnkinfo, lnk_path], timeout=10)

        if ret != 0:
            self.print_warning(f"lnkinfo failed, using basic parsing")
            return self.parse_lnk_basic(lnk_path)

        # Parse lnkinfo output
        for line in stdout.split('\n'):
            line = line.strip()

            if 'Local path' in line or 'Command line arguments' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    value = parts[1].strip()

                    if 'Local path' in line:
                        result['target'] = value
                    elif 'Command line arguments' in line:
                        result['arguments'] = value

                        # Extract credentials from arguments
                        creds = self.extract_credentials_from_string(value)
                        result['credentials'].extend(creds)

            elif 'Working directory' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    result['working_dir'] = parts[1].strip()

            elif 'Description' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    result['description'] = parts[1].strip()

        return result

    def extract_credentials_from_string(self, text: str) -> list:
        """Extract potential credentials from command arguments"""
        credentials = []

        # Common password argument patterns
        patterns = [
            # PuTTY: -pw password
            r'-pw\s+([^\s]+)',
            # Generic --password=value
            r'--password[=\s]+([^\s]+)',
            r'-password[=\s]+([^\s]+)',
            # User@host patterns
            r'([a-zA-Z0-9._-]+)@([a-zA-Z0-9.-]+)',
            # user:password patterns
            r'([a-zA-Z0-9._-]+):([^\s@]+)@',
            # Generic -p password
            r'-p\s+([^\s]+)',
            # RDP passwords
            r'/v:([^\s]+)',
            r'/u:([^\s]+)',
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if 'password' in pattern.lower() or '-pw' in pattern.lower() or '-p ' in pattern:
                    credentials.append({
                        'type': 'password',
                        'value': match.group(1) if match.groups() else match.group(0)
                    })
                elif '@' in pattern:
                    if len(match.groups()) == 2:
                        credentials.append({
                            'type': 'username',
                            'value': match.group(1)
                        })
                        credentials.append({
                            'type': 'host',
                            'value': match.group(2)
                        })

        return credentials

    def run(self) -> bool:
        """Execute the LNK parsing"""
        lnk_file = self.get_option("LNKFILE")
        directory = self.get_option("DIRECTORY")
        extract_creds = self.get_option("EXTRACT_CREDS")

        files_to_parse = []

        # Determine which files to parse
        if directory and os.path.isdir(directory):
            self.print_status(f"Scanning directory: {directory}")
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith('.lnk'):
                        files_to_parse.append(os.path.join(root, file))
            self.print_status(f"Found {len(files_to_parse)} LNK files")

        elif lnk_file and os.path.exists(lnk_file):
            if os.path.isdir(lnk_file):
                # Treat as directory
                for root, dirs, files in os.walk(lnk_file):
                    for file in files:
                        if file.endswith('.lnk'):
                            files_to_parse.append(os.path.join(root, file))
            else:
                files_to_parse.append(lnk_file)

        else:
            self.print_error(f"LNK file not found: {lnk_file}")
            return False

        if not files_to_parse:
            self.print_error("No LNK files to parse")
            return False

        # Parse each file
        found_creds = False
        for lnk_path in files_to_parse:
            self.print_line()
            self.print_status(f"Parsing: {lnk_path}")
            self.print_line("=" * 60)

            result = self.parse_lnk_with_lnkinfo(lnk_path)

            if result['target']:
                self.print_good(f"Target: {result['target']}")

            if result['arguments']:
                self.print_good(f"Arguments: {result['arguments']}")

            if result['working_dir']:
                self.print_status(f"Working Dir: {result['working_dir']}")

            if result['description']:
                self.print_status(f"Description: {result['description']}")

            if extract_creds and result['credentials']:
                self.print_line()
                self.print_good("CREDENTIALS FOUND:")
                self.print_line("-" * 60)

                seen = set()
                for cred in result['credentials']:
                    cred_key = f"{cred['type']}:{cred['value']}"
                    if cred_key not in seen:
                        seen.add(cred_key)
                        self.print_good(f"  {cred['type'].upper()}: {cred['value']}")
                        found_creds = True

        self.print_line()

        if found_creds:
            self.print_good("=" * 60)
            self.print_good("Credential extraction complete!")
            self.print_good("=" * 60)
            return True
        else:
            self.print_warning("No credentials found in LNK file(s)")
            return False


# Module instantiation
module = LnkParser()
