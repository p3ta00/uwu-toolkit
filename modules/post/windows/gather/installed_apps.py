from core.module_base import ModuleBase, ModuleType, Platform
import subprocess
import re


class InstalledApps(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "installed_apps"
        self.description = "Enumerate installed applications with versions for vulnerability matching"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.POST
        self.platform = Platform.WINDOWS
        self.tags = ["post", "windows", "gather", "enumeration", "applications", "privesc"]

        self.register_option("SESSION", "Session ID or command execution method", required=True)
        self.register_option("OUTPUT_FILE", "File to save results", required=False, default="")
        self.register_option("SEARCH", "Search for specific application name", required=False, default="")
        self.register_option("VULN_CHECK", "Check against known vulnerable versions", required=False, default="true")

    def run(self) -> bool:
        session = self.get_option("SESSION")
        output_file = self.get_option("OUTPUT_FILE")
        search_term = self.get_option("SEARCH")
        vuln_check = self.get_option("VULN_CHECK").lower() == "true"

        self.print_status("Enumerating installed applications...")

        # Known vulnerable applications and versions for privilege escalation
        known_vulns = {
            "PDF24": {
                "vulnerable_versions": ["11.15.1", "11.15.0", "11.14", "11.13"],
                "cve": "CVE-2023-49147",
                "description": "PDF24 Creator - Local Privilege Escalation via MSI installer",
                "reference": "https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator/"
            },
            "mRemoteNG": {
                "vulnerable_versions": ["*"],
                "cve": "N/A",
                "description": "mRemoteNG stores encrypted passwords in confCons.xml that can be decrypted",
                "reference": "https://github.com/haseebT/mRemoteNG-Decrypt"
            },
            "FileZilla": {
                "vulnerable_versions": ["*"],
                "cve": "N/A",
                "description": "FileZilla stores credentials in plaintext XML files",
                "reference": "FileZilla stores creds in %APPDATA%\\FileZilla\\sitemanager.xml"
            },
            "WinSCP": {
                "vulnerable_versions": ["*"],
                "cve": "N/A",
                "description": "WinSCP stores encrypted credentials in registry",
                "reference": "HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions"
            },
            "PuTTY": {
                "vulnerable_versions": ["*"],
                "cve": "N/A",
                "description": "PuTTY stores session data in registry",
                "reference": "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions"
            },
            "TeamViewer": {
                "vulnerable_versions": ["*"],
                "cve": "CVE-2019-18988",
                "description": "TeamViewer stores credentials that can be decrypted",
                "reference": "Registry: HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer"
            },
            "VNC": {
                "vulnerable_versions": ["*"],
                "cve": "N/A",
                "description": "VNC servers often store weakly encrypted passwords",
                "reference": "Various registry locations depending on VNC variant"
            },
            "Keepass": {
                "vulnerable_versions": ["2.53", "2.53.1"],
                "cve": "CVE-2023-32784",
                "description": "KeePass master password extraction from memory",
                "reference": "https://github.com/vdohney/keepass-password-dumper"
            },
            "7-Zip": {
                "vulnerable_versions": ["21.07", "21.06", "21.05", "21.04", "21.03", "21.02", "21.01", "21.00"],
                "cve": "CVE-2022-29072",
                "description": "7-Zip Help File Heap Overflow - Local Privilege Escalation",
                "reference": "https://github.com/kagancapar/CVE-2022-29072"
            },
            "Foxit Reader": {
                "vulnerable_versions": ["*"],
                "cve": "Multiple",
                "description": "Foxit Reader has multiple RCE vulnerabilities",
                "reference": "Check specific version against CVE database"
            }
        }

        # PowerShell commands to enumerate installed applications
        ps_commands = [
            # Get applications from registry (32-bit)
            'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -ne $null }',
            # Get applications from registry (64-bit)
            'Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -ne $null }',
            # Get applications from user registry
            'Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -ne $null }'
        ]

        # Alternative WMI command (slower but more comprehensive)
        wmi_command = 'Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Format-Table -AutoSize'

        all_apps = []
        
        self.print_status("Querying registry for installed applications...")
        
        # Execute PowerShell commands
        for i, ps_cmd in enumerate(ps_commands):
            self.print_status(f"Running query {i+1}/3...")
            
            # Build the full command
            full_cmd = f'powershell -Command "{ps_cmd} | Format-Table -AutoSize"'
            
            try:
                result = self._execute_command(session, full_cmd)
                if result:
                    apps = self._parse_powershell_output(result)
                    all_apps.extend(apps)
            except Exception as e:
                self.print_error(f"Error executing query {i+1}: {str(e)}")

        # Remove duplicates based on app name
        seen = set()
        unique_apps = []
        for app in all_apps:
            if app['name'] and app['name'] not in seen:
                seen.add(app['name'])
                unique_apps.append(app)

        # Sort alphabetically
        unique_apps.sort(key=lambda x: x['name'].lower() if x['name'] else '')

        # Filter by search term if provided
        if search_term:
            unique_apps = [app for app in unique_apps if search_term.lower() in app['name'].lower()]

        # Display results
        self.print_good(f"Found {len(unique_apps)} installed applications")
        self.print_status("-" * 80)
        
        vulnerable_found = []
        
        for app in unique_apps:
            app_name = app['name']
            app_version = app['version'] or 'Unknown'
            app_publisher = app['publisher'] or 'Unknown'
            
            # Check for vulnerabilities
            vuln_info = None
            if vuln_check:
                for vuln_app, vuln_data in known_vulns.items():
                    if vuln_app.lower() in app_name.lower():
                        if vuln_data['vulnerable_versions'] == ['*'] or app_version in vuln_data['vulnerable_versions']:
                            vuln_info = vuln_data
                            vulnerable_found.append({
                                'app': app_name,
                                'version': app_version,
                                'vuln': vuln_data
                            })
                            break

            if vuln_info:
                self.print_warning(f"[VULN] {app_name} v{app_version}")
                self.print_warning(f"       CVE: {vuln_info['cve']}")
                self.print_warning(f"       {vuln_info['description']}")
            else:
                self.print_status(f"{app_name} v{app_version} ({app_publisher})")

        self.print_status("-" * 80)

        # Summary of vulnerabilities
        if vulnerable_found:
            self.print_good(f"\n[!] Found {len(vulnerable_found)} potentially vulnerable applications:")
            for v in vulnerable_found:
                self.print_warning(f"    - {v['app']} v{v['version']}")
                self.print_warning(f"      CVE: {v['vuln']['cve']}")
                self.print_warning(f"      Info: {v['vuln']['description']}")
                self.print_warning(f"      Ref: {v['vuln']['reference']}")
                self.print_status("")

        # Save to file if requested
        if output_file:
            self._save_results(output_file, unique_apps, vulnerable_found)
            self.print_good(f"Results saved to {output_file}")

        # Store results for other modules
        self.results = {
            'applications': unique_apps,
            'vulnerable': vulnerable_found,
            'total_count': len(unique_apps),
            'vulnerable_count': len(vulnerable_found)
        }

        return True

    def _execute_command(self, session, command):
        """Execute command via session/shell"""
        # This can be adapted based on how uwu-toolkit handles sessions
        # For now, assume we're executing locally or via a shell
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.print_error("Command timed out")
            return None
        except Exception as e:
            self.print_error(f"Execution error: {str(e)}")
            return None

    def _parse_powershell_output(self, output):
        """Parse PowerShell table output into structured data"""
        apps = []
        lines = output.strip().split('\n')
        
        # Skip header lines
        data_started = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if '----' in line:
                data_started = True
                continue
            if not data_started:
                continue
            
            # Parse the line - format is typically: DisplayName DisplayVersion Publisher InstallDate
            # This is a simplified parser; real implementation may need adjustment
            parts = re.split(r'\s{2,}', line)
            if len(parts) >= 1:
                app = {
                    'name': parts[0] if len(parts) > 0 else '',
                    'version': parts[1] if len(parts) > 1 else '',
                    'publisher': parts[2] if len(parts) > 2 else '',
                    'install_date': parts[3] if len(parts) > 3 else ''
                }
                if app['name']:
                    apps.append(app)
        
        return apps

    def _save_results(self, filepath, apps, vulnerables):
        """Save results to file"""
        try:
            with open(filepath, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("INSTALLED APPLICATIONS ENUMERATION\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Total Applications: {len(apps)}\n")
                f.write(f"Potentially Vulnerable: {len(vulnerables)}\n\n")
                
                if vulnerables:
                    f.write("-" * 40 + "\n")
                    f.write("VULNERABLE APPLICATIONS\n")
                    f.write("-" * 40 + "\n")
                    for v in vulnerables:
                        f.write(f"\n[!] {v['app']} v{v['version']}\n")
                        f.write(f"    CVE: {v['vuln']['cve']}\n")
                        f.write(f"    Description: {v['vuln']['description']}\n")
                        f.write(f"    Reference: {v['vuln']['reference']}\n")
                
                f.write("\n" + "-" * 40 + "\n")
                f.write("ALL APPLICATIONS\n")
                f.write("-" * 40 + "\n\n")
                
                for app in apps:
                    f.write(f"{app['name']}\n")
                    f.write(f"  Version: {app['version']}\n")
                    f.write(f"  Publisher: {app['publisher']}\n")
                    f.write(f"  Install Date: {app['install_date']}\n\n")
                    
        except Exception as e:
            self.print_error(f"Failed to save results: {str(e)}")
