"""
Custom Linux Reconnaissance Module
Comprehensive Linux enumeration without external tools
"""

import os
import subprocess
from datetime import datetime
from typing import Optional, List, Tuple, Dict
from core.module_base import ModuleBase, ModuleType, Platform


class LinuxRecon(ModuleBase):
    """
    Custom Linux reconnaissance and enumeration

    Features:
    - No external dependencies (pure shell commands)
    - Categorized enumeration sections
    - Finds common privilege escalation vectors
    - Saves detailed report to loot
    """

    # Enumeration scripts for each category
    ENUM_SCRIPTS = {
        'system_info': '''
echo "=== SYSTEM INFORMATION ==="
echo "[*] Hostname: $(hostname)"
echo "[*] Kernel: $(uname -a)"
echo "[*] OS Release:"
cat /etc/*release 2>/dev/null | head -5
echo "[*] Architecture: $(uname -m)"
echo "[*] CPU Info:"
lscpu 2>/dev/null | head -10 || cat /proc/cpuinfo | head -20
echo "[*] Memory:"
free -h 2>/dev/null || cat /proc/meminfo | head -5
echo "[*] Disk Space:"
df -h 2>/dev/null | head -10
''',

        'user_info': '''
echo "=== USER INFORMATION ==="
echo "[*] Current User: $(whoami)"
echo "[*] User ID: $(id)"
echo "[*] Groups: $(groups)"
echo "[*] Logged in users:"
w 2>/dev/null || who 2>/dev/null
echo "[*] Last logins:"
last -10 2>/dev/null
echo "[*] All users (UID >= 1000):"
awk -F: '$3 >= 1000 {print $1":"$3":"$6":"$7}' /etc/passwd 2>/dev/null
echo "[*] Users with shell:"
grep -E '/bin/(ba)?sh$' /etc/passwd 2>/dev/null
echo "[*] Sudoers:"
cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"
cat /etc/sudoers.d/* 2>/dev/null | grep -v "^#" | grep -v "^$"
''',

        'network_info': '''
echo "=== NETWORK INFORMATION ==="
echo "[*] IP Addresses:"
ip addr 2>/dev/null || ifconfig 2>/dev/null
echo "[*] Routing Table:"
ip route 2>/dev/null || route -n 2>/dev/null
echo "[*] DNS Servers:"
cat /etc/resolv.conf 2>/dev/null
echo "[*] Listening Ports:"
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo "[*] Established Connections:"
ss -tnp 2>/dev/null | head -20 || netstat -tnp 2>/dev/null | head -20
echo "[*] ARP Cache:"
ip neigh 2>/dev/null || arp -a 2>/dev/null
echo "[*] /etc/hosts:"
cat /etc/hosts 2>/dev/null
''',

        'suid_sgid': '''
echo "=== SUID/SGID BINARIES ==="
echo "[*] SUID binaries:"
find / -perm -4000 -type f 2>/dev/null
echo "[*] SGID binaries:"
find / -perm -2000 -type f 2>/dev/null
echo "[*] Checking for common exploitable SUID:"
for bin in nmap vim vi nano less more awk find bash sh cp mv perl python python3 ruby lua php node; do
    path=$(find / -perm -4000 -name "$bin" 2>/dev/null)
    [ -n "$path" ] && echo "[!] EXPLOITABLE SUID: $path"
done
''',

        'capabilities': '''
echo "=== FILE CAPABILITIES ==="
getcap -r / 2>/dev/null
echo "[*] Checking for dangerous capabilities..."
getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin|cap_sys_ptrace'
''',

        'sudo_privs': '''
echo "=== SUDO PRIVILEGES ==="
echo "[*] Sudo version:"
sudo -V 2>/dev/null | head -1
echo "[*] Sudo -l output:"
sudo -l 2>/dev/null
echo "[*] Can sudo without password?"
sudo -n true 2>/dev/null && echo "[!] YES - Can run sudo without password!"
''',

        'cron_jobs': '''
echo "=== CRON JOBS ==="
echo "[*] /etc/crontab:"
cat /etc/crontab 2>/dev/null
echo "[*] /etc/cron.d/:"
ls -la /etc/cron.d/ 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
echo "[*] Cron directories:"
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null
echo "[*] User crontabs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u $user 2>/dev/null | grep -v "^#" && echo "  ^ Above: $user"
done
echo "[*] Systemd timers:"
systemctl list-timers --all 2>/dev/null | head -20
''',

        'writable_files': '''
echo "=== WRITABLE FILES/DIRECTORIES ==="
echo "[*] Writable /etc files:"
find /etc -writable -type f 2>/dev/null
echo "[*] Writable in PATH:"
for dir in $(echo $PATH | tr ':' ' '); do
    [ -w "$dir" ] && echo "[!] Writable PATH dir: $dir"
done
echo "[*] World-writable directories:"
find / -type d -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -30
echo "[*] World-writable files:"
find / -type f -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -30
''',

        'sensitive_files': '''
echo "=== SENSITIVE FILES ==="
echo "[*] /etc/passwd readable:"
[ -r /etc/passwd ] && head -5 /etc/passwd
echo "[*] /etc/shadow readable:"
[ -r /etc/shadow ] && echo "[!] SHADOW IS READABLE!" && head -3 /etc/shadow
echo "[*] Password hashes in passwd:"
grep -v ':x:' /etc/passwd 2>/dev/null
echo "[*] SSH keys:"
find /home /root -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
echo "[*] Writable authorized_keys:"
find /home /root -name "authorized_keys" -writable 2>/dev/null
echo "[*] History files:"
find /home /root -name ".*_history" -readable 2>/dev/null
echo "[*] Config files with passwords:"
grep -r -l -i "password" /etc/*.conf /etc/*/*.conf 2>/dev/null | head -10
grep -r -i "pass.*=" /var/www/ 2>/dev/null | head -10
''',

        'processes': '''
echo "=== RUNNING PROCESSES ==="
echo "[*] Processes running as root:"
ps aux | grep "^root" | head -30
echo "[*] All processes:"
ps aux | head -40
echo "[*] Process tree:"
pstree 2>/dev/null | head -30 || ps auxf 2>/dev/null | head -30
''',

        'services': '''
echo "=== SERVICES ==="
echo "[*] Running services:"
systemctl list-units --type=service --state=running 2>/dev/null | head -30
echo "[*] All services:"
systemctl list-unit-files --type=service 2>/dev/null | head -40 || service --status-all 2>/dev/null
echo "[*] Init.d scripts:"
ls -la /etc/init.d/ 2>/dev/null
''',

        'containers': '''
echo "=== CONTAINERS ==="
echo "[*] Docker installed:"
which docker 2>/dev/null && docker --version 2>/dev/null
echo "[*] Docker socket:"
ls -la /var/run/docker.sock 2>/dev/null
echo "[*] User in docker group:"
id | grep -q docker && echo "[!] User is in docker group!"
echo "[*] Docker images:"
docker images 2>/dev/null
echo "[*] Docker containers:"
docker ps -a 2>/dev/null
echo "[*] LXC/LXD:"
which lxc lxd 2>/dev/null
id | grep -qE "lxd|lxc" && echo "[!] User is in lxd/lxc group!"
''',

        'interesting_files': '''
echo "=== INTERESTING FILES ==="
echo "[*] Backup files:"
find / -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null | head -20
echo "[*] Database files:"
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -20
echo "[*] Log files with passwords:"
grep -r -i "password" /var/log/*.log 2>/dev/null | head -10
echo "[*] Wordpress config:"
find / -name "wp-config.php" 2>/dev/null
echo "[*] PHP files with credentials:"
find /var/www -name "*.php" -exec grep -l -i "password\|passwd\|pwd" {} \; 2>/dev/null | head -10
echo "[*] .git directories:"
find / -name ".git" -type d 2>/dev/null | head -10
'''
    }

    def __init__(self):
        super().__init__()
        self.name = "linux_recon"
        self.description = "Comprehensive Linux enumeration using native shell commands"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.POST
        self.platform = Platform.LINUX
        self.tags = ["privesc", "linux", "enumeration", "recon", "post-exploitation"]
        self.references = [
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/",
            "https://gtfobins.github.io/",
        ]

        # Register options
        self.register_option("RHOST", "Target host IP", required=True)
        self.register_option("RPORT", "SSH port", default="22")
        self.register_option("USERNAME", "SSH username", required=True)
        self.register_option("PASSWORD", "SSH password", default="")
        self.register_option("SSH_KEY", "Path to SSH private key", default="")
        self.register_option("SECTIONS", "Sections to run (comma-separated or 'all')", default="all")
        self.register_option("LOOT_DIR", "Directory to save loot", default="~/.uwu-toolkit/loot")
        self.register_option("EXEGOL_CONTAINER", "Exegol container name", default="")
        self.register_option("TIMEOUT", "Command timeout in seconds", default="300")

        # Results storage
        self._results: Dict[str, str] = {}
        self._findings: List[Tuple[str, str]] = []

    def _get_loot_dir(self) -> str:
        """Get and create loot directory"""
        loot_dir = os.path.expanduser(self.get_option("LOOT_DIR"))
        os.makedirs(loot_dir, exist_ok=True)
        return loot_dir

    def _build_ssh_cmd(self, script: str) -> List[str]:
        """Build SSH command"""
        host = self.get_option("RHOST")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        base_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-p", str(port),
        ]

        if ssh_key:
            return ["ssh", "-i", ssh_key] + base_opts + [f"{user}@{host}", f"bash -c '{script}'"]
        elif password:
            return ["sshpass", "-p", password, "ssh"] + base_opts + [f"{user}@{host}", f"bash -c '{script}'"]
        else:
            return ["ssh"] + base_opts + [f"{user}@{host}", f"bash -c '{script}'"]

    def _run_via_exegol(self, cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Run command via Exegol if configured"""
        container = self.get_option("EXEGOL_CONTAINER")
        if container:
            full_cmd = ["docker", "exec", container] + cmd
        else:
            full_cmd = cmd

        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _run_section(self, section: str) -> str:
        """Run a single enumeration section"""
        if section not in self.ENUM_SCRIPTS:
            return f"Unknown section: {section}"

        script = self.ENUM_SCRIPTS[section]
        timeout = int(self.get_option("TIMEOUT"))

        ssh_cmd = self._build_ssh_cmd(script)
        ret, out, err = self._run_via_exegol(ssh_cmd, timeout)

        if ret != 0 and not out:
            return f"Error running {section}: {err}"

        return out

    def _analyze_results(self) -> None:
        """Analyze results for interesting findings"""
        self._findings = []

        for section, output in self._results.items():
            lines = output.split('\n')

            for line in lines:
                # Check for critical indicators
                if '[!]' in line or 'EXPLOITABLE' in line:
                    self._findings.append(('CRITICAL', line.strip()))
                elif 'READABLE' in line.upper() and 'shadow' in line.lower():
                    self._findings.append(('CRITICAL', line.strip()))
                elif 'NOPASSWD' in line:
                    self._findings.append(('HIGH', line.strip()))
                elif 'writable' in line.lower() and any(x in line.lower() for x in ['/etc/', 'cron', 'passwd']):
                    self._findings.append(('HIGH', line.strip()))
                elif 'docker' in line.lower() and 'group' in line.lower():
                    self._findings.append(('CRITICAL', line.strip()))

    def _save_report(self) -> str:
        """Save comprehensive report to loot"""
        loot_dir = self._get_loot_dir()
        host = self.get_option("RHOST")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_path = os.path.join(loot_dir, f"linux_recon_{host}_{timestamp}.txt")

        with open(report_path, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("  Linux Reconnaissance Report\n")
            f.write(f"  Target: {host}\n")
            f.write(f"  Date: {datetime.now().isoformat()}\n")
            f.write("=" * 70 + "\n\n")

            # Executive summary
            if self._findings:
                f.write("EXECUTIVE SUMMARY - FINDINGS\n")
                f.write("-" * 70 + "\n\n")

                critical = [f for f in self._findings if f[0] == 'CRITICAL']
                high = [f for f in self._findings if f[0] == 'HIGH']

                if critical:
                    f.write("CRITICAL FINDINGS:\n")
                    for _, finding in critical:
                        f.write(f"  [!] {finding}\n")
                    f.write("\n")

                if high:
                    f.write("HIGH SEVERITY FINDINGS:\n")
                    for _, finding in high:
                        f.write(f"  [+] {finding}\n")
                    f.write("\n")

                f.write("-" * 70 + "\n\n")

            # Full results
            for section, output in self._results.items():
                f.write("\n" + "=" * 70 + "\n")
                f.write(f"  {section.upper().replace('_', ' ')}\n")
                f.write("=" * 70 + "\n\n")
                f.write(output)
                f.write("\n")

        return report_path

    def run(self) -> bool:
        """Main execution"""
        sections_opt = self.get_option("SECTIONS")

        if sections_opt.lower() == "all":
            sections = list(self.ENUM_SCRIPTS.keys())
        else:
            sections = [s.strip() for s in sections_opt.split(",")]

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Linux Reconnaissance")
        self.print_good("=" * 60)
        self.print_line()

        self.print_status(f"Target: {self.get_option('RHOST')}")
        self.print_status(f"Sections: {len(sections)}")
        self.print_line()

        # Run each section
        for i, section in enumerate(sections, 1):
            self.print_status(f"[{i}/{len(sections)}] Running {section}...")

            output = self._run_section(section)
            self._results[section] = output

            # Quick analysis for critical findings
            if '[!]' in output or 'EXPLOITABLE' in output:
                self.print_warning(f"  Potential findings in {section}!")

        # Analyze all results
        self._analyze_results()

        # Save report
        report_path = self._save_report()
        self.print_line()
        self.print_good(f"Report saved: {report_path}")

        # Print summary
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Summary")
        self.print_good("=" * 60)

        critical = [f for f in self._findings if f[0] == 'CRITICAL']
        high = [f for f in self._findings if f[0] == 'HIGH']

        self.print_status(f"Critical findings: {len(critical)}")
        self.print_status(f"High severity findings: {len(high)}")

        if critical:
            self.print_line()
            self.print_warning("CRITICAL - Likely Privilege Escalation Vectors:")
            for _, finding in critical[:10]:
                self.print_warning(f"  {finding[:70]}")

        if high:
            self.print_line()
            self.print_status("HIGH - Notable Findings:")
            for _, finding in high[:10]:
                self.print_line(f"  {finding[:70]}")

        return True

    def check(self) -> bool:
        """Check SSH connectivity"""
        ssh_cmd = self._build_ssh_cmd("echo test")
        ret, out, err = self._run_via_exegol(ssh_cmd, timeout=15)

        if ret == 0 and 'test' in out:
            self.print_good("SSH connection successful")
            return True

        self.print_error(f"SSH connection failed: {err}")
        return False
