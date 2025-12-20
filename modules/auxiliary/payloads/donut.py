"""
Donut Shellcode Generator Module
Generates position-independent shellcode from PE/DLL/.NET assemblies
"""

import os
import base64
import subprocess
from typing import Optional
from core.module_base import ModuleBase, ModuleType, Platform


class Donut(ModuleBase):
    """
    Donut shellcode generator with automatic base64 encoding.
    Converts executables to shellcode for in-memory execution.
    """

    def __init__(self):
        super().__init__()
        self.name = "donut"
        self.description = "Generate Donut shellcode from PE/DLL/.NET with base64 encoding"
        self.author = "UwU Toolkit"
        self.version = "1.0.0"
        self.module_type = ModuleType.AUXILIARY
        self.platform = Platform.WINDOWS
        self.tags = ["shellcode", "donut", "payload", "evasion", "loader"]
        self.references = [
            "https://github.com/TheWover/donut",
            "https://thewover.github.io/Introducing-Donut/"
        ]

        # Required options
        self.register_option("INPUT", "Input file (.exe, .dll, .vbs, .js, .xsl)", required=True)
        self.register_option("OUTPUT", "Output file (without extension)", default="loader")

        # Command/parameters for the payload
        self.register_option("PARAMS", "Parameters to pass to the payload (e.g., '-cmd \"cmd /c whoami\"')", default="")

        # Architecture: 1=x86, 2=x64, 3=x86+x64
        self.register_option("ARCH", "Target architecture (1=x86, 2=x64, 3=both)",
                           default="2",
                           choices=["1", "2", "3"])

        # Bypass options: 1=none, 2=abort on fail, 3=continue on fail
        self.register_option("BYPASS", "AMSI/WLDP bypass (1=none, 2=abort, 3=continue)",
                           default="3",
                           choices=["1", "2", "3"])

        # .NET specific options
        self.register_option("CLASS", "Class name for .NET DLL", default="")
        self.register_option("METHOD", "Method name for .NET DLL", default="")

        # Advanced options
        self.register_option("ENTROPY", "Entropy (1=none, 2=random, 3=encrypted)",
                           default="3",
                           choices=["1", "2", "3"])

        self.register_option("COMPRESS", "Compression (1=none, 2=aPLib, 3=LZNT1, 4=Xpress, 5=XpressHuff)",
                           default="1",
                           choices=["1", "2", "3", "4", "5"])

        self.register_option("FORMAT", "Output format (1=bin, 2=b64, 3=c, 4=ruby, 5=py, 6=ps1, 7=cs, 8=hex)",
                           default="1",
                           choices=["1", "2", "3", "4", "5", "6", "7", "8"])

        self.register_option("EXIT_OPT", "Exit behavior (1=thread, 2=process)",
                           default="1",
                           choices=["1", "2"])

        # Base64 encoding
        self.register_option("BASE64", "Also create base64 encoded version",
                           default="yes",
                           choices=["yes", "no"])

        # Working directory (uses global WORKING_DIR by default)
        self.register_option("WORKDIR", "Output directory (defaults to WORKING_DIR)", default="")

    def run(self) -> bool:
        input_file = self.get_option("INPUT")
        output_base = self.get_option("OUTPUT")
        params = self.get_option("PARAMS")
        arch = self.get_option("ARCH")
        bypass = self.get_option("BYPASS")
        class_name = self.get_option("CLASS")
        method = self.get_option("METHOD")
        entropy = self.get_option("ENTROPY")
        compress = self.get_option("COMPRESS")
        fmt = self.get_option("FORMAT")
        exit_opt = self.get_option("EXIT_OPT")
        do_base64 = self.get_option("BASE64") == "yes"
        workdir = self.get_option("WORKDIR")

        # Use global WORKING_DIR if workdir not explicitly set
        if not workdir and self._config:
            workdir = self._config.get_working_dir()

        # Resolve input file path using workdir if relative
        if not os.path.isabs(input_file) and workdir:
            resolved_input = os.path.join(workdir, input_file)
            if os.path.exists(resolved_input):
                input_file = resolved_input

        # Validate input file exists
        if not os.path.exists(input_file):
            self.print_error(f"Input file not found: {input_file}")
            return False

        # Build output path
        if workdir:
            os.makedirs(workdir, exist_ok=True)
            output_bin = os.path.join(workdir, f"{output_base}.bin")
        else:
            output_bin = f"{output_base}.bin"

        self.print_status(f"Input: {input_file}")
        self.print_status(f"Output: {output_bin}")
        self.print_status(f"Architecture: {'x86' if arch == '1' else 'x64' if arch == '2' else 'x86+x64'}")
        if params:
            self.print_status(f"Parameters: {params}")
        self.print_line()

        # Build donut command
        cmd_parts = ["donut", input_file]
        cmd_parts.extend(["-o", output_bin])
        cmd_parts.extend(["-a", arch])
        cmd_parts.extend(["-b", bypass])
        cmd_parts.extend(["-e", entropy])
        cmd_parts.extend(["-z", compress])
        cmd_parts.extend(["-f", fmt])
        cmd_parts.extend(["-t", exit_opt])

        # Add .NET specific options
        if class_name:
            cmd_parts.extend(["-c", class_name])
        if method:
            cmd_parts.extend(["-m", method])

        # Add parameters - handle the tricky quoting
        if params:
            # Strip outer single quotes if present (from shell quoting)
            if params.startswith("'") and params.endswith("'"):
                params = params[1:-1]
            cmd_parts.extend(["-p", params])

        # Execute donut
        self.print_status(f"Executing: {' '.join(cmd_parts)}")
        self.print_line()

        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Display output
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('[+]'):
                        self.print_good(line)
                    elif line.startswith('[-]'):
                        self.print_error(line)
                    elif line.startswith('[*]'):
                        self.print_status(line.replace('[*]', '').strip())
                    else:
                        self.print_line(f"    {line}")

            if result.stderr:
                self.print_error(result.stderr)

            if result.returncode != 0:
                self.print_error("Donut failed to generate shellcode")
                return False

        except FileNotFoundError:
            self.print_error("donut command not found. Ensure donut is installed and in PATH")
            return False
        except subprocess.TimeoutExpired:
            self.print_error("Donut timed out")
            return False
        except Exception as e:
            self.print_error(f"Error running donut: {e}")
            return False

        # Verify output was created
        if not os.path.exists(output_bin):
            self.print_error(f"Output file was not created: {output_bin}")
            return False

        file_size = os.path.getsize(output_bin)
        self.print_good(f"Shellcode generated: {output_bin} ({file_size} bytes)")

        # Base64 encode if requested
        if do_base64:
            output_b64 = f"{output_bin[:-4]}.enc" if output_bin.endswith('.bin') else f"{output_bin}.enc"

            try:
                with open(output_bin, 'rb') as f:
                    shellcode = f.read()

                b64_shellcode = base64.b64encode(shellcode).decode('ascii')

                with open(output_b64, 'w') as f:
                    f.write(b64_shellcode)

                self.print_good(f"Base64 encoded: {output_b64}")

                # Show preview
                self.print_line()
                self.print_status("Base64 preview (first 100 chars):")
                self.print_line(f"    {b64_shellcode[:100]}...")

            except Exception as e:
                self.print_error(f"Failed to base64 encode: {e}")
                return False

        self.print_line()
        self.print_good("Shellcode generation complete!")

        return True

    def check(self) -> bool:
        """Verify donut is available"""
        try:
            result = subprocess.run(
                ["donut", "--help"],
                capture_output=True,
                timeout=5
            )
            return True
        except:
            return False
