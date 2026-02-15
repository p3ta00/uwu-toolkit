"""
Donut Shellcode Generator Module
Generates position-independent shellcode from PE, DLL, VBS, JS, and .NET assemblies.
Uses the donut-shellcode Python package or the donut binary.
Supports multiple output formats and automatic base64 encoding.
"""

import os
import base64
import shlex
from core.module_base import ModuleBase, ModuleType, Platform, find_tool


# Map user-friendly format names to donut format codes
FORMAT_MAP = {
    "bin": "1",
    "base64": "2",
    "c": "3",
    "py": "5",
    "powershell": "6",
    "csharp": "7",
}

# Map user-friendly arch names to donut arch codes
ARCH_MAP = {
    "x86": "1",
    "x64": "2",
    "x86+x64": "3",
}


class Donut(ModuleBase):
    """
    Donut shellcode generator with multiple output formats.

    Converts PE executables, DLLs, VBS, JS, and .NET assemblies into
    position-independent shellcode for in-memory execution.
    Supports x86, x64, and x86+x64 architectures.
    """

    def __init__(self):
        super().__init__()
        self.name = "donut"
        self.description = "Generate Donut shellcode from PE/DLL/.NET with multiple output formats"
        self.author = "UwU Toolkit"
        self.version = "2.0.0"
        self.module_type = ModuleType.PAYLOAD
        self.platform = Platform.WINDOWS
        self.tags = ["shellcode", "donut", "payload", "evasion", "loader", "pe", "dotnet"]
        self.references = [
            "https://github.com/TheWover/donut",
            "https://thewover.github.io/Introducing-Donut/",
        ]

        # Required options
        self.register_option("INPUT", "Input file (.exe, .dll, .vbs, .js, .xsl)", required=True)
        self.register_option("OUTPUT", "Output file path (without extension)", default="loader")

        # Architecture
        self.register_option("ARCH", "Target architecture",
                             default="x64",
                             choices=["x86", "x64", "x86+x64"])

        # Output format
        self.register_option("FORMAT", "Output format",
                             default="bin",
                             choices=["bin", "base64", "c", "py", "powershell", "csharp"])

        # .NET specific options
        self.register_option("CLASS", "Class name for .NET DLLs", default="")
        self.register_option("METHOD", "Method name for .NET DLLs", default="")

        # Parameters to pass to the payload
        self.register_option("ARGS", "Arguments to pass to the payload", default="")

        # AMSI/WLDP bypass
        self.register_option("BYPASS", "AMSI/WLDP bypass (1=none, 2=abort, 3=continue)",
                             default="3",
                             choices=["1", "2", "3"])

        # Entropy/encryption
        self.register_option("ENTROPY", "Entropy level (1=none, 2=random, 3=encrypted)",
                             default="3",
                             choices=["1", "2", "3"])

        # Compression
        self.register_option("COMPRESS", "Compression (1=none, 2=aPLib, 3=LZNT1, 4=Xpress, 5=XpressHuff)",
                             default="1",
                             choices=["1", "2", "3", "4", "5"])

        # Exit behavior
        self.register_option("EXIT_OPT", "Exit behavior (1=thread, 2=process)",
                             default="1",
                             choices=["1", "2"])

        # Working directory
        self.register_option("WORKDIR", "Output directory (defaults to current dir)", default="")

    def run(self) -> bool:
        input_file = self.get_option("INPUT")
        output_base = self.get_option("OUTPUT")
        arch = self.get_option("ARCH")
        fmt = self.get_option("FORMAT")
        class_name = self.get_option("CLASS")
        method = self.get_option("METHOD")
        args = self.get_option("ARGS")
        bypass = self.get_option("BYPASS")
        entropy = self.get_option("ENTROPY")
        compress = self.get_option("COMPRESS")
        exit_opt = self.get_option("EXIT_OPT")
        workdir = self.get_option("WORKDIR")

        # Use global WORKING_DIR if workdir not set
        if not workdir and self._config:
            workdir = self._config.get_working_dir()

        # Resolve input file path
        if not os.path.isabs(input_file) and workdir:
            resolved_input = os.path.join(workdir, input_file)
            if os.path.exists(resolved_input):
                input_file = resolved_input

        # Validate input file
        if not os.path.exists(input_file):
            self.print_error(f"Input file not found: {input_file}")
            return False

        # Build output path with appropriate extension
        ext_map = {
            "bin": ".bin",
            "base64": ".b64",
            "c": ".c",
            "py": ".py",
            "powershell": ".ps1",
            "csharp": ".cs",
        }
        output_ext = ext_map.get(fmt, ".bin")

        if workdir:
            os.makedirs(workdir, exist_ok=True)
            output_file = os.path.join(workdir, f"{output_base}{output_ext}")
        else:
            output_file = f"{output_base}{output_ext}"

        # Resolve donut format/arch codes
        arch_code = ARCH_MAP.get(arch, "2")
        format_code = FORMAT_MAP.get(fmt, "1")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Donut Shellcode Generator")
        self.print_good("=" * 60)
        self.print_status(f"Input: {input_file}")
        self.print_status(f"Output: {output_file}")
        self.print_status(f"Architecture: {arch}")
        self.print_status(f"Format: {fmt}")
        self.print_status(f"Bypass: {bypass} ({'none' if bypass == '1' else 'abort on fail' if bypass == '2' else 'continue on fail'})")
        self.print_status(f"Entropy: {entropy} ({'none' if entropy == '1' else 'random' if entropy == '2' else 'encrypted'})")
        if class_name:
            self.print_status(f".NET Class: {class_name}")
        if method:
            self.print_status(f".NET Method: {method}")
        if args:
            self.print_status(f"Arguments: {args}")
        self.print_line()

        # Try Python donut-shellcode package first, then binary
        success = self._try_python_donut(input_file, output_file, arch_code, format_code,
                                          bypass, entropy, compress, exit_opt,
                                          class_name, method, args)

        if not success:
            self.print_status("Python donut failed, trying donut binary...")
            success = self._try_binary_donut(input_file, output_file, arch_code, format_code,
                                              bypass, entropy, compress, exit_opt,
                                              class_name, method, args)

        if not success:
            self.print_status("Local donut failed, trying via Exegol...")
            success = self._try_exegol_donut(input_file, output_file, arch_code, format_code,
                                              bypass, entropy, compress, exit_opt,
                                              class_name, method, args)

        if not success:
            self.print_error("All donut methods failed. Ensure donut is installed.")
            self.print_error("Install with: pip install donut-shellcode")
            return False

        # Verify output
        if not os.path.exists(output_file):
            self.print_error(f"Output file was not created: {output_file}")
            return False

        file_size = os.path.getsize(output_file)
        self.print_line()
        self.print_good(f"Shellcode generated: {output_file} ({file_size} bytes)")

        # If format is bin, also create a base64 version for convenience
        if fmt == "bin":
            b64_file = output_file.replace(".bin", ".b64")
            try:
                with open(output_file, 'rb') as f:
                    shellcode = f.read()
                b64_data = base64.b64encode(shellcode).decode('ascii')
                with open(b64_file, 'w') as f:
                    f.write(b64_data)
                self.print_good(f"Base64 encoded: {b64_file}")
                self.print_line()
                self.print_status("Base64 preview (first 100 chars):")
                self.print_line(f"    {b64_data[:100]}...")
            except Exception as e:
                self.print_warning(f"Could not create base64 version: {e}")

        self.print_line()
        self.print_good("Shellcode generation complete!")
        return True

    def _try_python_donut(self, input_file, output_file, arch, fmt, bypass, entropy,
                           compress, exit_opt, class_name, method, args) -> bool:
        """Try using the donut-shellcode Python package."""
        try:
            import donut

            kwargs = {
                "in_file": input_file,
                "out_file": output_file,
                "arch": int(arch),
                "bypass": int(bypass),
                "entropy": int(entropy),
                "compress": int(compress),
                "format": int(fmt),
                "exit_opt": int(exit_opt),
            }

            if class_name:
                kwargs["cls"] = class_name
            if method:
                kwargs["method"] = method
            if args:
                kwargs["params"] = args

            self.print_status("Using donut-shellcode Python package...")
            shellcode = donut.create(**kwargs)

            if shellcode is None:
                self.print_warning("donut.create() returned None")
                return False

            self.print_good("Donut Python module succeeded")
            return True

        except ImportError:
            self.print_status("donut-shellcode Python package not available")
            return False
        except Exception as e:
            self.print_warning(f"donut Python error: {e}")
            return False

    def _try_binary_donut(self, input_file, output_file, arch, fmt, bypass, entropy,
                           compress, exit_opt, class_name, method, args) -> bool:
        """Try using the donut binary."""
        donut_path = find_tool("donut")
        if not donut_path:
            return False

        cmd = [
            donut_path, input_file,
            "-o", output_file,
            "-a", arch,
            "-b", bypass,
            "-e", entropy,
            "-z", compress,
            "-f", fmt,
            "-t", exit_opt,
        ]

        if class_name:
            cmd.extend(["-c", class_name])
        if method:
            cmd.extend(["-m", method])
        if args:
            cmd.extend(["-p", args])

        self.print_status(f"Using donut binary: {donut_path}")
        ret, stdout, stderr = self.run_command(cmd, timeout=60)

        # Display output
        for line in (stdout + stderr).split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('[+]'):
                self.print_good(line)
            elif line.startswith('[-]'):
                self.print_error(line)
            elif line.startswith('[*]'):
                self.print_status(line.replace('[*]', '').strip())
            else:
                self.print_line(f"    {line}")

        return ret == 0

    def _try_exegol_donut(self, input_file, output_file, arch, fmt, bypass, entropy,
                           compress, exit_opt, class_name, method, args) -> bool:
        """Try running donut inside Exegol container."""

        cmd = (
            f"donut {shlex.quote(input_file)} "
            f"-o {shlex.quote(output_file)} "
            f"-a {arch} -b {bypass} -e {entropy} -z {compress} -f {fmt} -t {exit_opt}"
        )

        if class_name:
            cmd += f" -c {shlex.quote(class_name)}"
        if method:
            cmd += f" -m {shlex.quote(method)}"
        if args:
            cmd += f" -p {shlex.quote(args)}"

        self.print_status(f"Running donut in Exegol...")
        ret, stdout, stderr = self.run_in_exegol(cmd, timeout=60)

        # Display output
        for line in (stdout + stderr).split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('[+]'):
                self.print_good(line)
            elif line.startswith('[-]'):
                self.print_error(line)
            elif line.startswith('[*]'):
                self.print_status(line.replace('[*]', '').strip())
            else:
                self.print_line(f"    {line}")

        return ret == 0

    def check(self) -> bool:
        """Verify donut is available via Python package, binary, or Exegol."""
        # Check Python package
        try:
            import donut
            self.print_good("donut-shellcode Python package available")
            return True
        except ImportError:
            pass

        # Check binary locally
        donut_path = find_tool("donut")
        if donut_path:
            self.print_good(f"donut binary found: {donut_path}")
            return True

        # Check in Exegol
        ret, stdout, _ = self.run_in_exegol("which donut || pip show donut-shellcode 2>/dev/null | head -1", timeout=15)
        if ret == 0 and stdout.strip():
            self.print_good(f"donut found in Exegol: {stdout.strip()}")
            return True

        self.print_error("donut not found")
        self.print_error("Install with: pip install donut-shellcode")
        self.print_error("Or download from: https://github.com/TheWover/donut")
        return False
