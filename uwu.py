#!/usr/bin/env python3
"""
UwU Toolkit - Main Entry Point
Penetration Testing Framework
"""

import sys
import os

# Add toolkit to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.console import UwUConsole
from core.config import Config


def main():
    """Main entry point"""
    config = Config()
    console = UwUConsole(config)

    # Check for command-line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "-c" and len(sys.argv) > 2:
            # Execute commands directly
            commands = sys.argv[2].split(";")
            for cmd in commands:
                cmd = cmd.strip()
                if cmd:
                    console.execute_command(cmd)
            return
        elif sys.argv[1] == "-r" and len(sys.argv) > 2:
            # Execute resource file
            console.execute_command(f"resource {sys.argv[2]}")
            return
        elif sys.argv[1] in ["-h", "--help"]:
            print("UwU Toolkit - Penetration Testing Framework")
            print("\nUsage:")
            print("  uwu.py              Interactive console")
            print("  uwu.py -c 'cmd'     Execute commands (semicolon separated)")
            print("  uwu.py -r file.rc   Execute resource file")
            return

    # Start interactive console
    console.run()


if __name__ == "__main__":
    main()
