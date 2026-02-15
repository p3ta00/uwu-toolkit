#!/usr/bin/env python3
"""Standalone entrypoint for UwU Toolkit MCP Server."""

import sys
import os

# Add parent directory to path so we can import mcp package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uwu_mcp.server import main

if __name__ == "__main__":
    main()
