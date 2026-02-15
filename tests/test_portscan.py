#!/usr/bin/env python3
"""Quick test: rustscan portscan_fast against DRAGONSTONE and WINTERFELL."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.enumeration.portscan_fast import FastPortScanner

targets = {
    "DRAGONSTONE": "10.2.10.10",
    "WINTERFELL": "10.2.10.20",
}

target_name = sys.argv[1] if len(sys.argv) > 1 else "DRAGONSTONE"
ip = targets.get(target_name, target_name)

m = FastPortScanner()
m.set_option("RHOSTS", ip)
m.set_option("OUTPUT", f"/tmp/scan_{target_name.lower()}")
result = m.run()

tag = "PASS" if result else "FAIL"
print(f"\n=== {target_name} ({ip}): {tag} ===")
sys.exit(0 if result else 1)
