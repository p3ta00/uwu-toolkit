#!/usr/bin/env python3
"""
Download Potato Exploits for SeImpersonate Privilege Escalation
Downloads: GodPotato, PrintSpoofer, SweetPotato, JuicyPotato, RoguePotato
"""

import os
import sys
import argparse
import urllib.request
import zipfile
import io
from pathlib import Path

# Default download location
DEFAULT_PATH = "/opt/my-resources/tools/potatoes"

# Potato download sources
POTATOES = {
    "GodPotato.exe": {
        "url": "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe",
        "description": "GodPotato - Windows 8-11, Server 2012-2022",
    },
    "PrintSpoofer.exe": {
        "url": "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe",
        "description": "PrintSpoofer - Uses print spooler service",
    },
    "JuicyPotato.exe": {
        "url": "https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe",
        "description": "JuicyPotato - Classic, works on older Windows",
    },
    "RoguePotato.exe": {
        "url": "https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip",
        "description": "RoguePotato - Requires attacker listener",
        "zip_extract": "RoguePotato.exe",
    },
    "SweetPotato.exe": {
        "url": "https://raw.githubusercontent.com/uknowsec/SweetPotato/master/SweetPotato-Webshell-new/bin/Release/SweetPotato.exe",
        "description": "SweetPotato - Combines multiple techniques",
    },
}

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def print_status(msg):
    print(f"{CYAN}[*]{RESET} {msg}")


def print_good(msg):
    print(f"{GREEN}[+]{RESET} {msg}")


def print_error(msg):
    print(f"{RED}[-]{RESET} {msg}")


def print_warning(msg):
    print(f"{YELLOW}[!]{RESET} {msg}")


def download_file(url: str, dest_path: Path, extract_from_zip: str = None) -> bool:
    """Download a file from URL"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "UwU-Toolkit"})
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read()

        if extract_from_zip:
            # Extract specific file from zip
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if extract_from_zip.lower() in name.lower():
                        with open(dest_path, "wb") as f:
                            f.write(zf.read(name))
                        return True
            return False
        else:
            with open(dest_path, "wb") as f:
                f.write(data)
            return True

    except Exception as e:
        print_error(f"Download failed: {e}")
        return False


def check_and_download(output_dir: Path, force: bool = False) -> dict:
    """Check for missing potatoes and download them"""
    results = {"downloaded": [], "existing": [], "failed": []}

    output_dir.mkdir(parents=True, exist_ok=True)

    for filename, info in POTATOES.items():
        dest_path = output_dir / filename

        # Check if already exists
        if dest_path.exists() and dest_path.stat().st_size > 1000 and not force:
            print_good(f"Already exists: {filename}")
            results["existing"].append(filename)
            continue

        # Download
        print_status(f"Downloading {filename}...")
        print_status(f"  {info['description']}")

        zip_extract = info.get("zip_extract")
        if download_file(info["url"], dest_path, zip_extract):
            # Verify download
            if dest_path.exists() and dest_path.stat().st_size > 1000:
                print_good(f"  Saved: {dest_path}")
                results["downloaded"].append(filename)
            else:
                print_error(f"  Download appears corrupt")
                dest_path.unlink(missing_ok=True)
                results["failed"].append(filename)
        else:
            results["failed"].append(filename)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Download Potato exploits for SeImpersonate privilege escalation"
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_PATH,
        help=f"Output directory (default: {DEFAULT_PATH})"
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force re-download even if files exist"
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List available potatoes without downloading"
    )

    args = parser.parse_args()

    print(f"""
{CYAN}╔══════════════════════════════════════════════════════╗
║  Potato Exploit Downloader                           ║
║  SeImpersonate Privilege Escalation Tools            ║
╚══════════════════════════════════════════════════════╝{RESET}
""")

    if args.list:
        print("Available Potato Exploits:")
        print("-" * 50)
        for name, info in POTATOES.items():
            print(f"  {GREEN}{name}{RESET}")
            print(f"    {info['description']}")
            print()
        return

    output_dir = Path(args.output)
    print_status(f"Output directory: {output_dir}")
    print()

    # Check write permissions
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        test_file = output_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
    except PermissionError:
        print_error(f"Cannot write to {output_dir}")
        fallback = Path.home() / ".local" / "share" / "potatoes"
        print_warning(f"Using fallback: {fallback}")
        output_dir = fallback
        output_dir.mkdir(parents=True, exist_ok=True)

    # Download
    results = check_and_download(output_dir, args.force)

    # Summary
    print()
    print("=" * 50)
    print(f"{GREEN}Downloaded:{RESET} {len(results['downloaded'])}")
    print(f"{CYAN}Existing:{RESET}   {len(results['existing'])}")
    if results["failed"]:
        print(f"{RED}Failed:{RESET}     {len(results['failed'])} - {', '.join(results['failed'])}")

    print()
    print_good(f"Potatoes saved to: {output_dir}")
    print()
    print("Usage in UwU Toolkit:")
    print(f"  {CYAN}use post/windows/seimpersonate{RESET}")
    print(f"  {CYAN}set POTATO godpotato{RESET}")
    print(f"  {CYAN}set SESSION 1{RESET}")
    print(f"  {CYAN}set EXECUTE whoami{RESET}")
    print(f"  {CYAN}run{RESET}")


if __name__ == "__main__":
    main()
