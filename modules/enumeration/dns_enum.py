"""
DNS Enumeration Module
Comprehensive DNS reconnaissance including:
- Zone transfers (AXFR)
- Subdomain bruteforce
- DNS record enumeration (A, AAAA, MX, NS, TXT, SRV, SOA)
- Reverse DNS lookups
- DNSSEC checks
"""

import subprocess
import shutil
import os
import re
import socket
from typing import List, Dict, Set, Optional
from datetime import datetime
from core.module_base import ModuleBase, ModuleType, Platform
from core.wordlists import resolve_wordlist


class DNSEnum(ModuleBase):
    """
    DNS Enumeration module combining multiple techniques:
    - Zone transfer attempts (AXFR)
    - Record enumeration
    - Subdomain bruteforce
    - Reverse lookups
    """

    def __init__(self):
        super().__init__()
        self.name = "dns_enum"
        self.description = "DNS enumeration - zone transfers, records, subdomains"
        self.author = "UwU Toolkit"
        self.module_type = ModuleType.ENUMERATION
        self.platform = Platform.NETWORK
        self.tags = ["dns", "enumeration", "recon", "subdomain", "zone-transfer"]

        # Register options
        self.register_option("DOMAIN", "Target domain", required=True)
        self.register_option("NAMESERVER", "Specific nameserver to query", default="")
        self.register_option("MODE", "Enumeration mode",
                           default="all",
                           choices=["all", "records", "axfr", "bruteforce", "reverse"])
        self.register_option("WORDLIST", "Wordlist for bruteforce (name or path)",
                           default="medium")
        self.register_option("THREADS", "Threads for bruteforce", default="50")
        self.register_option("OUTPUT", "Output directory", default="./dns_results")
        self.register_option("SUBNET", "Subnet for reverse lookups (e.g., 10.10.10.0/24)", default="")

        self.results: Dict[str, List] = {
            "nameservers": [],
            "mx_records": [],
            "a_records": [],
            "aaaa_records": [],
            "txt_records": [],
            "srv_records": [],
            "cname_records": [],
            "zone_transfer": [],
            "subdomains": [],
        }

    def run(self) -> bool:
        domain = self.get_option("DOMAIN")
        nameserver = self.get_option("NAMESERVER")
        mode = self.get_option("MODE")
        output_dir = self.get_option("OUTPUT")

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  DNS Enumeration")
        self.print_good("=" * 60)
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Mode: {mode}")
        self.print_line()

        # Get nameservers first if not specified
        if not nameserver:
            nameservers = self._get_nameservers(domain)
            if nameservers:
                nameserver = nameservers[0]
                self.results["nameservers"] = nameservers
                self.print_status(f"Discovered nameservers: {', '.join(nameservers)}")
            else:
                self.print_warning("Could not discover nameservers, using system resolver")

        if mode in ["all", "records"]:
            self._enumerate_records(domain, nameserver)

        if mode in ["all", "axfr"]:
            self._try_zone_transfer(domain)

        if mode in ["all", "bruteforce"]:
            self._bruteforce_subdomains(domain, nameserver, output_dir, timestamp)

        if mode in ["all", "reverse"] or self.get_option("SUBNET"):
            subnet = self.get_option("SUBNET")
            if subnet:
                self._reverse_lookup(subnet, output_dir, timestamp)

        # Save results
        self._save_results(domain, output_dir, timestamp)
        self._print_summary(domain)

        return True

    def _get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers for domain"""
        try:
            result = subprocess.run(
                ["dig", "+short", "NS", domain],
                capture_output=True, text=True, timeout=10
            )
            nameservers = [ns.rstrip('.') for ns in result.stdout.strip().split('\n') if ns]
            return nameservers
        except Exception:
            return []

    def _enumerate_records(self, domain: str, nameserver: str) -> None:
        """Enumerate various DNS record types"""
        self.print_line()
        self.print_good("[DNS Record Enumeration]")
        self.print_line("-" * 40)

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV", "CNAME"]

        for rtype in record_types:
            records = self._query_record(domain, rtype, nameserver)
            if records:
                self.print_status(f"{rtype} Records:")
                for record in records:
                    self.print_good(f"  {record}")

                # Store results
                key = f"{rtype.lower()}_records"
                if key in self.results:
                    self.results[key].extend(records)

        # Check for wildcard
        self._check_wildcard(domain, nameserver)

        # Check DNSSEC
        self._check_dnssec(domain)

    def _query_record(self, domain: str, rtype: str, nameserver: str = "") -> List[str]:
        """Query specific DNS record type"""
        try:
            cmd = ["dig", "+short", rtype, domain]
            if nameserver:
                cmd.insert(1, f"@{nameserver}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            records = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]
            return records
        except Exception:
            return []

    def _check_wildcard(self, domain: str, nameserver: str) -> None:
        """Check for wildcard DNS"""
        import random
        import string

        random_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
        test_domain = f"{random_sub}.{domain}"

        records = self._query_record(test_domain, "A", nameserver)
        if records:
            self.print_warning(f"[!] Wildcard DNS detected! Random subdomain resolves to: {records[0]}")
        else:
            self.print_status("[*] No wildcard DNS detected")

    def _check_dnssec(self, domain: str) -> None:
        """Check DNSSEC status"""
        try:
            result = subprocess.run(
                ["dig", "+dnssec", "DNSKEY", domain],
                capture_output=True, text=True, timeout=10
            )
            if "RRSIG" in result.stdout:
                self.print_good("[+] DNSSEC is enabled")
            else:
                self.print_status("[*] DNSSEC not detected")
        except Exception:
            pass

    def _try_zone_transfer(self, domain: str) -> None:
        """Attempt zone transfer against all nameservers"""
        self.print_line()
        self.print_good("[Zone Transfer Attempts (AXFR)]")
        self.print_line("-" * 40)

        nameservers = self.results.get("nameservers", []) or self._get_nameservers(domain)

        if not nameservers:
            self.print_warning("No nameservers found to try zone transfer")
            return

        for ns in nameservers:
            self.print_status(f"Trying zone transfer on {ns}...")

            try:
                result = subprocess.run(
                    ["dig", f"@{ns}", "AXFR", domain],
                    capture_output=True, text=True, timeout=30
                )

                if "Transfer failed" in result.stdout or "XFR size" not in result.stdout:
                    self.print_error(f"  Zone transfer failed on {ns}")
                else:
                    self.print_good(f"  [!!!] Zone transfer SUCCESSFUL on {ns}!")
                    self.print_line()

                    # Parse and display results
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line and not line.startswith(';'):
                            self.print_good(f"    {line}")
                            self.results["zone_transfer"].append(line)

            except subprocess.TimeoutExpired:
                self.print_error(f"  Timeout on {ns}")
            except Exception as e:
                self.print_error(f"  Error on {ns}: {e}")

    def _bruteforce_subdomains(self, domain: str, nameserver: str,
                               output_dir: str, timestamp: str) -> None:
        """Bruteforce subdomains using available tools"""
        self.print_line()
        self.print_good("[Subdomain Bruteforce]")
        self.print_line("-" * 40)

        wordlist = self._get_wordlist(self.get_option("WORDLIST"))
        threads = self.get_option("THREADS")
        output_file = f"{output_dir}/{domain}_{timestamp}_subdomains"

        self.print_status(f"Wordlist: {wordlist}")

        # Try different tools in order of preference
        if shutil.which("gobuster"):
            self._bruteforce_gobuster(domain, wordlist, threads, output_file)
        elif shutil.which("dnsrecon"):
            self._bruteforce_dnsrecon(domain, wordlist, output_file)
        elif shutil.which("dnsenum"):
            self._bruteforce_dnsenum(domain, wordlist, output_file)
        else:
            self._bruteforce_dig(domain, wordlist, nameserver, output_file)

    def _get_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path using cross-platform resolver"""
        # Map old names to new resolver names
        name_map = {
            "small": "subdomains_small",
            "medium": "subdomains_medium",
            "large": "subdomains_large",
            "fierce": "dns_fierce",
        }
        resolved_name = name_map.get(wordlist, wordlist)
        resolved = resolve_wordlist(resolved_name, fallback="subdomains")
        if resolved:
            return resolved
        if os.path.exists(wordlist):
            return wordlist
        self.print_warning(f"Wordlist '{wordlist}' not found")
        return resolve_wordlist("subdomains_small") or "/usr/share/wordlists/dirb/common.txt"

    def _bruteforce_gobuster(self, domain: str, wordlist: str, threads: str, output_file: str) -> None:
        """Use gobuster for DNS bruteforce"""
        cmd = [
            "gobuster", "dns",
            "-d", domain,
            "-w", wordlist,
            "-t", threads,
            "-o", f"{output_file}.txt",
        ]

        self.print_status(f"Using gobuster: {' '.join(cmd[:8])}...")
        self._run_bruteforce(cmd)

    def _bruteforce_dnsrecon(self, domain: str, wordlist: str, output_file: str) -> None:
        """Use dnsrecon for bruteforce"""
        cmd = [
            "dnsrecon",
            "-d", domain,
            "-t", "brt",
            "-D", wordlist,
            "-j", f"{output_file}.json",
        ]

        self.print_status(f"Using dnsrecon: {' '.join(cmd[:8])}...")
        self._run_bruteforce(cmd)

    def _bruteforce_dnsenum(self, domain: str, wordlist: str, output_file: str) -> None:
        """Use dnsenum for bruteforce"""
        cmd = [
            "dnsenum",
            "--dnsserver", "8.8.8.8",
            "-f", wordlist,
            "-o", f"{output_file}.xml",
            domain,
        ]

        self.print_status(f"Using dnsenum: {' '.join(cmd[:6])}...")
        self._run_bruteforce(cmd)

    def _bruteforce_dig(self, domain: str, wordlist: str, nameserver: str, output_file: str) -> None:
        """Manual bruteforce using dig"""
        self.print_status("Using dig for bruteforce (slower)...")

        try:
            with open(wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.print_error(f"Failed to read wordlist: {e}")
            return

        found = []
        total = len(subdomains)

        for i, sub in enumerate(subdomains[:1000]):  # Limit for dig method
            if i % 100 == 0:
                self.print_status(f"Progress: {i}/{min(total, 1000)}")

            test_domain = f"{sub}.{domain}"
            records = self._query_record(test_domain, "A", nameserver)
            if records:
                self.print_good(f"Found: {test_domain} -> {records[0]}")
                found.append((test_domain, records[0]))
                self.results["subdomains"].append(test_domain)

        # Save results
        with open(f"{output_file}.txt", 'w') as f:
            for sub, ip in found:
                f.write(f"{sub},{ip}\n")

        self.print_status(f"Found {len(found)} subdomains")

    def _run_bruteforce(self, cmd: List[str]) -> None:
        """Run bruteforce tool with output"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in iter(process.stdout.readline, ''):
                line = line.rstrip()
                if line:
                    if "found" in line.lower() or re.search(r'\d+\.\d+\.\d+\.\d+', line):
                        self.print_good(line)
                        # Extract subdomain
                        match = re.search(r'Found:\s*(\S+)', line)
                        if match:
                            self.results["subdomains"].append(match.group(1))
                    else:
                        self.print_line(line)

            process.wait()

        except Exception as e:
            self.print_error(f"Bruteforce error: {e}")

    def _reverse_lookup(self, subnet: str, output_dir: str, timestamp: str) -> None:
        """Perform reverse DNS lookups on subnet"""
        self.print_line()
        self.print_good("[Reverse DNS Lookups]")
        self.print_line("-" * 40)

        import ipaddress

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            self.print_error(f"Invalid subnet: {e}")
            return

        self.print_status(f"Scanning {network.num_addresses} addresses...")

        found = []
        for ip in list(network.hosts())[:256]:  # Limit to /24
            try:
                hostname, _, _ = socket.gethostbyaddr(str(ip))
                self.print_good(f"{ip} -> {hostname}")
                found.append((str(ip), hostname))
            except socket.herror:
                pass
            except Exception:
                pass

        self.print_status(f"Found {len(found)} reverse DNS entries")

    def _save_results(self, domain: str, output_dir: str, timestamp: str) -> None:
        """Save all results to file"""
        output_file = f"{output_dir}/{domain}_{timestamp}_dns_enum.txt"

        with open(output_file, 'w') as f:
            f.write(f"DNS Enumeration Results for {domain}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write("=" * 60 + "\n\n")

            for key, values in self.results.items():
                if values:
                    f.write(f"[{key.upper()}]\n")
                    for v in values:
                        f.write(f"  {v}\n")
                    f.write("\n")

        self.print_status(f"Results saved to: {output_file}")

    def _print_summary(self, domain: str) -> None:
        """Print enumeration summary"""
        self.print_line()
        self.print_good("=" * 60)
        self.print_good("  Enumeration Summary")
        self.print_good("=" * 60)

        total = sum(len(v) for v in self.results.values())
        self.print_status(f"Domain: {domain}")
        self.print_status(f"Total records found: {total}")

        for key, values in self.results.items():
            if values:
                self.print_line(f"  {key}: {len(values)}")

        # Highlight findings
        if self.results["zone_transfer"]:
            self.print_line()
            self.print_warning("[!!!] ZONE TRANSFER SUCCESSFUL - Check full output!")

        if self.results["subdomains"]:
            self.print_line()
            self.print_status("Discovered subdomains:")
            for sub in self.results["subdomains"][:10]:
                self.print_good(f"  {sub}")
            if len(self.results["subdomains"]) > 10:
                self.print_status(f"  ... and {len(self.results['subdomains']) - 10} more")

    def check(self) -> bool:
        """Check if dig is available"""
        if not shutil.which("dig"):
            self.print_error("dig not found")
            return False
        return True
