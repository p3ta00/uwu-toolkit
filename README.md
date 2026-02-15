# UwU Toolkit

A modular penetration testing framework inspired by Metasploit, designed for modern offensive security workflows. Built to run seamlessly inside Exegol containers with a cyberpunk neon aesthetic.

**[Full Documentation & Wiki](https://p3ta00.github.io/uwu-toolkit/)**

---

## Quick Start

```bash
# Interactive mode
uwu

# Set target and creds once, use everywhere
uwu > setg RHOSTS 10.10.10.100
uwu > setg DOMAIN corp.local
uwu > setg USER admin
uwu > setg PASS Password123

# Find and run modules
uwu > search kerberos
uwu > use ad/kerberoast
uwu > run
```

---

## Installation

### Exegol (Recommended)

```bash
git clone https://github.com/p3ta00/uwu-toolkit.git /opt/my-resources/tools/uwu-toolkit
cd /opt/my-resources/tools/uwu-toolkit
./install-exegol.sh
```

### Kali / Debian

```bash
git clone https://github.com/p3ta00/uwu-toolkit.git ~/uwu-toolkit
cd ~/uwu-toolkit
./install-kali.sh
```

---

## Module Categories

| Type | Path Prefix | Count | Description |
|------|-------------|-------|-------------|
| **Impacket** | `impacket/` | 40+ | Every Impacket tool auto-wrapped as a module |
| **BloodyAD** | `bloodyad/` | 25+ | Every BloodyAD operation auto-wrapped |
| **AD** | `ad/` | 30+ | Custom AD attack & enumeration modules |
| **Auxiliary** | `auxiliary/` | 15+ | SMB, SSH, web, cracking, git, AWS |
| **Enumeration** | `enumeration/` | 10+ | Host and service discovery |
| **Post** | `post/` | 15+ | Post-exploitation (Linux & Windows) |
| **Payloads** | `payloads/` | 4 | Reverse shells, ASPX, Donut |
| **Exploits** | `exploits/` | 3+ | Exploitation modules |

## Integrations

- **Exegol** - Auto-detects container, finds tools automatically
- **Claude AI** - Interactive security assistant (`claude ask "..."`)
- **Sliver C2** - Server/client management from within UwU
- **Penelope** - Shell handler with auto-upgrade
- **Ligolo-ng** - Network tunneling with route management
- **MCP Server** - Model Context Protocol server for AI agent integration

---

## Documentation

| Page | Link |
|------|------|
| **Wiki Home** | [p3ta00.github.io/uwu-toolkit](https://p3ta00.github.io/uwu-toolkit/) |
| **Installation** | [Installation Guide](https://p3ta00.github.io/uwu-toolkit/installation/) |
| **Commands** | [Commands Reference](https://p3ta00.github.io/uwu-toolkit/commands/) |
| **Custom Tooling** | [Custom Modules](https://p3ta00.github.io/uwu-toolkit/custom-tooling/) |
| **Integrations** | [Impacket, BloodyAD, Claude, Sliver, Penelope, Ligolo](https://p3ta00.github.io/uwu-toolkit/integrations/) |
| **Modules Guide** | [Using & Creating Modules](https://p3ta00.github.io/uwu-toolkit/modules/) |
| **Quick Reference** | [Cheat Sheet](https://p3ta00.github.io/uwu-toolkit/quick-reference/) |

---

## License

This tool is intended for authorized security testing only. Use responsibly.
