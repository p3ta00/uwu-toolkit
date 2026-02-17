#!/bin/bash
#
# UwU Toolkit - Kali/Debian Install Script
# Installs system dependencies, Python packages, and pentesting tools
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.uwu-toolkit"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PINK='\033[38;5;213m'
NC='\033[0m'

print_status() { echo -e "${CYAN}[*]${NC} $1"; }
print_good()   { echo -e "${GREEN}[+]${NC} $1"; }
print_error()  { echo -e "${RED}[-]${NC} $1"; }
print_warning(){ echo -e "${YELLOW}[!]${NC} $1"; }

echo -e "${PINK}"
echo "  ██╗   ██╗██╗    ██╗██╗   ██╗"
echo "  ██║   ██║██║    ██║██║   ██║"
echo "  ██║   ██║██║ █╗ ██║██║   ██║"
echo "  ██║   ██║██║███╗██║██║   ██║"
echo "  ╚██████╔╝╚███╔███╔╝╚██████╔╝"
echo "   ╚═════╝  ╚══╝╚══╝  ╚═════╝  Kali/Debian Install"
echo -e "${NC}"
echo

# ============================================================================
# Environment Guard
# ============================================================================

if [ -e "/.exegol" ] || [ -e "/opt/.exegol_aliases" ]; then
    print_error "Exegol detected. Use: ${CYAN}./install-exegol.sh${NC}"
    exit 1
fi

# Check for root/sudo
if [ "$EUID" -eq 0 ]; then
    SUDO=""
elif command -v sudo &>/dev/null; then
    SUDO="sudo"
else
    print_error "This script requires root or sudo access for system packages."
    exit 1
fi

# ============================================================================
# System Dependencies
# ============================================================================

echo "=========================================="
echo "       Installing System Packages"
echo "=========================================="
echo

SYSTEM_PKGS=(
    python3
    python3-pip
    tmux
    git
    curl
    wget
    netcat-openbsd
    socat
    nmap
    sshpass
    jq
    rlwrap
    smbclient
    iproute2
)

MISSING_SYS=()
for pkg in "${SYSTEM_PKGS[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        print_good "$pkg"
    else
        MISSING_SYS+=("$pkg")
    fi
done

if [ ${#MISSING_SYS[@]} -gt 0 ]; then
    print_status "Installing: ${MISSING_SYS[*]}"
    $SUDO apt-get update -qq
    $SUDO apt-get install -y "${MISSING_SYS[@]}"
    print_good "System packages installed"
fi

echo

# ============================================================================
# Python Version Check
# ============================================================================

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    print_good "Python $PYTHON_VERSION (>= $REQUIRED_VERSION)"
else
    print_error "Python $PYTHON_VERSION too old (>= $REQUIRED_VERSION required)"
    exit 1
fi

echo

# ============================================================================
# Python Dependencies
# ============================================================================

echo "=========================================="
echo "       Installing Python Packages"
echo "=========================================="
echo

# Determine pip flags
PIP_FLAGS="--user"
# On newer Debian/Ubuntu, --break-system-packages is needed
if python3 -m pip install --help 2>/dev/null | grep -q "break-system-packages"; then
    PIP_FLAGS="--user --break-system-packages"
fi

# Framework packages
FRAMEWORK_PY=(
    "prompt_toolkit:prompt_toolkit"
    "rich:rich"
    "requests:requests"
    "yaml:pyyaml"
    "fastmcp:fastmcp"
    "donut:donut-shellcode"
)

MISSING_PY=()
for pair in "${FRAMEWORK_PY[@]}"; do
    IFS=':' read -r import_name pip_name <<< "$pair"
    if python3 -c "import $import_name" 2>/dev/null; then
        print_good "Python: $import_name"
    else
        MISSING_PY+=("$pip_name")
    fi
done

# Pentesting CLI tools (checked as executables, not Python imports)
# format: command_name:pip_package
PENTEST_TOOLS=(
    "impacket-secretsdump:impacket"
    "certipy:certipy-ad"
    "bloodyAD:bloodyad"
    "nxc:netexec"
    "bloodhound-python:bloodhound"
)

MISSING_PENTEST=()
for pair in "${PENTEST_TOOLS[@]}"; do
    IFS=':' read -r cmd pip_name <<< "$pair"
    if command -v "$cmd" &>/dev/null; then
        print_good "$cmd (pentesting)"
    else
        print_warning "$cmd not found"
        MISSING_PENTEST+=("$pip_name")
    fi
done

if [ ${#MISSING_PY[@]} -gt 0 ]; then
    print_status "Installing framework packages: ${MISSING_PY[*]}"
    python3 -m pip install $PIP_FLAGS "${MISSING_PY[@]}" || {
        print_error "Some pip packages failed to install"
        print_warning "You may need to install them individually"
    }
    print_good "Framework packages installed"
fi

if [ ${#MISSING_PENTEST[@]} -gt 0 ]; then
    print_status "Installing pentesting tools: ${MISSING_PENTEST[*]}"
    python3 -m pip install $PIP_FLAGS "${MISSING_PENTEST[@]}" || {
        print_error "Some pentesting tools failed to install"
        print_warning "You may need to install them individually (e.g. pipx install impacket)"
    }
    print_good "Pentesting tools installed"
fi

echo

# ============================================================================
# SecLists
# ============================================================================

if [ -d "/usr/share/seclists" ]; then
    print_good "SecLists found at /usr/share/seclists"
elif dpkg -s seclists &>/dev/null; then
    print_good "SecLists package installed"
else
    print_status "Installing SecLists..."
    $SUDO apt-get install -y seclists 2>/dev/null || {
        print_warning "SecLists not available via apt"
        print_status "Install manually: sudo apt install seclists"
    }
fi

echo

# ============================================================================
# Directory Structure
# ============================================================================

echo "=========================================="
echo "       Setting Up UwU Toolkit"
echo "=========================================="
echo

print_status "Creating directories..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}/loot"
mkdir -p "${CONFIG_DIR}/sessions"
mkdir -p "${HOME}/.local/share/potatoes"
mkdir -p "${HOME}/.local/share/ligolo-ng"

# Check for Ligolo-ng proxy
if command -v ligolo-proxy &>/dev/null; then
    print_good "Ligolo-ng proxy found ($(which ligolo-proxy))"
else
    LIGOLO_FOUND=""
    for lp in "$HOME/.local/share/ligolo-ng/proxy" "$HOME/go/bin/ligolo-proxy"; do
        if [ -x "$lp" ]; then
            LIGOLO_FOUND="$lp"
            break
        fi
    done
    if [ -n "$LIGOLO_FOUND" ]; then
        print_good "Ligolo-ng proxy found ($LIGOLO_FOUND)"
    else
        print_warning "Ligolo-ng proxy not found"
        print_status "Install options:"
        echo "  1. Run 'ligolo download' from within UwU"
        echo "  2. go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest"
        echo "  3. Download from https://github.com/nicocha30/ligolo-ng/releases"
    fi
fi

print_good "Directories ready"
echo

# ============================================================================
# Symlinks
# ============================================================================

print_status "Creating symlinks in ${INSTALL_DIR}..."

UWU_SCRIPTS=(
    "uwu"
    "uwu_dashboard:uwu-dashboard"
    "uwu-clear"
    "uwu-export"
    "uwu-hacks"
    "uwu-list"
    "uwu-loot"
    "uwu-navi"
    "uwu-parse"
    "uwu-pwned"
    "uwu-target"
    "uwu-bash-completion"
)

for entry in "${UWU_SCRIPTS[@]}"; do
    IFS=':' read -r src link_name <<< "$entry"
    link_name="${link_name:-$src}"
    src_path="${SCRIPT_DIR}/${src}"

    if [ ! -e "$src_path" ]; then
        continue
    fi

    ln -sf "$src_path" "${INSTALL_DIR}/${link_name}"
done

print_good "Symlinks created"
echo

# ============================================================================
# Make Scripts Executable
# ============================================================================

print_status "Setting permissions..."
chmod +x "${SCRIPT_DIR}/uwu" "${SCRIPT_DIR}/uwu.py" "${SCRIPT_DIR}/uwu_dashboard"
for entry in "${UWU_SCRIPTS[@]}"; do
    IFS=':' read -r src _ <<< "$entry"
    [ -e "${SCRIPT_DIR}/${src}" ] && chmod +x "${SCRIPT_DIR}/${src}"
done
print_good "Permissions set"
echo

# ============================================================================
# PATH Check
# ============================================================================

if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    print_warning "${INSTALL_DIR} is not in your PATH"
    echo ""
    echo "  Add to your shell rc file (~/.bashrc or ~/.zshrc):"
    echo ""
    echo "    export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    echo ""
fi

# ============================================================================
# Shell Integration
# ============================================================================

print_status "Creating shell integration..."
cat > "${CONFIG_DIR}/shell-integration.sh" << 'SHELL_EOF'
# UwU Toolkit Shell Integration
# Source this file in your .bashrc or .zshrc

export PATH="${HOME}/.local/bin:${PATH}"

uwu-load-vars() {
    if [[ -f "${HOME}/.uwu-toolkit/globals.json" ]]; then
        eval $(uwu export --script 2>/dev/null)
        echo "[+] UwU variables loaded"
    fi
}

alias uwu-nc='uwu start nc'
alias uwu-php='uwu start php'
alias uwu-http='uwu start gosh'

uwu-target() {
    if [[ -n "$1" ]]; then
        uwu setg RHOSTS "$1"
    else
        echo "Usage: uwu-target <ip>"
    fi
}

uwu-listen() {
    local port="${1:-4444}"
    uwu start nc "$port"
}
SHELL_EOF

print_good "Shell integration at ${CONFIG_DIR}/shell-integration.sh"
echo

# ============================================================================
# Verify
# ============================================================================

echo "=========================================="
echo "       Verifying Installation"
echo "=========================================="
echo

print_status "Verifying..."
if "${INSTALL_DIR}/uwu" help > /dev/null 2>&1; then
    print_good "Installation successful!"
elif python3 "${SCRIPT_DIR}/uwu.py" help > /dev/null 2>&1; then
    print_good "Installation successful (via python3 uwu.py)"
else
    print_error "Verification failed — try: python3 ${SCRIPT_DIR}/uwu.py"
fi

echo
print_status "To enable shell integration, add to your rc file:"
echo ""
echo "    source ${CONFIG_DIR}/shell-integration.sh"
echo ""

# ============================================================================
# Summary
# ============================================================================

echo "=========================================="
echo "           Setup Complete!"
echo "=========================================="
echo
echo -e "${GREEN}=== Quick Start ===${NC}"
echo ""
echo "  Start:    uwu"
echo "  Search:   search smb"
echo "  Module:   use auxiliary/ad/kerberoast"
echo "  Target:   set RHOSTS 10.10.10.10"
echo "  Run:      run"
echo ""
echo -e "${GREEN}=== Key Commands ===${NC}"
echo ""
echo "  setg RHOSTS <ip>     Set global target"
echo "  creds add <u> <p>    Add credential"
echo "  potatoes download    Download privesc tools"
echo "  start nc 4444        Quick netcat listener"
echo ""
echo -e "${GREEN}=== Tips ===${NC}"
echo ""
echo "  Tools in ~/.local/bin/ (impacket, nxc, certipy, etc.)"
echo "  Wordlists at /usr/share/seclists"
echo "  Potatoes at ~/.local/share/potatoes"
echo ""
