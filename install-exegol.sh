#!/bin/bash
#
# UwU Toolkit - Exegol Install Script
# Non-interactive installer for Exegol containers
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/bin"
OPT_BIN="/opt/tools/bin"
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
echo "   ╚═════╝  ╚══╝╚══╝  ╚═════╝  Exegol Install"
echo -e "${NC}"
echo

# ============================================================================
# Environment Guard
# ============================================================================

if [ ! -e "/.exegol" ] && [ ! -e "/opt/.exegol_aliases" ]; then
    print_error "This script is for Exegol containers only."
    print_status "For Kali/Debian, run: ${CYAN}./install-kali.sh${NC}"
    exit 1
fi

print_good "Exegol environment detected"
echo

# ============================================================================
# Python Dependencies
# ============================================================================

print_status "Checking Python packages..."

PY_PACKAGES=(
    "prompt_toolkit:prompt_toolkit"
    "rich:rich"
    "requests:requests"
    "yaml:pyyaml"
    "fastmcp:fastmcp"
    "donut:donut-shellcode"
)

MISSING_PY=()
for pair in "${PY_PACKAGES[@]}"; do
    IFS=':' read -r import_name pip_name <<< "$pair"
    if python3 -c "import $import_name" 2>/dev/null; then
        print_good "Python: $import_name"
    else
        print_warning "Python: $import_name not found"
        MISSING_PY+=("$pip_name")
    fi
done

if [ ${#MISSING_PY[@]} -gt 0 ]; then
    print_status "Installing: ${MISSING_PY[*]}"
    pip3 install --break-system-packages "${MISSING_PY[@]}" || {
        print_error "pip install failed"
        exit 1
    }
    print_good "Python packages installed"
fi

echo

# ============================================================================
# Directory Structure
# ============================================================================

print_status "Creating directories..."
mkdir -p "${CONFIG_DIR}/loot"
mkdir -p "${CONFIG_DIR}/sessions"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${OPT_BIN}" 2>/dev/null || true

# Potatoes directory (Exegol path)
POTATOES_DIR="/opt/my-resources/tools/potatoes"
mkdir -p "$POTATOES_DIR" 2>/dev/null || true

print_good "Directories ready"
echo

# ============================================================================
# Symlinks
# ============================================================================

print_status "Creating symlinks..."

# Helper scripts to symlink
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

    # Symlink in /opt/tools/bin/ (primary for Exegol)
    if [ -d "$OPT_BIN" ]; then
        ln -sf "$src_path" "${OPT_BIN}/${link_name}" 2>/dev/null || true
    fi

    # Also symlink in ~/.local/bin/ as backup
    ln -sf "$src_path" "${INSTALL_DIR}/${link_name}"
done

print_good "Symlinks created in ${OPT_BIN} and ${INSTALL_DIR}"
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

print_status "Verifying installation..."
if uwu help > /dev/null 2>&1; then
    print_good "Installation successful!"
elif "${INSTALL_DIR}/uwu" help > /dev/null 2>&1; then
    print_good "Installation successful (via ~/.local/bin/uwu)"
elif python3 "${SCRIPT_DIR}/uwu.py" help > /dev/null 2>&1; then
    print_good "Installation successful (via python3 uwu.py)"
else
    print_error "Verification failed — try: python3 ${SCRIPT_DIR}/uwu.py"
fi

echo
echo -e "${GREEN}=== Quick Start ===${NC}"
echo ""
echo "  Start:    uwu"
echo "  Search:   search smb"
echo "  Module:   use auxiliary/ad/kerberoast"
echo "  Target:   set RHOSTS 10.10.10.10"
echo "  Run:      run"
echo ""
