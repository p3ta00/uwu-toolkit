#!/bin/bash
#
# UwU Toolkit Setup Script
# Installs the toolkit, checks dependencies, and sets up shell integration
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
NC='\033[0m' # No Color

print_status() { echo -e "${CYAN}[*]${NC} $1"; }
print_good() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

echo -e "${PINK}"
echo "  ██╗   ██╗██╗    ██╗██╗   ██╗"
echo "  ██║   ██║██║    ██║██║   ██║"
echo "  ██║   ██║██║ █╗ ██║██║   ██║"
echo "  ██║   ██║██║███╗██║██║   ██║"
echo "  ╚██████╔╝╚███╔███╔╝╚██████╔╝"
echo "   ╚═════╝  ╚══╝╚══╝  ╚═════╝ Toolkit Setup"
echo -e "${NC}"
echo

# ============================================================================
# Dependency Check Functions
# ============================================================================

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Detect package manager
detect_package_manager() {
    if check_command apt-get; then
        echo "apt"
    elif check_command dnf; then
        echo "dnf"
    elif check_command yum; then
        echo "yum"
    elif check_command pacman; then
        echo "pacman"
    elif check_command apk; then
        echo "apk"
    elif check_command brew; then
        echo "brew"
    else
        echo "unknown"
    fi
}

install_package() {
    local pkg="$1"
    local pkg_mgr=$(detect_package_manager)

    print_status "Installing $pkg..."

    case "$pkg_mgr" in
        apt)
            sudo apt-get update -qq && sudo apt-get install -y "$pkg"
            ;;
        dnf)
            sudo dnf install -y "$pkg"
            ;;
        yum)
            sudo yum install -y "$pkg"
            ;;
        pacman)
            sudo pacman -S --noconfirm "$pkg"
            ;;
        apk)
            sudo apk add "$pkg"
            ;;
        brew)
            brew install "$pkg"
            ;;
        *)
            print_error "Unknown package manager. Please install $pkg manually."
            return 1
            ;;
    esac
}

# ============================================================================
# System Dependencies Check
# ============================================================================

echo "=========================================="
echo "       Checking System Dependencies"
echo "=========================================="
echo

MISSING_DEPS=()

# Required system tools
REQUIRED_TOOLS=(
    "python3:python3"
    "pip3:python3-pip"
    "tmux:tmux"
    "git:git"
    "curl:curl"
    "wget:wget"
    "nc:netcat-openbsd"
    "socat:socat"
    "nmap:nmap"
)

# Optional but recommended tools
OPTIONAL_TOOLS=(
    "docker:docker.io"
    "jq:jq"
    "rlwrap:rlwrap"
    "sshpass:sshpass"
)

# Check required tools
print_status "Checking required tools..."
for tool_pair in "${REQUIRED_TOOLS[@]}"; do
    IFS=':' read -r tool package <<< "$tool_pair"
    if check_command "$tool"; then
        print_good "$tool found"
    else
        print_error "$tool not found"
        MISSING_DEPS+=("$package")
    fi
done

echo

# Check optional tools
print_status "Checking optional tools..."
MISSING_OPTIONAL=()
for tool_pair in "${OPTIONAL_TOOLS[@]}"; do
    IFS=':' read -r tool package <<< "$tool_pair"
    if check_command "$tool"; then
        print_good "$tool found"
    else
        print_warning "$tool not found (optional)"
        MISSING_OPTIONAL+=("$package")
    fi
done

echo

# ============================================================================
# Python Dependencies Check
# ============================================================================

echo "=========================================="
echo "       Checking Python Dependencies"
echo "=========================================="
echo

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    print_good "Python $PYTHON_VERSION (>= $REQUIRED_VERSION required)"
else
    print_error "Python $PYTHON_VERSION is too old (>= $REQUIRED_VERSION required)"
    MISSING_DEPS+=("python3")
fi

# Required Python packages
PYTHON_PACKAGES=(
    "prompt_toolkit"
    "rich"
    "requests"
    "pyyaml"
)

# Check Python packages
print_status "Checking Python packages..."
MISSING_PY_PKGS=()

for pkg in "${PYTHON_PACKAGES[@]}"; do
    if python3 -c "import $pkg" 2>/dev/null; then
        print_good "Python: $pkg"
    else
        print_error "Python: $pkg not found"
        MISSING_PY_PKGS+=("$pkg")
    fi
done

echo

# ============================================================================
# Install Missing Dependencies
# ============================================================================

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "=========================================="
    echo "       Installing Missing Dependencies"
    echo "=========================================="
    echo

    print_warning "Missing required packages: ${MISSING_DEPS[*]}"
    echo

    # Check if we can use sudo or if we're root
    if [ "$EUID" -eq 0 ]; then
        CAN_INSTALL=true
    elif check_command sudo; then
        CAN_INSTALL=true
    else
        CAN_INSTALL=false
    fi

    if [ "$CAN_INSTALL" = true ]; then
        read -p "Install missing packages? [Y/n] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
            for pkg in "${MISSING_DEPS[@]}"; do
                install_package "$pkg" || print_error "Failed to install $pkg"
            done
        fi
    else
        print_error "Cannot install packages without sudo/root access"
        print_status "Please install manually: ${MISSING_DEPS[*]}"
    fi
    echo
fi

# Install missing Python packages
if [ ${#MISSING_PY_PKGS[@]} -gt 0 ]; then
    echo "=========================================="
    echo "     Installing Python Dependencies"
    echo "=========================================="
    echo

    print_warning "Missing Python packages: ${MISSING_PY_PKGS[*]}"
    echo

    read -p "Install missing Python packages? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        # Try pip install
        print_status "Installing via pip..."

        # Check if we should use --user flag
        if [ "$EUID" -ne 0 ] && [ ! -w "$(python3 -c 'import site; print(site.getsitepackages()[0])')" ]; then
            PIP_FLAGS="--user"
        else
            PIP_FLAGS=""
        fi

        for pkg in "${MISSING_PY_PKGS[@]}"; do
            print_status "Installing $pkg..."
            python3 -m pip install $PIP_FLAGS "$pkg" || {
                # Try with --break-system-packages for newer systems
                python3 -m pip install $PIP_FLAGS --break-system-packages "$pkg" 2>/dev/null || {
                    print_error "Failed to install $pkg"
                }
            }
        done
    fi
    echo
fi

# Offer to install optional packages
if [ ${#MISSING_OPTIONAL[@]} -gt 0 ]; then
    echo
    print_status "Optional packages not installed: ${MISSING_OPTIONAL[*]}"
    read -p "Install optional packages? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for pkg in "${MISSING_OPTIONAL[@]}"; do
            install_package "$pkg" || print_warning "Failed to install $pkg (optional)"
        done
    fi
    echo
fi

# ============================================================================
# Tool-Specific Checks
# ============================================================================

echo "=========================================="
echo "       Checking Security Tools"
echo "=========================================="
echo

# Check for common pentesting tools
PENTEST_TOOLS=(
    "nxc:NetExec"
    "crackmapexec:CrackMapExec"
    "evil-winrm:Evil-WinRM"
    "bloodhound-python:BloodHound.py"
    "impacket-smbclient:Impacket"
    "ligolo-proxy:Ligolo-ng"
    "rusthound:RustHound"
)

print_status "Checking pentesting tools..."
for tool_pair in "${PENTEST_TOOLS[@]}"; do
    IFS=':' read -r cmd name <<< "$tool_pair"
    if check_command "$cmd"; then
        print_good "$name ($cmd)"
    else
        print_warning "$name ($cmd) - not found"
    fi
done

echo

# ============================================================================
# Create Directories
# ============================================================================

echo "=========================================="
echo "       Setting Up UwU Toolkit"
echo "=========================================="
echo

print_status "Creating directories..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}/loot"
mkdir -p "${CONFIG_DIR}/sessions"

# Create potatoes directory
POTATOES_DIR="/opt/my-resources/tools/potatoes"
if [ -d "/opt/my-resources" ]; then
    mkdir -p "$POTATOES_DIR" 2>/dev/null || true
    print_status "Potatoes directory: $POTATOES_DIR"
else
    POTATOES_DIR="${HOME}/.local/share/potatoes"
    mkdir -p "$POTATOES_DIR"
    print_status "Potatoes directory: $POTATOES_DIR"
fi

# Create ligolo directory
LIGOLO_DIR="/opt/tools/ligolo-ng"
if [ -d "/opt/tools" ]; then
    mkdir -p "$LIGOLO_DIR" 2>/dev/null || true
else
    LIGOLO_DIR="${HOME}/.local/share/ligolo-ng"
    mkdir -p "$LIGOLO_DIR"
fi

# ============================================================================
# Install UwU Toolkit
# ============================================================================

# Create symlinks
print_status "Creating symlink to ${INSTALL_DIR}/uwu..."
ln -sf "${SCRIPT_DIR}/uwu" "${INSTALL_DIR}/uwu"

print_status "Creating symlink to ${INSTALL_DIR}/uwu-dashboard..."
ln -sf "${SCRIPT_DIR}/uwu_dashboard" "${INSTALL_DIR}/uwu-dashboard"

# Also create symlinks in /opt/tools/bin if it exists (Exegol/Kali)
if [ -d "/opt/tools/bin" ]; then
    print_status "Creating symlinks in /opt/tools/bin (Exegol)..."
    ln -sf "${SCRIPT_DIR}/uwu" "/opt/tools/bin/uwu" 2>/dev/null || sudo ln -sf "${SCRIPT_DIR}/uwu" "/opt/tools/bin/uwu"
    ln -sf "${SCRIPT_DIR}/uwu_dashboard" "/opt/tools/bin/uwu-dashboard" 2>/dev/null || sudo ln -sf "${SCRIPT_DIR}/uwu_dashboard" "/opt/tools/bin/uwu-dashboard"
fi

# Make executable
chmod +x "${SCRIPT_DIR}/uwu"
chmod +x "${SCRIPT_DIR}/uwu.py"
chmod +x "${SCRIPT_DIR}/uwu_dashboard"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    print_warning "${INSTALL_DIR} is not in your PATH"
    print_status "Add the following to your shell rc file:"
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

# Add to PATH if needed
export PATH="${HOME}/.local/bin:${PATH}"

# Load UwU environment variables
uwu-load-vars() {
    if [[ -f "${HOME}/.uwu-toolkit/globals.json" ]]; then
        eval $(uwu export --script 2>/dev/null)
        echo "[+] UwU variables loaded"
    fi
}

# Quick aliases
alias uwu-nc='uwu start nc'
alias uwu-php='uwu start php'
alias uwu-http='uwu start gosh'

# Function to quickly set target
uwu-target() {
    if [[ -n "$1" ]]; then
        uwu setg RHOSTS "$1"
    else
        echo "Usage: uwu-target <ip>"
    fi
}

# Function to start a listener
uwu-listen() {
    local port="${1:-4444}"
    uwu start nc "$port"
}
SHELL_EOF

echo

# ============================================================================
# Download Tools Prompt
# ============================================================================

echo "=========================================="
echo "       Optional Downloads"
echo "=========================================="
echo

# Check if potatoes exist
if [ -z "$(ls -A "$POTATOES_DIR" 2>/dev/null)" ]; then
    print_status "Potato exploits not found"
    read -p "Download potato exploits (GodPotato, PrintSpoofer, etc.)? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        if [ -f "${SCRIPT_DIR}/scripts/download-potatoes.py" ]; then
            python3 "${SCRIPT_DIR}/scripts/download-potatoes.py" -o "$POTATOES_DIR"
        else
            print_warning "Download script not found. Run 'potatoes download' from within UwU."
        fi
    fi
else
    print_good "Potato exploits found in $POTATOES_DIR"
fi

echo

# Check if ligolo agents exist
if [ -z "$(ls -A "$LIGOLO_DIR" 2>/dev/null)" ]; then
    print_status "Ligolo agents not found"
    read -p "Download ligolo-ng agents? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        print_status "Run 'ligolo download' from within UwU to download agents"
    fi
else
    print_good "Ligolo agents found in $LIGOLO_DIR"
fi

echo

# ============================================================================
# Verify Installation
# ============================================================================

echo "=========================================="
echo "       Verifying Installation"
echo "=========================================="
echo

print_status "Running verification..."
if "${INSTALL_DIR}/uwu" help > /dev/null 2>&1; then
    print_good "Installation successful!"
else
    # Try with full python path
    if python3 "${SCRIPT_DIR}/uwu.py" help > /dev/null 2>&1; then
        print_good "Installation successful (use: python3 ${SCRIPT_DIR}/uwu.py)"
    else
        print_error "Installation may have issues"
        print_status "Try running: python3 ${SCRIPT_DIR}/uwu.py"
    fi
fi

echo
print_status "Shell integration script created at:"
echo "    ${CONFIG_DIR}/shell-integration.sh"
echo
print_status "To enable shell integration, add to your rc file:"
echo
echo "    source ${CONFIG_DIR}/shell-integration.sh"
echo

# ============================================================================
# Summary
# ============================================================================

echo "=========================================="
echo "           Setup Complete!"
echo "=========================================="
echo
echo -e "${GREEN}=== Quick Start ===${NC}"
echo ""
echo "1. Start the toolkit:    uwu"
echo "2. Search for modules:   search smb"
echo "3. Use a module:         use auxiliary/smb/smb_enum"
echo "4. Set target:           set RHOSTS 10.10.10.10"
echo "5. Run module:           run"
echo ""
echo -e "${GREEN}=== Key Commands ===${NC}"
echo ""
echo "- setg RHOSTS <ip>     Set global target"
echo "- sessions             View active sessions"
echo "- ligolo               Enter ligolo pivoting mode"
echo "- potatoes download    Download privilege escalation tools"
echo "- start nc 4444        Quick netcat listener"
echo ""
echo -e "${GREEN}=== Tips ===${NC}"
echo ""
echo "- Use 'setg' to set global variables that persist"
echo "- Use 'history RHOSTS' to see previous targets"
echo "- Use Tab for autocompletion"
echo "- Type 'help' for full command list"
echo ""
