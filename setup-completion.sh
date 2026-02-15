#!/usr/bin/env bash
#
# setup-completion.sh - Install tab completion for uwu-* tools
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== uwu-ctf Tab Completion Setup ==="
echo ""

# Detect shell
if [[ -n "$ZSH_VERSION" ]]; then
    SHELL_TYPE="zsh"
elif [[ -n "$BASH_VERSION" ]]; then
    SHELL_TYPE="bash"
else
    echo "Unable to detect shell type. Please run with zsh or bash."
    exit 1
fi

echo "Detected shell: $SHELL_TYPE"
echo ""

if [[ "$SHELL_TYPE" == "zsh" ]]; then
    # ZSH completion setup
    COMP_DIR="$HOME/.zsh/completions"
    RC_FILE="$HOME/.zshrc"

    # Create completion directory
    mkdir -p "$COMP_DIR"

    # Copy completion file
    cp "$SCRIPT_DIR/_uwu-completion" "$COMP_DIR/_uwu"

    # Create symlinks for each command
    for cmd in uwu-loot uwu-list uwu-pwned uwu-target uwu-export uwu-navi; do
        ln -sf "$COMP_DIR/_uwu" "$COMP_DIR/_${cmd}"
    done

    echo "✓ Installed zsh completion files to $COMP_DIR"

    # Add to .zshrc if not already present
    if ! grep -q "\.zsh/completions" "$RC_FILE" 2>/dev/null; then
        cat >> "$RC_FILE" << 'ZSHRC'

# uwu-* CTF tools completion
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit
compinit
ZSHRC
        echo "✓ Added completion config to $RC_FILE"
    else
        echo "✓ Completion config already in $RC_FILE"
    fi

    echo ""
    echo "To enable completion in your current shell, run:"
    echo "  source ~/.zshrc"

elif [[ "$SHELL_TYPE" == "bash" ]]; then
    # Bash completion setup
    COMP_DIR="$HOME/.local/share/bash-completion/completions"
    RC_FILE="$HOME/.bashrc"

    # Create completion directory
    mkdir -p "$COMP_DIR"

    # Copy completion file
    cp "$SCRIPT_DIR/uwu-bash-completion" "$COMP_DIR/uwu"
    chmod +x "$COMP_DIR/uwu"

    echo "✓ Installed bash completion to $COMP_DIR/uwu"

    # Check if bash-completion is sourced in .bashrc
    if ! grep -q "bash-completion" "$RC_FILE" 2>/dev/null; then
        cat >> "$RC_FILE" << 'BASHRC'

# Enable bash completion
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
BASHRC
        echo "✓ Added bash-completion to $RC_FILE"
    else
        echo "✓ Bash-completion already configured in $RC_FILE"
    fi

    echo ""
    echo "To enable completion in your current shell, run:"
    echo "  source ~/.bashrc"
fi

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "Test tab completion by typing:"
echo "  uwu-<TAB>"
echo "  uwu-loot -<TAB>"
echo ""
