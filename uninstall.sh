#!/bin/bash

set -e

# Define paths
SHELL_BIN="/usr/local/bin/shell"
SHELL_DIR="/opt/shell"
SHELL_CONFIG="/etc/shell"
SHELL_LOG="/var/log/shell"
SHELL_STATE="/var/lib/shell"
SHELL_RUN="/var/run/shell"
SHELL_SYSTEMD="/etc/systemd/system"
SHELL_USER="shell"
SHELL_GROUP="shell"
SUDOERS_FILE="/etc/sudoers.d/shell"

# macOS paths
if [[ "$(uname)" == "Darwin" ]]; then
  SHELL_CONFIG="$HOME/Library/Application Support/shell/config"
  SHELL_LOG="$HOME/Library/Logs/shell"
  SHELL_STATE="$HOME/Library/Application Support/shell/secrets"
fi

echo "🛑 Note: Shell is a standalone CLI tool without systemd services"

echo "🧹 Removing shell binary..."
if [[ -f "${SHELL_BIN}" ]]; then
    sudo rm -f "${SHELL_BIN}"
    echo "✓ Removed ${SHELL_BIN}"
fi

echo "🗑️ Removing configuration and log directories..."
# Remove directories if they exist
if [[ -d "${SHELL_CONFIG}" ]]; then
    sudo rm -rf "${SHELL_CONFIG}"
    echo "✓ Removed ${SHELL_CONFIG}"
fi

if [[ -d "${SHELL_LOG}" ]]; then
    sudo rm -rf "${SHELL_LOG}"
    echo "✓ Removed ${SHELL_LOG}"
fi

if [[ -d "${SHELL_STATE}" ]]; then
    sudo rm -rf "${SHELL_STATE}"
    echo "✓ Removed ${SHELL_STATE}"
fi

if [[ -d "${SHELL_DIR}" ]]; then
    sudo rm -rf "${SHELL_DIR}"
    echo "✓ Removed ${SHELL_DIR}"
fi

# Remove user and group if they exist (Linux only)
if [[ "$(uname)" == "Linux" ]]; then
    echo "👤 Removing shell user and group..."
    if id "${SHELL_USER}" &>/dev/null; then
        sudo userdel "${SHELL_USER}" || true
        echo "✓ Removed user ${SHELL_USER}"
    fi
    if getent group "${SHELL_GROUP}" &>/dev/null; then
        sudo groupdel "${SHELL_GROUP}" || true
        echo "✓ Removed group ${SHELL_GROUP}"
    fi
    if [[ -f "${SUDOERS_FILE}" ]]; then
        sudo rm -f "${SUDOERS_FILE}"
        echo "✓ Removed sudoers file"
    fi
fi

echo " Shell has been completely removed from the system."