#!/bin/bash
# install-nuclei.sh - Install and configure Nuclei for shells
# This script is run automatically during shells setup

set -e

echo "===== Installing Nuclei for shells ====="

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed. Please install Go first."
    exit 1
fi

# Get Go bin directory
GOBIN=$(go env GOPATH)/bin
mkdir -p "$GOBIN"

echo "Installing Nuclei from GitHub..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Verify installation
if [ ! -f "$GOBIN/nuclei" ]; then
    echo "ERROR: Nuclei installation failed"
    exit 1
fi

echo "Nuclei installed successfully at: $GOBIN/nuclei"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo "Adding $GOBIN to PATH..."

    # Add to current session
    export PATH=$PATH:$GOBIN

    # Add to shell profile
    if [ -f "$HOME/.bashrc" ]; then
        if ! grep -q "$GOBIN" "$HOME/.bashrc"; then
            echo "export PATH=\$PATH:$GOBIN" >> "$HOME/.bashrc"
            echo "Added to ~/.bashrc"
        fi
    fi

    if [ -f "$HOME/.zshrc" ]; then
        if ! grep -q "$GOBIN" "$HOME/.zshrc"; then
            echo "export PATH=\$PATH:$GOBIN" >> "$HOME/.zshrc"
            echo "Added to ~/.zshrc"
        fi
    fi
fi

# Update Nuclei templates
echo "Updating Nuclei templates..."
"$GOBIN/nuclei" -update-templates -silent

# Create nuclei config directory
NUCLEI_CONFIG_DIR="$HOME/.config/nuclei"
mkdir -p "$NUCLEI_CONFIG_DIR"

# Create minimal config file
cat > "$NUCLEI_CONFIG_DIR/config.yaml" <<EOF
# Nuclei configuration for shells
rate-limit: 150
bulk-size: 25
concurrency: 25
retries: 2
timeout: 900
silent: true
stats: true
EOF

echo "Nuclei config created at: $NUCLEI_CONFIG_DIR/config.yaml"

# Verify installation
echo "Verifying Nuclei installation..."
NUCLEI_VERSION=$("$GOBIN/nuclei" -version 2>&1 | head -1)
echo "Nuclei version: $NUCLEI_VERSION"

# Test basic functionality
echo "Testing Nuclei..."
if "$GOBIN/nuclei" -u https://scanme.sh -tags dns -silent > /dev/null 2>&1; then
    echo "✓ Nuclei test successful"
else
    echo "⚠ Nuclei test failed, but installation complete"
fi

echo ""
echo "===== Nuclei Installation Complete ====="
echo "Binary location: $GOBIN/nuclei"
echo "Templates location: $HOME/nuclei-templates/"
echo "Config location: $NUCLEI_CONFIG_DIR/config.yaml"
echo ""
echo "To use immediately, run: export PATH=\$PATH:$GOBIN"
echo "Or restart your shell to load from profile"
