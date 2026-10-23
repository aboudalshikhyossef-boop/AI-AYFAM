#!/usr/bin/env bash
# AI AYFAM Idempotent Setup Script for Linux Mint
set -e

echo "=== AI AYFAM Setup & Initialization ==="

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required." >&2
    exit 1
fi

# Ensure virtual environment or local dependencies
echo "Installing Python dependencies from requirements.txt..."
python3 -m pip install -r requirements.txt --quiet

# Install Polkit policy if root
POLKIT_DIR="/usr/share/polkit-1/actions"
if [ "$EUID" -eq 0 ] && [ -d "$POLKIT_DIR" ]; then
    echo "Installing Polkit helper policy..."
    cp resources/../engine/privileged/org.ayfam.helper.policy "$POLKIT_DIR/org.ayfam.helper.policy" 2>/dev/null || cp privileged/org.ayfam.helper.policy "$POLKIT_DIR/org.ayfam.helper.policy" 2>/dev/null || true
    chmod 0644 "$POLKIT_DIR/org.ayfam.helper.policy"
fi

# Create run and log directories
mkdir -p ~/.ayfam ~/.config/ayfam

echo "AI AYFAM setup completed successfully."
