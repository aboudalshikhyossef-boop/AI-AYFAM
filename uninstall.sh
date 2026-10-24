#!/usr/bin/env bash
# AI AYFAM Clean Uninstaller Script

set -e

echo "=== AI AYFAM Uninstaller ==="

# Stop sentinel / helper if running
pkill -f "engine/sentinel.py" 2>/dev/null || true
pkill -f "engine/privileged/helper.py" 2>/dev/null || true

# Remove desktop entry & binaries if installed system-wide
if [ "$EUID" -eq 0 ]; then
    rm -f /usr/share/applications/ayfam.desktop
    rm -f /usr/share/polkit-1/actions/org.ayfam.helper.policy
    rm -f /usr/bin/ayfam
    rm -f /usr/bin/ayfam-gui
    rm -rf /run/ayfam
    echo "System-wide components removed successfully."
else
    echo "Note: Re-run with sudo to remove system-wide desktop launchers and Polkit policies."
fi

# Remove user local cache and config (optional user prompt)
read -p "Do you want to remove local configuration and database (~/.ayfam)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf ~/.ayfam ~/.config/ayfam
    echo "User configuration and databases removed."
fi

echo "AI AYFAM uninstalled cleanly."
