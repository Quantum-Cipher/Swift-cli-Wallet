#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p ~/Automation/{bin,logs,Queues/{Review,Quarantine,Archive,Duplicates},Targets,Organized,keys}
ln -sf "$ROOT/bin"/* ~/Automation/bin/
# Optional: copy launchd plists into place
mkdir -p ~/Library/LaunchAgents
cp -f "$ROOT/launchd/"*.plist ~/Library/LaunchAgents/ 2>/dev/null || true
echo "Installed symlinks into ~/Automation and plists into ~/Library/LaunchAgents"
