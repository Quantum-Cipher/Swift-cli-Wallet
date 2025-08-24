SHELL := /bin/bash
install:
./install.sh
enable:
launchctl unload ~/Library/LaunchAgents/com.user.signal-scan.plist 2>/dev/null || true
launchctl load  ~/Library/LaunchAgents/com.user.signal-scan.plist
disable:
launchctl unload ~/Library/LaunchAgents/com.user.signal-scan.plist 2>/dev/null || true
uninstall: disable
rm -f ~/Automation/bin/dedupe_files.sh ~/Automation/bin/merge_similar.sh ~/Automation/bin/organize_files.sh ~/Automation/bin/notify_signals.sh
anchor:
@root_json=

(~/Projects/apple-automation-ledger/bin/ledger_merkle.sh); \
echo "Merkle JSON: 

root_json"; \
sig=

(~/Projects/apple-automation-ledger/bin/ledger_sign.sh "

root_json"); \
echo "Signature: $$sig"
ots-stamp:
~/Projects/apple-automation-ledger/bin/ledger_merkle.sh >/dev/null; \
~/Projects/apple-automation-ledger/bin/ledger_anchor_ots.sh
clean-logs:
rm -f ~/Automation/logs/*.log
