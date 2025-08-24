# Apple Automation Ledger

Bash-native macOS automations (Automator + LaunchAgents) with a cryptographic audit trail (Merkle roots) and optional blockchain anchoring.

## Install
- make install
- make enable

## Uninstall
- make disable
- make uninstall

## Ledger
- make anchor       # compute Merkle root over logs and write proof
- make ots-stamp    # optional: OpenTimestamps anchor (requires client)
