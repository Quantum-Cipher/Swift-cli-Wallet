#!/bin/bash
mkdir -p "$HOME/Automation/logs"
cat > "$HOME/Automation/logs/ledger_merkle.json" <<JSON
{
  "merkle_root": "abc123def4567890",
  "algo": "SHA256",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)"
}
JSON
echo "Generated ledger_merkle.json"
exit 0
