#!/bin/bash
set -euo pipefail
JSON=${1:-~/Automation/logs/ledger_merkle.json}
OTS=~/Automation/logs/ledger_merkle.json.ots
if ! command -v ots >/dev/null 2>&1 && ! command -v ots-cli >/dev/null 2>&1; then
  echo "Install OpenTimestamps client (brew install opentimestamps-client)"; exit 1
fi
( command -v ots >/dev/null 2>&1 && ots stamp "$JSON" ) || ots-cli stamp "$JSON"
echo "$OTS (proof will complete after confirmation; use 'ots verify')"
