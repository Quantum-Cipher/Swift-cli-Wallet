#!/bin/bash
set -e
dirs=(~/Automation/bin ~/Automation/logs ~/Automation/Queues/Review ~/Automation/Queues/Quarantine ~/Automation/Queues/Archive ~/Automation/Queues/Duplicates ~/Automation/Queues/Merged ~/Automation/Targets ~/Automation/Organized ~/Automation/keys)
echo "🔍 EternumSentinel Path Audit"
for d in "${dirs[@]}"; do
  if [ -d "$d" ]; then
    echo "✅ $d"
  else
    echo "❌ MISSING: $d"
  fi
done
