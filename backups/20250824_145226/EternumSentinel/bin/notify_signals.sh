#!/bin/bash
set -euo pipefail
LOG=~/Automation/logs/notify_signals.log
stamp(){ echo "$(date '+%F %T') $*" | tee -a "$LOG"; }
notify(){ osascript -e 'display notification "'"$2"'" with title "'"$1"'"'; }
qcount=$(find ~/Automation/Queues/Quarantine -type f 2>/dev/null | wc -l | tr -d ' ')
if [[ "$qcount" -gt 0 ]]; then
  notify "Quarantine Alert" "$qcount files need review"
  stamp "Quarantine queue: $qcount files"
fi
mapfile -t unsigned < <(find ~/Automation/Targets -name "*.app" -type d -print0 \
  | xargs -0 -I{} sh -c 'codesign -dv "{}" >/dev/null 2>&1 || echo "{}"')
if (( ${#unsigned[@]} )); then
  notify "Unsigned Apps" "${#unsigned[@]} items flagged"
  stamp "Unsigned apps:"; for app in "${unsigned[@]}"; do stamp "  $app"; done
fi
