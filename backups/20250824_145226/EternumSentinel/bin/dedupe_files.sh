#!/bin/bash
set -euo pipefail
LOG=~/Automation/logs/dedupe_files.log
DUP_DIR=~/Automation/Queues/Duplicates
mkdir -p "$DUP_DIR"
touch "$DUP_DIR/.seen_md5"
stamp(){ echo "$(date '+%F %T') $*" | tee -a "$LOG"; }
notify(){ osascript -e 'display notification "'"$2"'" with title "'"$1"'"'; }
find ~/Automation/Targets -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  [[ ! -e "$f" ]] && continue
  h=$(md5 -q "$f" 2>/dev/null || true)
  [[ -z "$h" ]] && continue
  if grep -q "^$h$" "$DUP_DIR/.seen_md5"; then
    stamp "Duplicate: $(basename "$f") → $DUP_DIR"
    mv -n "$f" "$DUP_DIR/"
    notify "Duplicate Removed" "$(basename "$f") moved to Duplicates"
  else
    echo "$h" >> "$DUP_DIR/.seen_md5"
  fi
done
