#!/bin/bash
set -euo pipefail
LOG=~/Automation/logs/cache_sweep.log
DRY_RUN=${DRY_RUN:-1}
notify() { /usr/bin/osascript -e 'display notification "'"$2"'" with title "'"$1"'"'; }
stamp()  { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }

# Only user caches and temp thumbnails; never system caches
TARGETS=(
  "$HOME/Library/Caches/*"
  "$HOME/Library/Containers/*/Data/Library/Caches/*"
  "$HOME/Library/Application Support/Slack/Service Worker/CacheStorage/*"
  "$HOME/Library/Application Support/Code/CachedData/*"
)

freed=0
for t in "${TARGETS[@]}"; do
  for path in $(/bin/ls -d $t 2>/dev/null || true); do
    sz=$(du -sk "$path" 2>/dev/null | awk '{print $1}')
    (( freed += sz ))
    stamp "CLEAN: $path (${sz}K)"
    [[ "$DRY_RUN" == "0" ]] && /bin/rm -rf "$path"
  done
done

mb=$((freed/1024))
notify "Cache sweep" "$mb MB targeted. Set DRY_RUN=0 to apply."
