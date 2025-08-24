#!/bin/bash
set -euo pipefail
SRC=~/Desktop
ARCH=~/Automation/Queues/Archive/Desktop_$(date +%Y-%m)
LOG=~/Automation/logs/desktop_tidy.log
notify() { /usr/bin/osascript -e 'display notification "'"$2"'" with title "'"$1"'"'; }
stamp()  { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
DRY_RUN=${DRY_RUN:-1}
mkdir -p "$ARCH"
find "$SRC" -maxdepth 1 -type f -mtime +14 -print0 | while IFS= read -r -d '' f; do
  base="$(basename "$f")"
  stamp "ARCHIVE: $base -> $ARCH"
  [[ "$DRY_RUN" == "0" ]] && mv -n "$f" "$ARCH/"
done
notify "Desktop tidy" "Older files archived to $(basename "$ARCH")"
