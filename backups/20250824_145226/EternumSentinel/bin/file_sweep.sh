#!/bin/bash
set -euo pipefail
LOG=~/Automation/logs/file_sweep.log
REVIEW=~/Automation/Queues/Review
QUAR=~/Automation/Queues/Quarantine
ARCH=~/Automation/Queues/Archive
DUPS=~/Automation/Queues/Duplicates

notify() { /usr/bin/osascript -e 'display notification "'"$2"'" with title "'"$1"'"'; }
stamp()  { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }

# DRY_RUN=1 logs only; set to 0 to enact moves
DRY_RUN=${DRY_RUN:-1}

dest_for() {
  local f="$1" kind
  kind="$(/usr/bin/mdls -name kMDItemKind -raw "$f" 2>/dev/null || echo '')"
  case "$kind" in
    *"Application"*)           echo "$REVIEW";;
    *"Installer package"*|*"Disk Image"*) echo "$REVIEW";;
    *"Image"*)                 echo ~/Pictures;;
    *"Movie"*)                 echo ~/Movies;;
    *"Audio"*|*"Music"*)       echo ~/Music;;
    *"PDF"*)                   echo ~/Documents;;
    *"Spreadsheet"*|*"Presentation"*|*"Document"*) echo ~/Documents;;
    *)                         echo "$ARCH";;
  esac
}

is_quarantined() { /usr/bin/xattr -p com.apple.quarantine "$1" >/dev/null 2>&1; }
is_signed() { /usr/bin/codesign -dv --verbose=2 "$1" >/dev/null 2>&1; }
hash_md5() { /sbin/md5 -q "$1" 2>/dev/null || /usr/bin/md5 -q "$1" 2>/dev/null; }

dedupe_if_needed() {
  local f="$1" base="$2"
  local h="$(hash_md5 "$f" 2>/dev/null || true)"
  [[ -z "$h" ]] && return 0
  local seen="$DUPS/.seen_md5"
  mkdir -p "$DUPS"; touch "$seen"
  if grep -q "^$h$" "$seen"; then
    stamp "DUPLICATE: $base ($h) -> $DUPS"
    [[ "$DRY_RUN" == "0" ]] && /bin/mv -n "$f" "$DUPS/"
    notify "Duplicate parked" "$base moved to Duplicates"
    return 1
  else
    echo "$h" >> "$seen"
    return 0
  fi
}

process_one() {
  local f="$1"
  [[ ! -e "$f" ]] && return 0
  local base="$(/usr/bin/basename "$f")"
  stamp "PROCESS: $f"

  # Quarantine handling
  if is_quarantined "$f"; then
    stamp "QUARANTINE: $base -> $QUAR"
    [[ "$DRY_RUN" == "0" ]] && /bin/mv -n "$f" "$QUAR/"
    notify "Quarantined" "$base set aside for review"
    return 0
  fi

  # Suspicious installers/apps
  if [[ "$f" == *.app ]] || [[ "$f" == *.pkg ]] || [[ "$f" == *.dmg ]]; then
    if ! is_signed "$f"; then
      stamp "UNSIGNED: $base -> $REVIEW"
      [[ "$DRY_RUN" == "0" ]] && /bin/mv -n "$f" "$REVIEW/"
      notify "Unsigned item" "$base moved to Review"
      return 0
    fi
  fi

  # Dedupe check
  if ! dedupe_if_needed "$f" "$base"; then
    return 0
  fi

  # Route by kind
  local dest
  dest="$(dest_for "$f")"
  mkdir -p "$dest"
  stamp "ROUTE: $base -> $dest"
  [[ "$DRY_RUN" == "0" ]] && /bin/mv -n "$f" "$dest/"
}

# Accepts file paths on stdin or as args
if [[ "$#" -gt 0 ]]; then
  for p in "$@"; do process_one "$p"; done
else
  while IFS= read -r line; do [[ -n "$line" ]] && process_one "$line"; done
fi
