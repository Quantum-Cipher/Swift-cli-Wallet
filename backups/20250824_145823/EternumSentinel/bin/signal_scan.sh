#!/bin/bash
set -euo pipefail
LOG=~/Automation/logs/signal_scan.log
notify() { /usr/bin/osascript -e 'display notification "'"$2"'" with title "'"$1"'"'; }
stamp()  { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }

window="${1:-1h}" # e.g., 1h, 24h

report=""
add() { report+="$1\n"; stamp "$1"; }

# 1) New or changed LaunchAgents/Daemons
for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  [[ -d "$dir" ]] || continue
  recent=$(find "$dir" -type f -mmin -$(( ${window%h} * 60 )) 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$recent" != "0" ]]; then
    add "Launch items changed in $(basename "$dir"): $recent"
  fi
done

# 2) New apps installed
apps=$(find /Applications "$HOME/Applications" -name "*.app" -type d -mmin -$(( ${window%h} * 60 )) 2>/dev/null | head -n 10)
[[ -n "$apps" ]] && add "New apps within ${window}:\n$apps"

# 3) Unsigned executables in Downloads
mapfile -t unsigned < <(find ~/Downloads -type f  -perm -111 -o -name "*.app" -o -name "*.pkg" -o -name "*.dmg"  -mmin -$(( ${window%h} * 60 )) -print0 2>/dev/null \
  | xargs -0 -I{} sh -c '/usr/bin/codesign -dv --verbose=2 "{}" >/dev/null 2>&1 || echo "{}"' | head -n 10)
if (( ${#unsigned[@]} )); then
  add "Unsigned items in Downloads:\n$(printf '%s\n' "${unsigned[@]}")"
fi

# 4) Quarantined files awaiting review
qcount=$(find ~/Automation/Queues/Quarantine -type f 2>/dev/null | wc -l | tr -d ' ')
[[ "$qcount" != "0" ]] && add "Quarantine queue: $qcount files"

# 5) System log error pulse
errs=$(log show --last "$window" --predicate 'eventMessage CONTAINS[c] "error" OR subsystem CONTAINS[c] "launchd"' --info --debug --style compact 2>/dev/null | wc -l | tr -d ' ')
if [[ "$errs" -gt 200 ]]; then
  add "High error chatter in logs: $errs lines in $window"
fi

# 6) Disk space
usage=$(df -H / | awk 'NR==2{print $5}' | tr -d '%')
if [[ "$usage" -gt 85 ]]; then
  add "Disk usage high: ${usage}%"
fi

# Notify if any signals
if [[ -n "$report" ]]; then
  notify "Signals detected" "$(echo -e "$report" | sed -E 's/.{200}$/.../')"
else
  stamp "No significant signals in $window."
fi
