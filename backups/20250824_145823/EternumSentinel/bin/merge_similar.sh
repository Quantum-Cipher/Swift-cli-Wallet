#!/bin/bash
set -euo pipefail
MERGE_DIR=~/Automation/Queues/Merged
mkdir -p "$MERGE_DIR"
LOG=~/Automation/logs/merge_similar.log
stamp(){ echo "$(date '+%F %T') $*" | tee -a "$LOG"; }
mapfile -d '' -t files < <(find ~/Automation/Targets -type f -name "*.txt" -print0 2>/dev/null)
for ((i=0; i<${#files[@]}; i++)); do
  for ((j=i+1; j<${#files[@]}; j++)); do
    f1="${files[i]}"; f2="${files[j]}"
    if diff -q "$f1" "$f2" >/dev/null 2>&1; then
      out="$MERGE_DIR/$(basename "$f1" .txt)_merged.txt"
      stamp "Merging: $f1 + $f2 -> $out"
      cat "$f1" "$f2" > "$out"
      rm -f "$f1" "$f2"
    fi
  done
done
