#!/bin/bash
set -euo pipefail
BASE=~/Automation/Organized
mkdir -p "$BASE"
LOG=~/Automation/logs/organize_files.log
stamp(){ echo "$(date '+%F %T') $*" | tee -a "$LOG"; }
route(){
  local f="$1" label="Misc"
  local kind; kind=$(mdls -name kMDItemKind -raw "$f" 2>/dev/null || echo "")
  case "$kind" in
    *Image*) label="Images" ;;
    *PDF*) label="PDFs" ;;
    *Spreadsheet*) label="Spreadsheets" ;;
    *Presentation*) label="Slides" ;;
    *Text*) label="Text" ;;
    *Audio*|*Music*) label="Audio" ;;
    *Movie*) label="Videos" ;;
    *Code*|*Source*) label="Code" ;;
    *Document*) label="Docs" ;;
  esac
  mkdir -p "$BASE/$label"
  mv -n "$f" "$BASE/$label/"
  stamp "Moved: $(basename "$f") → $label"
}
find ~/Automation/Targets -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  route "$f"
done
