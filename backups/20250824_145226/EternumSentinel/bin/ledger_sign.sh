#!/bin/bash
set -euo pipefail
MERKLE_JSON=${1:-~/Automation/logs/ledger_merkle.json}
KEY_DIR=~/Automation/keys
OUT_SIG=~/Automation/logs/ledger_merkle.sig
mkdir -p "$KEY_DIR"
# Generate EC key on first use (P-256)
if [[ ! -f "$KEY_DIR/ledger.key" ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/ledger.key"
  openssl ec -in "$KEY_DIR/ledger.key" -pubout -out "$KEY_DIR/ledger.pub"
fi
openssl dgst -sha256 -sign "$KEY_DIR/ledger.key" -out "$OUT_SIG" "$MERKLE_JSON"
echo "$OUT_SIG"
