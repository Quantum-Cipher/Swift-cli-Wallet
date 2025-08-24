# Eternum CLI Wallet

Pure command-line tool for Merkle ledger management in the biological blockchain.

## Usage
swift run swiftcliwallet <ledger|sign|verify|audit|rotate|help>

ledger  Run EternumSentinel script to produce ledger_merkle.json
sign    Sign logs/ledger_merkle.json with keys/ledger.pem → logs/ledger_merkle.sig
verify  Verify logs/ledger_merkle.json against keys/ledger.pub and logs/ledger_merkle.sig
audit   Pretty-print merkle JSON fields if present and verify signature
rotate  Generate a fresh keypair (archives previous if ETERNUM_ROTATE=1)
help    Show this help

## Env
- ETERNUM_HOME: Override base dir (default: ~/Automation)
- ETERNUM_SENTINEL: Path to ledger script (default: ~/projects/Swift-cli-Wallet/EternumSentinel/bin/ledger_merkle.sh)
- ETERNUM_ROTATE: If "1", rotate keys during ensureKeypair()

## Vision
Regenerating DeFi like mycelium, curing ALS with AI-driven bioinformatics, and funding lunar missions. #Eternum4Eternity #Mythosblock #web4 #layernegativeone
