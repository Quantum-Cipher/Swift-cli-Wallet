# Eternum CLI Wallet

Pure command-line tool for Merkle ledger management in the biological blockchain.

## Usage
```bash
swift run swiftcliwallet <ledger|sign|verify|audit|help>

ledger  Run EternumSentinel script to produce ledger_merkle.json
sign    Sign logs/ledger_merkle.json with keys/ledger.pem → logs/ledger_merkle.sig
verify  Verify logs/ledger_merkle.json against keys/ledger.pub and logs/ledger_merkle.sig
audit   Pretty-print merkle JSON fields and verify signature
help    Show this help
