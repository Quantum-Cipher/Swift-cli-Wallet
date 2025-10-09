🛡 Eternum CLI Wallet

A lightweight command-line tool for Merkle ledger management and cryptographic verification in the Eternum ecosystem.

Quick Reference: see COMMANDS.md

🚀 Usage
swift run swiftcliwallet <command>

⚡ Commands
Command
Description
ledger
Run the EternumSentinel script to produce ledger_merkle.json.
sign
Sign logs/ledger_merkle.json with keys/ledger.pem, output logs/ledger_merkle.sig.
verify
Verify logs/ledger_merkle.json against keys/ledger.pub + logs/ledger_merkle.sig.
audit
Pretty-print Merkle JSON fields and verify signature integrity.
rotate
Generate a fresh keypair and archive the previous one.
help
Show usage information.

🌍 Environment Variables
Variable
Description
Default
ETERNUM_HOME
Override base directory.
~/Automation
ETERNUM_SENTINEL
Path to ledger script.
~/projects/Swift-cli-Wallet/EternumSentinel/bin/ledger_merkle.sh
ETERNUM_ROTATE
Rotate keys during ensureKeypair() if set to "1".

📂 Project Layout
Swift-cli-Wallet/
 ├── Sources/SwiftCliWallet/   # Main CLI source
 ├── EternumSentinel/          # Submodule with automation scripts
 └── docs/eternum-cli/         # Documentation

🔮 Planned Integrations
	•	Smart Contracts: Solidity modules such as contracts/SigilMemory.sol
	•	Deployment Scripts: Foundry-based flows (e.g., script/Deploy.s.sol)
	•	Watermark Engine: Integration with Eternum’s watermark verification layer
	•	Alchemy Bridge: Optional API connections for blockchain transactions

✨ Overview

Eternum CLI Wallet provides a secure, modular framework for:
	•	Ledger management and signing
	•	Key rotation and integrity verification
	•	Merkle tree generation and auditing

It is designed for reliability, transparency, and compatibility with future Eternum protocol layers.


