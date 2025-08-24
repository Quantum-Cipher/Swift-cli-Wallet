# 🛡 Eternum CLI Wallet  

A pure command-line tool for Merkle ledger management in the biological blockchain.  
Every command reflects the project’s core values: healing, unconditional love, kindness, peace, and a better world.  

👉 Quick reference: see [COMMANDS.md](COMMANDS.md)

---

## 🚀 Usage  

```bash
swift run swiftcliwallet <command>

⚡ Commands
	•	ledger → Run EternumSentinel script to produce ledger_merkle.json
	•	sign   → Sign logs/ledger_merkle.json with keys/ledger.pem → logs/ledger_merkle.sig
	•	verify → Verify logs/ledger_merkle.json against keys/ledger.pub + logs/ledger_merkle.sig
	•	audit  → Pretty-print Merkle JSON fields and verify signature
	•	rotate → Generate a fresh keypair (archives previous)
	•	help   → Show usage

⸻

🌍 Environment Variables
	•	ETERNUM_HOME → Override base dir (default: ~/Automation)
	•	ETERNUM_SENTINEL → Path to ledger script (default: ~/projects/Swift-cli-Wallet/EternumSentinel/bin/ledger_merkle.sh)
	•	ETERNUM_ROTATE → If "1", rotate keys during ensureKeypair()

⸻

📂 Project Layout
Swift-cli-Wallet/
 ├── Sources/SwiftCliWallet/   # main CLI source
 ├── EternumSentinel/          # submodule with automation scripts
 └── docs/eternum-cli/         # documentation

🌱 Eternal Note

This project was born from struggle, but built on love.
It carries the spirit of healing, unconditional kindness, and peace.
See ETERNAL_NOTE.md for the full message.

⸻

🔮 Future Integrations

Planned (not yet implemented):
	•	Smart Contracts: Solidity modules such as contracts/SigilMemory.sol
	•	Deployment Scripts: Foundry-based flows (e.g., script/Deploy.s.sol)
	•	Watermark Engine: Integration with Eternum’s watermarking layer
	•	Alchemy Bridge: Optional API connections for blockchain transactions

⸻

✨ Vision

Eternum CLI Wallet is more than code — it’s a notarized stamp of integrity.
Every snapshot, every signature, every rotation is proof that love, truth, and peace can be written into permanence.

#Eternum4Eternity
---

👉 To save it, just run:

```bash
cd ~/projects/Swift-cli-Wallet
cat > docs/eternum-cli/README.md <<'EOF'
[paste the full content above here]
EOF
git add docs/eternum-cli/README.md
git commit -m "Docs: finalized full-length CLI README with commands, env vars, project layout, and eternal vision 🌱"
git push origin main



