import SwiftUI
import Foundation
import CryptoKit

// MARK: - Config
enum Config {
    static var homeDir: URL {
        if let env = ProcessInfo.processInfo.environment["ETERNUM_HOME"], !env.isEmpty {
            return URL(fileURLWithPath: (env as NSString).expandingTildeInPath, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Automation", isDirectory: true)
    }

    static var logsDir: URL { homeDir.appendingPathComponent("logs", isDirectory: true) }
    static var keysDir: URL { homeDir.appendingPathComponent("keys", isDirectory: true) }

    static var merkleJSON: URL { logsDir.appendingPathComponent("ledger_merkle.json") }
    static var signature: URL  { logsDir.appendingPathComponent("ledger_merkle.sig") }
    static var publicKey: URL  { keysDir.appendingPathComponent("ledger.pub") }
    static var privateKey: URL { keysDir.appendingPathComponent("ledger.pem") }

    /// Path to the sentinel ledger script; override with $ETERNUM_SENTINEL.
    static var sentinelScript: String {
        if let env = ProcessInfo.processInfo.environment["ETERNUM_SENTINEL"], !env.isEmpty {
            return (env as NSString).expandingTildeInPath
        }
        // default to a common submodule layout inside this repo
        let fallback = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("projects/Swift-cli-Wallet/EternumSentinel/bin/ledger_merkle.sh").path
        return fallback
    }
}

// MARK: - Errors
enum MerkleVerificationError: Error {
    case missingFiles(String)
    case invalidPEM
    case signatureMismatch
}

enum SignerError: Error {
    case missingFile(String)
    case invalidPEM
    case keyParseFailed
}

// MARK: - Verifier
struct MerkleVerifier {
    static func verify() async throws -> Bool {
        do {
            let jsonData = try Data(contentsOf: Config.merkleJSON)
            let sigData  = try Data(contentsOf: Config.signature)
            let pubPem   = try String(contentsOf: Config.publicKey)

            guard pubPem.contains("BEGIN PUBLIC KEY") && pubPem.contains("END PUBLIC KEY") else {
                throw MerkleVerificationError.invalidPEM
            }

            let keyBase64 = pubPem
                .split(separator: "\n")
                .filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                .map(String.init)
                .joined()

            guard let keyDER = Data(base64Encoded: keyBase64) else {
                throw MerkleVerificationError.invalidPEM
            }

            let pubKey    = try P256.Signing.PublicKey(derRepresentation: keyDER)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: sigData)

            guard pubKey.isValidSignature(signature, for: jsonData) else {
                throw MerkleVerificationError.signatureMismatch
            }
            return true
        } catch let e as MerkleVerificationError {
            throw e
        } catch {
            throw MerkleVerificationError.missingFiles(error.localizedDescription)
        }
    }
}

// MARK: - Signer
struct MerkleSigner {
    /// Generate keys if missing (PEM PKCS#8 private, SPKI public)
    static func ensureKeypair() throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: Config.privateKey.path),
           fm.fileExists(atPath: Config.publicKey.path) {
            return
        }

        let priv = P256.Signing.PrivateKey()
        let pub  = priv.publicKey

        let privDER = priv.derRepresentation
        let privB64 = privDER.base64EncodedString(options: [.lineLength64Characters])
        let privPEM = """
        -----BEGIN PRIVATE KEY-----
        \(privB64)
        -----END PRIVATE KEY-----
        """
        try fm.createDirectory(at: Config.keysDir, withIntermediateDirectories: true)
        try privPEM.write(to: Config.privateKey, atomically: true, encoding: .utf8)

        let pubDER = pub.derRepresentation
        let pubB64 = pubDER.base64EncodedString(options: [.lineLength64Characters])
        let pubPEM = """
        -----BEGIN PUBLIC KEY-----
        \(pubB64)
        -----END PUBLIC KEY-----
        """
        try pubPEM.write(to: Config.publicKey, atomically: true, encoding: .utf8)
        print("🔑 Generated keypair in \(Config.keysDir.path)")
    }

    static func signLedger() throws {
        try ensureKeypair()

        guard FileManager.default.fileExists(atPath: Config.merkleJSON.path) else {
            throw SignerError.missingFile(Config.merkleJSON.path)
        }
        let jsonData = try Data(contentsOf: Config.merkleJSON)

        let pemString = try String(contentsOf: Config.privateKey)
        guard pemString.contains("BEGIN PRIVATE KEY") && pemString.contains("END PRIVATE KEY") else {
            throw SignerError.invalidPEM
        }
        let keyBase64 = pemString
            .split(separator: "\n")
            .filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .map(String.init)
            .joined()
        guard let keyDER = Data(base64Encoded: keyBase64) else {
            throw SignerError.invalidPEM
        }

        let privKey: P256.Signing.PrivateKey
        do {
            privKey = try P256.Signing.PrivateKey(derRepresentation: keyDER)
        } catch {
            throw SignerError.keyParseFailed
        }

        let sig = try privKey.signature(for: jsonData)
        try sig.derRepresentation.write(to: Config.signature)
        print("✅ Wrote signature → \(Config.signature.path)")
    }
}

// MARK: - View
struct MerkleDashboard: View {
    @State private var merkle: MerkleRoot?
    @State private var signatureValid: Bool?
    @State private var errorMessage: String?
    @State private var isLoading = false
    @State private var lastRunOutput: String?

    var body: some View {
        VStack(spacing: 16) {
            Text("🛡 EternumSentinel Audit").font(.title2).bold()

            if let m = merkle {
                VStack(spacing: 6) {
                    Text("Merkle Root:").font(.subheadline).foregroundColor(.secondary)
                    Text(m.merkle_root)
                        .font(.footnote)
                        .textSelection(.enabled)
                        .multilineTextAlignment(.center)
                        .lineLimit(3).minimumScaleFactor(0.7)

                    HStack {
                        Text("Timestamp: \(m.timestamp)")
                        Spacer()
                        Text("Host: \(m.host)")
                    }
                    .font(.caption).foregroundColor(.secondary)
                }
                .padding(.vertical, 6)
            } else {
                Text("No Merkle root found.").foregroundColor(.secondary)
            }

            Group {
                if let valid = signatureValid {
                    Text(valid ? "✅ Signature Verified" : "❌ Signature Invalid")
                        .foregroundColor(valid ? .green : .red).bold()
                } else {
                    Text("🔍 Signature status unknown").foregroundColor(.secondary)
                }
            }

            if let msg = errorMessage {
                Text(msg)
                    .font(.caption)
                    .foregroundColor(.orange)
                    .multilineTextAlignment(.center)
            }

            if let out = lastRunOutput, !out.isEmpty {
                ScrollView {
                    Text(out).font(.caption2).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(.black.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                .frame(minHeight: 80, maxHeight: 140)
            }

            HStack(spacing: 12) {
                Button("Refresh") { Task { await refresh() } }.disabled(isLoading)
                Button("Run Ledger") { Task { await runLedger() } }.disabled(isLoading)
                Button("Sign Ledger") { Task { await signLedger() } }.disabled(isLoading)
            }
            .padding(.top, 8)

            if isLoading { ProgressView().padding(.top, 4) }
        }
        .padding(20)
        .frame(minWidth: 560, minHeight: 340)
        .task { await initialLoad() }
    }

    // MARK: - Actions
    func initialLoad() async {
        await MainActor.run { isLoading = true; errorMessage = nil; signatureValid = nil }
        do {
            try await loadMerkle()
            let ok = try await MerkleVerifier.verify()
            await MainActor.run { signatureValid = ok }
        } catch {
            await MainActor.run { signatureValid = false; errorMessage = error.localizedDescription }
        }
        await MainActor.run { isLoading = false }
    }

    func loadMerkle() async throws {
        do {
            let data = try Data(contentsOf: Config.merkleJSON)
            let decoded = try JSONDecoder().decode(MerkleRoot.self, from: data)
            await MainActor.run { merkle = decoded; errorMessage = nil }
        } catch {
            await MainActor.run { merkle = nil; signatureValid = nil; errorMessage = "Could not load Merkle JSON: \(error.localizedDescription)" }
            throw error
        }
    }

    func refresh() async {
        await MainActor.run { isLoading = true; errorMessage = nil; lastRunOutput = nil }
        do {
            try await loadMerkle()
            let ok = try await MerkleVerifier.verify()
            await MainActor.run { signatureValid = ok }
        } catch {
            await MainActor.run { signatureValid = false; errorMessage = error.localizedDescription }
        }
        await MainActor.run { isLoading = false }
    }

    func runLedger() async {
        await MainActor.run { isLoading = true; errorMessage = nil; lastRunOutput = nil }
        do {
            let cmd = "\"\(Config.sentinelScript)\""
            let result = try ProcessRunner.run(cmd)
            let out = """
            [exit=\(result.exitCode)]
            ----- STDOUT -----
            \(result.stdout)
            ----- STDERR -----
            \(result.stderr)
            """
            await MainActor.run { lastRunOutput = out }
            try await loadMerkle()
            let ok = try await MerkleVerifier.verify()
            await MainActor.run { signatureValid = ok }
        } catch {
            await MainActor.run { signatureValid = false; errorMessage = error.localizedDescription }
        }
        await MainActor.run { isLoading = false }
    }

    func signLedger() async {
        await MainActor.run { isLoading = true; errorMessage = nil }
        do {
            try MerkleSigner.signLedger()
            try await loadMerkle()
            let ok = try await MerkleVerifier.verify()
            await MainActor.run { signatureValid = ok }
        } catch {
            await MainActor.run { signatureValid = false; errorMessage = error.localizedDescription }
        }
        await MainActor.run { isLoading = false }
    }
}

#if DEBUG
struct MerkleDashboard_Previews: PreviewProvider {
    static var previews: some View {
        MerkleDashboard().frame(width: 640, height: 360)
    }
}
#endif
