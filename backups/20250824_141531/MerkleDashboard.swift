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
    static var signature: URL { logsDir.appendingPathComponent("ledger_merkle.sig") }
    static var publicKey: URL { keysDir.appendingPathComponent("ledger.pub") }
    static var privateKey: URL { keysDir.appendingPathComponent("ledger.pem") }
}

// MARK: - Errors
enum MerkleVerificationError: Error {
    case missingFiles(String)
    case invalidPEM
    case decodingError(String)
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
            let sigData = try Data(contentsOf: Config.signature)
            let pubPem = try String(contentsOf: Config.publicKey)

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

            let pubKey = try P256.Signing.PublicKey(derRepresentation: keyDER)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: sigData)

            guard pubKey.isValidSignature(signature, for: jsonData) else {
                throw MerkleVerificationError.signatureMismatch
            }

            return true
        } catch let error as MerkleVerificationError {
            throw error
        } catch {
            throw MerkleVerificationError.missingFiles(error.localizedDescription)
        }
    }
}

// MARK: - Signer
struct MerkleSigner {
    static func ensureKeypair() throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: Config.privateKey.path),
           fm.fileExists(atPath: Config.publicKey.path) {
            return
        }

        let priv = P256.Signing.PrivateKey()
        let pub = priv.publicKey

        // Save private key in PEM (PKCS#8 DER base64)
        let privDER = priv.derRepresentation
        let privB64 = privDER.base64EncodedString(options: [.lineLength64Characters])
        let privPEM = """
        -----BEGIN PRIVATE KEY-----
        \(privB64)
        -----END PRIVATE KEY-----
        """
        try fm.createDirectory(at: Config.keysDir, withIntermediateDirectories: true)
        try privPEM.write(to: Config.privateKey, atomically: true, encoding: .utf8)

        // Save public key in PEM (SPKI DER base64)
        let pubDER = pub.derRepresentation
        let pubB64 = pubDER.base64EncodedString(options: [.lineLength64Characters])
        let pubPEM = """
        -----BEGIN PUBLIC KEY-----
        \(pubB64)
        -----END PUBLIC KEY-----
        """
        try pubPEM.write(to: Config.publicKey, atomically: true, encoding: .utf8)
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

        let signature = try privKey.signature(for: jsonData)
        try signature.derRepresentation.write(to: Config.signature)
    }
}

// MARK: - Model
struct MerkleRoot: Codable {
    let merkle_root: String
    let algo: String
    let timestamp: String
    let host: String
}

// MARK: - View
struct MerkleDashboard: View {
    @State private var merkle: MerkleRoot?
    @State private var signatureValid: Bool?
    @State private var errorMessage: String?
    @State private var isLoading: Bool = false

    var body: some View {
        VStack(spacing: 16) {
            Text("🛡 EternumSentinel Audit")
                .font(.title2).bold()

            if let m = merkle {
                VStack(spacing: 6) {
                    Text("Merkle Root:")
                        .font(.subheadline).foregroundColor(.secondary)
                    Text(m.merkle_root)
                        .font(.footnote)
                        .textSelection(.enabled)
                        .multilineTextAlignment(.center)
                        .lineLimit(3)
                        .minimumScaleFactor(0.7)

                    HStack {
                        Text("Timestamp: \(m.timestamp)")
                        Spacer()
                        Text("Host: \(m.host)")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
                .padding(.vertical, 6)

                if let valid = signatureValid {
                    Text(valid ? "✅ Signature Verified" : "❌ Signature Invalid")
                        .foregroundColor(valid ? .green : .red)
                        .bold()
                } else {
                    Text("🔍 Verifying signature...")
                        .foregroundColor(.secondary)
                }

                if let msg = errorMessage {
                    Text(msg)
                        .font(.caption)
                        .foregroundColor(.orange)
                        .multilineTextAlignment(.center)
                        .padding(.top, 4)
                }

                HStack(spacing: 12) {
                    Button("Refresh") {
                        Task { await refresh() }
                    }
                    .disabled(isLoading)
                    Button("Run Ledger") {
                        Task { await runEternumSentinelLedger() }
                    }
                    .disabled(isLoading)
                    Button("Sign Ledger") {
                        Task { await signLedger() }
                    }
                    .disabled(isLoading)
                }
                .padding(.top, 8)
            } else {
                Text("No Merkle root found.")
                    .foregroundColor(.secondary)
                Button("Run Ledger") {
                    Task { await runEternumSentinelLedger() }
                }
                .disabled(isLoading)
                Button("Sign Ledger") {
                    Task { await signLedger() }
                }
                .disabled(isLoading)
            }
        }
        .padding(20)
        .frame(minWidth: 520, minHeight: 280)
        .onAppear {
            Task { await refresh() }
        }
    }

    // MARK: - Logic
    private func loadMerkle() async {
        do {
            let data = try Data(contentsOf: Config.merkleJSON)
            let decoded = try JSONDecoder().decode(MerkleRoot.self, from: data)
            await MainActor.run {
                merkle = decoded
                errorMessage = nil
            }
        } catch let error as DecodingError {
            await MainActor.run {
                merkle = nil
                signatureValid = nil
                errorMessage = "Decoding error: \(error.localizedDescription)"
            }
        } catch {
            await MainActor.run {
                merkle = nil
                signatureValid = nil
                errorMessage = "Could not load Merkle JSON: \(error.localizedDescription)"
            }
        }
    }

    private func refresh() async {
        await MainActor.run { isLoading = true }
        await loadMerkle()
        do {
            let valid = try await MerkleVerifier.verify()
            await MainActor.run {
                signatureValid = valid
                errorMessage = valid ? nil : "Signature verification failed."
                isLoading = false
            }
        } catch let error as MerkleVerificationError {
            await MainActor.run {
                signatureValid = false
                errorMessage = switch error {
                case .missingFiles(let msg): "Missing files: \(msg)"
                case .invalidPEM: "Invalid public key format."
                case .decodingError(let msg): "Decoding error: \(msg)"
                case .signatureMismatch: "Signature mismatch."
                }
                isLoading = false
            }
        } catch {
            await MainActor.run {
                signatureValid = false
                errorMessage = "Verification error: \(error.localizedDescription)"
                isLoading = false
            }
        }
    }

    private func runEternumSentinelLedger() async {
        await MainActor.run { isLoading = true }
        do {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = ["bash", "-lc", "EternumSentinel ledger"]

            let pipe = Pipe()
            process.standardError = pipe

            try process.run()
            process.waitUntilExit()

            if process.terminationStatus != 0 {
                let errorData = pipe.fileHandleForReading.readDataToEndOfFile()
                let errorMessage = String(data: errorData, encoding: .utf8) ?? "Unknown error"
                throw NSError(domain: "EternumSentinel", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: errorMessage])
            }

            await refresh()
        } catch {
            await MainActor.run {
                errorMessage = "Failed to run EternumSentinel: \(error.localizedDescription)"
                isLoading = false
            }
        }
    }

    private func signLedger() async {
        await MainActor.run { isLoading = true }
        do {
            try MerkleSigner.signLedger()
            await refresh()
        } catch let error as SignerError {
            await MainActor.run {
                errorMessage = switch error {
                case .missingFile(let path): "Missing file: \(path)"
                case .invalidPEM: "Invalid private key format."
                case .keyParseFailed: "Failed to parse private key."
                }
                isLoading = false
            }
        } catch {
            await MainActor.run {
                errorMessage = "Signing error: \(error.localizedDescription)"
                isLoading = false
            }
        }
    }
}

// MARK: - Preview
#if DEBUG
struct MerkleDashboard_Previews: PreviewProvider {
    static var previews: some View {
        MerkleDashboard()
            .frame(width: 600, height: 320)
    }
}
#endif
