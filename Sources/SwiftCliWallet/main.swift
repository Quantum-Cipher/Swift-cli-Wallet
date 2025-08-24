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

// MARK: - Model
struct MerkleRoot: Codable {
    let merkle_root: String
    let algo: String
    let timestamp: String
    let host: String
}

// MARK: - Verifier
struct MerkleVerifier {
    static func verify() throws -> Bool {
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

// MARK: - CLI Functions
func loadMerkle() throws -> MerkleRoot? {
    do {
        let data = try Data(contentsOf: Config.merkleJSON)
        let decoded = try JSONDecoder().decode(MerkleRoot.self, from: data)
        return decoded
    } catch let error as DecodingError {
        print("Decoding error: \(error.localizedDescription)")
        return nil
    } catch {
        print("Could not load Merkle JSON: \(error.localizedDescription)")
        return nil
    }
}

func runEternumSentinelLedger() throws {
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
}

func printMerkleInfo(_ merkle: MerkleRoot) {
    print("🛡 EternumSentinel Audit")
    print("Merkle Root: \(merkle.merkle_root)")
    print("Algorithm: \(merkle.algo)")
    print("Timestamp: \(merkle.timestamp)")
    print("Host: \(merkle.host)")
}

func verifyAndPrint() {
    do {
        let valid = try MerkleVerifier.verify()
        print(valid ? "✅ Signature Verified" : "❌ Signature Invalid")
    } catch let error as MerkleVerificationError {
        let msg = switch error {
        case .missingFiles(let msg): "Missing files: \(msg)"
        case .invalidPEM: "Invalid public key format."
        case .decodingError(let msg): "Decoding error: \(msg)"
        case .signatureMismatch: "Signature mismatch."
        }
        print("❌ \(msg)")
    } catch {
        print("Verification error: \(error.localizedDescription)")
    }
}

// MARK: - Main CLI Entry
let arguments = CommandLine.arguments
guard arguments.count > 1 else {
    print("Usage: swift run SwiftCliWallet <command>")
    print("Commands: ledger, sign, verify, audit")
    exit(1)
}

let command = arguments[1].lowercased()

switch command {
case "ledger":
    do {
        try runEternumSentinelLedger()
        print("✅ Ledger updated successfully.")
        if let merkle = try loadMerkle() {
            printMerkleInfo(merkle)
        }
    } catch {
        print("Failed to run EternumSentinel ledger: \(error.localizedDescription)")
        exit(1)
    }
case "sign":
    do {
        try MerkleSigner.signLedger()
        print("✅ Ledger signed successfully.")
        if let merkle = try loadMerkle() {
            printMerkleInfo(merkle)
        }
        verifyAndPrint()
    } catch {
        print("Signing error: \(error.localizedDescription)")
        exit(1)
    }
case "verify":
    do {
        let valid = try MerkleVerifier.verify()
        print(valid ? "✅ Signature Verified" : "❌ Signature Invalid")
        if let merkle = try loadMerkle() {
            printMerkleInfo(merkle)
        }
    } catch {
        print("Verification error: \(error.localizedDescription)")
        exit(1)
    }
case "audit":
    if let merkle = try? loadMerkle() {
        printMerkleInfo(merkle)
        verifyAndPrint()
    } else {
        print("No Merkle root found. Run 'ledger' first.")
    }
default:
    print("Unknown command: \(command)")
    print("Usage: swift run SwiftCliWallet <command>")
    print("Commands: ledger, sign, verify, audit")
    exit(1)
}
