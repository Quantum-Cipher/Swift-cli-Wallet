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

    static var sentinelScript: URL? {
        if let env = ProcessInfo.processInfo.environment["ETERNUM_SENTINEL"], !env.isEmpty {
            let path = (env as NSString).expandingTildeInPath
            return FileManager.default.fileExists(atPath: path) ? URL(fileURLWithPath: path) : nil
        }
        let defaultPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("projects/Swift-cli-Wallet/EternumSentinel/bin/ledger_merkle.sh")
        return FileManager.default.fileExists(atPath: defaultPath.path) ? defaultPath : nil
    }
}

// MARK: - Model
struct MerkleRoot: Codable {
    let merkle_root: String
    let algo: String
    let timestamp: String
    let host: String
}

// MARK: - Errors
enum MerkleVerificationError: Error, CustomStringConvertible {
    case missingFiles(String), invalidPEM, signatureMismatch
    var description: String {
        switch self {
        case .missingFiles(let s): return "Missing files: \(s)"
        case .invalidPEM: return "Invalid PEM format"
        case .signatureMismatch: return "Signature mismatch"
        }
    }
}
enum SignerError: Error, CustomStringConvertible {
    case missingFile(String), invalidPEM, keyParseFailed
    var description: String {
        switch self {
        case .missingFile(let p): return "Missing file: \(p)"
        case .invalidPEM: return "Invalid private key PEM"
        case .keyParseFailed: return "Failed to parse private key"
        }
    }
}
enum ShellError: Error, CustomStringConvertible {
    case scriptNotFound(String), executionFailed(Int32, String)
    var description: String {
        switch self {
        case .scriptNotFound(let path): return "Ledger script not found at \(path). Set ETERNUM_SENTINEL env var."
        case .executionFailed(let status, let err): return "Script failed (status \(status)): \(err)"
        }
    }
}

// MARK: - Shell
@discardableResult
func runShell(_ script: URL) throws -> (status: Int32, out: String, err: String) {
    guard FileManager.default.isExecutableFile(atPath: script.path) else {
        throw ShellError.scriptNotFound(script.path)
    }
    let p = Process()
    p.executableURL = script
    let outPipe = Pipe(), errPipe = Pipe()
    p.standardOutput = outPipe
    p.standardError = errPipe
    try p.run()
    p.waitUntilExit()
    let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    return (p.terminationStatus, out, err)
}

// MARK: - Signer/Verifier
struct MerkleSigner {
    static func ensureKeypair() throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: Config.privateKey.path),
           fm.fileExists(atPath: Config.publicKey.path) {
            return
        }

        let priv = P256.Signing.PrivateKey()
        let pub = priv.publicKey
        try fm.createDirectory(at: Config.keysDir, withIntermediateDirectories: true)

        let privPEM = """
-----BEGIN PRIVATE KEY-----
\(priv.derRepresentation.base64EncodedString(options: [.lineLength64Characters]))
-----END PRIVATE KEY-----
"""
        try privPEM.write(to: Config.privateKey, atomically: true, encoding: .utf8)

        let pubPEM = """
-----BEGIN PUBLIC KEY-----
\(pub.derRepresentation.base64EncodedString(options: [.lineLength64Characters]))
-----END PUBLIC KEY-----
"""
        try pubPEM.write(to: Config.publicKey, atomically: true, encoding: .utf8)
        print("🔑 Generated new keypair → \(Config.keysDir.path)")
    }

    static func sign() throws {
        try ensureKeypair()
        guard FileManager.default.fileExists(atPath: Config.merkleJSON.path) else {
            throw SignerError.missingFile(Config.merkleJSON.path)
        }
        let jsonData = try Data(contentsOf: Config.merkleJSON)
        let pem = try String(contentsOf: Config.privateKey)
        let keyB64 = pem.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.isEmpty }
            .joined()
        guard let keyDER = Data(base64Encoded: keyB64) else { throw SignerError.invalidPEM }
        let priv = try P256.Signing.PrivateKey(derRepresentation: keyDER)
        let sig = try priv.signature(for: jsonData)
        try fm.createDirectory(at: Config.logsDir, withIntermediateDirectories: true)
        try sig.derRepresentation.write(to: Config.signature)
        print("✍️ Wrote signature → \(Config.signature.path)")
    }
}

struct MerkleVerifier {
    static func verify() throws {
        let json = try Data(contentsOf: Config.merkleJSON)
        let sig = try Data(contentsOf: Config.signature)
        let pubPEM = try String(contentsOf: Config.publicKey)
        let keyB64 = pubPEM.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.isEmpty }
            .joined()
        guard let keyDER = Data(base64Encoded: keyB64) else { throw MerkleVerificationError.invalidPEM }
        let pub = try P256.Signing.PublicKey(derRepresentation: keyDER)
        let sigDER = try P256.Signing.ECDSASignature(derRepresentation: sig)
        guard pub.isValidSignature(sigDER, for: json) else { throw MerkleVerificationError.signatureMismatch }
        print("✅ Signature verified")
    }
}

// MARK: - Commands
enum Command: String { case ledger, sign, verify, audit, help }

func usage(_ executable: String) {
    print("""
Usage: \(executable) <command>

  ledger    Run EternumSentinel script to produce ledger_merkle.json
  sign      Sign logs/ledger_merkle.json with keys/ledger.pem → logs/ledger_merkle.sig
  verify    Verify logs/ledger_merkle.json against keys/ledger.pub and logs/ledger_merkle.sig
  audit     Pretty-print merkle JSON fields and verify signature
  help      Show this help

Env:
  ETERNUM_HOME      Override base dir (default: ~/Automation)
  ETERNUM_SENTINEL  Path to ledger script (default: ~/projects/Swift-cli-Wallet/EternumSentinel/bin/ledger_merkle.sh)
""")
}

func cmd_ledger() {
    do {
        guard let script = Config.sentinelScript else { throw ShellError.scriptNotFound("ETERNUM_SENTINEL") }
        let (status, out, err) = try runShell(script)
        if status != 0 { throw ShellError.executionFailed(status, err) }
        if !out.isEmpty { print(out.trimmingCharacters(in: .whitespacesAndNewlines)) }
    } catch {
        fputs("ledger error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_sign() {
    do { try MerkleSigner.sign() } catch {
        fputs("sign error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_verify() {
    do { try MerkleVerifier.verify() } catch {
        fputs("verify error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_audit() {
    do {
        guard FileManager.default.fileExists(atPath: Config.merkleJSON.path) else {
            print("No Merkle JSON found. Run 'ledger' first.")
            return
        }
        let data = try Data(contentsOf: Config.merkleJSON)
        let m = try JSONDecoder().decode(MerkleRoot.self, from: data)
        print("🛡 Eternum Audit")
        print("merkle_root: \(m.merkle_root)")
        print("algo: \(m.algo)")
        print("timestamp: \(m.timestamp)")
        print("host: \(m.host)")
        do { try MerkleVerifier.verify() } catch {
            print("Signature verification failed: \(error)")
        }
    } catch {
        fputs("audit error: \(error)\n", stderr)
        exit(1)
    }
}

// MARK: - Entry
@main
struct WalletCLI {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        let executable = CommandLine.arguments[0].components(separatedBy: "/").last ?? "swiftcliwallet"
        guard let first = args.first, let cmd = Command(rawValue: first.lowercased()) else {
            usage(executable)
            exit(0)
        }
        switch cmd {
        case .ledger: cmd_ledger()
        case .sign: cmd_sign()
        case .verify: cmd_verify()
        case .audit: cmd_audit()
        case .help: usage(executable)
        }
    }
}
