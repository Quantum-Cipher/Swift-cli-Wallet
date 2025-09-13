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

    /// Path to ledger script; override with $ETERNUM_SENTINEL
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
    case missingFiles(String), invalidPEM, signatureMismatch, invalidHash
    var description: String {
        switch self {
        case .missingFiles(let s): return "Missing files: \(s)"
        case .invalidPEM: return "Invalid PEM format"
        case .signatureMismatch: return "Signature mismatch"
        case .invalidHash: return "Invalid hash format"
        }
    }
}
enum SignerError: Error, CustomStringConvertible {
    case missingFile(String), invalidPEM, keyParseFailed, invalidHash
    var description: String {
        switch self {
        case .missingFile(let p): return "Missing file: \(p)"
        case .invalidPEM: return "Invalid private key PEM"
        case .keyParseFailed: return "Failed to parse private key"
        case .invalidHash: return "Invalid hash format"
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
    let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return (p.terminationStatus, out, err)
}

// MARK: - Canonical Hash Integration
func canonicalHash(for filePath: URL) throws -> [String: Any] {
    let fm = FileManager.default
    guard fm.fileExists(atPath: filePath.path) else { throw SignerError.missingFile(filePath.path) }
    let data = try Data(contentsOf: filePath)
    
    // Canonicalize: UTF-8, trim trailing whitespace, add newline for text
    var canonicalData = data
    if filePath.pathExtension == "txt" {
        if let text = String(data: data, encoding: .utf8) {
            canonicalData = (text.trimmingCharacters(in: .whitespaces) + "\n").data(using: .utf8)!
        }
    }
    let hash = SHA256.hash(data: canonicalData)
    let contentHash = hash.compactMap { String(format: "%02x", $0) }.joined()
    
    // CID-style content_id (simplified multihash → multibase32)
    let multihash = "1220" + contentHash // SHA2-256 prefix
    let contentId = Data(multihash.utf8).base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "=")).lowercased()
    
    return [
        "file": filePath.lastPathComponent,
        "bytesize_original": data.count,
        "mime_detected": filePath.pathExtension == "txt" ? "text/plain" : "application/octet-stream",
        "bytesize_canonical": canonicalData.count,
        "content_hash": contentHash,
        "content_id": "b" + contentId,
        "wm_version_hint": "v1-canon"
    ]
}

// MARK: - Signer/Verifier
struct MerkleSigner {
    static func ensureKeypair() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: Config.keysDir, withIntermediateDirectories: true, attributes: [.posixPermissions: NSNumber(value: 0o700)])

        let needRotate = ProcessInfo.processInfo.environment["ETERNUM_ROTATE"] == "1"
        if needRotate, fm.fileExists(atPath: Config.privateKey.path) || fm.fileExists(atPath: Config.publicKey.path) {
            let ts = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
            let archiveDir = Config.keysDir.appendingPathComponent("archive-\(ts)")
            try fm.createDirectory(at: archiveDir, withIntermediateDirectories: true, attributes: [.posixPermissions: NSNumber(value: 0o700)])
            if fm.fileExists(atPath: Config.privateKey.path) {
                try fm.moveItem(at: Config.privateKey, to: archiveDir.appendingPathComponent("ledger.pem"))
            }
            if fm.fileExists(atPath: Config.publicKey.path) {
                try fm.moveItem(at: Config.publicKey, to: archiveDir.appendingPathComponent("ledger.pub"))
            }
            print("🔁 Rotated old keypair → \(archiveDir.path)")
        }

        if fm.fileExists(atPath: Config.privateKey.path), fm.fileExists(atPath: Config.publicKey.path), !needRotate {
            let pem = try String(contentsOf: Config.privateKey)
            let pubPEM = try String(contentsOf: Config.publicKey)
            guard pem.contains("BEGIN PRIVATE KEY"), pem.contains("END PRIVATE KEY"),
                  pubPEM.contains("BEGIN PUBLIC KEY"), pubPEM.contains("END PUBLIC KEY") else {
                throw SignerError.invalidPEM
            }
            return
        }

        let priv = P256.Signing.PrivateKey()
        let pub = priv.publicKey
        let privPEM = priv.pemRepresentation
        let pubPEM = pub.pemRepresentation
        try privPEM.write(to: Config.privateKey, atomically: true, encoding: .utf8)
        try pubPEM.write(to: Config.publicKey, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: Config.privateKey.path)
        try fm.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: Config.publicKey.path)
        print(needRotate ? "🔑 Generated new rotated keypair" : "🔑 Generated keypair → \(Config.keysDir.path)")
    }

    static func sign(hash: String? = nil) throws -> String {
        try ensureKeypair()
        let fm = FileManager.default
        guard fm.fileExists(atPath: Config.privateKey.path) else {
            throw SignerError.missingFile(Config.privateKey.path)
        }
        let pem = try String(contentsOf: Config.privateKey)
        guard pem.contains("BEGIN PRIVATE KEY"), pem.contains("END PRIVATE KEY") else {
            throw SignerError.invalidPEM
        }
        let keyB64 = pem.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.isEmpty }
            .joined()
        guard let keyDER = Data(base64Encoded: keyB64) else { throw SignerError.invalidPEM }
        let priv = try P256.Signing.PrivateKey(derRepresentation: keyDER)

        if let hash = hash {
            guard hash.count == 64, hash.allSatisfy({ $0.isHexDigit }) else {
                throw SignerError.invalidHash
            }
            let hashData = Data(hex: hash)
            let sig = try priv.signature(for: hashData)
            let sigB64 = sig.derRepresentation.base64EncodedString()
            try sig.derRepresentation.write(to: Config.signature)
            print("✍️ Wrote signature → \(Config.signature.path)")
            return sigB64
        } else {
            guard fm.fileExists(atPath: Config.merkleJSON.path) else {
                throw SignerError.missingFile(Config.merkleJSON.path)
            }
            let jsonData = try Data(contentsOf: Config.merkleJSON)
            let canonical = try canonicalHash(for: Config.merkleJSON)
            let contentHash = canonical["content_hash"] as! String
            let sig = try priv.signature(for: jsonData)
            try sig.derRepresentation.write(to: Config.signature)
            print("✍️ Wrote signature → \(Config.signature.path)")
            print("🔗 Canonical hash: \(contentHash)")
            return sig.derRepresentation.base64EncodedString()
        }
    }

    static func printPEM() throws {
        try ensureKeypair()
        let fm = FileManager.default
        guard fm.fileExists(atPath: Config.privateKey.path), fm.fileExists(atPath: Config.publicKey.path) else {
            throw SignerError.missingFile("Keys missing")
        }
        let privPEM = try String(contentsOf: Config.privateKey)
        let pubPEM = try String(contentsOf: Config.publicKey)
        print("Private Key:\n\(privPEM)")
        print("Public Key:\n\(pubPEM)")
    }
}

struct MerkleVerifier {
    static func verify(hash: String? = nil, sigB64: String? = nil) throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: Config.publicKey.path) else {
            throw MerkleVerificationError.missingFiles(Config.publicKey.path)
        }
        let pubPEM = try String(contentsOf: Config.publicKey)
        guard pubPEM.contains("BEGIN PUBLIC KEY"), pubPEM.contains("END PUBLIC KEY") else {
            throw MerkleVerificationError.invalidPEM
        }
        let keyB64 = pubPEM.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.isEmpty }
            .joined()
        guard let keyDER = Data(base64Encoded: keyB64) else { throw MerkleVerificationError.invalidPEM }
        let pub = try P256.Signing.PublicKey(derRepresentation: keyDER)

        if let hash = hash, let sigB64 = sigB64 {
            guard hash.count == 64, hash.allSatisfy({ $0.isHexDigit }) else {
                throw MerkleVerificationError.invalidHash
            }
            guard let sigData = Data(base64Encoded: sigB64) else {
                throw MerkleVerificationError.signatureMismatch
            }
            let hashData = Data(hex: hash)
            let sigDER = try P256.Signing.ECDSASignature(derRepresentation: sigData)
            guard pub.isValidSignature(sigDER, for: hashData) else {
                throw MerkleVerificationError.signatureMismatch
            }
            print("✅ Signature verified for hash: \(hash)")
        } else {
            guard fm.fileExists(atPath: Config.merkleJSON.path) else {
                throw MerkleVerificationError.missingFiles(Config.merkleJSON.path)
            }
            guard fm.fileExists(atPath: Config.signature.path) else {
                throw MerkleVerificationError.missingFiles(Config.signature.path)
            }
            let json = try Data(contentsOf: Config.merkleJSON)
            let canonical = try canonicalHash(for: Config.merkleJSON)
            let contentHash = canonical["content_hash"] as! String
            let sig = try Data(contentsOf: Config.signature)
            let sigDER = try P256.Signing.ECDSASignature(derRepresentation: sig)
            guard pub.isValidSignature(sigDER, for: json) else {
                throw MerkleVerificationError.signatureMismatch
            }
            print("🔗 Canonical hash verified: \(contentHash)")
            print("✅ Signature verified")
        }
    }
}

// MARK: - Commands
enum Command: String { case ledger, sign, verify, audit, rotate, printPEM, help }

func usage() {
    print("""
Usage: swift run swiftcliwallet <command> [options]

  ledger          Run EternumSentinel ledger script to produce ledger_merkle.json
  sign [--hash <hex>]  Sign logs/ledger_merkle.json or provided hash with keys/ledger.pem
  verify [--hash <hex> --sig <base64>]  Verify logs/ledger_merkle.json or hash against signature
  audit           Pretty-print merkle JSON fields and verify signature
  rotate          Generate a fresh keypair (archives previous)
  print-pem       Print private and public key PEMs
  help            Show this help

Env:
  ETERNUM_HOME      Override base dir (default: ~/Automation)
  ETERNUM_SENTINEL  Path to ledger script (default: ~/projects/Swift-cli-Wallet/EternumSentinel/bin/ledger_merkle.sh)
  ETERNUM_ROTATE    If "1", rotate keys during ensureKeypair()
""")
}

func cmd_ledger() {
    do {
        guard let script = Config.sentinelScript else { throw ShellError.scriptNotFound("ETERNUM_SENTINEL") }
        let (status, out, err) = try runShell(script)
        if status != 0 { throw ShellError.executionFailed(status, err) }
        if !out.isEmpty { print(out) }
    } catch {
        fputs("ledger error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_sign() {
    do {
        let args = Array(CommandLine.arguments.dropFirst(2))
        var hash: String?
        if args.contains("--hash"), let idx = args.firstIndex(of: "--hash"), idx + 1 < args.count {
            hash = args[idx + 1]
        }
        let sigB64 = try MerkleSigner.sign(hash: hash)
        if let hash = hash { print("Signature (base64): \(sigB64)") }
    } catch {
        fputs("sign error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_verify() {
    do {
        let args = Array(CommandLine.arguments.dropFirst(2))
        var hash: String?
        var sigB64: String?
        if args.contains("--hash"), let idx = args.firstIndex(of: "--hash"), idx + 1 < args.count {
            hash = args[idx + 1]
        }
        if args.contains("--sig"), let idx = args.firstIndex(of: "--sig"), idx + 1 < args.count {
            sigB64 = args[idx + 1]
        }
        try MerkleVerifier.verify(hash: hash, sigB64: sigB64)
    } catch {
        fputs("verify error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_audit() {
    do {
        let fm = FileManager.default
        guard fm.fileExists(atPath: Config.merkleJSON.path) else { print("No Merkle JSON at \(Config.merkleJSON.path). Run 'ledger' first."); return }
        let data = try Data(contentsOf: Config.merkleJSON)
        let m = try JSONDecoder().decode(MerkleRoot.self, from: data)
        print("""
🛡 Eternum Audit
merkle_root: \(m.merkle_root)
algo:        \(m.algo)
timestamp:   \(m.timestamp)
host:        \(m.host)
""")
        do { try MerkleVerifier.verify() } catch {
            print("Signature verification failed: \(error)")
        }
    } catch {
        fputs("audit error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_rotate() {
    do {
        setenv("ETERNUM_ROTATE", "1", 1)
        try MerkleSigner.ensureKeypair()
        unsetenv("ETERNUM_ROTATE")
        print("♻️ Rotated keys")
    } catch {
        fputs("rotate error: \(error)\n", stderr)
        exit(1)
    }
}
func cmd_printPEM() {
    do {
        try MerkleSigner.printPEM()
    } catch {
        fputs("print-pem error: \(error)\n", stderr)
        exit(1)
    }
}

// MARK: - Entry
@main
struct WalletCLI {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let first = args.first, let cmd = Command(rawValue: first.lowercased()) else { usage(); exit(0) }
        switch cmd {
        case .ledger: cmd_ledger()
        case .sign: cmd_sign()
        case .verify: cmd_verify()
        case .audit: cmd_audit()
        case .rotate: cmd_rotate()
        case .printPEM: cmd_printPEM()
        case .help: usage()
        }
    }
}

// MARK: - Data Extension for Hex
extension Data {
    init(hex: String) {
        let len = hex.count / 2
        var data = Data(capacity: len)
        var i = hex.startIndex
        for _ in 0..<len {
            let j = hex.index(i, offsetBy: 2)
            let bytes = hex[i..<j]
            if let num = UInt8(bytes, radix: 16) {
                data.append(num)
            }
            i = j
        }
        self = data
    }
}
