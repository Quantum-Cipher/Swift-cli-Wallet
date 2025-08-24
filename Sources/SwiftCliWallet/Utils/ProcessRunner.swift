import Foundation

struct ProcessResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

enum ProcessError: LocalizedError {
    case failedToStart(String)
    var errorDescription: String? {
        switch self {
        case .failedToStart(let msg): return "Failed to start process: \(msg)"
        }
    }
}

struct ProcessRunner {
    static func run(_ command: String) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["bash", "-lc", command]

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError  = errPipe

        do { try process.run() } catch {
            throw ProcessError.failedToStart(error.localizedDescription)
        }
        process.waitUntilExit()

        let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return ProcessResult(exitCode: process.terminationStatus, stdout: out, stderr: err)
    }
}
