import Foundation
import Core

public protocol SignedXMLVerifier: Sendable {
    func verify(_ signedXML: Data) async throws
}

/// Optional independent integrity check of the final XML bytes, before upload.
public struct XMLSecVerifier: SignedXMLVerifier {
    let executableURL: URL?
    let temporaryDirectory: URL

    public init() {
        executableURL = ["/opt/homebrew/bin/xmlsec1", "/usr/local/bin/xmlsec1", "/usr/bin/xmlsec1"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
        temporaryDirectory = FileManager.default.temporaryDirectory
    }

    init(executableURL: URL?, temporaryDirectory: URL) {
        self.executableURL = executableURL
        self.temporaryDirectory = temporaryDirectory
    }

    public func verify(_ signedXML: Data) async throws {
        guard let executableURL else {
            FileHandle.standardError.write(Data("xmlsec1 chưa được cài; bỏ qua kiểm tra XML tuỳ chọn\n".utf8))
            return
        }
        // Process.waitUntilExit must not block the UI or a NIO event loop.
        try await Task.detached {
            let dir = temporaryDirectory.appendingPathComponent("TokenSigner-verify-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: dir) }
            let file = dir.appendingPathComponent("signed.xml")
            try signedXML.write(to: file)
            let process = Process()
            process.executableURL = executableURL
            // Certificate validity/consent is handled by SigningService. Here
            // --insecure skips chain trust only; signature/digests are verified.
            var args = ["--verify", "--insecure", "--enabled-key-data", "x509",
                        "--enabled-reference-uris", "empty,same-doc",
                        "--id-attr:Id", "http://www.w3.org/2000/09/xmldsig#:Object"]
            for attribute in ["id", "Id", "ID"] {
                args += ["--id-attr:\(attribute)", "HSoKhaiThue"]
            }
            process.arguments = args + [file.path]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                process.waitUntilExit()
                guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                    throw SigningFailure.bad("Chữ ký XML không hợp lệ; tờ khai chưa được gửi. Vui lòng ký lại.")
                }
            } catch let error as SigningFailure { throw error }
            catch { throw SigningFailure.bad("Không thể chạy xmlsec1 để kiểm tra chữ ký XML; tờ khai chưa được gửi.") }
        }.value
    }
}
