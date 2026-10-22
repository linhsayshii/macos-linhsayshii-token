import Foundation
import Core

public protocol SigningBackend: Sendable {
    func certificates() async -> [CertInfo]
    func sign(serial: String, digestB64: String) async throws -> String
}

public struct CTSignBridge: Sendable {
    let backend: any SigningBackend
    public init(backend: any SigningBackend) { self.backend = backend }

    // (verify) against the real CTSigningHub 1.2 Version string via a Parallels capture.
    public static let version = "1.2.0.0"

    public func handle(method: String, path: String, body: Data) async -> (status: Int, json: Data) {
        switch (method, path) {
        case ("GET", "/api/SignHash/Version"):
            return (200, jsonString(Self.version))
        case ("GET", "/api/Info/GetInfoCert"):
            return (200, jsonString("1"))
        case ("GET", "/api/HubClient/GetCert"):
            let certs = await backend.certificates()
            if certs.isEmpty { return (200, emptyCerts()) }
            let infos = certs.map {
                CertificateInfo(serinumber: $0.serialHex, subjectDN: $0.subject, issuedDN: $0.issuer,
                                pemCert: $0.derB64, valid: true, validFrom: $0.notBefore,
                                validTo: $0.notAfter, error: nil)
            }
            return (200, wrap(status: 200, data: infos, message: "SUCCESS"))
        case ("POST", "/api/HubClient/SignHash"):
            guard var req = try? JSONDecoder().decode(SignHashRequest.self, from: body) else {
                return (200, errorBody(500, "bad request"))
            }
            do {
                for i in req.hash.indices {
                    req.hash[i].CKy = try await backend.sign(serial: req.serinumber, digestB64: req.hash[i].DLieuHash)
                }
                return (200, wrap(status: 200, data: req.hash, message: "SUCCESS"))
            } catch is CancellationError {
                return (200, errorBody(500, "Đã huỷ yêu cầu ký"))
            } catch MinvoiceError.busy {
                return (200, errorBody(500, "Đang có yêu cầu khác, vui lòng thử lại sau"))
            } catch CTSignError.unknownSerial(let s) {
                return (200, errorBody(404, "Không tìm thấy CTS có serinumber \(s)"))
            } catch CTSignError.precomputedHashUnsupported {
                return (200, errorBody(400, "DLieuHash không phải SHA-256 32 byte (base64 hoặc hex)."))
            } catch {
                return (200, errorBody(500, "\(error)"))
            }
        default:
            return (404, Data("{}".utf8))
        }
    }
}

// MARK: - JSON helpers

private struct Wrapper<T: Encodable>: Encodable {
    let status: Int
    let data: T?
    let message: String?
}

private func enc<T: Encodable>(_ v: T) -> Data {
    (try? JSONEncoder().encode(v)) ?? Data("{}".utf8)
}

private func jsonString(_ s: String) -> Data { enc(s) }

private func wrap<T: Encodable>(status: Int, data: T, message: String) -> Data {
    enc(Wrapper(status: status, data: data, message: message))
}

private func errorBody(_ status: Int, _ message: String) -> Data {
    enc(Wrapper<[String]>(status: status, data: nil, message: message))
}

private func emptyCerts() -> Data {
    // {"status":0,"data":null,"message":null}
    enc(Wrapper<[CertificateInfo]>(status: 0, data: nil, message: nil))
}
