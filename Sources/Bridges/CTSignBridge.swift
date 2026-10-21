import Foundation
import Core

public protocol SigningBackend: Sendable {
    func certificates() async -> [CertInfo]
    func sign(serial: String, digestB64: String, origin: String) async throws -> String
}

public struct CTSignBridge: Sendable {
    let backend: any SigningBackend
    let service: (any SigningService)?
    public init(backend: any SigningBackend, service: (any SigningService)? = nil) {
        self.backend = backend; self.service = service
    }

    // (verify) against the real CTSigningHub 1.2 Version string via a Parallels capture.
    public static let version = "1.2.0.0"

    /// notAfter is "yyyy-MM-dd HH:mm:ss"; an unparsable date counts as valid (the sign path still blocks expired certs).
    static func notExpired(_ notAfter: String) -> Bool {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.date(from: notAfter).map { $0 > Date() } ?? true
    }

    public func handle(method: String, path: String, body: Data, origin: String = "local") async -> (status: Int, json: Data) {
        switch (method, path.lowercased() == "/api/hubclient/signxml" ? "/api/HubClient/signxml" : path) {
        case ("GET", "/api/SignHash/Version"):
            return (200, jsonString(Self.version))
        case ("GET", "/api/Info/GetInfoCert"):
            return (200, jsonString("1"))
        case ("GET", "/api/HubClient/GetCert"):
            let certs = await backend.certificates()
            if certs.isEmpty { return (200, emptyCerts()) }
            let infos = certs.map {
                CertificateInfo(serinumber: $0.serialHex, subjectDN: $0.subject, issuedDN: $0.issuer,
                                pemCert: $0.derB64, valid: Self.notExpired($0.notAfter), validFrom: $0.notBefore,
                                validTo: $0.notAfter, error: nil)
            }
            return (200, wrap(status: 200, data: infos, message: "SUCCESS"))
        case ("POST", "/api/HubClient/SignHash"):
            guard var req = try? JSONDecoder().decode(SignHashRequest.self, from: body) else {
                return (200, errorBody(500, "bad request"))
            }
            do {
                for i in req.hash.indices {
                    req.hash[i].CKy = try await backend.sign(serial: req.serinumber, digestB64: req.hash[i].DLieuHash, origin: origin)
                }
                return (200, wrap(status: 200, data: req.hash, message: "SUCCESS"))
            } catch CTSignError.unknownSerial(let s) {
                return (200, errorBody(404, "Không tìm thấy CTS có serinumber \(s)"))
            } catch SigningFailure.unknownSerial(let s) {
                return (200, errorBody(404, "Không tìm thấy CTS có serinumber \(s)"))
            } catch SigningFailure.userDenied, SigningFailure.userCancelled {
                return (200, errorBody(403, "Người dùng từ chối ký"))
            } catch SigningFailure.certExpired {
                return (200, errorBody(500, "Chứng thư số đã hết hạn"))
            } catch SigningFailure.bad(let m) {
                return (200, errorBody(500, m))
            } catch {
                return (200, errorBody(500, "\(error)"))
            }
        case ("POST", "/api/HubClient/signxml"):
            return await signXML(body: body, origin: origin)
        default:
            return (404, Data("{}".utf8))
        }
    }
}

extension CTSignBridge {
    func signXML(body: Data, origin: String) async -> (status: Int, json: Data) {
        guard let service else { return (200, errorBody(501, "signxml chưa được hỗ trợ")) }
        guard let req = SignXmlRequestAdapter.parse(body) else {
            return (200, errorBody(500, "thiếu dataFile (bridge không đọc filePath)"))
        }
        do {
            let out = try await service.signXML(BridgeContext(bridge: "ctsigninghub", origin: origin),
                                                serial: req.serial, xml: req.xml, options: req.options)
            return (200, wrap(status: 200, data: out.base64EncodedString(), message: "SUCCESS"))
        } catch SigningFailure.unknownSerial(let s) {
            return (200, errorBody(404, "Không tìm thấy CTS có serinumber \(s)"))
        } catch SigningFailure.userDenied, SigningFailure.userCancelled {
            return (200, errorBody(403, "Người dùng từ chối ký"))
        } catch SigningFailure.certExpired {
            return (200, errorBody(500, "Chứng thư số đã hết hạn"))
        } catch {
            return (200, errorBody(500, "\(error)"))
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

func wrap<T: Encodable>(status: Int, data: T, message: String) -> Data {
    enc(Wrapper(status: status, data: data, message: message))
}

func errorBody(_ status: Int, _ message: String) -> Data {
    enc(Wrapper<[String]>(status: status, data: nil, message: message))
}

private func emptyCerts() -> Data {
    // {"status":0,"data":null,"message":null}
    enc(Wrapper<[CertificateInfo]>(status: 0, data: nil, message: nil))
}
