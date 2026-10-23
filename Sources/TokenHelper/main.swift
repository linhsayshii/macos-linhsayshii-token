// token-helper: reads one JSON HelperRequest per line on stdin, writes one JSON
// HelperResponse per line on stdout. Credentials stay on the stdin pipe.
import Foundation
import Core
import TSShim

func emit(_ r: HelperResponse) {
    let d = (try? JSONEncoder().encode(r)) ?? Data("{\"error\":\"encode failed\"}".utf8)
    FileHandle.standardOutput.write(d)
    FileHandle.standardOutput.write(Data([0x0a]))
}

let args = CommandLine.arguments
let backend: any TokenBackend
if let i = args.firstIndex(of: "--backend"), i + 1 < args.count, ["fastca", "efy", "espk-discovery"].contains(args[i + 1]) {
    ts_set_reencoding_enabled(0)
    let profile: NativeESPKProfile = args[i + 1] == "espk-discovery" ? .discovery : (args[i + 1] == "efy" ? .efy : .fastca)
    let reader = args.firstIndex(of: "--reader").flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil }
    backend = ESPKBackend(profile: profile, scan: { ReaderScanner().readers().filter { reader == nil || $0.reader == reader } })
} else if let i = args.firstIndex(of: "--module"), i + 1 < args.count {
    if let b = args.firstIndex(of: "--backend"), b + 1 < args.count, args[b + 1] == "oneca" {
        ts_set_reencoding_enabled(0)
        backend = OneCA(modulePath: args[i + 1])
    } else {
        backend = PKCS11(modulePath: args[i + 1])
    }
} else {
    FileHandle.standardError.write(Data("expected --module <path> or --backend fastca|efy\n".utf8))
    exit(2)
}

while let line = readLine(strippingNewline: true) {
    guard let reqData = line.data(using: .utf8),
          let req = try? JSONDecoder().decode(HelperRequest.self, from: reqData) else {
        emit(.error("bad request")); continue
    }
    do {
        switch req {
        case .listTokens: emit(.tokens(try backend.listTokens()))
        case .listCerts(let serial): emit(.certs(try backend.certs(serial: serial)))
        case .login(let serial, let pin): emit(.loginResult(try backend.login(serial: serial, pin: pin)))
        case .sign(let serial, let certId, let mech, let dataB64):
            guard let data = Data(base64Encoded: dataB64) else { emit(.error("bad base64")); break }
            let sig = try backend.sign(serial: serial, certId: certId, mech: mech, data: Array(data))
            emit(.signature(Data(sig).base64EncodedString()))
        case .logout(let serial): backend.logout(serial: serial); emit(.ok)
        }
    } catch let error as ESPKError {
        emit(.failure(TokenFailure(code: error.code, message: error.description)))
    } catch { emit(.error("\(error)")) }
}
