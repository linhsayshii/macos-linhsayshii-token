// token-helper: reads one JSON HelperRequest per line on stdin, writes one JSON
// HelperResponse per line on stdout. P1 implements listTokens and listCerts only.
import Foundation
import Core

func emit(_ r: HelperResponse) {
    let d = (try? JSONEncoder().encode(r)) ?? Data("{\"error\":\"encode failed\"}".utf8)
    FileHandle.standardOutput.write(d)
    FileHandle.standardOutput.write(Data([0x0a]))
}

let args = CommandLine.arguments
guard let i = args.firstIndex(of: "--module"), i + 1 < args.count else {
    FileHandle.standardError.write(Data("missing --module <path>\n".utf8))
    exit(2)
}
let p11 = PKCS11(modulePath: args[i + 1])

while let line = readLine(strippingNewline: true) {
    guard let reqData = line.data(using: .utf8),
          let req = try? JSONDecoder().decode(HelperRequest.self, from: reqData) else {
        emit(.error("bad request")); continue
    }
    do {
        switch req {
        case .listTokens: emit(.tokens(try p11.listTokens()))
        case .listCerts(let serial): emit(.certs(try p11.certs(serial: serial)))
        default: emit(.error("unsupported in P1"))   // login/sign land in Task 11
        }
    } catch { emit(.error("\(error)")) }
}
