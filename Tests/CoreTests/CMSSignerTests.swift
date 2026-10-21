import Testing
import Foundation
@testable import Core

private func verify(_ pki: TestPKI, content: Data, sig: Data) throws -> (status: Int32, stderr: String) {
    let d = try TempDir()
    try content.write(to: d["c.bin"]); try sig.write(to: d["s.der"])
    if ProcessInfo.processInfo.environment["CMS_DEBUG"] != nil { print("DBG", d.url.path, pki.certPEMPath) }
    return try Tool.run("openssl", ["cms", "-verify", "-binary", "-inform", "DER", "-in", d["s.der"].path,
                                    "-content", d["c.bin"].path, "-CAfile", pki.certPEMPath,
                                    "-purpose", "any", "-out", "/dev/null"])
}

@Test(.enabled(if: Tool.exists("openssl")), arguments: [HashAlg.sha256, HashAlg.sha1])
func cmsDetachedVerifiesWithOpenSSL(h: HashAlg) async throws {
    let pki = try TestPKI.make()
    let content = Data("<a>hello</a>".utf8)
    let der = try await CMSSigner.signDetached(content: content, signer: pki.signer, hash: h)
    let ok = try verify(pki, content: content, sig: der)
    #expect(ok.status == 0, "\(ok.stderr)")
    let bad = try verify(pki, content: Data("<a>HELLO</a>".utf8), sig: der)
    #expect(bad.status != 0)
}
