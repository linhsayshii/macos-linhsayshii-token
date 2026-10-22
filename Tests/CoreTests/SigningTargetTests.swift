import Testing
@testable import Core

@Test func bridgeCertificateSerialResolvesPhysicalTokenAndRejectsAmbiguity() throws {
    let module = try #require(ModuleRegistry.lookup(atr: FastCAProfile.atr))
    func target(_ token: String, _ serial: String, _ certID: String) -> SigningTarget {
        SigningTarget(tokenSerial: token, module: module,
                      cert: CertInfo(id: certID, derB64: "", subject: "", issuer: "",
                                     serialHex: serial, notBefore: "", notAfter: ""), flags: [])
    }
    let first = target("FASTCA-USB-A", "AB01", "key-1")
    let second = target("FASTCA-USB-A", "AB02", "key-2")
    let chosen = try SigningTarget.forCertificate(serial: "ab02", in: [first, second])
    #expect(chosen.tokenSerial == "FASTCA-USB-A")
    #expect(chosen.cert.id == "key-2")
    #expect(throws: SigningTargetError.unknownCertificate) {
        try SigningTarget.forCertificate(serial: "FASTCA-USB-A", in: [first, second])
    }
    #expect(throws: SigningTargetError.ambiguousCertificate) {
        try SigningTarget.forCertificate(serial: "AB01", in: [first, target("FASTCA-USB-B", "AB01", "key-3")])
    }
}
