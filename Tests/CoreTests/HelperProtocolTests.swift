import Testing
import Foundation
@testable import Core

@Test func requestRoundTrips() throws {
    let req = HelperRequest.sign(serial: "83772", certId: "01", mech: .sha256RSA, dataB64: "AAAA")
    let data = try JSONEncoder().encode(req)
    let back = try JSONDecoder().decode(HelperRequest.self, from: data)
    #expect(back == req)
}

@Test func loginResultEncodesRetries() throws {
    let data = try JSONEncoder().encode(HelperResponse.loginResult(.pinIncorrect(retriesLeft: 2)))
    let s = String(decoding: data, as: UTF8.self)
    #expect(s.contains("pinIncorrect"))
    #expect(s.contains("2"))
}

@Test func mechRawValues() {
    #expect(SignMech.sha256RSA.rawValue == "SHA256_RSA_PKCS")
    #expect(SignMech.rsaPKCS.rawValue == "RSA_PKCS")
}
