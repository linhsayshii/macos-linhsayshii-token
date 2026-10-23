import Foundation
import Testing
import Core
@testable import App

private func summaryCertificate(_ serial: String, expires: String) -> CertInfo {
    CertInfo(id: serial, derB64: "", subject: "CN=Fixture \(serial)", issuer: "CN=Test CA",
             serialHex: serial, notBefore: "2020-01-01", notAfter: expires)
}

@Test func tokenSummaryShowsLatestExpiryRegardlessOfEnumerationOrder() {
    let old = summaryCertificate("OLD", expires: "2025-07-28 11:09:47")
    let renewed = summaryCertificate("RENEWED", expires: "2029-07-28T11:09:47Z")
    let other = summaryCertificate("OTHER", expires: "2027-08-06")
    for certificates in [[old, renewed, other], [other, old, renewed], [renewed, other, old]] {
        let displayed = CertificateText.latestExpiry(in: certificates)
        #expect(displayed?.serialHex == "RENEWED")
        #expect(displayed?.subject == renewed.subject)
        #expect(displayed?.notAfter == renewed.notAfter)
    }
    // The same instant expressed in different zones must be compared as dates.
    let earlier = summaryCertificate("EARLIER", expires: "2029-07-28T12:00:00+07:00")
    #expect(CertificateText.latestExpiry(in: [earlier, renewed])?.serialHex == "RENEWED")
}

@Test func tokenSummaryHandlesMissingDatesAndKeepsTokenScopesSeparate() {
    let unknown = summaryCertificate("UNKNOWN", expires: "unavailable")
    let expired = summaryCertificate("EXPIRED", expires: "2025-01-01")
    let otherToken = summaryCertificate("OTHER-TOKEN", expires: "2035-01-01")
    #expect(CertificateText.latestExpiry(in: [unknown, expired])?.serialHex == "EXPIRED")
    #expect(CertificateText.latestExpiry(in: [otherToken])?.serialHex == "OTHER-TOKEN")
    #expect(CertificateText.latestExpiry(in: [unknown])?.serialHex == "UNKNOWN")
    #expect(CertificateText.latestExpiry(in: []) == nil)
}
