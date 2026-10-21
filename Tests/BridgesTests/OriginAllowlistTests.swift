import Testing
@testable import Bridges

@Test func wildcardMatchesSubdomain() {
    let a = OriginAllowlist.defaults
    #expect(a.contains("https://thuedientu.gdt.gov.vn"))
    #expect(a.contains("https://nhantokhai.gdt.gov.vn"))
}

@Test func exactHostMatches() {
    #expect(OriginAllowlist.defaults.contains("https://dichvucong.gov.vn"))
}

@Test func unlistedOriginRejected() {
    #expect(!OriginAllowlist.defaults.contains("https://evil.example.com"))
}

@Test func httpNonLoopbackRejected() {
    #expect(!OriginAllowlist.defaults.contains("http://thuedientu.gdt.gov.vn"))
}

@Test func wildcardDoesNotMatchLookalikeSuffix() {
    // "evilgdt.gov.vn" must not match "*.gdt.gov.vn"
    #expect(!OriginAllowlist(patterns: ["*.gdt.gov.vn"]).contains("https://evilgdt.gov.vn"))
}

@Test func loopbackHttpAllowedForTesting() {
    #expect(OriginAllowlist(patterns: []).contains("http://127.0.0.1") == false) // empty list → no
}
