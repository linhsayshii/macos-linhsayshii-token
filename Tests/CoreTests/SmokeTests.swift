import Testing
@testable import Core

@Test func coreVersionIsP1() {
    #expect(Core.version == "0.1.0")
}
