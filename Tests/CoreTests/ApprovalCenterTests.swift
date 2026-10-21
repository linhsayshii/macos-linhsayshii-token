import Testing
import Foundation
@testable import Core

@Test func firstRequestPrompts() async {
    let c = ApprovalCenter(now: { Date(timeIntervalSince1970: 0) })
    #expect(await c.decide(origin: "https://thuedientu.gdt.gov.vn", certSerial: "01") == .prompt)
}

@Test func allowedSessionAutoApprovesWithinWindow() async {
    let box = TimeBox()
    let c = ApprovalCenter(now: { box.now })
    await c.allow(origin: "https://thuedientu.gdt.gov.vn", certSerial: "01", minutes: 10)
    box.now = Date(timeIntervalSince1970: 300)   // +5 min
    #expect(await c.decide(origin: "https://thuedientu.gdt.gov.vn", certSerial: "01") == .allowedSession)
}

@Test func sessionExpires() async {
    let box = TimeBox()
    let c = ApprovalCenter(now: { box.now })
    await c.allow(origin: "https://x.gdt.gov.vn", certSerial: "01", minutes: 10)
    box.now = Date(timeIntervalSince1970: 601)   // +10 min 1 s
    #expect(await c.decide(origin: "https://x.gdt.gov.vn", certSerial: "01") == .prompt)
}

@Test func differentSerialPrompts() async {
    let c = ApprovalCenter(now: { Date(timeIntervalSince1970: 0) })
    await c.allow(origin: "https://x.gdt.gov.vn", certSerial: "01", minutes: 10)
    #expect(await c.decide(origin: "https://x.gdt.gov.vn", certSerial: "02") == .prompt)
}

final class TimeBox: @unchecked Sendable { var now = Date(timeIntervalSince1970: 0) }
