import Foundation
import Security
import Testing
import X509
import SwiftASN1
import Core
@testable import TokenHelper

private func attributes(_ values: [(UInt32, Data)]) -> Data {
    var data = Data()
    for (type, value) in values {
        for n in [type, UInt32(value.count)] { data.append(contentsOf: (0..<4).map { UInt8((n >> ($0 * 8)) & 255) }) }
        data.append(value)
    }
    return data
}

private final class Card: ESPKCardConnection {
    let key: SecKey
    let der: Data
    var files: [UInt16: Data]
    var reads: [UInt16] = []
    var auths = 0, signs = 0, closes = 0
    var result: LoginResult = .ok
    var loginError = false, signError = false, corrupt = false
    init() throws {
        key = try #require(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false] as CFDictionary, nil))
        let pub = try #require(SecKeyCopyPublicKey(key))
        let encoded = try #require(SecKeyCopyExternalRepresentation(pub, nil) as Data?)
        // Ephemeral Security.framework fixture exports canonical PKCS#1 RSA-2048.
        #expect(Array(encoded.prefix(9)) == [0x30,0x82,1,0x0a,2,0x82,1,1,0])
        let modulus = encoded.subdata(in: 9..<265)
        let privateKey = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("Synthetic EFY backend fixture") }
        let cert = try Certificate(version: .v3, serialNumber: .init(bytes: [1]), publicKey: privateKey.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 0), notValidAfter: Date(timeIntervalSince1970: 1),
            issuer: name, subject: name, extensions: Certificate.Extensions {}, issuerPrivateKey: privateKey)
        var serializer = DER.Serializer(); try serializer.serialize(cert)
        der = Data(serializer.serializedBytes)
        var catalog = [UInt8](repeating: 0, count: 1500)
        // Deliberately different FIDs from research hardware; no fixed 24C0/A020.
        for (index, record) in [(0x2500, "", "cardid"), (0x2560, "pkcs11", "cert0007"), (0x2520, "pkcs11", "prvk0007")].enumerated() {
            let pos = index * 30
            catalog[pos] = UInt8(record.0 & 255); catalog[pos + 1] = UInt8(record.0 >> 8)
            catalog.replaceSubrange((pos + 2)..<(pos + 2 + record.1.utf8.count), with: record.1.utf8)
            catalog.replaceSubrange((pos + 12)..<(pos + 12 + record.2.utf8.count), with: record.2.utf8)
        }
        files = [0x6f01: Data(catalog), 0x2500: Data(repeating: 0x77, count: 16),
            0x2560: attributes([(0,Data([1,0,0,0])), (0x102,Data([0,7])), (0x11,der)]),
            0x2520: attributes([(0,Data([3,0,0,0])), (0x100,Data([0,0,0,0])), (0x108,Data([1])),
                (0x102,Data([0,7])), (0x120,modulus), (0x122,Data([1,0,1])), (0x80000100,Data([0xe0,0xa0,0,0]))])]
    }
    func read(_ fid: UInt16) throws -> Data { reads.append(fid); return try #require(files[fid]) }
    func login(_ bytes: [UInt8]) throws -> LoginResult {
        auths += 1
        if loginError { throw ESPKError("synthetic uncertain authentication") }
        return result
    }
    func sign(key: UInt16, block: [UInt8]) throws -> Data {
        signs += 1
        #expect(key == 0xa0e0)
        #expect(block.count == 256 && block.prefix(2) == [0,1])
        if signError { throw ESPKError("synthetic uncertain signature") }
        let separator = try #require(block.dropFirst(2).firstIndex(of: 0))
        #expect(block[2..<separator].allSatisfy { $0 == 0xff })
        let payload = Data(block[(separator + 1)...])
        var signature = try #require(SecKeyCreateSignature(self.key, .rsaSignatureDigestPKCS1v15Raw, payload as CFData, nil) as Data?)
        if corrupt { signature[0] ^= 1 }
        return signature
    }
    func close() { closes += 1 }
}

private func backend(_ card: Card, profile: NativeESPKProfile = .efy) -> ESPKBackend {
    ESPKBackend(profile: profile, scan: { [("synthetic reader", profile.atr)] }, connect: { _ in card })
}

@Test func efyReadsDynamicCatalogAndStableCardIdentityWithoutPIN() throws {
    let card = try Card(), b = backend(card)
    let token = try #require(b.listTokens().first)
    #expect(token.label == "EFY-CA" && token.serial.hasPrefix("EFY-"))
    #expect(token.flags == ["PIN_RETRIES_UNKNOWN"])
    #expect(try b.certs(serial: token.serial).first?.id == "0007")
    let moved = ESPKBackend(profile: .efy, scan: { [("renumbered reader", EfyProfile.atr)] }, connect: { _ in card })
    #expect(try moved.listTokens().first?.serial == token.serial)
    #expect(card.auths == 0 && card.signs == 0 && card.closes == 3)
    #expect(Set(card.reads) == [0x6f01,0x2500,0x2560,0x2520])
    #expect(try backend(card, profile: .fastca).listTokens().first?.serial != token.serial)
}

@Test(arguments: ["empty-cardid", "bad-key", "duplicate-file", "bad-cert"])
func efyRejectsBadPreflightBeforeAnyPIN(fault: String) throws {
    let card = try Card(), b = backend(card)
    let serial = try #require(b.listTokens().first?.serial)
    switch fault {
    case "empty-cardid": card.files[0x2500] = Data()
    case "bad-key": card.files[0x2520] = attributes([(0,Data([3,0,0,0]))])
    case "duplicate-file":
        var catalog = try #require(card.files[0x6f01]); catalog.replaceSubrange(90..<120, with: catalog[0..<30]); card.files[0x6f01] = catalog
    default: card.files[0x2560] = attributes([(0,Data([1,0,0,0])), (0x102,Data([0,7])), (0x11,Data([0x30,0]))])
    }
    #expect(throws: (any Error).self) { try b.login(serial: serial, pin: "fixture") }
    #expect(card.auths == 0 && card.signs == 0 && card.closes == 2)
}

@Test(arguments: ["incorrect", "locked", "transport"])
func efyAuthenticationFailureClosesSessionAndNeverRetries(fault: String) throws {
    let card = try Card(), b = backend(card)
    let serial = try #require(b.listTokens().first?.serial)
    if fault == "transport" { card.loginError = true }
    else { card.result = fault == "locked" ? .pinLocked : .pinIncorrect(retriesLeft: 2) }
    if card.loginError { #expect(throws: (any Error).self) { try b.login(serial: serial, pin: "fixture") } }
    else { #expect(try b.login(serial: serial, pin: "fixture") == card.result) }
    #expect(throws: (any Error).self) { try b.sign(serial: serial, certId: "0007", mech: .rsaPKCS, data: [1]) }
    b.logout(serial: serial)
    #expect(card.auths == 1 && card.signs == 0 && card.closes == 2)
}

@Test(arguments: [SignMech.sha256RSA, .rsaPKCS])
func efySignsExactlySelectedKeyAndVerifiesBeforeReturning(mech: SignMech) throws {
    let card = try Card(), b = backend(card)
    let serial = try #require(b.listTokens().first?.serial)
    #expect(try b.login(serial: serial, pin: "fixture") == .ok)
    #expect(throws: (any Error).self) { try b.login(serial: serial, pin: "fixture") }
    let message = Data("local synthetic message".utf8)
    let payload = Data(try DigestInfo.sha256Block(message))
    let signature = try b.sign(serial: serial, certId: "0007", mech: mech, data: Array(mech == .sha256RSA ? message : payload))
    #expect(RSAPKCS1v15.verify(signature: Data(signature), payload: payload, certificateDER: card.der))
    #expect(!RSAPKCS1v15.verify(signature: Data(signature), payload: payload + Data([0]), certificateDER: card.der))
    #expect(throws: (any Error).self) { try b.sign(serial: serial, certId: "0007", mech: mech, data: Array(payload)) }
    #expect(card.auths == 1 && card.signs == 1 && card.closes == 2)
}

@Test(arguments: ["wrong-id", "unsupported", "corrupt", "transport"])
func efySigningFailureAlwaysClosesWithoutFallback(fault: String) throws {
    let card = try Card(), b = backend(card)
    let serial = try #require(b.listTokens().first?.serial)
    #expect(try b.login(serial: serial, pin: "fixture") == .ok)
    card.corrupt = fault == "corrupt"; card.signError = fault == "transport"
    #expect(throws: (any Error).self) {
        try b.sign(serial: serial, certId: fault == "wrong-id" ? "ffff" : "0007",
            mech: fault == "unsupported" ? .rsaX509 : .sha256RSA, data: [1])
    }
    #expect(card.auths == 1 && card.signs == (["wrong-id", "unsupported"].contains(fault) ? 0 : 1) && card.closes == 2)
}

@Test func efyRejectsAmbiguousCardIDsAndUnsupportedReadersBeforePIN() throws {
    let card = try Card(), b = backend(card)
    let serial = try #require(b.listTokens().first?.serial)
    let ambiguous = ESPKBackend(profile: .efy, scan: { [("r1", EfyProfile.atr), ("r2", EfyProfile.atr)] }, connect: { _ in card })
    #expect(throws: (any Error).self) { try ambiguous.login(serial: serial, pin: "fixture") }
    #expect(card.auths == 0 && card.closes == 3)
    let other = ESPKBackend(profile: .efy, scan: { [("other", FastCAProfile.atr)] }, connect: { _ in Issue.record("Wrong profile connected"); return card })
    #expect(try other.listTokens().isEmpty)
    #expect(throws: (any Error).self) { try b.login(serial: serial, pin: "❌") }
    #expect(card.auths == 0 && card.closes == 3)
}
