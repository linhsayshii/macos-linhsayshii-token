import Foundation
import Testing
@testable import Core

@Test func espkDirectoryDecodesBoundedNamesAndRejectsCollisions() throws {
    var bytes = [UInt8](repeating: 0, count: 1500)
    bytes[0] = 0xe0; bytes[1] = 0x24
    bytes.replaceSubrange(2..<8, with: Array("pkcs11".utf8))
    bytes.replaceSubrange(12..<20, with: Array("cert0001".utf8))
    let files = try ESPKCatalog.parse(Data(bytes))
    #expect(files.count == 1)
    #expect(files[0].id == 0x24e0)
    #expect(files[0].directory == "pkcs11")
    #expect(files[0].name == "cert0001")
    bytes.replaceSubrange(30..<60, with: Array(bytes[0..<30]))
    #expect(throws: ESPKMetadataError.duplicateFile) { try ESPKCatalog.parse(Data(bytes)) }
    #expect(throws: ESPKMetadataError.invalidCatalogSize) { try ESPKCatalog.parse(Data(bytes.dropLast())) }
}

@Test func espkAttributesPreserveIDsAndRejectMalformedLengthsAndDuplicates() throws {
    // CKA_ID contains binary zero bytes and must remain byte-exact.
    let fixture = Data([2,1,0,0, 3,0,0,0, 0,0xff,7, 8,1,0,0, 1,0,0,0, 1])
    let attrs = try ESPKAttributes(data: fixture)
    #expect(attrs.values[0x102] == Data([0,0xff,7]))
    #expect(try attrs.boolean(0x108) == true)
    #expect(throws: ESPKMetadataError.truncatedAttribute) { try ESPKAttributes(data: Data(fixture.dropLast())) }
    #expect(throws: ESPKMetadataError.duplicateAttribute) { try ESPKAttributes(data: fixture + fixture) }
    #expect(throws: ESPKMetadataError.invalidAttribute) { try attrs.uint32(0x102) }
    #expect(throws: ESPKMetadataError.truncatedAttribute) {
        try ESPKAttributes(data: Data([1,0,0,0, 0xff,0xff,0xff,0xff]))
    }
}
