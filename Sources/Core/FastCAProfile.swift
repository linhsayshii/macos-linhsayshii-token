import Foundation

public enum FastCAProfile {
    /// Only the observed ESPK card profile is enabled. Customer byte alone is
    /// insufficient evidence that a different applet supports these commands.
    public static let atr: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
                                     0x05,0x10,0x52,0x39,0x71,0xdf,0,0,0x69,0,0,0x11]
}

public struct ESPKSigningIdentity: Equatable, Sendable {
    public let id: Data
    public let certificateDER: Data
    public let modulus: Data
    public let exponent: Data
    public let keyReference: UInt16

    public static func resolve(certificates: [ESPKAttributes], keys: [ESPKAttributes]) throws -> [Self] {
        var certificatesByID: [Data: Data] = [:]
        for cert in certificates {
            guard try cert.uint32(0) == 1,
                  let id = cert.values[0x102], !id.isEmpty, id.count <= 64,
                  let der = cert.values[0x11], !der.isEmpty else {
                throw ESPKMetadataError.invalidAttribute
            }
            guard certificatesByID.updateValue(der, forKey: id) == nil else {
                throw ESPKMetadataError.duplicateAttribute
            }
        }
        var identities: [Self] = []
        var keyIDs = Set<Data>()
        for key in keys {
            guard try key.uint32(0) == 3, try key.uint32(0x100) == 0,
                  try key.boolean(0x108) == true else { continue }
            guard let id = key.values[0x102], !id.isEmpty, id.count <= 64,
                  let modulusData = key.values[0x120], let exponent = key.values[0x122],
                  let reference = try key.uint32(0x80000100) else {
                throw ESPKMetadataError.invalidAttribute
            }
            guard keyIDs.insert(id).inserted else { throw ESPKMetadataError.duplicateAttribute }
            let modulus = Data(modulusData.drop(while: { $0 == 0 }))
            // First supported profile: RSA 2048, exponent 65537, ESPK key EF.
            guard modulus.count == 256, let first = modulus.first, first & 0x80 != 0,
                  exponent == Data([1,0,1]), (0xa000...0xafff).contains(reference),
                  let der = certificatesByID[id] else { continue }
            identities.append(Self(id: id, certificateDER: der, modulus: modulus,
                                   exponent: exponent, keyReference: UInt16(reference)))
        }
        return identities
    }
}
