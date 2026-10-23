import Foundation

/// The observed OneCAV3 profile. Generic Longmai readers must never be routed
/// by the Feitian customer-byte table.
public enum OneCAProfile {
    public static let atr: [UInt8] = [0x3b,0x9f,0x11,0x81,0x31,0xfe,0x9f,0x00,
        0x6a,0x6d,0x54,0x6f,0x6b,0x65,0x6e,0x2d,0x5b,0x00,0x05,0x81,0x90,0x00,0x61]
    public static let readerFilter = "longmai mtoken onecav3"
    public static let moduleSHA256 = "b4e1b8d804ebf444b3c1acc7222a27dfb5d42cea7f6c51d3e067bdcbf2bbef0c"

    public static func matches(reader: String) -> Bool {
        reader.lowercased().contains(readerFilter)
    }

    /// Slot descriptions in this module are synthetic. Until the vendor exposes
    /// a measured slot/reader mapping, accept only one matching physical reader
    /// and one token, and fail closed for multiple Longmai devices.
    public static func bind(readers: [(reader: String, atr: [UInt8])], tokens: [TokenInfo]) -> [TokenInfo] {
        let candidates = readers.filter { matches(reader: $0.reader) }
        guard candidates.count == 1, let reader = candidates.first, reader.atr == atr,
              tokens.count == 1, let token = tokens.first, !token.serial.isEmpty else { return [] }
        return [TokenInfo(slot: token.slot, reader: reader.reader, serial: token.serial,
                          label: token.label, flags: token.flags)]
    }
}
