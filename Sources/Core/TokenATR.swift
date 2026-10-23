/// ISO 7816-3 framing validation. ATRs are routing hints, never a PIN protocol.
public struct TokenATR: Sendable, Equatable {
    public let bytes: [UInt8]
    public let historicalBytes: [UInt8]
    public let protocols: [UInt8]

    public init?(_ bytes: [UInt8]) {
        guard (2...33).contains(bytes.count), bytes[0] == 0x3b || bytes[0] == 0x3f else { return nil }
        var index = 2, presence = bytes[1] >> 4, protocols: [UInt8] = []
        while presence != 0 {
            var next: UInt8 = 0
            for bit in [UInt8(1), 2, 4, 8] where presence & bit != 0 {
                guard index < bytes.count else { return nil }
                let value = bytes[index]; index += 1
                if bit == 8 { protocols.append(value & 15); next = value >> 4 }
            }
            presence = next
        }
        let historicalCount = Int(bytes[1] & 15)
        let hasChecksum = protocols.contains { $0 != 0 }
        guard index + historicalCount + (hasChecksum ? 1 : 0) == bytes.count else { return nil }
        if hasChecksum, bytes.dropFirst().reduce(UInt8(0), ^) != 0 { return nil }
        self.bytes = bytes
        historicalBytes = Array(bytes[index..<(index + historicalCount)])
        self.protocols = protocols.isEmpty ? [0] : protocols
    }
}

/// OpenSC 0.27.1 card-epass2003.c, epass2003_atrs. This family includes several
/// issuers and applets. A match permits public discovery, not authentication.
public enum ESPKFamily {
    public static let name = "Feitian ePass2003 / FTCOS"
    private static let pattern: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
        0x05,0,0,0,0x71,0xdf,0,0,0,0,0,0]
    private static let mask: [UInt8] = [0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0,0,0,0xff,0xff,0xff,0xff,0,0,0,0]

    public static func matches(atr: [UInt8]) -> Bool {
        guard TokenATR(atr) != nil, atr.count == pattern.count else { return false }
        return atr.indices.allSatisfy { atr[$0] & mask[$0] == pattern[$0] & mask[$0] }
    }
    public static func customer(atr: [UInt8]) -> UInt8? { matches(atr: atr) ? atr[19] : nil }
}
