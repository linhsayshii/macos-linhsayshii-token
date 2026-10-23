import Foundation

public enum FastCAProfile {
    /// Measured fixtures and established PIN-contract mappings. Family-based
    /// public discovery is separate from permission to authenticate.
    public static let atr: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
                                     0x05,0x10,0x52,0x39,0x71,0xdf,0,0,0x69,0,0,0x11]
    /// Second physical card: public ESPK catalog, signing metadata and matching
    /// certificate key verified on 2026-10-23, before any authentication.
    public static let atr0631: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
                                         0x05,0x10,0x06,0x31,0x71,0xdf,0,0,0x69,0,0,0x4d]
    public static let supportedATRs = [atr, atr0631]
    /// Driver-family hint for public discovery. Authentication is a separate
    /// capability; a previously unseen firmware must not inherit a PIN scheme.
    public static func matches(atr: [UInt8]) -> Bool { ESPKFamily.customer(atr: atr) == 0x69 }
    public static func hasVerifiedPINProtocol(atr: [UInt8]) -> Bool { supportedATRs.contains(atr) }
}
