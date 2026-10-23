import Foundation

public enum FastCAProfile {
    /// Only the observed ESPK card profile is enabled. Customer byte alone is
    /// insufficient evidence that a different applet supports these commands.
    public static let atr: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
                                     0x05,0x10,0x52,0x39,0x71,0xdf,0,0,0x69,0,0,0x11]
}
