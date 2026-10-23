import Foundation

public enum TokenFailureCode: String, Codable, Sendable {
    case runtimeUnavailable, transport, incompatibleMetadata, unsupportedOperation
}

public struct TokenFailure: Codable, Equatable, Sendable {
    public let code: TokenFailureCode
    public let message: String
    public init(code: TokenFailureCode, message: String) { self.code = code; self.message = message }
}

public enum TokenCompatibility {
    /// A public metadata match does not establish an unobserved PIN protocol.
    public static let discoveryOnlyFlag = "SIGNING_PROTOCOL_UNVERIFIED"
    public static func permitsSigning(flags: [String]) -> Bool { !flags.contains(discoveryOnlyFlag) }

    public struct KnownUnsupportedModel: Sendable {
        public let issuer, hardwareFamily, reason: String
    }
    public static func knownUnsupportedModel(atr: [UInt8]) -> KnownUnsupportedModel? {
        // OneCA V1's documented registry entry is exact; no invented Longmai
        // wildcard or automatic F2/F3 module loading is justified by it.
        let onecaV1: [UInt8] = [0x3b,0x9f,0x11,0x81,0x31,0xfe,0x9f,0,0x6a,0x6d,0x54,0x6f,
            0x6b,0x65,0x6e,0x2d,0x5a,0,0x05,0x81,0x90,0,0x60]
        guard atr == onecaV1 else { return nil }
        return KnownUnsupportedModel(issuer: "OneCA V1", hardwareFamily: "Longmai mToken",
            reason: "Đã nhận diện OneCA V1 (Longmai); chưa có backend macOS đã xác minh cho dòng này")
    }

    public struct Provider: Sendable {
        public let issuerHint, hardwareFamily, discoveryRule, runtime: String
        public let backend: ModuleBackend
    }
    /// Issuer/OEM and protocol are separate axes. This describes implemented
    /// providers, not a claim that every device sold by an issuer is supported.
    public static let providers: [Provider] = [
        .init(issuerHint: "FastCA", hardwareFamily: ESPKFamily.name, discoveryRule: "OpenSC family + customer 69 + ESPK preflight", runtime: "OpenSC 0.27.1", backend: .fastca),
        .init(issuerHint: "EFY-CA", hardwareFamily: ESPKFamily.name, discoveryRule: "OpenSC family + customer 51 + ESPK preflight", runtime: "OpenSC 0.27.1", backend: .efy),
        .init(issuerHint: "Unknown / other issuer", hardwareFamily: ESPKFamily.name, discoveryRule: "OpenSC family + public ESPK preflight; discovery only", runtime: "OpenSC 0.27.1", backend: .espkDiscovery),
        .init(issuerHint: "OneCA V3", hardwareFamily: "Longmai mToken", discoveryRule: "Measured ATR + unique physical reader/token", runtime: "Hash-pinned CryptoIDA F2", backend: .oneca),
        .init(issuerHint: "VNPT / NC-CA / CMC / I-CA", hardwareFamily: "Vendor middleware", discoveryRule: "Registered PKCS#11 provider + physical reader match for unseen ATR", runtime: "Matching installed vendor module", backend: .pkcs11),
    ]
}
