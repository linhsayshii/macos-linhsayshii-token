public enum ModuleArch: Sendable { case universal, x86_64 }
public enum ModuleTokenScope: Sendable { case module, reader }
public enum ModuleBackend: Sendable { case pkcs11, fastca }

public struct ModuleInfo: Sendable, Equatable {
    public let ca: String
    public let moduleName: String
    public let arch: ModuleArch
    public let isExperimental: Bool
    public let tokenScope: ModuleTokenScope
    public let backend: ModuleBackend
    public init(ca: String, moduleName: String, arch: ModuleArch,
                isExperimental: Bool = false, tokenScope: ModuleTokenScope = .module,
                backend: ModuleBackend = .pkcs11) {
        self.ca = ca; self.moduleName = moduleName; self.arch = arch
        self.isExperimental = isExperimental; self.tokenScope = tokenScope
        self.backend = backend
    }

    /// Generic middleware may enumerate other CAs too. Require its reported
    /// reader to match PC/SC before associating certificates or signing targets.
    /// An unknown slot description deliberately yields no target.
    public func tokensForReader(_ reader: String, from tokens: [TokenInfo]) -> [TokenInfo] {
        tokenScope == .reader ? tokens.filter { $0.reader == reader } : tokens
    }
}

public enum ModuleRegistry {
    // Keyed by ATR customer byte. FastCA additionally requires the exact tested
    // ESPK profile before the native backend is selected. EFY is absent.
    private static let table: [UInt8: ModuleInfo] = [
        0x32: ModuleInfo(ca: "VNPT",  moduleName: "libvnptca_p11_v8.dylib", arch: .universal),
        0x59: ModuleInfo(ca: "NC-CA", moduleName: "ncca_csp11_v1.dylib",    arch: .universal),
        0x61: ModuleInfo(ca: "CMC",   moduleName: "cmcca_csp11_v1.dylib",   arch: .universal),
        0x72: ModuleInfo(ca: "I-CA",  moduleName: "ica_csp11_v1.dylib",     arch: .universal),
        0x69: ModuleInfo(ca: "FastCA", moduleName: "FastCA-ESPK", arch: .universal,
                         isExperimental: true, tokenScope: .reader, backend: .fastca),
    ]

    public static func lookup(atr: [UInt8]) -> ModuleInfo? {
        guard atr.count > 19 else { return nil }
        if atr[19] == 0x69 && atr != FastCAProfile.atr { return nil }
        return table[atr[19]]
    }
}
