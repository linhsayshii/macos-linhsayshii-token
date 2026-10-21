public enum ModuleArch: Sendable { case universal, x86_64 }

public struct ModuleInfo: Sendable, Equatable {
    public let ca: String
    public let moduleName: String
    public let arch: ModuleArch
    public init(ca: String, moduleName: String, arch: ModuleArch) {
        self.ca = ca; self.moduleName = moduleName; self.arch = arch
    }
}

public enum ModuleRegistry {
    // Keyed by ATR customer byte (index 19). FastCA (0x69) and EFY (0x51) have
    // no usable macOS module yet, so they are intentionally absent.
    private static let table: [UInt8: ModuleInfo] = [
        0x32: ModuleInfo(ca: "VNPT",  moduleName: "libvnptca_p11_v8.dylib", arch: .universal),
        0x59: ModuleInfo(ca: "NC-CA", moduleName: "ncca_csp11_v1.dylib",    arch: .universal),
        0x61: ModuleInfo(ca: "CMC",   moduleName: "cmcca_csp11_v1.dylib",   arch: .universal),
        0x72: ModuleInfo(ca: "I-CA",  moduleName: "ica_csp11_v1.dylib",     arch: .universal),
    ]

    public static func lookup(atr: [UInt8]) -> ModuleInfo? {
        guard atr.count > 19 else { return nil }
        return table[atr[19]]
    }
}
