public enum ModuleArch: Sendable { case universal, x86_64 }
public enum ModuleTokenScope: Sendable { case module, reader }
public enum ModuleBackend: Sendable { case pkcs11, fastca, oneca, efy, espkDiscovery }

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
    // Legacy issuer hints select an installed middleware candidate. Only a
    // successful reader/token/certificate preflight produces usable identities.
    private static let table: [UInt8: ModuleInfo] = [
        0x32: ModuleInfo(ca: "VNPT",  moduleName: "libvnptca_p11_v8.dylib", arch: .universal),
        0x59: ModuleInfo(ca: "NC-CA", moduleName: "ncca_csp11_v1.dylib",    arch: .universal),
        0x61: ModuleInfo(ca: "CMC",   moduleName: "cmcca_csp11_v1.dylib",   arch: .universal),
        0x72: ModuleInfo(ca: "I-CA",  moduleName: "ica_csp11_v1.dylib",     arch: .universal),
        0x69: ModuleInfo(ca: "FastCA", moduleName: "FastCA-ESPK", arch: .universal,
                         isExperimental: true, tokenScope: .reader, backend: .fastca),
    ]

    public static let espkDiscovery = ModuleInfo(ca: "ESPK", moduleName: "ESPK-Discovery", arch: .universal,
        isExperimental: true, tokenScope: .reader, backend: .espkDiscovery)

    public static func lookup(atr: [UInt8]) -> ModuleInfo? { candidates(atr: atr).first }

    /// Ordered, bounded public probes. Never enumerate arbitrary libraries or
    /// fall back from a failed PIN attempt to another provider.
    public static func candidates(atr: [UInt8], includeVendorDiscovery: Bool = false) -> [ModuleInfo] {
        let known = preferredCandidates(atr: atr)
        guard includeVendorDiscovery, known.isEmpty, TokenATR(atr) != nil,
              TokenCompatibility.knownUnsupportedModel(atr: atr) == nil else { return known }
        // Bounded to the already registered PKCS#11 providers. Their public
        // enumeration must report this exact physical reader before any target
        // is accepted. Never load arbitrary files or OEM wrappers such as F3.
        return table.values.filter { $0.backend == .pkcs11 }.sorted { $0.ca < $1.ca }.map {
            ModuleInfo(ca: $0.ca, moduleName: $0.moduleName, arch: $0.arch,
                       isExperimental: true, tokenScope: .reader, backend: .pkcs11)
        }
    }

    private static func preferredCandidates(atr: [UInt8]) -> [ModuleInfo] {
        guard TokenATR(atr) != nil else { return [] }
        if atr == OneCAProfile.atr {
            return [ModuleInfo(ca: "OneCA", moduleName: "libcryptoida_pkcs11_f2.dylib", arch: .universal,
                              isExperimental: true, tokenScope: .reader, backend: .oneca)]
        }
        if EfyProfile.matches(atr: atr) {
            return [ModuleInfo(ca: "EFY-CA", moduleName: "EFY-ESPK", arch: .universal,
                               isExperimental: true, tokenScope: .reader, backend: .efy)]
        }
        if FastCAProfile.matches(atr: atr), let fastca = table[0x69] { return [fastca] }
        if ESPKFamily.matches(atr: atr) {
            if let vendor = table[atr[19]], vendor.backend == .pkcs11 { return [vendor, espkDiscovery] }
            return [espkDiscovery]
        }
        guard atr.count > 19, atr[19] != 0x69 else { return [] }
        return table[atr[19]].map { [$0] } ?? []
    }
}
