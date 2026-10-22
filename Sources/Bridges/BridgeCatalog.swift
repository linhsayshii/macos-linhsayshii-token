import Foundation

public enum BridgeKind: String, CaseIterable, Sendable {
    case ctsign, esigner, esignerAlternate, vnpt, vnptDVC, minvoice
}

public struct BridgeEndpoint: Identifiable, Sendable {
    public var id: BridgeKind { kind }
    public let kind: BridgeKind
    public let name: String
    public let port: Int
    public let tls: Bool
    public let path: String
}

/// One inventory shared by startup and status UI, including both alternate ports.
public enum BridgeCatalog {
    public enum ConfigurationError: Error { case invalidPortOffset }
    public static func endpoints(offset: Int = 0) throws -> [BridgeEndpoint] {
        guard (0...(65535 - 32001)).contains(offset) else { throw ConfigurationError.invalidPortOffset }
        return [
            BridgeEndpoint(kind: .ctsign, name: "CTSigningHub", port: 32001 + offset, tls: false, path: "/api"),
            BridgeEndpoint(kind: .esigner, name: "eSigner", port: 8768 + offset, tls: false, path: "/plugin/sign"),
            BridgeEndpoint(kind: .esignerAlternate, name: "eSigner", port: 8769 + offset, tls: false, path: "/plugin/sign"),
            BridgeEndpoint(kind: .vnpt, name: "VNPT-CA", port: 4433 + offset, tls: true, path: "/plugin"),
            BridgeEndpoint(kind: .vnptDVC, name: "VNPT-CA · DVC", port: 4434 + offset, tls: true, path: "/plugin"),
            BridgeEndpoint(kind: .minvoice, name: "Minvoice", port: 16080 + offset, tls: false, path: "/signalr")
        ]
    }
}
