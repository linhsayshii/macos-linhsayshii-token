import Foundation
import Core

public struct BridgeContext: Sendable {
    public let bridge: String
    public let origin: String
    public init(bridge: String, origin: String) { self.bridge = bridge; self.origin = origin }
}

public enum SigningFailure: Error, Equatable, Sendable {
    case unknownSerial(String), userDenied, userCancelled, certExpired, bad(String), card(String)
}

/// What the P2 bridges call. Implemented by AppModel: approval → PIN → sign → audit.
/// `serial == nil` means "the only certificate" (flows without a chooser).
public protocol SigningService: Sendable {
    func certificates() async -> [CertInfo]
    func signXML(_ ctx: BridgeContext, serial: String?, xml: Data, options: XMLSignOptions) async throws -> Data
    func signCMS(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> Data
}
