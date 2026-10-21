import Foundation

public enum ApprovalDecision: Sendable, Equatable { case allowedSession, prompt, denied }

/// Session-based approval, keyed by (origin, cert serial). A granted session
/// auto-approves until it expires; otherwise the caller must prompt the user.
public actor ApprovalCenter {
    private struct Key: Hashable { let origin: String; let serial: String }
    private var sessions: [Key: Date] = [:]   // key -> expiry
    private let now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = { Date() }) { self.now = now }

    public func allow(origin: String, certSerial: String, minutes: Int) {
        sessions[Key(origin: origin, serial: certSerial)] = now().addingTimeInterval(Double(minutes) * 60)
    }

    public func decide(origin: String, certSerial: String) -> ApprovalDecision {
        let k = Key(origin: origin, serial: certSerial)
        if let exp = sessions[k], exp > now() { return .allowedSession }
        sessions[k] = nil
        return .prompt
    }
}
