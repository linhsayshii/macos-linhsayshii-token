import Foundation

/// One command's transient PIN. Never published, persisted or reused by another
/// command; the owner clears it with defer on every terminal path.
@MainActor final class MinvoicePINSession {
    private var value: String?
    func pin(prompt: () async throws -> String) async throws -> String {
        try Task.checkCancellation()
        if let value { return value }
        let entered = try await prompt()
        try Task.checkCancellation()
        guard !entered.isEmpty else { throw CancellationError() }
        value = entered
        return entered
    }
    func clear() { value = nil }
}
