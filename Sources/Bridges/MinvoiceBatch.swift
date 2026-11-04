import Foundation
import Core

/// Resource policies of TokenSigner, separate from the vendor's cash group size.
public enum MinvoiceBatchLimits {
    public static let maxInvoices = 1_000
    public static let commandBytes = 65_536
    public static let cashGroupSize = 100
    /// Plugin default when tenant-setting-sign is null; smaller is always safe.
    public static let ordinaryGroupSize = 2
    public static let archiveBytes = 16 << 20
    public static let documentBytes = 8 << 20
    public static let expandedBytes = 32 << 20
    public static let maxDocuments = 100
    public static let uploadBytes = 40 << 20
}

/// Counts and states only: never retains credentials, invoice IDs or XML.
public struct MinvoiceBatchProgress: Sendable, Equatable {
    public enum State: String, Sendable { case pending, downloading, signing, uploading, acknowledged, failed, cancelled, uploadUncertain }
    public enum Outcome: String, Sendable { case running, completed, failed, cancelled, uploadUncertain }
    public struct Group: Sendable, Equatable {
        public let invoices: Int
        public var documents = 0
        public var signedDocuments = 0
        public var state: State = .pending
    }
    public var groups: [Group]
    public var outcome: Outcome = .running
    public var checkedInvoices = 0
    public internal(set) var diagnostic: String?
    public var totalInvoices: Int { groups.reduce(0) { $0 + $1.invoices } }
    public var acknowledged: Int { groups.filter { $0.state == .acknowledged }.reduce(0) { $0 + $1.invoices } }
    public var uncertain: Int { groups.filter { $0.state == .uploadUncertain }.reduce(0) { $0 + $1.invoices } }
    public var notStarted: Int { groups.filter { $0.state == .pending }.reduce(0) { $0 + $1.invoices } }
    public var documents: Int { groups.reduce(0) { $0 + $1.documents } }
    public var signedDocuments: Int { groups.reduce(0) { $0 + $1.signedDocuments } }
    public var summary: String {
        let counts = "Minvoice: đã xác nhận upload \(acknowledged)/\(totalInvoices) hóa đơn"
        if outcome == .completed { return counts + " · \(signedDocuments) XML đã ký" }
        if uncertain > 0 { return counts + " · chưa rõ \(uncertain) · chưa chạy \(notStarted). Kiểm tra trên Minvoice trước khi gửi lại." }
        if outcome == .cancelled { return counts + " · đã hủy · chưa chạy \(notStarted)" }
        if outcome == .failed { return counts + " · đã dừng · chưa chạy \(notStarted)" }
        if let index = groups.firstIndex(where: { [.downloading, .signing, .uploading].contains($0.state) }) {
            return counts + " · nhóm \(index + 1)/\(groups.count) · XML \(groups[index].signedDocuments)/\(groups[index].documents)"
        }
        return counts + " · kiểm tra \(checkedInvoices)/\(totalInvoices)"
    }
    var payload: [String: Any] {
        var result: [String: Any] = ["requestedInvoices": totalInvoices, "checkedInvoices": checkedInvoices, "uploadAcknowledgedInvoices": acknowledged,
         "uploadUncertainInvoices": uncertain, "notStartedInvoices": notStarted,
         "documents": documents, "signedDocuments": signedDocuments, "outcome": outcome.rawValue,
         "groups": groups.enumerated().map { index, group in
             ["index": index + 1, "invoiceCount": group.invoices, "documentCount": group.documents,
              "signedDocumentCount": group.signedDocuments, "state": group.state.rawValue] as [String: Any]
         }]
        if let diagnostic { result["diagnostic"] = diagnostic }
        return result
    }
}

public struct MinvoiceBatchFailure: Error, Sendable {
    public let progress: MinvoiceBatchProgress
    public let code: Int
    public let message: String
}

/// Mutable execution state shared only by this command's serialized operation.
actor MinvoiceBatchTracker {
    var progress: MinvoiceBatchProgress
    let backend: any MinvoiceSigningBackend
    init(counts: [Int], backend: any MinvoiceSigningBackend) {
        progress = .init(groups: counts.map { .init(invoices: $0) }); self.backend = backend
    }
    func update(_ index: Int? = nil, state: MinvoiceBatchProgress.State? = nil, documents: Int? = nil,
                signed: Int? = nil, checked: Int? = nil, outcome: MinvoiceBatchProgress.Outcome? = nil) async {
        if let index {
            if let state { progress.groups[index].state = state }
            if let documents { progress.groups[index].documents = documents }
            if let signed { progress.groups[index].signedDocuments = signed }
        }
        if let checked { progress.checkedInvoices = checked }
        if let outcome { progress.outcome = outcome }
        await backend.batchProgress(progress)
    }
    /// Only valid before any group has started.
    func regroup(_ counts: [Int]) async {
        progress.groups = counts.map { .init(invoices: $0) }
        await backend.batchProgress(progress)
    }
    func failed(_ error: Error) async -> MinvoiceBatchFailure {
        let denied: Bool
        if case TokenBroker.SignError.card(let message) = error { denied = message == "Người dùng từ chối ký" }
        else { denied = false }
        let cancelled = denied || error is CancellationError || (error as? MinvoiceError) == .cancelled
        if let index = progress.groups.firstIndex(where: { [.downloading, .signing, .uploading].contains($0.state) }) {
            let uploading = progress.groups[index].state == .uploading
            progress.groups[index].state = uploading ? .uploadUncertain : cancelled ? .cancelled : .failed
            progress.outcome = uploading ? .uploadUncertain : cancelled ? .cancelled : .failed
        } else { progress.outcome = cancelled ? .cancelled : .failed }
        progress.diagnostic = (error as? MinvoiceHTTPFailure)?.description
        await backend.batchProgress(progress)
        let cause: Error = progress.uncertain > 0 ? MinvoiceError.uploadUncertain : cancelled ? MinvoiceError.cancelled : progress.diagnostic != nil ? MinvoiceError.transport : error
        let failure = MinvoiceBridge.failure(cause)
        let message = progress.diagnostic != nil && progress.uncertain == 0 ? "Minvoice không hoàn tất yêu cầu ở bước được ghi bên dưới." : failure.1
        return .init(progress: progress, code: failure.0, message: message + (progress.diagnostic.map { " \($0)" } ?? ""))
    }
}
