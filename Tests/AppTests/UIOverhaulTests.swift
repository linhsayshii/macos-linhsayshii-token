import AppKit
import SwiftUI
import Testing
import Core
@testable import App

@MainActor private struct PreviewPromptPresenter: SigningPromptPresenting {
    func present<Content: View>(title: String, content: Content, onCancel: @escaping () -> Void) {}
    func dismiss() {}
}

@MainActor private func previewModel(count: Int) throws -> AppModel {
    let names = ["NC-CA", "VNPT", "OneCA", "EFY-CA"]
    let rows = (0..<count).map { i in
        AppModel.TokenRow(ca: names[i % names.count], supported: true, experimental: i > 1,
            reader: "Đầu đọc thử nghiệm \(i)", serial: "TOKEN-SYNTHETIC-\(i)", label: "Fixture",
            certSubject: "CN=CÔNG TY THỬ NGHIỆM GIAO DIỆN, O=Thông tin tổng hợp để kiểm tra chuỗi dài",
            notAfter: i == 1 ? "2025-07-28 11:09:47" : "2027-08-06 10:22:16",
            certificateName: "CÔNG TY THỬ NGHIỆM GIAO DIỆN \(i + 1)")
    }
    let audits = try (0..<5).map { i in
        try JSONDecoder().decode(AuditEntry.self, from: JSONSerialization.data(withJSONObject: [
            "time": "2026-10-23T05:01:42Z", "origin": "https://portal.example.test",
            "bridge": ["menu", "minvoice", "vnpt"][i % 3], "certSerial": "SYNTHETIC",
            "operation": "RSA_PKCS", "inputSHA256": String(repeating: "a", count: 64), "result": i == 3 ? "cancelled" : "ok",
        ]))
    }
    return AppModel(broker: TokenBroker(helperURL: URL(fileURLWithPath: "/nonexistent"), shimURL: URL(fileURLWithPath: "/nonexistent"), moduleDirs: []),
                    promptWindow: PreviewPromptPresenter(), tokenRows: rows, auditEntries: audits)
}

@MainActor private func render<V: View>(_ view: V, size: CGSize, dark: Bool, name: String) throws {
    let host = NSHostingView(rootView: view.environment(\.colorScheme, dark ? .dark : .light))
    host.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
    let window = NSWindow(contentRect: CGRect(origin: .zero, size: size), styleMask: [.borderless], backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    window.contentView = host
    host.setFrameSize(size); host.layoutSubtreeIfNeeded()
    #expect(host.fittingSize.width <= size.width + 1)
    #expect(host.fittingSize.height <= size.height + 1)
    #expect(host.bounds.size == size)
    if let path = ProcessInfo.processInfo.environment["TOKENSIGNER_UI_GALLERY"] {
        let dir = URL(fileURLWithPath: path); try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let bitmap = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: bitmap)
        let data = try #require(bitmap.representation(using: .png, properties: [:]))
        try data.write(to: dir.appendingPathComponent(name + (dark ? "-dark" : "-light") + ".png"))
    }
    window.contentView = nil; window.close()
}

@Test @MainActor func menuAndPromptLayoutsRemainBoundedAcrossPagesAndExpandedContent() throws {
    for count in [0, 4, 10] {
        let model = try previewModel(count: count), presentation = MenuPresentation()
        for height in [350.0, 560.0] {
            presentation.size = CGSize(width: 380, height: height)
            for page in MenuPresentation.Page.allCases {
                presentation.page = page
                presentation.expandedTokens = Set(model.tokens.map(\.id))
                for dark in [false, true] {
                    try render(MenuBarView(model: model, presentation: presentation), size: presentation.size, dark: dark,
                               name: "menu-\(page)-\(count)-\(Int(height))-expanded")
                    if count == 4 && height == 560 && page == .tokens {
                        presentation.expandedTokens = []
                        try render(MenuBarView(model: model, presentation: presentation), size: presentation.size, dark: dark,
                                   name: "menu-tokens-collapsed")
                        presentation.expandedTokens = Set(model.tokens.map(\.id))
                    }
                }
            }
            for _ in 0..<20 {
                presentation.expandedTokens = []
                presentation.expandedTokens = Set(model.tokens.map(\.id))
                #expect(abs(presentation.size.height - CGFloat(height)) < 0.5)
            }
        }
    }
    let model = try previewModel(count: 4)
    let approval = AppModel.ApprovalPrompt(origin: "https://portal-with-a-long-hostname.example.test", subject: "CÔNG TY THỬ NGHIỆM GIAO DIỆN", ca: "EFY-CA", notAfter: "2027-08-06 10:22:16", operation: "Ký hóa đơn Minvoice", docCount: 300)
    let pin = AppModel.PINPrompt(ca: "EFY-CA", serial: "SYNTHETIC-TOKEN", warning: "Chưa biết số lần thử PIN còn lại; chỉ xác thực một lần, không tự thử lại", locked: false)
    for dark in [false, true] {
        for size in [CGSize(width: 460, height: 560), CGSize(width: 460, height: 350)] {
            try render(ApprovalSheet(prompt: approval, model: model).environment(\.signingPromptSize, size), size: size, dark: dark, name: "approval-\(Int(size.height))")
            try render(PINSheet(prompt: pin, model: model).environment(\.signingPromptSize, size), size: size, dark: dark, name: "pin-\(Int(size.height))")
            try render(OriginPromptSheet(origin: approval.origin, model: model).environment(\.signingPromptSize, size), size: size, dark: dark, name: "origin-\(Int(size.height))")
        }
    }
}

@Test @MainActor func cancellingMenuSigningHasNeutralResultAndDoesNotAuthenticate() async throws {
    let model = try previewModel(count: 4)
    let task = Task { await model.testSign(serial: "") }
    for _ in 0..<100 {
        if model.certificatePrompt != nil { break }
        try await Task.sleep(for: .milliseconds(5))
    }
    try #require(model.certificatePrompt != nil)
    model.submitCertificate(nil)
    await task.value
    #expect(model.signingResult?.kind == .cancelled)
    #expect(model.lastSignResult == "Đã hủy yêu cầu ký")
    #expect(!model.isWorking && model.pinDraft.isEmpty && model.pinPrompt == nil)
}

@Test func promptFitsSmallScreenAndDatesUseActualUTCParsing() {
    let frame = CGRect(x: -1440, y: -900, width: 1280, height: 650)
    #expect(PromptLayout.size(visibleFrame: frame) == CGSize(width: 460, height: 560))
    #expect(PromptLayout.size(visibleFrame: CGRect(x: 0, y: 0, width: 320, height: 400)) == CGSize(width: 288, height: 328))
    #expect(CertificateText.date("2026-10-23T05:01:42Z") == CertificateText.date("2026-10-23 05:01:42"))
    #expect(CertificateText.localDate("invalid") == "invalid")
}
