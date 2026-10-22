import AppKit
import Bridges

/// Independent native chooser that can be cancelled when the WebSocket disconnects.
struct OpenPanelChooser: FileChooser {
    @MainActor private static var panel: NSOpenPanel?
    func chooseXML() async -> URL? {
        let id = UUID()
        return await withTaskCancellationHandler {
            await Self.run(id: id)
        } onCancel: {
            Task { @MainActor in
                if Self.requestID == id { Self.panel?.cancel(nil) }
            }
        }
    }
    @MainActor private static var requestID: UUID?
    @MainActor private static func run(id: UUID) async -> URL? {
        guard panel == nil, !Task.isCancelled else { return nil }
        let panel = NSOpenPanel()
        Self.panel = panel; requestID = id
        defer { Self.panel = nil; requestID = nil }
        NSApplication.shared.activate(ignoringOtherApps: true)
        panel.title = "Chọn tệp tờ khai (XML)"
        panel.allowedContentTypes = [.xml]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.level = .floating
        return await withCheckedContinuation { continuation in
            panel.begin { result in continuation.resume(returning: result == .OK ? panel.url : nil) }
        }
    }
}
