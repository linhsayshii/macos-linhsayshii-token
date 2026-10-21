import AppKit
import UniformTypeIdentifiers
import Bridges

/// eSigner's CHOOSE_FILE: a native macOS open panel (the original pops a Java Swing chooser).
struct OpenPanelChooser: FileChooser {
    @MainActor private static func run() -> URL? {
        NSApp.activate(ignoringOtherApps: true)
        let p = NSOpenPanel()
        p.title = "Chọn tệp tờ khai (XML)"
        p.allowedContentTypes = [.xml]
        p.allowsMultipleSelection = false
        p.canChooseDirectories = false
        p.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        return p.runModal() == .OK ? p.url : nil
    }
    func chooseXML() async -> URL? { await MainActor.run { Self.run() } }
}
