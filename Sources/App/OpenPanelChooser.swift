import AppKit
import UniformTypeIdentifiers
import Bridges

/// eSigner's CHOOSE_FILE: a native macOS open panel (the original pops a Java Swing chooser).
struct OpenPanelChooser: FileChooser {
    @MainActor private static var open = false

    @MainActor private static func run() -> URL? {
        guard !open else { return nil }   // portal clicked again while the panel is up
        open = true; defer { open = false }
        // Menu-bar app: without this the panel opens behind the browser.
        NSApp.setActivationPolicy(.accessory)
        NSRunningApplication.current.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
        let p = NSOpenPanel()
        p.title = "Chọn tệp tờ khai (XML)"
        p.allowedContentTypes = [.xml]
        p.allowsMultipleSelection = false
        p.canChooseDirectories = false
        p.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        p.level = .floating
        p.makeKeyAndOrderFront(nil)
        return p.runModal() == .OK ? p.url : nil
    }
    func chooseXML() async -> URL? { await MainActor.run { Self.run() } }
}
