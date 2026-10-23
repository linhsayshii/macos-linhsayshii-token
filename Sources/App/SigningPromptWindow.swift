import SwiftUI
import AppKit

@MainActor
protocol SigningPromptPresenting {
    func present<Content: View>(title: String, content: Content, onCancel: @escaping () -> Void)
    func dismiss()
}

/// Hosts signing prompts even when the menu bar popover has never been opened.
@MainActor
final class SigningPromptWindow: NSObject, NSWindowDelegate, SigningPromptPresenting {
    static let willPresent = Notification.Name("TokenSignerSigningPromptWillPresent")
    private var panel: NSPanel?
    private var onCancel: (() -> Void)?

    func present<Content: View>(title: String, content: Content, onCancel: @escaping () -> Void) {
        dismiss()
        NotificationCenter.default.post(name: Self.willPresent, object: nil)
        self.onCancel = onCancel
        let host = NSHostingView(rootView: content)
        let panel = NSPanel(contentRect: .zero, styleMask: [.titled, .closable],
                            backing: .buffered, defer: false)
        panel.title = title
        panel.appearance = NSAppearance(named: .aqua)
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.level = .floating
        panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        panel.contentView = host
        panel.setContentSize(host.fittingSize)
        panel.delegate = self
        panel.center()
        self.panel = panel
        NSApplication.shared.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        panel.orderFrontRegardless()
    }

    func dismiss() {
        onCancel = nil
        panel?.delegate = nil
        panel?.close()
        panel?.contentView = nil
        panel = nil
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        // The callback resumes the waiting continuation and dismisses the panel.
        let cancel = onCancel
        cancel?()
        return false
    }
}
