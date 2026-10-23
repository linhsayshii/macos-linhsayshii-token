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
    private var resize: (() -> Void)?
    nonisolated(unsafe) private var screenObserver: NSObjectProtocol?

    override init() {
        super.init()
        screenObserver = NotificationCenter.default.addObserver(forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.resize?() }
        }
    }

    func present<Content: View>(title: String, content: Content, onCancel: @escaping () -> Void) {
        dismiss()
        NotificationCenter.default.post(name: Self.willPresent, object: nil)
        self.onCancel = onCancel
        let screen = NSScreen.screens.first { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) } ?? NSScreen.main
        let initialSize = PromptLayout.size(visibleFrame: screen?.visibleFrame ?? CGRect(x: 0, y: 0, width: 1024, height: 768))
        let host = NSHostingView(rootView: content.environment(\.signingPromptSize, initialSize))
        let panel = NSPanel(contentRect: .zero, styleMask: [.titled, .closable],
                            backing: .buffered, defer: false)
        panel.title = title
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.level = .floating
        panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        panel.contentView = host
        panel.setContentSize(initialSize)
        panel.delegate = self
        if let screen {
            panel.setFrameOrigin(NSPoint(x: screen.visibleFrame.midX - panel.frame.width / 2,
                                         y: screen.visibleFrame.midY - panel.frame.height / 2))
        }
        resize = { [weak panel, weak host] in
            guard let panel, let host, let target = panel.screen ?? NSScreen.main else { return }
            let visible = target.visibleFrame
            let size = PromptLayout.size(visibleFrame: visible)
            host.rootView = content.environment(\.signingPromptSize, size)
            host.setFrameSize(size)
            panel.setContentSize(size)
            panel.setFrameOrigin(NSPoint(x: visible.midX - panel.frame.width / 2, y: visible.midY - panel.frame.height / 2))
        }
        resize?()
        self.panel = panel
        NSApplication.shared.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        panel.orderFrontRegardless()
    }

    func dismiss() {
        onCancel = nil
        resize = nil
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

    func windowDidChangeScreen(_ notification: Notification) { resize?() }
    deinit { if let screenObserver { NotificationCenter.default.removeObserver(screenObserver) } }
}
