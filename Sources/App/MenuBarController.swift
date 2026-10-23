import AppKit
import SwiftUI

/// Owns only presentation. Every view observes the single app-lifetime model.
@MainActor
final class MenuBarController: NSObject {
    private let item: NSStatusItem
    private let popover = NSPopover()
    private let presentation = MenuPresentation()
    private let host: NSHostingController<MenuBarView>
    nonisolated(unsafe) private var observers: [NSObjectProtocol] = []
    nonisolated(unsafe) private var spaceObserver: NSObjectProtocol?
    private var positioning = false

    init(model: AppModel) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        host = NSHostingController(rootView: MenuBarView(model: model))
        super.init()
        host.rootView = MenuBarView(model: model, presentation: presentation)
        item.autosaveName = "TokenSigner"
        if let button = item.button {
            button.image = NSImage(systemSymbolName: "key.fill", accessibilityDescription: "TokenSigner")
            button.image?.isTemplate = true
            button.toolTip = "TokenSigner — chữ ký số"
            button.target = self; button.action = #selector(toggle)
        }
        popover.behavior = .transient
        popover.animates = false
        popover.contentViewController = host
        for name in [NSApplication.didChangeScreenParametersNotification, NSWindow.didMoveNotification, NSWindow.didChangeScreenNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, self.popover.isShown else { return }
                    self.show()
                }
            })
        }
        observers.append(NotificationCenter.default.addObserver(forName: SigningPromptWindow.willPresent, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.popover.performClose(nil) }
        })
        spaceObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.activeSpaceDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.popover.performClose(nil) }
        }
    }

    @objc private func toggle() {
        if popover.isShown { popover.performClose(nil) } else { show() }
    }

    private func show() {
        guard !positioning, let button = item.button, let window = button.window, let screen = window.screen else { return }
        positioning = true; defer { positioning = false }
        let anchor = window.convertToScreen(button.convert(button.bounds, to: nil))
        let size = MenuLayout.size(anchor: anchor, visibleFrame: screen.visibleFrame)
        guard size.width > 0, size.height > 0 else { return }
        presentation.size = size
        host.preferredContentSize = size
        host.view.setFrameSize(size)
        popover.contentSize = size
        host.view.layoutSubtreeIfNeeded()
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    }

    deinit {
        observers.forEach(NotificationCenter.default.removeObserver)
        if let spaceObserver { NSWorkspace.shared.notificationCenter.removeObserver(spaceObserver) }
    }
}
