import AppKit

/// Explicit accessory-app lifetime. No empty SwiftUI Settings scene is opened
/// on launch/reopen, and the model/status item cannot be discarded with a scene.
@main
struct TokenSignerApp {
    @MainActor static func main() {
        let app = NSApplication.shared
        let delegate = TokenSignerDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
}

@MainActor
final class TokenSignerDelegate: NSObject, NSApplicationDelegate {
    private var model: AppModel?
    private var menu: MenuBarController?
    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = AppModel()
        self.model = model
        menu = MenuBarController(model: model)
        model.start()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationWillTerminate(_ notification: Notification) { menu?.shutdown() }
}
