import SwiftUI

@main
struct TokenSignerApp: App {
    @NSApplicationDelegateAdaptor(TokenSignerDelegate.self) private var delegate
    var body: some Scene { Settings { EmptyView() } }
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
}
