import SwiftUI
import AppKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    func applicationDidFinishLaunching(_ note: Notification) {
        model.start()   // start the bridge at launch, not when the popover opens
    }
}

@main
struct TokenSignerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra("TokenSigner", systemImage: "key.fill") {
            MenuBarView(model: delegate.model)
                .preferredColorScheme(.light)
        }
        .menuBarExtraStyle(.window)
    }
}
