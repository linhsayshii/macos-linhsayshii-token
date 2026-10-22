import SwiftUI

@main
struct TokenSignerApp: App {
    // Owned by the SwiftUI graph so the MenuBarExtra window observes its
    // @Published changes live. (Held in an AppDelegate it did not, so the
    // open popover showed stale data until reopened.)
    @StateObject private var model: AppModel

    init() {
        let model = AppModel()
        _model = StateObject(wrappedValue: model)
        // Start independently of rendering or opening the menu bar extra.
        Task { @MainActor in model.start() }
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(model: model)
                .preferredColorScheme(.light)
        } label: {
            Image(systemName: "key.fill")
        }
        .menuBarExtraStyle(.window)
    }
}
