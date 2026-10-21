import SwiftUI

@main
struct TokenSignerApp: App {
    // Owned by the SwiftUI graph so the MenuBarExtra window observes its
    // @Published changes live. (Held in an AppDelegate it did not, so the
    // open popover showed stale data until reopened.)
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(model: model)
                .preferredColorScheme(.light)
        } label: {
            // Runs when the menu bar icon first appears, i.e. at launch —
            // starts the bridge + scan before the user opens the popover.
            Image(systemName: "key.fill")
                .task { model.start() }
        }
        .menuBarExtraStyle(.window)
    }
}
