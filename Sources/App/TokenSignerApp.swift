import SwiftUI

@main
struct TokenSignerApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra("TokenSigner", systemImage: "key.fill") {
            MenuBarView(model: model)
                .preferredColorScheme(.light)
                .onAppear { model.start() }
        }
        .menuBarExtraStyle(.window)
    }
}
