import AppKit
import SwiftUI

@MainActor final class CheckDelegate: NSObject, NSApplicationDelegate {
    let presenter = SigningPromptWindow()
    var cancelled = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        presenter.present(title: "TokenSigner — kiểm tra cửa sổ", content: Text("Kiểm tra cửa sổ duyệt ký").padding(20)) {
            self.cancelled = true
            self.presenter.dismiss()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            let app = NSApplication.shared
            let panel = app.windows.first { $0.title == "TokenSigner — kiểm tra cửa sổ" }!
            FileHandle.standardError.write(Data("visible=\(panel.isVisible) key=\(panel.isKeyWindow) active=\(app.isActive)\n".utf8))
            precondition(panel.isVisible && panel.isKeyWindow && app.isActive)
            panel.performClose(nil)
            precondition(self.cancelled && !panel.isVisible && panel.contentView == nil)
            var nextCancelled = false
            self.presenter.present(title: "TokenSigner — kiểm tra PIN", content: Text("Kiểm tra bước PIN").padding(20)) {
                nextCancelled = true
            }
            let next = app.windows.first { $0.title == "TokenSigner — kiểm tra PIN" }!
            precondition(next.isVisible)
            self.presenter.dismiss()
            precondition(!next.isVisible && next.contentView == nil && !nextCancelled)
            FileHandle.standardOutput.write(Data("PASS: visible, key, active; close cancels; next prompt opens; submit dismisses without cancellation\n".utf8))
            app.terminate(nil)
        }
    }
}

@main struct PromptWindowCheck {
    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = CheckDelegate()
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}
