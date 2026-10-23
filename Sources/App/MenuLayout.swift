import AppKit
import Combine

/// All sizes are points in the screen containing the status item, including
/// displays whose origin is negative. Content changes never resize the shell.
enum MenuLayout {
    static func size(anchor: CGRect, visibleFrame: CGRect) -> CGSize {
        // Scene-backed status items can expose a proxy view at (0,0). AppKit
        // still owns popover placement; use the screen's available top for size.
        let top = anchor.minY < visibleFrame.minY ? visibleFrame.maxY : min(anchor.minY, visibleFrame.maxY)
        return CGSize(width: min(380, max(0, visibleFrame.width - 24)),
                      height: min(560, max(0, top - visibleFrame.minY - 24)))
    }
}

final class MenuPresentation: ObservableObject {
    enum Page: String, CaseIterable { case tokens = "Token", connections = "Kết nối", history = "Lịch sử" }
    @Published var size = CGSize(width: 380, height: 560)
    @Published var page: Page = .tokens
    @Published var expandedTokens = Set<String>()
}
