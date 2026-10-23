import AppKit
import Combine

/// All sizes are points in the screen containing the status item, including
/// displays whose origin is negative. Content changes never resize the shell.
enum MenuLayout {
    static func size(anchor: CGRect, visibleFrame: CGRect) -> CGSize {
        CGSize(width: min(380, max(0, visibleFrame.width - 24)),
               height: min(560, max(0, min(anchor.minY, visibleFrame.maxY) - visibleFrame.minY - 24)))
    }
}

final class MenuPresentation: ObservableObject {
    @Published var size = CGSize(width: 380, height: 560)
}
