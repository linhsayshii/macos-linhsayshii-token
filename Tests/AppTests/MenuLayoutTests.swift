import AppKit
import Testing
@testable import App

@Test func menuFitsSmallAndNegativeOriginScreensWithoutRememberingOldSize() {
    for frame in [CGRect(x: 0, y: 24, width: 1280, height: 674), CGRect(x: -1440, y: -900, width: 1440, height: 876), CGRect(x: 0, y: 24, width: 320, height: 350)] {
        for x in [frame.minX, frame.maxX - 24] {
            let anchor = CGRect(x: x, y: frame.maxY, width: 24, height: 24)
            let size = MenuLayout.size(anchor: anchor, visibleFrame: frame)
            #expect(size.height <= frame.height - 24 && size.width <= frame.width - 24)
            for _ in 0..<20 { #expect(MenuLayout.size(anchor: anchor, visibleFrame: frame) == size) }
        }
    }
    #expect(MenuLayout.size(anchor: .zero, visibleFrame: .zero) == .zero)
}
