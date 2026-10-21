import SwiftUI

/// The single source of color and type tokens (spec §7). Nothing else hard-codes a color.
enum Theme {
    static let primary       = Color(hex: 0x181818)
    static let primaryHover  = Color(hex: 0x2E2E2E)
    static let onPrimary     = Color.white
    static let background    = Color(hex: 0xF4F4F6)
    static let surface       = Color.white
    static let foreground    = Color(hex: 0x2C2C2C)
    static let muted         = Color(hex: 0x707070)
    static let border        = Color(hex: 0xF7F7F8)
    static let borderStrong  = Color(hex: 0xEAEAEA)
    static let itemHover     = Color(hex: 0xF4F4F6)
    static let secondary     = Color(hex: 0xE7E8EC)
    static let danger        = Color(hex: 0xC70036)
    static let dangerBg      = Color(red: 1, green: 32.0/255, blue: 86.0/255).opacity(0.10)
    static let success       = Color(hex: 0x007A55)
    static let warning       = Color(hex: 0xBB4D00)
    static let errorText     = Color(hex: 0xE7000B)

    // Type scale (pt): xs 11, sm 13 (app default), base 15, lg 17, xl 20.
    enum Size { static let xs = 11.0, sm = 13.0, base = 15.0, lg = 17.0, xl = 20.0 }
}

extension Color {
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }
}
