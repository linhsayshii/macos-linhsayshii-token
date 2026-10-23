import SwiftUI

/// The single source of color and type tokens (spec §7). Nothing else hard-codes a color.
enum Theme {
    private static func adaptive(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let value = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: Double((value >> 16) & 255)/255,
                           green: Double((value >> 8) & 255)/255, blue: Double(value & 255)/255, alpha: 1)
        })
    }
    static let primary       = adaptive(0x202124, 0xEEEEF0)
    static let primaryHover  = adaptive(0x383A40, 0xD6D7DB)
    static let onPrimary     = adaptive(0xFFFFFF, 0x191A1E)
    static let background    = adaptive(0xF5F5F7, 0x202125)
    static let surface       = adaptive(0xFFFFFF, 0x2A2C31)
    static let foreground    = adaptive(0x24262B, 0xF2F2F4)
    static let muted         = adaptive(0x60636C, 0xB4B7C1)
    static let border        = adaptive(0xD8DAE0, 0x484B54)
    static let borderStrong  = adaptive(0x858994, 0x858B99)
    static let itemHover     = adaptive(0xEBEDF1, 0x353840)
    static let secondary     = adaptive(0xE9EBF0, 0x393C44)
    static let danger        = adaptive(0xBC2345, 0xFF8FA4)
    static let dangerBg      = adaptive(0xFFF0F2, 0x452A34)
    static let success       = adaptive(0x007A55, 0x75DBAF)
    static let warning       = adaptive(0x9B4900, 0xFFBF76)
    static let errorText     = danger
    enum Space { static let xs = 4.0, sm = 8.0, md = 12.0, lg = 16.0, xl = 24.0 }
    enum Radius { static let control = 8.0, card = 12.0 }

    // Type scale (pt): xs 11, sm 13 (app default), base 15, lg 17, xl 20.
    enum Size { static let xs = 11.0, sm = 13.0, base = 15.0, lg = 17.0, xl = 20.0 }
}

extension View {
    /// Dynamic AppKit colors and native controls follow the same appearance.
    func tokenSignerAppearance() -> some View {
        self.tint(Theme.primary)
            .accentColor(Theme.primary)
    }
}

struct ThemePrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.isFocused) private var focused

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(isEnabled ? Theme.onPrimary : Theme.muted)
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(isEnabled ? (configuration.isPressed ? Theme.primaryHover : Theme.primary) : Theme.secondary,
                        in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(focused ? Theme.foreground : .clear, lineWidth: 2).padding(-3))
    }
}

/// Explicit arrow and label colors stay legible in a dark menu-bar host.
struct ThemeDisclosureStyle: DisclosureGroupStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.15)) { configuration.isExpanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 11, weight: .semibold))
                        .rotationEffect(.degrees(configuration.isExpanded ? 90 : 0))
                        .frame(width: 12, height: 16)
                    configuration.label
                    Spacer(minLength: 0)
                }
                .foregroundStyle(Theme.foreground)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityValue(configuration.isExpanded ? "Đã mở" : "Đã thu gọn")
            if configuration.isExpanded {
                configuration.content.padding(.leading, 20).padding(.top, 8)
            }
        }
    }
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
