import SwiftUI

enum NoticeTone {
    case neutral, success, warning, danger
    var color: Color {
        switch self { case .neutral: Theme.muted; case .success: Theme.success; case .warning: Theme.warning; case .danger: Theme.danger }
    }
    var symbol: String {
        switch self { case .neutral: "info.circle"; case .success: "checkmark.circle.fill"; case .warning: "exclamationmark.triangle"; case .danger: "exclamationmark.circle.fill" }
    }
}

struct AppCard<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        content.padding(Theme.Space.md).frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.card))
            .overlay(RoundedRectangle(cornerRadius: Theme.Radius.card).stroke(Theme.border, lineWidth: 1))
    }
}

struct SectionHeader: View {
    let title: String
    var detail: String? = nil
    var body: some View {
        HStack {
            Text(title).font(.system(size: Theme.Size.sm, weight: .semibold)).accessibilityAddTraits(.isHeader)
            Spacer()
            if let detail { Text(detail).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted) }
        }
    }
}

struct StatusBadge: View {
    let text: String
    var tone: NoticeTone = .neutral
    var body: some View {
        Label(text, systemImage: tone.symbol).font(.system(size: Theme.Size.xs, weight: .medium))
            .foregroundStyle(tone.color).padding(.horizontal, 6).padding(.vertical, 3)
            .background(tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 5))
            .fixedSize(horizontal: false, vertical: true)
    }
}

struct InlineNotice: View {
    let text: String
    var tone: NoticeTone = .neutral
    var body: some View {
        Label { Text(text).fixedSize(horizontal: false, vertical: true) } icon: { Image(systemName: tone.symbol) }
            .font(.system(size: Theme.Size.sm)).foregroundStyle(tone.color)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct ThemeSecondaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    @Environment(\.isFocused) private var focused
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.font(.system(size: Theme.Size.sm, weight: .medium))
            .foregroundStyle(enabled ? Theme.foreground : Theme.muted)
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(configuration.isPressed ? Theme.itemHover : Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.control))
            .overlay(RoundedRectangle(cornerRadius: Theme.Radius.control).stroke(focused ? Theme.foreground : Theme.borderStrong, lineWidth: focused ? 2 : 1))
    }
}

struct DetailLine: View {
    let label: String
    let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
            HStack(alignment: .top, spacing: 8) {
                Text(value).font(.system(size: Theme.Size.sm)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button {
                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string)
                } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.plain).foregroundStyle(Theme.muted)
                    .help("Sao chép \(label)").accessibilityLabel("Sao chép \(label)")
            }
        }
    }
}
