import SwiftUI

private struct PromptSizeKey: EnvironmentKey {
    static let defaultValue = CGSize(width: 460, height: 560)
}
extension EnvironmentValues {
    var signingPromptSize: CGSize {
        get { self[PromptSizeKey.self] }
        set { self[PromptSizeKey.self] = newValue }
    }
}

struct PromptContainer<Content: View, Actions: View>: View {
    let title: String
    let symbol: String
    let step: String?
    let content: Content
    let actions: Actions
    @Environment(\.signingPromptSize) private var size
    init(title: String, symbol: String, step: String? = nil,
         @ViewBuilder content: () -> Content, @ViewBuilder actions: () -> Actions) {
        self.title = title; self.symbol = symbol; self.step = step
        self.content = content(); self.actions = actions()
    }
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: symbol).font(.system(size: 22)).frame(width: 44, height: 44)
                    .background(Theme.secondary, in: RoundedRectangle(cornerRadius: Theme.Radius.card))
                VStack(alignment: .leading, spacing: 4) {
                    Text(step ?? "TokenSigner").font(.system(size: Theme.Size.xs, weight: .medium)).foregroundStyle(Theme.muted)
                    Text(title).font(.system(size: Theme.Size.xl, weight: .semibold)).accessibilityAddTraits(.isHeader)
                }
                Spacer(minLength: 0)
            }.padding(20)
            Divider().overlay(Theme.border)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) { content }
                    .padding(20).frame(maxWidth: .infinity, alignment: .leading)
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider().overlay(Theme.border)
            VStack(spacing: 12) { actions }.padding(20).frame(maxWidth: .infinity)
        }
        .frame(width: size.width, height: size.height)
        .font(.system(size: Theme.Size.sm))
        .background(Theme.background).foregroundStyle(Theme.foreground)
        .tokenSignerAppearance()
    }
}

enum PromptLayout {
    static func size(visibleFrame: CGRect) -> CGSize {
        CGSize(width: min(460, max(0, visibleFrame.width - 32)), height: min(560, max(0, visibleFrame.height - 72)))
    }
}
