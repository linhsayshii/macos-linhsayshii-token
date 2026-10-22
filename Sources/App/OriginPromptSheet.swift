import SwiftUI
import Core

/// Asks whether to allow an origin that is not on the allowlist. Requests from
/// it stay rejected until the user allows it.
struct OriginPromptSheet: View {
    let origin: String
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Trang web lạ muốn ký").font(.system(size: Theme.Size.lg, weight: .semibold))
            Text(origin).font(.system(size: Theme.Size.sm, weight: .medium)).lineLimit(3)
            Text("Trang này chưa nằm trong danh sách cho phép. Chỉ cho phép nếu bạn tin tưởng.")
                .font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.muted)
            HStack(spacing: 8) {
                Button { model.answerOrigin(allow: true) } label: { Text("Cho phép").frame(maxWidth: .infinity) }
                    .buttonStyle(ThemePrimaryButtonStyle())
                Button("Từ chối") { model.answerOrigin(allow: false) }
                    .buttonStyle(.plain).frame(maxWidth: .infinity).foregroundStyle(Theme.danger)
            }
            .font(.system(size: Theme.Size.sm))
        }
        .padding(20).frame(width: 340)
        .background(Theme.background).foregroundStyle(Theme.foreground)
        .tokenSignerAppearance()
    }
}
