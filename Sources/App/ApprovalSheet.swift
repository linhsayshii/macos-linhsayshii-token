import SwiftUI
import Core

/// Consent for one sign request, keyed by (origin, cert). "Cho phép 10 phút"
/// opens a session so repeat requests from the same origin skip this sheet.
struct ApprovalSheet: View {
    let prompt: AppModel.ApprovalPrompt
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Yêu cầu ký số").font(.system(size: Theme.Size.lg, weight: .semibold))
            Text(prompt.origin).font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.muted)

            VStack(alignment: .leading, spacing: 4) {
                Text(prompt.subject).font(.system(size: Theme.Size.sm, weight: .medium)).lineLimit(2)
                Text(prompt.ca).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                Text("Hết hạn: \(prompt.notAfter)").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
            }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface)
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.borderStrong, lineWidth: 1))

            Text("\(prompt.operation) · \(prompt.docCount) tài liệu").font(.system(size: Theme.Size.sm))

            VStack(spacing: 8) {
                Button { model.submitApproval(.session) } label: {
                    Text("Cho phép 10 phút").frame(maxWidth: .infinity)
                }
                .buttonStyle(ThemePrimaryButtonStyle())
                HStack(spacing: 8) {
                    Button("Chỉ lần này") { model.submitApproval(.once) }
                        .buttonStyle(.plain)
                        .frame(maxWidth: .infinity)
                        .foregroundStyle(Theme.primary)
                    Button("Từ chối") { model.submitApproval(.deny) }
                        .keyboardShortcut(.cancelAction)
                        .buttonStyle(.plain)
                        .frame(maxWidth: .infinity)
                        .foregroundStyle(Theme.danger)
                }
            }
            .font(.system(size: Theme.Size.sm))
        }
        .padding(20).frame(width: 340)
        .background(Theme.background).foregroundStyle(Theme.foreground)
        .tokenSignerAppearance()
    }
}
