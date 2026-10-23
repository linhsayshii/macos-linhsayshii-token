import SwiftUI
import Core

struct ApprovalSheet: View {
    let prompt: AppModel.ApprovalPrompt
    @ObservedObject var model: AppModel
    var body: some View {
        PromptContainer(title: "Duyệt yêu cầu ký", symbol: "signature", step: "Bước 2 · Xác nhận") {
            DetailLine(label: "Nguồn yêu cầu", value: prompt.origin)
            AppCard {
                VStack(alignment: .leading, spacing: 8) {
                    Text(prompt.subject).fontWeight(.medium).fixedSize(horizontal: false, vertical: true)
                    Text(prompt.ca).foregroundStyle(Theme.muted)
                    Label("Hết hạn: \(CertificateText.localDate(prompt.notAfter))", systemImage: "calendar").foregroundStyle(Theme.muted)
                }
            }
            Text("\(prompt.operation)").font(.system(size: Theme.Size.base, weight: .semibold))
            Text("\(prompt.docCount) \(prompt.countUnit)").foregroundStyle(Theme.muted)
            InlineNotice(text: "Cho phép 10 phút ghi nhớ việc duyệt cho trang và chứng thư này, không phải lưu PIN trong 10 phút.")
        } actions: {
            Button { model.submitApproval(.once) } label: { Text("Cho phép lần này").frame(maxWidth: .infinity) }
                .buttonStyle(ThemePrimaryButtonStyle()).keyboardShortcut(.defaultAction)
            HStack {
                Button("Từ chối") { model.submitApproval(.deny) }
                    .buttonStyle(ThemeSecondaryButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Cho phép 10 phút") { model.submitApproval(.session) }.buttonStyle(ThemeSecondaryButtonStyle())
            }
        }
    }
}
