import SwiftUI
import Core

/// Selection only: authentication still happens at the later PIN step.
struct CertificatePicker: View {
    @ObservedObject var model: AppModel
    var body: some View {
        if let prompt = model.certificatePrompt {
            PromptContainer(title: "Chọn chữ ký số", symbol: "person.badge.key", step: "Bước 1 · Chứng thư") {
                DetailLine(label: "Nguồn yêu cầu", value: prompt.origin)
                Text(prompt.operation).fontWeight(.medium)
                if let serial = prompt.requestedSerial, !serial.isEmpty {
                    AppCard { DetailLine(label: "Serial chứng thư trang yêu cầu", value: serial) }
                }
                if prompt.choices.isEmpty {
                    AppCard {
                        VStack(alignment: .leading, spacing: 12) {
                            Label("Chưa tìm thấy chữ ký số", systemImage: "externaldrive.badge.plus").fontWeight(.medium)
                            Text("Cắm USB token vào máy. Danh sách sẽ tự cập nhật.").foregroundStyle(Theme.muted)
                        }
                    }
                } else {
                    ForEach(prompt.choices) { choice in certificateRow(choice) }
                }
                if !prompt.choices.isEmpty && !prompt.choices.contains(where: \.canSelect) {
                    InlineNotice(text: "Chưa có CKS phù hợp. Kiểm tra token hoặc chứng thư trang yêu cầu.", tone: .warning)
                }
                if let message = prompt.message { InlineNotice(text: message, tone: .warning) }
                if model.refreshingCertificates {
                    HStack { ProgressView().controlSize(.small); Text("Đang đọc token…").foregroundStyle(Theme.muted) }
                }
            } actions: {
                Text("Bạn sẽ duyệt yêu cầu và nhập PIN ở bước ký.").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                HStack {
                    Button("Hủy") { model.submitCertificate(nil) }.buttonStyle(ThemeSecondaryButtonStyle()).keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Tiếp tục") { model.submitCertificate(model.selectedCertificateID) }
                        .buttonStyle(ThemePrimaryButtonStyle()).keyboardShortcut(.defaultAction)
                        .disabled(model.refreshingCertificates || !prompt.choices.contains { $0.id == model.selectedCertificateID && $0.canSelect })
                }
            }
        }
    }
    private func certificateRow(_ choice: SigningCertificateChoice) -> some View {
        let selected = model.selectedCertificateID == choice.id
        return Button { model.selectedCertificateID = choice.id } label: {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(choice.canSelect ? Theme.primary : Theme.muted).font(.system(size: 20))
                VStack(alignment: .leading, spacing: 6) {
                    Text(choice.target.module.ca).font(.system(size: Theme.Size.base, weight: .semibold))
                    Text(CertificateText.name(derB64: choice.target.cert.derB64, fallback: choice.target.cert.subject)).lineLimit(2)
                    Text("Token: \(choice.target.tokenSerial)").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted).lineLimit(2)
                    Text("CKS: \(choice.target.cert.serialHex)").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted).lineLimit(2)
                    Text("Hết hạn: \(CertificateText.localDate(choice.target.cert.notAfter))").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                    if let reason = choice.unavailableReason ?? choice.warning { InlineNotice(text: reason, tone: .warning) }
                }
                Spacer(minLength: 0)
            }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                .background(selected ? Theme.secondary : Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.card))
                .overlay(RoundedRectangle(cornerRadius: Theme.Radius.card).stroke(selected ? Theme.foreground : Theme.borderStrong, lineWidth: selected ? 2 : 1))
                .contentShape(RoundedRectangle(cornerRadius: Theme.Radius.card))
        }
        .buttonStyle(.plain).disabled(!choice.canSelect)
        .accessibilityLabel("\(choice.target.module.ca), \(choice.target.cert.subject), token \(choice.target.tokenSerial)")
        .accessibilityValue(selected ? "Đã chọn" : (choice.unavailableReason ?? "Chưa chọn"))
    }
}
