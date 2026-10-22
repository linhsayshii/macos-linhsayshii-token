import SwiftUI
import Core

/// TokenSigner's own certificate chooser. Selection never authenticates a token.
struct CertificatePicker: View {
    @ObservedObject var model: AppModel

    var body: some View {
        if let prompt = model.certificatePrompt {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 12) {
                    Image(systemName: "person.badge.key.fill")
                        .font(.system(size: 28)).foregroundStyle(Theme.primary)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Chọn chữ ký số").font(.system(size: Theme.Size.xl, weight: .semibold))
                        Text("TokenSigner").font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.muted)
                    }
                    Spacer()
                }
                Text(prompt.origin).font(.system(size: Theme.Size.sm, weight: .medium)).lineLimit(2).textSelection(.enabled)
                Text(prompt.operation).font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.muted)
                if let serial = prompt.requestedSerial, !serial.isEmpty {
                    Text("Trang yêu cầu CKS có serial \(serial).")
                        .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                }

                if prompt.choices.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "externaldrive.badge.plus").font(.system(size: 32)).foregroundStyle(Theme.muted)
                        Text("Chưa tìm thấy chữ ký số").font(.system(size: Theme.Size.base, weight: .medium))
                        Text("Cắm USB token vào máy. Danh sách sẽ tự cập nhật.")
                            .font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.muted)
                    }
                    .frame(maxWidth: .infinity).frame(height: 300)
                } else {
                    ScrollView {
                        VStack(spacing: 8) {
                            ForEach(prompt.choices) { choice in certificateRow(choice) }
                        }
                        .padding(2)
                    }
                    .frame(height: 300)
                }

                if !prompt.choices.isEmpty && !prompt.choices.contains(where: \.canSelect) {
                    Text("Chưa có CKS phù hợp. Kiểm tra token hoặc CKS trang đã chọn.")
                        .font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.warning)
                }
                if let message = prompt.message {
                    Text(message).font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.warning)
                }
                if model.refreshingCertificates {
                    HStack { ProgressView().controlSize(.small); Text("Đang đọc token…").font(.system(size: Theme.Size.xs)) }
                }
                Text("Bạn sẽ duyệt yêu cầu và nhập PIN ở bước ký.")
                    .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                HStack {
                    Button("Huỷ") { model.submitCertificate(nil) }
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Tiếp tục") { model.submitCertificate(model.selectedCertificateID) }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(model.refreshingCertificates || !prompt.choices.contains { $0.id == model.selectedCertificateID && $0.canSelect })
                }
            }
            .padding(24).frame(width: 460)
            .background(Theme.background).foregroundStyle(Theme.foreground)
            .preferredColorScheme(.light)
        }
    }

    private func certificateRow(_ choice: SigningCertificateChoice) -> some View {
        let selected = model.selectedCertificateID == choice.id
        return Button {
            model.selectedCertificateID = choice.id
        } label: {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(choice.canSelect ? Theme.primary : Theme.muted)
                    .font(.system(size: 19))
                VStack(alignment: .leading, spacing: 4) {
                    Text(choice.target.module.ca).font(.system(size: Theme.Size.base, weight: .semibold))
                    Text(choice.target.cert.subject).font(.system(size: Theme.Size.sm)).lineLimit(2)
                    Text("Token: \(choice.target.tokenSerial)")
                        .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted).lineLimit(1)
                    Text("CKS: \(choice.target.cert.serialHex) · Hết hạn: \(choice.target.cert.notAfter)")
                        .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted).lineLimit(2)
                    if let reason = choice.unavailableReason ?? choice.warning {
                        Text(reason).font(.system(size: Theme.Size.xs, weight: .medium)).foregroundStyle(Theme.warning)
                    }
                }
                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(12)
            .background(selected ? Theme.secondary : Theme.surface)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(selected ? Theme.primary : Theme.borderStrong, lineWidth: 1))
            .contentShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain).disabled(!choice.canSelect)
        .accessibilityLabel("\(choice.target.module.ca), \(choice.target.cert.subject), token \(choice.target.tokenSerial)")
        .accessibilityValue(selected ? "Đã chọn" : (choice.unavailableReason ?? "Chưa chọn"))
    }
}
