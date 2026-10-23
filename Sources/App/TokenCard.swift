import SwiftUI

struct TokenCard: View {
    let token: AppModel.TokenRow
    @ObservedObject var presentation: MenuPresentation
    let busy: Bool
    let sign: () -> Void
    private var expanded: Binding<Bool> {
        Binding(get: { presentation.expandedTokens.contains(token.id) }, set: { value in
            if value { presentation.expandedTokens.insert(token.id) } else { presentation.expandedTokens.remove(token.id) }
        })
    }
    var body: some View {
        AppCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top) {
                    Label(token.ca, systemImage: "externaldrive").font(.system(size: Theme.Size.base, weight: .semibold))
                    Spacer(minLength: 4)
                    if !token.supported { StatusBadge(text: "Chưa hỗ trợ", tone: .warning) }
                    else if token.experimental { StatusBadge(text: "Thử nghiệm", tone: .warning) }
                }
                if token.certSubject != nil {
                    Text(token.certificateName ?? "Chứng thư số").font(.system(size: Theme.Size.sm, weight: .medium)).lineLimit(2)
                }
                if let raw = token.notAfter {
                    let expired = CertificateText.date(raw).map { $0 < Date() } ?? false
                    Label("\(expired ? "Đã hết hạn" : "Hết hạn"): \(CertificateText.localDate(raw))", systemImage: expired ? "exclamationmark.triangle" : "calendar")
                        .font(.system(size: Theme.Size.xs)).foregroundStyle(expired ? Theme.warning : Theme.muted)
                }
                if let error = token.readError { InlineNotice(text: error, tone: .warning) }
                HStack {
                    Button { expanded.wrappedValue.toggle() } label: {
                        Label(expanded.wrappedValue ? "Thu gọn" : "Chi tiết", systemImage: expanded.wrappedValue ? "chevron.up" : "chevron.down")
                    }.buttonStyle(.plain).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                        .accessibilityValue(expanded.wrappedValue ? "Đã mở" : "Đã thu gọn")
                    Spacer()
                    if token.supported && !token.serial.isEmpty {
                        Button("Ký thử", action: sign).buttonStyle(ThemeSecondaryButtonStyle()).disabled(busy)
                    }
                }
                if expanded.wrappedValue {
                    Divider().overlay(Theme.border)
                    DetailLine(label: "Serial token", value: token.serial.isEmpty ? "Chưa đọc được" : token.serial)
                    DetailLine(label: "Đầu đọc", value: token.reader)
                    if let subject = token.certSubject { DetailLine(label: "Chủ thể chứng thư", value: subject) }
                }
            }
        }
    }
}
