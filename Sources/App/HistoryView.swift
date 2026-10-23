import SwiftUI
import Core

struct HistoryView: View {
    let entries: [AuditEntry]
    var body: some View {
        SectionHeader(title: "Lịch sử ký gần đây")
        if entries.isEmpty {
            AppCard { InlineNotice(text: "Chưa có hoạt động ký. Kết quả sẽ hiện ở đây sau khi xử lý yêu cầu.") }
        }
        ForEach(Array(entries.reversed().enumerated()), id: \.offset) { _, entry in
            AppCard {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(bridgeName(entry.bridge)).fontWeight(.semibold)
                        Spacer()
                        StatusBadge(text: result(entry.result).0, tone: result(entry.result).1)
                    }
                    Text(CertificateText.localDate(entry.time, withTime: true)).foregroundStyle(Theme.muted)
                    Text(entry.origin).lineLimit(2)
                    DisclosureGroup("Chi tiết") {
                        VStack(alignment: .leading, spacing: 10) {
                            DetailLine(label: "Thời gian chuẩn", value: entry.time)
                            DetailLine(label: "Nguồn yêu cầu", value: entry.origin)
                            DetailLine(label: "Serial chứng thư", value: entry.certSerial)
                            DetailLine(label: "SHA-256 dữ liệu chuẩn bị ký", value: entry.inputSHA256)
                            Text("\(entry.operation) · \(entry.result)").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                        }
                    }
                }
            }
        }
    }
    private func bridgeName(_ name: String) -> String {
        switch name.lowercased() { case "menu": "Ký thử"; case "ctsign", "ctsigninghub": "CTSigningHub"; case "minvoice": "Minvoice"; case "vnpt": "VNPT-CA"; case "esigner": "eSigner"; default: name }
    }
    private func result(_ value: String) -> (String, NoticeTone) {
        switch value { case "ok": ("Thành công", .success); case "cancelled": ("Đã hủy", .neutral); default: ("Chưa hoàn tất", .danger) }
    }
}
