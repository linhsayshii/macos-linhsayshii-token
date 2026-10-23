import SwiftUI
import Bridges

struct ConnectionView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        SectionHeader(title: "Dịch vụ ký", detail: "Chỉ trên máy này")
        AppCard {
            VStack(spacing: 14) {
                ForEach(BridgeService.allCases) { service in
                    let rows = model.bridges.filter { $0.id.service == service }
                    VStack(alignment: .leading, spacing: 7) {
                        HStack(alignment: .center, spacing: 10) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(service.name).fontWeight(.medium)
                                Text("Cổng " + rows.map { String($0.endpoint.port) }.joined(separator: " · "))
                                    .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            let summary = summary(rows)
                            StatusBadge(text: summary.0, tone: summary.1)
                                .fixedSize()
                            Toggle(service.name, isOn: Binding(get: { model.serviceEnabled(service) },
                                                              set: { model.setServiceEnabled(service, $0) }))
                                .labelsHidden()
                                .toggleStyle(.switch).controlSize(.small)
                                .tint(Theme.success)
                                .disabled(!model.canChangeServices)
                                .accessibilityLabel("Dịch vụ \(service.name)")
                        }
                        ForEach(rows) { row in
                            if case .failed(let message) = row.status {
                                InlineNotice(text: "Cổng \(row.endpoint.port): \(message)", tone: .danger)
                            } else if row.status == .portInUse {
                                InlineNotice(text: "Cổng \(row.endpoint.port) đang được ứng dụng khác sử dụng.", tone: .warning)
                            }
                        }
                    }
                    if service != BridgeService.allCases.last { Divider().overlay(Theme.border) }
                }
            }
        }
        Text(!model.canChangeServices ? "Chờ yêu cầu hoặc thao tác hiện tại hoàn tất để đổi dịch vụ." : "Lựa chọn được lưu cho lần mở app tiếp theo.")
            .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
        if let error = model.serviceSettingsError { InlineNotice(text: error, tone: .danger) }
        SectionHeader(title: "Chứng chỉ localhost")
        AppCard {
            VStack(alignment: .leading, spacing: 12) {
                InlineNotice(text: model.trustStatus, tone: model.localhostTrusted ? .success : .warning)
                if !model.localhostTrusted {
                    Text("VNPT dùng kết nối bảo mật trên máy. macOS sẽ hỏi quyền khi bạn tin cậy chứng chỉ.")
                        .foregroundStyle(Theme.muted)
                    Button("Tin cậy localhost cho VNPT") { model.trustLocalhostCertificate() }
                        .buttonStyle(ThemeSecondaryButtonStyle())
                }
            }
        }
        SectionHeader(title: "Trang được cho phép")
        if model.allowedOrigins.isEmpty {
            Text("Chưa thêm trang ngoài danh sách mặc định. Trang mới sẽ hỏi quyền trước khi ký.").foregroundStyle(Theme.muted)
        }
        ForEach(model.allowedOrigins, id: \.self) { host in
            AppCard {
                HStack(alignment: .top) {
                    Text(host).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    Button("Gỡ") { model.removeOrigin(host) }.buttonStyle(.plain).foregroundStyle(Theme.danger)
                        .accessibilityLabel("Gỡ quyền \(host)")
                }
            }
        }
    }
    private func summary(_ rows: [AppModel.BridgeRow]) -> (String, NoticeTone) {
        if rows.allSatisfy({ $0.status == .disabled }) { return ("Đã tắt", .neutral) }
        if rows.contains(where: { $0.status == .stopping }) { return ("Đang tắt", .neutral) }
        if rows.contains(where: { $0.status == .starting }) { return ("Đang mở", .neutral) }
        let ready = rows.filter { $0.status == .up }.count
        if ready == rows.count { return ("Sẵn sàng", .success) }
        if ready > 0 { return ("\(ready)/\(rows.count) sẵn sàng", .warning) }
        if rows.contains(where: { $0.status == .portInUse }) { return ("Cổng bị chiếm", .warning) }
        return ("Lỗi", .danger)
    }
}
