import SwiftUI

struct ConnectionView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        SectionHeader(title: "Dịch vụ ký", detail: "Chỉ trên máy này")
        AppCard {
            VStack(spacing: 12) {
                ForEach(model.bridges) { row in
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(row.endpoint.name).fontWeight(.medium)
                            Text("Cổng \(String(row.endpoint.port))").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                        }
                        Spacer(minLength: 4)
                        StatusBadge(text: status(row.status).0, tone: status(row.status).1)
                    }
                    if case .failed(let message) = row.status { InlineNotice(text: message, tone: .danger) }
                }
            }
        }
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
    private func status(_ status: AppModel.BridgeStatus) -> (String, NoticeTone) {
        switch status {
        case .up: ("Sẵn sàng", .success)
        case .starting: ("Đang mở", .neutral)
        case .portInUse: ("Cổng bị chiếm", .warning)
        case .failed: ("Lỗi", .danger)
        }
    }
}
