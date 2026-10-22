import SwiftUI
import Core

struct MenuBarView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(model.bridges) { row in
                HStack(spacing: 8) {
                    Circle().fill(statusColor(row.status)).frame(width: 8, height: 8)
                    Text("\(row.endpoint.name) · \(String(row.endpoint.port))").font(.system(size: Theme.Size.sm))
                    Spacer(minLength: 4)
                    Text(statusText(row.status)).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                }
            }
            DisclosureGroup("Kết nối và quyền") {
                VStack(alignment: .leading, spacing: 8) {
                    Text(model.trustStatus).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                    if !model.localhostTrusted {
                        Text("VNPT dùng SSL localhost. macOS sẽ hỏi quyền khi bạn tin cậy chứng chỉ.")
                            .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                        Button("Tin cậy localhost cho VNPT") { model.trustLocalhostCertificate() }
                            .buttonStyle(.bordered)
                    }
                    ForEach(model.allowedOrigins, id: \.self) { host in
                        HStack {
                            Text(host).font(.system(size: Theme.Size.xs))
                            Spacer()
                            Button("Gỡ") { model.removeOrigin(host) }
                                .buttonStyle(.plain).foregroundStyle(Theme.danger)
                        }
                    }
                }.padding(.top, 6)
            }.font(.system(size: Theme.Size.sm))
            Divider().overlay(Theme.border)
            tokenSection
            Button { Task { await model.testSign(serial: "") } } label: {
                Text("Chọn CKS và ký thử…").frame(maxWidth: .infinity)
            }
                .font(.system(size: Theme.Size.sm))
                .buttonStyle(ThemePrimaryButtonStyle())
            if let s = model.signingStatus {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(s).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                }
            } else if let r = model.lastSignResult {
                Text(r).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
            }
            if !model.recentAudit.isEmpty {
                DisclosureGroup("Lịch sử ký gần đây") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(model.recentAudit.reversed().enumerated()), id: \.offset) { _, entry in
                            Text("\(entry.bridge) · \(entry.result) · \(entry.time)")
                                .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                        }
                    }
                }.font(.system(size: Theme.Size.sm))
            }
            Divider().overlay(Theme.border)
            Button("Thoát") { NSApplication.shared.terminate(nil) }
                .buttonStyle(.plain)
                .font(.system(size: Theme.Size.sm))
                .foregroundStyle(Theme.muted)
        }
        .padding(16)
        .frame(width: 360)
        .background(Theme.background)
        .foregroundStyle(Theme.foreground)
        .disclosureGroupStyle(ThemeDisclosureStyle())
        .tokenSignerAppearance()
    }

    private func statusColor(_ status: AppModel.BridgeStatus) -> Color {
        switch status {
        case .up: return Theme.success
        case .starting: return Theme.warning
        case .portInUse, .failed: return Theme.danger
        }
    }
    private func statusText(_ status: AppModel.BridgeStatus) -> String {
        switch status {
        case .up: return "Sẵn sàng"
        case .starting: return "Khởi động…"
        case .portInUse: return "Cổng bị chiếm"
        case .failed: return "Lỗi khởi động"
        }
    }

    @ViewBuilder private var tokenSection: some View {
        Text("TOKEN").font(.system(size: Theme.Size.xs, weight: .medium)).foregroundStyle(Theme.muted)
        if model.tokens.isEmpty {
            Text("Chưa cắm token").font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.muted)
        } else {
            ForEach(model.tokens) { t in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(t.ca).font(.system(size: Theme.Size.sm, weight: .medium))
                        if !t.supported {
                            Text("Chưa hỗ trợ")
                                .font(.system(size: Theme.Size.xs))
                                .foregroundStyle(Theme.warning)
                        } else if t.experimental {
                            Text("Thử nghiệm")
                                .font(.system(size: Theme.Size.xs))
                                .foregroundStyle(Theme.warning)
                        }
                        Spacer()
                        if !t.serial.isEmpty {
                            Text(t.serial).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                        }
                    }
                    if let subj = t.certSubject {
                        Text(subj).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted).lineLimit(1)
                    }
                    if let exp = t.notAfter {
                        Text("Hết hạn: \(exp)").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                    }
                    if let error = t.readError {
                        Text(error).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.warning)
                    }
                    if t.supported && !t.serial.isEmpty {
                        Button("Ký thử") { Task { await model.testSign(serial: t.serial) } }
                            .buttonStyle(.plain)
                            .font(.system(size: Theme.Size.xs, weight: .medium))
                            .foregroundStyle(Theme.primary)
                            .padding(.top, 2)
                    }
                }
                .padding(.vertical, 2)
            }
        }
    }
}
