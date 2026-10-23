import SwiftUI
import Core
import Bridges

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
                Text(r).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted).textSelection(.enabled)
            }
            if model.minvoiceBatchActive {
                Button("Hủy lô Minvoice") { model.cancelMinvoiceBatch() }
                    .buttonStyle(.plain).font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.danger)
            }
            if let batch = model.minvoiceBatch {
                DisclosureGroup("Lô Minvoice · \(batch.acknowledged)/\(batch.totalInvoices)") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Số hóa đơn theo nhóm upload; số XML/chữ ký có thể khác.")
                        ScrollView {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(Array(batch.groups.enumerated()), id: \.offset) { index, group in
                                    Text("Nhóm \(index + 1): \(group.invoices) hóa đơn · \(group.signedDocuments)/\(group.documents) XML · \(batchState(group.state))")
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }.frame(height: min(150, CGFloat(batch.groups.count * 36)))
                    }
                    .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                }.font(.system(size: Theme.Size.sm))
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

    private func batchState(_ state: MinvoiceBatchProgress.State) -> String {
        switch state {
        case .pending: return "chưa chạy"
        case .downloading: return "đang tải XML"
        case .signing: return "đang ký/kiểm tra"
        case .uploading: return "đang upload"
        case .acknowledged: return "đã xác nhận upload"
        case .failed: return "lỗi, chưa upload"
        case .cancelled: return "đã hủy, chưa upload"
        case .uploadUncertain: return "upload chưa rõ kết quả"
        }
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
