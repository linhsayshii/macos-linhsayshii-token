import SwiftUI
import Core

struct MenuBarView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            statusLine
            ForEach([8768, 8769], id: \.self) { port in
                HStack(spacing: 8) {
                    Circle().fill(esignerColor(port)).frame(width: 8, height: 8)
                    Text(esignerText(port)).font(.system(size: Theme.Size.xs))
                }
            }
            Text(model.minvoiceStatus).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
            Divider().overlay(Theme.border)
            tokenSection
            Button("Chọn CKS và ký thử…") { Task { await model.testSign(serial: "") } }
                .font(.system(size: Theme.Size.sm))
            if let s = model.signingStatus {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(s).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                }
            } else if let r = model.lastSignResult {
                Text(r).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
            }
            Divider().overlay(Theme.border)
            Button("Thoát") { NSApplication.shared.terminate(nil) }
                .buttonStyle(.plain)
                .font(.system(size: Theme.Size.sm))
                .foregroundStyle(Theme.muted)
        }
        .padding(16)
        .frame(width: 320)
        .background(Theme.background)
        .foregroundStyle(Theme.foreground)
    }

    private var statusLine: some View {
        HStack(spacing: 8) {
            Circle().fill(statusColor).frame(width: 8, height: 8)
            Text(statusText).font(.system(size: Theme.Size.sm))
            Spacer()
        }
    }

    private var statusColor: Color {
        switch model.bridgeStatus {
        case .up: return Theme.success
        case .starting: return Theme.warning
        case .portInUse, .failed: return Theme.danger
        }
    }

    private var statusText: String {
        switch model.bridgeStatus {
        case .starting: return "CTSigningHub · 32001 khởi động…"
        case .up: return "CTSigningHub · 32001 sẵn sàng"
        case .portInUse: return "CTSigningHub · 32001 đã bị chiếm"
        case .failed(let m): return "Lỗi: \(m)"
        }
    }

    private func esignerColor(_ port: Int) -> Color {
        switch model.esignerStatuses[port] ?? .starting {
        case .up: return Theme.success
        case .starting: return Theme.warning
        case .portInUse, .failed: return Theme.danger
        }
    }
    private func esignerText(_ port: Int) -> String {
        let prefix = "eSigner · \(port)"
        switch model.esignerStatuses[port] ?? .starting {
        case .up: return "\(prefix) sẵn sàng"
        case .starting: return "\(prefix) khởi động…"
        case .portInUse: return "\(prefix) đã bị chiếm"
        case .failed: return "\(prefix) lỗi khởi động"
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
