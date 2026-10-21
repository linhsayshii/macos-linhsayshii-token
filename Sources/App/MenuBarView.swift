import SwiftUI
import Core

struct MenuBarView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            statusLine
            Divider().overlay(Theme.border)
            tokenSection
            if model.activeSigns > 0 {
                Text("Đang ký \(model.activeSigns)").font(.system(size: Theme.Size.xs, weight: .medium)).foregroundStyle(Theme.primary)
            }
            if let s = model.signingStatus {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text(s).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                }
            } else if let r = model.lastSignResult {
                Text(r).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
            }
            Divider().overlay(Theme.border)
            auditSection
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
        .sheet(item: $model.approvalPrompt) { ApprovalSheet(prompt: $0, model: model) }
        .sheet(item: Binding(get: { model.originPrompt.map(OriginItem.init) }, set: { _ in })) { OriginPromptSheet(origin: $0.id, model: model) }
        .sheet(item: $model.pinPrompt) { PINSheet(prompt: $0, model: model) }
    }

    private var statusLine: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(model.bridges) { b in
                HStack(spacing: 8) {
                    Circle().fill(color(b.status)).frame(width: 8, height: 8)
                    Text(text(b)).font(.system(size: Theme.Size.sm))
                    Spacer()
                }
            }
            if !model.localhostTrusted {
                Button("Tin cậy chứng chỉ localhost (cho VNPT-CA)") { model.trustLocalhostCertificate() }
                    .buttonStyle(.plain).font(.system(size: Theme.Size.xs, weight: .medium)).foregroundStyle(Theme.warning)
            }
        }
    }

    private func color(_ s: AppModel.BridgeStatus) -> Color {
        switch s {
        case .up: return Theme.success
        case .starting: return Theme.warning
        case .portInUse, .failed: return Theme.danger
        }
    }

    private func text(_ b: AppModel.BridgeRow) -> String {
        switch b.status {
        case .starting: return "\(b.name): đang khởi động…"
        case .up: return "\(b.name) · cổng \(b.port)"
        case .portInUse: return "\(b.name): cổng \(b.port) đã bị chiếm"
        case .failed(let m): return "\(b.name): lỗi \(m)"
        }
    }

    @ViewBuilder private var auditSection: some View {
        Text("LẦN KÝ GẦN ĐÂY").font(.system(size: Theme.Size.xs, weight: .medium)).foregroundStyle(Theme.muted)
        if model.recentAudit.isEmpty {
            Text("Chưa có lần ký nào").font(.system(size: Theme.Size.sm)).foregroundStyle(Theme.muted)
        } else {
            ForEach(Array(model.recentAudit.enumerated()), id: \.offset) { _, e in
                Text("\(e.time.suffix(9).prefix(8)) · \(e.bridge) · \(e.operation) · \(e.result == "ok" ? "OK" : "lỗi")")
                    .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted).lineLimit(1)
            }
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

private struct OriginItem: Identifiable { let id: String }
