import SwiftUI
import Core
import Bridges

struct MenuBarView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var presentation = MenuPresentation()

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "key.fill").font(.system(size: 18))
                        .frame(width: 32, height: 32).background(Theme.secondary, in: RoundedRectangle(cornerRadius: 8))
                    Text("TokenSigner").font(.system(size: Theme.Size.lg, weight: .semibold))
                    Spacer()
                    Button { presentation.page = .connections } label: {
                        let ready = model.bridges.filter { $0.status == .up }.count
                        StatusBadge(text: "\(ready)/\(model.bridges.count)", tone: ready == model.bridges.count ? .success : .warning)
                    }.buttonStyle(.plain).help("Trạng thái kết nối dịch vụ")
                }
                HStack(spacing: 4) {
                    ForEach(MenuPresentation.Page.allCases, id: \.self) { page in
                        Button { presentation.page = page } label: {
                            Text(page.rawValue).font(.system(size: Theme.Size.sm, weight: .medium))
                                .frame(maxWidth: .infinity).padding(.vertical, 7)
                                .background(presentation.page == page ? Theme.surface : .clear, in: RoundedRectangle(cornerRadius: 6))
                        }.buttonStyle(.plain).accessibilityAddTraits(presentation.page == page ? .isSelected : [])
                    }
                }.padding(3).background(Theme.secondary, in: RoundedRectangle(cornerRadius: 8))
            }.padding(16)
            Divider().overlay(Theme.border)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    switch presentation.page {
                    case .tokens:
                        SectionHeader(title: "Chữ ký số", detail: "\(model.tokens.count) token")
                        if model.tokens.isEmpty {
                            AppCard { VStack(alignment: .leading, spacing: 8) {
                                Label("Chưa có token kết nối", systemImage: "externaldrive.badge.plus").fontWeight(.medium)
                                Text("Cắm USB token vào máy. Danh sách sẽ tự cập nhật.").foregroundStyle(Theme.muted)
                            }}
                        }
                        ForEach(model.tokens) { token in
                            TokenCard(token: token, presentation: presentation, busy: model.isWorking) {
                                Task { await model.testSign(serial: token.serial) }
                            }
                        }
                    case .connections: ConnectionView(model: model)
                    case .history: HistoryView(entries: model.recentAudit)
                    }
                    if let batch = model.minvoiceBatch { batchDetails(batch) }
                    if let result = model.signingResult {
                        DisclosureGroup("Kết quả gần nhất") {
                            Text(result.message).font(.system(size: Theme.Size.sm)).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            }.id(presentation.page).frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider().overlay(Theme.border)
            footer.padding(16)
        }
        .frame(width: presentation.size.width, height: presentation.size.height)
        .font(.system(size: Theme.Size.sm))
        .background(Theme.background).foregroundStyle(Theme.foreground)
        .disclosureGroupStyle(ThemeDisclosureStyle()).tokenSignerAppearance()
    }

    private var footer: some View {
        VStack(spacing: 10) {
            if let status = model.signingStatus {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(status).font(.system(size: Theme.Size.xs)).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                }.accessibilityLabel(status)
            } else if let result = model.signingResult {
                InlineNotice(text: result.title, tone: result.tone)
            }
            if model.minvoiceBatchActive {
                Button("Hủy lô Minvoice") { model.cancelMinvoiceBatch() }
                    .buttonStyle(ThemeSecondaryButtonStyle()).foregroundStyle(Theme.danger)
            }
            Button { Task { await model.testSign(serial: "") } } label: {
                Label("Chọn CKS và ký thử…", systemImage: "signature").frame(maxWidth: .infinity)
            }.buttonStyle(ThemePrimaryButtonStyle()).disabled(model.isWorking || !model.tokens.contains { $0.supported && !$0.serial.isEmpty })
            HStack {
                Text("Khóa bí mật nằm trong token").font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                Spacer()
                Button("Thoát") { NSApplication.shared.terminate(nil) }
                    .buttonStyle(.plain).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
                    .disabled(model.isWorking)
            }
        }
    }

    private func batchDetails(_ batch: MinvoiceBatchProgress) -> some View {
        DisclosureGroup("Lô Minvoice · \(batch.acknowledged)/\(batch.totalInvoices)") {
            VStack(alignment: .leading, spacing: 8) {
                Text(batch.summary).textSelection(.enabled)
                Text("Số hóa đơn và số XML/chữ ký có thể khác nhau.").foregroundStyle(Theme.muted)
                ForEach(Array(batch.groups.enumerated()), id: \.offset) { index, group in
                    Text("Nhóm \(index + 1): \(group.invoices) hóa đơn · \(group.signedDocuments)/\(group.documents) XML · \(batchState(group.state))")
                }
            }.font(.system(size: Theme.Size.sm))
        }
    }

    private func batchState(_ state: MinvoiceBatchProgress.State) -> String {
        switch state {
        case .pending: "chưa chạy"
        case .downloading: "đang tải XML"
        case .signing: "đang ký/kiểm tra"
        case .uploading: "đang upload"
        case .acknowledged: "đã xác nhận upload"
        case .failed: "lỗi, chưa upload"
        case .cancelled: "đã hủy, chưa upload"
        case .uploadUncertain: "upload chưa rõ kết quả"
        }
    }
}
