import SwiftUI
import Core

struct OriginPromptSheet: View {
    let origin: String
    @ObservedObject var model: AppModel
    var body: some View {
        PromptContainer(title: "Quyền truy cập trang web", symbol: "globe.badge.chevron.backward") {
            Text("Trang web muốn kết nối TokenSigner").font(.system(size: Theme.Size.base, weight: .medium))
            AppCard { DetailLine(label: "Địa chỉ trang web", value: origin) }
            InlineNotice(text: "Trang này chưa nằm trong danh sách cho phép. Chỉ cho phép nếu bạn tin tưởng.", tone: .warning)
            Text("Cho phép kết nối không tự động đồng ý ký. Mỗi yêu cầu vẫn qua bước chọn chứng thư, duyệt và nhập PIN theo phiên.")
                .foregroundStyle(Theme.muted)
        } actions: {
            HStack {
                Button("Từ chối") { model.answerOrigin(allow: false) }
                    .buttonStyle(ThemeSecondaryButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Cho phép kết nối") { model.answerOrigin(allow: true) }.buttonStyle(ThemePrimaryButtonStyle())
            }
        }
    }
}
