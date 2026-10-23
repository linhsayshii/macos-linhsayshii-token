import SwiftUI
import Core

struct PINSheet: View {
    let prompt: AppModel.PINPrompt
    @ObservedObject var model: AppModel
    @FocusState private var focused: Bool
    var body: some View {
        PromptContainer(title: "Nhập PIN token", symbol: "lock", step: "Bước 3 · Ký số · \(prompt.ca)") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Mã PIN").fontWeight(.medium)
                SecureField("Nhập mã PIN", text: $model.pinDraft)
                    .textFieldStyle(.plain).font(.system(size: Theme.Size.base))
                    .padding(.horizontal, 12).frame(height: 42)
                    .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.control))
                    .overlay(RoundedRectangle(cornerRadius: Theme.Radius.control).stroke(focused ? Theme.foreground : Theme.borderStrong, lineWidth: focused ? 2 : 1))
                    .focused($focused).disabled(prompt.locked).onSubmit(submit)
                    .accessibilityLabel("Mã PIN token")
            }
            if let warning = prompt.warning { InlineNotice(text: warning, tone: prompt.locked ? .danger : .warning) }
            AppCard { DetailLine(label: "Serial token", value: prompt.serial) }
            InlineNotice(text: "Sai PIN sẽ trừ một lần thử. App không tự thử lại.")
        } actions: {
            HStack {
                Button("Hủy") { model.submitPIN(nil) }.buttonStyle(ThemeSecondaryButtonStyle()).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Xác nhận và ký", action: submit).buttonStyle(ThemePrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction).disabled(prompt.locked || model.pinDraft.isEmpty)
            }
        }.onAppear { focused = !prompt.locked }
    }
    private func submit() {
        guard !model.pinDraft.isEmpty, !prompt.locked else { return }
        model.submitPIN(model.pinDraft)
    }
}
