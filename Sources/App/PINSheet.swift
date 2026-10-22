import SwiftUI
import Core

/// PIN entry for a login/sign. The PIN string goes straight to the helper via
/// AppModel; it is cleared on submit and never logged or stored. The draft lives
/// in AppModel (this toolchain lacks the SwiftUI @State macro), not in the view.
struct PINSheet: View {
    let prompt: AppModel.PINPrompt
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Đăng nhập token").font(.system(size: Theme.Size.lg, weight: .semibold))

            VStack(alignment: .leading, spacing: 2) {
                Text(prompt.ca).font(.system(size: Theme.Size.sm, weight: .medium))
                Text(prompt.serial).font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)
            }

            if let w = prompt.warning {
                Text(w)
                    .font(.system(size: Theme.Size.xs, weight: .medium))
                    .foregroundStyle(Theme.danger)
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Theme.dangerBg)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            SecureField("Nhập mã PIN", text: $model.pinDraft)
                .textFieldStyle(.plain)
                .font(.system(size: Theme.Size.base))
                .padding(.horizontal, 12).frame(height: 40)
                .background(Theme.surface)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.borderStrong, lineWidth: 1))
                .disabled(prompt.locked)
                .onSubmit(submit)

            Text("Sai PIN sẽ trừ một lần thử.")
                .font(.system(size: Theme.Size.xs)).foregroundStyle(Theme.muted)

            HStack {
                Spacer()
                Button("Huỷ") { model.submitPIN(nil) }
                    .keyboardShortcut(.cancelAction)
                    .buttonStyle(.plain)
                    .font(.system(size: Theme.Size.sm))
                    .foregroundStyle(Theme.muted)
                Button("Đăng nhập", action: submit)
                    .font(.system(size: Theme.Size.sm, weight: .medium))
                    .buttonStyle(.borderedProminent)
                    .disabled(prompt.locked || model.pinDraft.isEmpty)
            }
        }
        .padding(20).frame(width: 320)
        .background(Theme.background).foregroundStyle(Theme.foreground)
        .preferredColorScheme(.light)
    }

    private func submit() {
        guard !model.pinDraft.isEmpty, !prompt.locked else { return }
        model.submitPIN(model.pinDraft)   // submitPIN clears the draft
    }
}
