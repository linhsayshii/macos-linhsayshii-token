# Build and test

Môi trường test FastCA + M-Invoice đã được chuẩn bị: xem
[TEST-ENVIRONMENT.md](TEST-ENVIRONMENT.md). Từ checkout gốc, chạy
`./scripts/test-env.sh test-all`; runner tự cấu hình cache và Testing paths cho
hai worktree. Dùng `./scripts/run-test-app.sh fastca|minvoice` để mở từng app sau
khi build. Hai app phải chạy lần lượt vì cùng dùng cổng 32001.

Command Line Tools only (no Xcode). Build:

    swift build

Run tests — this environment needs the Testing macro plugin path passed explicitly,
or `swift test` fails with "plugin for module 'TestingMacros' not found":

    swift test -Xswiftc -plugin-path -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing

Do not run two `swift build`/`swift test` processes against this checkout at once; they
corrupt each other's `.build`.

## SwiftUI without full Xcode

Command Line Tools ship no SwiftUI macro plugin, so `@State` / `@Bindable` / `@Observable`
do not compile here. The App target uses the pre-macro pattern instead: `ObservableObject`
+ `@Published` + `@StateObject` / `@ObservedObject`. Install full Xcode to switch to the
macro style.

## FastCA native

App/TokenHelper đã dùng backend ESPK/OpenSC cho FastCA. Chạy
`./scripts/test-env.sh setup-fastca` để kiểm tra runtime OpenSC 0.27.1, build/test
như trên, rồi `./scripts/package-test-app.sh` để tạo
`.local/test-env/TokenSigner.app` từ outputs có sẵn. Không dùng/copy `libcastle`
cho backend mới. Xem [FASTCA.md](FASTCA.md) về runtime, phạm vi và kiểm tra thật.
