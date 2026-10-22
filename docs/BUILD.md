# Build và test app tích hợp

Chạy tại checkout gốc, nhánh `p1-token-core`. Tất cả bridge dùng cùng một app;
không build/chạy worktree eSigner hoặc Minvoice riêng để nghiệm thu bản hiện tại.
`Package.resolved` được version hóa để cố định dependency đã kiểm tra.

```sh
./scripts/test-env.sh test-all
./scripts/package-test-app.sh
python3 scripts/check-integrated-app.py
./scripts/run-test-app.sh all
```

Smoke tự mở rồi đóng app của nó; hãy đóng app đang chạy trước khi smoke hoặc
đóng gói. `run-test-app.sh fastca|minvoice|esigner|vnpt` là alias của cùng app gốc,
không chuyển worktree. Xem [BRIDGES.md](BRIDGES.md) về sáu listener và TLS localhost.

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
