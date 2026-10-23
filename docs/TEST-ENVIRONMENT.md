# Môi trường test app tích hợp

Chỉ dùng checkout gốc `main`. Toàn bộ app/helper/bridge build từ cùng
`Package.swift` và `Package.resolved`; không còn tuyến test Minvoice worktree riêng.

```sh
./scripts/test-env.sh check
./scripts/test-env.sh test-all
./scripts/test-env.sh test-minvoice
./scripts/package-test-app.sh
python3 scripts/check-integrated-app.py
python3 scripts/check-native-espk.py
./scripts/run-test-app.sh all --print
./scripts/run-test-app.sh all
```

Không chạy đồng thời hai builder trong checkout hoặc hai app đang dùng token.
`run-test-app.sh fastca|minvoice|esigner|vnpt` chỉ là alias của app gốc.
`TOKENSIGNER_PORT_OFFSET=100` dịch cả sáu cổng khi chủ động thử dev instance;
không dùng offset để chạy hai luồng đăng nhập token cùng lúc.

App đóng gói tại `.local/test-env/TokenSigner.app`, ký ad-hoc. FastCA và EFY dùng
runtime OpenSC 0.27.1 ARM64 trong bundle cùng libcrypto, dependency closure và
license. Khi đóng gói, script sao chép runtime đã kiểm chứng có sẵn trên máy;
không tải/cài middleware hãng. Helper phát triển rời có thể dùng runtime ngoài.
TLS VNPT tạo/tái dùng `~/Library/Application Support/TokenSigner/tls`; khóa mode
0600, thư mục 0700. Tin cậy Keychain không chạy trong suite hay smoke.

Smoke kiểm tra sáu listener với request version/check-plugin, TLS bằng public
CA được pin riêng trong client test, origin 403, route CTSign và Minvoice SignalR.
Không nhập PIN, tạo chữ ký, đăng nhập nghiệp vụ hoặc upload thật.

Hướng dẫn cũ đã lưu tại
[archive/TEST-ENVIRONMENT-before-consolidation.md](archive/TEST-ENVIRONMENT-before-consolidation.md).
