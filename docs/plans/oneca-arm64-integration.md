# Kế hoạch tích hợp OneCA V3 vào app chính

Ngày: 23/10/2026. Người dùng yêu cầu lập kế hoạch và báo cho luồng chính để tích hợp.

## Kết quả và phạm vi handoff

**Đường OneCA ARM64 đã triển khai trong shared checkout và đã ký thử thành công.** Phần còn lại là review, hợp nhất với thay đổi đang làm ở luồng chính, build app hoàn chỉnh và kiểm tra bản đóng gói tại thời điểm cập nhật phù hợp. Không cần thực hiện lại nghiên cứu Windows hay tìm module từ đầu.

Luồng chính: **“Tiếp tục phần còn lại của dự án”**, thread `01a16222-0b7d-7d91-9daa-8a12c6a35d07`.

- [Báo cáo runtime ARM64](../re/oneca-macos-arm.md).
- [Bằng chứng ký và verify độc lập](../re/evidence/oneca-arm64-signing-validation.json).
- [Inventory tích hợp, hash source/module/helper](../re/evidence/oneca-arm64-integration.json).
- [Nghiên cứu Windows ban đầu](../re/oneca-windows.md): chỉ dùng làm lịch sử và đối chiếu; kết luận candidate x86_64 cũ đã được thay thế bởi kết quả ARM64.

## Đầu vào đã sẵn sàng

### Module vendor nguyên gốc

```text
Tên: libcryptoida_pkcs11_f2.dylib
Kiến trúc: universal x86_64 + arm64; runtime đã kiểm chứng arm64
SHA-256: b4e1b8d804ebf444b3c1acc7222a27dfb5d42cea7f6c51d3e067bdcbf2bbef0c
Developer ID: Beijing Century Longmai Technology Co.,Ltd (4M7RX53G2N)
Nguồn: https://prodigisign.com/utilities/
Archive: https://prodigisign.com/repository/mac-driver.zip
Đã đặt tại: ~/Library/Application Support/TokenSigner/modules/libcryptoida_pkcs11_f2.dylib
```

Bản chạy là universal nguyên gốc đã ký, không phải ARM64 thin phục vụ disassembler. Không chạy installer/postinstall và không cần cài Qt app. Không thay bằng `libcryptoid_pkcs11.dylib` 2020, wrapper hoặc F3: đó không phải artifact đã ký thử thành công.

Raw package và bản giải nén giữ tại `.local/oneca-windows/mac-reference/`; không đưa binary thô, certificate cá nhân, PIN hay debug log vào commit.

### Chín đường dẫn source/test thuộc phần OneCA

| Đường dẫn | Việc đã làm |
|---|---|
| `Sources/Core/OneCAProfile.swift` | Exact ATR, hash module, lowercase reader filter, binding single-reader/single-token |
| `Sources/Core/ModuleRegistry.swift` | Full-ATR matcher trước bảng Feitian, backend `.oneca`, experimental |
| `Sources/Core/TokenBroker.swift` | Native helper `--backend oneca --module ...`, bỏ injected shim cho OneCA |
| `Sources/TokenHelper/OneCA.swift` | Adapter PKCS#11, reader/serial checks, giữ một phiên login/sign/logout |
| `Sources/TokenHelper/PKCS11.swift` | Hash trước dlopen; cấu hình exported global ngắn trước initialize |
| `Sources/TokenHelper/main.swift` | Khởi tạo backend OneCA, tắt static shim policy |
| `Sources/TSShim/include/tsshim.h` | API đặt policy reencoding theo helper process |
| `Sources/TSShim/shim.c` | OneCA bypass Feitian reencoding; default của backend khác giữ nguyên |
| `Tests/CoreTests/ModuleRegistryTests.swift` | OneCA exact ATR và negative cases cho reader/token mơ hồ |

Các thay đổi **đã nằm trong cùng checkout**, chưa tạo commit riêng. Không cherry-pick, reset hoặc chép source cũ đè lên thay đổi của luồng chính. Khi stage, chọn đúng đường dẫn; tránh `git add .` trong workspace nhiều luồng.

## Thứ tự tích hợp tại luồng chính

### 1. Review và hợp nhất source

Đọc 9 đường dẫn trên cùng báo cáo ARM64. Giữ các điều kiện đã kiểm chứng:

- OneCA dùng full ATR `3b9f118131fe9f006a6d546f6b656e2d5b000581900061`; không route theo byte cuối `0x61` hoặc byte 19 `0x81` chung.
- Hash pin đúng module F2 trước load. Default filter vendor không nhận reader OneCAV3; dùng lowercase `longmai mtoken onecav3,not used,vid_055c&pid_0223`.
- **Không gọi `M_SetEnumString`**: code vendor copy `0x400` vào global 256 byte, đã làm hỏng function table ở process thử. Backend hiện ghi chuỗi ngắn vào exported data của đúng hash đã kiểm chứng; không sửa file dylib.
- Shim đã link **tĩnh** vào helper, do đó chỉ bỏ `DYLD_INSERT_LIBRARIES` là chưa đủ. Giữ `ts_set_reencoding_enabled(0)` trước khi load OneCA.
- Chỉ cho đúng một matching physical reader/full ATR và một token; từ chối nhiều OneCA hoặc binding mơ hồ. Không dùng synthetic slot description làm tên PC/SC.
- Sau login không refresh discovery trước sign; giữ vendor session. CKA_ID phải có giá trị; app tiếp tục verify signature với certificate/payload đã duyệt.

Không cần sửa bridge VNPT/CTSign/Minvoice để bổ sung OneCA: registry → broker → helper tạo signing target và giao diện ký hiện có dùng lại đường chung.

### 2. Hoàn tất build chung khi M-Invoice batch ổn định

Lượt build App trước đó gặp `MinvoiceSigningBackend.batchProgress` chưa tồn tại do luồng chính đang bổ sung file batch. Khi đọc lại lúc handoff, member đã xuất hiện trong `Sources/Bridges/MinvoiceInvoices.swift`; **chưa re-run build để xác nhận lỗi chung đã hết**. Luồng OneCA không sửa hay loại bỏ file batch.

Chạy tuần tự, tránh hai lệnh SwiftPM sửa cùng build directory:

```sh
swift build --product TokenHelper
swift build --product App
swift test --filter 'CoreTests|TSShimTests' \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
git diff --check
```

Plugin path là cấu hình đã pass trên host này; nếu active developer directory thay đổi, resolve lại đường tương ứng. Sau đó chạy test bridge/M-Invoice cần thiết cho phần việc luồng chính; không gán kết quả OneCA cho thay đổi batch chưa kiểm tra.

### 3. Kiểm tra helper bằng module đã staged

Read-only smoke test: registry nhận đúng OneCA; broker/helper chạy arm64; trả đúng reader thật, token và certificate; module sai hash bị từ chối. Lưu sanitized summary thay vì certificate DER/debug log vào Git.

Không cần ký lại chỉ để tạo thêm bằng chứng: đã có một chữ ký test hợp lệ từ helper mới, một lần user nhập PIN trực tiếp, verify Security.framework và OpenSSL. Nếu packaging hoặc code ký có thay đổi cần test lại, dùng luồng consent/PIN trực tiếp trong UI, không yêu cầu PIN qua chat/argv, không tự retry login khi sai PIN.

### 4. Đóng gói và chuyển sang app đang phục vụ

App đang chạy tại `.local/test-env/TokenSigner.app` được giữ nguyên trong lượt OneCA, PID ban đầu `32846`; source build/helper test không có nghĩa app cũ đã nhận OneCA. Tuân theo thời điểm/scope cập nhật đã được người dùng cho phép ở luồng chính; không tự kill app đang ký.

Khi chuyển bản: build/kiểm tra trước; thay App, TokenHelper và libTSShim đồng bộ; giữ module nguyên gốc tại module search directory; verify code signature và đúng hash module. Dùng workflow đóng gói hiện có, kiểm tra packaged shim sau policy change. Không chạy vendor package/postinstall để triển khai một dylib.

Smoke test bản đóng gói: app hiển thị OneCA và chứng thư đúng, cờ experimental đúng, chọn certificate tạo target backend `.oneca`, hủy PIN không ký, backend khác vẫn hoạt động với policy shim mặc định. Không chạy hai bản app dùng chung port hoặc thiết bị cùng lúc.

### 5. Chốt tích hợp

Ghi rõ trạng thái **đã cập nhật app hay mới source/helper**, snapshot build/test mới và các giới hạn. Commit chọn lọc source/test/docs/evidence OneCA cùng phần luồng chính chủ ý tích hợp; không stage binary và dữ liệu nhạy cảm trong `.local`.

## Acceptance và giới hạn

Đã đạt: native arm64; đúng token/full ATR; 1 cert DER 1304 byte/CKA_ID 20 byte; RSA PKCS#1 v1.5 SHA-256 trả 256 byte; Security.framework PASS; OpenSSL `Verified OK`; module sai hash bị từ chối; 45 Core/TSShim tests passed.

Luồng chính cần xác nhận: full App build với batch mới; packaged App/Helper/shim đồng bộ; UI app thực tế chọn đúng OneCA; smoke test các CA hiện có sau đổi shim policy.

Giới hạn giữ nguyên: experimental; một matching OneCAV3 tại một thời điểm; mới kiểm chứng một token/profile và module hash này; chưa test hotplug lúc ký, nhiều OneCA, Intel runtime, PIN sai/locked, hoặc nghiệp vụ/cổng/chain-revocation. Windows là nguồn đối chiếu tùy chọn, không còn là điều kiện để đường ký Mac ARM hoạt động.

## Cập nhật phạm vi các dòng OneCA — 23/10/2026

Main đã đóng gói V3 theo [packaged evidence](../re/evidence/oneca-packaged-app-2026-10-23.json). Phần kế hoạch phía trên là snapshot handoff ban đầu.

Yêu cầu compatibility mới được phân tích trong [inventory và kế hoạch các dòng OneCA](../re/oneca-family-coverage.md): V1/V3 thuộc Longmai CryptoID; V2 có registry mask và middleware EnterSafe/ESPK. Không mở rộng mọi OneCA qua F2 Longmai hoặc từ exact ATR thành PIN wildcard. Main tiếp nhận routing/native/UI/build; nghiên cứu bổ sung chỉ tạo docs/evidence/fixtures offline.
