# OneCA V3 ký thành công trên Mac ARM — 23/10/2026

**Đã đọc chứng thư và ký RSA SHA-256 trực tiếp bằng ARM64 trên Mac của người dùng. Chữ ký 256 byte được xác minh thành công bằng cả Security.framework và OpenSSL (`Verified OK`).** Không cần Rosetta hay Windows cho đường hoạt động này.

Người dùng đã mở rộng phạm vi từ phân tích tĩnh sang thử nghiệm với mục tiêu chạy trên Mac ARM. PIN được nhập trực tiếp trong `NSSecureTextField` của cửa sổ test, chỉ truyền qua pipe tới helper. Một lần đăng nhập, một chuỗi thử ngẫu nhiên cục bộ; không ký hóa đơn/tài liệu và không lưu PIN. Kết quả ở [oneca-arm64-signing-validation.json](evidence/oneca-arm64-signing-validation.json).

## Những gì đã hoạt động

| Phép đo thực tế | Kết quả |
|---|---|
| Host / helper / module slice | Apple Silicon / arm64 / arm64 |
| Reader | `Longmai mToken OneCAV3` |
| ATR | `3b9f118131fe9f006a6d546f6b656e2d5b000581900061` |
| Token label | `One-CA Token v3` |
| Token serial | `ONE2309A00001147` |
| Initialize / slot list / token info | CKR_OK |
| Mechanism list | 47, có `CKM_RSA_PKCS` và `CKM_SHA256_RSA_PKCS` |
| Chứng thư | 1 certificate, DER 1304 byte, CKA_ID 20 byte |
| Thời hạn chứng thư đọc được | 14/12/2023 06:29:34 → 03/03/2027 06:57:23 UTC |
| Login → SignInit → Sign → Logout | Thành công trong cùng helper process |
| Kiểu dữ liệu ký | Host SHA-256 → DigestInfo → CKM_RSA_PKCS |
| Chữ ký | RSA 2048, 256 byte |
| Verify Security.framework | `SecKeyVerifySignature(.rsaSignatureMessagePKCS1v15SHA256)` thành công |
| Verify độc lập OpenSSL | `openssl dgst -sha256 -verify ...` → `Verified OK`, exit 0 |

Kết quả chỉ chứng minh chữ ký toán học đúng trên token/profile này, chưa kiểm tra chain/revocation hoặc chấp nhận tại cổng nghiệp vụ. Không có thêm chữ ký tự động sau lượt user consent.

## Module mới và nguồn gốc

Từ [trang Utilities của ProDigiSign](https://prodigisign.com/utilities/), link mToken Driver for MAC/Apple trỏ tới [mac-driver.zip](https://prodigisign.com/repository/mac-driver.zip). File tải trong lượt này dài **124556805 byte**; SHA-256 được giữ trong [integration evidence](evidence/oneca-arm64-integration.json). Zip chứa DMG và testing-report PDF; DMG có package arm64/x86 riêng.

Chỉ mount DMG read-only và `pkgutil --expand-full`; **không chạy Install.app, installer hoặc postinstall**. Postinstall có thay đổi permission `/usr/local/lib`, không cần cho phương án này và chưa thực hiện. Mount nghiên cứu đã tháo sau khi giải nén.

`pkgutil --check-signature` cho `mToken_CryptoID_Arm64.pkg` báo Developer ID Installer **Beijing Century Longmai Technology Co.,Ltd (4M7RX53G2N)**, trusted/notarized, timestamp 24/07/2026. Package chứa 3 thư viện universal x86_64+arm64: wrapper `libcryptoida_pkcs11.dylib`, FIPS-2 `libcryptoida_pkcs11_f2.dylib`, FIPS-3 `libcryptoida_pkcs11_f3.dylib`.

Đường đã kiểm chứng dùng **trực tiếp FIPS-2 module**, không cần wrapper hay app Qt:

```text
libcryptoida_pkcs11_f2.dylib
SHA-256 b4e1b8d804ebf444b3c1acc7222a27dfb5d42cea7f6c51d3e067bdcbf2bbef0c
Developer ID Application: Beijing Century Longmai Technology Co.,Ltd (4M7RX53G2N)
Timestamp: 26/06/2026
```

F2 mới import PCSC.framework và SCard*; đây là thay đổi quyết định so với candidate 2020 raw USB. Bản được triển khai vẫn giữ nguyên binary/signature, không patch code hay sửa file dylib. Bản ARM64 thin dưới `.local` chỉ phục vụ REA; bản chạy là universal nguyên gốc.

Raw/extracted artifacts nằm dưới `.local/oneca-windows/mac-reference/prodigisign*`. Module nguyên gốc đã đặt tại:

```text
~/Library/Application Support/TokenSigner/modules/libcryptoida_pkcs11_f2.dylib
```

Không thay thế file khác nếu có hash không khớp. Chưa copy vào `/usr/local/lib` hay cài vendor package.

## Vì sao candidate cũ thất bại

Bản `libcryptoid_pkcs11.dylib` SHA-256 `372500d1…f9ce0f` chạy được x86_64 dưới Rosetta. REA capture `ev_14fa47c6a2f90067defd1ccf6abc5bbc5f7e2527c43d79c81fa41f25cb3ed89f` cho Initialize OK, 4 Virtual Slots, 0 present token; [full capture](evidence/oneca-mac-readonly-rea.json).

Diagnostic read-only phát hiện USB `055c:0223` nhưng libusb báo **`USBInterfaceOpen: another process has device opened for exclusive access`** khi claim interface 1. Đây là runtime evidence cho lỗi raw USB, không còn chỉ là suy luận tranh chấp CCID. Không detach Apple driver, không dừng CryptoTokenKit/ifdreader và không chuyển USB sang VM. Xem [selected debug observations](evidence/oneca-mac-usb-blocker.json).

Ngoài ra `M_SetEnumString` có lỗi bộ nhớ: static data `_g_p11_device_criteria` → `_g_p11_oem_id` cách nhau `0x100` byte, nhưng code `strncpy(..., 0x400)`. Gọi setter trên bản cũ trong process thử làm các pointer `C_GetSlotList`/`C_GetInfo` từ hợp lệ thành null rồi SIGSEGV. Các crash chỉ thuộc probe riêng, app chính vẫn chạy.

F2 ARM64 mới vẫn có cấu trúc/lệnh copy tương tự trong phân tích tĩnh. **Không gọi `M_SetEnumString` trong backend tích hợp.** Sau khi kiểm hash module, helper chỉ ghi chuỗi ngắn có null terminator vào exported global 256 byte trước `C_Initialize`. Default criteria `mtoken cryptoida` không khớp reader thực tế; đổi thành chữ thường:

```text
longmai mtoken onecav3,not used,vid_055c&pid_0223
```

Code native `mac_scard_discover::identify_device` lowercase reader rồi dùng substring match; uppercase `OneCAV3` đã thử và vẫn trả 0 token, lowercase chính xác trả 1 token và chứng thư. Direct config này chỉ được bật cho hash module đã kiểm chứng, không áp dụng tùy tiện cho bản khác.

## Phần tích hợp đã thay đổi

- [OneCAProfile.swift](../../Sources/Core/OneCAProfile.swift): full ATR, hash module, filter reader và binding fail-closed khi có nhiều reader/token.
- [ModuleRegistry.swift](../../Sources/Core/ModuleRegistry.swift): backend `.oneca`, native universal, experimental; full ATR trước bảng customer-byte Feitian. Không nhầm byte cuối `0x61` với CMC.
- [OneCA.swift](../../Sources/TokenHelper/OneCA.swift): adapter PKCS#11, kiểm đúng một physical reader và một token, trả tên reader thật thay slot description tổng hợp. Cert/login kiểm serial; sign giữ vendor session đã login và kiểm reader/ATR trước dispatch.
- [PKCS11.swift](../../Sources/TokenHelper/PKCS11.swift): kiểm SHA-256 **trước dlopen**, cấu hình global ngắn trước initialize cho profile OneCA. Luồng certificate/key lookup và ký chuẩn được tái sử dụng; CKA_ID không được rỗng ở backend OneCA.
- [TokenBroker.swift](../../Sources/Core/TokenBroker.swift) và [main.swift](../../Sources/TokenHelper/main.swift): `--backend oneca --module ...`, native helper, không inject Feitian shim.
- [TSShim](../../Sources/TSShim/shim.c): helper thực tế còn link tĩnh shim, vì vậy chỉ bỏ DYLD variable chưa đủ. Thêm policy switch; main OneCA tắt reencoding trước khi load module. Mặc định cũ của các backend khác giữ nguyên.

Một reader đúng ATR là giới hạn chủ động: module vẫn có slot description tổng hợp, chưa có bằng chứng slot→reader mapping đủ chắc cho nhiều OneCa cùng lúc. Backend từ chối trường hợp mơ hồ thay vì chọn đại một token. Chưa test hotplug trong lúc ký; sai PIN/locked PIN không bị cố tình kích hoạt để thử.

## Validation và trạng thái app

Helper native ARM64 đã build và chạy thực tế qua backend `.oneca`, đọc/parse chứng thư thành công, một chữ ký test thành công. Module sai hash (candidate cũ) bị helper từ chối trước dlopen. `swift test --filter 'CoreTests|TSShimTests'` với Testing macro plugin hiện có: **45 tests passed**, gồm full-ATR/multiple-reader negative cases mới. `git diff --check` sạch cho phần thay đổi. Lượt test đầu thiếu macro-plugin path đã fail; lượt có cấu hình plugin đúng đã pass, không bỏ qua failure đó.

App đang phục vụ tại `.local/test-env/TokenSigner.app` **chưa được đóng gói lại, thay thế hoặc restart**, PID `32846` được giữ. Kết quả ký thuộc helper mới và cửa sổ thử riêng. Source và module đã sẵn sàng; binary app đang chạy cần một lượt cập nhật sau khi người dùng cho phép thời điểm thay app. Không tuyên bố UI app cũ đã hiển thị OneCA.

Build toàn bộ `App` sau lượt kiểm thử OneCA gặp lỗi ở file **M-Invoice batch đang được luồng khác bổ sung trong checkout chung**: `Sources/Bridges/MinvoiceBatch.swift:79,88` gọi `MinvoiceSigningBackend.batchProgress` khi protocol chưa có member đó. Không sửa/loại bỏ phần việc của luồng kia. Đây là giới hạn build chung tại thời điểm kiểm tra, tách biệt với helper OneCA đã build và ký thành công. Log đầy đủ giữ local ở `.local/oneca-windows/app-build.log`.

Evidence chính:

- [oneca-arm64-integration.json](evidence/oneca-arm64-integration.json): native helper observations, sanitized certificate metadata, source/module/helper hashes, rejection check.
- [oneca-arm64-signing-validation.json](evidence/oneca-arm64-signing-validation.json): consent, số lần login, signature size, challenge/cert/signature hash và hai kết quả verify.
- [oneca-arm64-analysis-rea.json](evidence/oneca-arm64-analysis-rea.json): native reader filter, setter và criteria parser analysis. ARM64 thin identity được giữ riêng; không nhầm với universal module chạy thực tế.
- [oneca-mac-analysis-rea.json](evidence/oneca-mac-analysis-rea.json): generic 2020 static follow-up.
- [oneca-mac-readonly.c](evidence/oneca-mac-readonly.c), [oneca-sign-test.swift](evidence/oneca-sign-test.swift): probe và secure local UI source. Raw certificate, message, signature, logs chỉ nằm trong `.local/oneca-windows/`.

[oneca-windows.md](oneca-windows.md) là snapshot phân tích tĩnh trước lượt runtime này. Kết quả ở tài liệu hiện tại thay thế nhận định cũ rằng chỉ có candidate x86_64 chưa kiểm chứng.
