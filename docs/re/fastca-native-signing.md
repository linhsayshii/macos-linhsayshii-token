# FastCA ký trực tiếp trên macOS — đã xác minh 2026-10-22

**Đã tạo và verify chữ ký FastCA trên macOS arm64, không đi qua Windows.**
Backend thử nghiệm dùng `libopensc.13.dylib` OpenSC 0.27.1 (`epass2003`) để
vận chuyển secure messaging, và mã riêng xử lý catalog ESPK, xác thực PIN,
chọn khóa và ký RSA. Generic PKCS#11 `libcastle` vẫn không dùng được với thẻ này.

**Đã tích hợp backend native vào App/TokenHelper** sau phép thử độc lập dưới đây.
User đã ký từ menu thành công; SignHash qua HTTP local trả chữ ký 256 byte và
OpenSSL verify độc lập `Verified OK`. Registry không còn chọn generic module.
Xem [hướng dẫn app](../FASTCA.md),
[app validation](evidence/fastca-app-signing-validation.json). Phần mô tả harness
và các FID cố định dưới đây là lịch sử phép chứng minh native đầu tiên.

## Kết quả quan sát

| Bước | Kết quả |
|---|---|
| Reader được chọn chính xác | `FT ePass2003Auto` |
| ATR được kiểm tra toàn bộ trước PIN | `3b9f958131fe9f006646530510523971df000069000011` |
| Catalog `3F00/2003/6F01` | Đọc 1500 byte, 9 logical files |
| Chứng thư `pkcs11/cert0001`, FID `24E0` | DER 1395 byte; cùng thumbprint với lượt Windows |
| Metadata `pkcs11/prvk0001`, FID `24C0` | CKA_ID khớp chứng thư, CKA_SIGN=true, RSA 2048, key reference `A020` |
| Xác thực PIN trong lượt ký | Một lệnh, `SW=9000`, không tự retry |
| MSE chọn khóa | `rv=0`, `SW=9000` |
| PSO ký | `rv=0`, `SW=9000`, chữ ký 256 byte |
| Security.framework | `VERIFIED` |
| OpenSSL kiểm tra độc lập | `Verified OK`, exit 0 |

Dữ liệu duy nhất được ký:

```text
TokenSigner FastCA native macOS signing test 2026-10-22
```

Chứng thư SHA-1 `7EF1E56BF406078890C6CEE040CB2DC9C373913D`, DER SHA-256
`fe4414c939c92562e13c3b2c8ea13fe292bd4676d35dc7ca625a38ecf0fbc77e`.
Chứng thư đã hết hạn 30/07/2026. Hai phép verify trên chỉ kiểm tra toán học chữ
ký, không kiểm tra chain/revocation hoặc việc cổng nghiệp vụ chấp nhận chứng thư.

## Vì sao generic module thất bại

Phép đo cô lập reader xác định chính xác đường lỗi trong arm64 `libcastle`:

```text
catalog initialization → 0x10af14 → 0x115f70
0x10ff0c đọc metadata bằng GET DATA 0181: trả thành công, giá trị u32 0x6900
0x116190 so sánh 4 byte với hằng 00 86 00 00 tại 0x1a961d (u32 0x8600)
so sánh tiếp với 0x0600; cả hai không khớp
nhánh 0x1161c8 đặt kết quả 5
caller đổi thành FFFF → CKR_DEVICE_ERROR 0x30 → C_GetTokenInfo trả 5
```

Đây là điều kiện tương thích/customer identifier của module được quan sát
bằng phân tích tĩnh và debugger đọc metadata. Chưa chứng minh đây là kiểm tra
license. Secure messaging unwrap trả 0, inner DO99 và outer status đều `9000`.
Không có căn cứ quy lỗi này cho USB, PIN, thiếu directory hoặc shim APDU length.
Không sửa binary vendor, hằng so sánh, ATR hoặc dữ liệu phản hồi thẻ.

Bằng chứng: [REA compatibility records](evidence/fastca-compatibility-rea.json),
[live debugger log](evidence/fastca-compatibility-debug.log). Trong log, `x0=0x63`
ở đầu nhánh `0x1161c8` là giá trị còn lại từ so sánh; không phải mã lỗi cuối.
Module SHA-256 vẫn là
`3e7b9e91a861fccbafa9e992daa4c3c4746d9a20eb99e2f43ac860037159cf9c`.

## Căn cứ cho lệnh native

Windows DLL FastCA đã ký được trên cùng thẻ, SHA-256
`d2c52982f4799b53b308e306a0c22f6cf59ea27d62c8f57ee6199d7f17ddacf3`,
được phân tích tĩnh để xác định giao thức; không thử các công thức PIN ngẫu nhiên.

- `C_Login 0x10067cd3 → 0x1006bc34 → 0x1004a7e4`: nhận đúng raw PIN bytes và
  độ dài, tạo `SHA1(PIN) || BE32(length)` 24 byte. `0x1004a24b` ghi độ dài big endian.
- GET CHALLENGE 8 byte; 3DES-EDE3-CBC, IV zero; EXTERNAL AUTHENTICATE
  `00 82 01 81`, payload 8 byte qua secure messaging. Không lưu PIN hay derived key.
- `0x1004949d` chọn khóa bằng MSE `00 22 41 B8`, template
  `80 01 84 81 02 <key-reference big endian>`, sau đó PSO `00 2A 80 86`.
- Host hash SHA-256, dựng DigestInfo và khối PKCS#1 v1.5 đủ 256 byte, rồi
  dùng lệnh RSA trên thẻ. Khóa bí mật không được đọc hay xuất.

[REA Windows records](evidence/fastca-windows-native-rea.json) lưu pseudocode và
assembly gốc. Evidence IDs cho derivation: `ev_f55340fdd008e5ccde232a3b6d2be4b73a394b5d21cd07f3fc18540e524f6e17`,
`ev_99e351cb873aa4e1a8b9d0f6877079308ee4077616007a69dc0de73c1b8c1221`;
cho MSE/PSO: `ev_0b05b659593475e2db1c449a53c0414c2d305699a0139f4733d4ba7eccd99d8b`.
Các record này là bằng chứng tĩnh; status `9000` và chữ ký verify được là bằng
chứng chạy thật độc lập sau đó.

Lượt UI xác thực đầu tiên dừng trước EXTERNAL AUTHENTICATE do prototype nhầm
`sc_get_challenge` phải trả 8. API thực tế trả `SC_SUCCESS=0`; sau khi sửa điều
kiện thành `<0`, lượt xác thực tiếp theo thành công. Không có lần thử sai PIN
hoặc tự retry từ lỗi này. Sau mỗi lượt đã xác thực, helper reset session thẻ.

## Source và chạy lại

[Native probe snapshots](evidence/fastca-native-probe/) chứa đúng source của
phép thử: `probe.c`, `auth_probe.c`, `sign_probe.c`, `AuthPrompt.swift`,
`SignPrompt.swift`. Đây là harness cho đúng thẻ/chứng thư/FID tại thời điểm đo,
có đường dẫn tuyệt đối của workspace; chưa phải backend tổng quát. Source OpenSC
0.27.1 và runtime có sẵn tại `.local/fastca-native/OpenSC-0.27.1` và `/opt/homebrew/lib`;
không cài thêm driver hoặc thay cấu hình hệ thống.

Ví dụ build C trên máy đã chuẩn bị (chỉ build, không nhận PIN):

```sh
clang -DENABLE_SM -I .local/fastca-native/OpenSC-0.27.1/src \
  docs/re/evidence/fastca-native-probe/sign_probe.c \
  -L /opt/homebrew/lib -lopensc -o .local/fastca-native/sign_probe
```

Cửa sổ test đã build ở `.local/fastca-native/FastCASignTest.app`. User tự nhập
PIN trong NSSecureTextField; app gửi qua pipe stdin và xóa field. Không nhập PIN
vào chat, argv, file hoặc log. Chỉ user bấm “Ký test 1 lần” mới gửi xác thực/ký.
Nếu đổi thẻ hoặc chứng thư, harness từ chối trước xác thực; không tự đổi hash/FID
để vượt điều kiện đó. Muốn hỗ trợ thẻ khác phải đọc lại và ghép metadata trước.

[Validation record](evidence/fastca-native-signing-validation.json) lưu message,
chữ ký, hash source, status và giới hạn. Public key test nằm tại
[fastca-native-public.pem](evidence/fastca-native-public.pem); không lưu DER chứa
thông tin định danh vào repo. Verify lại bằng:

```sh
python3 scripts/verify-fastca-native.py
```

Core có parser read-only `ESPKCatalog`/`ESPKAttributes` cùng kiểm tra bounds,
truncation và duplicate metadata. `scripts/test-env.sh test-core` build thành
công, **33 tests đạt** (3 shim, 19 Core, 11 Bridges). Parser cũng đã decode
metadata thật và kiểm tra CKA_ID certificate/key khớp ở checkpoint prototype.
Parser sau đó đã được nối vào backend app, theo phần tích hợp dưới đây.

## Tích hợp vào app — đã hoàn tất và test thật

- `CFastCA` nạp động OpenSC 0.27.1, khóa transaction, kiểm tra ATR/driver, vận
  chuyển lệnh metadata/auth/MSE/PSO và reset phiên sau xác thực.
- `TokenHelper/FastCA.swift` ghép chứng thư/khóa từ catalog và CKA_ID, kiểm tra
  public key khớp; không hardcode FID chứng thư, key reference hoặc thumbprint.
- Broker chọn `--backend fastca`, không inject vendor shim; PIN dùng stdin và
  không bật debug APDU. CA khác giữ đường PKCS#11.
- App duyệt/PIN như trước, hiển thị lỗi runtime/đọc, kiểm tra lại chữ ký bằng
  chứng thư đã duyệt. User xác nhận menu “Ký và xác minh OK”.
- SignHash tra serial chứng thư để tìm đúng serial USB/CKA_ID, từ chối serial
  mơ hồ; hỗ trợ mọi chứng thư hợp lệ được ghép trên token, thay vì chỉ cert đầu.
- Test SignHash local với fixed message
  `TokenSigner FastCA app SignHash integration test 2026-10-22`: HTTP/status 200,
  chữ ký 256 byte, helper + AppModel verify và OpenSSL độc lập `Verified OK`.
- Build đạt; **38 tests đạt** (3 shim, 24 Core, 11 Bridges), gồm tamper/wrong cert,
  metadata mơ hồ, padding, routing certificate/token và lỗi runtime broker.

Bằng chứng mới: [fastca-app-signing-validation.json](evidence/fastca-app-signing-validation.json),
[test result](evidence/fastca-app-tests.txt). Chưa test hotplug/nhiều FastCA thật,
portal hoặc chứng thư còn hạn; chưa đóng gói runtime/notarization để phân phối.
