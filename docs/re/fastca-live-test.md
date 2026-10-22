# FastCA: lịch sử thử generic middleware macOS — 2026-10-22

**Kết quả mới nhất:** FastCA đã ký trực tiếp trên macOS bằng OpenSC + backend
ESPK thử nghiệm; chữ ký RSA 256 byte đạt cả Security.framework và OpenSSL.
Root cause generic module đã được xác định là điều kiện customer identifier:
metadata `0x6900` không khớp `0x8600`/`0x0600`. Xem
[fastca-native-signing.md](fastca-native-signing.md) và
[validation](evidence/fastca-native-signing-validation.json).
App/TokenHelper sau đó đã chuyển sang backend native và test menu/SignHash đạt;
xem [hướng dẫn app](../FASTCA.md).

Báo cáo dưới đây giữ nguyên quan sát **lượt generic middleware trước PIN**.
Các câu “chưa xác định root cause”, “chưa ký” trong phần lịch sử không mô tả
trạng thái điều tra hiện tại. Kết quả Windows trước đó ở
[windows-signing-test.md](windows-signing-test.md).

## Quan sát trên host

| Bước | Kết quả |
|---|---|
| PC/SC | 6 readers, gồm `FT ePass2003Auto 02` có ATR customer byte `0x69` |
| ATR FastCA tại thời điểm đo | `3b9f958131fe9f006646530510523971df000069000011` |
| Module đã provision | `libcastle_v2.1.0.0.dylib`, SHA-256 `3e7b9e91a861fccbafa9e992daa4c3c4746d9a20eb99e2f43ac860037159cf9c` |
| TokenHelper + shim hiện tại | Exit 0, JSON `{"tokens":{"_0":[]}}` |
| Probe PKCS#11 arm64 | Init/GetInfo OK, 5 slots; mọi `C_GetTokenInfo` trả 5 |
| Probe x86_64/Rosetta cùng module | Cùng kết quả: 5 slots, token-info trả 5 |
| Slot description | `ES SLOT 1`…`ES SLOT 5`, không phải tên reader PC/SC |
| Mở public session trong probe nhiều reader | Trả 5, không gọi login |

Helper lọc bỏ các slot có `C_GetTokenInfo` thất bại nên trả danh sách rỗng.
Registry lookup không giải quyết được lỗi nằm bên trong middleware này.

## Đo cô lập đúng FastCA

Không dùng số slot như danh tính cố định của thẻ. Một interposer chẩn đoán do
analyst viết giới hạn `SCardListReaders` **trong riêng process probe** còn đúng
reader `FT ePass2003Auto 02`. Nó giữ nguyên tên reader thật, ATR, APDU và phản hồi
thẻ; không giả ATR, đổi dữ liệu thẻ hoặc sửa dylib vendor. `SCardConnect` ghi
nhận đúng reader này. Các thẻ khác vẫn nối với macOS bình thường.

Với phạm vi đó, candidate trả đúng **1 slot** và `C_GetTokenInfo` vẫn trả
`CKR_GENERAL_ERROR (5)`. LLDB trên process read-only xác định:

```text
C_GetTokenInfo → 0x8a64
0x3b00c returns 0 (connection/state check passes)
0x3b6ec → 0x22c64
0x22ccc calls 0x9650c; return at 0x22cd0 = 0
0x22d1c calls 0xd79ec; return at 0x22d20 = 0x30
return at 0x8c34 = 0x30
0x8a64 translates the nonzero internal result into 5
```

`0x30` là `CKR_DEVICE_ERROR` trong header Cryptoki của repo. Pseudocode
`0xd79ec` chứa các bước đọc/parse và duyệt catalog qua virtual calls; chưa xác
định call con hay điều kiện cụ thể sinh lỗi. Không coi đây là bằng chứng đã xác
định đầy đủ root cause hoặc đã chứng minh customer-ID check.

Trace transport của **reader đã cô lập** chỉ ghi chiều dài, 5 byte header, mã
PC/SC và SW ngoài: `00CA0186`, `8050`, `8482`, `0CCA0184`, `0CA4`, `0CCA0181`
đều có PC/SC rv=0, outer SW=9000. Không ghi body, MAC, key hoặc PIN.
Outer SW=9000 không tự chứng minh decode secure messaging hay parse catalog thành
công. Chưa có căn cứ sửa shim length encoding từ phép đo này.

## Sửa kết luận trung gian về directory

Một trace ban đầu trên slot 5 khi có nhiều readers trả `0x80100023`
(`SCARD_E_DIR_NOT_FOUND`) lúc đọc logical `mscp/cmapfile`. Slot này **chưa được
gắn chắc chắn với FastCA**. Không sử dụng trace đó làm root cause của FastCA.
Phép đo cô lập ở trên supersede kết luận trung gian ấy.

Các tên logical directory/file được đọc từ globals đã khởi tạo của cùng module:
`mscp`, `cmapfile`, `internal`, `containermap`. Trong trace cô lập FastCA,
`0x9650c` trả 0; lỗi xuất hiện ở call tiếp theo `0xd79ec`. Sự có mặt của các tên
này trong module không chứng minh thẻ FastCA thiếu những directory đó.

## Bằng chứng tái sử dụng

- [fastca-live-validation.json](evidence/fastca-live-validation.json): observations,
  hash nguồn log, kết quả arm64/x86_64 và phép đo cô lập; local analyst record,
  không phải REA Evidence ID.
- [fastca-live-debug.log](evidence/fastca-live-debug.log): log LLDB cô lập FastCA,
  đã bỏ giá trị object pointer không cần thiết.
- [fastca-tokeninfo-rea.json](evidence/fastca-tokeninfo-rea.json) và
  [fastca-catalog-rea.json](evidence/fastca-catalog-rea.json): chọn các record REA
  gốc cho đúng artifact/arm64, gồm pseudocode và assembly; đây là phân tích tĩnh.
- [Source probe](evidence/fastca-live-probe/slots.c),
  [reader filter](evidence/fastca-live-probe/reader-filter.c),
  [connect metadata](evidence/fastca-live-probe/connect-metadata.c),
  [shim snapshot](evidence/fastca-live-probe/reader-shim.c): mã analyst tự viết,
  không phải file vendor. Reader hardcode chỉ đúng tại thời điểm đo, cần xác
  minh lại ATR trước khi tái sử dụng.

REA Evidence quan trọng:

| Method | Evidence ID |
|---|---|
| `0x8a64`, token-info wrapper | `ev_8e1b86735fe2e7a695df56b24502ad3f27c1fc235d26fc39aa490b769d6613c6` |
| `0x3b6ec`, init caller | `ev_a6c94d49fccbf79c675f976b484593f9c71e5592e2ecce41028592a6c0039868` |
| `0x22c64`, catalog orchestration | `ev_0ddd2580753162605b87edac544d3343cd5765b91c4995e478806fd0f182423f` |
| `0xd79ec`, failing call in isolated run | `ev_941b00d78c861a2a52795cf657cd651b2cefe579e250e00d5f24a65ba870d7aa` |

Hopper đã được đóng sau phân tích. LLDB chỉ đọc register/metadata/vtable và các
tên logical file đã xác định; không chạy login, không dump key hoặc credential.

## Candidate khác đã kiểm tra

1. [Feitian ePass2003 India 20210512](https://download.ftsafe.com/files/ePass/temp/ePass2003-India-20210512.dmg),
   tải từ HTTPS máy chủ hãng. DMG SHA-256
   `d1e1d036bc8e8959223f5ced5d97a7ebbb52443235de0a4d7660fa8e9c96b69b`.
   Trích xuất tĩnh, không chạy installer. Module x86_64 SHA-256
   `bef7acde8531105c3b8734869877d83add13efed9ef2404c3663c3011f36b9e0`,
   unsigned; probe read-only/Rosetta thấy 6 slots và mọi token-info read đều
   trả 5. Không provision module này, không dùng nó để login/sign.
2. [Hongkong Post e-Cert download terms](https://www.ecert.gov.hk/product/download/token_f/mac/step2_text.html)
   giới hạn sử dụng cho e-Cert subscribers. Gói được tải/inventory/extract tĩnh
   trước khi đọc đủ terms; sau khi thấy giới hạn đó đã không nạp/chạy module,
   không phân tích mã của gói này để dùng cho FastCA. DMG SHA-256
   `d63e7c04bf9df310f2e08bd2429733eb7f1550887634ae8b137a4a8f84ac3d42`.
3. Tra cứu lại [hướng dẫn FastCA](https://fastca.vn/ho-tro/cai-dat-chu-ky-so-fastca)
   và [trang bộ cài](https://cms.fastca.vn/ho-tro/bo-cai-dat-kem-trong-thiet-bi-usb-token):
   chưa tìm thấy macOS PKCS#11 phù hợp trong hai trang đã kiểm tra. Đây là tìm
   kiếm có giới hạn, không phải khẳng định FastCA không có macOS build.

Các DMG đã unmount. Không chạy installer, không thay driver/trust store, không
đổi PIN, không ghi dữ liệu hay phát hành hóa đơn.

## Điểm cần giải quyết trước lần ký đầu tiên

Cần giải quyết lỗi catalog khi cô lập reader hoặc có middleware đọc được đúng
token FastCA. Sau khi đọc được chứng thư và xác định chắc chắn token/cert target,
mới mở approval/PIN trong app, thực hiện một login và ký test message qua host
SHA-256 → DigestInfo → CKM_RSA_PKCS, rồi verify bằng public key. Không dùng module
khác CA bằng cách giả ATR, không đoán cách suy PIN và không tự retry login.

Chứng thư FastCA từng đọc trước đây đã hết hạn; chưa đọc lại được cert hiện tại
trong lượt này. Kết quả verify RSA và việc portal chấp nhận chứng thư cần tách riêng.
