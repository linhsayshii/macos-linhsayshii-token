# OneCA: inventory các dòng và kế hoạch discovery trên Mac ARM

Ngày 23/10/2026. Bổ sung cho [kế hoạch tích hợp V3](../plans/oneca-arm64-integration.md), theo [mục tiêu compatibility chung](../TOKEN-COMPATIBILITY.md). Main sở hữu routing/native/UI/build; lượt này chỉ tạo nghiên cứu, evidence và fixture offline. Không nạp module, gửi APDU, login hay ký mới.

**OneCA có ít nhất hai họ middleware trong artifact đã thu thập: V1/V3 Longmai CryptoID và V2 EnterSafe/ESPK.** Vì vậy issuer OneCA không quyết định transport. Chỉ V3 hiện có bằng chứng đọc, xác thực và ký/verify native ARM64; các dòng còn lại cần discovery và xác minh riêng.

## Coverage có bằng chứng

| Dòng / OEM | Nhận diện từ artifact | Đọc thật trên Mac ARM | PIN auth thật | Ký/verify thật | Portal |
|---|---|---|---|---|---|
| OneCA V1 / Longmai CryptoID | Registry exact ATR, reader/config OEM, PKCS#11 x86/x64 | Chưa | Chưa | Chưa | Chưa |
| OneCA V2 / EnterSafe ESPK | Registry ATR mask, manifest EnterSafe, `ENTERSAFE-ESPK`, PDB `nca_eps2k3a.pdb` | Chưa | Chưa | Chưa | Chưa |
| OneCA V3 / Longmai CryptoID | Registry exact ATR + reader/token đã đo | Có | Có, một lần user nhập PIN | Có, RSA SHA-256; Security và OpenSSL pass | Chưa kiểm chứng nghiệp vụ |
| CryptoID F3 | Module ARM64/x64 và criteria có trong gói vendor | Chưa; chưa có bằng chứng OneCA phát hành dòng này | Chưa | Chưa | Chưa |
| OEM/model OneCA khác | Chưa có inventory đầy đủ | Chưa | Chưa | Chưa | Chưa |

V1/V2/V3 là tên artifact/product đã quan sát; không suy ra firmware hay thứ tự đổi OEM của mọi thiết bị. Chưa có danh mục chính thức đầy đủ các firmware/model OneCA. Không thể tuyên bố “hỗ trợ toàn bộ OneCA” chỉ từ ba bộ cài.

V3 đã được main đóng gói sau handoff đầu tiên: [packaged evidence](evidence/oneca-packaged-app-2026-10-23.json) ghi module hash đúng, App/Helper/shim đồng bộ và discovery quảng bá đúng certificate; không có login/sign mới khi đóng gói. Trạng thái này cập nhật giới hạn “chưa đóng gói” trong báo cáo runtime lịch sử. [Ký thật V3](evidence/oneca-arm64-signing-validation.json) và [báo cáo ARM64](oneca-macos-arm.md) vẫn là bằng chứng ký.

## V1: Longmai nhưng không cùng exact profile V3

[Trang tải chính thức OneCA](https://www.one-ca.net/download) trỏ tới [Setup_one-ca_v1.exe.zip](https://center.visnam.com/api/files/resources/community-files/visnam_019c46d7-dc5b-7b08-9810-0f1bf9a2e17b/other/Setup_one-ca_v1.exe.zip). Archive SHA-256 `dfe9b3e42cfd53d02a55f910ee6c6a27a0a2e6d0143ade0c5409a0f86a8248dd`; PE bên trong `852938c3f8352ccacc021ef3e52da83e41f668815263b8e7c39875c3a2058a11`. Chỉ giải nén ZIP/Inno, không chạy installer.

`app/reg/CryptoID.reg` (SHA-256 `52e4fd72039fa981ab2289899268a8245248efcdfb04c9897c57c9ffa2022b39`) đăng ký:

```text
ATR      3b9f118131fe9f006a6d546f6b656e2d5a000581900060
ATRMask  ffffffffffffffffffffffffffffffffffffffffffffff
Reader   Longmai mToken OneCA
Provider One-CA CSP V1.0
```

DLL `one-ca_v1.dll@32bit` SHA-256 `ab8c2fac521ba7543192a72dd49b6b9a0cd85035aea84f81751b9a4bfe9c1b24`; x64 `ae518f023c17a0c19d8639dd2698c217491f92e53f0ec5ff4acc51341a9b158f`. Cả hai có 68 `C_*` và 25 `M_*` exports. DLL x86 chứa criteria tại offset `0x7b400`:

```text
Longmai mToken OneCA,vid_055c&pid_0223|vid_0bda&pid_0165,gmpcsc
```

`OneCA01` tại `0x7b800`/`0x7b8c0` là dữ liệu cấu hình quan sát được; chưa truy được ý nghĩa/đường dùng để coi đó là auth profile. Bảng `gm3000` chung trong binary không chứng minh OneCA phát hành mọi PID trong bảng. [Inventory V1 đầy đủ](evidence/oneca-family-v1-static.json).

V1 và V3 khác byte 16 và TCK cuối (offset zero-based). Hai registry đều dùng mask toàn `ff`; **không có căn cứ tạo mask Longmai rộng chỉ bằng cách bỏ qua các byte khác nhau giữa hai mẫu**. Reader filter `onecav3` hiện tại cũng không bao phủ reader V1. F2 ARM64 là ứng viên cho V1, chưa có bằng chứng đọc/PIN/ký với V1 hay cấu hình OEM phù hợp.

## V2: một provider khác, có mask thực từ bộ cài

[Trang tải KKVAT](https://www.kkvat.com.vn/tai-ve.html) công bố link “Token Manager ONE-ca V2” tới [Setup_v2.exe](https://www.kkvat.com.vn/data/news/2512/Setup_v2.exe). Đây là nguồn phân phối lại, không phải host chính thức OneCA. PE dài 3311584 byte được ghi chính xác trong inventory; SHA-256 `a07cc666acc5f8151f98ab2157efe00347b76f0589adac4102a1a538a41defba`. Chưa xác minh Authenticode trust; không thực thi.

`app/reg/ONECA2.0.reg` SHA-256 `1ebcb6be487602d9c2be3256c32dd9f9433460aa3d27fe9c8ef07263044b2f80` và WOW64 đăng ký:

```text
ATR      3b9f958131fe9f006646530500000071df000081000000
ATRMask  ffffffffffffffffffffffff000000ffffffffffffff00
Provider One-CA CSP V2
CardName OneCA PKI Token
```

Mask 23 byte, wildcard tại **12, 13, 14, 22**. Byte 19 `81` vẫn cố định. Template registry có XOR từ T0 đến cuối bằng `82`, **không phải capture ATR hợp lệ**; TCK offset 22 đã bị mask. Luồng thực tế phải parse ATR, kiểm tra độ dài/TCK rồi mới so mask; không copy template này thành một “thiết bị đã đo”. Các biến thể fixture với TCK được tính lại là tổng hợp, ghi nhãn riêng.

`one-ca_v2.dll@32bit` SHA-256 `4a7a262c29b0feb2472bfb862cbeb7c619119c0579d11612728df5d7717990b3`; x64 `0d79a4682c75da8d3bf6a3d220fde71fe07a0132c5dc6c38b9a43c62cd904828`. Khác V1/V3, DLL gom CSP, minidriver (`CardAcquireContext`), KSP (`GetKeyStorageInterface`), PKCS#11 và `E_GetAuxFunctionList`: 98 exports. Import `WinSCard.dll`. Dấu vết x86:

| Offset file | Nội dung |
|---|---|
| `0xab520` | `nca_eps2k3a.pdb` |
| `0xbc968` | `ENTERSAFE-ESPK` |
| `0xbd936` (UTF-16) | `EnterSafe PKCS#11 Library.` |
| `0x136d1d` | Manifest `EnterSafe CSP PKCS11 Library` |

Đây là bằng chứng provider EnterSafe/ESPK từ artifact; chưa chứng minh mọi firmware V2 có cùng APDU/PIN semantics như FastCA/EFY. Main nên đưa V2 vào discovery ứng viên ESPK và đối chiếu [FastCA family evidence](fastca-family-discovery.md), đọc catalog/schema/capability trước. Không route V2 sang Longmai F2 chỉ vì issuer là OneCA, cũng không tự gán profile authentication FastCA/EFY cho V2. [Inventory V2](evidence/oneca-family-v2-static.json).

Microsoft mô tả ATR mask là bitmask dùng khi so ATR trong database; đó là điều kiện chọn card/provider, không xác nhận capability đăng nhập/ký. [SCardIntroduceCardType](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardintroducecardtypea).

## Gói macOS 2026: F2, F3 và wrapper

[Inventory ba module](evidence/oneca-family-module-inventory.json) giữ universal hash, imports/exports và criteria. Nguồn gói: [ProDigiSign Utilities](https://prodigisign.com/utilities/) → [mac-driver.zip](https://prodigisign.com/repository/mac-driver.zip). Không chạy postinstall.

| Module | Universal SHA-256 | Kết luận |
|---|---|---|
| F2 | `b4e1b8d804ebf444b3c1acc7222a27dfb5d42cea7f6c51d3e067bdcbf2bbef0c` | ARM64 PC/SC đã đọc/ký thật V3 với cấu hình đã kiểm chứng |
| F3 | `8761309ebdcc5ca2ef9d6cd037bc47bcab6d0df06726d20063786ace0150664e` | Criteria `mTokenCryptoFIPS\|vid_4c4d&pid_8b15`; chỉ inventory, chưa chứng minh OneCA phát hành |
| Wrapper | `825a05acb88fead1991fdb0159fbcec10198b488c18978990d97f429fd397966` | Ghép F2/F3; không thay trực tiếp provider đã đo |

Hai lưu ý tĩnh mới:

- **F3 `cryptoid_mscp::InitAtrAndVendorReader` tại `0xa368` là thao tác ghi cấu hình**: gọi `_mToken_PutData(...,0x102,...)`, `_mToken_ConfigureVendor`, `_mToken_ConfigureReader`. Không đưa vào public preflight vì thấy tên “ATR”. Evidence `ev_495df6485a80ff07e3ff731a5478405145536744a33e7a11b474d9a1693069e8`, [bundle REA](evidence/oneca-family-f3-rea.json).
- Wrapper load path `/usr/local/lib/libcryptoida_pkcs11_f3.dylib` và `...f2.dylib`; `C_Initialize` gọi các function table nếu có rồi **luôn trả 0**. `C_GetSlotList` ghép/remap slot; chưa chứng minh binding physical reader. Initialize OK không phải token compatibility. Evidence `ev_6a823fff4c2c8a488791fc35a0b94fd66a3d3a288cd9dc16d155932a5405423e`, `ev_2cbe881371c9a762a485889d032ffb274159d266ff91700b8fd22ddb320a7d7e`, [bundle REA](evidence/oneca-family-wrapper-rea.json).

Giữ tránh `M_SetEnumString` vì lỗi copy 0x400 vào global 0x100 đã đo ở candidate cũ và thấy cấu trúc tương tự F2 mới. Không dùng raw USB candidate 2020 để fallback: đã gặp exclusive-access với CCID, không đọc được token. Những kết quả âm này không chứng minh V1 hay mọi Longmai không được hỗ trợ.

## Các bước main tích hợp

1. **Tách candidate discovery khỏi signing authority.** Parse ATR trước; dùng mask từ artifact và tín hiệu reader/USB để chọn provider ứng viên. V2 dùng mask có nguồn; V1/V3 giữ exact regression + family hint. ATR Longmai hợp lệ mới có thể hiện “đang nhận diện/cần provider preflight”, không tự trở thành PIN-ready. Một CA có thể xuất hiện trên nhiều provider.
2. **Đọc public có giới hạn qua provider phù hợp.** Với F2 chỉ load hash đã duyệt trong helper cô lập, tắt shim reencoding như hiện tại, cấu hình ngắn đã kiểm chứng trước initialize. Không mở rộng string OEM/global tùy ý. Với ESPK V2, main kiểm catalog/schema/card metadata/protocol trước chọn profile. Không dùng thao tác ghi hay thử auth để tìm giao thức.
3. **Preflight target.** Ràng buộc physical reader/token/serial/snapshot; DER parse; issuer chain theo trust anchors cấu hình (CN substring không đủ); thuật toán, key size, mechanisms, CKA_ID không rỗng; so public modulus/exponent với cert; sign usage/capability. Nếu private attributes bị ẩn trước login, đánh dấu chưa xác minh, không thử PIN để học protocol. Chỉ profile authentication có căn cứ mới được mở đường consent/PIN; sau login so private/public binding trước sign và verify chữ ký trả về.
4. **Giữ guard V3.** Không bỏ hash pin, giới hạn một matching reader/token hay đổi module sang wrapper/F3 để tăng số model “nhận được”. Chưa có per-reader channel binding nên nhiều Longmai vẫn là ambiguous. Hotplug phải vô hiệu target/session cũ. Không tự retry PIN.
5. **Nghiệm thu riêng từng mức.** Fixtures offline trước; public discovery trên model thực khi có thiết bị; authentication/ký qua user consent riêng khi profile đã xác minh; verify độc lập; portal là bước riêng. Adapter MISA/Minvoice dùng broker/capabilities chung, không thêm ATR/serial cố định.

## Fixture giao main và giới hạn

[Fixture JSON](evidence/oneca-family-discovery-fixtures.json) chứa 3 registry profiles và 13 ATR cases: V1/V3 đã đăng ký; V2 template không hợp lệ; V2 wildcard variants có checksum; thay byte customer cố định; Longmai generation mới chỉ family hint; TCK sai, truncated, trailing; ATR khác họ; FastCA cùng ESPK nhưng không OneCA V2 mask. Cases tổng hợp được ghi rõ, không coi là token đã quan sát.

10 preflight scenarios mô tả expected decisions để main viết tests cho binding, cert/key mismatch, hash, hidden attributes, wrapper false-positive và hotplug; đây là yêu cầu kiểm thử, **chưa chạy runtime implementation**.

Chạy `python3 docs/re/evidence/oneca-family-matching.py`: **13/13 cases pass**, zero hardware/auth/sign calls. [Validation JSON](evidence/oneca-family-fixture-validation.json). Chỉ xác minh fixture/parser/mask offline; không mở rộng coverage phần cứng. Source runtime và `.build` không thay đổi trong lượt này. Các binary gốc giữ local, không đưa vào Git; evidence không chứa PIN hay private key.
