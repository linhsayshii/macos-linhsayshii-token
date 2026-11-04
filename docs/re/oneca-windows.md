# OneCa V3 Windows → hướng tích hợp TokenSigner macOS

**Cập nhật runtime:** [OneCA ký thành công trực tiếp trên ARM64](oneca-macos-arm.md), bằng module Longmai F2 mới, đã verify độc lập với OpenSSL. Các mục bên dưới là snapshot phân tích tĩnh ban đầu; giới hạn “chưa chạy/chưa sửa Sources” chỉ áp dụng lượt ban đầu đó.

Ngày nghiên cứu: **23/10/2026**. Phạm vi: phân tích tĩnh artifact người dùng cung cấp, payload đã lưu từ nghiên cứu trước, và đối chiếu source hiện tại. **Chưa chạy bộ cài, load DLL/dylib vendor, nhập PIN hoặc ký.** Không sửa `Sources`, không đóng gói hay khởi động lại app đang phục vụ người dùng.

## Kết luận có thể dùng để ra quyết định

OneCa V3 trong tập artifact này thuộc **Longmai CryptoID**, có PKCS#11 x86/x64 và CSP riêng. Đây không phải middleware Feitian/ESPK của FastCA/NC-CA. Hướng ngắn nhất trên macOS là kiểm chứng **Longmai generic `libcryptoid_pkcs11.dylib` x86_64 qua helper Rosetta**, hiện mới là candidate: VID/PID khớp dữ liệu Windows, nhưng chưa chứng minh mở được thiết bị, đọc được certificate hay ký với customization OneCa.

Windows DLL không thể đưa thẳng vào `dlopen` của helper macOS. Nếu candidate generic không tương thích, cần module macOS đúng customization từ nhà cung cấp hoặc backend Longmai mới. Không có bằng chứng cho phép tái sử dụng backend FastCA/Feitian hiện tại chỉ bằng đổi ATR.

| Câu hỏi | Trạng thái | Kết quả |
|---|---|---|
| Loại bộ cài và payload | Đã xác định tĩnh | USB `Setup.exe` là downloader PE32; payload lưu trước là Inno Setup 5.5.7 Unicode |
| Driver / minidriver / CSP / KSP / PKCS#11 | Đã kiểm kê trong payload | CCID driver XP, CSP x86/x64, PKCS#11 x86/x64; không có export minidriver/KSP trong các PE đã giải nén |
| Đường đọc chứng thư | Xác định API, chưa chạy | TokenMgr dùng Cryptoki object search và `CKA_VALUE`; có bộ lọc thuộc tính vendor |
| Đường ký RSA | Theo dấu tĩnh | `C_SignInit` → mechanism factory → RSA PKCS#1 context; `C_Sign` → update/final; kiểm tra độ dài và size query |
| Định danh / giao vận | Có dữ liệu tĩnh | ATR exact trong registry; OneCAV3 VID/PID string; đường PC/SC `SCardTransmit` T=1 |
| Tương thích macOS | Chưa xác minh runtime | Generic Longmai x86_64 có cùng VID/PID candidate; còn vấn đề transport, object layout và binding reader |
| Môi trường Windows | Có sẵn | `prlctl list -a` thấy `Windows 11 LTSC` đang chạy; chưa chạy OneCa trong guest |

## Artifact và chuỗi nguồn

Binary thô và bản giải nén chỉ lưu dưới `.local/oneca-windows/`:

| Artifact | Byte | SHA-256 |
|---|---:|---|
| `original/Setup.exe` | 469552 | `07e2b31f6cfbee88aa0846bae451bad80dd777fa4b093f1da929dfac206eb366` |
| `original/Setup_v3.exe` | 2226920 | `99fdbf986a60db4838743f9274b62f02bc7e04fadbaf23a80b525dcfd1cebad8` |
| `extracted/sys/one-ca_v3.dll@32bit` | 550448 | `3cadd6fcdb473ffeb2b075ad033cb244c2f7424fa6004d30e8772dfdef93030e` |
| `extracted/sys/one-ca_v3.dll@64bit` | 710192 | `698fedb3f8e53b49ccf26b8d518f2d6386737fb8bf38864e6413ddb996a0baaa` |
| `mac-reference/libcryptoid_pkcs11.dylib` | 1020796 | `372500d17c2ab333a86d960683d1c159053a445581782d39323bf19998f9ce0f` |

`Setup.exe` được copy trực tiếp từ `/Volumes/One-CA V3/Setup.exe`; hash khớp REA. Resource version mô tả `Download middleware ONE-CA 3.0`, version `1.0.23.926`. REA inventory có 58 resource leaves, là resource UI/version/manifest; không thấy payload middleware đóng trong các resource này. Giải nén PE resource riêng ở `stub-resources/`, không coi các section/resource là bộ cài hoàn chỉnh. Xem E1 và L1.

`Setup_v3.exe` được **tái sử dụng từ artifact local của lượt nghiên cứu trước**, tại scratch root ghi trong [fastca-oneca.md](fastca-oneca.md), không phải vừa tải từ USB hay server. SHA-1 hiện đo là `65bc1dce84720524743704473634e4a6e2b99d61`, size `2226920`, khớp cặp size/SHA1 được báo cáo trước đó. Đây là kiểm tra nhất quán với bản lưu, không chứng minh server hiện nay vẫn trả cùng file hay payload được vendor xác thực trong lượt này. Chưa kiểm tra Authenticode trust lại.

Trong stub, byte scan thấy UTF-16 URL `http://tms.visnam.vn/software/token/one-ca_v3/` tại offset gần `0x3f68e` (literal scan có ký tự liền trước URL). REA tìm được `Setup_v3.txt`, `Setup_v3.exe`, `Setup_v3.exe.bak`; xref dẫn tới routine chứa `0x40587d`, có `InternetReadFile`, temp path và `ShellExecuteW`. **Quan sát:** có logic tải/khởi chạy payload khi stub được chạy; không có lần tải/khởi chạy nào trong lượt này. Search string object `tms.visnam` của Hopper rỗng mặc dù byte scan có URL, minh họa giới hạn string inventory. E2 và L1.

Extraction dùng:

```sh
innoextract --collisions rename -d .local/oneca-windows/extracted .local/oneca-windows/original/Setup_v3.exe
```

`--collisions rename` giữ được cả hai kiến trúc, tránh bản x64 ghi đè bản x86 cùng tên. Hậu tố `@32bit`, `@64bit`, `$0` là tên do extractor tạo. L1 lưu hash, normal imports, toàn bộ export và selected ASCII/UTF-16 literals của từng PE; L2 lưu extraction log.

## Thành phần thực tế và phụ thuộc

| File giải nén | Kiến trúc | Bằng chứng / vai trò |
|---|---|---|
| `sys/one-ca_v3.dll@32bit`, `@64bit` | x86, x86_64 | Mỗi bản 93 exports: **68 `C_*` + 25 `M_*`**. PKCS#11 và extension Longmai; không export `CP*` |
| `sys/one-ca_v3_csp.dll@32bit`, `@64bit` | x86, x86_64 | Mỗi bản 27 exports; bộ thực thi CSP, normal import `MSVCR90.dll`, WinSCard, CRYPT32, ADVAPI32, UI/OLE |
| `sys/one-ca_v3_csp_s.dll`, `one-ca_v3_csp_s.x64.dll` | x86, x86_64 | 25 `CP*` exports. CSP loader/forwarder; normal import KERNEL32 |
| `sys/one-ca_v3_csp.en.dll@*`, `.vn.dll@*` | x86, x86_64 | DLL ngôn ngữ, không export named API |
| `app/oneca_v3.exe` | x86 | Token Manager; import trực tiếp `one-ca_v3.dll`, CryptoAPI, UI, WinINet |
| `app/TokenMgr.dll` | x86 | 66 exports quản lý token/container/certificate/RSA; dùng PKCS#11 dynamic loading |
| `app/oneca_v3_certd.exe` | x86 | Import TokenMgr; tên/export liên quan certificate propagation. Không chạy để xác nhận startup hay lịch cập nhật |
| `tmp/mozillaInst.exe`, `$0` | x86_64, x86 | Utility đi kèm; chưa theo hết hành vi đăng ký Mozilla. Tên file không đủ chứng minh một browser signer service |
| `app/DrvSetup/winXP/usbccid.{sys,inf,cat}` | `.sys` x86 | INF class `SmartCardReader`, match `USB\Class_0B&SubClass_00`, driver version `5.2.3790.2724`; driver CCID chung, không phải card minidriver |
| `app/RootCA/*` | dữ liệu | Root/intermediate certificate và registry payload; không phải certificate cá nhân đọc từ token |

PKCS#11 DLL normal imports: KERNEL32, **WinSCard**, CRYPT32, USER32, ADVAPI32; không có CLR directory, không cần .NET theo normal imports đã kiểm tra. CSP cần VC90 runtime qua `MSVCR90.dll`; chưa kiểm chứng assembly/SxS resolution. Không thấy file Mach-O, JavaScript/.NET signer hay web plugin/server độc lập trong **33 regular files của payload đã giải nén**. Không suy rộng kết quả này ra mọi bản OneCa hay những thứ có thể tải thêm.

**Minidriver/KSP:** không có `CardAcquireContext` hay `GetKeyStorageInterface` trong export inventory của các PE nói trên; registry chỉ trỏ Crypto Provider cổ điển. Không thấy card-minidriver DLL/INF riêng trong payload. Đây là negative search có giới hạn, không phải khẳng định OneCa không bao giờ có minidriver/KSP.

Registry `Defaults\Provider\One-CA CSP V3` có Type `1`, Crossprocess `1`, trỏ CSP stub theo bitness. REA `CPSignHash` x64 tại `0x180001400` gọi function pointer `0x18000cea8`; routine init `0x1800014a0` thực hiện `LoadLibraryA` và `GetProcAddress("CPSignHash")`, cùng các `CP*` khác. Routine `0x180001000` dựng đường dẫn DLL sibling từ filename hiện tại. **Quan sát:** CSP stub chuyển tiếp sang implementation, không tự chứa toàn bộ ký RSA. E7.

## Định danh token và giao thức

Registry `CryptoID.reg` đăng ký `Longmai mToken OneCA`; bản WOW64 dùng tên `Longmai mToken OneCAV3`:

```text
ATR     = 3b9f118131fe9f006a6d546f6b656e2d5b000581900061
ATRMask = ff × 23   (exact match)
Provider = One-CA CSP V3
```

Đây là **ATR kỳ vọng trong cấu hình Windows**, không phải phép đo token mới. Các file `unCryptoID*.reg` chứa entry cũ kết thúc `...900060` và provider `One-CA CSP V3.0`, khác file đăng ký; không dùng uninstall data đó làm fingerprint hiện tại.

PKCS#11 x64 có literal tại file offset `0xa0b50`:

```text
OneCAV3,vid_055c&pid_0223|vid_0bda&pid_0165,gmpcsc
```

Và table khác `gm3000,vid_055c&pid_db08,...e618|f603|2205`. Manufacturer/label strings: `One-CA Technology`, `One-CA PKCS11 V3`, `One-CA PKCS11 V3 Slot %d`. PDB path có `Customization\CryptoID\LXY-1312-723_VN\...\OneCA3\...\PKCS11`. Các literal này cùng registry củng cố nhận định Longmai; chưa chứng minh mọi device ID đều là USB OneCa mà user đang dùng. L1.

WinSCard normal imports gồm enumerate/status/connect/reconnect, begin/end transaction và transmit. Xref từ `j_SCardTransmit` dẫn tới `0x1800871f0`, routine có **`SCardTransmit(..., g_rgSCardT1Pci, ...)`**, retry/reconnect cho lỗi PC/SC. Đây là đường **T=1 quan sát trong code**, không phải trace APDU trên thiết bị. Chưa khôi phục đầy đủ AID, file layout, device-auth/secure channel hay APDU RSA/PIN của customization này. E6.

## Chứng thư: entrypoint → object → giá trị DER

`TokenMgr.dll!init_pkcs11` → `0x10003410`: `LoadLibraryA` module được truyền vào, lấy `C_GetFunctionList` và `M_GetExtFunctionList`, rồi initialize. API extension này có mặt trong cả hai PKCS#11 DLL đã kiểm kê. Đây là dynamic binding theo tên có chứng cứ native, không chỉ một tên DLL trong strings. E3.

`container_get_cert` (`0x10006160`) → `0x100052f0`:

1. Gọi function-list offset `0x6a`, `0x6e`, `0x72`: lần lượt FindObjectsInit / FindObjects / FindObjectsFinal trong bảng Cryptoki x86 có version 2 byte và function pointer 4 byte.
2. Assembly có template **4 thuộc tính**: class `1` (`CKO_CERTIFICATE`), token boolean, và hai thuộc tính vendor `0x80000067`, `0x80000066`. Ý nghĩa đầy đủ của hai thuộc tính vendor chưa khôi phục.
3. Tạo attribute type **`0x11` (`CKA_VALUE`)**, gọi bảng offset `0x62` (`C_GetAttributeValue`) để hỏi chiều dài rồi đọc dữ liệu vào buffer.

Hopper làm mất/nhầm một số register và stack-variable trong pseudocode x86; kết luận về template dựa thêm [assembly certificate read](evidence/oneca-certificate-read.asm), hash artifact và địa chỉ đã giữ trong L1/L2. E3.

Ở PKCS#11 x64, `C_FindObjectsInit` → `0x180006fb0` → `0x18000b510`; `C_GetAttributeValue` → `0x180006c50`, xử lý session/object/attribute và lazy loading. Từ đó chưa lần hoàn chỉnh tới file chứng thư trên card. **Suy luận:** đường chuẩn `CKO_CERTIFICATE` + `CKA_VALUE` của helper phù hợp ở cấp API; chưa xác minh module generic sẽ trả object/CKA_ID giống OneCa Windows. E4.

`token_add_allcerts_to_msstore` dùng `CryptAcquireContextA` với provider truyền vào và `CryptSetProvParam(0x3e8,...)`. Điều này cho thấy certificate propagation đi qua CSP; chưa thực hiện thay đổi Windows certificate store. E3.

## RSA: API chuẩn và các điểm đã lần tới

Trong PKCS#11 x64:

```text
C_SignInit  0x180001a70 → 0x18000b090 → factory 0x180012310
C_Sign      0x180001b40 → 0x1800064e0 → 0x18000b210
                                 → context vtable +0x80 (0x18001ff20)
                                 → Init / Update / Final qua +0x68 / +0x70 / +0x78
```

PE jump table `0x1800129dc` map mechanism `1` (`CKM_RSA_PKCS`) tới `0x180012386`, dựng vtable `0x180092c58`. RTTI của vtable là **`pkcs11_hardware_rsa_pkcs_ctx`**. Mechanism `3` (`CKM_RSA_X_509`) tới `0x180012422`, vtable `0x180092e58`, RTTI **`pkcs11_hardware_rsa_raw_ctx`**. Dữ liệu table, RTTI và vtable-slot nằm trong L2; factory pseudocode ở E5, [assembly factory](evidence/oneca-mechanism-factory.asm) đối chiếu byte/instruction. Đây là liên kết tĩnh xác định được, chưa có dispatch runtime.

RSA PKCS context có Init `0x18001cfd0`, Update `0x180021620`, Final `0x18001fdb0`. Final lấy `CKA_MODULUS_BITS (0x121)` hoặc chiều dài `CKA_MODULUS (0x120)`, nhánh thấy **1024/2048 bit**; trả size khi output null, trả buffer-too-small `0x150` nếu thiếu chỗ, rồi chuyển việc ký xuống `0x1800225e0`. Update giới hạn buffer quan sát được `0x100` byte. Không khẳng định hỗ trợ RSA 3072/4096 từ code này. E5.

`TokenMgr!algo_rsa_pkcs1_sign` → `0x10008460` gọi function-list `+0xaa` (`C_SignInit`) và `+0xae` (`C_Sign`). Helper macOS đã có đúng chuỗi login → tìm private key theo `CKA_ID` → `C_SignInit` → hỏi size → `C_Sign`; app hiện chọn `.rsaPKCS` với payload DigestInfo và verify chữ ký trả về. **Hướng dùng lại API hợp lý**, còn quan hệ cert-ID/private-key và semantics cụ thể phải đo trên module macOS. Chưa lần RSA handler xuống hết APDU, chưa xác nhận byte order/signature thực tế. E3/E5.

## Đối chiếu source và bước tích hợp cụ thể

[ModuleRegistry.swift](../../Sources/Core/ModuleRegistry.swift) hiện lookup Feitian bằng `atr[19]`. **OneCa ATR byte 19 là `0x81`**, và `0x61` ở cuối ATR không phải customer-byte dùng cho CMC. OneCa hiện chưa có entry. Nếu triển khai, thêm matcher **full ATR Longmai** trước bảng Feitian; không thêm `0x81` chung hoặc gán `0x61` vào CMC.

[TokenBroker.swift](../../Sources/Core/TokenBroker.swift) đã có đường `ModuleArch.x86_64` chạy `/usr/bin/arch -x86_64 TokenHelper --module ...`. Có thể tái dùng kiến trúc này sau khi bảo đảm helper và mọi dependency thực sự có slice x86_64, Rosetta sẵn sàng và dylib load được. Chưa build/chạy kiểm tra những điều đó trong lượt này.

Candidate local `mac-reference/libcryptoid_pkcs11.dylib` là bản A của [fastca-oneca.md](fastca-oneca.md), từ reseller `upmac.zip` SHA-256 `7d0998c73872050b1c17a6e7d1872ae48b3854b6a0082a759e3b0bea64151236`, **không phải OneCa-branded**. Kiểm tra lại cho thấy x86_64, unsigned; dependency Foundation/IOKit/CoreFoundation/libobjc/libc++/libSystem, không có PCSC framework; imports IOKit, có `libusb_claim_interface` và device string chứa `055c:0223`. **Suy luận:** có đường raw USB đáng thử, có thể tranh chấp interface với CCID; chưa quan sát tranh chấp hay token enumeration. L2.

Các thay đổi đề xuất cho lượt triển khai riêng:

1. **Read-only candidate probe trước:** helper x86_64 riêng, timeout, chỉ Initialize/GetInfo/GetSlotList/GetSlotInfo/GetTokenInfo/GetMechanismList và certificate search. Không tự login/sign. Ghi chính xác CKR, kiến trúc, module hash, slot description, token serial và chứng thư tìm được.
2. **Binding reader:** `ModuleTokenScope.reader` hiện so sánh slot description với tên PC/SC bằng equality. Generic có string `Virtual Slot %d`, nên không mặc định giả định khớp. Nếu không có binding đáng tin cậy, giữ chưa hỗ trợ; bổ sung identity mapping được đo, không nhận mọi token của module thành OneCa. Kiểm tra nhiều token cùng lúc.
3. **Shim theo middleware:** broker đang inject `libTSShim.dylib` cho mọi PKCS#11 module, shim sửa mẫu APDU Feitian dựa vào byte shape, không gate bằng token/vendor. Không áp dụng mặc định shim này cho Longmai mới. Với candidate raw USB, shim PC/SC cũng không tạo được transport mà thư viện không sử dụng. Đề xuất thêm cấu hình shim rõ ràng, mặc định off cho OneCa.
4. **Certificate/key semantics:** so sánh DER, `CKA_ID`, private-key handles và mechanism list với Windows đúng OneCa. Native TokenMgr dùng vendor attributes để chọn certificate; helper hiện chỉ lọc class rồi lấy toàn bộ, vì vậy cần kiểm chứng tránh cert/key mismatch.
5. **Chỉ sau read-only thành công**, test có consent/PIN theo luồng app, một chữ ký test, verify độc lập và hotplug/retry/PIN-state. Khi đó mới cân nhắc entry experimental `ca: OneCa`, module x86_64 và binding đã chứng minh. Không chuyển sang production chỉ dựa trên VID/PID.
6. **Nếu candidate generic thất bại:** ưu tiên module macOS arm64/universal đúng `OneCAV3` từ vendor. Nếu phải làm native PC/SC, cần RE thêm device discovery/auth, object/file catalog, PIN state, RSA APDU và test fixtures; không port nguyên Windows DLL hay dùng backend FastCA như một shortcut.

## Runtime còn thiếu và phép đo tiếp theo

`prlctl list -a` trong lượt này: VM UUID `{cc8b63dd-8328-4967-9d24-c07898fa78f0}`, `Windows 11 LTSC`, trạng thái `running`. [windows-signing-test.md](windows-signing-test.md) ghi môi trường lịch sử Windows ARM64 đã chạy x86 middleware của FastCA/NC-CA. Điều đó không chứng minh OneCa đã cài, USB OneCa đã passthrough, hoặc DLL x64 OneCa chạy được trong VM. Không đổi USB ownership, không chạy lệnh trong guest ở lượt này.

Phép đo còn thiếu: inventory OneCa installed DLL/provider và signature trên guest; PC/SC reader/ATR mới; x86 read-only Cryptoki probe với hash DLL này; so sánh certificate/object IDs và mechanism list; probe generic mac module trên cùng token. Nếu cần quan sát APDU ký/PIN, phải có scope runtime riêng và loại dữ liệu PIN/secure-channel khỏi evidence chia sẻ. Hiện **không có runtime OneCa thành công, không có bằng chứng chữ ký OneCa đã verify**.

## Evidence ledger và giới hạn

REA records đầy đủ tại [oneca-native-rea.json](evidence/oneca-native-rea.json); resource tree riêng tại [oneca-setup-resources-rea.json](evidence/oneca-setup-resources-rea.json). Các tên L1/L2 dưới đây là **local evidence IDs**, không giả làm ID do REA sinh.

| Nhóm | Evidence ID tiêu biểu | Nội dung |
|---|---|---|
| E1 | `ev_32fd7a2e4228aea005478ec4941736ffa2b70cdb5a7e3856deb8081d87ba2982` | Complete bounded PE resource tree của USB stub |
| E2 | `ev_5322c530831030ec79bbdc6678126e7e88d18f48df6c623039a8fe581b5c6fcd`, `ev_16e98eb6e4cd19b8a3f527322c90b5321cae598f22510593341a790c68b22be6` | Payload-name strings, stub downloader pseudocode |
| E3 | `ev_6ef3db509e204c4d6c23ade60eddd9b07187541a0ce4c6464bdddf6722c1a49f`, `ev_aa6955197f2dd9d93705f544f2867eafcaf34f1b151c87a233205d2ea925ac37`, `ev_6e64c500990e0164e28fa65e98a815f331007033715d19ef563ecb6f3a18e34d` | TokenMgr dynamic loading, certificate fetch, SignInit/Sign |
| E4 | `ev_9fe7a59e388896ce49e682d8d46827e77adbdf37ddc8beeeb8c408aed6f7be23`, `ev_540ae6b026cff1fb0975e24ae25ad8fa54125a07d9115db3d9454b64f8f81423` | FindObjectsInit wrapper, GetAttributeValue core |
| E5 | `ev_fc62736c67f9b220d4b7169291979c342f9f725caf53db9d1d444a67f6e05363`, `ev_8c1db67a06e2f7a3477f638588785a8b4c3e809e187a86c50672397fe036335b`, `ev_9b72b7dd40468d3b2f97b17e7f8eb8ec6ee7769b5c9445bff17d25a95a78c8a4` | Mechanism factory, context dispatch, RSA PKCS final |
| E6 | `ev_3a1025dbc1117760f25d0c6306a28dc8aa8474c09044b326f232721f8a8aa123` | PC/SC transport/T=1 routine |
| E7 | `ev_fd4badace0ec1d5c5477c5c52ed3547342b8aea9ca1ab1f76bd1ed343bda7c30`, `ev_df1591cc633a56de4c22a37e64ee3ac97ccac9279676fd7595b02a2e99a326ba` | CSP forwarder and dynamic resolver |
| L1 | `oneca-local-static-20261023` | [oneca-static-inventory.json](evidence/oneca-static-inventory.json), generated by [oneca-static-inspect.py](evidence/oneca-static-inspect.py) |
| L2 | `oneca-local-crosschecks-20261023` | [oneca-local-crosschecks.json](evidence/oneca-local-crosschecks.json): artifact origins, extraction log, RTTI/jump table, command outputs, source/reference hashes |

Hopper pseudocode là biểu diễn phân tích, không phải source gốc và có lỗi kiểu/stack recovery; byte/assembly được dùng để đối chiếu các liên kết quan trọng. Normal-import inventory không bao phủ mọi dynamic/delay load. Public certificate-chain URL literals trong signed PE không phải endpoint ký. Không có cơ sở kết luận phân phối macOS OneCa không tồn tại: lượt này chỉ kiểm tra candidate local đã có, không thực hiện web search mới. REA session đã export và đóng sau phân tích.
