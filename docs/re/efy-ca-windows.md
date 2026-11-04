# EFY-CA Token v1: Windows middleware và hướng tích hợp macOS

**Cập nhật đường ARM64:** đã đọc thành công catalog/chứng thư EFY thật, ghép metadata khóa và verify public key bằng OpenSC/PCSC ARM64. Sau đó **xác thực PIN thành công, SW9000, một auth, reset thành công**, chưa ký. Xem [EFY-CA ARM64 native](efy-ca-arm64-native.md), evidence A01–A05/B01–B03 và [kế hoạch tích hợp app](efy-ca-app-plan.md). Trạng thái mới này thay thế ưu tiên helper Intel/discovery và các ghi chép “chưa thử PIN” bên dưới; phần middleware giữ nguyên lịch sử khảo sát.

Ngày khảo sát: **2026-10-23, Asia/Ho_Chi_Minh**. Phạm vi là EFY-CA. Lượt đầu phân tích tĩnh; sau khi người dùng xác nhận đã cài EFY trên Parallels, lượt bổ sung kiểm tra installation thực, chạy probe metadata PKCS#11 x86/x64 trên Windows và x86_64/Rosetta trên macOS. Không chạy bộ cài/GUI vendor, không nhập PIN, gọi login/sign hoặc ghi dữ liệu token. Không sửa `Sources`, đóng gói hay khởi động lại TokenSigner trong nghiên cứu EFY.

**Kết luận cập nhật:** EFY **đã cài trong Windows trên Parallels**, version module `1.1.25.207`; hash bốn DLL trùng payload đã phân tích. Cả probe Windows x86/x64 đều khởi tạo PKCS#11 được. Registry EFY và ATR live trên Mac cùng xác nhận customer byte **`0x51`**. Module macOS Intel **nạp và khởi tạo thành công dưới Rosetta**, nhưng trả `CKR_TOKEN_NOT_PRESENT` và không có token-present slot. Đã quan sát một lỗi tương thích discovery: module chạy `sw_vers … | cut -d . -f2`, trên **macOS 27.2** nhận `2`, và runtime đi vào nhánh legacy tìm `/var/run/pcscd` không tồn tại. Hướng gần nhất là sửa/adapter discovery có giới hạn trong helper Intel; chưa đọc được chứng thư hoặc ký EFY, nên chưa bật registry. Phần **0** là trạng thái mới nhất, thay thế các khoảng trống tương ứng trong ghi chép lượt đầu ở phần 1–7.

## Quy ước và bằng chứng

- **[O] Quan sát:** byte, metadata, export/import hoặc source đã đọc; không đồng nghĩa hành vi đã chạy.
- **[I] Suy luận/đề xuất:** kết luận có điều kiện từ các quan sát.
- **[U] Chưa biết:** cần disassembly sâu hơn hoặc phép thử có kiểm soát.
- Các ID `EFY-CA-E##` là hồ sơ bằng chứng cục bộ của nghiên cứu này. ID `ev_…` do REA trả về; không trộn hai loại.
- Dữ liệu thô, bản sao volume và toàn bộ payload nằm tại `.local/efy-ca-windows/`. Hồ sơ portable có tiền tố `efy-ca` trong `docs/re/evidence/`; không cần cài payload để đọc lại bằng chứng.

| Evidence ID | Hồ sơ | Phạm vi |
|---|---|---|
| EFY-CA-E01 | [artifact-manifest](evidence/efy-ca-artifact-manifest.json) | Toàn bộ 7 file trên volume, đường dẫn, kích thước, SHA-256 |
| EFY-CA-E02 | [download-manifest](evidence/efy-ca-download-manifest.json) | URL, HTTP headers, hash payload đã tải; có cả phản hồi lỗi |
| EFY-CA-E03 | [windows-strings](evidence/efy-ca-windows-strings.json) | Chuỗi literal ASCII/UTF-16 và file offset trong hai EXE trên volume |
| EFY-CA-E04 | [extracted-manifest](evidence/efy-ca-extracted-manifest.json) | Hash mọi file giải nén Windows/macOS, định dạng và kiến trúc |
| EFY-CA-E05 | [module-strings](evidence/efy-ca-module-strings.json) | Chuỗi provider, Feitian/ePass/ESPK; không phải call-flow |
| EFY-CA-E06 | [source-and-package-text](evidence/efy-ca-source-and-package-text.json) | Source bootstrap/update, README, PackageInfo, postinstall, plist/config |
| EFY-CA-E07 | [atr-candidates](evidence/efy-ca-atr-candidates.json) | Byte giống ATR trong DLL Windows, bối cảnh raw; chưa xác minh xref/mask |
| EFY-CA-E08 | [static-interfaces](evidence/efy-ca-static-interfaces.json) | PE imports/exports, Mach-O symbols/dependencies, chữ ký, plist |
| EFY-CA-E09 | [environment](evidence/efy-ca-environment.json) | Kiểm tra VM/service/module/provider có giới hạn; blocker native REA |
| EFY-CA-E10 | [static-raw](evidence/efy-ca-static-raw.json) | Output đầy đủ `file`/`llvm-objdump`/`otool`/`nm`, archive list, extraction log, certificate metadata |
| EFY-CA-E11 | [source-crosscheck](evidence/efy-ca-source-crosscheck.json) | Commit và hash các file source/nghiên cứu đối chiếu |
| EFY-CA-E12 | [validation](evidence/efy-ca-validation.json) | Đọc lại JSON, đối chiếu hash/size và link báo cáo |
| EFY-CA-E13 | [installed-windows](evidence/efy-ca-installed-windows.json) | Installation, Registry32/64, CSP/KSP và companion process thực |
| EFY-CA-E14 | [installed-hash-crosschecks](evidence/efy-ca-installed-hash-crosschecks.json) | Hash/size trên guest so với payload cục bộ |
| EFY-CA-E15 | [runtime-windows](evidence/efy-ca-runtime-windows.json) | Probe own x86/x64: PC/SC, init, info, slots; không login/sign |
| EFY-CA-E16 | [runtime-macos](evidence/efy-ca-runtime-macos.json) | ATR live, dlopen/init, slot/token-info, LLDB observation |
| EFY-CA-E17 | [version-static](evidence/efy-ca-version-static.json) | Disassembly x86_64 của version check và discovery legacy |
| EFY-CA-E18 | [followup-validation](evidence/efy-ca-followup-validation.json) | Kiểm tra bằng chứng bổ sung và giới hạn runtime |

REA resource inventory thành công, giữ đầy đủ record:

- `ev_4f5c809d25e9aa0b56893120d3019fe24c049db9db9d67154c4b82d1e204924c`: [onlineinstaller-rea-resources](evidence/efy-ca-onlineinstaller-rea-resources.json), 55 resources, coverage complete trong parser PE resource.
- `ev_f1ce51a3a7fc94dedfc54f45b0b07777074f2f2f56451ba0419fd7d1c3c4dc8b`: [module-rea-resources](evidence/efy-ca-module-rea-resources.json), DLL x86, 64 resources, coverage complete trong parser PE resource.

Các record này **không giải mã hàm PKCS#11/CSP/KSP**. Xem giới hạn REA ở cuối báo cáo.

## 0. Kết quả bổ sung từ bản Windows đã cài và token trên Mac

### 0.1. Sửa kết luận trước về installation

**[O; E13]** Kết luận trước “chưa thấy EFY cài trong VM” không đúng. Lượt đầu chỉ xem `FileVersion` nullable và dùng lệnh `-Command` có quoting không đáng tin qua `prlctl`; giá trị null không chứng minh file không tồn tại. Lượt bổ sung dùng `-EncodedCommand`, kiểm tra tên/path trực tiếp và hai registry view riêng. Giữ E09 làm lịch sử, không dùng nó làm bằng chứng EFY vắng mặt.

Installation đã xác minh:

- `C:\Program Files (x86)\EFY-CA\PKI Token Manager v1.0`.
- Vendor key Registry32 `SOFTWARE\EFY Certification Authority\Token Manager v1.0`: `Version=110250207`, `InstallLanguageId=1066`, `NonCache=0`, `Path` trỏ thư mục trên.
- DLL chính x86: `C:\Windows\SysWOW64\efyca_p11_v1.dll`, 891,464 B; DLL x64: `C:\Windows\System32\efyca_p11_v1.dll`, 1,443,912 B. Cả hai version `1, 1, 25, 207`.
- `_s.dll` tương ứng cũng có trong cả hai thư mục. Hash cả bốn DLL **trùng byte** với payload E04/E08; đây là bằng chứng tái sử dụng static exports/imports cho bản đang cài. [E14]
- Windows `Get-AuthenticodeSignature`: hai DLL chính **Valid**, signer **Mobile-ID Technologies And Services Joint Stock Company**; hai `_s.dll` **NotSigned**. Đây là kết quả trên guest tại thời điểm đo, không áp cho toàn bộ distribution hay mọi máy.
- `efyca_p11_v1_certd.exe` đang chạy (PID 14000 trong snapshot); manager không được mình khởi chạy. Manager và certd trên guest có hash trùng payload đã giữ. Uninstaller có hash khác member `.nsis` đã trích, chưa phân tích sự khác biệt đó.

**[O; E13]** `EFY-CA Token CSP v1.0` đã đăng ký trong cả Registry64 và Registry32, Type `1`/`PROV_RSA_FULL`, `Image Path=C:\WINDOWS\system32\efyca_p11_v1_s.dll`. Không suy ra file vật lý mà tiến trình 32-bit sẽ nạp chỉ từ chuỗi System32, vì có filesystem redirection. `certutil -csplist` từ tiến trình ARM64 liệt kê CSP và **EFY-CA Token v1 Key Storage Provider**, nhưng KSP báo `Provider DLL failed to initialize correctly`. Điều đó xác nhận tên KSP hiện diện và lỗi trong caller ARM64 này; chưa chứng minh KSP hỏng trên x86/x64 hoặc nguyên nhân chính xác. Lệnh liệt kê có thể thử khởi tạo provider, nên không gọi đây là kiểm tra hoàn toàn tĩnh.

Copy payload từ guest tới `\\Mac\Home\…` bị lỗi quyền/path; không đổi share permissions hay security settings. Hash được tính trực tiếp trên Windows, còn raw bytes tương ứng đã có từ full installer. Không ghi việc copy thất bại thành thành công.

### 0.2. ATR EFY được đối chiếu bằng registry và PC/SC live

**[O; E13, E16]** Cả Registry64 và Registry32 có key `SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\EFY-CA Token Manager v1.0`, `Crypto Provider=EFY-CA Token CSP v1.0`:

```text
ATR:     3b9f958131fe9f006646530500000071df000051000000
ATRMask: ffffffffffffffffffffffff000000ffffffffffffff00
```

Mask match byte 0–11 và 15–21, bỏ byte 12–14 và 22; **byte index 19 = 0x51 được mask FF**, có ý nghĩa định danh EFY trong profile installation này. Đây là quy tắc đã cài trong Windows, khác candidate chưa trace E07 có trường customer rỗng.

PC/SC read-only trên Mac thấy `FT ePass2003Auto 02`:

```text
Live ATR: 3b9f958131fe9f006646530510113971df00005100006a
```

ATR live dài 23 byte, khớp toàn bộ mask EFY trên. Việc đọc dùng `SCardGetStatusChange(timeout=0)`; không `SCardConnect`, gửi APDU hay đổi USB passthrough trong bước này. Vì vậy đã có liên hệ **registry EFY ↔ ATR live ↔ reader cụ thể**. Chưa coi một customer byte là quy tắc cho mọi thế hệ EFY; route triển khai nên giữ kiểm tra pattern/mask hoặc profile đã kiểm chứng.

### 0.3. Runtime Windows: x86 và x64 đều nạp/khởi tạo được

Probe tự viết [efy-ca-readonly-probe.cs](evidence/efy-ca-readonly-probe.cs) được build bằng compiler .NET có sẵn, `/platform:x86` và `/platform:x64`; chạy trong thư mục tạm riêng `C:\Windows\Temp\TokenSigner-EFY-Research`. Source không có entry gọi `C_Login`, `C_Sign`, generate key, initialize token hay set PIN. [O; E15]

| Kết quả | DLL x86/SysWOW64 | DLL x64/System32 |
|---|---|---|
| Load + `C_Initialize` | OK, `0` | OK, `0` |
| `C_GetInfo` | OK, Cryptoki 2.20 | OK, Cryptoki 2.20 |
| Manufacturer/library | EFY Certification Authority / 1.20 | Cùng kết quả |
| `C_GetSlotList(false)` | 1 slot, ID 1 | 1 slot, ID 1 |
| Slot description | EFY Certification Authority virtual Slot 1 | Cùng kết quả |
| `C_GetSlotList(true)` | **0 token-present slots** | **0 token-present slots** |
| `C_Finalize` | OK | OK |

**[O]** PC/SC Windows tại thời điểm đo chỉ có `FT ePass2003Auto 0`, ATR customer byte `0x32`; không khớp EFY mask `0x51`. Token EFY matching đang thấy ở **host Mac**, không được chuyển qua VM trong nghiên cứu. Vì thế không có cơ sở dùng kết quả zero-present ở guest để kết luận DLL Windows không hỗ trợ token EFY. Chưa có certificate/mechanism enumeration trên một token EFY thực ở Windows.

### 0.4. Runtime macOS: loader đã qua, discovery chưa qua

**[O; E16]** Probe Intel riêng đã `dlopen` thành công đúng dylib hash `73977562…5cec09`, tìm được `C_GetFunctionList`, rồi thực hiện:

```text
C_GetFunctionList = CKR_OK
C_Initialize      = CKR_OK
C_GetInfo         = CKR_OK; Cryptoki 2.20; EFY Certification Authority; library 1.20
C_GetSlotList(false) = 1; description ES SLOT 1
C_GetTokenInfo(1) = 0xe0 = CKR_TOKEN_NOT_PRESENT
C_GetSlotList(true)  = 0
C_Finalize        = CKR_OK
```

Do đó `libstdc++.6`/`libgcc_s` **không chặn load trên host này**. Kết quả chỉ áp cho host đã đo, không suy ra mọi macOS đều có dependency đó. Dylib vẫn không có arm64; app fixture đang có helper/shim arm64-only. Không thể giải quyết chỉ bằng thêm `0x51` vào registry.

Probe [efy-ca-macos-readonly-probe.c](evidence/efy-ca-macos-readonly-probe.c) có phần mở session read-only/đọc chứng thư nhưng chưa đi vào được vì không có token-present slot. **Không có DER/chứng thư được lấy ra, không có key matching, login hay signature** trong lượt này. Không dùng `_s.dll` Windows hoặc module NC-CA/FastCA để thay EFY.

### 0.5. Bug discovery: chọn nhánh PC/SC legacy trên macOS mới

**[O tĩnh; E17]** Disassembly trên slice x86_64 đã hash:

- `0xb7a12` / `0xb7b03` chọn literal `sw_vers -productVersion|cut -d . -f2`; `popen` tại `0xb7a19` / `0xb7b0a`.
- `atoi` kết quả; `0xb7a76` / `0xb7b70` so với `9`. Chỉ kết quả `>9` mới đặt flag nhánh mới.
- Loop tại `0xb977f` kiểm tra flag; nhánh cũ `stat` rồi `open` `/var/run/pcscd`, có vòng sleep/retry khi thiếu file.
- Host báo `27.2`; pipeline thực trả `2`; `/var/run/pcscd` không tồn tại.

**[O runtime; E16]** LLDB chạy **probe riêng**, chỉ đọc register/string ở function entry, quan sát caller trong `efyca_p11_v1.dylib`:

```text
EFY_CALL popen argument='sw_vers -productVersion|cut -d . -f2'
EFY_CALL stat  argument='/var/run/pcscd'
EFY_CALL stat  argument='/var/run/pcscd'
EFY_CALL stat  argument='/var/run/pcscd'
```

Đây là bằng chứng nhánh legacy thực sự được gọi, củng cố lỗi version detection trong discovery. Run LLDB bị dừng theo timeout 30 giây; không có kết quả exit hoàn chỉnh từ run debug đó. Các run không debug phía trên đã finalize/exit thành công. Đã kiểm tra không còn probe/debugger EFY của mình chạy sau lượt đo.

Observer dùng dyld interpose không thu được event nên **không coi stderr rỗng là bằng chứng không gọi PC/SC/popen/stat**. Dùng observation LLDB để kết luận đường legacy, không dùng kết quả âm của observer. Source observer giữ ở [efy-ca-pcsc-observer.c](evidence/efy-ca-pcsc-observer.c); nó không thay tên reader, ATR, APDU hay return value.

**[I]** Sửa discovery cần đánh giá theo hai tầng: version detection chọn đúng nhánh trên major >=11, và dùng danh sách reader thực qua PC/SC thay các template cũ `FT  ePass2003Auto …` có hai dấu cách. Chưa thử sửa/substitute version output, patch binary, giả ATR hoặc thay global OS config. Chưa chứng minh chỉ sửa version là đủ để đọc chứng thư: reader naming, SM/APDU và certificate catalog còn cần phép thử tiếp theo.

### 0.6. Quyết định tích hợp sau lượt bổ sung

- **Đã có:** module chính hãng, hash bản Windows thực, CSP registration, tên KSP, ATR/mask `0x51`, ATR live tương ứng, module macOS load/init được dưới Rosetta, và bằng chứng nhánh discovery legacy.
- **Ưu tiên tiếp theo:** adapter discovery thử nghiệm chỉ trong process helper Intel, giới hạn đúng module hash và reader EFY đã match ATR; sau đó kiểm tra read-only token-info → mechanisms → DER/CKA_ID. Bản helper/shim Intel cần build ở fixture riêng; không thay app đang phục vụ người dùng.
- **Chưa bật EFY:** chưa đọc DER, chưa xác minh association key/cert, chưa chạy login/sign; `ModuleRegistry` vẫn không có EFY tại lần đọc source bổ sung. Backend native ESPK vẫn là phương án thứ hai nếu adapter discovery không đủ.
- **Không làm trong nghiên cứu này:** sửa `Sources`, cài driver, thay registry/trust store/share permissions, di chuyển USB, nhập PIN, gọi ký, phát hành chứng từ hoặc repack/restart app. Các thay đổi Sources đồng thời từ luồng khác được giữ nguyên.

## 1. Chuỗi artifact từ volume

**[O; E01, E06]** `/Volumes/EFY-CA/MACOSX/install.py` là bootstrap Python dài **450 byte**, SHA-256 `1c8cf6f837f0149a9f926cc53ee737720233b9ea57007a2fcf88467f002fbc82`. Nó import `urllib`, `getpass`, `ssl`, `os`, `platform`, đặt URL có một dấu cách đầu chuỗi:

` https://efyca.vn/download/tokenV1/ScriptInstall.py`

Mã dự định tải vào `/tmp/ScriptInstall.py`, tạo `ssl._create_unverified_context()`, rồi gọi `os.system('python '+scriptInstall)`. Đây là **ý định trong source**, chưa xác minh bootstrap chạy được: source dùng `print "…"` của Python 2 và truyền `context=` cho `urllib.urlretrieve`; tính tương thích của API đó cũng chưa được chạy. Không phải bộ cài Windows.

**[O; E01]** Kiểm kê toàn bộ volume nhỏ này cho 7 file: `MACOSX/install.py`, `MACOSX/readme.txt`, `UBUNTU/install.sh`, `UBUNTU/readme.txt`, `autorun.exe`, `autorun.inf`, `efyca_p11_v1_onlineinstaller.exe`. Không có DLL/PKG đầy đủ trên volume trong lần kiểm kê.

**[O; E02, E03, E06]** Chuỗi đích đã tải bằng `curl` với xác minh TLS bình thường; không dùng logic TLS của script:

| Đường dẫn tham chiếu | Nội dung lấy được |
|---|---|
| [ScriptInstall.py](https://efyca.vn/download/tokenV1/ScriptInstall.py) | 574 B, Python 2; tải rồi `open /tmp/efyca_p11_v1.pkg` |
| [macOS PKG](https://efyca.vn/download/tokenV1/macosx/efyca_p11_v1.pkg) | 3,057,742 B, distribution XAR package |
| [Windows full installer](https://efyca.vn/download/tokenV1/efyca_p11_v1_installer.exe) | 3,375,208 B, PE32 chứa NSIS LZMA; URL literal tại file offset 221416 của onlineinstaller |

`autorun.inf` ghi `OnlineInsPackage=efyca_p11_v1_onlineinstaller.exe`, `RegPath=EFY Certification Authority\Token Manager v1.0`, `Product=EFY-CA Token v1.0`, `Version=110181022`. Onlineinstaller có metadata `1.1.18.828`; full installer hiện tải được có `1.1.25.207`, members mang mốc 2024–2025. Mốc PE stub 2009 và copyright không phải ngày phát hành đáng tin; chỉ là metadata. **Không xem full installer hôm nay là bản byte-for-byte đi kèm token lúc phát hành.**

Hash các artifact chính:

| Artifact | SHA-256 |
|---|---|
| `autorun.exe` trên volume | `a09aaee8affbeb61a5ae591340e415be79a7ec24134f28311ac26e991ed8174e` |
| `efyca_p11_v1_onlineinstaller.exe` trên volume | `0977dadabfa0810cff343c2d51f38535a719adea16cd4d8067cfcb6d6a721f42` |
| `ScriptInstall.py` tải từ EFY | `5a8cf9effa608a6662deeff7db8a6b3a4b3c3f7957503d0b370ea911e1ed1ba3` |
| `efyca_p11_v1.pkg` | `2cbe321f5b547eeb53010e81a25dbb251c9e09117ddcc4c7ac4826749b533b10` |
| `efyca_p11_v1_installer.exe` | `55dff7ecd59d4efed67ac152be6fefc74b2ee17069df6fce3ac28e81afb6f546` |

## 2. Bộ Windows

Giải nén bằng `7zz x -y -aou`, không chạy NSIS. Archive có **hai members cùng tên** `$_2_/efyca_p11_v1.dll` và hai members `efyca_p11_v1_s.dll`; `_1` dưới đây do extractor đổi tên để giữ cả hai. `$_2_` là đường dẫn biến trong archive; **chưa chứng minh là thư mục cài đặt cuối cùng**. [O; E04, E08, E10]

| File giải nén | Byte | Kiến trúc | Giao diện quan sát |
|---|---:|---|---|
| `$_2_/efyca_p11_v1.dll` | 891,464 | PE32 x86 | 98 named exports; CSP, minidriver, KSP, 68 `C_*` |
| `$_2_/efyca_p11_v1_1.dll` | 1,443,912 | PE32+ x86_64 | Cùng 98 tên export, RVA khác |
| `$_2_/efyca_p11_v1_s.dll` | 10,752 | PE32 x86 | 23 CSP `CP*` exports |
| `$_2_/efyca_p11_v1_s_1.dll` | 48,128 | PE32+ x86_64 | Cùng 23 CSP `CP*` exports |
| `efyca_p11_v1_mgr.exe` | 5,122,120 | PE32 x86 | GUI manager; import certificate/CryptoAPI/WinHTTP/WinInet/Winsock |
| `efyca_p11_v1_certd.exe` | 215,112 | PE32 x86 | Certificate companion; import WinSCard/Crypt32/MFC42u |
| `CCID/usbccid.sys` | 29,184 | PE32 x86 | Driver CCID, kèm INF/CAT/SetupTool |

Hash module chính:

- x86: `49b0577682f70ea8208580fb499774c6ac4e3c778df5d76b1ee0b6a6ad2d04e0`.
- x64: `4cd6c0b57b35d5ee6109edf020370abfa6d8f63befd150ccd20210a5b1bff010`.
- `_s` x86: `3df383f4b0195620badc0bb9f5e1d86ebdb4975b60da4b910a26fee9b4af474f`.
- `_s` x64: `7c062329835c528928357fec772f9a7a6dbd8943a59efd3a108831dbc3067c94`.

**[O; E08]** Ví dụ RVA trong module x86 (không phải VA):

| Export | RVA | Ý nghĩa giao diện |
|---|---|---|
| `CPAcquireContext` | `0xf38c` | Legacy CryptoAPI CSP |
| `CPSignHash` | `0x102c7` | CSP signing entry |
| `CardAcquireContext` | `0x7c5b4` | Smart card minidriver entry |
| `GetKeyStorageInterface` | `0x7caaa` | CNG KSP entry |
| `C_GetFunctionList` | `0x6c783` | PKCS#11 function table |
| `C_FindObjects` / `C_GetAttributeValue` | `0x6bf94` / `0x6beec` | Object/certificate enumeration API |
| `C_Login` | `0x6bdde` | PKCS#11 user authentication entry |
| `C_SignInit` / `C_Sign` | `0x6c2cf` / `0x6c305` | PKCS#11 signing API |

**[O; E05, E08]** Module chính import `WinSCard.dll`, gồm `SCardEstablishContext`, `SCardListReadersW`, `SCardConnectW`, `SCardTransmit`, transaction/status/reconnect APIs và T=0/T=1 PCI. Các chuỗi literal xác định `EFY-CA Token CSP v1.0`, `EFY-CA Token v1 Key Storage Provider`, `EFY-CA PKCS#11 Library.`, `ePass2003Auto`, `ENTERSAFE-ESPK`; có export `eb_RegKspProvider`/`eb_UnRegKspProvider`. Chứng minh có nhiều giao diện trong cùng DLL; chưa kiểm tra hiệu lực đăng ký provider trên Windows.

**[O; E06]** `csp.ini` cho lựa chọn `private csp` / `microsoft csp`. `_s.dll` có import CryptoAPI và 23 exports, nhưng chưa trace chức năng delegation/config của từng lựa chọn. Không gọi nó là PKCS#11 module.

**[O; E06]** `usbccid.inf`: class `SmartCardReader`, generic match `USB\Class_0B&SubClass_00`, `usbccid.sys`, `DriverVer=08/01/2006,5.2.3790.2724`, registry additions cho `SCardSvr`/`CertPropSvc`. Đây là driver reader CCID, khác `CardAcquireContext` minidriver trong DLL; INF không định danh USB VID/PID riêng cho EFY. Không thấy ARM64 SYS trong payload đã kiểm kê.

**[O/I; E04, E08]** `FirefoxEFYCA.exe`, `FirefoxEFYCAun.exe`, `thunderEFYCA.exe`, `thunderEFYCAun.exe` là các companion có tên tích hợp trình duyệt. Tên file và import/export chưa đủ để khẳng định cơ chế native messaging/ActiveX hay local HTTP signer. Trong payload này không có artifact được xác minh là signer/plugin web độc lập; không kết luận toàn bộ hệ sinh thái EFY không có signer khác.

## 3. Bộ macOS

Giải nén bằng `pkgutil --expand-full`, không gọi `installer` và không chạy postinstall. Có 9 component packages. Package identifiers chứa `www.ftsafe.com.epass2003tomicaefyca20190314`; distribution mang timestamp 2019. [O; E04, E06, E10]

| Component | Vị trí do metadata/source chỉ ra | Kiến trúc/chức năng |
|---|---|---|
| `efyca_p11_v1.dylib` | `/usr/local/lib/efyca_p11_v1.dylib` | Universal **Intel i386 + x86_64**, không có arm64; 2,976,556 B; 68 `C_*` exports mỗi slice |
| `EFY-CA Token Manager V1.app` | `/Applications/` | x86_64, bundle `vn.mobileid.efyca`; minOS 10.7, SDK 10.14 trong executable |
| `efyca_p11_v1.tokend` | Script chọn `/System/Library/Security/tokend/` hoặc `/Library/Security/tokend/` | i386+x86_64, legacy tokend; bundle `com.apple.tokend.efyca_p11_v1`, version 1.1.1/30557 |
| `ifd-FeiTccid.bundle/libccid.dylib` | Script có nhánh `/usr/libexec/SmartCardServices/drivers/` và `/usr/local/libexec/SmartCardServices/drivers/` | x86_64, Generic CCID, Info.plist ghi 1.4.20 |
| `nssFirefox`, `nssThunderbird` | Copy vào app tương ứng, đăng ký module | i386+x86_64, helper NSS |
| `EFY-CA.crt`, `MICNationalRootCA.crt` | `/tmp`, rồi helper NSS import | CA certificates, không phải chứng thư cá nhân trong token |
| `uninstall.sh` | `/usr/local/EFY-CA/PKI Token Manager v1.0/` | Shell source |

**[O; E04, E08, E10]** PKCS#11 dylib SHA-256: `7397756209003a7345e091e2b79e88d49c0149c84de44131c32f73d39a5cec09`. `codesign -dv` báo **not signed at all**, `pkgutil --check-signature` báo PKG **no signature**. Không có kết quả notarization/runtime assessment. Không thấy component CryptoTokenKit `.appex`/`.xpc` trong package đã giải nén.

Dependencies của cả hai slice:

```text
/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
/System/Library/Frameworks/PCSC.framework/Versions/A/PCSC
/usr/lib/libSystem.B.dylib
/usr/lib/libstdc++.6.dylib
/usr/lib/libgcc_s.1.dylib
```

**[O/I; E08]** Có imports `SCardTransmit`, `SCardConnect`, `SCardEstablishContext`, transaction/reconnect APIs. Không có dependency vendor dylib khác trong load commands; đây là ứng viên module tự chứa lớp token qua PC/SC. Tuy nhiên module có import IOKit và khởi tạo tĩnh, nên chưa chứng minh chỉ dùng PC/SC hoặc nạp thành công trên macOS hiện tại. `libstdc++.6`/`libgcc_s` và thiếu arm64 là điều kiện phải kiểm tra; không suy ra thiếu dependency chỉ từ `test -e /usr/lib/…` vì dylib hệ thống có thể ở shared cache. Không có `LC_VERSION_MIN_MACOSX`/`LC_BUILD_VERSION` được liệt kê cho chính dylib trong dump, không gán minOS của GUI sang module.

**[O; E06]** README/config/NSS scripts cùng chỉ `LibPath=/usr/local/lib/efyca_p11_v1.dylib`; module name NSS là `EFY Certification Authority PKCS#11 Module v1.0`. Config ghi `VersionUT=1.0.0`, `VersionDylib=1.0.0`; file [version_macos.ini](https://efyca.vn/download/tokenV1/macosx/version_macos.ini) tải hôm nay vẫn ghi `usertool=1.0.0`, `dylib=1.0.0` (HTTP Last-Modified 2022-12-06). Không dùng config version làm bằng chứng version thực của ABI.

**[O; E02, E06]** Theo các file update thực có trong app:

- `ScriptUpdate.py` vẫn trỏ chính PKG đã tải ở trên.
- `ScriptUpdateUT.py` trỏ `efyca_p11_v1.zip` cho GUI, nhưng phần unzip lại ghi một tên ZIP khác. Chỉ đọc script, không tải thêm GUI ZIP vì không trả lời khoảng trống module/driver.
- `Config.ini` trả HTTP 403; `efyca_p11_v1_mgr.cfg` chuyển tới `/404.html`, body `404 not found :(` dù HTTP cuối là 200. Không coi các body này là config hợp lệ.

**[O; E06]** Postinstall có nhánh sửa/copy CCID, dừng `ifdreader`/`pcscd`; script NSS có `rm -rf /Applications/Firefox.app` hoặc Thunderbird khi không thấy executable tại đường dẫn mong đợi. Đây là các tác động ghi trong source, **không xảy ra trong khảo sát**. Vì thế kế hoạch nghiên cứu module sử dụng payload đã giải nén thay vì chạy toàn bộ gói trên máy đang phục vụ người dùng.

**[O; E10]** CA cert trong package: EFY-CA do MIC National Root CA cấp, hết hạn **2023-07-18**; root hết hạn 2040-05-16. Chúng không xác định hiệu lực chứng thư thực trong token và không được import vào trust store trong nghiên cứu.

## 4. Token, ATR và protocol

**[O; E05, E06, E08]** Metadata/package, chuỗi `ePass2003_pcsc_mutex_`, `Feitian ePass2003`, `FT  ePass2003Auto`, `ENTERSAFE-ESPK` và PC/SC imports đều tương hợp họ **Feitian ePass2003 / EnterSafe ESPK**. Đây là định danh middleware; chưa phải quan sát phần cứng EFY đang kết nối.

CCID plist khai báo VID `0x096E`, PID `0807,080A,0703,0853,0855,0856,0859`; postinstall còn thêm `080F` (eJAVA). Các PID này thuộc danh sách hỗ trợ driver dùng chung, **không phải PID riêng của token EFY**. [O; E06, E08]

**[O; E07]** DLL Windows có candidate 23 byte tại file offset `790748` (x86) / `1329076` (x64):

```text
3b 9f 95 81 31 fe 9f 00 66 46 53 05 00 00 00 71 df 00 00 00 00 00 00
```

Có length-like `17 00 00 00` ngay trước và vùng mask-like `ff/00` phía sau. Còn mẫu khác bắt đầu `3b 9f 95 81 31 fe 9f 00 65 46 53…`. Chưa trace xrefs/layout/matching nên chỉ giữ **candidate byte pattern**, không gọi đây là ATR thực, không chọn byte19=0 làm mã EFY. Tìm cùng raw prefix trong macOS dylib không có match; kết quả âm chỉ giới hạn ở prefix đó.

**[U]** Chưa có reader/USB mapping hay ATR lấy trực tiếp từ một token được xác nhận EFY; chưa có APDU SELECT/authentication/RSA trace. Không dùng thông tin volume label để gán ATR cho reader khác. T=0/T=1 imports cho thấy middleware biết hai giao thức, chưa xác định giao thức đang đàm phán.

## 5. Đọc chứng thư và ký RSA

**[O; E08]** macOS và Windows đều có `C_GetFunctionList`, `C_GetSlotList`, `C_GetTokenInfo`, `C_OpenSession`, `C_FindObjectsInit/FindObjects/Final`, `C_GetAttributeValue`, `C_Login`, `C_SignInit`, `C_Sign`, `C_GetMechanismList/Info`. Export là bằng chứng bề mặt API; một số entry trong Windows chia sẻ RVA, nên không suy ra mọi chức năng đều được thực thi hoặc hỗ trợ.

**[I; E08, E11]** Giao thức tích hợp đề xuất, khớp `Sources/TokenHelper/PKCS11.swift`:

1. Helper đúng kiến trúc `dlopen` module; lấy function table qua `C_GetFunctionList`; `C_Initialize`.
2. Enumerate slot/token/reader và serial. Mở read-only session, tìm `CKO_CERTIFICATE`, đọc DER từ `CKA_VALUE` và ID từ `CKA_ID`. Trả qua `CertInfo`; không dùng CA cert đóng gói thay cho chứng thư cá nhân.
3. Khi được phép ký, mở R/W session và `C_Login(CKU_USER)` với PIN người dùng cung cấp; tìm private key `CKO_PRIVATE_KEY` theo **đúng `CKA_ID`** của chứng thư đã chọn.
4. Ưu tiên kiểm tra `CKM_RSA_PKCS` cho dữ liệu DigestInfo đã hash ở host, rồi `C_SignInit`/`C_Sign`; xác minh chữ ký bằng public key của đúng DER. Cần phân biệt raw-message `CKM_SHA256_RSA_PKCS` với DigestInfo để tránh hash hai lần.
5. Logout/đóng session trong cùng helper process. Không thử PIN mặc định trong config; nó là giá trị công khai do nhà cung cấp đóng gói, không phải bằng chứng PIN của token.

**[U]** Chưa chạy `C_GetMechanismList/Info`, chưa xác nhận RSA key size, cơ chế/hash được hỗ trợ, certificate visibility trước login, mapping `CKA_ID`, query-size/retry semantics của `C_Sign`, PIN retry flags hoặc hành vi session. Không có phép ký RSA EFY thành công trong nghiên cứu này. Các bước trên là kế hoạch API, không phải trace đã quan sát.

Windows có thể đi qua PKCS#11 trực tiếp để giữ cùng mô hình, hoặc CryptoAPI/CNG thông qua CSP/KSP sau khi xác minh đăng ký provider và chọn certificate/key. Chưa xác minh `CryptSignHash`/`NCryptSignHash`, padding hay byte order của đường Windows cụ thể; không đổi format signature trong app dựa trên export đơn thuần.

## 6. Đối chiếu TokenSigner và đường tích hợp

**[O; E09, E11]** `ModuleRegistry.swift` hiện bỏ EFY, chọn module theo `atr[19]`; FastCA còn đòi toàn bộ `FastCAProfile.atr`. `TokenBroker.swift` đã hỗ trợ `.x86_64` bằng `/usr/bin/arch -x86_64 TokenHelper --module …`; app tìm module trong `/usr/local/lib` và thư mục Modules của app. Nhánh PKCS#11 chèn `libTSShim.dylib` qua `DYLD_INSERT_LIBRARIES`. Shim sửa hai dạng Lc/Le của secure-messaging APDU và interpose `SCardTransmit`; chưa có bằng chứng EFY cần đúng phép sửa đó. **Bản `TokenHelper` và `libTSShim.dylib` hiện có trong `.local/test-env/TokenSigner.app/Contents/MacOS/` đều chỉ là arm64** theo `file`; code có nhánh x86_64 không có nghĩa bundle hiện tại đã chạy được nhánh đó. Cần build helper/shim Intel hoặc universal trong fixture riêng trước khi thử EFY, không thay bundle đang phục vụ người dùng.

**[I] Đường A, module EFY chính hãng:** ứng viên `ModuleInfo(ca: "EFY-CA", moduleName: "efyca_p11_v1.dylib", arch: .x86_64, isExperimental: true)` chỉ là thiết kế, **chưa thêm vào code**. Điều kiện trước khi route tự động:

- Xác minh helper và shim đều có slice x86_64, Rosetta thực dùng được, module load được với các dependency cũ. Receipt Rosetta trên host đã có; chưa chạy module. Không gọi cặp i386+x86_64 này là `.universal` theo enum dự án, vì arm64 helper không nạp được nó.
- Lấy ATR thực có liên hệ rõ ràng tới EFY; xác minh quy tắc match, không chọn customer byte từ candidate table có mask chưa biết. Nếu middleware dùng chung, ưu tiên `tokenScope: .reader` và kiểm tra slotDescription ↔ reader để tránh ghép nhầm token.
- Chạy kiểm tra read-only theo từng tầng: load → slots → token info → certificates/CKA_ID. Sau đó mới đến phép thử login/sign đã được cho phép, có xác minh chữ ký độc lập.
- Đánh giá TSShim trên chính APDU của EFY. Việc các CA khác cần shim không chứng minh EFY cần nó; không bật một sửa protocol mới từ suy luận chung.

**[I] Đường B, backend PC/SC độc lập:** `ENTERSAFE-ESPK`, ePass metadata và PC/SC imports là cơ sở để khảo sát các primitive hiện có trong [FastCA native](fastca-native-signing.md) và [Feitian PIN auth](pin-auth-feitian.md). Cần xác minh application/DF, SM/device-auth profile, certificate catalog, key reference và PIN transform riêng EFY. Không route EFY qua `.fastca`/`FastCAProfile` hoặc sao chép key/profile FastCA. Đây có thể là hướng arm64 lâu dài nếu không có module EFY mới, nhưng chưa có bằng chứng tương thích protocol EFY ở mức đủ để triển khai.

**[O/I; E11]** [NC-CA](ncca.md) có module arm64 và bộ thành phần mới hơn; cùng họ Feitian không làm module NC-CA thành module thay thế EFY. [MacSigner](macsigner-repo.md) đã có discovery tên `efyca_p11_v1.dylib`, nhưng ghi không có EFY validation; đây chỉ củng cố tên/path discovery, không chứng minh token được ký. Những kết quả ký thật FastCA/NC-CA trước đây không được tính là test EFY.

## 7. Môi trường và khoảng trống

**[O; E09]** Parallels `Windows 11 LTSC` UUID `{cc8b63dd-8328-4967-9d24-c07898fa78f0}` đang chạy; guest báo ARM64, `SCardSvr=Running`. Kiểm tra read-only không thấy version của `C:\Windows\System32\efyca_p11_v1.dll` hoặc `C:\Windows\SysWOW64\efyca_p11_v1.dll`, không tìm thấy tên CSP chứa EFY ở nhánh provider đã kiểm tra. Không kiểm kê toàn bộ ổ đĩa, không chứng minh mọi software EFY đều vắng mặt. Chưa kiểm tra Windows KSP registration riêng. Không chạy provider x86/x64 qua emulation, không passthrough/chuyển USB, không cài driver.

**[U]** Runtime Windows sẵn có nhưng EFY middleware và token mapping chưa được xác minh. DLL x86/x64 không phải driver ARM64; generic CCID SYS x86 trong package không chứng minh reader dùng được trên guest ARM64. Các phép thử runtime tương lai cần môi trường snapshot/fixture riêng và chỉ dùng middleware/token đã định danh; không cần sửa app đang chạy để tiếp tục nghiên cứu.

REA native: `open_binary` nhận PE32, nhưng `binary_overview` hết timeout 120s chờ Hopper bridge; shutdown acknowledgement không hoàn tất, private runtime `/tmp/rea-bwb6UO` còn được REA giữ. Record lỗi: [rea-native-blocker](evidence/efy-ca-rea-native-blocker.json). UI read-only thấy Hopper đang ở `TokenMgr.hop` của luồng OneCA và chạy script REA của luồng đó; không thao tác/đóng cửa sổ dùng chung hoặc kill Hopper. Một lần mở FAT macOS bị parser từ chối vì không có arm64; slice x86_64 được `lipo -thin` ra scratch, nhưng mở target tiếp bị blocker cleanup cũ. Đã gọi `close_binary`; REA trả cleanup incomplete, không ghi là đóng thành công. Không cài/sửa cấu hình REA/Hopper/Ghidra. Các phân tích PE/Mach-O còn lại dùng toolchain tĩnh và lưu output thô; không có pseudocode/call-flow native đã xác minh.

| Câu hỏi | Mức hoàn thành | Phần còn thiếu |
|---|---|---|
| Định danh artifact EFY | Đã trả lời trong phạm vi volume + URL tham chiếu | Không khảo sát mọi phiên bản EFY trên thị trường |
| Driver/minidriver/CSP/KSP/PKCS#11 Windows | Đã định danh bề mặt tĩnh | Setup registry, native call-flow và runtime |
| Signer/plugin web Windows | Một phần | Chưa có artifact/protocol local signer được xác minh |
| Module macOS, kiến trúc, dependencies | Đã trả lời tĩnh | Loadability và hoạt động trên macOS hiện tại |
| Đọc chứng thư, ký RSA | API path đề xuất | Slots/certs/keys/mechanisms/login/sign EFY thực |
| Họ token/USB | Định danh middleware, hỗ trợ driver | Reader/VID/PID của thiết bị EFY thực |
| ATR/protocol | Candidate bytes + họ ESPK | ATR live, xrefs/mask, APDU/SM/profile EFY |
| Tích hợp TokenSigner | Hai đường khả thi có điều kiện | Chưa đủ cơ sở bật EFY trong registry |

Kiểm tra kết thúc: JSON evidence đọc lại được; hash bản sao volume/download/payload được kiểm tra với manifests; không có test app, ký thật hay thay đổi Sources từ nghiên cứu EFY. Dữ liệu không được ghi vào tài liệu chung hoặc đường dẫn OneCA.
