# Môi trường test FastCA và M-Invoice

**FastCA đã ký và verify trực tiếp trên macOS** bằng helper OpenSC/ESPK thử
nghiệm, chữ ký RSA 256 byte. Xem [native report](re/fastca-native-signing.md).
App/TokenHelper, nút “Ký thử” và SignHash đã nối backend mới và test thành
công; xem [FASTCA.md](FASTCA.md). FastCA và NC-CA cũng đã ký/verify qua Windows
ARM, xem [windows-signing-test.md](re/windows-signing-test.md). Software tests không thay
thế kiểm tra phần cứng.

Đã chuẩn bị ngày 2026-10-22 trên macOS / Apple Silicon, Command Line Tools Swift
6.4. Dùng hai worktree hiện có, không merge nhánh. Swift, Python 3, OpenSSL,
xmlsec1, Testing.framework và macro plugin đều đã có; không cần cài lại Xcode.

## Chạy lại bộ kiểm tra

Từ checkout gốc:

```sh
./scripts/test-env.sh check
./scripts/test-env.sh test-all
```

`check` kiểm tra công cụ, loopback và tạo khóa RSA tạm trong bộ nhớ. `test-all`
build/test core trước, rồi build/test worktree M-Invoice. Mỗi worktree chỉ có một
builder chạy tại một thời điểm. Cache, file tạm và log của runner nằm trong
`.local/test-env/` (Git bỏ qua); M-Invoice còn dùng cache riêng trong `/private/tmp`.

Không cần token, PIN, tài khoản M-Invoice hoặc VM cho các software tests này.
Nếu executor chặn loopback/RSA, runner dừng ở preflight để báo đúng lỗi môi trường.

## FastCA native runtime

App dùng OpenSC 0.27.1 đã có tại `/opt/homebrew/lib/libopensc.13.dylib`; header
upstream được giữ trong repo. Backend không dùng generic `libcastle` nữa.

```sh
./scripts/test-env.sh setup-fastca
```

Setup giờ chỉ kiểm tra runtime/version, không copy/nạp vendor PKCS#11, không kết
nối thẻ, không nhận PIN hoặc ký. Nếu thiếu/khác runtime, runner và app báo rõ;
không tự cài driver hay đổi trust store. Xem [FASTCA.md](FASTCA.md).

## Mở app để test thủ công

Sau khi build/test, chọn **một** app:

```sh
./scripts/run-test-app.sh fastca
# Thoát app trên trước khi mở worktree còn lại:
./scripts/run-test-app.sh minvoice
```

Launcher kiểm tra binary/helper/shim và các cổng cần dùng; không dừng process khác.
`--print` chỉ in đường dẫn app đã build, không khởi chạy. Mở app có thể đọc token
đang cắm qua middleware; thao tác ký vẫn đi qua cửa sổ approval và PIN của app.
PIN không nhập trong chat hoặc command line. Backend FastCA mới đã nối vào
app: dùng nút “Ký thử”, duyệt một lần và nhập PIN trong cửa sổ app. Có thể tạo
bundle local bằng `./scripts/package-test-app.sh`, rồi mở
`.local/test-env/TokenSigner.app`. Đóng app trước khi đóng gói lại.

Hai app cùng dùng cổng 32001 nên chạy lần lượt. Worktree M-Invoice còn dùng
16080, 8768/8769, 4433/4434. Mã FastCA mới nằm ở core; chưa được merge vào worktree
M-Invoice. Chưa có một app kết hợp FastCA + phát hành M-Invoice end-to-end.

## Phạm vi M-Invoice đã test được

Full suite gồm SignalR loopback, XMLDSig/xmlsec1, CMS/OpenSSL, broker và request
builder REST bằng fixture. Script riêng tự tìm framework/macro/linker paths của
CLT: [TEST-MINVOICE.md](../.claude/worktrees/beautiful-shirley-8acdc0/docs/TEST-MINVOICE.md).
`SignInvoices` vẫn 501 cho đến khi xác minh profile XML và response thực.

Parallels đã có VM **Windows 11 LTSC**, đang suspended tại lúc kiểm tra. Chưa
resume VM, chạy MinvoicePlug/installer, cài proxy hay thêm proxy CA. Capture thực
cần process plugin Windows và tenant thử nghiệm do người dùng kiểm soát; DevTools
của tab không thấy request do process .NET gửi. Không dùng hóa đơn thật để chạy
software tests trên đây.

## Bằng chứng và phần còn lại

- [FastCA native](re/fastca-native-signing.md): đọc catalog/chứng thư, xác thực
  PIN và ký thật đều đạt; Security.framework và OpenSSL verify thành công.
  App/TokenHelper/menu/SignHash cũng đã test đạt; chứng thư đã hết hạn, chưa test portal.
- [M-Invoice](re/minvoice-rest-static.md): CIL và contract REST; vẫn cần signed XML,
  login/response fixture và capture Windows trước khi nối ký/upload thật.
- [Kết quả môi trường M-Invoice](re/evidence/minvoice-env-validation.json): host
  preflight/build và 81 tests đạt; supersede lỗi sandbox lịch sử.

## Windows ARM: ký thật đã đạt

Ngày 22/10/2026, FastCA và NC-CA ký dữ liệu test thành công qua CSP vendor trong
Windows ARM/Parallels, với user tự nhập PIN. Cả hai chữ ký được verify độc lập
trên macOS bằng OpenSSL. FastCA dùng chứng thư đã hết hạn; phép đo chưa kiểm tra
portal/trust. Generic `libcastle` vẫn không tương thích; backend native hiện dùng
OpenSC/ESPK và đã được test riêng qua app.
Chi tiết: [windows-signing-test.md](re/windows-signing-test.md).


## FastCA native macOS: ký thật đã đạt

Không cần Windows cho đường ký OpenSC/ESPK mới. Kết quả được lưu trong
[fastca-native-signing-validation.json](re/evidence/fastca-native-signing-validation.json).
Verify lại artifact mà không dùng token/PIN: `python3 scripts/verify-fastca-native.py`.
Sau tích hợp app, bộ test đạt 38 tests. Chạy `python3 scripts/verify-fastca-native.py --app`
để verify lại chữ ký SignHash đã lưu, không cần PIN/token.
