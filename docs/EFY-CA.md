# EFY-CA native trên macOS

Ngày 23/10/2026, người dùng đã bấm **Ký thử** ở dòng EFY-CA của app đóng gói,
tự nhập PIN và xác nhận kết quả **“Ký và xác minh OK”**. Backend kiểm tra chữ ký
RSA bằng public key của đúng DER đã chọn trước khi trả kết quả. Đây là thử ký
dữ liệu cục bộ; chưa kiểm tra cổng nghiệp vụ, chain hoặc revocation.

## Phạm vi hỗ trợ

- Profile ESPK có exact ATR `3b9f958131fe9f006646530510113971df00005100006a`.
  Byte customer `51` riêng lẻ không đủ để bật backend. EFY vẫn có nhãn thử nghiệm.
- Helper chạy native ARM64, `--backend efy`, không dùng EFY dylib Intel hay Rosetta.
  Broker loại biến injection/debug và không nạp APDU shim cho backend này.
- OpenSC 0.27.1 phụ trách PC/SC và secure messaging. Sau reset khi mở phiên,
  transport khởi tạo lại SM trước khi đọc metadata hoặc xác thực PIN.
- Đọc catalog ESPK để tìm cardid, certificate và private-key metadata; không
  hardcode FID chứng thư hoặc key reference của thẻ nghiên cứu. Không đọc key EF.
- Serial token là `EFY-` + hash cardid, độc lập tên/số reader và gia hạn chứng thư.
  Nhiều token trùng cardid bị từ chối trước PIN.
- Ghép CKA_ID, class/type/sign capability, RSA-2048 và public key DER trước PIN.
  Khi ký chỉ dùng certId thuộc snapshot đã kiểm tra trong cùng phiên.
- Hỗ trợ RSA_PKCS với payload đã chuẩn bị và SHA256_RSA_PKCS với message thô;
  RSA_X_509 chưa hỗ trợ. Mỗi phiên chỉ ký một lần; lỗi không fallback/retry.

## PIN và vòng đời phiên

PIN 1–64 ký tự ASCII được nhập trong app, đi qua stdin pipe của helper, không
đặt trong argv/log. Công thức profile đã đo là `SHA1(raw bytes) || BE32(count)`,
challenge8 → 3DES CBC IV0 → external-auth qua SM. Chỉ một lần xác thực; cấm
retry wrong-length/get-response cho auth và primitive ký.

SW 63Cx cung cấp retries khi thực sự nhận được; 6983/63C0 báo khóa. Lỗi transport
báo chưa xác định và không tự thử PIN lại. Trước khi biết retries, UI hiển thị
`PIN_RETRIES_UNKNOWN`. Phiên đóng/reset sau sign, lỗi, logout hoặc helper kết thúc;
phiên EFY mới luôn reset lại để không tin trạng thái auth còn sót sau crash.
Buffer C/Swift kiểm soát được có wipe; không bảo đảm xóa mọi bản sao String do
Swift/AppKit quản lý. Việc reset được gọi không phải phép đo độc lập trạng thái
auth của thẻ sau reset.

## Bundle thử nghiệm

`package-test-app.sh` đóng gói runtime ARM64 đã đo và libcrypto vào
`Contents/Frameworks/ESPK`; ABI, kiến trúc, dependency closure, code signature và
license được kiểm tra. Manifest và thông báo bản quyền nằm trong
`Contents/Resources/ESPK-Notices`. Bản helper trong bundle ưu tiên runtime này.
Chạy helper rời khi phát triển có thể dùng OpenSC 0.27.1 cài sẵn.

Gói local ký ad-hoc, chưa notarize/phát hành. Script hiện pin hash runtime OpenSC
đã nghiên cứu trên máy này; bản build runtime khác cần kiểm chứng trước khi dùng.

## Kiểm chứng

163 Swift tests đạt, gồm backend giả lập với metadata/FID khác mẫu thật,
certificate mismatch, cardid mơ hồ, lỗi PIN/transport, cleanup và verify chữ ký.
`python3 scripts/check-native-espk.py` chạy implementation C với OpenSC giả:
exact profile, reset/SM refresh, một auth, MSE/PSO, lỗi và không retry.

Helper trong bundle đọc được đúng một chứng thư EFY thật; fingerprint khớp nghiên
cứu. GetCert của app quảng bá đúng DER đó và đánh dấu còn hiệu lực. Đã kiểm tra
helper nạp OpenSC/libcrypto từ bundle, smoke sáu cổng đạt. Không cần nhập PIN
thêm hoặc ký hồ sơ để kiểm tra những bước này.

Kết quả ký thật dựa trên xác nhận trực tiếp của người dùng sau phép **Ký thử**;
không thu signature/wire capture riêng. Chưa có kết quả EFY + Minvoice/eTax/DVC
nghiệp vụ. [Evidence](re/evidence/efy-packaged-app-2026-10-23.json).
