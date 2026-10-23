# FastCA trong TokenSigner

FastCA dùng backend native ESPK/OpenSC trong `TokenHelper --backend fastca`.
App chọn backend theo toàn bộ ATR profile đã test, đọc catalog để ghép chứng thư
với khóa RSA theo CKA_ID và public key, rồi dùng approval/PIN hiện có. Không dùng
`libcastle`, không cần Windows hoặc shim vendor cho FastCA. Các CA khác giữ PKCS#11.

## Môi trường và mở app

Máy này đã có OpenSC 0.27.1. Backend nạp động `libopensc.13.dylib` từ
`/opt/homebrew/lib`, `/usr/local/lib` hoặc `/Library/OpenSC/lib`. Do OpenSC có
struct ABI theo phiên bản, backend yêu cầu đúng 0.27.1 và báo lỗi rõ nếu thiếu
hoặc khác phiên bản. Header upstream/LGPL được lưu trong `Sources/CFastCA/vendor`;
không cần tải SDK header để build. Gói app thử hiện nhúng runtime ở
`Contents/Frameworks/ESPK` và ưu tiên nạp runtime đó trước các đường dẫn hệ thống.

```sh
./scripts/test-env.sh setup-fastca  # kiểm tra runtime; không cài hay copy module
./scripts/test-env.sh test-core
./scripts/package-test-app.sh      # đóng app cũ trước; đóng gói build có sẵn
```

Mở `.local/test-env/TokenSigner.app`, bấm biểu tượng chìa khóa trên menu bar.
FastCA phải hiện chứng thư, ngày hết hạn và nút “Ký thử”. Nếu có lỗi đọc/runtime,
menu hiện lỗi thay vì hiển thị một token trống. Khởi động lại app sau khi bổ sung
runtime, hoặc rút/cắm token để quét lại. Đây là bản local ký ad-hoc để test trên
máy phát triển; chưa phải gói phân phối/notarization.

## Đường ký

1. Reader + ATR phải khớp đúng profile FastCA đã xác minh.
2. Helper đọc `6F01`, tìm logical `cardid`, `pkcs11/cert*`, `pkcs11/prvk*`.
   FID chứng thư/metadata và key reference được lấy từ catalog/attributes;
   không dùng FID hoặc thumbprint cố định của harness cũ.
3. Chỉ chọn key có CKA_SIGN, RSA 2048/exponent 65537, CKA_ID không mơ hồ và public
   key khớp chứng thư. Không đọc hoặc xuất private key EF.
4. User duyệt yêu cầu và nhập PIN trong cửa sổ app. PIN chỉ đi qua stdin pipe.
   Một authentication, một signature; không tự thử lại. Chưa có truy vấn bộ đếm
   retry đã xác minh, nên PIN sheet nói rõ chưa biết số lần còn lại.
5. Host tạo DigestInfo/PKCS#1 v1.5; helper chọn key bằng MSE và ký PSO. Helper
   verify chữ ký bằng chứng thư đang đọc; app verify lần nữa bằng chứng thư đã
   được user duyệt trước khi trả chữ ký cho menu/bridge. Session được reset khi
   kết thúc hoặc lỗi sau authentication.

Luồng CTSigningHub SignHash cũng đi qua backend này: digest đã dựng sẵn được bọc
DigestInfo một lần, không hash lại. Thử portal/nghiệp vụ cần kiểm tra riêng; chứng
thư mẫu ngày 22/10 hết hạn 30/07/2026; chiếc FastCA khác đọc ngày 23/10 còn hạn
đến 06/08/2028. Verify RSA không kiểm tra chain/revocation.

## Phạm vi

Profile hiện hỗ trợ hai ATR FastCA ESPK đã đo:

- `3b9f958131fe9f006646530510523971df000069000011` — mẫu đã ký native ngày 22/10.
- `3b9f958131fe9f006646530510063171df00006900004d` — mẫu ngày 23/10: catalog 1500
  byte, 9 logical files; chứng thư FastCA/RSA 2048, CKA_ID và public key khớp key
  metadata. Đọc metadata này không gửi xác thực PIN hoặc ký.

RSA 2048 và PIN ASCII 1–64 byte.
ATR khác, key khác loại/kích thước và RSA_X_509 bị từ chối rõ ràng. Không suy rộng
kết quả sang mọi mẫu FastCA. Module registry vẫn ghi “Thử nghiệm”.

Nguồn giao thức và bằng chứng native ban đầu:
[fastca-native-signing.md](re/fastca-native-signing.md).

## Kết quả trên máy ngày 22/10/2026

- Build đạt, 38 tests đạt (3 shim, 24 Core, 11 Bridges).
- Menu “Ký thử”: user xác nhận “Ký và xác minh OK”.
- GetCert trả đúng DER đã xác minh; SignHash local ký SHA-256 dựng sẵn, trả 256 byte.
  Helper/AppModel và OpenSSL đều verify đạt.
- [Validation](re/evidence/fastca-app-signing-validation.json) có message/signature,
  hash binary/source và phạm vi đo; không chứa PIN hoặc private key.

## Sửa nhận diện chiếc FastCA thứ hai — 23/10/2026

App báo “Chưa hỗ trợ” vì ATR chiếc đang cắm khác mẫu đầu ở historical bytes và
checksum, dù cùng customer byte `69`. Bộ lọc exact ATR được giữ lại và bổ sung
đúng mẫu mới ở registry, ESPK reader filter và C transport; không đổi sang wildcard
customer byte hoặc giả ATR. Mọi metadata/certificate/key vẫn phải qua preflight.

[Read-only validation](re/evidence/fastca-0631-readonly-validation.json) và source
probe/check lưu bằng chứng của chiếc mới. Chứng thư DER/raw metadata chỉ giữ local;
repo chỉ có hash và trạng thái, không có PIN hoặc private key.
