# NC-CA: bổ sung bản sửa APDU ký bị sót khi tích hợp

Báo lỗi 23/10/2026: sau khi nhập PIN trên Minvoice, helper trả `C_Sign rv=48`.
48 thập phân là `0x30 / CKR_DEVICE_ERROR` trong PKCS#11, xuất phát từ bước ký,
không phải mã lỗi PIN của `C_Login`. Mã này tự nó chưa xác định nguyên nhân phần
cứng; đối chiếu repo phát hiện một thiếu sót cụ thể trong bản app đang phân phối.

Bản sửa `fd3554f` ở nhánh P2 đã sửa và thử trên NC-CA, nhưng chưa nằm trong
`p1-token-core` hoặc `libTSShim.dylib` của gói app tích hợp. Shim chỉ sửa dạng
short Lc + extended Le; còn thiếu extended Lc + short Le trong lệnh PSO ký.

Dạng lệnh đã ghi nhận trong kiểm thử phần cứng P2:

```text
0C 2A 90 80 00 01 12 <274 byte dữ liệu SM> 20
→
0C 2A 90 80 00 01 12 <giữ nguyên dữ liệu SM> 00 20
```

DigestInfo host chỉ dài 51 byte, nhưng RSA padding và secure messaging vẫn tạo
lệnh truyền tới thẻ lớn hơn 255 byte. Vì vậy host-hash không thay thế bản sửa
định dạng APDU. Lần sửa này đưa đúng nhánh Le-fix của P2 vào shim, không đưa
command chaining hoặc các thử nghiệm P2 khác vào app.

## Kiểm tra

- Trước sửa: test đúng dạng APDU NC-CA và test bảo toàn dữ liệu đều thất bại.
  Kiểm tra `ts_reencode` ngay trong thư viện của gói app cũ cũng thất bại.
- Sau sửa: 70 tests đạt (7 shim, 24 Core, 30 Bridges, 9 App). Test xác nhận giữ
  nguyên header/SM/MAC, không sửa APDU extended hợp lệ, không sửa lệnh không SM,
  và từ chối buffer thiếu chỗ mà không ghi dữ liệu.
- `scripts/check-packaged-shim.py` gọi hàm thuần với dữ liệu giả ngay trong
  dylib đóng gói. `package-test-app.sh` chạy kiểm tra này sau codesign để chặn
  gói app bị thiếu một trong hai bản sửa length, kể cả source/tests đúng nhưng
  thư viện được copy là bản cũ. Kiểm tra không kết nối token hoặc dùng PIN.
- Xem [validation record](re/evidence/ncca-shim-fix-validation-2026-10-23.json).

Đợt này không tự đăng nhập token, tạo chữ ký hoặc gửi lại hóa đơn của người dùng.
Cần người dùng ký thử lại trên bản app đã cập nhật để xác nhận lỗi thực tế hết.
Nếu còn lỗi, cần xác định đúng CA/token và mã trả về mới; không tự thử lại PIN
hoặc kết luận mọi `CKR_DEVICE_ERROR` đều cùng nguyên nhân.

Tham chiếu mã lỗi: [OASIS PKCS#11](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.pdf).
