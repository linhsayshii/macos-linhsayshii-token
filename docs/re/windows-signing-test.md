# FastCA và NC-CA: ký thật trên Windows ARM — 2026-10-22

**Cả hai token ký thành công và chữ ký đã được verify độc lập trên macOS.**
User bấm từng nút test và tự nhập PIN trong dialog của CSP vendor. Agent không
nhận PIN. Chỉ ký chuỗi test ngẫu nhiên cục bộ, không ký hóa đơn hoặc hợp đồng.

## Môi trường và kết quả

- Parallels VM `Windows 11 LTSC`, Windows ARM64, Guest Tools đã có sẵn.
- Hai USB được passthrough thật vào Windows; `SCardSvr` chạy và hai reader dùng
  `Microsoft Usbccid Smartcard Reader (WUDF)`, PnP status OK.
- Reader `FT ePass2003Auto 0`: ATR customer byte `0x59`, NC-CA.
- Reader `FT ePass2003Auto 1`: ATR customer byte `0x69`, FastCA.
- Token Manager/CSP đã được cài từ trước. Lượt này không chạy installer, thay
  driver, sửa trust store, đổi execution policy hoặc đổi cấu hình bảo mật VM.
- Các probe và UI do analyst viết được compile bằng .NET Framework `csc.exe`
  sẵn có, `/platform:x86`, chạy trong phiên user Windows hiện tại.

| Kiểm tra | FastCA | NC-CA |
|---|---|---|
| DLL x86 | `C:\Windows\SysWOW64\fca_v1.dll` | `C:\Windows\SysWOW64\ncca_csp11_v1.dll` |
| Authenticode theo Windows | Valid, CYBERLOTUS | Valid, MOBILE-ID |
| PKCS#11 Initialize / GetSlotList / GetTokenInfo | 0 / 0 / 0; đúng 1 token | 0 / 0 / 0; đúng 1 token |
| CSP dùng để ký | FastCA CSP 1.0 | NC-CA Token CSP v1.0 |
| Phép ký | SHA-256 / RSA PKCS#1 v1.5 | SHA-256 / RSA PKCS#1 v1.5 |
| Chữ ký | 256 byte | 256 byte |
| Verify bằng public key trong Windows | PASS | PASS |
| Verify độc lập bằng OpenSSL trên macOS | Verified OK, exit 0 | Verified OK, exit 0 |
| Chứng thư tại thời điểm test | Hết hạn 30/07/2026 | Còn hạn đến 17/03/2029 |

## Công cụ và bằng chứng

- [TokenMetadata.cs](evidence/windows-token-probe/TokenMetadata.cs): PC/SC ATR và
  PKCS#11 metadata; không có login/sign/PIN. Reader numbering chỉ đúng lần đo.
- [TokenSignerWindowsTest.cs](evidence/windows-token-probe/TokenSignerWindowsTest.cs):
  UI test cục bộ, ghim đúng hai certificate thumbprint của phiên này. Mỗi nút
  thực hiện tối đa một lần; user bấm mới gọi CSP và không tự retry khi lỗi.
  CSP xử lý dialog PIN. Không export private key.
- [windows-signing-validation.json](evidence/windows-signing-validation.json):
  kết quả, certificate thumbprint, SHA-256 của message/signature/certificate và
  kết quả OpenSSL. Đây là record đo local, không phải REA Evidence ID.

DLL x86 đã dùng:

```text
fca_v1.dll       d2c52982f4799b53b308e306a0c22f6cf59ea27d62c8f57ee6199d7f17ddacf3
ncca_csp11_v1.dll 986b0e861ec27a8ee8bd0008dac87a03c6f5e898fa492085d7ac6c866a00aa90
```

UI nằm tại `%LOCALAPPDATA%\TokenSignerTest\TokenSignerWindowsTest.exe`.
Kết quả trong `%LOCALAPPDATA%\TokenSignerTest\results\`, mỗi lần ký có
`message.bin`, `signature.bin`, `certificate.der`, `result.json`. Bản sao local
để verify ở repo `.local/windows-test/results/` và Downloads
`TokenSigner-Windows-Test/results/`; không đưa certificate DER vào Git.

Phép verify độc lập sử dụng public key lấy từ DER và:

```sh
openssl dgst -sha256 -verify public.pem -signature signature.bin message.bin
```

Không kiểm tra chain/revocation hoặc cổng nghiệp vụ. Chữ ký RSA đúng không làm
chứng thư FastCA hết hạn trở lại hợp lệ. Kết quả Windows chưa giải quyết lỗi
catalog của candidate `libcastle` trên macOS; xem
[fastca-live-test.md](fastca-live-test.md).
