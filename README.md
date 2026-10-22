# TokenSigner cho macOS

Một app menu bar dùng USB token để phục vụ các cổng ký phổ biến. Nhánh hiện tại
là `p1-token-core`; tất cả nhánh tính năng đã được merge vào đây.

| Giao thức | Cổng loopback |
| --- | --- |
| CTSigningHub | HTTP 32001 |
| eSigner/eTax | WS 8768, 8769 |
| VNPT-CA/DVC | WSS 4433, 4434 |
| Minvoice | HTTP/SignalR 16080 |

Yêu cầu ký tự mở cửa sổ: chọn CKS → duyệt → nhập PIN. PIN chỉ đi qua stdin của
helper; không tự ký/retry. Có origin guard, kiểm tra chữ ký và nhật ký digest-only.
VNPT dùng chứng chỉ TLS localhost riêng; nếu máy chưa tin cậy, user chủ động
bấm nút trong menu “Kết nối và quyền”.

```sh
./scripts/test-env.sh test-all
./scripts/package-test-app.sh
python3 scripts/check-integrated-app.py
./scripts/run-test-app.sh all
```

Đóng app đang chạy trước khi đóng gói/smoke. Không cần chạy lại app theo từng
worktree. Gói local nằm ở `.local/test-env/TokenSigner.app`, ký ad-hoc.

- [Trạng thái và giới hạn](docs/PROGRESS.md)
- [Build/test](docs/BUILD.md)
- [Các bridge](docs/BRIDGES.md)
- [Đối chiếu tất cả nhánh, phần còn thiếu](docs/BRANCH-CONSOLIDATION.md)
- [FastCA/OpenSC runtime](docs/FASTCA.md)
- [Minvoice cash](docs/MINVOICE.md)

Minvoice hiện hỗ trợ cash TDiep đơn; PDF/Office, native messaging, mọi token/ATR,
notarization và một số protocol vendor chưa hoàn tất. Kết quả kiểm thử phần mềm
không thay thế kiểm thử portal/hồ sơ thật do người dùng tự thực hiện.

Ghi chú nghiên cứu được giữ trong `docs/re/`; trace/probe/log thô được giữ local,
không version hóa. Không tự chạy installer hoặc cài middleware hãng.
