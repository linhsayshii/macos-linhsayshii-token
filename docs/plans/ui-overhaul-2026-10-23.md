# Kế hoạch đại tu giao diện TokenSigner

Ngày: 23/10/2026. Phạm vi: **kế hoạch**, chưa thay giao diện hay khởi động lại app.

## Mục tiêu và vấn đề đã xác định

Thống nhất menu bar, chọn chứng thư, duyệt yêu cầu, nhập PIN, quyền trang web,
tiến trình và kết quả ký. Ưu tiên sửa panel tràn màn hình và vị trí mở menu trước
khi thay đổi hình thức.

Hai ảnh người dùng cung cấp cho thấy menu rất cao khi có bốn token và mở thêm
các mục. `MenuBarView.swift` hiện chứa toàn bộ nội dung trong `VStack`, chỉ đặt
`frame(width: 360)`, không giới hạn chiều cao hoặc có scroll ngoài. Các
`DisclosureGroup` tăng kích thước cửa sổ khi mở. Riêng lô Minvoice có scroll con;
token, quyền và lịch sử thì không. Đây là nguyên nhân xác định được của việc
nội dung có thể vượt chiều cao màn hình.

`TokenSignerApp.swift` dùng `MenuBarExtra(.window)`, để SwiftUI quản lý vị trí.
Chưa có chính sách kích thước theo màn hình chứa icon. Ảnh cho thấy panel thay
đổi vị trí giữa các trạng thái nhưng chưa đủ để kết luận lỗi tọa độ cụ thể:
cần tái hiện trên màn hình thật với display scaling và vị trí icon thực tế.
Giới hạn chiều cao sẽ loại bỏ một nguyên nhân khiến hệ thống phải dịch panel.

Ảnh bổ sung lúc 12:06 và phản hồi người dùng ghi nhận **kích thước cũ còn lưu
sau đóng/mở dropdown**: nền/chrome của panel có thể lớn hơn phần nội dung đang
vẽ, để dư vùng phía trên. Theo dõi thành lỗi riêng của đợt 1, gồm cả toggle mục
bên trong lẫn đóng/mở menu từ icon. Chưa kết luận do cache của SwiftUI/AppKit
trước khi đo content bounds và host frame thực tế; sửa riêng padding/VStack
không đủ để chứng minh đã hết lỗi.

`SigningPromptWindow.swift` dùng `fittingSize` rồi `center()`; picker rộng 460pt,
approval/origin 340pt, PIN 320pt. Chưa có khung thích ứng chiều cao chung. Theme
đã tập trung màu cơ bản nhưng spacing, button phụ, card, header/footer vẫn riêng
từng màn. Hiện app ép sáng ở cả SwiftUI và AppKit.

## Bố cục đích

Menu là bảng điều khiển nhanh, ba trang **Token / Kết nối / Lịch sử**. Không xếp
tất cả phần chi tiết thành một cột disclosure dài. Trang Token mở mặc định.

```text
┌────────────────────────────────────────┐
│ TokenSigner                 ● Sẵn sàng │  Header cố định
│ Token       Kết nối        Lịch sử     │  Điều hướng cố định
├────────────────────────────────────────┤
│ 4 token được kết nối                   │
│ ┌ EFY-CA                  Thử nghiệm ┐ │
│ │ Tên tổ chức                        │ │
│ │ Còn hạn đến 06/08/2027             │ │  Nội dung cuộn
│ │ Chi tiết                  Ký thử  │ │  Một vùng cuộn
│ └────────────────────────────────────┘ │
│ …                                     │
├────────────────────────────────────────┤
│ ✓ Ký và xác minh thành công            │  Trạng thái cố định
│ [       Chọn CKS và ký thử…          ] │
│                                  Thoát│
└────────────────────────────────────────┘
```

Thông số khởi điểm, đo lại bằng prototype: menu rộng 380pt, cao mong muốn 560pt;
dialog rộng 460pt. Kích thước thực luôn nhỏ hơn vùng khả dụng của màn hình.
Trong phiên mở menu, mở chi tiết hoặc dữ liệu mới không làm đổi chiều cao vỏ
panel. Header, điều hướng và hành động cuối luôn nhìn thấy; phần giữa nhận phần
chiều cao còn lại và cuộn. Không thêm cửa sổ dashboard lớn trong đợt này.

- **Token:** card gọn có tên CA, tên tổ chức, hạn và trạng thái. Serial đầy đủ,
  subject gốc, reader và lỗi kỹ thuật chuyển vào chi tiết, có copy. Cần phân biệt
  serial token và serial chứng thư. Tên tổ chức lấy từ dữ liệu chứng thư đã parse;
  display label không được thay đổi identity dùng để ký.
- **Kết nối:** tổng trạng thái sáu dịch vụ; mỗi dòng có trạng thái/cổng. Phần TLS
  localhost và danh sách trang đã cho phép nằm bên dưới trong cùng vùng cuộn.
- **Lịch sử:** thời gian theo múi giờ máy, nhãn kết quả tiếng Việt, CA/bridge khi
  có dữ liệu hiện hữu. Mở chi tiết mới hiện timestamp chuẩn và mã kỹ thuật. Không
  thêm nội dung hóa đơn, PIN, cookie hay dữ liệu nhạy cảm vào audit.
- **Đang ký/lô Minvoice:** trạng thái và nút hủy dễ thấy trong vùng cố định.
  Danh sách nhóm nằm trong phần chi tiết cuộn, không có hai scroll lồng nhau.
  Giữ phân biệt đã ACK / chưa chạy / upload chưa rõ kết quả.

## Chiều cao, neo menu và nhiều màn hình

1. Tách chính sách layout khỏi view: đầu vào là rect của icon, vùng hiển thị
   màn hình chứa icon, kích thước mong muốn và phần chrome của popover. Tính bằng
   **point**, không lấy tọa độ pixel từ screenshot.
2. Giới hạn content theo phần không gian thực có dưới icon; chừa gap, lề dưới
   và phần chrome/arrow đo được. Không đặt `minHeight` vượt vùng khả dụng.
   Header/footer co giãn padding khi thấp, nội dung giữa cuộn.
3. Neo vào `NSStatusItem.button.bounds` qua API popover của AppKit. AppKit quyết
   định anchor và tránh mép; không lấy vị trí con trỏ để mở panel, không mặc định
   `NSScreen.main`, không cộng offset tọa độ hardcode. Gần mép, panel có thể lệch
   tâm icon để nằm trọn màn hình; đó là hành vi mong muốn.
4. Khi đổi màn hình, resolution/scaling, vị trí status item hoặc Spaces, tính
   lại vùng khả dụng và anchor. Không thêm lề notch hai lần nếu visible frame đã
   loại phần menu bar. Kiểm tra riêng menu bar tự ẩn và Dock ở các cạnh.
5. Dùng `NSStatusItem` + `NSPopover` có controller nhỏ nếu MenuBarExtra vẫn dịch
   sai sau bản sửa giới hạn chiều cao. Đây là hướng đích để kiểm soát anchor;
   bước chuyển host chỉ thực hiện sau fixture đo geometry, tránh thay host và
   thay toàn bộ giao diện cùng một lượt. Dùng public API phù hợp macOS 14+;
   API mới hơn phải có availability guard, không introspect private window.
6. Giữ đúng **một AppModel** sống cùng app, UI dùng `ObservedObject`. Không để
   controller mới tạo model thứ hai hoặc phụ thuộc việc mở menu để start bridge.
   Cần kiểm tra dữ liệu cập nhật ngay khi panel đang mở, vì repo từng có lỗi này
   khi đổi ownership sang AppDelegate.
7. Khi mở menu, tính lại kích thước hợp lệ từ màn hình hiện tại và áp cho cả
   hosting view lẫn popover trước khi hiển thị/neo; không dùng lại frame cao nhất
   từng đo hoặc frame từ màn hình trước. Khi đóng/mở disclosure, chỉ thay nội
   dung vùng cuộn bên trong vỏ có chiều cao đã chọn, không để host tự lưu một
   kích thước khác. Theo dõi thay đổi screen/layout qua một controller và nguồn
   kích thước duy nhất, tránh vòng lặp intrinsic size → resize → intrinsic size.
   Không chữa bằng cách tạo lại AppModel, xóa trạng thái yêu cầu ký hoặc nới
   frame trong suốt che lên ứng dụng phía sau.

Không thay vị trí biểu tượng menubar do người dùng/macOS quản lý. Mục tiêu là
panel neo đúng icon, nằm trên đúng màn hình và không bị cắt.

## Bộ giao diện chung và popup ký

Tách token thiết kế trong `Theme.swift`: màu semantic, typography, spacing,
corner radius, border, focus ring và trạng thái disabled/hover/pressed. Điểm
khởi đầu: spacing 4/8/12/16/24pt, chữ nội dung 13pt, tiêu đề 17–20pt; tránh dùng
11pt cho thông tin chính. Màu xanh/đỏ/cam luôn đi cùng chữ hoặc biểu tượng.

Tạo bộ thành phần dùng lại: `AppCard`, `StatusBadge`, `SectionHeader`,
`AppPrimaryButton`, `AppSecondaryButton`, `InlineNotice`, `ResultBanner` và
`PromptContainer`. Không tạo framework hoặc dependency UI mới.

Các dialog dùng chung header/body/footer và độ rộng 460pt; body cuộn theo vùng
khả dụng, footer vẫn thấy trên màn hình thấp. Picker, duyệt và PIN thể hiện bước
hiện tại nhất quán. Quyền trang web là dialog độc lập, không gắn số bước ký.
NSOpenPanel vẫn là bảng chọn file native, đồng bộ tiêu đề và cách trình bày.

- Chủ thể đang ký, tên trang và hành động luôn rõ; không rút gọn hostname đến
  mức che mất đích xin quyền. Chuỗi dài wrap hoặc mở chi tiết, không đẩy nút ra
  khỏi panel.
- Tab/Shift-Tab, focus, Space/Return/Esc, VoiceOver và expanded/selected state
  phải đầy đủ. Return không được bỏ qua chọn chứng thư hay duyệt yêu cầu.
- Đóng menu không hủy một request ký. Chuyển sang popup ký thì thu menu để
  không che/chồng nội dung; đóng popup vẫn gọi đúng continuation hủy hiện có.
- Phân biệt **đã hủy** (trung tính), thành công, cảnh báo và lỗi. Hiện menu có
  thể ghi “Lỗi ký: Đã hủy…”; đổi presentation của kết quả, không đổi semantics
  callback cho portal. Không suy trạng thái bằng cách tìm chữ trong message.
- Menu và popup theo cùng appearance. Giai đoạn đầu giữ palette sáng hiện tại
  để tránh tái phát lỗi contrast; tiếp theo cung cấp palette sáng/tối semantic
  đồng bộ theo hệ thống, bỏ ép `.aqua`/`.light` cùng một lượt sau khi có snapshot
  cho cả hai. Không phối nền sáng với control kế thừa host tối.

## Các đợt triển khai

| Đợt | Việc và file chính | Điều kiện hoàn tất |
|---|---|---|
| 1 — Sửa tràn và giữ size cũ | `MenuBarView.swift`, layout policy mới; một scroll ngoài, chiều cao theo màn hình, footer cố định, đồng bộ host/content khi mở lại, bỏ scroll Minvoice lồng | Mở mọi chi tiết với 0/4/10 token không vượt màn hình; nút cuối luôn thấy; thu gọn/mở lại không dư nền hoặc dùng frame cũ |
| 2 — Neo ổn định | Fixture geometry; `MenuBarController.swift` mới nếu cần, `TokenSignerApp.swift`; status item/popover và lifecycle | Neo đúng màn hình ở mép trái/phải, không nhảy khi nội dung đổi; một model/sáu listener |
| 3 — Menu mới | `MenuBarView.swift`, `TokenCard.swift`, `ConnectionView.swift`, `HistoryView.swift`; state trình bày tách khỏi trạng thái ký | Ba trang, card gọn, chi tiết/copy, trạng thái và tiến trình thống nhất |
| 4 — Popup chung | `Theme.swift`, `Components/`, `PromptContainer.swift`, picker/approval/PIN/origin, `SigningPromptWindow.swift` | Cùng khung/spacing/button/focus, thích ứng màn hình; hủy/hotplug/busy vẫn đúng |
| 5 — Appearance và chốt | Palette sáng/tối, kết quả typed/local time; fixture, bundle và smoke | Đủ checklist bên dưới, mở app mới để người dùng kiểm tra hình thức |

Mỗi đợt có commit và bằng chứng riêng. Đợt 1 phải dùng được ngay, không chờ đại
tu xong mới sửa clipping. Giữ `Theme` wrapper cũ trong lúc chuyển dần thành phần;
không trộn thay đổi crypto, PIN/session policy, provider routing hoặc HTTP vào
commit UI. Toolchain hiện dùng Command Line Tools: dùng Published/ObservedObject
cho state trình bày, không đưa macro `@State` chưa được toolchain này hỗ trợ vào.

## Kiểm chứng và tiêu chí nghiệm thu

Tạo fixture tổng hợp, không dùng screenshot chứa thông tin doanh nghiệp làm
asset repo. Mỗi fixture có thể mở cả ba trang và mọi phần chi tiết để đo bounds.

| Nhóm | Tình huống phải kiểm tra |
|---|---|
| Nội dung | 0/1/4/10 token; tên/serial/origin dài; 0/5/50 audit rows; nhiều origin; mở mọi chi tiết |
| Màn hình | 1280×720, 1440×900, màn lớn; scaling khác nhau; nhiều màn với origin âm; icon gần hai mép; display tháo/cắm |
| Menubar | Tự ẩn; đổi vị trí icon; chuyển Spaces/full screen; mở/đóng bằng chuột và bàn phím |
| Layout | Đo toàn bộ outer panel nằm trong vùng khả dụng; header/footer và nút chính không bị clip; mở chi tiết không đổi vỏ panel; nội dung cuối cuộn tới được |
| Size cũ | Mở tất cả mục → thu gọn → đóng menu → mở lại, lặp 20 lần; lặp sau khi chuyển màn hình/scaling và tháo token; host/content bounds nhất quán, không dư vùng trong suốt/trắng phía trên/dưới, không giữ frame lớn nhất từng có |
| Signing | Request tự mở picker khi chưa bấm menu; chọn/duyệt/PIN, hủy tại mỗi bước, token rút khi chọn, concurrent/busy, tiến trình/hủy lô Minvoice |
| Appearance | Sáng/tối, host khác appearance, Increase Contrast/Reduce Motion, focus/hover/disabled; VoiceOver đọc đúng trạng thái |

Geometry unit tests dùng input rect tổng hợp; layout snapshots cần assert bounds
và reachability ngoài so ảnh. Anchor thật vẫn phải thử qua UI/AppKit: render ảnh
tĩnh không chứng minh được vị trí menubar, Spaces hay nhiều màn hình.

Chạy AppTests liên quan sau từng phần; full suite hiện **163 tests** ở mốc EFY,
native ESPK regression khi cần, package strict codesign và smoke sáu cổng ở cuối.
Không nhập PIN thật, ký hóa đơn hoặc upload hồ sơ để kiểm tra layout. Khi thay
bundle chỉ đóng app lúc không có thao tác token đang chạy.

Hoàn tất khi: toàn bộ bề mặt app dùng cùng bộ thành phần; không còn clipping ở
ma trận đã nêu; menu neo đúng icon/màn hình và giữ vị trí khi mở chi tiết; dữ liệu
cập nhật trực tiếp; mọi luồng chọn/duyệt/PIN/hủy giữ đúng hành vi hiện hữu.
