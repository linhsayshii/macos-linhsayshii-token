// Research fixture only. PIN stays in a secure local field / anonymous pipe.
import AppKit
import Foundation
import Darwin

disableCoreDumps()
func disableCoreDumps() { var limit = rlimit(rlim_cur: 0, rlim_max: 0); _ = setrlimit(RLIMIT_CORE, &limit) }
let root = "/Users/linhsayshii/macos-linhsayshii-token/.local/efy-ca-windows/pin"
let helper = root + "/efy-auth-arm64"
let resultURL = URL(fileURLWithPath: root + "/auth-result.log")
let app = NSApplication.shared
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
func runProbe(preflight: Bool, input: inout Data) throws -> (Int32, Data) {
 let p = Process(); p.executableURL = URL(fileURLWithPath: helper)
 p.arguments = preflight ? ["--preflight"] : []
 // No inherited logger, injection variables or custom OpenSC configuration.
 p.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(), "OPENSC_DEBUG": "0"]
 let stdin = Pipe(), stdout = Pipe()
 p.standardInput = stdin; p.standardOutput = stdout; p.standardError = FileHandle.nullDevice
 try p.run()
 if !preflight { stdin.fileHandleForWriting.write(input) }
 input.resetBytes(in: 0..<input.count); input.removeAll(keepingCapacity: false)
 try stdin.fileHandleForWriting.close()
 let output = stdout.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
 return (p.terminationStatus, output)
}
func save(_ data: Data) throws {
 try data.write(to: resultURL, options: .atomic)
 try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: resultURL.path)
}
func report(_ title: String, _ detail: String) {
 let a = NSAlert(); a.messageText = title; a.informativeText = detail
 a.addButton(withTitle: "Đóng"); a.runModal()
}
do {
 var empty = Data()
 let (status, preflight) = try runProbe(preflight: true, input: &empty)
 guard status == 0 else {
  try save(preflight); report("Chưa thể thử PIN EFY", String(decoding: preflight, as: UTF8.self)); exit(1)
 }
 let alert = NSAlert()
 alert.messageText = "Thử PIN EFY trực tiếp trên Mac ARM64"
 alert.informativeText = "Đã kiểm tra đúng token EFY và chứng thư. Nhập PIN EFY tại đây. Chỉ xác thực 1 lần, không tự thử lại; chưa ký tài liệu. PIN chuyển qua pipe đến helper cục bộ, không ghi vào log. Phiên được reset sau lần xác thực."
 alert.addButton(withTitle: "Xác thực 1 lần"); alert.addButton(withTitle: "Hủy")
 let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 360, height: 28))
 field.placeholderString = "PIN EFY-CA"; alert.accessoryView = field; alert.window.initialFirstResponder = field
 let response = alert.runModal()
 guard response == .alertFirstButtonReturn && !field.stringValue.isEmpty else {
  field.stringValue = ""; try save(Data("CANCEL user_auth_attempts=0; signatures=0\n".utf8)); exit(0)
 }
 var input = Data(field.stringValue.utf8); input.append(0x0a); field.stringValue = ""
 let (authStatus, output) = try runProbe(preflight: false, input: &input)
 try save(output)
 report(authStatus == 0 ? "Xác thực EFY ARM64 thành công" : "Phép thử EFY đã dừng", String(decoding: output, as: UTF8.self))
} catch {
 try? save(Data("STOP local prompt/helper error; no automatic retry\n".utf8))
 report("Không hoàn tất phép thử EFY", error.localizedDescription)
}
