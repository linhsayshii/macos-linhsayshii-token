import AppKit
import Foundation
import CryptoKit
import Security

// One user-approved local challenge, one login attempt. Never prints/stores PIN.
let root = URL(fileURLWithPath: "/Users/linhsayshii/macos-linhsayshii-token")
let output = root.appendingPathComponent(".local/oneca-windows/sign-test", isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
let helper = root.appendingPathComponent(".build/out/Products/Debug/TokenHelper")
let module = root.appendingPathComponent(".local/oneca-windows/mac-reference/prodigisign-arm64/mToken_CryptoID_Arm64.pkg/Payload/usr/local/lib/libcryptoida_pkcs11_f2.dylib")
func request(_ messages: [[String: Any]]) throws -> [[String: Any]] {
    let p=Process();p.executableURL=helper;p.arguments=["--backend","oneca","--module",module.path]
    var env=ProcessInfo.processInfo.environment;env.removeValue(forKey:"DYLD_INSERT_LIBRARIES");env.removeValue(forKey:"TSSHIM_LOG");p.environment=env
    let input=Pipe(),out=Pipe();p.standardInput=input;p.standardOutput=out;p.standardError=FileHandle.nullDevice
    try p.run()
    for m in messages {input.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject:m));input.fileHandleForWriting.write(Data([10]))}
    try input.fileHandleForWriting.close()
    let data=out.fileHandleForReading.readDataToEndOfFile();p.waitUntilExit()
    guard p.terminationStatus==0 else{throw NSError(domain:"OneCAHelper",code:Int(p.terminationStatus))}
    return try data.split(separator:10).map{try JSONSerialization.jsonObject(with:Data($0)) as! [String:Any]}
}
func save(_ value:[String:Any]) {try? JSONSerialization.data(withJSONObject:value,options:[.prettyPrinted,.sortedKeys]).write(to:output.appendingPathComponent("result.json"),options:.atomic)}
let app=NSApplication.shared;app.setActivationPolicy(.accessory)
func notice(_ message:String){let a=NSAlert();a.messageText="Kiểm tra OneCA trên Mac ARM";a.informativeText=message;a.addButton(withTitle:"Đóng");app.activate(ignoringOtherApps:true);a.runModal()}
do {
    let ts=try request([["listTokens":[:]]]);let values=(ts.first?["tokens"] as? [String:Any])?["_0"] as? [[String:Any]] ?? []
    guard values.count==1,let token=values.first,let serial=token["serial"] as? String else{throw NSError(domain:"Không tìm thấy đúng token OneCA",code:1)}
    let flags=token["flags"] as? [String] ?? []
    guard !flags.contains("USER_PIN_LOCKED"),!flags.contains("USER_PIN_FINAL_TRY") else{throw NSError(domain:"PIN đang khóa hoặc chỉ còn một lần thử",code:2)}
    let cs=try request([["listCerts":["serial":serial]]]);let certs=(cs.first?["certs"] as? [String:Any])?["_0"] as? [[String:Any]] ?? []
    guard certs.count==1,let cert=certs.first,let id=cert["id"] as? String,!id.isEmpty,let b64=cert["derB64"] as? String,let der=Data(base64Encoded:b64),let sc=SecCertificateCreateWithData(nil,der as CFData),let key=SecCertificateCopyKey(sc) else{throw NSError(domain:"Không có đúng một chứng thư hợp lệ",code:3)}
    let challenge=Data(("TokenSigner OneCA ARM64 local signing test\n"+UUID().uuidString+"\n").utf8)
    let digest=Data(SHA256.hash(data:challenge));let prefix=Data([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]);let payload=prefix+digest
    let a=NSAlert();a.messageText="Ký thử OneCA trên Mac ARM"
    a.informativeText="Token: \(serial)\nChứng thư: \(SecCertificateCopySubjectSummary(sc) as String? ?? "OneCA")\n\nChỉ ký một chuỗi kiểm tra ngẫu nhiên cục bộ, không ký tài liệu. Nhập PIN OneCA để thử đúng một lần; PIN chỉ truyền qua pipe trong bộ nhớ."
    let pin=NSSecureTextField(frame:NSRect(x:0,y:0,width:340,height:25));pin.placeholderString="PIN OneCA";a.accessoryView=pin
    a.addButton(withTitle:"Ký một lần");a.addButton(withTitle:"Hủy");app.activate(ignoringOtherApps:true);a.window.initialFirstResponder=pin
    guard a.runModal() == .alertFirstButtonReturn,!pin.stringValue.isEmpty else{save(["status":"cancelled","loginAttempted":false]);exit(0)}
    var credential=pin.stringValue;pin.stringValue=""
    let replies=try request([["login":["serial":serial,"pin":credential]],["sign":["serial":serial,"certId":id,"mech":"RSA_PKCS","dataB64":payload.base64EncodedString()]],["logout":["serial":serial]]]);credential=""
    guard let lr=replies.first?["loginResult"] as? [String:Any],lr["_0"] is [String:Any],let status=lr["_0"] as? [String:Any],status["ok"] != nil else{save(["status":"login_failed","replies":replies,"loginAttempts":1]);notice("Đăng nhập thất bại. Không thử lại tự động.");exit(1)}
    guard replies.count>1,let s=replies[1]["signature"] as? [String:Any],let sb=s["_0"] as? String,let sig=Data(base64Encoded:sb) else{save(["status":"sign_failed","replies":replies,"loginAttempts":1]);notice("Token chưa trả chữ ký. Kết quả lỗi đã lưu cục bộ.");exit(1)}
    var error:Unmanaged<CFError>?
    let verified=SecKeyVerifySignature(key,.rsaSignatureMessagePKCS1v15SHA256,challenge as CFData,sig as CFData,&error)
    try challenge.write(to:output.appendingPathComponent("message.bin"));try sig.write(to:output.appendingPathComponent("signature.bin"));try der.write(to:output.appendingPathComponent("certificate.der"))
    save(["status":verified ? "verified":"verification_failed","architecture":"arm64","loginAttempts":1,"signatureBytes":sig.count,"messageSHA256":SHA256.hash(data:challenge).map{String(format:"%02x",$0)}.joined(),"certificateSHA256":SHA256.hash(data:der).map{String(format:"%02x",$0)}.joined()])
    notice(verified ? "Thành công: chữ ký RSA của OneCA đã được xác minh trên Mac ARM.":"Chữ ký trả về chưa khớp chứng thư.")
} catch {save(["status":"error","message":String(describing:error)]);notice("Không hoàn tất kiểm tra: \(error)");exit(1)}
