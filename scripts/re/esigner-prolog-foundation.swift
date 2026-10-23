import Foundation
import CryptoKit
let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<HSoThueDTu xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"><HSoKhaiThue id=\"ID_1\"><tenDVu>Thử tổng hợp</tenDVu></HSoKhaiThue><CKyDTu/></HSoThueDTu>"
let plain = Data(xml.utf8)
let cases: [(String, Data)] = [
 ("utf8",plain), ("utf8-bom",Data([0xef,0xbb,0xbf])+plain),
 ("double-bom",Data([0xef,0xbb,0xbf,0xef,0xbb,0xbf])+plain),
 ("base64-text",Data(plain.base64EncodedString().utf8)),
 ("json-envelope",try! JSONSerialization.data(withJSONObject:["data":plain.base64EncodedString()])),
 ("html",Data("<!DOCTYPE html><html><body>Test login</body></html>".utf8)),
 ("junk-prolog",Data("TEST_ONLY".utf8)+plain),
 ("utf16",xml.replacingOccurrences(of:"UTF-8",with:"UTF-16").data(using:.utf16)!)
]
var results:[[String:Any]]=[]
for (label, data) in cases {
 var row:[String:Any] = ["fixture":label,"bytes":data.count,"sha256":SHA256.hash(data:data).map {String(format:"%02x",$0)}.joined(),"utf8Decodable":String(data:data,encoding:.utf8) != nil]
 do {
  let doc = try XMLDocument(data:data,options:[.nodePreserveAll])
  row["foundationParse"] = doc.rootElement() != nil
  let output = doc.xmlData(options:[.nodePreserveAll])
  row["serializedBytes"] = output.count
  row["serializedUTF8"] = String(data:output,encoding:.utf8) != nil
  row["serializedBOM"] = output.starts(with:[0xef,0xbb,0xbf])
  row["serializedStartsXML"] = output.starts(with:Data("<?xml".utf8))
 } catch {row["foundationParse"] = false}
 results.append(row)
}
print(String(decoding:try! JSONSerialization.data(withJSONObject:results,options:[.sortedKeys,.prettyPrinted]),as:UTF8.self))
