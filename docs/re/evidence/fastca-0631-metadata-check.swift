import Foundation
import CryptoKit
import Security
@main struct Validate {
 static func main() throws {
  let root=URL(fileURLWithPath:CommandLine.arguments[1]);let catalog=try Data(contentsOf:root.appendingPathComponent("catalog.bin"));let files=try ESPKCatalog.parse(catalog)
  func load(_ file:ESPKFile)throws->ESPKAttributes {try ESPKAttributes(data:Data(contentsOf:root.appendingPathComponent(String(format:"%04x.bin",file.id))))}
  let certificates=try files.filter{$0.directory=="pkcs11" && $0.name.hasPrefix("cert")}.map(load)
  let keys=try files.filter{$0.directory=="pkcs11" && $0.name.hasPrefix("prvk")}.map(load)
  let identities=try ESPKSigningIdentity.resolve(certificates:certificates,keys:keys)
  guard !identities.isEmpty,identities.allSatisfy(RSAPKCS1v15.certificateMatches)else{throw ESPKMetadataError.invalidAttribute}
  for (i,identity) in identities.enumerated(){try identity.certificateDER.write(to:root.appendingPathComponent("certificate-\(i).der"))}
  func hex(_ value:some Sequence<UInt8>)->String{value.map{String(format:"%02x",$0)}.joined()}
  let record:[String:Any]=["date":"2026-10-23","atr":"3b9f958131fe9f006646530510063171df00006900004d","reader":"FT ePass2003Auto 01","driver":"epass2003","catalogBytes":catalog.count,"logicalFiles":files.count,"identities":identities.map{["certificateSHA256":hex(SHA256.hash(data:$0.certificateDER)),"DERBytes":$0.certificateDER.count,"CKA_ID_SHA256":hex(SHA256.hash(data:$0.id)),"keyReference":String(format:"%04X",$0.keyReference),"modulusBytes":$0.modulus.count,"certificatePublicKeyMatchesMetadata":true]},"authenticationAttempts":0,"signaturesCreated":0]
  let json=try JSONSerialization.data(withJSONObject:record,options:[.prettyPrinted,.sortedKeys]);try json.write(to:root.appendingPathComponent("metadata-validation.json"));print(String(decoding:json,as:UTF8.self))
 }
}
