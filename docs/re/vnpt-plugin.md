# VNPT-CA Plugin (macOS) — RE notes

Target: `VNPT-CA Plugin.app` v1.0.1.2, bundle id `com.vnpt.ca.server`, from `VNPT-CA Plugin_1.0.1.2.pkg`
(two sub-pkgs: `com.vnptsoftware.pkg.VNPT-CAPlugin` → `/Applications`, `...Config` → `/`).
Purpose: interoperability research for a native Swift all-in-one signing tool. **Static analysis only** (pkg
expanded, Payload cpio-unpacked, JAR disassembled with `javap`; nothing installed or run).
This is the **local signing bridge** web portals call (Cổng DVC quốc gia etc.) — distinct from `VNPT-CA Token Manager`.
No large verbatim code copied. Paths relative to the app `Contents/` or the Config payload unless noted.

---

## 1. Architecture / tech

### Observed
- **Java 8 app**, not native/Electron/.NET. Bundles Oracle **JRE 1.8.0_141** (`Contents/PlugIns/Java.runtime`).
  Native launcher `Contents/MacOS/VNPT-CA Plugin` + `libpackager.dylib` (javapackager). Single fat jar
  `Contents/Java/VNPT-CA Plugin.jar` (17 MB), main class **`com.vnpt.ca.server.EventServer`** (`...cfg`, MANIFEST).
- `Info.plist`: `LSUIElement=1`, `LSBackgroundOnly=1` → headless background agent, minOS 10.7.4. Ad-hoc, not notarized.
- Libraries in the jar: **Jetty** (embedded server + WebSocket), **BouncyCastle** (CMS/TLS), **iText/lowagie**
  (PDF), JSR-105 `org.jcp.xml.dsig` + Xalan/Xerces (XML-DSig), **Gson** (JSON), log4j. Also a large chunk of
  **SignServer/CESeCore/EJBCA** classes (`org.cesecore.*`, `CryptoTokenHelper`) — the PKCS#11 plumbing is lifted from SignServer.
- Token access: standard **`sun.security.pkcs11.SunPKCS11`** provider (strings `PKCS11`, `pkcs11-`, SunPKCS11 config
  `library=…\nname=SmartCard\nslot=…`). **No CryptoTokenKit, no pkcs11js/JNA.**

### Inferred
- Version mismatch: pkg/app = **1.0.1.2**, but `EventSocket.APP_VERSION` reported over the wire = **"1.0.0.9"** (stale constant).

## 2. Install footprint

### Observed
- App → `/Applications/VNPT-CA Plugin.app`.
- **LaunchAgent** `com.vnpt.vnpt-ca_plugin` → `/Library/LaunchAgents/com.vnpt.vnpt-ca_plugin.plist`:
  `RunAtLoad`, `KeepAlive{SuccessfulExit=false}`, runs `open -a "/Applications/VNPT-CA Plugin.app"`.
- Config tree at **`/Library/VNPT-CA Plugin Config/`**: `app.properties`, `log4j.properties`,
  `defaultvalues.properties` (verbatim EJBCA/CESeCore defaults), NSS DBs `cert9.db`/`key4.db`, fonts (`times.ttf`,
  Lao font), `Language/{en,vi,lao}.lg`, `Certificate/{localhost.jks, localhost.cer}`, and `CA/` with 9 CA certs.
- **TLS trust install at runtime** (not via pkg script — pkgs have **no** pre/postinstall). `Configuration` runs via
  `/bin/bash -c`: `security add-trusted-cert -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" <localhost.cer>`
  → adds the server cert as a **trusted root in the user login keychain**. Also configures **Firefox** (NSS `cert9.db`/
  `key4.db` via `certutil`-style flow), **Chrome/Safari** (`KeychainStore`); kills running browsers (`killall -9`).
- `localhost.cer` = **self-signed `CN=VNPT-CA`** (issuer=subject), valid 2017-10-31 → **2050-10-31**, **no SAN**.
  Keystore `localhost.jks`, keystore + keymanager password (redacted — hardcoded string literal in `EventServer.main`) (hardcoded in `EventServer.main`).
- **PKCS#11 module**: does **NOT** bundle a p11 library. `CryptoTokenHelper` probes
  `PKCS11_PROVIDER_LIST` (≈70 names, all Vietnamese CA + token middlewares) and on macOS resolves each to
  **`/usr/local/lib/lib<name>.dylib`** (strings `/usr/local/lib`, `lib`, `.dylib`), building `provider_found_list`.
  `app.properties provider_list=vnptca_p11_v8,vnptca_p11_v10`. So it depends on `/usr/local/lib/libvnptca_p11_v8.dylib`
  (and others) being installed separately by the vendor token drivers.

### Inferred
- `ServerConnector` has no `setHost` → binds **0.0.0.0:4433**, not loopback-only (reachable from LAN).
- A browser trusts `https://localhost:4433` only because the root is added to keychain/NSS; the cert has no
  `localhost` SAN, so modern browsers may still warn on hostname — unverified.

## 3. LOCAL API (most important)

### Observed
- **Transport: WebSocket over Jetty.** `EventServer.main` = HTTPS on **port 4433** (SslContextFactory ⇐ `localhost.jks`,
  pw redacted; logs "Implement ssl two way"). `EventServer.main_nossl` = plain HTTP :4433 (dev path). Servlet
  **`EventServlet extends WebSocketServlet`** mapped at **`/plugin/*`**, websocket name `ws-events`, context `/`.
  → client connects `wss://localhost:4433/plugin/...`. Only **port 4433** appears in this build (hinted 4434/4435/9201/9202 absent).
- **Request** = JSON parsed by Gson → `com.vnpt.ca.common.Connector`:
  `{ "functionID": int, "funcCallback": string, "args": string[] }` (`functionID` = ordinal in FUNCTION_ID list below).
- **Response** = Gson of `com.vnpt.ca.common.DataResult` →
  `{ "code": int, "data": string, "error": string }` (field format confirmed `"code":%d, "data":"%s", "error":"%s"`).
  For sign ops **`code` = ordinal of `SIGNING_RESULT`**: 0 sigSuccess, 1 sigBadInput, 2 sigBadKey, 3 sigSigningFailed,
  4 sigNotFoundPrvKey, 5 sigUnknow, 6 sigMultiplePagesNotfound, 7 sigPDFPageNumberNotAllow, 8 sigXmlNotFoundTagName,
  9 sigXmlCantRefID, 10 sigDataIncludeSigInvalid, 11 sigUserCancel, 12 sigInternalError, 13 sigInvalidAlgorithm.
  `data` = base64 signed result; `error` = human message ("Bad input", "Not found certificate", "Private key not exists",
  "Signing failed", "The action was cancelled by the user", …). `EventSocket.sendMessageToBrowser` echoes `funcCallback`.
- **FUNCTION_ID enum (ordinal → op):** 0 GetCertInfo, 1 SignXML, 2 SignPDF, 3 SignOFFICE, 4 SignCMS, 5 ChooseFile,
  6 SetLicenseKey, 7 CheckPlugin, 8 signArrData, 9 signHash, 10 signArrDataAdvanced, 11 getVersion,
  12 SignPDFMultiplePages, 13 checkPluginAdvanced, 14 ValidateCertificate, 15 ValidateCertificateBase64,
  16 CheckValidTime, 17 CheckValidTimeBase64, 18 CheckOCSP, 19 CheckOCSPBase64, 20 ShowCertificateViewer,
  21 CheckCRL, 22 CheckCRLBase64, 23 SetLanguage, 24 Scan, 25 OpenDocument, 26 BatchScan, 27 HandleFile,
  28 DeleteFile, 29 SetIgnoreListFiles, 30 GetAllFiles, 31 GetFilePreview, 32 UploadFile, 33 GetDataScanned,
  34 CheckToken, 35 SetGetCertFromUsbToken, 36 SetGetCertByPkcs11, 37 SetShowCertListDialog, 38 ConvertWordToPdf.
- **Origin / CORS**: `onWebSocketConnect` parses the WS `Origin` header (split on ":") into `_domainConnect` /
  `_domainWithoutHttp`. No `Access-Control-Allow-Origin` allowlist on the HTTP side observed; gating is via the license (below).
- **License/domain gate**: in `onWebSocketText`, every function **except** `CheckPlugin`, `SetLicenseKey`, `getVersion`,
  `checkPluginAdvanced` requires the connecting domain to be in `EventServer.DomainLicenseChecked`; otherwise returns
  `"License not set for: <domain>"`. The portal first calls **SetLicenseKey** (FUNCTION_ID 6) with an XML license blob.

### Example messages (reconstructed; verify at runtime)
- **CheckPlugin / getVersion** (no license): req `{"functionID":7,"funcCallback":"cb","args":[]}` →
  `{"code":0,"data":"1.0.0.9","error":""}` (getVersion returns `Utils.getAppVersion`).
- **GetCertInfo** (0): `{"functionID":0,"funcCallback":"cb","args":[]}` → pops the native cert-chooser UI
  (`CertificateChooser`), returns selected cert info JSON (serial/subject/issuer/validity/base64 — from
  `PKCS11CryptoToken.getAllCertificateInfo` / `CertificateInfo`). PIN entered in a Swing dialog, never over the wire.
- **signHash** (9): `args=[ base64Hash, ObjData ]` where `ObjData={data,type,sigOptions}`, `sigOptions` → `SignatureOption
  {digestMethod, signatureMethod, certificateSerial, SigningTime}`. `Cms.signHash` = **raw RSA** `RSA/ECB/PKCS1Padding`
  over the supplied digest (default SHA256). → `{"code":0,"data":"<b64 signature>","error":""}`.
- **SignCMS** (4) vs **signArrData** (8): both call `EventProcessing.signCms(conn, FUNCTION_ID)`; the FUNCTION_ID
  distinguishes attached vs detached (`Cms.sign`, BouncyCastle `BC`, `adbe.pkcs7.detached` style). `args` carry base64 data + sigOptions.
- **SignXML** (1): `args=[ xmlBase64, XmlSignatureOption ]` → `{code,data=<signed xml b64>,error}`.
- **SignPDF** (2) / **SignPDFMultiplePages** (12): `args=[ pdfBase64, PdfSigJSOption ]`.

## 4. Signing formats / algorithms

### Observed
- **CMS/PKCS#7** (`com.vnpt.ca.signature.Cms`, BouncyCastle): attached + detached; default digest **SHA256**
  (also SHA1 OID `1.3.14.3.2.26`). `signHash` = PKCS#1 v1.5 raw-hash signing (`RSA/ECB/PKCS1Padding`).
- **PDF** (`Pdf`, iText/lowagie): PAdES-style `adbe.pkcs7.detached`; **visible signature** via `PdfSigJSOption`
  (ImageBase64/background, position llx/lly/urx/ury, page/`PagesArray`, Signer/Reason/Description/SigningTime,
  color/text size, document-number & send-date stamps, encrypt-output option). TSA fields client-supplied
  (`TsaUrl`/`TsaUsername`/`TsaPassword`); CRL embedding present ("…signature size contribution for CRL"). `DigestAlgrothim` selectable.
- **XML-DSig** (`Xml`, JSR-105 `XMLDSigRI`): enveloped signature, C14N `REC-xml-c14n-20010315`, default `rsa-sha1`/`sha1`;
  `XmlSignatureOption` exposes ParrentTagSigning/TagSigning/NodeToSign/TagSaveResult/NameXPathFilter/NameIDTimeSignature/
  DsSignature/SigningType → supports enveloped + XAdES-like node targeting. **Office** signing via `Office`/`VerifyOffice`.
- Cert validation/revocation built in: `CheckOCSP`, `CheckCRL`, `ValidateCertificate`, `CheckValidTime` (+Base64 variants),
  classes `OCSPConnection`/`CRLConnection`/`ValidateCertificate`.

### Unknown
- Whether PAdES-LTV/CAdES-A levels are produced; exact default when `DigestAlgrothim` omitted (SHA1 vs SHA256) — not traced into iText calls.
- Built-in TSA/OCSP URLs: none hardcoded in signer; OCSP/CRL URLs taken from the cert's AIA/CDP. (Not runtime-verified.)

## 5. Cert selection / PIN / multi-token

### Observed
- `CertificateChooser` (Swing) lists certs across slots; `PINVerification` dialog collects the PIN locally;
  `SystemTrayEvent` shows the tray/notification. **PIN never crosses the WebSocket.** `max_slot=5` (`MAX_SLOT`).
- `CertificateHandle` holds PIN/provider/slot; errors `CKR_PIN_INCORRECT`, `CKR_PIN_LOCKED`; default test PIN string `12345678` present.
- `SetGetCertByPkcs11` / `SetGetCertFromUsbToken` / `SetShowCertListDialog` toggle selection mode.

## 6. Token/CA filtering

### Observed
- **Not VNPT-only.** `CryptoTokenHelper.PKCS11_PROVIDER_LIST` enumerates ~70 provider libs across VNPT, Bkav, Viettel,
  FPT, NCA/NEWTEL, CA2, Vina-CA, SAFE-CA, SmartSign/CK, plus generic middleware (eToken/`etpkcs11`, Feitian
  `ShuttleCsp11_3003`, `ngp11v211`, `gclib`, `st3csp11`…). Any token whose `/usr/local/lib/lib<name>.dylib` exists is used.
- Trusted-CA set = `CA/config.properties` (9 CA certs: VNPT, Bkav, SmartSign, CA2, SAFE-CA, FPT, NEWTEL, Viettel, MIC
  root thumbprint `42843bc401476cda242034b945bbf409a6bdd5c7`). `verify/config.properties` has stale Windows `C:\…` paths.

## 7. Network endpoints

### Observed
- **Update**: `app.properties update_url=http://kyso.vnpt-ca.vn/`. `Updater` calls
  `…/api/pluginversion/checkupdatemacos?currentVersion=<v>` then `…/api/pluginversion/getupdatepackage?url=<…>`,
  downloads to `/Library/VNPT-CA Plugin Config/VNPT-CA Plugin.pkg` (`application/json`). **Note: plain HTTP.**
- **License** is local/offline: SetLicenseKey posts a signed XML license; `LicenseKey`/`XmlValidator` verify an XML-DSig
  (SHA-1 thumbprint of a fixed VNPT signer cert: `CertLicenseThumbprint`/`IssuerCA`/`SubjectCN`). License XML fields:
  `DonViDuocCap` (org), `NgayBatDau`/`NgayKetThuc` (valid from/to, `MM/dd/yyyy HH:mm:ss`), a **MacOS** platform flag, and a
  **hostname whitelist** (`checkValidHostName`). Errors: "The license not include MacOS", "license not correspond", expired.
- No analytics/telemetry endpoint observed.

### Inferred
- Portal flow: open `wss://localhost:4433/plugin/...` → SetLicenseKey(signed XML binding portal domain) →
  GetCertInfo → sign* . A clone must serve the same WebSocket + JSON schema and accept (or re-issue) the license, or
  bypass the license gate entirely in the Swift reimplementation.

---
## Open items / Unknown
- Exact byte layout of `args` per function (which index is data vs options) for Office/Scan/HandleFile/Upload ops — not fully traced.
- Whether SignCMS "attached vs detached" maps to FUNCTION_ID 4 vs 8 as inferred.
- Runtime: actual bound interface, TLS handshake behavior with the no-SAN cert, and whether two-way (client-cert) TLS is really enforced (log string only).
- `localhost.jks` private key / full license signer cert not extracted (secrets left in place).
