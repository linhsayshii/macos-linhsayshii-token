# eSigner 1.1.0 — reverse-engineering notes (interop)

Target: `eSigner_1.1.0_setup.exe` (Inno Setup 6.3.0). Unpacked with innoextract HEAD
(release 1.9 cannot parse 6.3.0 headers). Payload = Java app. Evidence = innoextract
file list, config files, `javap`/string-constant analysis of `eSignerJava.jar` classes.
Tags: **[O]** observed in payload, **[I]** inferred, **[?]** unknown.

---

## 1. Vendor / CA, tech stack, components

- **[O] Vendor = SeaTech IT.** Packages `com.seatech.*` and `seatechit.ihtkk.*`;
  `proxy.properties` banner `### SEATECHIT ###`. Not a CA product.
- **[O] This is the signing plugin for Vietnam's General Department of Taxation
  (Tổng cục Thuế, `gdt.gov.vn`) eTax / iHTKK / eTaxNNT portals.** Chrome manifest is
  named `esigner.chrome.tct.gdt.gov.vn`; update URL and portal URLs are all
  `thuedientu.gdt.gov.vn`.
- **[O/I] CA-agnostic.** No single CA ships it; it is the tax authority's plugin and
  works with every registered Vietnamese CA's USB token via that token's PKCS#11 driver
  (see §3 DLL list) plus the Windows certificate store.
- **[O] Tech stack:** Java (GUI = SWT). Native launcher `eSigner.exe` runs
  `eSignerJava.jar` (Main-Class `com.seatech.signer.Main`). Key libs in
  `eSignerJava_lib/` (73 jars): **Tyrus** (JSR-356 WebSocket server+client) +
  **Grizzly**, **BouncyCastle 1.49** (`bcprov`/`bcpkix`), **iText 5.5.2** (PDF),
  **Apache xmlsec 1.4.3** + `xmldsig` + `xalan`/`serializer` (XML sig), **JNA 4.1.0**,
  `org.json`, `rxjava`, `tika-core`. Many `*Importer.jar` = tax-form importers.
- **[O] Installed components:** `app/eSigner.exe`, `app/eSignerJava.jar`,
  `app/eSignerJava_lib/*.jar`, `app/localhost.cer`, `app/proxy.properties`,
  `app/esigner.chrome.tct.gdt.gov.vn.json` (native-messaging manifest),
  `app/update/{updater.jar,update.xml,latest.xml,files.xml}` + `app/tmp/` copies,
  `icon48.ico`.
- **[O] Two front-door transports / autostart:**
  1. **Chrome/Edge Native Messaging host** — manifest `type:"stdio"`, `path:"eSigner.exe"`,
     `allowed_origins` = 5 extension IDs (`knldjmfmopnpolahpmmgbagdohdnhkik`,
     `ckjefchnfjhjfedoccjbhjpbncimppeg`, `eacnlhofpemkkcphjdpiiphglgpofjlj`,
     `ojkemejbppgnpppnjkdcfmdnfkhenphm`, `ekaaenaocpheoabajfdnkhiibfmfmloo`).
     Browser launches `eSigner.exe` on demand.
  2. **Local WebSocket server** (see §2), started when the app runs.
- **[?] No Windows service found.** Autostart is browser-driven native messaging (and/or
  a registry Run key set by the installer — not confirmed; full Inno script not parsed).

---

## 2. Local API (most important)

- **[O] Transport = WebSocket** (Tyrus `org.glassfish.tyrus.server.Server`), **plain `ws://`**.
  - **[O] Host bind = `0.0.0.0`** (all interfaces, not loopback-only).
  - **[O] Port = 8768**, **fallback 8769** (`WebSocketServer.defaultPort/backupPort`).
  - **[O] Context path = `/plugin`** → endpoint `ws://127.0.0.1:8768/plugin`.
  - **[O/I] No TLS.** `localhost.cer` (self-signed `CN=localhost`, expired 2023-09-08) is
    bundled but no `SSLContext`/`KeyManagerFactory` wiring exists in the seatech classes →
    inferred legacy/unused (older HTTPS-applet era). Serve plain `ws`.
- **[O] Second transport = Chrome Native Messaging** over stdio: `App.read()`/`readMessage()`
  with 4-byte length prefix + UTF-8 JSON (`App.getInt`/`getBytes`). Same JSON dispatch.
- **[O] CORS / origin allowlist:**
  - WebSocket endpoint (`WebSocketService`) has only `@OnOpen/@OnMessage/@OnClose/@OnError`
    — **no `ServerEndpointConfig.Configurator` / `checkOrigin`**. Tyrus default accepts any
    origin on the bound host → **any local (or LAN) web page can connect.**
  - Origin restriction exists **only** on the native-messaging path (the 5 extension IDs).
  - → For your macOS tool: listen on `ws://127.0.0.1:8768/plugin` (+8769), accept any origin.
- **[O] Dispatch:** one text frame = a JSON string → `WebSocketService.startSignProcess`
  → `App.navigationProcess(JSONObject)` → returns a JSON string reply.
- **[O] Request shape:** `{"CODE":"<cmd>", "INPUT":{...}}` (keys `CODE`, `INPUT`, plus
  flat params). **Response shape** (built by `MessageResponse(messageCode,isSuccess,json)`
  and `App.write`): `{"CODE":"<cmd>", "SUCCESS":"TRUE"|"FALSE", ...output fields}`.
  Some payloads also use `"RESULT":"SUCC"|"FAIL"`.
- **[O] Command codes (`CODE`):** `CHECK_VERSION`, `CER_CHECK_NTDT`,
  `CER_001` (sign declaration), `CER_002` (get cert info), `JFU_001/002/003`
  (choose / sign / upload file), `JFU_PLUC_001/002/003`, `NTDT_CER_001` (GNT sign),
  `NTDT_CER_002` (multi-sign), `IMP_001/002` (import tkhai/phuluc), `DWN_BKE_001`,
  `CHOOSE_FILE`, `OFFLINE_XML_SIGN_002/003`, `OFFLINE_SIGN_002/003`,
  `ONLINE_XML_CER_001/002`, `ONLINE_SUBMIT_SIGNING_001/002`.
- **[O] INPUT params:** `PKCS_11_LIBRARY_NAME_LIST`, `SERIAL_NUMBER`, `ACTIVE_CERT_SERIAL`,
  `CHECK_CERT_SERIAL`, `PIN_CODE`, `TIN`/`CHECK_TIN`/`TIN_VALID`, `DATE_SIGNING`,
  `TIMEZONE_SIGNING`, `GDT_SIGN_PATH`, `BANK_SIGN_PATH`, `NTDT_SIGN_CODE`
  (`00`=GNT,`01`=register,`02`=addbank,`03`=stopbank,`04`=modifybank,`05`=multiple),
  `LOAI_HSO`, `ROOT_URL`, `VALUE`/`BASE64_VALUE`; upload set: `URL_FILE_NAME`,
  `UPLOADED_FILE_NAME`, `XPATH_DATA`, `XPATH_SIGN`, `REQUEST_URL_ACTION`, `CHUNKSIZE`,
  `COOKIE_NAME`, `COOKIE_VALUE`, `VALID_XML`, `CERT_CHAIN`, `SIGNATURE`.
- **[O] OUTPUT cert fields (`CER_002`):** `HEX_SERIAL`, `CERT_ISSUER`, `CERT_SUBJECT`,
  `NGAY_HHAN` (expiry), `NGAY_HLUC` (valid-from), `MST` (tax code); plus `CERT`,
  `CERT_CHAIN`, `SIGNED_CONTENT`, `STATUS`.

### Example (reconstructed from constants)
Request (get certificate):
```json
{"CODE":"CER_002","INPUT":{"PKCS_11_LIBRARY_NAME_LIST":"","CHECK_CERT_SERIAL":""}}
```
Response:
```json
{"CODE":"CER_002","SUCCESS":"TRUE","HEX_SERIAL":"54010A...","CERT_SUBJECT":"CN=...,
 MST=0101...","CERT_ISSUER":"CN=VNPT-CA","NGAY_HLUC":"...","NGAY_HHAN":"...",
 "CERT_CHAIN":"<base64>"}
```
Request (sign XML declaration): `{"CODE":"CER_001","INPUT":{"VALUE":"<base64 xml>",
"SERIAL_NUMBER":"...","PIN_CODE":"...","DATE_SIGNING":"...","TIMEZONE_SIGNING":"+07:00"}}`
→ `{"CODE":"CER_001","SUCCESS":"TRUE","SIGNED_CONTENT":"<base64 signed xml>"}`.

---

## 3. Signing

- **[O] Formats:**
  - **XML / XAdES-ish XMLDSig** (primary, for tax declarations) — `XMLSigner`,
    `XMLSignerForTCT` on Apache Santuario/xmlsec. Transforms: enveloped-signature,
    exclusive C14N (`xml-exc-c14n#`), xpath-filter2, xpath-19991116.
  - **PDF PAdES** — `seatechit.ihtkk...PDFSigner` on iText 5.5.2. Both
    `ADBE_PKCS7_DETACHED` (CMS/CAdES-basic) and `ETSI_CADES_DETACHED` (PAdES) sub-filters.
  - **CMS / CAdES** via BouncyCastle 1.49. **[?] Office (POI) — not found.**
- **[O] Hash / sig algos:** SHA-1 and SHA-256; signature `SHA1withRSA` (default
  `DIGITAL_SIGNATURE_ALGORITHM_NAME`) and SHA-256; `SHA1-SHA256` type switch
  (`SignatureConstant.TYPE_SHA`). XMLDSig uses `rsa-sha1` and `xmldsig-more#rsa-sha256`.
- **[O/?] TSA (timestamp):** `PDFSigner` wires iText `TSAClient` but **no TSA URL is
  hardcoded** → inferred normally null/disabled; signing time comes from `DATE_SIGNING` /
  `TIMEZONE_SIGNING` inputs and an XML `DateTimeStamp` property, not RFC-3161. [?] whether a
  TSA is supplied at runtime.
- **[O/?] OCSP / CRL:** verifier side has CRL support (`crlMap`, `X509CRL`) and `PdfPKCS7`
  parses embedded OCSP (`BasicOCSPResp`); signer can embed OCSP (iText `OcspClient`) but **no
  responder/CRL URL hardcoded** → [?] runtime-supplied.
- **[O] Certificate selection — two providers:**
  1. **PKCS#11 (USB token):** `InitSigning` builds a SunPKCS11 config on the fly —
     `name=IHTKKProvider\nlibrary=<dll>\nslot=<n>` — provider name
     `SunPKCS11-IHTKKProvider`, keystore type `PKCS11`, temp config file
     `.usb_token_signer_applet.config`; PIN via `PINCodeDialog` or `PIN_CODE`.
  2. **Windows cert store:** `Windows-MY` keystore (SunMSCAPI) via
     `KeyStoreBean.getKeyStoreFromLocal`.
  - Target cert matched by `SERIAL_NUMBER` / `ACTIVE_CERT_SERIAL`; `SelectCertDialog`
    lets the user pick otherwise.
- **[O] Built-in PKCS#11 DLL probe list** (default; overridable by `PKCS_11_LIBRARY_NAME_LIST`
  input). It tries each `.dll` until one loads a token:
  `vdctdcsp11, vnpt-ca_csp11, BkavCA, vnpt-ca_v34, viettel-ca, ShuttleCsp11_3003,
  ngp11v211, st3csp11, gclib, fpt-ca, CA2_v34, CA2_csp11, psapkcs, ostc1_csp11,
  fpt-ca-stx, viettel-ca_v1..v6, etpkcs11/eTPKCS11, U1000AUTO, safe-ca, eToken,
  Vina-CA, Vina-CA_s, Vina-CAv3..v5, vnpt-ca_cl_v1, ostt1..3_csp11, ostc2_csp11,
  nca_eps2k2a, nca_eps2k3a, vnptca_p11_v6..v10, nca_v4..v9` (all `.dll`).
- **[I] DLL → CA/token vendor map:** `vnpt-ca*`,`vnptca_p11_*`→VNPT-CA; `viettel-ca*`→Viettel-CA;
  `BkavCA`→Bkav-CA; `fpt-ca*`→FPT-CA; `CA2_*`,`nca_*`→Nacencomm (CA2/NEW-CA);
  `Vina-CA*`→SmartSign/Vina-CA; `etpkcs11`/`eToken`/`st3csp11`/`ShuttleCsp11_*`→SafeNet
  eToken/SafeNet middleware; `ngp11v211`,`gclib`,`safe-ca`,`U1000AUTO`,`psapkcs`,`ost*`,
  `vdctdcsp11`→other token middlewares. (Exact vendor of a few is uncertain.)
  → On macOS, map each to the vendor's `.dylib`/`.so` PKCS#11 module, or use Keychain in
  place of `Windows-MY`.

---

## 4. Network endpoints

- **[O] Update:** `https://thuedientu.gdt.gov.vn/etaxnnt/static/update` (`Main`,
  `AutoUpdate`, `SignUI`) — fetches `latest.xml`/`update.xml`; `updater.jar` applies
  `MOVE`/`EXECUTE` instructions (replaces `eSignerJava.jar` then relaunches). Bundled
  `latest.xml` = pkgver **4.3**, pubDate 2026-02-25.
- **[O] Tax-portal data endpoints** used by message handlers (not the plugin's own servers):
  `thuedientu.gdt.gov.vn/IBSCorpUAT/Request...`, `localhost:8080/IBSCorporate/...`
  (`/servlet/UploadFileServlet`, `/tempFiles/...`). Actual upload URL is passed per-request
  via `REQUEST_URL_ACTION` / `FULL_PATH_URL` by the portal.
- **[O] Proxy:** `proxy.properties` optional `PROXY_HOST`/`PROXY_PORT` (blank by default).
- **[?] No license or telemetry endpoint found.**

---

## Interop takeaways for the macOS tool
- Implement a WebSocket server at `ws://127.0.0.1:8768/plugin` (fallback 8769), accept any
  origin, speak the `{CODE, INPUT}` → `{CODE, SUCCESS, ...}` JSON above. Optionally also a
  native-messaging stdio host (4-byte length + JSON) for the browser extensions.
- Replace PKCS#11 `.dll` probing with macOS `.dylib`/`.so` modules per CA; replace
  `Windows-MY` with the macOS Keychain.
- Implement at least: `CHECK_VERSION`, `CER_002` (list/return cert), `CER_001` (XMLDSig sign),
  `JFU_001/002/003` (choose/sign/upload). SHA-1 + SHA-256, SHA1withRSA/RSA-SHA256.

**Security caveat (not advice to replicate):** the original binds `0.0.0.0` with no WS origin
check — any page/host can drive signing with a known PIN. A loopback-only bind + origin
allowlist is the safer choice for a reimplementation.

## Correction (2026-10-21, cross-check vs MacSigner repo)
- **Path:** the endpoint class `com.seatech.server.WebSocketService` is annotated `@ServerEndpoint("/sign")`, and the server context path is `/plugin`. The full URL is therefore **`ws://127.0.0.1:8768/plugin/sign`**, not `/plugin`. MacSigner is right on this point.
- **Request shape:** `AppConstants` defines `PARAM_CODE="CODE"` and `PARAM_INPUT="INPUT"`, plus `PARAM_INPUT_*` keys such as `PIN_CODE`, `NTDT_SIGN_CODE`, `DATE_SIGNING` and `TIMEZONE_SIGNING`. That supports a nested `{"CODE":..,"INPUT":{..}}` shape. MacSigner claims flat fields. This stays **unresolved until we decompile the `WebSocketService.onMessage` body or capture live traffic** (Parallels VM + eTax portal).

## eTax XML-khai flow (confirmed 2026-10-22: portal JS `plugin_websocket.js` + eSignerJava.jar static disassembly)
Requests are **flat** (`{"CODE":…,fields}`), not nested in `INPUT`.
1. `CHOOSE_FILE` `{CODE}` → `{SUCCESS, TKHAI_FORMAT:"9"(XML)|"0", FULL_PATH_URL, FILE_NAME}`. Original: Swing JFileChooser; ours: NSOpenPanel.
2. `OFFLINE_XML_SIGN_002` `{LOAI_HSO, URL_FILE_NAME, XPATH_DATA:"/HSoThueDTu/HSoKhaiThue", XPATH_SIGN:"/HSoThueDTu/CKyDTu", SERIAL_NUMBER(decimal), CHECK_CERT_SERIAL, CHECK_TIN, TIN_VALID, DATE_SIGNING "dd/MM/yyyy HH:mm:ss", TIMEZONE_SIGNING, PKCS_11_LIBRARY_NAME_LIST}` → `{SUCCESS:"TRUE"}`. Original signs the file in place (reference `//ancestor-or-self::HSoKhaiThue`); ours keeps the signed bytes in memory.
3. `OFFLINE_XML_SIGN_003` `{REQUEST_URL_ACTION, URL_FILE_NAME, UPLOADED_FILE_NAME, CHUNKSIZE, COOKIE_NAME, COOKIE_VALUE, …}` → plugin uploads the file itself (JFileUpload multipart POST, cookie `JSESSIONID`) → `{SUCCESS, PIN_CODE:<maTKhai text, else MSo>}`.
Upload field names (`todo=upload`, `uploadedFileName`, `filename`, file part `uploadfile`) are reconstructed from bytecode, not captured live.
