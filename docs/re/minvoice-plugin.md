# M-Invoice signing plugin — reverse-engineering notes

Interop research for a macOS Swift re-implementation. Target owned by the user.
Artifact: `MinvoicePlug.exe` SHA-256 `57ffb22ea1c0555479d88bb120e9e1a09f8658b1fbab3378d9387c78cbc97a2c`
(.NET Framework 4.7.2, x86 anycpu-prefer-32, assembly `MinvoicePlug` v1.1.1.0).
Delivered by ClickOnce `MinvoicePlug.application` v**1.0.9.3** from
`https://plugin.minvoice.com.vn/MinvoicePlugin_NewApp/`. Static analysis only; nothing executed.

**2026-10-22 correction:** this file preserves the initial metadata/string survey.
The invoice-specific CIL findings in [minvoice-rest-static.md](minvoice-rest-static.md)
supersede its inferred wire examples, authentication and signing-profile assumptions.
The user-supplied `setup.exe` is a separate ClickOnce bootstrapper; see
[setup-clickonce.md](setup-clickonce.md). It is not the managed assembly itself.

## Version
- ClickOnce deployment: **1.0.9.3**; assembly: 1.1.1.0; `appSettings/AppVersion` = `1.1.1`.
- Second updater `MinvoiceUpdate.exe` (reads `Version.txt`, pulls `*_Update.zip`, restarts).
- Publisher cert: "CONG TY TNHH HOA DON DIEN TU M-INVOICE", EV via GlobalSign (serial 0106026495).

## Local API — MOST IMPORTANT

### Observed
- **Transport**: self-hosted **ASP.NET SignalR (classic, Microsoft.AspNet.SignalR.Core)** over
  **OWIN** (`Microsoft.Owin.Hosting` `WebApp.Start<Startup>`). `MinvoicePlug.Startup.Configuration`
  calls `GlobalHost.Configuration.MaxIncomingWebSocketMessageSize=…`, `new HubConfiguration()`,
  `app.UseCors(CorsOptions.AllowAll)`, `app.RunSignalR(hubConfig)`.
- **Port / scheme**: `appSettings/HubHot = http://localhost:16080` — **plain HTTP, no TLS** on the
  local listener. A `https://localhost:7186/` literal also appears (dev/alt).
- **CORS / origin**: `CorsOptions.AllowAll` — **no origin check** (any web origin may connect).
- **Hub class**: `MinvoicePlug.HandlerHub` (extends SignalR `Hub`). Classic SignalR → JS proxy name
  `handlerHub`, negotiate at `http://localhost:16080/signalr` (WebSocket + fallback transports).
- **Hub methods (client-invokable)**, all take one JSON **string** arg:
  - `GetVersion()` → string
  - `GetCommandInfo(string)` → object: `JObject.Parse` → `.ToObject<…>` → stored in
    `GlobalData.Instance.commandInfo` (sets session context: app settings / tenant / token).
  - `ProcessMessage(string)` → void (async; fire-and-forget)
  - `VoucherHub(string)` → Task<object>
  - `SwichTask(string)` → Task<object>  ← main command dispatcher (sic: "Swich")
  - `RunUpdate()` → void (triggers `MinvoiceUpdate.exe`)
- **Outbound relay**: also a **Microsoft.AspNetCore.SignalR.Client** (`RegisterSignalR`/`StartAsync`/
  `StopSignalR`) connecting OUT to cloud `UrlHubService = https://hub.minvoice.com.vn/`, endpoint
  `/api/Hub/hub-active`, auth header `HubToken = cRm12#$56` — lets the web app push sign requests
  to the desktop even without a direct localhost call.

### Inferred (from property/backing-field names; not decompiled bodies)
- Command envelope JSON (page → `SwichTask`/`VoucherHub`): `{ CommandName, FunctionName,
  ParameterRequest/Parameters, Xml | XmlBase64 | XmlData, SerialNumber, Token, ClientId,
  ConnectionId }` (wrapper type carries a `PlugCommand` + `PlugCommandType`).
- Command names (ldstr literals): `SignInvoices`, `SignSS04`, `StatementInvoice`,
  `StatementInvoiceBuyer`, `DECLARATION`, `ExportXML`, `ExportInvoiceXML`, `ExportInvoice`,
  `ExportPdf`, `SyncInvoiceData`, `GetHubActives` (+ `GetCertificate`/`GetInfoToken`).
- Response envelope: `{ Code/ErrorCode, IsError, ErrorMessage, Message, Data/Result,
  SignedXml/Xml, Base64Certificate, SerialNumber }`; `Code` serialized via
  `JsonEnumConverter<RestResultCode>` (RestResultCode = 79-value enum).

### Example (inferred, illustrative)
Request (hub `SwichTask`, single string arg = JSON):
`{"CommandName":"SignInvoices","SerialNumber":"<token serial>","ParameterRequest":{"InvoiceIds":[...]},"Xml":"<base64-or-raw TCT invoice xml>"}`
Response:
`{"IsError":false,"Code":"SUCCESS","Data":{"SignedXml":"<signed xml>","Base64Certificate":"<cert b64>","SerialNumber":"..."}}`

## Signing

### Observed
- **XML (XMLDSig, enveloped)** via `System.Security.Cryptography.Xml.SignedXml` in
  `MinvoicePlug.Business.VoucherSign` (`SignXmlData`, `VoucherSignFile`, `CreateObjectSigningTime`):
  `AddReference`, `AddTransform`, `ComputeSignature`, `KeyInfoX509Data`.
- **Transforms**: `XmlDsigEnvelopedSignatureTransform`
  (`…xmldsig#enveloped-signature`) + `XmlDsigC14NTransform`
  (inclusive C14N `…REC-xml-c14n-20010315`).
- **SignatureMethod**: `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` (literal present).
- **SigningTime**: `CreateObjectSigningTime` builds a `<ds:Object>` with
  `SignatureProperties`/`SignatureProperty`; a `SigningTime` element id-anchored and referenced via
  `#signtime` / `#SigningTime-<n>` / `#signatureProperties`; time format `yyyy-MM-ddTHH:mm:ss`
  (UTC, `ToUniversalTime`), fetched/validated through `GetDateAsync` (server time).
- **Signature placement** — XPath targets (Vietnam TCT e-invoice schema, signature goes inside the
  role's `DSCKS` element):
  - `//HDon/DSCKS/NBan`  (invoice, seller)
  - `//BKe/DSCKS/NMua`   (buyer list, buyer)
  - `//TBao/DSCKS/NNT`   (notice, taxpayer)
  - `//TKhai/DSCKS/NNT`  (declaration, taxpayer)
  - `//TDiep//DLieu`     (message/data envelope)
  - `/CTu/DSCKS/TCTTNhap` (voucher/chứng từ)
- **KeyInfo**: `KeyInfoX509Data` (+ `RSAKeyValue` seen) → `<X509Data>` with the signer cert, and
  an `RSAKeyValue` key value.
- **Certificate selection**: **Windows cert store / CryptoAPI**. `X509Store`, `X509Certificate2`,
  `X509Certificate2UI` → `SelectCertificateForm` (UI picker), `GetDefaultUsbToken`,
  `GetTokenBySerialNumber`, `GetX509Certificate2Collection`. Private key via
  `RSACertificateExtensions.GetRSAPrivateKey` / `RSACryptoServiceProvider`. **No PKCS#11 .dll list
  and no vendor-named module** (VNPT/Viettel/NC-CA/SafeNet/etc.) in the binary — it relies on the
  USB token's Windows CSP/minidriver already registered in the user cert store.
- **Cert parsing / chain**: BouncyCastle (`Org.BouncyCastle.X509`, `X509CertificateParser`,
  `DotNetUtilities`); OCSP helper `GetAuthorityInformationAccessOcspUrl`, `GetCertStatus`,
  `GetRootCA`/`GetNameRootCA` (status/root-CA checks).
- **PDF**: HTML→PDF via `Select.HtmlToPdf` + `itextsharp` (`GetPrintInvoiceHtml`,
  `ExportPdf`, filenames `{0}_{1}_{2}.pdf`); printing via `RawPrint`. No evidence PDFs are
  digitally signed — PDF path is render/print only; signing is XML.

### Inferred
- **PIN prompt**: handled by the token's Windows CSP when `GetRSAPrivateKey`/`ComputeSignature`
  first touches the private key — the plugin does not prompt for or handle the PIN itself.
- **DigestMethod** = SHA-256 (`…xmlenc#sha256`): a `Sha256` property is set and signature is
  rsa-sha256; the Reference digest almost certainly SHA-256 (not confirmed via a literal URI).
- **Hash-only signing**: not observed; the plugin signs whole XML elements, not externally
  supplied hashes.

## Network endpoints contacted

### Initial string/configuration observations (not established request paths)
- Base `appSettings/API Base Uri = https://api-hddt.minvoice.com.vn/api/app/`; header
  `api-key: cRm12#$56`; Bearer/JWT + `RequestVerificationToken`; backend is ABP
  (`abp/application-configuration`).
- Relative paths: `session/login`, `session/account-info/{0}`, `appsetting?groupCode={0}`,
  `tenant-company/current-tenant`, `token/by-serial-number?serialNumber={0}`,
  `companies/update-token/{0}`, `declarations/sign-file/{0}`, `declarations/submit-bhxh/{0}/{1}`,
  `declare-register-invoice/{0}/upload-xml`, `release-invoice/tenant-setting-sign`,
  `release-invoice/delete-cache`, `statement-invoice/{0}/upload-xml`,
  `statement-invoice/{0}/upload-xml-buyer-sign`, `wrong-invoice/{0}/upload-xml`,
  `invoice/print-mutile-invoice-xml`, `file-upload/download/{0}`,
  `my-account/reset-password-by-token`.
- Cloud SignalR relay: `https://hub.minvoice.com.vn/` + `/api/Hub/hub-active`.
- Update: ClickOnce `plugin.minvoice.com.vn/MinvoicePlugin_NewApp/*` (+ zip updater).
- NLog config embeds a Gmail SMTP fatal-error notifier (hardcoded creds) — not needed for interop.

### Unknown / not resolved
- Exact JSON field names and `switch` arms inside `SwichTask`/`VoucherHub`/`SignXmlData` (async
  state-machine `MoveNext` bodies not decompiled; no C# decompiler available on host — only CIL
  metadata + ldstr literals read).
- Whether the Reference over the document uses `URI=""` (enveloped) vs `URI="#<id>"`; both anchor
  styles (`#data`, `#signtime`) are present.
- Any TSA timestamping — none observed (SigningTime is a self-asserted SignatureProperty, not RFC3161).
- Precise OCSP/CRL hosts (derived at runtime from each cert's AIA).

## STATUS (2026-10-22 — branch `claude/beautiful-shirley-8acdc0`)
SignalR server + `GetVersion`/TokenInfo built and serving on `localhost:16080`
(`handlerHub`, negotiate `/signalr`). **`SignInvoices` blocked, returns code 501.**
The minvoice 2.0 page sends `BrowserInfo` and `PlugCommand` to the plugin, without
XML. The **plugin process** downloads and uploads the XML. Page DevTools can show
the localhost invocation; it cannot observe the plugin's own REST requests.
The new static CIL investigation resolves concrete download/upload construction
without making business requests. Remaining checks concern the invoice signing
profile, authentication/response behavior and controlled plugin-process capture.
See [minvoice-rest-static.md](minvoice-rest-static.md) for evidence and exact gaps.

## Interop takeaways for the Swift tool
- Host an HTTP SignalR-protocol server bound to `127.0.0.1:16080`, enforce the project's origin allowlist, expose a hub named
  `handlerHub` with methods `GetVersion`, `GetCommandInfo`, `ProcessMessage`, `VoucherHub`,
  `SwichTask`, `RunUpdate`, each taking one JSON-string arg. Classic SignalR protocol (JSONP/
  long-poll/WebSocket + `/signalr/negotiate`) is required for compatibility with minvoice pages.
- Initial voucher findings: inclusive C14N + enveloped-signature transforms, rsa-sha256,
  SHA-256 digests, `<X509Data>`+`<RSAKeyValue>` KeyInfo, a `SigningTime` SignatureProperty,
  `<Signature>` inserted under the role `DSCKS` node per the XPaths above. Do not
  assume this is the invoice profile; the invoice CIL uses a different method.
- Drive the token through PKCS#11 (macOS has no Windows cert store); map "select by serial number"
  and "default token" to PKCS#11 slot/cert enumeration. In this app, retain explicit
  approval/PIN UI and pass PIN only to TokenHelper through stdin.
