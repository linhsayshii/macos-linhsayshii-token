# CTSigningHub 1.2 — interoperability RE notes

Target: `CTSigningHub.exe` (PE32 GUI, 48 MB, Authenticode-signed). For interoperability
research: building a macOS tool that serves the same local signing protocol.

Legend: **[O]** observed in artifact · **[I]** inferred · **[?]** unknown / not recovered.

## How it was unpacked (reproducible)
- **[O]** Installer = **Advanced Installer 15.6 (build 0c40bd)** SFX (`ADVINSTSFX`, Caphyon).
  Stub is a PE32 GUI; the real payload is appended after the PE.
- **[O]** Obfuscation is **XOR 0xFF applied to only two 512-byte regions**, rest is plaintext:
  1. the embedded MSI's OLE2/CFB **header** (first 512 B) — raw `2f30ee1f…` XOR FF = `d0cf11e0…`.
  2. the appended CAB's **first 512 B** (CAB header + first CFFILE rows).
- **[O]** The ~45 MB **CAB is appended at file offset 1140736**, *outside* the CFB directory
  (hidden trailing data; MSI `Media.Cabinet=ctsigninghub1.cab`, no `#`). CAB is **MSZIP**.
- Recipe: XOR-FF the MSI 512-B header → valid MSI (`msiinfo`); the file payload is the trailing
  CAB → `cab = XORFF(raw[1140736:1140736+512]) + raw[1140736+512:+cbCabinet]` → `7zz x` → 89 files.
  Extracted set: `/private/tmp/claude-501/.../scratchpad/re/ct/files/`.

## 1. Packer, publisher, tech stack
- **[O] Authenticode signer (publisher):** `CN=Tổng Cục Thuế, O=Tổng Cục Thuế, OU=IT Department,
  C=VN, ST/L=Ha Noi, street "So 123 Lo Duc, Quan Hai Ba Trung", businessCategory=Government Entity`.
  EV code-signing cert issued by **GlobalSign GCC R45 EV CodeSigning CA 2020**.
  → Official **Vietnam General Department of Taxation (GDT / Tổng Cục Thuế)** desktop signing tool.
- **[O] App:** `ctSignerv2.exe` — .NET Framework **4.8**, x64 WinForms; internal namespace
  `nSignerv2`; ProductName "CTSigningHub", version **1.2.0.0**. UI = MetroFramework.
- **[O] Local server stack:** self-hosted **OWIN** (`Microsoft.Owin.Host.HttpListener`,
  `Microsoft.Owin.Hosting`) + **ASP.NET Web API 2** (`System.Web.Http`) + **CORS**
  (`System.Web.Http.Cors`) + **Newtonsoft.Json**.
- **[O] Signing engine:** `NEACSignLib.dll` (sub-namespaces Certificates / Office / Pdf /
  Timestamping / Xml) + **iTextSharp** (+ iTextSharp 4.1.6) + **Patagames.Pdf / pdfium** +
  **EPPlus** + Office Interop (Word/Excel/PowerPoint).
- **[O] Other:** SQLite + EntityFramework 6 (local DB; table `LogCheckAutoVerify`); log4net →
  `%AppData%\CTSigningHub\Log.txt`; `autoUpd.exe` auto-updater; DotNetZip (Ionic.Zip).
- **[O] NEAC = National Electronic Authentication Center.** App embeds the **Vietnam National
  Root CA** cert (NEAC, MIC) for chain validation.

## 2. Local API  (most important)
- **[O] Listener:** **HTTP (plaintext, not HTTPS)** on **`http://127.0.0.1:32001/`**, loopback only.
  OWIN `HttpListener`. **[O]** No TLS / no localhost cert. **[?]** No WebSocket observed.
- **[O] Route template:** default Web API `api/{controller}/{action}/{id}`.
- **[O] Endpoints** (controller `HubClient` is primary):

| Method | URL | Body type | Response |
|---|---|---|---|
| GET  | `/api/HubClient/GetCert` | — | `GetCertResponse` |
| POST | `/api/HubClient/SignHash` | `SignHashRequest` | `SignHashResponse` |
| POST | `/api/HubClient/signpdf` | `SignPdfRequest` | `SignPdfResponse` |
| POST | `/api/HubClient/signooxml` | `SignOfficeRequest` | (status/msg/data) |
| POST | `/api/HubClient/signxml` | `SignXmlRequest` | (status/msg/data) |
| GET  | `/api/HubClient/getFileLocal` | — | file/data |
| GET  | `/api/Info/GetInfoCert` | — | `string` (cert info) |
| GET  | `/api/SignHash/Version` | — | `string` (app version) |

- **[O] JSON schema** (properties from `nSignerv2.Common.*`, Json.NET camelCase as-declared):
  - `SignHashRequest` = `{ hash, serinumber, requestId, signature }`
  - `SignPdfRequest` = `{ dataFile, filePath, serinumber, requestId, sig }`
  - `SignOfficeRequest` = `{ dataFile, filePath, serinumber, requestId }`
  - `SignXmlRequest` = `{ dataFile, filePath, base64Cert, cks, dataBV, serinumber, requestId }`
  - `GetCertResponse` / `SignHashResponse` / `SignPdfResponse` = `{ status:int, message:string, data:string }`
    (`data` carries base64/JSON: cert list, or signed bytes/signature).
  - **[I]** `serinumber` = X.509 **serial number** selecting the signing cert; `dataFile` = base64
    document, `filePath` = local path alternative; `sig` = visible-signature appearance config;
    `cks`/`dataBV` = XML/e-invoice signing params; `requestId` echoed for correlation.
- **[O] CORS:** `[EnableCors]` / `System.Web.Http.Cors` is wired in. **[?] Exact origin allowlist
  not statically recoverable** (lives in the EnableCors attribute/Startup blob, not in #US strings).
  **[I]** Likely GDT tax/e-invoice web portals (`*.gdt.gov.vn` and related) and/or `*`.
- **[O] Example calls** (shape):
  ```
  GET  http://127.0.0.1:32001/api/HubClient/GetCert
  GET  http://127.0.0.1:32001/api/SignHash/Version
  POST http://127.0.0.1:32001/api/HubClient/SignHash
       {"hash":"<base64 digest>","serinumber":"<cert serial hex>","requestId":"<id>"}
    -> {"status":1,"message":"...","data":"<base64 PKCS#1 signature>"}
  POST http://127.0.0.1:32001/api/HubClient/signpdf
       {"dataFile":"<base64 pdf>","serinumber":"<serial>","requestId":"<id>","sig":{...appearance...}}
  ```

## 3. Signing formats, algorithms, cert selection
- **[O] Hash signing** (`SignHash`): client sends a precomputed **hash**, server returns an
  **RSA PKCS#1 v1.5** signature over it (`GetRSAPrivateKey`, `RSAPKCS1SHA256SignatureDescription`).
- **[O] PDF = PAdES** (iTextSharp + pdfium): LTV supported (`PadesLtvLevel`), visible signature
  (`AppearanceMode`, `Position`, `page`, `image`, `SOrg`/`SUnit`/`SEmail`).
- **[O] XML = XAdES / XML-DSig** (`xmldsig#`, `xmldsig-more#rsa-sha256`, `xmlenc#sha256`), with
  **`AddXAdESPropertiesTT78`** → Vietnam e-invoice **Circular 78/2021 (TT78)** profile. Full XAdES
  XSD present (AllDataObjects/Archive timestamps, OCSPValues).
- **[O] Office = OOXML** (`signooxml`) via Office Interop / EPPlus.
- **[O] Algorithms:** **SHA-256 with RSA** primary (`SHA256RSA`). Legacy SHA-1 paths exist
  (`BCY_SHA1`, `MIC_SHA1`) for specific issuers.
- **[O] Cert selection = Windows Certificate Store** by **serial number** (`X509Store`,
  `StoreName`, `StoreLocation`; `GetCertificatesFromStore`, `X509Certificate2UI`).
  **[I]** `CurrentUser\My`. **[O] No PKCS#11 / cryptoki code** in this Windows build → USB tokens
  are reached via their Windows CSP/minidriver (certs surface into the OS store), **not** a
  PKCS#11 DLL list. (A `cryptoki_ext.node` exists under `scratchpad/re/asar_x/` but belongs to a
  **separate macOS Electron** target, not CTSigningHub.)
- **[O] TSA (RFC3161):** optional, config-driven via `tsa.xml` (default `<use>0</use>`, empty url);
  `NEACSignLib.Timestamping`: `TsaServerName`, `IsQualifiedTimestamp`, `IncludeTimestamp`.
  **[?]** No default TSA URL hardcoded.
- **[O] Revocation:** `verify.xml` default `<use>1</use>` (cert verification on);
  `IncludeOCSPRevocationInfo`. **[?]** No default OCSP URL hardcoded (taken from cert AIA).

## 4. Network endpoints
- **[O] Update:** `https://signingupdate.gdt.gov.vn/tct/update/version.xml` and
  `.../tct/update/certca.txt` (CA trust-list refresh). Handled by `autoUpd.exe`;
  `autoUpd.exe.config` `UpdateUrl` empty → falls back to the hardcoded GDT host.
- **[O] License server:** none observed.
- **[O] CRL/OCSP in binary** are only the GlobalSign chain of the code-signing cert, not runtime.

## Config files (install dir / `%AppData%\CTSigningHub`)
- **[O]** `profile.xml` (signer profiles/templates, `DefaultTemplate=-1`), `tsa.xml`,
  `verify.xml`, `vrs.xml` (local version 1.2.0.0).

## To reimplement on macOS (interop)
Serve **HTTP on 127.0.0.1:32001** with Web API routes above; accept/return the JSON DTOs;
select cert by serial; sign hash (RSA-PKCS1-SHA256), PDF (PAdES/LTV), XML (XAdES-TT78), OOXML;
optional RFC3161 TSA from `tsa.xml`. **Verify the real CORS origin allowlist at runtime** before
assuming `*` — it gates which web pages may call the hub.
