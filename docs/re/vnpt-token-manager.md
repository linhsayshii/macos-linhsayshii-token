# VNPT-CA Token Manager (macOS) — RE notes

Target: `VNPT-CA Token Manager.app` v1.0.1, bundle id `vn.vnpt.tokenmanager`, from `vn.vnpt.tokenmanager.pkg`.
Purpose: interoperability research for a native Swift all-in-one signing tool.
Paths below are relative to the extracted asar (`app.asar` → `asar_x/`) or to `Contents/`.
Secrets seen in the bundle are **not** copied here; only their locations are given.

Note: the bundled EULA (`Scripts/license.txt`) forbids decompiling. Check your local law on interoperability exceptions.

---

## 1. Architecture

### Observed
- Electron 38.1.0 (`Electron Framework.framework` Info.plist). Main exe is **arm64 only**. Ad-hoc signed, no Team ID, not notarized.
  `LSMinimumSystemVersion` 12.0.
- `package.json`: name `vnpt-ca-token-manager` 1.0.1. Deps: node-forge, pkijs/asn1js, ocsp, axios, crypto-js,
  electron-updater, sudo-prompt, electron-log, jquery. There is **no pkcs11js/graphene/ffi**.
- Main process: `main.js` (windows, tray, autoUpdater, IPC `save-cert`, `save-report`, `set-proxy`, `open-popup`,
  `fetch-contacts`). `main_thread/index.js` is a leftover `login-success` stub.
- Renderers use `nodeIntegration:true, contextIsolation:false` (`main.js` createLoginWindow/createMainScreen). All
  business logic runs **in the renderer**, which `require`s the native addon directly:
  - `src/infastructure_layer/usbtoken_infastructure.js` thin wrappers around the addon
  - `src/application_layer/usecase/{login,main}_usecase.js` flows + raw-TLS HTTP calls
  - `src/application_layer/events/{login,main}_events.js` DOM wiring
  - `src/domain_layer/index.js` PIN format check (`VerifyPin`: 8–12 chars)
  - screens: `src/presentation_layer/screen/{login,main,unlock-token,popup,update*,confirmed_delete}.html`
- Token access goes through a **custom N-API addon** `build/Release/cryptoki_ext.node` (arm64, links only libc++/libSystem).
  It is loaded via `require(path.join(process.cwd(),'build','Release','cryptoki_ext.node'))`
  (`usbtoken_infastructure.js:4`, `main_events.js:19`). This is why `Contents/build/` duplicates the addon.
  The addon `dlopen`s **`/usr/local/lib/libvnptca_p11_v8.dylib`** (hardcoded string) → `C_GetFunctionList`, then calls
  through `CK_FUNCTION_LIST` plus the vendor `E_GetAuxFunctionList` → `EP_SetTokenLabel`.
- Addon C++ units (from `obj.target/.../src_cpp/cpp/*.o`): addon, pkcs11_manager, dynamic_library, certificate_manager,
  change_password, Set_Init_Pin, rename_token, rsa_key_gen, sign_base64, import_cert, check_lib, usb_events.
- Addon JS API (N-API exports): `loginToken, logoutToken, changeUserPin, getUsbTokenInfo, getUsbTokenSlots`
  (returns base64 JSON; callback for hotplug), `renameToken, initUsbToken, generateRsaKeyPair, signCsrBase64,
  listCertificates, listAllRsaKeys, getKeyRSAWithoutCert, compareModulusExponent, importCertToToken,
  importCAToWindowsStore, checkCert, checkWrapper, checkFiles` (SHA-512 file check via CommonCrypto).
- USB hotplug: IOKit `IOServiceAddMatchingNotification("IOUSBDevice")` + CFRunLoop thread, with N-API threadsafe function `_tsfn`.
- `ensureDylibInstalled()` (`main.js`) copies the dylib to `/usr/local/lib` via `sudo-prompt` if missing. The pkg
  `postinstall` does the same (`cp -f`, `chown root:wheel`, `chmod -R 755` on the app).

### Inferred
- Launching from Finder gives cwd `/`, so `process.cwd()/build/...` may fail unless the cwd is `Contents/`. The
  duplicate `Contents/build` suggests the developers worked around this by hand. Not runtime-verified.
- Intel Macs: the Electron exe and addon are arm64-only, so the app will not run there, even though the dylib is universal.

## 2. PKCS#11 module `libvnptca_p11_v8.dylib`

### Observed
- Universal **x86_64 + arm64**, ad-hoc linker-signed, minOS 10.9 (x86_64) / 11.0 (arm64). Size 3.8 MB.
- `otool -L`: libc++, CoreFoundation, IOKit, libSystem, **PCSC.framework**. It talks to the reader via PC/SC
  (`/var/run/pcscd`, `PCSCBus`, `pcsc_dev_t`).
- Exports: the full standard PKCS#11 v2.x set, `C_Initialize` … `C_WaitForSlotEvent` (68 `C_*`), plus one vendor
  export **`E_GetAuxFunctionList`**. Aux table entry name seen in the addon: `EP_SetTokenLabel` (used by `renameToken`).
- Lineage: Feitian **ePass2003 / EnterSafe** middleware rebranded. Evidence strings: `ePass2003.ini`,
  `ePass2003_pcsc_mutex_`, `CToken2003`, `CStore2003`, `AuthManager2003`, `ENTERSAFE-ESPK`, `..._FEITIAN` GUID,
  manufacturer `SecureMetric Technology Sdn.Bhd`, labels `VNPT-CA PKCS#11 Library.`, `VNPT-CA PKI Token`, `VNPT-CA Token`.
  Windows leftovers: `vnptcav2_p11_v8.dll`, `Software\VNPT-CA\VNPT-CA Ace v2.0 Token Manager`, CSP/KSP names.
- Built-in ATR template (bytes at arm64 slice ~0x3744bd, with mask):
  `3B 9F 95 81 31 FE 9F 00 66 46 53 05 ?? ?? ?? 71 DF 00 00 32 00 00`. The mask wildcards bytes 12–14.
  This is the ePass2003 ATR family. No other ATR template was found.
- Crypto: `ES_SSL 0.14.0` (PolarSSL-derived). Hard/soft classes for RSA PKCS#1/PSS/OAEP/X9.31, SHA1/224/256/384/512
  RSA sign, ECDSA, AES/DES/3DES/RC2/RC4, HMAC, plus Chinese SSF33/SCB2 secret keys.
  The embedded PEM certs and keys are only **PolarSSL test vectors** (`CN=PolarSSL Test CA`, `CN=localhost`), not VNPT secrets.
- PIN policy, as seen in addon strings and JS:
  - user PIN length 8–12 (`domain_layer VerifyPin`; addon "New PIN length is out of range")
  - new PIN and confirmation must match
  - retry counters are read from token info (`PinMaxRetries`, `PinCurCounter`), with "last attempt" warnings
  - SO PIN lock is detected
  - `loginToken` returns `isLocked` and `isRenewed`
- Signing in the addon (`SignCsr::signBase64`, `cryptoki_ext.node` 0x1ed38): Login(CKU_USER) → FindObjects private
  key by label → `C_SignInit` with mechanism constant 0x40 = **CKM_SHA256_RSA_PKCS** (const at 0x23e78) → `C_Sign`.
- Keygen (`RSAKeyPairGenerator::GenerateRSAKeyPair`): RSA **2048** (`#0x800`), e = 65537, random CKA_ID, generated label.

### Unknown
- Supported USB VID/PID list: matching is by ATR through PC/SC, with no VID filter observed. Other token models
  (non-ePass2003) are unconfirmed.
- Full `E_GetAuxFunctionList` table layout (only `EP_SetTokenLabel` was observed). Min/max PIN enforced inside the
  dylib vs the card (not decompiled). ECC key support on real VNPT tokens.

## 3. Features

### Observed (UI menus in `main.html`/CSS: danh_sach_cts, chi_tiet_cts, thong_tin_token, kich_hoat_cts, chuan_doan, cau_hinh, thong_bao, huong_dan, lien_he)
- Pick slot and log in with the user PIN. Show token info: label, serial, model/type, firmware.
- Rename the token label (vendor aux function).
- List certificates, view details (node-forge/pkijs), and save a cert as `.crt` (IPC `save-cert`).
- **Revocation check**: CRL download over `http.get` + pkijs, and OCSP via the `ocsp` npm package with issuer lookup in `./issuer`
  (`main_usecase.js` `checkCrlStatus`, `checkOcspStatus`, `findIssuerCert`).
- Change user PIN (`changeUserPin` → `C_SetPIN`).
- **Unlock / reset PIN** (`login_events.js` ~380–520, `login_usecase.js` `requestUnlock`/`unlockToken`/`decryptSOPIN`/`InitSOPINToken`):
  1. `POST /token/request-unlock?tokenSerial&certSerial`: the server sends an unlock code to the customer.
  2. `POST /token/unlock?tokenSerial&certSerial&unlockCode` → `data.sopin` (encrypted).
  3. Decrypt with **AES-128-ECB/PKCS7 using a hardcoded key** (`decryptSOPIN`, `login_usecase.js:472`).
  4. Log in as SO, then `C_InitPIN` with the new user PIN (`initUsbToken`).

  The SO PIN is kept in plaintext in `localStorage`.
  There is no offline PUK. Unlock depends on VNPT's server.
- **Activate / renew a cert online** (`kich_hoat_cts`, `main_usecase.js` handleStep1..5):
  1. `GET /cert/check-active-code?username&activationCode`
  2. Generate an RSA-2048 key on the token, then `POST /cert/csr-info {username, base64PublicKey}` → `{csrId, base64Csr}` (the TBS)
  3. Sign the TBS on the token (SHA256-RSA), then `POST /cert/gen-cert {username, csrId, base64Signature}` → `data.pkcs7_cert`
  4. Parse the PKCS#7, match it to the key modulus/exponent, and import the end-entity cert onto the token with `C_CreateObject`.
     The addon `importCAToWindowsStore` is also called for CA certs.
  5. `GET /cert/get-pending-certs-to-activate?customerId`
- Contacts: `POST /customer/contacts`, `PUT <path>` (update contact). Diagnostics (`chuan_doan`): `checkMidderwares`
  (Windows-path SHA-512 check, which always fails on macOS), `checkWrapper`, `checkCert`. Config: HTTP proxy (IPC `set-proxy`) +
  `checkProxyWorking` (api.ipify.org). Report: export the latest log.
- **Not present**: file/PDF/XML signing, PAdES/XAdES/CAdES, and any local HTTP/WebSocket server for web portals. No
  `createServer`/`listen`/`WebSocket` appears in the app JS. The only on-token signature is the CSR TBS signature above.

### Inferred
- `importCAToWindowsStore` on macOS is probably a no-op or error. The addon imports no Keychain/SecItem APIs (only `SecTransform` for base64).
- Browser/portal signing for tax, customs and BHXH is done by a different VNPT product, not this app.

## 4. `issuer/`, `build/`, bundled certs, network

### Observed
- `Contents/issuer/`: `VNPT-CA SHA-256.cer` (expired 2025-07-28) and `VNPT-CA SHA2.cer` (valid to 2029-08-30). Both are
  issued by `Vietnam National Root CA`. They are used as OCSP issuers (`issuersDir = "./issuer"`, also cwd-relative).
- `Contents/build/`: a node-gyp build tree (Makefile, `config.gypi` with node 22.19.0 headers, ABI 127, arm64, dev path
  `/Users/meomeo/...`), `cryptoki_ext.node` (identical to the asar copy), and **Windows** `iconv-2.dll`/`charset-1.dll`
  (dead weight). It contains no update URLs.
- In the asar `certs/`: `Vietnam National Root CA.cer` (to 2039), plus **`keystore.p12`** = the mTLS client identity for the
  VNPT API. Its passphrase is hardcoded at `main_usecase.js` ~line 40 and in `login_usecase.js`. There is also a dev identity
  `Admin_DEV_NTL_98.p12`. Every install ships the same client key, and `rejectUnauthorized:false` is set.
- `log/`: 773 developer native-trace logs (162 MB, 2025-07 → 2025-11) shipped by mistake in the asar.
- Network endpoints:
  - `vnpt-ca.vn:444` over raw `tls.connect` with hand-written HTTP/1.1: `/customer/contacts`, `/token/request-unlock`,
    `/token/unlock`, `/version/check?currentVersion=` (Host header typo `vnpt-ca.vn1`), `/cert/check-active-code`,
    `/cert/csr-info`, `/cert/gen-cert`, `/cert/get-pending-certs-to-activate`, plus a PUT for contact update.
    A dev IP `10.168.3.111` is commented out.
  - CRL/OCSP URLs taken from each cert's CDP/AIA.
  - `https://api.ipify.org?format=json` (proxy check). The link `https://smartca.vnpt.vn/solution#vnptca` and Bootstrap CSS
    from `cdn.jsdelivr.net` (`confirmed_delete.html`).
  - electron-updater: `checkForUpdatesAndNotify()`. **No `app-update.yml`** is in Resources, so the feed URL is unknown and the check
    likely errors. The error handler calls `quitAndInstall` (`main.js`).
- There is no license-server call.

### Unknown
- The real auto-update feed. The response schemas of the endpoints beyond the fields named above.

## 5. Reuse vs rewrite for a native Swift app

**Reuse as-is**
- `libvnptca_p11_v8.dylib` (universal). `dlopen` it from your app bundle, not `/usr/local/lib`, and call
  `C_GetFunctionList`. Standard PKCS#11 covers login, list certs, sign, SetPIN, InitPIN, GenerateKeyPair and CreateObject.
  Only token rename needs `E_GetAuxFunctionList`.
  - Signing a document hash: `CKM_SHA256_RSA_PKCS` (0x40) or `CKM_RSA_PKCS` over a DigestInfo. Keys are RSA-2048.
- The ATR template, to detect VNPT/ePass2003 tokens through CryptoTokenKit/PC/SC before loading the module.
- The issuer certs plus the Vietnam National Root CA, for chain building and OCSP/CRL.

**Rewrite (straightforward)**
- UI, slot hotplug (`TKSmartCardSlotManager` or `C_WaitForSlotEvent`), cert parsing (Security.framework/swift-certificates),
  OCSP/CRL with URLSession, and the PIN-change flow.

**Rewrite (scope you must add; not in this app)**
- PAdES (PDF) signing, XAdES (XML, for e-invoice/tax/BHXH), CAdES/PKCS#7 detached signing, and timestamping.
- A local signing bridge (HTTP/WebSocket) for web portals. The protocol must be reverse-engineered from the portal's JS or
  from VNPT's separate plugin, not from this app.

**Avoid / do not copy**
- The shared mTLS `keystore.p12`, the hardcoded AES key for the SO PIN, `rejectUnauthorized:false`, keeping the SO PIN in
  plaintext localStorage, and `nodeIntegration` renderers.
- Online unlock and cert activation only work against VNPT's private API with VNPT's client cert. Treat them as
  out of scope unless VNPT provides access.
- Installing to `/usr/local/lib` with root. Prefer `Contents/Frameworks` and re-sign. The dylib is ad-hoc signed, so
  hardened-runtime apps need `com.apple.security.cs.disable-library-validation` or to re-sign it with your Team ID.
