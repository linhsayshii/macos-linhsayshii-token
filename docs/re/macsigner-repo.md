# MacSigner (DeanOpen/MacSigner) — reuse assessment

Source: `git clone --depth 50` at `259ef8d` (v0.3.0, 2026-10-21) into the session scratchpad
(`.../scratchpad/macsigner/src`). Read-only static review: nothing was built, run or installed, and no token was touched.
Tags: **[O]** observed in source/metadata · **[I]** inferred · **[?]** unknown.

## 1. Repo facts
- **[O] Stack:** Rust (edition 2024) core crate `macsigner` + **Tauri 2** desktop app (`app/src-tauri`, React/TypeScript UI).
  This is **not Swift**. Key crates: `cryptoki 0.12` (PKCS#11), `pcsc 2.9`, `axum 0.8`/`tower-http` (HTTP), `tungstenite 0.30` (WS),
  `lopdf 0.38` (PDF), `rsa 0.9`, `x509-parser`, `p12-keystore` (`Cargo.toml`). Cross-platform: also builds for Windows and Linux.
- **[O] License:** **Apache-2.0** (SPDX `Apache-2.0`), "Copyright 2026 Nextwaves" (`LICENSE` appendix). There are no extra license
  restrictions. `DISCLAIMER.md` is advisory only (no affiliation, no warranty, no claim of legal validity). Bundled
  `assets/fonts/NotoSans.ttf` is under OFL (`assets/fonts/OFL.txt`). The CA logos in `assets/ca-logos/` are third-party trademarks.
- **[O] Activity:** created **2026-10-20**, last push 2026-10-21. The whole history is **14 commits in about 2 days**. 28 stars,
  7 forks, 0 watchers. One maintainer: `DeanOpen` / "Dean" `<hello@deanoss.com>`, plus a release bot.
- **[O] Releases:** v0.2.0, v0.2.1, v0.2.2 and v0.3.0 (latest), all within 2 days. CI builds a universal macOS DMG that is
  codesigned and notarized (`.github/workflows/build.yml:53,141-150`).
- **[O] Issues:** none filed yet. The only PR is #1 (merged): "VNPT service UI and token bundle validation".
- **[O] Self-declared status:** **Alpha**. The README says ESIGN tax signing was "tested only with test certificates, never
  on the real portal with a real USB token". `ETOKEN-SUPPORT.md` lists every CA we care about as "🟡 Chưa test full" (not fully tested).
  `capabilities()` hardcodes `"real_portal_verified": false, "macos_linux_runtime_verified": false` (`src/esign/protocol.rs:215-216`).

## 2. Architecture
- **[O] Process model:** a single windowed Tauri app (`vn.nextwaves.macsigner`, frameless window, `tauri.conf.json`). There is
  **no menu-bar/tray mode, no LaunchAgent, no daemon, and no login item** (searches for tray/LaunchAgent/SMAppService
  found nothing). The services the user enabled start with the app (`app/src-tauri/src/lib.rs:59-77`) and stop when it quits.
  A headless `macsigner serve --esign --ctsign` CLI exists only in source builds; it refuses signing commands because it has no approval UI.
- **[O] Layers:** `src/crypto` (algorithms, X.509) ← `src/token` (PKCS#11 discovery and signing, PC/SC inventory, Windows
  store) ← `src/esign`, `src/ctsign`, `src/pdf.rs`, `src/cms.rs` ← `app/src-tauri` (commands, approval bridge, USB watch, updater).
- **[O] Local servers:**

| Service | Bind | TLS | Path / routes | Origin/Host checks |
|---|---|---|---|---|
| ESIGN (eSigner clone) | `127.0.0.1:8768`, fallback 8769 (`websocket.rs:58-65`) | none (`ws://`) | **`/plugin/sign`** only, no query string | **Exact Origin allowlist** (default `https://thuedientu.gdt.gov.vn`), Host must be `localhost:port`/`127.0.0.1:port`, single Origin header (`websocket.rs:23-35`) |
| CTSIGN (CTSigningHub clone) | `127.0.0.1:32001` (`services.rs:146`) | none | catch-all dispatcher, case-insensitive `api/{ctrl}/{action}[/id]` | **CORS `allow_origin(Any)`, no Host check** (`ctsign/api.rs:28-33`) |
| VNPT-CA Plugin | not served. Only a TCP probe of 4433-4435/9201/9202 (`vnpt/diagnostics.rs`) | n/a | frame parser for `{functionID,args,funcCallback,domain}` → `payload*callback` (`vnpt/protocol.rs`) | `ensure_available()` always returns Err (`vnpt/mod.rs`) |
| M-Invoice SignalR :16080 | **absent** | | | |
| Chrome native messaging | CLI only (`esign/native.rs`). It never signs (no backend) | | 4-byte LE length + JSON, 1 MiB cap | |

### CTSIGN vs our `ctsigninghub.md`
| Endpoint | MacSigner | Delta vs our notes |
|---|---|---|
| `GET/POST api/Info/GetInfoCert` | returns `"1"` (`api.rs:148`) | our notes: "cert info string". **[I]** MacSigner matched this against a live original |
| `api/SignHash/Version` | returns `"3333333333333333"` (`api.rs:149`) | our notes: app version string. **[?]** verify against the real 1.2.0.0 |
| `api/HubClient/GetCert` | `{status:200,data:[{serinumber,subjectDN,issuedDN,pemCert,valid,validFrom,validTo,error}],message:"SUCCESS"}`. If empty: `{status:0,data:null,message:null}` (`model.rs:48-63`) | **we did not have the cert DTO.** `pemCert` is base64 DER |
| `HubClient/SignHash` | `hash` is an **array** of `{Ma, DLieuHash, CKy}`. Each `DLieuHash` must be a 32-byte SHA-256, signed RSA-PKCS1 and returned in `CKy` (`model.rs:4-22`, `signing.rs:271-316`) | **our notes assumed a single base64 `hash` and `status:1`.** MacSigner uses `status:200`, 404 for an unknown serial, 403 while API signing is disabled |
| `HubClient/signpdf` | implemented. `sig[]` = `{type 0/1/2/3/5, image, info, sigField, page,x,y,w,h}` (`model.rs:79-95`), and `filePath` is read straight from disk (`signing.rs:324-331`) | our `sig` was "appearance config", and this gives its full shape |
| `HubClient/signxml`, `signooxml` | **501 not implemented** (`api.rs:213-217`) | missing |
| `HubClient/getFileLocal` | **501** (`api.rs:185-189`) | missing |
| CORS | `*`. A test is named `live_original_probe_headers_and_cors_match` (`tests/ctsign_contracts.rs:269`) | **[I]** answers our "[?] origin allowlist": the original probably sends `*` too |

### ESIGN vs our `esign.md`
- **[O] Path is `/plugin/sign`** (`data/commands.json` `transport.path`). Our notes say context `/plugin`. **[I]** Tyrus context `/plugin` +
  `@ServerEndpoint("/sign")`. Re-check `WebSocketService`'s annotation in the jar.
- **[O] Request fields are flat at the top level** (`CODE`, `BASE64_VALUE`, `SERIAL_NUMBER`, …). Validation reads `input.get(name)` at the top
  level (`protocol.rs:47-54`), with no nested `INPUT` object. This differs from our `{"CODE","INPUT":{…}}` reconstruction. **[?]** which one the portal sends.
- **[O] Catalogue of 24 codes** with required fields per code (`src/esign/data/commands.json`). `IMP_002` lists 9 SUB_CODEs, `IMP_001`
  is "declared but not dispatched", and `OFFLINE_XML_SIGN_003_NOT_KY` is a code we did not have. This is useful as a cross-check of our list.
- **[O] Implemented:** `CHECK_VERSION` (always `IS_UPDATE:"N"`), and the **"prepared-byte" signers** `CER_001`, `ONLINE_XML_CER_001`, `ONLINE_SUBMIT_SIGNING_001`.
  `BASE64_VALUE` is treated as the exact bytes Java's `Signature.update` receives (the portal-canonicalized SignedInfo). The reply is
  `SIGNED_CONTENT` (base64 signature(s), comma-joined), `CERT`, `CERT_CHAIN` (PkiPath) and `PIN_CODE:""` (`esign/legacy.rs:77-123`, `online.rs:8-9`).
  `CER_001` is forced to **SHA1withRSA**; the ONLINE_* codes use the cert's own algorithm and refuse SHA-1 (`legacy.rs:83-92`).
- **[O] Not implemented (they answer FALSE):** `CER_002`, `CER_CHECK_NTDT`, `NTDT_CER_*`, `JFU_*`, `IMP_*`, `DWN_BKE_001`, `CHOOSE_FILE`,
  `OFFLINE_*`, and `*_002` (`bridge.rs:29-30`). Real XMLDSig building for offline declarations is "in development".
- **[O] Delta:** our notes describe `CER_001` as returning signed XML. MacSigner says it returns a raw signature over portal-prepared bytes. **Verify in the jar before building.**

## 3. Token access
- **[O] PKCS#11 only**, via `cryptoki`, with `C_Initialize(OS_LOCKING_OK)` and one shared context per module path (`token/context.rs:16-32`).
  **No CryptoTokenKit and no Keychain** (no `SecKey`/`SecItem`/CTK code). Software P12/PFX/PEM identities are also supported.
- **[O] Module discovery** (`token/discovery/paths.rs:151-188`, `catalog.rs:19-67`):
  - hardcoded `/Applications/VNPT-CA Token Manager.app/Contents/Resources/libvnptca_p11_v8.dylib` (`data/token-modules.json:80-82`)
  - `$MACSIGNER_PKCS11_MODULES` (colon-separated)
  - bundled `Contents/{MacOS,Resources}/pkcs11/**`
  - recursive walk of `/usr/lib`(5), `/usr/local/lib`(4), `/lib`, `/opt`(6), `/Library`(6), `/opt/homebrew/lib`(3)
  - `/Applications` and `~/Applications` apps whose name contains token|pkcs11|ca2|nacencomm|e-ca|vnpt
  - p11-kit `*.module` files

  A file is a candidate when its name contains `pkcs11|csp11|_p11|p11_|opensc|vnpt|…` (or it exports `C_GetFunctionList`, for portable dirs).
  - **[I] Matches our modules:** `/usr/local/lib/{ncca,cmcca,ica}_csp11_v1.dylib` and `efyca_p11_v1.dylib` are found by name.
  - **[I] Not found:** OneCA/Longmai `/Applications/CryptoIDATools.app/.../libcryptoid_pkcs11.dylib`, because the app name has no hint.
    It is x86_64-only anyway and fails the Mach-O arch check on arm64 (`probe.rs:12-25`). There is no Rosetta helper; the x86 worker is Windows-only (`remote.rs:34`).
- **[O] Probing:** each module is probed in a **child process** (re-exec of its own binary, 8 s timeout, 4 MiB stdout cap) (`probe.rs:59-116`).
  **Signing, however, loads the vendor dylib in-process** in the GUI (`ctsign/signing.rs:569-621`). For that the app is shipped with
  `com.apple.security.cs.disable-library-validation` (`packaging/macos/Entitlements.plist:6`).
- **[O] Signing mechanism:** host-side DigestInfo + **`CKM_RSA_PKCS`** (`ctsign/signing.rs:75-83,145-148`). `load_token` requires
  RSA_PKCS (`:431-437`), and `pkcs11::sign_many` can also use `CKM_SHA*_RSA_PKCS`. Every signature is verified against the cert before it is returned. RSA only (no ECDSA).
- **[O] PIN:** typed in the app's own React dialog, either in the "Sign" view or in a per-request ESIGN approval prompt (120 s timeout,
  `app/src-tauri/src/bridge.rs:23,101-147`). A page-supplied `PIN_CODE` is used only if the user leaves the field empty. The PIN is never stored on disk, but
  **the logged-in PKCS#11 session is kept in memory for the life of the identity** (`Backend::Token{session}`, `signing.rs:614-620`), which
  amounts to an implicit PIN cache until the identities are cleared.
- **[O] Multi-token selection:** by **certificate serial** (normalized hex). It refuses to sign if two loaded certs share a serial
  (`signing.rs:252-257`). ESIGN also filters by `SERIAL_NUMBER` (decimal) and `MST` read from the subject (`legacy.rs:36-73`). Tokens are keyed by (module, slot, CKA_ID).
- **[O] PC/SC:** used only for reader inventory/ATR (`token/reader.rs`) and live plug/unplug (`SCardGetStatusChange`, `app/src-tauri/src/usb.rs`). No APDUs are sent.
- **[O] macOS 27 `0x80100016` fix: absent.** There is no SCardTransmit wrapper, DYLD interpose, or extended-length re-encoding anywhere (grep for
  transmit/80100016/DYLD/interpos/extended found nothing). **[I]** On this Mac, every Feitian vendor lib it loads will hit `CKR_GENERAL_ERROR` exactly as in `runtime-probe.md`.
- **[O] Per-CA ATR byte[19] filter: absent.** The ATR is only displayed. Every discovered module is tried against every slot. Unrecognized-token
  errors (`CKR_TOKEN_NOT_RECOGNIZED` etc.) are skipped (`token/README.md`), so each CA lib still only sees its own tokens. No own
  ePass2003/ENTERSAFE-ESPK driver exists. The macOS VNPT path is "statically confirmed only, never run on a Mac" (`token/README.md`).
- **[O] Token management:** no PIN change/unblock, no init, no cert write, and no renewal. Lifecycle helpers exist (`token/lifecycle.rs`: cert
  snapshot diff, CA-bundle validation gate) but are not wired into the UI. There is no driver installation: "does not download or install vendor software" (`token/README.md`).

## 4. Signing
- **[O] PDF:** a hand-rolled **PAdES B-B**: incremental update via lopdf, `/SubFilter /ETSI.CAdES.detached`, SHA-256, 24 KiB `/Contents`
  (`pdf.rs:1-10,555`). Supports visible appearance (image/text/background, embedded Noto Sans for Vietnamese), multi-signature preservation, and
  classic and xref-stream trailers (`pdf.rs:764-798`). Encrypted PDFs are refused. A verifier is included (`pdf.rs:892+`); it is a ByteRange
  digest plus RSA check, **with no chain, OCSP or CRL validation**.
- **[O] CMS:** hand-rolled DER (`cms.rs`) with signed attributes contentType, messageDigest and **signingCertificateV2**. RSA-SHA256 only.
- **[O] Missing:** **RFC 3161 TSA** (a settings field exists, `commands.rs:690`, but nothing sends it), **LTV/DSS**, **OCSP/CRL** (stated in
  `DISCLAIMER.md`), **XAdES/XMLDSig** (no c14n code at all, so no TT78 `AddXAdESPropertiesTT78` equivalent), **OOXML**, and general CMS/PKCS#7 of arbitrary files.
- **[O] Raw hash:** CTSIGN SignHash (SHA-256 only) and the ESIGN prepared-byte signers. CLI `sign-base64` supports sha1/256/384/512.
- **[I] Correctness concerns:**
  - The PDF writer is new and hand-written (lopdf re-serialization of the AcroForm/page objects). Expect edge cases with object streams, hybrid xref and AcroForm inheritance.
  - The tests validate with the `hayro` parser, not Adobe/eTax validators.
  - `CER_001` = SHA-1 by design.
  - The MST is parsed by searching for `"mst:"` in the subject string, which is fragile with UID vs OID 0.9.2342.19200300.100.1.1 renderings.

## 5. Security review (brief)
- **[O] Bind:** both services bind **127.0.0.1 only**, which is better than the original eSigner's `0.0.0.0`.
- **[O] ESIGN:** strict Origin and Host allowlist, a user approval prompt for **every** request, a 16-connection cap, 1 MiB messages. This is good.
- **[O] CTSIGN, high risk:**
  - `CORS *` with **no Host check** (DNS-rebinding exposure as well).
  - SignHash/signpdf have **no per-request prompt**. They are gated only by a global toggle, "Cho phép trang web ký qua API" (allow web pages to sign via API).
  - A logged-in token session persists.
  - Together these mean **any website can enumerate certs (GetCert needs no toggle) and silently sign arbitrary hashes** while the toggle is on.
  - `signpdf` with `filePath` reads **any local path** (`signing.rs:329-330`) and returns the signed bytes base64. A web page can therefore
    exfiltrate any local PDF it can name.
- **[O] getFileLocal:** stubbed (501).
- **[O] Secrets:** none in the repo. CI uses GitHub secrets. Test fixtures hold TEST-ONLY P12/PEM keys (`tests/fixtures/ctsign/`).
- **[O] Updater:** `tauri-plugin-updater` against GitHub `releases/latest/download/latest.json`, with a minisign pubkey pinned
  (`tauri.conf.json` `plugins.updater`). It **auto-downloads, installs and restarts with no user consent** every 6 h (`updater.rs:22-36`).
  It is disabled with `MACSIGNER_NO_UPDATE=1`. **[I]** Supply-chain trust then rests on a 2-day-old single-maintainer repo.
- **[O] Hardened runtime + `disable-library-validation`:** the app will load any dylib its discovery finds under `/usr/local/lib`, `/opt` or `/Library`.
- **[O] The Tauri `read_file(path)` command** reads any path. It is reachable only from the bundled UI (CSP `default-src 'self'`).

## 6. Code quality, tests, size
- **[O] LOC** (wc -l):
  - core `src/`: token 2,761, ctsign 1,104, pdf.rs 1,016, esign 887, selftest 604, activity 271, cli 257, cms 233, services 216, vnpt 248, crypto 186
  - Tauri backend 1,491 (`commands.rs` 904)
  - UI TS/TSX 4,604
  - tests 1,970
  - Rust total ≈ 11.5k
- **[O] Tests:** about 98 Rust tests (93 `#[test]` + 5 `#[tokio::test]`) covering:
  - wire contracts (CTSIGN byte-for-byte vs a .NET vector, `tests/ctsign_contracts.rs:39`; ESIGN legacy writer fixtures)
  - origin/host rejection, PDF sign→verify, a SoftHSM PKCS#11 path, and discovery/Mach-O parsing

  There are also 11 TS/Node tests. **No hardware tests on macOS.**
- **[I] Quality:** clean layering, careful error and zeroize handling, and honest "not implemented" replies. The comments and docs are
  bilingual and very cautious. It is young (2 days), heavily AI-assisted in style, and its runtime is unverified on real tokens and portals.

## 7. Recommendation: **reference-only, mine the protocol data. Do not fork.**
Reasons, tied to our goals:
1. **Language and platform mismatch.** It is Rust + Tauri + React. We want **Swift native**, and reusing code means rewriting it. Apache-2.0 allows porting with attribution (keep the NOTICE and copyright).
2. **Our hard problems are not solved here.**
   - No macOS 27 SCardTransmit fix, so it cannot sign on this Mac with any Feitian lib.
   - No ATR/customer routing and no own ePass2003/ESPK driver.
   - No OneCA/Longmai (x86_64-only lib, no Rosetta helper).
   - No EFY.
   - No CTK and no token management.
   - No driver installation.
   - Its "token support" claims are Windows-only evidence.
3. **Portal coverage is thin.**
   - Thuế: 3 prepared-byte commands (unverified on the portal). No `CER_002`, `JFU_*` or offline XMLDSig.
   - BHXH: none.
   - Hoá đơn: CTSIGN SignHash/signpdf only; no signxml (TT78), no M-Invoice SignalR, no VNPT plugin.
4. **Its security posture on CTSIGN is weaker than we want.** CORS `*` + silent signing + arbitrary `filePath` read.

**What to reuse (as specs/test vectors, ported to Swift):**
- **CTSIGN wire contract**: corrected SignHash `hash[]{Ma,DLieuHash,CKy}`, `status:200`, GetCert DTO, `sig[]` types 0/1/2/3/5,
  error codes 0/301/403/404/500/501, GetInfoCert `"1"`, Version string. Also take the test vector `tests/fixtures/ctsign/dotnet-vector.json`.
  Update `ctsigninghub.md` once checked against the real binary.
- **ESIGN**:
  - the `commands.json` catalogue (24 codes + required fields + IMP_002 SUB_CODEs)
  - the `/plugin/sign` path and flat-field shape to verify
  - prepared-byte semantics and the CER_001 SHA-1 rule
  - `legacy-writer-fixtures.json` as expected outputs
- **VNPT-CA Plugin** protocol pointer: ports 4433-4435/9201/9202, `{functionID,args,funcCallback,domain}`, `payload*callback` framing,
  function 7/11/13. This is a 4th browser protocol missing from our notes; RE `kyso.vnpt-ca.vn` before Hoá đơn work.
- **Design ideas worth copying:**
  - out-of-process module probing with a timeout
  - Mach-O arch pre-check before `dlopen`
  - an exact Origin+Host allowlist and per-request approval prompt for every browser channel (including CTSIGN)
  - a logout-on-error policy
  - the module-name heuristics list (`token-modules.json`, `catalog.rs:35-62`)
- **PAdES layout reference** (`pdf.rs`, `cms.rs`): useful to read, but on macOS prefer PDFKit for appearance plus our own CMS
  (or a vetted lib), and add TSA, DSS and LTV.

Unknowns to settle ourselves:
- **[?]** whether the portal really sends flat fields and expects a raw signature for CER_001
- **[?]** the real CTSigningHub `Version` string
- **[?]** whether Feitian vendor libs accept host-built DigestInfo with `CKM_RSA_PKCS`: our spike used `CKM_SHA256_RSA_PKCS`, and MacSigner's `load_token` *requires* RSA_PKCS
