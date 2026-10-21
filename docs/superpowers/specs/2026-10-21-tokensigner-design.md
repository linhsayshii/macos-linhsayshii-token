# TokenSigner — all-in-one macOS signing app for Vietnamese CA tokens

Status: approved design, 2026-10-21. Personal use: one user, one Mac (Apple Silicon, macOS 27).
Evidence: every protocol and token fact below comes from `docs/re/*.md`. Facts that are inferred
rather than observed are marked **(verify)**.

## 1. Goal

One native macOS app that replaces four Windows/Java signing bridges, so web portals can sign
with the user's USB tokens on a Mac. The four bridges are CTSigningHub, eSigner, M-Invoice
Plugin and VNPT-CA Plugin. The portals are Thuế, BHXH, Hoá đơn and Dịch vụ công.

The app also signs local files and manages tokens: certificate info, expiry and PIN change.

Out of scope:
- Windows and Linux.
- Online unlock or certificate activation through CA private APIs.
- Re-implementing CA drivers. FastCA and EFY stay unsupported until a working PKCS#11 module
  exists; the user signs them through the vendor Windows tools in Parallels.

## 2. Token support matrix (from runtime probes)

| CA | Hardware | ATR byte[19] | PKCS#11 module | Read | Sign |
|---|---|---|---|---|---|
| VNPT | Feitian ePass2003 | 0x32 | `libvnptca_p11_v8.dylib` (universal) | ✓ | ✓ verified |
| NC-CA | Feitian ePass2003 | 0x59 | `ncca_csp11_v1.dylib` (universal) | ✓ | ✓ verified |
| CMC | Feitian ePass2003 | 0x61 | `cmcca_csp11_v1.dylib` (universal) | ✓ | (verify) |
| I-CA | Feitian ePass2003 | 0x72 | `ica_csp11_v1.dylib` (universal) | ✓ | (verify) |
| FastCA | Feitian ePass2003 | 0x69 | none for macOS | — | unsupported |
| EFY | Feitian ePass2003 | 0x51 | `efyca_p11_v1.dylib`: i386/x86_64 only, does not see tokens on macOS 27 | — | unsupported |
| OneCA | Longmai mToken (USB 055c:0223) | n/a | `libcryptoid_pkcs11.dylib`: x86_64, unsigned, reseller source | untested | untested (P4) |

Known macOS 27 defect: the Feitian vendor libraries send SM APDUs encoded as short Lc with a
2-byte Le, and the system CCID stack rejects them with `SCardTransmit` → `0x80100016`. Fix
(proven): an `SCardTransmit` interposer re-encodes exactly that malformed form
(`CLA & 0x0C == 0x0C`, `len == 7 + Lc`) as extended length. Valid short APDUs stay untouched.
The MAC covers header + data objects, not Lc/Le, so SM stays valid. See
`docs/re/runtime-probe.md`.

## 3. Architecture

```
TokenSigner.app (arm64, SwiftUI MenuBarExtra, login item)
├─ Bridges   CTSigningHub :32001 | eSigner :8768 | VNPT-CA Plugin :4433 (wss) | M-Invoice :16080
├─ Core      SigningService · ApprovalCenter · AuditLog · Settings
├─ UI        menu bar · approval sheet · PIN sheet · token window · settings/allowlist
└─ TokenBroker ── stdin/stdout JSON-RPC ──► token-helper (one process per PKCS#11 module)
                                              arm64:  vendor dylib + linked SCardTransmit shim
                                              x86_64: same binary run via `arch -x86_64` (Longmai)
```

- **Helper per module.** It spawns lazily when a token of that CA appears. Each module runs in
  its own process for three reasons: every vendor lib exports `C_*` and keeps its own PC/SC
  locks, a vendor-lib crash kills only that helper (VNPT's own app aborts inside its addon), and
  x86_64-only modules need a Rosetta process. The app restarts a dead helper, and the in-flight
  request fails with an error.
- **Shim** is an `__interpose` section compiled into `token-helper` itself, so no
  `DYLD_INSERT_LIBRARIES` is needed. It is a pure function `reencode(apdu) -> apdu?` with unit
  tests.
- **Module routing.** The app reads readers and ATRs with PC/SC directly, takes ATR byte[19],
  and looks it up in a table (`ModuleRegistry`). Supporting a new CA means adding one row.
- **Module discovery.** The app looks in known install paths (`/usr/local/lib/<name>.dylib`) and
  in `~/Library/Application Support/TokenSigner/modules/`.
- **Packaging.** The repo is a SwiftPM package with targets `Core`, `Bridges`, `TokenHelper`
  and `App`. `scripts/bundle.sh` assembles `TokenSigner.app`: it embeds
  `Contents/Helpers/token-helper` (universal) and ad-hoc signs with
  `com.apple.security.cs.disable-library-validation`, which is needed to load third-party-signed
  dylibs.
- **Dependencies** (Apple only): `swift-nio` (+ `NIOHTTP1`, `NIOWebSocket`, `NIOSSL` for :4433),
  `swift-asn1` and `swift-certificates`. XML C14N uses Foundation's
  `XMLNode.canonicalXMLStringPreservingComments`.

## 4. Token layer

The app and a helper talk JSON-RPC over stdin/stdout, one JSON object per line. Each token runs
one call at a time; batches queue.

| Method | Params | Result |
|---|---|---|
| `listTokens` | — | `[{slot, reader, serial, label, flags}]` |
| `listCerts` | `serial` | `[{id, derB64, subject, issuer, serialHex, notBefore, notAfter}]` |
| `login` | `serial, pin` | `ok` \| `{pinIncorrect, retriesLeft?}` \| `pinLocked` |
| `sign` | `serial, certId, mech, dataB64` | `{sigB64}` |
| `logout` | `serial` | `ok` |
| `changePIN` (P4) | `serial, old, new` | `ok` \| error |
| event `tokenRemoved` | `serial` | — |

- `mech` takes two values:
  - `SHA256_RSA_PKCS`: the helper hashes. Verified on VNPT and NC-CA.
  - `RSA_PKCS`: the caller sends a ready DigestInfo. This is needed for hash-only signing.
    **(verify, first task of P1)**
- PIN: the user types it in a `SecureField` and it goes over the pipe to `C_Login`. The app
  zeroes its copy after sending. It is never written to disk or Keychain.
- Session: a token stays logged in for 10 minutes (configurable). The app calls `C_Logout` on
  timeout, token removal, screen lock or quit.
- Token flags drive the PIN sheet warnings: `USER_PIN_COUNT_LOW`, `USER_PIN_FINAL_TRY` (red
  "còn 1 lần") and `USER_PIN_LOCKED` (input disabled).

## 5. Bridges

Each bridge only translates its wire protocol into Core calls (`getCerts`, `signHash`,
`signXML`, `signPDF`, `signCMS`). No format logic lives in bridges.

| Bridge | Transport | Phase | Endpoints in scope | Source |
|---|---|---|---|---|
| CTSigningHub | HTTP `127.0.0.1:32001`, `api/{controller}/{action}` | P1 | `GET SignHash/Version`, `GET HubClient/GetCert`, `GET Info/GetInfoCert`, `POST HubClient/SignHash`; P2 `signxml`; P3 `signpdf` | ctsigninghub.md, macsigner-repo.md |
| eSigner | WS `127.0.0.1:8768/plugin/sign` (8769 fallback) | P2 | `{CODE, INPUT}` → `{CODE, SUCCESS, …}`, about 24 codes (CER_001 sign, CER_002 get cert, …) | esigner.md |
| VNPT-CA Plugin | WSS `127.0.0.1:4433/plugin/*` | P2 | `Connector{functionID, funcCallback, args[]}` → `{code, data, error}`; GetCertInfo=0, SignXML=1, SignPDF=2, SignCMS=4, signHash=9, getVersion=11, SetLicenseKey, CheckPlugin | vnpt-plugin.md |
| M-Invoice | ASP.NET SignalR classic, `localhost:16080/signalr`, hub `handlerHub` | P3 | `GetVersion`, `GetCommandInfo`, `SwichTask` → SignInvoices/SignSS04/… | minvoice-plugin.md |

Open protocol questions, each settled by capturing real traffic from the vendor tool in a
Parallels Windows VM before its bridge is coded:
- **CTSigningHub:** is `SignHash` input `hash[]{Ma, DLieuHash, CKy}` with `status:200`
  (MacSigner) or `{hash, serinumber}` (our RE)? **(verify)**
- **eSigner:** is the request nested `INPUT` (AppConstants supports this) or flat (MacSigner)?
  **(verify)**
- **VNPT-CA Plugin:**
  - The portal sends a signed license via `SetLicenseKey`. The app accepts and stores it, but
    access control is our origin allowlist, not the license.
  - TLS needs our own certificate: on first run the app generates a local CA plus a
    `localhost`/`127.0.0.1` leaf with SAN, and asks the user to trust the CA in the login
    keychain. The vendor key is never reused.

Not implemented on purpose:
- `getFileLocal`.
- Any `filePath` parameter, which would read arbitrary files. Only base64 `dataFile` is accepted.
- Binding to anything except `127.0.0.1`.

### Web defense (all bridges)
- `Host` header must be `127.0.0.1:<port>` or `localhost:<port>` (DNS-rebinding guard).
- CORS: echo `Access-Control-Allow-Origin` only for allowlisted origins, and answer preflight
  with `Access-Control-Allow-Private-Network: true`. WebSocket bridges check `Origin` at
  handshake.
- Allowlist is stored at `~/Library/Application Support/TokenSigner/origins.json`. Defaults:
  - `*.gdt.gov.vn`
  - `dichvucong.gov.vn`
  - `*.dichvucong.gov.vn`
  - `*.baohiemxahoi.gov.vn`
  - `*.minvoice.vn`
  - `*.minvoice.com.vn`
  - `*.minvoice.net`
- An unknown origin gets a prompt asking whether to add it. Requests from it are rejected until
  the user allows it.

### Approval (session-based)
- Key = (origin, cert serial). The first request opens an approval sheet showing:
  - the origin
  - the cert subject, CA and expiry
  - the operation and document count
  - three actions: **Cho phép 10 phút** (primary), **Chỉ lần này**, **Từ chối**
- If the token is not logged in, the PIN sheet follows the approval.
- Inside an active session, requests are auto-approved and the menu bar shows "Đang ký N".
- Expired certificates are blocked with a warning; there is no override.
- Audit log (`audit.jsonl`): time, origin, bridge, cert serial, operation, SHA-256 of input,
  result. It never contains PINs or document content.

## 6. Signing formats (Core)

`protocol Signer { func sign(digestInfo: Data) async throws -> Data }`. Real tokens implement it
through TokenBroker, and tests use a software `SecKey`.

| Format | Phase | Spec | Verified in tests by |
|---|---|---|---|
| Raw hash | P1 | SHA-256 (32B) / SHA-1 (20B) → DigestInfo → `RSA_PKCS` | `openssl pkeyutl -verify` |
| XMLDSig enveloped | P2 | See notes below | `xmlsec1 --verify` |
| CMS / PKCS#7 detached | P2 | SignedData with signed attrs `contentType`, `messageDigest`, `signingTime`, `signingCertificateV2` | `openssl cms -verify` |
| PDF PAdES-B-B | P3 | Incremental update, `/Sig` + `/ByteRange` + reserved `/Contents`, CMS detached (same builder), invisible signature | `pdfsig` |
| OOXML | later | — | — |

XMLDSig enveloped details:
- inclusive C14N, SHA-256, `rsa-sha256`
- `KeyInfo` = `X509Data` + `RSAKeyValue`
- TT78 `SigningTime` in `ds:Object/SignatureProperties`, referenced by `#id`
- placement XPaths per document type, for example `HDon/DSCKS/NBan` and `TKhai/DSCKS/NNT`
- SHA-1 / `rsa-sha1` variant for portals that require it

Deferred, because no target portal requires them yet: TSA (B-T), LTV, OCSP/CRL embedding. If
`swift-certificates` cannot use an external signer, SignedData is built directly with
`swift-asn1`.

Golden tests: sign the same input with the vendor tool (Parallels) and with TokenSigner, then
compare structure (transforms, references, attribute order).

## 7. UI

Built to the evon `ui-ux` standard, translated to SwiftUI. Path: "dựng luôn" (no wireframe gate,
by user decision). Style: flat (direction A, hairline). **Light mode default**; the app forces
`.preferredColorScheme(.light)`. Dark mode is not built.

Tokens live in one file, `App/Theme.swift`, and nothing else hard-codes colors:

| Token | Value | Use |
|---|---|---|
| `primary` / `primaryHover` / `onPrimary` | `#181818` / `#2e2e2e` / `#ffffff` | primary button (one per sheet) |
| `background` | `#f4f4f6` | window background (never pure white) |
| `surface` | `#ffffff` | cards, inputs |
| `foreground` / `muted` | `#2c2c2c` / `#707070` | text primary / secondary |
| `border` / `borderStrong` | `#f7f7f8` / `#eaeaea` | card hairline / input + outline button |
| `itemHover` / `secondary` | `#f4f4f6` / `#e7e8ec` | row hover / selected row, secondary button |
| `danger` / `dangerBg` | `#c70036` / rose-500 at 10% | Đăng xuất token, Từ chối, Xoá origin |
| `success`, `warning`, `neutral` (+`Bg`) | emerald-700 / amber-700 / zinc-600 on -50 | status badges |
| `errorText` | `#e7000b` | inline error under an input |

Layout and type rules:
- **Brand swap point:** `primary*` in `Theme.swift`. The font is the system font (SF Pro): one
  family, roles set by weight (600 headings, 400 body, 500 labels/buttons).
- **Type scale**, using exactly these steps:
  - 11 (`xs`): labels, timestamps
  - 13 (`sm`): app default
  - 15 (`base`): card title
  - 17 (`lg`): section title
  - 20 (`xl`): window title
- **Spacing:** 4/8/12/16/20/24/32/40 only, with half-steps 2/6/10 inside controls. Window
  padding is 16, card padding 16–20, grid gap 12.
- **Radius:** 12 for elements ≥ 40pt tall, 8 below 40pt. Inputs and form buttons are 40pt tall.
- **Shadow:** none in content. Only popovers and sheets get the system elevation.
- **Buttons:** four kinds: `outline` (default), `primary`, `secondary`, `ghost`. Danger is
  `ghost` on a `dangerBg` fill, always visible. Hovering an outline button changes only the fill
  (`#f1f1f3` on surface); the border stays. There are no focus rings on buttons, rows or tabs;
  text inputs get a `borderFocus` plus a 2pt ring of `primary` at 10%.
- **Inputs:** no leading icon. A required-field `*` is red.
- **Copy:** Vietnamese. Danger actions (Đăng xuất token, Từ chối, Xoá) are red per evon `I4`.

Screens:
1. **Menu bar popover:**
   - status line (bridges up, ports in conflict)
   - token list: CA badge, serial, cert CN, expiry badge, login state, ghost-danger "Đăng xuất"
   - bridge list with port status
   - last 10 signings
   - footer links: Quản lý token, Cài đặt, Thoát
   - icon states: normal / attention (PIN or approval pending) / error (port taken, for example
     by the original CTSigningHub)
2. **Approval sheet:** origin, cert card, operation summary, and the three actions from §5.
3. **PIN sheet:** CA, serial, `SecureField` (40pt), retry warning badge, Huỷ / Đăng nhập.
4. **Token window (P4):** cert detail as a description list, export `.cer`, expiry warning (30
   days), Đổi PIN.
5. **Settings:** session timeout, allowlist editor, module paths and status ("Driver" section:
   detect, download the official pkg over verified TLS, show SHA-256, extract only the dylib
   into the app modules dir with no sudo), localhost certificate trust status, launch at login.

Every list has an empty state ("Chưa cắm token", "Chưa có lần ký nào"), a loading state and an
error state.

## 8. Phases

| Phase | Deliverable | Done when |
|---|---|---|
| P1 | Package skeleton, Theme, ModuleRegistry, token-helper + shim, TokenBroker, PIN + approval sheets, menu bar, raw-hash Core, CTSigningHub bridge (Version, GetCert, GetInfoCert, SignHash) | A VNPT token signs a hash through `curl` against `:32001`, and openssl verifies it; the NC-CA token does the same |
| P2 | XMLDSig + CMS in Core; eSigner bridge; VNPT-CA Plugin bridge (WSS + local CA); CTSigningHub `signxml` | eTax test submission signs; DVC test signs |
| P3 | PDF PAdES-B-B; CTSigningHub `signpdf`; M-Invoice SignalR bridge | minvoice invoice signs |
| P4 | Token window, Đổi PIN, driver section, OneCA via x86_64 helper (if the Longmai module works), CMC / I-CA sign verification | — |

## 9. Testing

- **Unit:**
  - shim `reencode` with the 21-byte VNPT trace vector and the untouched short form
  - `ModuleRegistry` routing
  - DigestInfo builder
  - origin/Host matching
  - approval session expiry
- **Core:** each format signed with a software `SecKey`, then verified with openssl, xmlsec1 or
  pdfsig. A test is skipped if its tool is missing.
- **Bridge contracts:** JSON fixtures from `docs/re` and the MacSigner fixtures, replaced by
  Parallels captures as they arrive.
- **Hardware:** `TOKEN_TESTS=1` gates the manual tests, where the user enters the PIN. Never run
  in CI.

## 10. Risks

| Risk | Mitigation |
|---|---|
| Feitian libs may reject `CKM_RSA_PKCS` | First task of P1. If rejected, research alternatives before building SignHash |
| Portal-specific XML/PDF quirks | Golden captures from the vendor tools via Parallels |
| Port collision with the installed originals (CTSigningHub/eSigner) | Detect at start, show the error state, offer guidance |
| Vendor dylibs change or break on macOS updates | Isolation in helpers; the shim is narrowly scoped and unit tested |
| VNPT-CA Plugin needs a trusted local TLS cert | Own local CA, the user trusts it once; status shown in Settings |
