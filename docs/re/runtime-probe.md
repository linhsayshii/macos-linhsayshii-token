# Runtime probe — tokens on this Mac (2026-10-21)

Read-only probes only: no login, no PIN. Probe sources live in the session scratchpad (`probe.c`, `pcsc.c`).

## Hardware (system_profiler SPSmartCardsDataType)
4 readers, all Feitian **FT ePass2003Auto**, driver `ifd-ccid.bundle` 1.5.1, protocol T=1:

| Reader | ATR | Owner (per user) |
|---|---|---|
| FT ePass2003Auto    | 3b9f958131fe9f0066465305**34002571**df000032000020 | VNPT |
| FT ePass2003Auto 02 | 3b9f958131fe9f0066465305**34002571**df000032000020 | VNPT |
| FT ePass2003Auto 03 | 3b9f958131fe9f0066465305**10523971**df00003200004a | VNPT? |
| FT ePass2003Auto 01 | 3b9f958131fe9f0066465305**10523971**df000059000021 | NC-CA? |

The VNPT dylib's built-in ATR mask is `3B9F958131FE9F0066465305 ?????? 71DF0000320000` (see vnpt-token-manager.md).

## Results
- PC/SC: `SCardConnect` succeeds on all 4 readers, in both SHARED and EXCLUSIVE mode.
- OpenSC 0.26 `opensc-pkcs11.so`: "token not recognized" on all 4. These tokens use the vendor file system, not PKCS#15.
- `/usr/local/lib/libvnptca_p11_v8.dylib` (SecureMetric, PKCS#11 v2.20, lib v1.20): 3 slots `ES SLOT 1..3`, flags=7 (token present). Every `C_GetTokenInfo` and `C_OpenSession` returns `CKR_GENERAL_ERROR`.
- `ncca_csp11_v1.dylib` (from the cfg.nc-ca.vn dmg, ad-hoc signed): 1 slot. `C_GetTokenInfo` and `C_OpenSession` return `CKR_GENERAL_ERROR`.
- Same result with or without `CKF_OS_LOCKING_OK`, inside or outside the sandbox, and with the VNPT app quit.
- VNPT Token Manager opens no listening TCP port.

## VNPT Token Manager app on this Mac
- Launched from Finder, it fails with `Cannot find module '/build/Release/cryptoki_ext.node'`, because the addon path is relative to the cwd.
- Launched with cwd=`Contents/`, it loads, logs `Detected Slots (3)`, and then the renderer aborts (SIGABRT). The abort is in `cryptoki_ext.node` `PKCS11Manager::GetUSBTokenSlotsString()`: nlohmann::json throws, most likely on garbage label bytes after `C_GetTokenInfo` failed.
- So the official app is broken on this machine for the same root cause as the probe.

## Root cause trace (DYLD interpose on SCard*)
With the VNPT lib, reader `FT ePass2003Auto 03` (T=1), every step before the read succeeds:
- GET DATA `00CA0186` → 9000
- `8050` (get challenge / init) → 9000
- `8482` mutual authentication → 9000
- secure messaging is established
- SM SELECT `0CA4` → 9000

The SM READ BINARY `0CB000000E` then fails with `SCardTransmit` → **0x80100016 SCARD_E_NOT_TRANSACTED**. The CCID driver maps `IFD_COMMUNICATION_ERROR` to this code, so the error is in the driver/transport layer, not a card SW. The lib retries, re-auths, and fails again, and `C_GetTokenInfo` ends up as `CKR_GENERAL_ERROR`.

Environment: macOS 27.2 (26B118), Apple `ifd-ccid.bundle` 1.5.1. The NC-CA lib fails the same way.

Hypothesis: the macOS 27 CCID stack fails on the large SM-wrapped READ BINARY response (>256 bytes, T=1 chaining/extended length).

Candidate fixes:
- (a) Feitian's own CCID driver `ifd-FeiTccid.bundle` (ships in the NC-CA dmg), installed under `/usr/local/libexec/SmartCardServices/drivers`. Needs root.
- (b) Our own ePass2003 driver, ported from OpenSC `card-epass2003.c` (LGPL), that reads files in smaller chunks.
- (c) Wait for an Apple/vendor fix.

### Fix (a) tried: no effect
On 2026-10-21 `ifd-FeiTccid.bundle` 1.4.33 (ad-hoc signed) was installed into `/usr/local/libexec/SmartCardServices/drivers/`. `system_profiler` lists it as Reader Driver #02 next to Apple's `ifd-ccid` 1.5.1.

Result after replugging the tokens: unchanged. The SM READ BINARY `0CB000000E` still returns `0x80100016` (60 occurrences in one probe run), and both the VNPT and NC-CA libs still return `CKR_GENERAL_ERROR`. It is unknown which driver macOS actually binds to the readers, because both match `096E:080A`.

Next step: (b), our own ePass2003 driver. The Feitian driver was removed afterwards (`FEITIAN_REMOVED`).

## Spike (b): OpenSC epass2003 driver, read-only, no PIN (2026-10-21)
Tool: OpenSC 0.27.1 `opensc-explorer -c epass2003`, with Apple `ifd-ccid` 1.5.1 only.

Results:
- **Works on all 4 tokens** (3 VNPT + 1 NC-CA): SM is established, SELECT and READ BINARY succeed, and no `0x80100016` appears.
- Files of 1983, 2131 and 3072 bytes read fully. 35 SM READ BINARY calls, largest response 244 bytes.
- Root cause confirmed: the VNPT lib sends the SM READ BINARY `0CB000000E 97 02 00EF 8E08<mac> EF`, which asks for 239 (0xEF) bytes per chunk. The SM-wrapped response is then about 260 bytes, more than the 258-byte short-APDU maximum, and macOS 27's CCID stack fails on it. OpenSC uses smaller chunks, so its responses stay at 244 bytes or less.

Layout, the same on every token (VNPT and NC-CA are both Feitian/EnterSafe):
- MF holds `2F01` (15 B, an ATR copy) and DF `2003`, named `ENTERSAFE-ESPK`.
- DF 2003 holds `6F01` (1500 B), `9F00`, `2400`/`2420`/`2440`/`2460`, `8000`/`8020` (internal EFs, probably keys), and per-container groups `2480`/`24A0`/`24C0` and `24E0`/`2500`/`2520`.
- Certificate EFs (`24C0`, `2520`) start with a 131-byte vendor header (container metadata plus a UTF-8 CN) followed by the DER X.509 certificate. The header length field sits at offset 127 (u32 LE).

Two VNPT certificates were read from reader 0: one issued by VNPT-CA SHA-256 (expired 2025-07-28) and one by VNPT-CA SHA2 (valid until 2027-11-01).

Implication: OpenSC's epass2003 SM/APDU layer works on this Mac. What OpenSC lacks is a PKCS#15 emulator for the `ENTERSAFE-ESPK` layout, so `opensc-pkcs11.so` reports "token not recognized".

## Real root cause and a working fix for the vendor libs (2026-10-21)
The VNPT lib encodes its SM READ BINARY as **short Lc + a 2-byte Le**: `0C B0 00 00 0E <97 02 00EF 8E 08 mac> 00 EF`, 21 bytes. That is not a valid ISO 7816-4 encoding. macOS 27's CCID rejects it with `0x80100016`, while older stacks presumably passed it through. The NC-CA lib does the same.

The fix is a `DYLD_INSERT_LIBRARIES` interposer on `SCardTransmit` (`fix.c` in the scratchpad). It re-encodes only this malformed form (CLA&0x0C, `il == 7 + Lc`) as extended length: `CLA INS P1 P2 00 00 Lc <data> 00 EF`. The MAC covers the header and DOs, not the Lc/Le encoding, so SM stays valid. Valid short APDUs are left untouched, because re-encoding them gives `6A80`.

Result with the vendor libs unmodified:
- VNPT `libvnptca_p11_v8.dylib`: all 3 tokens work. `C_GetTokenInfo` OK, label `VNPT-CA PKI Token`, 2 certs each. 142 extended READ BINARY calls, all 9000.
- NC-CA `ncca_csp11_v1.dylib`: the token works, label `NC-CA Token v1.0`, 1 cert.

Implication: the vendor PKCS#11 modules are usable on macOS 27 if our app supplies the PC/SC transport shim. Our app loads the modules itself and can therefore interpose or wrap PC/SC.

Superseded by the shim, and not done: own-driver PIN tests. The `82 01 81` probes for retry counters returned `6985`, so no further key-auth APDUs were sent.

### Sign spike: VNPT, vendor lib + shim, PIN entered by the user via getpass
Setup: token serial `8377200522219143`, `C_Login` returns OK.

Each of the 2 private keys signed the fixed test message with `CKM_SHA256_RSA_PKCS`, producing a 256-byte signature (RSA-2048):

| Key | Issuer | Expiry | `openssl dgst -sha256 -verify` |
|---|---|---|---|
| key0 | VNPT-CA SHA-256 | expired 2025-07-28 | **Verified OK** |
| key1 | VNPT-CA SHA2 | valid until 2027-11-01 | **Verified OK** |

APDU flow: login sent 1× `0C84` (GET CHALLENGE) and 1× `0C82` (external auth, done by the vendor lib). Signing sent 2× `0C22` (MSE) and 4× `0C2A` (PSO). The run had zero `0x80100016` errors.

**Conclusion: VNPT signing works end to end on macOS 27 with the unmodified vendor lib plus our PC/SC shim.**

### Sign spike: NC-CA, vendor lib `ncca_csp11_v1.dylib` + the same shim
Token serial `540E2507021196`. `C_Login` returns OK.

The token holds 1 private key. It signed with `CKM_SHA256_RSA_PKCS` and produced a 256-byte signature, which **verified OK** against the cert.

The cert is issued by NC-CA SHA256 (O=CÔNG TY CỔ PHẦN CÔNG NGHỆ NCCA) and is valid until 2029-03-17.

The APDU flow matches VNPT:
- 1× `0C84` + 1× `0C82` for login
- 1× `0C22` + 2× `0C2A` for signing
- zero `0x80100016` errors

**Conclusion: both sample CAs (VNPT, NC-CA) sign end to end on macOS 27 with unmodified vendor libs plus the PC/SC shim.**

## Multi-CA scan (2026-10-21): 7 tokens, read-only, no PIN
Probe: OpenSC `epass2003`, reading DF 2003 and extracting the DER certificate from each large EF.

| Reader | Hardware | ATR customer byte [19] | Layout | Cert issuer CN (expiry) |
|---|---|---|---|---|
| FT ePass2003Auto    | Feitian | 0x32 | ENTERSAFE-ESPK | VNPT-CA SHA-256 (2025-07) + VNPT-CA SHA2 (2027-11) |
| FT ePass2003Auto 02 | Feitian | 0x32 | ENTERSAFE-ESPK | VNPT-CA SHA-256 (2025-07) + VNPT-CA SHA2 (2029-08) |
| FT ePass2003Auto 01 | Feitian | 0x59 | ENTERSAFE-ESPK | NC-CA SHA256 (2029-03) |
| FT ePass2003Auto 05 | Feitian | 0x69 | ENTERSAFE-ESPK | FastCA SHA-256 R1 (2026-07, **expired**) |
| FT ePass2003Auto 04 | Feitian | 0x61 | ENTERSAFE-ESPK | CMC-CA (2029-09) |
| FT ePass2003Auto 03 | Feitian | 0x72 | ENTERSAFE-ESPK | I-CA (2027-01) |
| Longmai mToken OneCAV3 | **Longmai** (ATR `3b9f1181...6a6d546f6b656e...` = "mToken") | n/a | n/a | OpenSC: "Unsupported card" |

Findings:
- **5 of the 6 CAs use the same Feitian ePass2003 + ENTERSAFE-ESPK layout, and OpenSC reads all of them with the default SM keys.** The SM keys are therefore not CA-specific.
- The cert-EF vendor header length varies by CA (81–131 bytes) because it embeds a UTF-8 CN, so the parser must read the header length field rather than assume a fixed 131. The same EF IDs are not used for every container: `24C0`, `24E0`, `2520` and `2580` were all seen.
- The vendor libs only accept their own CA's tokens. The VNPT lib (with shim) sees only the 0x32 tokens, and the NC-CA lib only the 0x59 token.
- There are two filters:
  - (1) the ATR customer byte [19]. Spoofing it to 0x32 (TCK recomputed) makes the VNPT lib enumerate every Feitian token.
  - (2) after SM, the lib reads `GET DATA 01 81` / `01 84` (SM-encrypted, 67/35 bytes), then gives up on non-VNPT tokens. A customer/vendor ID in that data object is the likely check. Not decoded.

Implication for the design:
- Per-CA vendor libs mean one dylib per CA, each with its own filter: VNPT and NC-CA are available, FastCA, CMC and I-CA are not yet located.
- One own ePass2003/ESPK driver covers all 5 Feitian CAs. Reading is proven. Signing still needs our own PIN external-auth, whose derivation is not yet confirmed against ESPK.
- OneCA (Longmai mToken) needs OneCA's own macOS PKCS#11 module.

Not tested yet:
- own-driver PIN external-auth + sign (confirm the derivation statically from the VNPT lib's C_Login first, so no PIN retries are spent)
- OneCA module
- private-key EF mapping
- `PSO: COMPUTE DIGITAL SIGNATURE`

## More CAs: CMC, I-CA, EFY (2026-10-21, read-only)
Vendor dylibs are extracted statically; see cmc-ica.md for CMC and I-CA. For EFY, `efyca.vn/download/tokenV1/macosx/efyca_p11_v1.pkg` is an unsigned pkg containing a 2019 Feitian build.

| CA | ATR byte [19] | Module | Arch | Shim off | Shim on |
|---|---|---|---|---|---|
| CMC | 0x61 | `cmcca_csp11_v1.dylib` (Feitian Dev ID S47T4UESP3) | x86_64+arm64 | CKR_GENERAL_ERROR | **OK**: label `CMC-CA Token v1.0`, 1 cert |
| I-CA | 0x72 | `ica_csp11_v1.dylib` (Feitian Dev ID S47T4UESP3) | x86_64+arm64 | CKR_GENERAL_ERROR | **OK**: label `ICA Token v1.0`, 1 cert |
| EFY | 0x51 | `efyca_p11_v1.dylib` (unsigned) | **i386+x86_64 only** | Rosetta: 1 slot `ES SLOT 1`, no token | same |

The EFY lib fails because it never calls `SCardEstablishContext`/`SCardConnect` on macOS 27, and `C_GetSlotInfo` returns garbage. Likely causes:
- It builds reader names itself in the old pcsc-lite style `FT  ePass2003Auto %.2d` (two spaces), with no `SCardListReaders` import, while macOS names the reader `FT ePass2003Auto`.
- It links `/usr/lib/libstdc++.6.dylib`.

Not pursued further: EFY should be covered by our own ePass2003/ESPK driver instead.

Status of the ATR customer-code map: 0x32 VNPT, 0x59 NC-CA, 0x61 CMC, 0x72 I-CA, 0x69 FastCA, 0x51 EFY.

## PIN external-auth: reconciled view (2026-10-21)
Sources: pin-auth-feitian.md (NC-CA, CMC, I-CA, FastCA: one codebase), pin-auth-vnpt.md (SecureMetric), and OpenSC card-epass2003.c.

Agreed by all three (Observed):
- The flow is GET CHALLENGE (8 bytes), then EXTERNAL AUTHENTICATE `00 82 01 (80|kid)` with Lc=8, all wrapped in SM.
- The cryptogram is 3DES-EDE3-CBC, IV=0, using a key of exactly 24 bytes.
- kid 1 = user PIN, kid 2 = SO PIN. VNPT selects DF 2003 first.
- Retries are read with `82 01 (80|kid)` as CASE_1 with no data: SW 63Cx gives the count, 6983 means blocked.
- The default SM keys are `01..10` for both enc and mac, so the SM keys are not CA-specific.

The 24-byte key layout is Inferred by both static passes, which could not byte-trace it through vtables or dispatch. Two candidates remain:
- **A (OpenSC `hash_data`)**: `SHA1(PIN as typed) || BE32(len(PIN))`. OpenSC's `epass2003_pin_cmd` passes the raw PIN to `external_key_auth` (`NEED_PADDING` only affects ISO PIN APDUs).
- **B**: `SHA1(PIN zero-padded to 16) || 00 00 00 10`.

A wrong candidate costs one PIN retry; it is not free. Plan: try A first on the FastCA token, whose cert has expired. If A fails, try B. Stop after 2 failures. To restore the counter, log in once with the official FastCA software in the Windows VM.

Signing differs. VNPT sends two PSOs: an on-card PSO:HASH `2A 90 ..` followed by PSO:COMPUTE. OpenSC hashes on the host and sends a single PSO; for RSA that is `2A 80 86` with a host-built PKCS#1 block, behaving like a raw decipher. We do not yet know which form ESPK keys accept. Test the OpenSC form first, then fall back to the VNPT two-step form.
