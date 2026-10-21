# Signing with the FastCA token on macOS 27 — legitimate options (2026-10-21)

Goal: sign with the user's own FastCA USB token (Feitian ePass2003Auto, ENTERSAFE-ESPK
layout, ATR customer byte `0x69`, cert from FastCA SHA-256 R1) on macOS 27 / Apple Silicon,
using vendor-supported software rather than a home-grown token driver.

All analysis below was **static and read-only**. Nothing was installed or run against the
token, no PIN was entered. Downloaded files were treated as untrusted data, mounted/expanded
read-only, and inspected with `lipo`, `codesign`, `pkgutil`, `nm`, `otool`, `strings`.

Scratch (untrusted, never executed): `/private/tmp/fastca-mac-94626/`.

Related notes: [`runtime-probe.md`](runtime-probe.md) (the PC/SC transport bug and the shim
that fixes it), [`fastca-oneca.md`](fastca-oneca.md) (the earlier hunt that found no FastCA
mac build), [`cmc-ica.md`](cmc-ica.md) (the sibling Feitian CA dylibs and their ATR filter).

---

## TL;DR — ranked

| # | Option | Vendor-supported? | arm64 | Effort | Confidence |
|---|---|---|---|---|---|
| 1 | **Official Feitian ePass2003 macOS PKCS#11 (`libcastle`)**, obtained from the HYP2003 / Castle installer, plugged into `ModuleRegistry` | Yes (Feitian's own middleware; FastCA's Windows module is the same codebase) | Yes, universal | Low–medium | **High** for reading; medium for signing (transport caveat) |
| 2 | Get an official macOS module from **FastCA / CyberLotus** (the issuer) | Yes, canonical | unknown | Low (a support request) | Low that one exists |
| 3 | Get the generic **EnterSafe/ePass2003 mac middleware from Feitian** directly | Yes | likely | Low–medium | Medium |
| 4 | **Fallback: Windows VM (Parallels) + official FastCA Windows software**, hand documents from the mac app | Yes, fully official | n/a (x86/arm Windows) | Medium–high | High that it works |

Option 1 is the recommendation: it is real Feitian middleware, Developer-ID signed and
Apple-notarized, universal (arm64), and — verified below — it does **not** filter the token
by customer code, so it accepts the `0x69` FastCA token. It loads through the same
`ModuleRegistry` + PC/SC-shim path the app already uses for the VNPT/NC-CA/CMC/I-CA dylibs.

---

## Option 1 — Official Feitian ePass2003 macOS middleware (`libcastle`) — RECOMMENDED

### What it is
FastCA's token is a stock Feitian ePass2003Auto, and FastCA's Windows module `fca_v1.dll`
is a rebranded Feitian "EnterSafe CSP PKCS11 Library" (see `fastca-oneca.md` §2). Feitian
ships a **generic** macOS build of that same middleware, `libcastle_v2.x.x.x.dylib`, with
every ePass2003/EnterSafe token. The sibling Vietnamese CA dylibs
(`ncca_csp11_v1.dylib`, `cmcca_csp11_v1.dylib`, `ica_csp11_v1.dylib`) are per-CA rebuilds of
this same codebase (same Feitian Team ID `S47T4UESP3`, same `_E_GetAuxFunctionList` export).
The difference that blocks them from the FastCA token is their ATR customer-byte filter.
The generic `libcastle` build does **not** have that filter.

### Source / evidence (verified on this Mac, 2026-10-21)
Package: `HYP2003-India_20250213.dmg`, inside `HYP2003-MAC-iOS.zip`.

- Download URL (Hypersecu CDN; their own download page shows Windows only):
  `https://www.hypersecu.com/_files/archives/5aae8d_455153f9dcfa4f98a57824244cc520a3.zip?dn=HYP2003-MAC-iOS.zip`
- `hyp.zip` sha256 `a57a1efb7d278fd0e8ca8bf9803faf7b6cd804e789f443e71aa06cf6105cca62` (7,915,040 B)
- `HYP2003-India_20250213.dmg` sha256 `72a95d4014e71faa0fc5e25d1129abeac277398781433fbd188748c907efc9a7` (6,492,515 B, 2025-02-13)
- Installer pkg `HYP2003-India_20250213.pkg`: **Developer ID Installer: FEITIAN Technologies
  Co.,Ltd. (S47T4UESP3)**, **notarized** by Apple, trusted timestamp 2025-02-13.

Files extracted from the pkg payload (copied out, inspected, nothing installed):

| File | Payload path | sha256 | Arch | Signature |
|---|---|---|---|---|
| `libcastle_v2.1.0.0.dylib` (PKCS#11, 3,717,296 B) | `pkcs11.pkg/Payload/` | `3e7b9e91a861fccbafa9e992daa4c3c4746d9a20eb99e2f43ac860037159cf9c` | x86_64 + arm64 | Dev-ID App FEITIAN `S47T4UESP3`, hardened runtime, `--verify --strict` OK |
| `ifd-FeiTccid.bundle` / `libccid.dylib` (CCID reader driver, 1.4.33) | `kext.pkg/Payload/` | `9a4d97a5124f9215e289f1bc6cd681124e80162aa8a54681e86cbbfe5f646c4c` | x86_64 + arm64 | Dev-ID App FEITIAN `S47T4UESP3`, hardened runtime, strict OK |

`libcastle` exports the 68 standard `C_*` functions plus `E_GetAuxFunctionList`, links
`PCSC.framework` (so the app's SCardTransmit shim applies), and its strings include
`ENTERSAFE-ESPK`, `ES SLOT %lu`, `EnterSafe HYP2003 CSP v1.0`, `Hypersecu`.

### The decisive check: no customer-code filter
`libcastle` carries one ATR value+mask at arm64 offset `0x188192` (identical bytes in the
x86_64 slice):

```
value 3b 9f 95 81 31 fe 9f 00 66 46 53 05 00 00 00 71 df 00 00 00 00 00 00
mask  ff ff ff ff ff ff ff ff ff ff ff ff 00 00 00 ff ff ff 00 00 00 00 00
                                                          ^byte19
```

Mask byte 19 (the customer code) = `0x00` → **wildcard**. The sibling VN dylibs use the
same value layout but mask byte 19 = `0xFF`, which pins it to their own CA
(`cmc-ica.md` §"PKCS#11 dylibs"): NC-CA `0x59`, CMC `0x61`, I-CA `0x72`. `libcastle`
masks out bytes 18–22 entirely, so it matches the common ePass2003 ATR header and accepts
**any** customer code, including FastCA's `0x69`.

No VNPT-style secondary customer-ID string was found in `libcastle` (searched for
`customer` / `vendor` / `product id` / `appname`; only `CKR_VENDOR_DEFINED` and the generic
`Hypersecu` / `HYP2003` branding appear). This is consistent with a CA-agnostic module.

### How to obtain (legitimately)
- The Hypersecu zip above is the cleanest universal/notarized source and is the one tested
  here. It is Feitian's binary, Feitian-signed; Hypersecu/Indian CAs only host it.
- Alternative official source of the same `libcastle` family: **Hong Kong Post e-Cert**
  publishes "e-Cert Token (FEITIAN) Client Tool - Mac" as `ePass2003-Castle.dmg`
  (`https://www.ecert.gov.hk/product/download/token_f/index_text.html`). Older/Intel-era in
  the guides; prefer the 2025 universal Hypersecu build.
- Most correct: ask **Feitian** (Option 3) for the current generic EnterSafe/Castle macOS
  PKCS#11 for ePass2003, or ask **FastCA** (Option 2) for their own.

### Integration (fits the existing app)
- Drop `libcastle_v2.1.0.0.dylib` into `ModuleRegistry` next to the VNPT/NC-CA/CMC/I-CA
  modules. Detect by ATR customer byte `0x69`; use the reported label (`ES SLOT …` /
  `EnterSafe HYP2003`) for display only, not detection.
- Same Dev-ID-mismatch constraint as the other vendor dylibs: a hardened-runtime host needs
  `com.apple.security.cs.disable-library-validation`, or load it in a helper. Team ID is
  `S47T4UESP3`, same as CMC/I-CA.

### What was verified vs. not
- Verified (static): Feitian Dev-ID signature + Apple notarization, universal arm64 slice,
  68 `C_*` exports, PCSC linkage, and the ATR mask leaving the customer byte wildcard.
- **Not verified (needs hardware + PIN, out of scope here):**
  1. That `C_GetTokenInfo` / `C_GetSlotList(TRUE)` actually enumerate the live `0x69` token.
     (High confidence from the mask, but untested.)
  2. **Transport for signing.** `libcastle`'s RSA-2048 sign is a large (~298-byte) extended
     APDU that macOS 27's built-in CCID stack rejects as `0x80100016 SCARD_E_NOT_TRANSACTED`
     — the same class of bug the app's shim was written for. **But the app's shim was
     validated against the VNPT/NC-CA malformed *SM READ BINARY* encoding
     (`CLA&0x0C`, `il == 7+Lc`), not against `libcastle`'s sign APDU.** Whether the existing
     shim re-encodes `libcastle`'s APDU correctly, or needs a widened rule, is unknown until
     tested. The vendor's own fix is to install the shipped `ifd-FeiTccid.bundle` and set
     `useIFDCCID`, which is global and needs root (see below). Preferred path for the app:
     test the existing shim against `libcastle` first; only fall back to the CCID bundle if
     the shim does not cover it.
  3. That `libcastle` has no other post-SM customer check. Low risk (no evidence found), but
     not provable without disassembly or a live run.

### Remaining risks
- Provenance: the binary is Feitian's but distributed via Hypersecu/HK Post, not FastCA.
  Mitigation: the Feitian Developer-ID signature + notarization were checked (above); pin the
  sha256 and re-verify on every update.
- Signing transport caveat (#2 above) is the main open item.
- The vendor CCID-driver route (`ifd-FeiTccid.bundle` + `sudo defaults write
  /Library/Preferences/com.apple.security.smartcard useIFDCCID -bool yes` +
  `sudo killall -9 usbsmartcardreaderd com.apple.ifdreader`) is **system-wide** and affects
  every smart-card reader on the Mac; `runtime-probe.md` §"Fix (a) tried" already found this
  bundle had no effect on the VNPT lib's malformed APDU. Prefer the in-process shim.

---

## Option 2 — Ask FastCA / CyberLotus (the issuer) for a macOS module

The canonical route. FastCA's own site says only *"Máy MAC sử dụng bộ cài riêng dành cho máy"*
("Macs use a separate installer") with **no link**, and the prior hunt found no mac file on
their servers or reseller pages (`fastca-oneca.md` §2): `rubtau.fastca.vn/tm/v1.0/` re-checked
on 2026-10-21 still lists only Windows files (`Setup.exe` 2026-01-06, `fca_v1.0.exe`
2024-08-25) — no `.dmg`/`.pkg`/`mac`.

### Contacts (verified on fastca.vn, 2026-10-21)
- Hotline: **1900 2158** (written `08.1900.2158` on the contact page).
- Email: **info@fastca.vn**; support alias **support@fastca.vn** (listed on the QR-code page).
- Zalo OA: search `FASTCA` (stated 24/7 support).
- Contact / QR pages: `https://fastca.vn/lien-he`, `https://fastca.vn/quet-qr-code-lien-he-truc-tiep-cung-fastca`
- Installer vendor on record: **CYBERLOTUS JOINT STOCK COMPANY** (Authenticode signer of the
  FastCA Windows `Setup.exe`, per `fastca-oneca.md` §1).
- Note: a separate brand "New FastCA" exists at `fast-ca.vn` / `fast-ca.net`; confirm which
  entity issued the user's cert before relying on their guidance.

### What to ask for
> "A macOS (Apple Silicon / arm64) PKCS#11 module for the FastCA ePass2003 USB token
> (customer code 0x69). If none exists, confirm it, and confirm whether the generic Feitian
> EnterSafe/Castle macOS middleware is approved for FastCA tokens."

### Risk
Likely no macOS build exists; the "separate installer for Mac" claim appears to be a dead
promise. Expect to be pointed at Windows, which leads to Option 1 or Option 4.

---

## Option 3 — Ask Feitian directly for the generic EnterSafe/ePass2003 macOS PKCS#11

Feitian's ePass2003 spec lists a *"Direct-called library for PKCS#11 under Windows, Linux and
macOS"* and OS support *"32 & 64 bit Linux, macOS X"*
(`https://www.ftsafe.com/products/PKI/Standard/Specification`) but gives no download link and
does not state arm64. This is the manufacturer of the actual chip and middleware.

### How to obtain
Feitian Support Resources / Inquiry pages on ftsafe.com; request the current universal macOS
EnterSafe/Castle PKCS#11 for ePass2003. In practice Option 1 already *is* this binary (the
HYP2003/Castle `libcastle` is Feitian's generic build), so this option mainly serves to get a
clean first-party download URL and written confirmation of arm64 + ePass2003 support.

### Risk
Feitian may redirect to the issuing CA; download URLs are not published openly.

---

## Option 4 — Fallback: Windows VM + official FastCA software, documents handed over from the mac app

Fully official and known-good: run FastCA's own Windows middleware inside a VM and sign there.

### Setup
- Parallels Desktop (Apple Silicon) with **Windows 11 arm64**. FastCA's `fca_v1.dll` is x86;
  Windows 11 arm64 runs x86/x64 apps under its built-in emulation, which the Feitian CSP/
  PKCS#11 stack works under. (A verified alternative is an Intel Windows VM via UTM/QEMU if
  emulation causes trouble.)
- Install FastCA from `rubtau.fastca.vn/tm/v1.0/Setup.exe` (Inno Setup, signed by CYBERLOTUS).
- USB passthrough: Parallels → the VM's **Devices → USB & Bluetooth** → connect
  "FT ePass2003Auto" to Windows. macOS releases the reader; the token then appears only in the
  VM. (Only one OS owns the token at a time.)

### Handing documents from the mac app to the VM
- Simplest: a Parallels **shared folder**; the mac app writes the document/hash there and a
  small Windows-side signer (CryptoAPI/CNG against the FastCA CSP, or the FastCA PKCS#11)
  signs and writes the result back.
- Cleaner: run a tiny HTTP signing service in the VM (localhost-only, bound to the
  Parallels host-only network) that accepts a hash and returns a PKCS#1/CMS signature. The
  mac app POSTs to it. This mirrors how the Vietnamese portals already call a local bridge
  (see `ctsigninghub.md` / `esigner.md`).

### Risk
- Needs a Windows license and a VM; heaviest option.
- x86-on-arm emulation of a CSP/PKCS#11 + USB smart-card stack can be finicky; test the full
  login+sign once before relying on it.
- Keep the signing service localhost/host-only; never expose the token over a routable port.

---

## Also on record (not a vendor option)

The app's own ePass2003/ENTERSAFE-ESPK path (OpenSC `card-epass2003.c`-derived) already reads
all five Feitian CAs on this Mac and is the non-vendor route; PIN external-auth + sign
derivation is still unconfirmed for FastCA (see `runtime-probe.md` §"PIN external-auth").
Option 1 is the *vendor-supported* equivalent and should be tried first for the FastCA token,
because it avoids guessing the PIN key derivation (a wrong guess costs a PIN retry, and the
FastCA cert is already expired).

## Suggested order of action
1. Plug `libcastle_v2.1.0.0.dylib` into `ModuleRegistry`; confirm it enumerates the live
   `0x69` token (read-only, no PIN needed for `C_GetTokenInfo`/cert read).
2. Test the existing PC/SC shim against `libcastle`'s sign APDU; widen the shim rule if the
   APDU shape differs. Only then try a PIN login/sign (ideally after restoring the counter via
   the Windows VM, since the FastCA cert is expired).
3. In parallel, file the FastCA (Option 2) and Feitian (Option 3) requests for a first-party
   URL + written arm64/ePass2003 confirmation.
4. Keep the Windows-VM path (Option 4) as the guaranteed fallback.
