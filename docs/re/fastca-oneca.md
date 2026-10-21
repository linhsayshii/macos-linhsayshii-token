# FastCA + OneCA token installers — RE notes (macOS PKCS#11 hunt)

Interop research for a self-built all-in-one macOS signing app. All analysis was static (strings, innoextract,
pkgutil --expand, cpio, nm/otool/lipo). Nothing was executed or installed, and no sudo was used.
Scratch root: `S=/private/tmp/claude-501/-Users-linhsayshii-macos-linhsayshii-token/c7155b36-14ea-4bde-bcd5-4cbdb36c6967/scratchpad/re`

## TL;DR
| CA | Token (live) | Windows PKCS#11 | macOS PKCS#11 found |
|---|---|---|---|
| FastCA | Feitian ePass2003Auto, USB 096e:080a, ATR byte19 = 0x69 | `fca_v1.dll` (Feitian "EnterSafe CSP PKCS11 Library") | **None published.** No macOS package anywhere. |
| OneCA | Longmai **mToken OneCAV3**, USB 055c:0223 | `one-ca_v3.dll` (Longmai CryptoID customization) | **Longmai generic** `libcryptoid_pkcs11.dylib` (x86_64 only, unsigned) from a reseller zip. Not from OneCA. |

---
## Observed

### 1. CD stubs (both use the same MFC "online_installer\updater" template as the NC-CA and I-CA stubs)
| | FastCA `vol/Setup.exe` | OneCA `vol/Setup.exe` |
|---|---|---|
| sha256 | `28ca66c6…948b` | `07e2b31f…eb366` |
| Type | MFC PE32 downloader stub, "FastCA online installer, Version 1.0" (2021) | same template, "ONE-CA online installer 3.0" (2023) |
| Authenticode | CYBERLOTUS JOINT STOCK COMPANY (Thawte/DigiCert TS) | SMART TECHNOLOGIES INVESTMENT & DEVELOPMENT JSC (Sectigo; `info@vtcsmarttech.com.vn`) |
| PDB | `E:\Document\FEITIAN\ePass2003\FastCA\Middleware\online_installer_coGiaoDien_update\…\Setup.pdb` | `E:\ONE-CA\OneCA_V3.0_longMai_mCryptoID\online_installer\…\Setup.pdb` |
| URLs (UTF-16) | `https://rubtau.fastca.vn/tm/v1.0/` + `Setup.txt`/`Setup.exe`; fallback `https://dauaold.fastca.vn/tm/v1.0/` (TLS fails now) | `http://tms.visnam.vn/software/token/one-ca_v3/` + `Setup_v3.txt`/`Setup_v3.exe` (HTTPS gives Cloudflare 526, so the stub uses **plain HTTP**) |
| Version file | `Setup.txt` = SHA1 of the payload (`82F68B18…`) | `Setup_v3.txt` = `size,SHA1` (`2226920,65BC1DCE…`) |
| Other | `AutoUpdateAgent`, `setup.exe.bak` | `Setup_v3.exe.bak`, older `Setup_oneca_v2.exe` string |
The AUTORUN.INF in both only sets the icon (`ICON=Setup.exe,0`).

### 2. FastCA Windows payload (`$S/fastca/dl`)
- `rubtau.fastca.vn/tm/v1.0/` has an open directory index with `Setup.exe` (2026-01-06), `fca_v1.0.exe` / `.html` / `.txt` (TokenManager 1.0.0.2, 2024-08). **There is no mac file.**
- `Setup.exe` is Inno Setup 5.5.7, signed by CYBERLOTUS (GlobalSign EV). Extracted with innoextract into `$S/fastca/dl/inno/`:
  - `sys/fca_v1.dll` is the **PKCS#11 module**, also a CSP, minidriver (`CardAcquireContext`) and KSP. It exports all 68 standard `C_*` plus `E_GetAuxFunctionList`, `eb_*`, and `CP*`.
    Its strings include "EnterSafe CSP PKCS11 Library", `ENTERSAFE-ESPK`, `nca_eps2k3a.pdb`, and "FastCA virtual Slot %d". It imports WinSCard.
  - `sys/fca_v1_s.dll` is the CSP stub (registered as "FastCA CSP 1.0"). `fca_v1.sig` is the CSP signature. There are also `fca_v1.0_certd.exe` (cert propagation) and `mozillaInst.exe`.
  - `app/reg/FastCA1.0.reg` creates `HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\FastCA Token`:
    `ATR=3b9f958131fe9f00664653050000 0071df0000690000 00`, `ATRMask=ff×12,00,00,00,ff×7,00`. Here **byte 19 = 0x69 is matched**. This is the FastCA customer byte, consistent with the live probe.
  - Root CAs shipped: `MIC2.cer`, `CA256.cer`. An XP-era `usbccid.sys` driver is also included.
- Embedded ATR table in `fca_v1.dll` @0x140df4: `3b9f958131fe9f00 66465305 000000 71df0000 09 000000` (len 0x17), followed by a mask. Section 5 covers how to read it.
- Website: fastca.vn (WordPress). The REST API search found no pkg, dmg or mac media. The install guide says only "Máy MAC sử dụng bộ cài riêng dành cho máy" ("Macs use a separate installer"), with no link.
  Guessed paths `/tm/mac/`, `/tm/v1.0/mac/`, `ScriptInstall.py`, `*.dmg` all return 404. `download.fastca.vn` just redirects to the homepage.
  The reseller page newca.vn/download lists only Windows files (`FastCA-Setup.exe`, `ban-cai-cks-fastca.zip`).

### 3. OneCA Windows payload (`$S/oneca/dl`)
- `Setup_v3.exe` is Inno Setup 5.5.7, signed by **Century Longmai Technology Co.,Ltd**. Extracted to `$S/oneca/dl/inno/`:
  - `sys/one-ca_v3.dll` (x64) is the **PKCS#11 module**. It exports 68 `C_*` + Longmai `M_*` extensions (`M_FormatToken`, `M_RemoteUnblockUserPin`, `M_GetExtFunctionList`…). It imports WinSCard.
    PDB: `E:\work\Customization\CryptoID\LXY-1312-723_VN\…\OneCA3\…\PKCS11\…\one-ca_v3.pdb`. Labels: "One-CA PKCS11 V3", "One-CA PKCS11 V3 Slot %d", "One-CA Technology".
    Device filter strings: `OneCAV3,vid_055c&pid_0223|vid_0bda&pid_0165,gmpcsc` and `gm3000,vid_055c&pid_db08,…e618|f603|2205`.
  - `one-ca_v3_csp*.dll` (CSP x86/x64 plus en/vn resource DLLs). Tools: `oneca_v3.exe` (TokenManager; URLs `tms.visnam.vn/software/token/one-ca_v3/`, `token.vin-ra.vn`; the PIN-unlock text names `support@newca.vn`), `oneca_v3_certd.exe` (About: `http://One-ca.com.vn`, `www.longmai.com.cn`).
  - `app/reg/CryptoID.reg` creates `Calais\SmartCards\Longmai mToken OneCA`: ATR `3b9f118131fe9f006a6d546f6b656e2d5b000581900061`, **mask all ff (exact match)**, provider "One-CA CSP V3".
- The domains oneca.vn, one-ca.vn and one-ca.com.vn do not resolve. visnam.vn sits behind Cloudflare; `/software/token/` returns 403 and every mac guess returns 404.
- On the user's Mac, read-only `ioreg` shows "mToken OneCAV3" from vendor "Longmai" at **0x055c:0x0223**, and "ePass2003Auto" from "FT" at **0x096e:0x080a**. The host is arm64.

### 4. macOS PKCS#11 found for OneCA: Longmai generic CryptoIDA (not OneCA-branded)
Source: Longmai reseller `https://mtokens.in/download/upmac.zip`. The zip is 11.5 MB, last-modified 2023-06-30, internal dates 2020-06-29, sha256 `7d0998c7…1236`. Unpacked into `$S/oneca/dl/mtokens_in/`.
- `CryptoIDAToolsA_Mac_v2.1.19.226.pkg`: flat pkg (Packages.app, id `com.mygreatcompany.pkg.CryptoIDAToolsAMacv2119226`, install-location `/`, root, **no scripts**).
  `pkgutil --check-signature` reports a **Developer ID Installer: Beijing Century Longmai Technology Co.,Ltd (4M7RX53G2N)** signature, timestamped 2020-06-01. The payload is the Qt 5.8 app `/Applications/CryptoIDATools.app` (`LM.CryptoIDATools`), which is unsigned.

| dylib | Install path | sha256 | Arch | Exports |
|---|---|---|---|---|
| A: `…/mtokens_in/payload/Applications/CryptoIDATools.app/Contents/MacOS/libcryptoid_pkcs11.dylib` (1,020,796 B) | `/Applications/CryptoIDATools.app/Contents/MacOS/libcryptoid_pkcs11.dylib` | `372500d17c2ab333a86d960683d1c159053a445581782d39323bf19998f9ce0f` | x86_64 only, minOS/SDK 10.10 | 68 `C_*`; 2945 global symbols |
| B: `…/mtokens_in/x/upmac/libcryptoid_pkcs11.dylib` (1,004,908 B) | standalone in the zip; the user picks the path (the guide uses it in Adobe "Attach Module") | `e97c0e6edaa0df1e9fe3414a93bdc70c106a5afd917f5d3fc6d279bca35bc1a9` | x86_64 only, 10.10 | 68 `C_*`; 2895 globals (an older build missing `MKF_VerifyPIN`, `MKF_UnblockPIN`, `SKF_*HS`…) |

- Both dylibs share these properties:
  - They are **not code-signed**.
  - `otool -L` lists Foundation, IOKit, CoreFoundation, libobjc, libc++, libSystem. There is **no PCSC.framework**, no `SCard*` imports and no dlopen of PC/SC.
  - They carry a **statically linked libusb** (`libusb_claim_interface`, `IOServiceMatching`, `IOCreatePlugInInterfaceForService`) and talk to the token over raw USB, bypassing PC/SC and CryptoTokenKit.
- Non-standard exports: `CK_I_ext_functions`, `M_*` (as on Windows), `MKF_*` (device admin: `SetUSBVIDPID`, `SetSerialNumber`, `EraseFirmware`, `DisableCDROM`, `DevAuth`…), the full Chinese GM/T **SKF_*** API (incl. `SKF_ECCSignData`), and OpenSSL `RC2_*` / `RC4*`.
- Device filter strings: `mtoken cryptoida,not used,vid_055c&pid_0223|vid_055c&pid_0229` and `GM3000C,vid_055c&pid_e917|vid_055c&pid_f603`. Labels: "CryptoIDA", "Longmai Technology", "Virtual Slot %d".
  There is **no ATR table, no "OneCA" string and no config file** (there are no `.ini`/`/Library`/`/opt` paths).

### 5. Cross-check of the Feitian ATR filter in the NC-CA mac dylib (`$S/ncca-dl/payloads/nccacsp11v1/ncca_csp11_v1.dylib`)
- Two ATR entries, both `…71df0000 59 000000`. Their mask is `ff×12,00×3,ff×8`, so **byte 19 must be 0x59 (the NC-CA customer byte)**. The FastCA token (0x69) does not match this table.
- In `fca_v1.dll` the template byte 19 is 0x09. The mask that follows is offset by 4 bytes (`00000000 ff×12 000000 ffff 00…`), so the exact struct layout and whether byte 19 is masked there are unverified.

## Inferred
- **FastCA has no macOS middleware.** Neither the vendor server nor the website nor the reseller hosts a mac build. The Windows module is a stock Feitian EnterSafe ePass2003 PKCS#11 rebrand (`fca_v1.dll`, same family as `ncca_csp11_v1`).
  For macOS the realistic routes are:
  1. **OpenSC's `epass2003` driver**, which reads the standard ENTERSAFE-ESPK layout. The user reports the same layout works for VNPT/NC-CA/CMC/I-CA.
  2. Reusing a sibling CA's Feitian mac dylib (`ncca_csp11_v1.dylib` etc.). This would likely **fail because of the customer-byte ATR check** (0x59 ≠ 0x69) unless that build has another code path.
  
  The Windows registry entry ties "FastCA Token" to byte19 = 0x69 exactly.
- **OneCA has no OneCA-branded macOS middleware.** OneCA V3 is a Longmai CryptoID customization (project `LXY-1312-723_VN`). Longmai's generic mac lib already lists **VID/PID 055c:0223**, which is exactly the user's "mToken OneCAV3", so it would probably enumerate the token.
  Labels would read "CryptoIDA/Longmai" instead of "One-CA PKCS11 V3".
- Integration constraints for the user's app:
  1. **x86_64 only.** It cannot be dlopen'd into an arm64 process. Use an x86_64 helper process under Rosetta (e.g. `arch -x86_64` pkcs11 bridge).
  2. **Unsigned.** A hardened-runtime host needs `disable-library-validation`, or must load the dylib in a separate helper.
  3. **Raw libusb access.** The USB interface may already be claimed by macOS's CCID stack (the token shows up in PC/SC with an ATR). `libusb_claim_interface` could then fail or contend with `com.apple.ifdreader`/CryptoTokenKit.

## Unknown (needs hardware test, which was not done here)
- Whether `libcryptoid_pkcs11.dylib` actually opens the OneCAV3 on macOS 26/27 while Apple's CCID driver holds it, and whether OneCA's customization (application name, device-auth key, file layout) is compatible with the generic CryptoIDA build for C_Sign.
- Whether Longmai or OneCA has a newer **universal/arm64** CryptoID mac build. longmai.net's "documents-tools" page has no public downloads, and other resellers (e.g. CertDigital RO) mention `libcryptoide_pkcs11.dylib` in `/opt/CryptoIDE/lib/` or `CryptoUserTools.app`, a different product line.
- The exact ATR-mask struct layout in `fca_v1.dll` and the full ATR list in `ncca_csp11_v1.dylib` (only byte-pattern hits were checked; no disassembly).
- What sits behind the dead `dauaold.fastca.vn` fallback, and the contents of `tms.visnam.vn/software/token/one-ca_v2/` (403).

## Artifacts
- `$S/fastca/dl/{Setup.exe,fca_v1.0.exe,inno/}` (Windows payload, extracted)
- `$S/oneca/dl/{Setup_v3.exe,inno/}` (Windows payload, extracted)
- `$S/oneca/dl/mtokens_in/{upmac.zip,x/upmac/,pkgx/,payload/}` (Longmai mac zip, expanded pkg, cpio payload)
- `$S/web/` (fetched HTML: fastca.vn, newca.vn/download, longmai, mtokens.in)
