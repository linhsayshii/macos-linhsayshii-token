# CMC-CA and I-CA macOS token installers — RE notes

Interop research for a self-built all-in-one macOS signing tool. Same method as `ncca.md`: static analysis only;
nothing downloaded was executed or installed (dmgs mounted `-readonly -nobrowse` into scratch dirs, pkgs
`pkgutil --expand`ed, payloads unpacked with `cpio`). Date: 2026-10-21. TLS verification left on for all downloads.

**Bottom line:** both are the same Feitian ePass2003 + Mobile-ID ("mobileid") template as NC-CA. All three PKCS#11
dylibs are separate builds of one Feitian codebase. The differences that matter are the module/label strings and
**one byte in the ATR filter** (the customer code): NC-CA `0x59`, CMC `0x61`, I-CA `0x72`.

## Chain (OBSERVED)

| Stage | CMC-CA | I-CA |
|---|---|---|
| CD launcher | `MACOSX/install.py` (no .app; readme says run `python install.py`) | `MACOSX/ICAv1_OnlineInstaller.app` (bundle `com.mobileid.download`, x86_64+arm64, Team `VR923PGQ8Z`, runs `/usr/bin/python` on `Resources/install.py`) |
| stage 1 `install.py` | py2-only (`print "…"`), `ssl._create_unverified_context()`, URL `' https://ca.cmc.vn/download/tokenV1/ScriptInstall.py'` (leading space in the URL) | identical script, URL `https://i-ca.vn/download/tokenV1/ScriptInstall.py` |
| stage 2 `ScriptInstall.py` | 968 B, works on py2 and py3, sets `ssl._create_default_https_context = _create_unverified_context`. Last-Modified 2025-05-19 (nginx/1.14.1) | 940 B, same code. Last-Modified 2026-05-27 |
| dmg | `https://ca.cmc.vn/download/tokenV1/cmc_ca_v1_installer.dmg` (5,292,652 B, LM 2025-05-13), sha256 `9d7045dc…f7ded1` | `https://i-ca.vn/download/tokenV1/ica_v1_installer.dmg` (5,974,595 B, LM 2026-05-27), sha256 `91d9f93a…f84547` |
| pkg | `/Volumes/cmc_ca_v1_installer/cmc_ca_v1.pkg`, Developer ID Installer **FEITIAN (S47T4UESP3)**, timestamp 2025-05-12, **not notarized** | `/Volumes/ica_v1_installer/ica_v1.pkg`, same signer, timestamp 2026-05-26, **notarized** |

Both dmgs also ship `ReadMe_en.rtf` and `license_en.rtf`. Both Distribution files set `hostArchitectures="x86_64"`, so the
installer needs Rosetta on Apple Silicon. Stage 2 then runs `hdiutil attach /tmp/<dmg>` and `open …pkg`.

Linux (CMC `UBUNTU/install.sh`): runs as root, `wget --no-check-certificate https://ca.cmc.vn/download/tokenV1/ubuntu/server_install.sh`
and executes it. The URL now returns **404** (so do `ubuntu/` and `ubuntu/cmcca_csp11_v1.so`). The readme names the module
`/usr/lib/cmcca_csp11_v1.so` (dpkg package `easy-1.0`). **Not downloaded** because it is unavailable.

## What the pkgs install (OBSERVED)

CMC: 6 sub-pkgs (`com.feitiansafe.pkg.*`). I-CA: 4 sub-pkgs (`com.ftsafe.pkg.*.epass2003.ica`). NC-CA had 12.

| Component | CMC-CA | I-CA |
|---|---|---|
| **PKCS#11 module** | `/usr/local/lib/cmcca_csp11_v1.dylib` | `/usr/local/lib/ica_csp11_v1.dylib` |
| CTK app (`com.apple.ctk-tokens`, driver-class `FTSmartTokenDriver`) | `/Applications/CMCCA_V1SmartToken.app` (`com.ftsafe.cmcca.SmartCardToken`, ext `com.ftsafe.cmcca.SmartCardTokenExt`, XPC loads `/usr/local/lib/cmcca_csp11_v1.dylib`) | `/Applications/ICASmartToken.app` (`com.ftsafe.ica.FTSmartToken`, ext `com.ftsafe.ica.FTSmartTokenExt`, XPC loads `/usr/local/lib/ica_csp11_v1.dylib`) |
| **LaunchAgent** (new vs NC-CA) | `/Library/LaunchAgents/com.FTSmartCard.CMCCA.tokenservice.plist` with KeepAlive and RunAtLoad, running the CTK app binary. Its postinstall loads the *wrong* names (`com.FT_ZJNX*.tokenservice.plist`), so the agent only starts at the next login | `/Library/LaunchAgents/com.FTSmartCard.ICA.tokenservice.plist` (same pattern). Loaded correctly |
| tokend | `cmcca_v1.tokend` (id `com.apple.tokend. cmcca-v1`, x86_64+i386), only on macOS 10.x | `ICAToken.tokend` (x86_64), only on <10.11 |
| CCID driver | `ifd-FeiTccid.bundle` (pcsc-lite libccid 1.4.33, Feitian-signed) → `/usr/local/libexec/SmartCardServices/drivers/` | same |
| GUI manager | `/Applications/CMC-CA Token Manager v1.0.app` (`vn.mobileid.cmc-ca-v1`, **1.25.04.22**, x86_64 only, signed with an **Apple Development** cert "Khanh Pham", Team `8VFRAXUUZP`, not Developer ID) | `/Applications/ICA Token Manager V1.0.app` (`vn.mobileid.ica-v1.0`, **1.26.04.28**, x86_64 only, Developer ID FEITIAN, hardened runtime) |
| Certs | `CMC.crt` (trustAsRoot) and `VNROOT.crt` (trustRoot) go into the **System keychain** via `security add-trusted-cert`, and into Firefox/Thunderbird NSS | `ICA.crt` and `I-CA_SHA256.crt` (trustAsRoot) and `vnroot.crt` (trustRoot) go into the **System keychain** and NSS |
| Other | `/etc/sysctl.conf` (`kern.sysv.semume=1000`), uninstaller in `/usr/local/CMC-CA/Token Manager v1.0/` (chmod 777) | uninstaller in `/usr/local/I-CA/Token Manager v1.0/` (chmod 777), **`defaults write /Library/Preferences/com.apple.security.smartcard useIFDCCID -bool yes`** (switches macOS to the legacy IFD CCID stack), kills `ctkd`/`ifdreader` |
| NSS module name | `"CMC-CA PKCS#11 Module v1.0"` | `"ICA PKCS#11 Module v1.0"` |

Both GUI managers statically link gSOAP and OpenSSL and use the same `http://tokenservice.mobileid.vn/TokenWS/*` SOAP actions
(getTokenInfo, requestUnlock, sendCsr, enrollCertificate, …), the same as NC-CA. They do not sign anything locally over HTTP.

### Certificates (OBSERVED, `openssl x509`)
- `VNROOT.crt` / `vnroot.crt` = Vietnam National Root CA (MIC/NEAC), 2014-04-15 → 2039-04-15, sha256 `BA:C8:BF:60…08:E7`.
  The CMC file is byte-identical to NC-CA's `vnrca256.crt`. The I-CA file is the same cert in a different encoding.
- `CMC.crt`: CN=CMC-CA, O=CMC Corporation, issuer VN Root CA, **2025-01-16 → 2030-01-16** (valid), sha256 `BE:9F:05:35…F0:44`.
- `I-CA_SHA256.crt`: CN=I-CA SHA-256, O=I-CA, **2025-10-08 → 2030-10-08** (valid), sha256 `25:3D:B4:50…F0:BE`.
- `ICA.crt`: CN=I-CA, O=I-CA, 2022-01-24 → **2027-01-24**, sha256 `94:7D:12:EB…53:03`.

## PKCS#11 dylibs (OBSERVED)

| | NC-CA `ncca_csp11_v1.dylib` | CMC `cmcca_csp11_v1.dylib` | I-CA `ica_csp11_v1.dylib` |
|---|---|---|---|
| size | 3,837,344 | 3,849,776 | 3,833,072 |
| sha256 | `3bd0a2d9…d9042b` | `0d1ba9cd…410f2b09` | `79a1acc0…3cc6d71` |
| archs | x86_64 arm64 | x86_64 arm64 | x86_64 arm64 |
| `nm -gU \| grep -c ' _C_'` | 68 | 68 | 68 |
| non-standard export | `_E_GetAuxFunctionList` | `_E_GetAuxFunctionList` | `_E_GetAuxFunctionList` |
| codesign | ad-hoc linker-signed only (no Team ID) | Developer ID **S47T4UESP3**, hardened runtime, ts 2025-05-12, `--verify --strict` OK | Developer ID **S47T4UESP3**, hardened runtime, ts 2026-05-26, verify OK |
| SDK / minos (arm64) | 11.1 / 11.0 | 12.0 / 11.0 | 12.1 / 11.0 |
| links | CoreFoundation, IOKit, PCSC.framework, libc++, libSystem (all three the same) | | |

**Diff result: they are not the same binary.** Each was built separately (different SDKs and sizes). The arm64 slices are
1,887,648 / 1,900,080 / 1,883,376 bytes, so `cmp -l` reports about 1.6 M differing bytes per pair (N/C 1,631,900, N/I 1,645,460),
because everything after the first difference is shifted. Diffing the `__TEXT,__cstring` sections shows the code is otherwise
the same Feitian codebase (583/583/577 unique strings). Only these differ:

1. **ATR filter (customer code).** Each dylib has one 23-byte ATR value and mask. The arm64 offsets are N `0x1987e2`, C `0x193c29`, I `0x190ec3`; x86_64 has the same bytes:
   ```
   value 3B 9F 95 81 31 FE 9F 00 66 46 53 05 00 00 00 71 DF 00 00 [cc] 00 00 00
   mask  FF FF FF FF FF FF FF FF FF FF FF FF 00 00 00 FF FF FF FF  FF  FF FF 00
   cc:   NC-CA 0x59 ('Y')   CMC 0x61 ('a')   I-CA 0x72 ('r')
   ```
   The mask keeps the customer-code byte (index 19) in the comparison, so each CA's module only accepts its own CA's ePass2003 tokens.
2. **Branding strings** (in `__data`): NC-CA `NC-CA Token v1.0` / `NC-CA Token CSP v1.0` / `NC-CA Key Storage Provider V1.0`.
   CMC: `CMC-CA Token v1.0`, `CMC-CA Token CSP v1.0`, `CMC-CA PKCS#11 Library.`, `CMC-CA Token Manager v1.0 Key Storage Provider`.
   I-CA: `ICA Token v1.0`, `ICA Token CSP 1.0`, `ICA PKCS#11 Module v1.0`, `ICA Key Storage Provider v6.0`.
   Plus Windows leftovers: `Software\<CA>\Token Manager…`, `<ca>_csp11_v1_mgr.exe`, `ePass2003.ini`.
3. **Product GUIDs**: NC-CA `5A9DFE19-166C-413a-9757-13964DDFBBE9`, CMC `9BBFEDDD-92E5-4494-93B6-2ECFB5B324E1`, I-CA `236140C7-BFD5-43f7-8FFF-71519ED8ACA2`.
4. **Reader-name strings**: NC-CA and CMC contain `Feitian ePass2003` and `FT  ePass2003Auto` (plus `%.2d` / `%.2d 00` variants), next to the `/var/run/pcscd` monitor code. **I-CA's dylib has none of them.**
5. Minor: source-path strings (`common/slot.cpp` in NC-CA vs `slot.cpp` in CMC and I-CA), and CMC's extra `ECCECDSASHA256*Hard/Soft*` symbol strings.

No config-file path is hardcoded in the dylibs. They need nothing on disk apart from PC/SC.

## Config files (OBSERVED)

The GUI manager's `Contents/Resources/Config.cfg` (UTF-16 `.strings` format):

| key | CMC | I-CA |
|---|---|---|
| UrlUpdate | `https://ca.cmc.vn/download/tokenV1/` | `https://i-ca.vn/download/tokenV1/` |
| Version | `1.25.04.22` | `1.26.04.28` |
| DefaultPIN | `12345678` (same as NC-CA) | `12345678` |
| LibPath | `/usr/local/lib/cmcca_csp11_v1.dylib` | `/usr/local/lib/ica_csp11_v1.dylib` |
| InsPath | `/usr/local/CMC-CA/Token Manager v1.0` | `/usr/local/I-CA/Token Manager v1.0` |
| NameConfig / NameVersion | `cmcca_csp11_v1_mgr.cfg` / `update_macos.ini` | `ica_csp11_v1_mgr.cfg` / `update_macos.ini` |

`UpdateManual` also embeds a py2 snippet that runs `hdiutil attach` and `open` on whatever update gets downloaded.

Server files (fetched read-only into `…/dl/srv/`): `update_macos.ini` is CMC `1.23.09.08` and I-CA `1.22.0725`, both *older*
than the shipped app versions. `version_macos.ini` and `update.py` return 404 on both servers. `*_mgr.cfg`:
- CMC: `ID07=https://tmsra.cmc.vn/TokenService/TokenWS` (the SOAP endpoint), `ID27=https://10.10.23.101/TokenService/TokenWS` (a private IP),
  `ID08=https://ca.cmc.vn/download/tokenV1/`, `ID04= .:.Welcome To CMC CA.:.`
- I-CA: `ID07=https://tws.i-ca.vn/TokenService/TokenWS`, `ID27=https://124.158.6.106:8443/TokenService/TokenWS`, `ID08=https://i-ca.vn/download/tokenV1/`

## Security concerns (OBSERVED)
1. TLS verification is disabled in stage 1 and stage 2 for both CAs. A spoofed `ca.cmc.vn` or `i-ca.vn` could serve a pkg that the user then installs. Mitigation: the pkg *is* Developer-ID signed (Feitian), and Installer.app shows the signer.
2. `/tmp` staging of the script and dmg (TOCTOU risk). The Linux path runs `wget --no-check-certificate | exec` as root.
3. Root CA trust is added to the **System keychain** (unlike NC-CA). `chmod 777` on the uninstaller dirs (and on `/Library/Security/tokend` on old macOS).
4. I-CA flips the system-wide `useIFDCCID` smartcard preference, which affects every smartcard reader on the Mac.
5. `DefaultPIN=12345678`. The CMC GUI app is signed with a personal Apple Development cert.
6. The CD launchers are broken on current macOS: stage 1 is py2-only and the I-CA app calls `/usr/bin/python`, which is gone since 12.3.
   Stage 2 itself is py3-compatible.

## Inferred
- **For the app:** one code path can serve NC-CA, CMC and I-CA tokens. Load the matching `<ca>_csp11_v1.dylib` by ATR byte 19
  (`0x59`/`0x61`/`0x72`), or load all three and use whichever returns a token in `C_GetSlotList(CK_TRUE)`. Each module rejects
  the other CAs' tokens because of the ATR mask.
- A single universal Feitian ePass2003 module could replace all three if it ignored byte 19, but that is not shipped here. Patching the
  byte would break the CMC/I-CA code signature (NC-CA's is ad-hoc anyway). Avoid patching and just bundle all three.
- CMC and I-CA dylibs are Developer-ID signed by Feitian. Loading them in a hardened-runtime app with library validation requires
  `com.apple.security.cs.disable-library-validation` (Team ID mismatch). NC-CA's ad-hoc dylib needs the same.
- I-CA's missing reader-name strings suggest it does not filter PC/SC readers by name, and relies only on the ATR filter.
- Token label probably reads `"<CA> Token v1.0"`. Use it for display, not detection.
- The CTK and LaunchAgent pieces are not needed for PKCS#11 signing.

## Unknown / not verified
- Live behaviour of the modules (no token attached), the slot/label strings they actually report, and any mechanism differences.
- Whether `E_GetAuxFunctionList` differs per CA (the export exists in all three; its table was not disassembled).
- Linux `.so` (server 404), and the purpose of the CMC private-IP `ID27` endpoint.
- Whether the I-CA `useIFDCCID=yes` setting is *required* for the token on macOS 15+, or only a workaround.

## Artifacts (scratchpad, untrusted, never executed)
Scratchpad root `/private/tmp/claude-501/-Users-linhsayshii-macos-linhsayshii-token/c7155b36-14ea-4bde-bcd5-4cbdb36c6967/scratchpad/re/`:
- `cmc/dl/`: `ScriptInstall.py`, `cmc_ca_v1_installer.dmg`, `vol_dmg/`, `pkg_expanded/`, `payloads/`, `srv/`
  - dylib: `cmc/dl/payloads/CMC-CA/cmcca_csp11_v1.dylib`
- `ica/dl/`: same layout; dylib: `ica/dl/payloads/P11/ica_csp11_v1.dylib`
- `re-work-cmcica/`: thinned slices plus `*.cs` cstring dumps used for the diff
