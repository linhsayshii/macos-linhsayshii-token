# NC-CA (NCCA) macOS Online Installer — RE notes

Interop research for a self-built all-in-one macOS signing tool for Vietnamese CA USB tokens.
Target analyzed statically only; nothing from it was executed/installed. Date: 2026-10-21.

## Chain (OBSERVED)

1. `NCCAv1_OnlineInstaller.app` — tiny Cocoa app (Foundation/AppKit, x86_64), bundle `com.ncca.download`.
   Only job: find a Python interpreter (`/usr/bin/python3`, `/usr/local/bin/python3`, …) and run bundled `install.py`.
2. `Contents/Resources/install.py` (48 lines, py3): downloads `ScriptInstall.py` to `/tmp`, runs `python3 /tmp/ScriptInstall.py`.
   - URL: `https://cfg.nc-ca.vn/download/tokenV1/ScriptInstall.py`
   - **Disables TLS verification**: `ssl._create_default_https_context = ssl._create_unverified_context`.
3. `ScriptInstall.py` (610 B, **Python-2 syntax only** — `print "…"`): downloads the installer dmg, mounts, opens the pkg.
   - URL: `https://cfg.nc-ca.vn/download/tokenV1/nc_ca_v1_installer.dmg` (4.99 MB)
   - `ssl._create_unverified_context()` again; writes to `/tmp/nc_ca_v1_installer.dmg`.
   - `hdiutil attach …` then `open /Volumes/nc_ca_v1_installer/nc_ca_v1.pkg` (GUI installer → asks admin pw).

All URLs reachable (HTTP 200, WildFly/Undertow origin, last-modified 2021-04-16). Files are from 2021.

## What the pkg installs (OBSERVED)

`nc_ca_v1.pkg` is a distribution pkg with 12 sub-packages (authoring id `www.FTSafe.com…`, app vendor `vn.mobileid`).
Branches on macOS version (buggy `cut -d . -f2` logic; intent below). Payload paths:

| Component | Installed path | Purpose |
|---|---|---|
| `ncca_csp11_v1.dylib` | `/usr/local/lib/ncca_csp11_v1.dylib` | **PKCS#11 module** (universal x86_64+arm64) |
| `ncca_v1.tokend` (`ePassToken.tokend`, Tokend-37563) | `/Library/Security/tokend/` (10.11–10.14) or `/System/Library/Security/tokend/` (<10.11) | legacy CDSA tokend |
| `NCCA_V1SmartToken.app` (+`.appex`+`.xpc`) | `/usr/local/Applications/` | **CryptoTokenKit** extension (10.15+) |
| `ifd-FeiTccid.bundle` (`libccid.dylib`) | `/usr/local/libexec/SmartCardServices/drivers/` (or patches system `ifd-ccid.bundle` Info.plist on <10.11) | **Feitian** CCID reader driver |
| `NC-CA Token Manager v1.0.app` | `/Applications/` | GUI token manager (PIN/cert/update) |
| `ncca.crt`, `vnrca256.crt` | registered into **NSS** DBs only | CA certs (see below) |
| `sysctl.conf` | `/etc/sysctl.conf` | sets `kern.sysv.semume=1000` |
| `uninstall.sh` | `/usr/local/NC-CA/NC-CA Token Manager v1.0/` | uninstaller |
| `nssFirefox`,`nssThunderbird` | into Firefox/Thunderbird `MacOS/` | bundled NSS `modutil` wrappers |

- **PKCS#11 module** `ncca_csp11_v1.dylib`: full standard Cryptoki — exports `C_GetFunctionList` + all `C_*`. Links only `CoreFoundation`, `IOKit`, `PCSC.framework`, `libc++`, `libSystem`. **Talks to the card directly over PC/SC — no vendor middleware dylib at runtime.** This is the clean reusable artifact.
- Both the tokend and the CTK XPC also hardcode `/usr/local/lib/ncca_csp11_v1.dylib` — everything funnels through that one module.
- CTK extension: `com.ftsafe.ncca-v1.SmartTokenApp`, `com.apple.ctk.class-id = com.ftsafe.FTSmartToken.FTSmartTokenApp`. Registered by `open`ing the app once in postinstall (CTK auto-registers via pluginkit). **No launchd agent/daemon.**
- NSS: registers module name `"NC-CA PKCS#11 Module v1.0"` into Firefox+Thunderbird and loads `ncca.crt`/`vnrca256.crt` as CA ("ICA"). **No install into the macOS login/System keychain by any script.**

## Hardware / middleware (OBSERVED)

- Vendor: **Feitian Technologies** (USB VID `0x096E`; `FTSafe` = Feitian). Token is a **Feitian ePass2003**-class smart token.
- CCID postinstall enumerates PIDs `0x0807/080A/0703/080F/0853/0855/0856/0859` →
  `Feitian ePass2003`, `FT ePass2003Auto`, `FT ePass3003Auto`, `Feitian eJAVA Token`, `Feitian ePass FIDO …CCID`.
- tokend binary strings: `ePassToken.tokend`, `/tmp/delay/ePassToken`; Resources named `epasstoken_csp_*.mds*`.
- CCID driver is Feitian's rebranded pcsc-lite `libccid` (`ifd-FeiTccid.bundle`, `org.debian.alioth.pcsclite.smartcardccid`).

## Online service (OBSERVED)

- `NC-CA Token Manager v1.0.app` statically links **gSOAP + OpenSSL**; it is a SOAP **client** (no local port/daemon).
- SOAP namespace / service: `http://tokenservice.mobileid.vn/` (`-[UsertoolAppDelegate getSoap]`). Used for remote cert update/management, not local signing.
- `Config.cfg`: `UrlUpdate=https://cfg.nc-ca.vn/download/tokenV1/`, `LibPath=/usr/local/lib/ncca_csp11_v1.dylib`,
  `Version=1.21.03.02`, `DefaultPIN=12345678`, update files `update_macos.ini`, `ncca_csp11_v1_mgr.cfg`, `update.py`.
- Signing is local (PKCS#11 / CTK / tokend against the card); no local signing HTTP service exists.

## Certificates (OBSERVED)

- `vnrca256.crt` = **Vietnam National Root CA** (MIC/NEAC), self-signed, 2014–2039.
- `ncca.crt` = **NC-CA SHA-256** intermediate (O=HN Investment and Business Support JSC), issued by VN Root CA, **2020–2025 (EXPIRED)**.
- Loaded only into Firefox/Thunderbird NSS stores, not the macOS keychain.

## Security concerns (OBSERVED)

1. **TLS verification disabled** in both stage-1 and stage-2 scripts while fetching executable payloads → MITM/DNS spoof of `cfg.nc-ca.vn` = arbitrary code, and the pkg then runs root postinstall scripts. Critical.
2. **Two-stage remote code fetch**: app → downloads+executes `/tmp/ScriptInstall.py` → downloads+opens pkg. Supply-chain/pin risk.
3. **World-writable `/tmp` staging** of script + dmg then executed/installed from there → local TOCTOU replacement.
4. Root postinstall does `chmod -R 777 /Library/Security/tokend` (world-writable security dir); edits system `ifd-ccid.bundle` in place on old macOS.
5. `DefaultPIN=12345678` shipped in `Config.cfg`.
6. **Installer is stale/broken on current macOS**: `ScriptInstall.py` is Python-2-only and will `SyntaxError` under python3 (no system python2 on macOS 12.3+); `ncca.crt` expired Jan 2025; dated 2021.

## For building your own tool (INFERRED)

- Reuse `ncca_csp11_v1.dylib` as a standard PKCS#11 provider from any Cryptoki-aware signer (pkcs11-tool/OpenSC, Java `SunPKCS11`, PDF/CAdES signers, `osslsigncode`). It needs only macOS PC/SC + the card.
- Reader path: Feitian ePass2003 over PC/SC (VID 0x096E). On recent macOS the built-in CCID driver often enumerates it; Feitian's `ifd-FeiTccid.bundle` is a fallback.
- Trust anchors: bundle VN Root CA + NC-CA intermediate yourself (fetch current NC-CA/NEAC certs; the shipped intermediate is expired).
- You do NOT need the tokend (deprecated) or the NCCA online SOAP flow for signing — only the PKCS#11 module + certs + a PIN entry UI.

## Unknown / not verified

- Exact ATRs and APDU command set of the token (would need the card or deeper disassembly of the dylib/CTK).
- Whether `ncca_csp11_v1.dylib` exposes multiple slots or vendor-specific mechanisms beyond the standard set.
- Code-signing/notarization status of the downloaded dylib/tokend/pkg (not checked; CTK app has a `_CodeSignature`).
- Contents of `update_macos.ini` / `ncca_csp11_v1_mgr.cfg` / `update.py` (referenced by Config.cfg, not in this dmg).
- Live behavior / endpoint URL of `tokenservice.mobileid.vn` (only the SOAP namespace was observed; not contacted).

## Artifacts (local scratchpad, not executed)

`…/scratchpad/re/ncca-dl/`: `ScriptInstall.py`, `nc_ca_v1_installer.dmg`, `nc_ca_v1.pkg`,
`pkg_expanded/` (all sub-pkg scripts/BOMs/PackageInfo), `payloads/` (extracted dylib, certs, configs, tokend).
