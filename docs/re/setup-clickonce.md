# `setup.exe`: M-Invoice ClickOnce bootstrapper (2026-10-22)

## Checklist and conclusion

- [x] Identify the supplied file independently of its name.
- [x] Hash, inventory resources, decode its bootstrap configuration, inspect the embedded signer.
- [x] Check the PKCS#7 signature mathematically and compare the PE Authenticode digest.
- [x] Extract resource data without executing the installer or its dependencies.
- [x] Select the managed application artifact for deeper REST analysis.
- [ ] Windows execution, installation, certificate-chain/revocation validation, live network capture: not performed.

**Observed:** `/Users/linhsayshii/Downloads/setup.exe` is a native x86 PE32 bootstrapper configured for **MinvoicePlug**, not a FastCA token driver. The exact target is in its named resources, rather than inferred from a filename or an unrelated URL string.

| Identity | Value |
|---|---|
| Bytes | 535,752 |
| SHA-256 | `48392dffe6c187b145ced70d43474f89470ad50131817d0052e19fcc0ebcd69d` |
| Version resource | `17.0.35716.53 built by: d17.13` (bootstrapper engine; **not** plugin version) |
| PE/CLI | No CLI data directory; no managed metadata/CIL in this file |
| `BASEURL`, type 40/name BASEURL/lang 0 | `https://plugin.minvoice.com.vn/MinvoicePlugin_NewApp/` |
| `SETUPCFG`, type 41/name SETUPCFG/lang 0 | Application `MinvoicePlug`; file and `UrlName` `MinvoicePlug.application`; `RequiresElevation="false"` |
| Manifest | `requestedExecutionLevel="asInvoker"` |

The structured PE resource inventory examined 258 entries and retained all 124 resources. Its complete REA Evidence is checked in as [evidence/setup-pe-resources.json](evidence/setup-pe-resources.json):

- `ev_669daf95b2692d4774303ba65ead88843871d5ac177a9659769f51c9003946d3` — resource inventory, source file ranges and hashes.
- `ev_8cc5393099211b3e0fa460b665f5d69a165f0ae757a22454b165b3b8387985cf` — managed classification, no CLI directory; summary view `ev_3afc7c3733723929cd567a086a680772c4494c79fafccfdf8ea9f54a56be7d2a`.

Exact resource coordinates (original file, bytes):

| Resource | Offset | Length | Payload SHA-256 |
|---|---:|---:|---|
| VERSION | 501932 | 736 | `95d9b9cca6519c4cafab65e5b92ca2a25a257324e0724d2687c28a4c942fc8b8` |
| Manifest | 502668 | 1378 | `88200286ee8d702e70afed4dd26b9f1169ba9286139d0660016e3a003d1bf86a` |
| BASEURL | 504048 | 108 | `b7997b5efea294c8e94407b33ed27779ae5261d83f70041627fbba7e3b6029c4` |
| SETUPCFG | 504212 | 428 | `1d384713d9c05e28f6ec94b47465dadc02502facb54b4c1091abd3a7a173d193` |

## Offline signature check

**Observed with local tools**, separate from the REA resource Evidence:

- WIN_CERTIFICATE table at `0x81a00`, length 4808, revision `0x0200`, type 2 (PKCS signed data).
- Embedded signer: `CONG TY TNHH HOA DON DIEN TU M-INVOICE`; issuer `GlobalSign GCC R45 EV CodeSigning CA 2020`.
- Signer certificate serial `02C6DE06676E950D7B457B7C`; validity 2024-01-02 05:43:23 UTC through 2027-03-28 01:01:01 UTC.
- Signer certificate SHA-256 `EBCEB3430CE2E8F318700A0F7C02BA700C1EA8E139501D9EC9E1CB54526BFAAE`.
- `openssl smime -verify -inform DER ... -noverify` returned **Verification successful** for the extracted PKCS#7. `-noverify` deliberately leaves certificate trust unverified.
- The embedded SpcIndirectData SHA-256 is `247301fdb66f994fbe57dcfd07dfad46b8e8f98530bd8c70a13f21fe51437cc8`. Independently hashing this file while excluding the checksum, security-directory entry and certificate table produced the same value. Its raw sections are contiguous from `0x400` through `0x81a00`, so this check has no section-gap or post-certificate-overlay ambiguity.

**Unknown:** Windows trust policy, a trusted timestamp, chain trust and revocation status. The mathematical signature and matching digest do not establish those properties. `openssl cms` rejected this legacy Authenticode content layout; the successful check used the older `smime` PKCS#7 reader, not a claimed successful CMS check.

## Extraction and next artifact

`7zz l` and `7zz x` treated the PE as data; extracted sections/resources are under `/private/tmp/tokensigner-setup-static/extracted/`. No executable, script, installer entry point or downloaded payload was launched. The inventory/extraction returned PE sections/resources, **not** the application assembly. The configured deployment manifest is an external file; this bootstrapper alone does not establish which application version would be served today.

An existing, separately hashed `MinvoicePlug.exe` and its manifests remain in the prior research scratch directory. That assembly is the input for [minvoice-rest-static.md](minvoice-rest-static.md); it must not be described as a payload extracted from this `setup.exe`.

Reproduction tools: REA `6.5.0` portable PE-resource/managed-static providers, local `7zz 26.04`, Python standard library and OpenSSL. REA MCP was already connected. Hopper was available; Ghidra/IDA were unconfigured. No setup/doctor, provider installation or native decompilation was needed for this identification.

## Reproduce the PE digest for this exact layout

```python
from pathlib import Path
import hashlib, struct
b = Path('/Users/linhsayshii/Downloads/setup.exe').read_bytes()
assert hashlib.sha256(b).hexdigest() == '48392dffe6c187b145ced70d43474f89470ad50131817d0052e19fcc0ebcd69d'
pe = struct.unpack_from('<I', b, 60)[0]
opt = pe + 24
certificate, size = struct.unpack_from('<II', b, opt + 128)
assert certificate + size == len(b)
h = hashlib.sha256()
for lo, hi in [(0, opt + 64), (opt + 68, opt + 128), (opt + 136, certificate)]:
    h.update(b[lo:hi])
assert h.hexdigest() == '247301fdb66f994fbe57dcfd07dfad46b8e8f98530bd8c70a13f21fe51437cc8'
# Do not generalize this contiguous-layout recipe to arbitrary PE files.
```
