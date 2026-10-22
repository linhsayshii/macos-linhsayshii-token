# FastCA signing on macOS — native backend integrated and verified

Updated 2026-10-22. Target: the user's Feitian ePass2003Auto with ATR customer
byte `[19] = 0x69`, ENTERSAFE-ESPK layout, previously read certificate issued by
FastCA SHA-256 R1. That certificate expired in July 2026 per
[runtime-probe.md](runtime-probe.md); a valid RSA signature would not establish
that a portal accepts this certificate.

## Current result

**Native macOS signing now passes:** an independent OpenSC/ESPK helper authenticated
once, produced a 256-byte RSA signature and passed both Security.framework and
OpenSSL verification. The generic module failure is now traced to its customer
identifier check (`0x6900` versus accepted `0x8600`/`0x0600`). See
[fastca-native-signing.md](fastca-native-signing.md) for live and static evidence.
The native backend is now integrated into App/TokenHelper, replacing the generic
candidate for FastCA. Menu signing passed (user confirmed); local SignHash returned
a 256-byte signature and independent OpenSSL verification passed. See
[app guide](../FASTCA.md) and [app validation](evidence/fastca-app-signing-validation.json).
Certificate expiry remains separate.

The candidate-specific history below describes the earlier integration/read probe.


The application previously stopped at `ModuleRegistry`: `0x69` had no entry,
so it never tried a FastCA module. It now selects the **experimental** universal
`libcastle_v2.1.0.0.dylib` candidate. The menu displays “Thử nghiệm”. The broker
resolves the exact filename in `/usr/local/lib` and
`~/Library/Application Support/TokenSigner/modules`, using the existing helper,
PC/SC shim, approval/PIN flow and host SHA-256 DigestInfo + `CKM_RSA_PKCS` path.

The environment-setup pass deliberately provisioned the exact module
at `~/Library/Application Support/TokenSigner/modules/libcastle_v2.1.0.0.dylib`
after an outside-sandbox hash and `codesign` check; the destination hash and
signature check also passed. At that setup checkpoint the module had not yet
been loaded; App and TokenHelper were not running during provisioning.
See [FCA-ENV-01](#fca-env-01--host-validation-and-provisioning-observed-by-parent).

**Subsequent live test requested by the user:** the module was loaded through
the helper and read-only probes. It sees slots but `C_GetTokenInfo` fails with
`CKR_GENERAL_ERROR (5)`; a public session also fails. The internal error is
`0x30` (`CKR_DEVICE_ERROR`) with the FastCA reader isolated. A separate
multi-reader slot trace returned `0x80100023` at `mscp/cmapfile`; that slot was
not reliably bound to FastCA and must not be used as the FastCA root cause.
ARM64 and x86_64 both fail token-info reads in the multi-reader probes.
The helper therefore returns no usable token. **No login or signing call was
made and no user PIN was supplied.** This candidate has not passed a real
FastCA signing test. See [fastca-live-test.md](fastca-live-test.md).

Generic middleware may report other CAs' tokens. Its registry entry therefore
has `tokenScope = .reader`: only a token whose reported PKCS#11 slot description
exactly equals the PC/SC reader being scanned can contribute certificates or a
signing target. There is no fallback accepting an unrelated single token. If
this build reports `ES SLOT …` instead of the PC/SC reader name, selection fails
closed and reader attribution needs hardware evidence before extending it.
Per-CA modules keep their existing scope.

## Checklist

| Question | Status | Evidence / remaining work |
|---|---|---|
| Why does the current app skip FastCA? | Answered | No `0x69` entry before this change; `AppModel.refreshTokens` requires registry lookup. |
| Is the retained candidate the recorded artifact? | Answered | Exact SHA-256 and size match, FCA-STATIC-01. |
| Does it contain native arm64 and PKCS#11 entry points? | Answered statically | FCA-STATIC-01/02. |
| Is its ATR table compatible with the common FastCA ATR? | Candidate, partially answered | Wildcard byte 19 observed; use by execution and later checks unproved, FCA-STATIC-03. |
| Is its current macOS signature validation clean? | Answered on the host | Outside-sandbox source and destination `codesign --verify --strict --all-architectures` passed; earlier restricted-shell failure retained in FCA-STATIC-04, updated by FCA-ENV-01. |
| Is the candidate provisioned for testing? | Answered | Exact hash copied into the app module directory; no module loading or signing, FCA-ENV-01. |
| Can it enumerate the live token and attribute its reader? | Attempted, blocked | PC/SC sees FastCA; candidate token-info reads fail with rv=5. Slot descriptions are `ES SLOT …`, not PC/SC names. See live report. |
| Can the generic candidate log in and sign through the existing shim? | Not reached | It rejects customer identifier before login; candidate was not used with PIN. |
| Can FastCA sign natively through a separate backend? | Observed success | OpenSC/ESPK helper: authentication/MSE/PSO all 9000; 256-byte signature independently verified. Menu and SignHash app integration also verified; see app guide. |
| Can the old FastCA certificate be used by a portal? | Unresolved / old cert expired | Cryptographic signing and portal acceptance are separate checks. |

## Evidence ledger

These `FCA-STATIC-*` and `FCA-ENV-*` IDs are local analyst evidence identifiers,
**not REA Evidence IDs**. The native REA session was reserved for the separate installer analysis;
these checks use ordinary read-only file tools. Reusable measurements are in
[fastca-static-evidence.json](fastca-static-evidence.json). Recompute with:

```sh
python3 docs/re/fastca-static-check.py /absolute/path/libcastle_v2.1.0.0.dylib
```

The script is a bounded check for this known two-slice universal artifact, not
a general Mach-O validator. It reads bytes, checks CodeDirectory code slots and
reports raw ATR candidates; it does not load or execute the module. Code-slot
checks do not validate special slots, certificate trust, notarization or runtime.

### FCA-STATIC-01 — exact retained artifact (observed)

File: `/private/tmp/fastca-mac-94626/inspect/libcastle_v2.1.0.0.dylib`.
The copy under `pkg/exp/pkcs11.pkg/Payload/` has the same digest.

- Size: 3,717,296 bytes.
- SHA-256: `3e7b9e91a861fccbafa9e992daa4c3c4746d9a20eb99e2f43ac860037159cf9c`.
- Universal slices: x86_64 at file offset 16,384, size 1,865,904; arm64 at
  1,884,160, size 1,833,136 (`file`, `lipo -info`, header parser).
- arm64 SHA-256: `7de76bea13da1a51bf97585ed499580803a6c67620967107a1c0c40b573d19ff`.
- x86_64 SHA-256: `1b913b2ae95aa56d873859c38eadfc3841d01e5e966adef3ac6c27ef71cd5063`.

### FCA-STATIC-02 — interface and linkage (observed)

`nm -gU -arch arm64` exposes the 68 standard `C_*` symbols and
`E_GetAuxFunctionList`, including `C_GetFunctionList`, `C_Initialize`,
`C_GetSlotList`, `C_GetTokenInfo`, `C_Login`, `C_SignInit`, `C_Sign` and `C_Logout`.
`otool -L` shows `PCSC.framework`, CoreFoundation, IOKit, libc++ and libSystem
on both architectures. PC/SC linkage makes the existing shim a candidate route;
it does not establish which APDUs this module sends or that the shim handles them.

### FCA-STATIC-03 — ATR candidate and limits (observed bytes, inferred role)

One common ePass2003 ATR template occurs at arm64 slice offset `0x188192`
(file `0x354192`) and x86_64 slice offset `0x197290` (file `0x19b290`):

```text
value 3b 9f 95 81 31 fe 9f 00 66 46 53 05 00 00 00 71 df 00 00 00 00 00 00
mask  ff ff ff ff ff ff ff ff ff ff ff ff 00 00 00 ff ff ff 00 00 00 00 00
```

On arm64 the candidate mask immediately follows the 23-byte value. On x86_64
it starts 32 bytes after the value (9 bytes of padding), correcting the earlier
claim that the layout was identical. Mask byte 19 is zero. This supports trying
the candidate for the `0x69` token. It does **not** prove table usage, absence of
another customer check, successful enumeration, application compatibility or
manufacturer/issuer approval for FastCA.

A bounded string search in the earlier investigation found only generic
Hypersecu/HYP2003/EnterSafe branding. Absence of a recognizable string is not
proof that a secondary check is absent.

### FCA-STATIC-04 — earlier restricted-shell signature observations

During the initial restricted-shell pass, `codesign -dvvv` reported identifier
`libcastle_v2`, Team ID `S47T4UESP3`, hardened-runtime flag and
`Authority=(unavailable)`. Both `codesign --verify --strict --verbose=4` and
`--all-architectures --verbose=4` returned **invalid signature**, naming arm64.
These are historical results from that environment, superseded for current
host validation by FCA-ENV-01 below.

Independent bounded byte checks found zero mismatched code slots in both SHA-1
and SHA-256 CodeDirectories: 446 slots for x86_64 and 438 for arm64. Extracted
CMS blobs verified cryptographically against each slice's primary SHA-1
CodeDirectory using `openssl cms -verify -binary -inform DER ... -noverify`.
The embedded certificate subject names `Developer ID Application: FEITIAN
Technologies Co.,Ltd. (S47T4UESP3)`, issued by Developer ID Certification Authority.
`-noverify` skips chain validation and does not establish notarization.

The restricted shell also reported `/usr/bin/codesign: CSSMERR_TP_NOT_TRUSTED`
for `codesign --verify --strict --verbose=4 /usr/bin/codesign` (arm64e.x1).
This control failed on a system binary as well as the candidate. An earlier
outside-sandbox request was cancelled while pending and supplied no result;
the later successful host checks are a separate observation. The comparison
supports an environment-dependent failure rather than a claim of modified
vendor bytes. Its exact low-level cause was not determined. No binary patch,
re-signing or trust-store change was made.

### FCA-ENV-01 — host validation and provisioning (observed by parent)

In the subsequent environment-setup pass on 2026-10-22, the parent agent ran the
checks outside the restricted shell. Its transcribed results are retained in
[fastca-environment-20261022.txt](evidence/fastca-environment-20261022.txt).
This child documentation pass did not repeat the probes.

- The source still has SHA-256
  `3e7b9e91a861fccbafa9e992daa4c3c4746d9a20eb99e2f43ac860037159cf9c`.
- `codesign --verify --strict --all-architectures` on that source returned exit
  0: valid on disk and satisfying its designated requirement.
- `codesign -dvvv` reports the authority chain `Developer ID Application:
  FEITIAN Technologies Co.,Ltd. (S47T4UESP3)` → `Developer ID Certification
  Authority` → `Apple Root CA`, and timestamp `13 Feb 2025 13:35:59`.
- The `/usr/bin/codesign` control also passed outside the restricted shell.
- The unmodified module was copied to
  `~/Library/Application Support/TokenSigner/modules/libcastle_v2.1.0.0.dylib`;
  the destination hash matched and the destination signature check passed.

These observations establish current host code-signature validation and
provisioning of the exact candidate. They do not establish notarization,
FastCA issuer approval, reader enumeration, PIN login, token signing or portal
acceptance. App/TokenHelper were not running; the module was not loaded.

## Historical acquisition provenance (not fetched again in this pass)

The retained archive was acquired on 2026-10-21 from Hypersecu's CDN:
`https://www.hypersecu.com/_files/archives/5aae8d_455153f9dcfa4f98a57824244cc520a3.zip?dn=HYP2003-MAC-iOS.zip`.
It contains `HYP2003-India_20250213.dmg`; the expanded package supplied the candidate.

- `hyp.zip` SHA-256: `a57a1efb7d278fd0e8ca8bf9803faf7b6cd804e789f443e71aa06cf6105cca62`.
- DMG SHA-256: `72a95d4014e71faa0fc5e25d1129abeac277398781433fbd188748c907efc9a7`.
- Historical notes reported a Feitian Developer ID Installer signature and
  notarization for the package; those checks were not reproduced in this pass.

This is third-party-distributed middleware with an embedded Feitian identity,
not a FastCA-branded macOS build or evidence of FastCA support approval.
The earlier bounded search for a branded build is in [fastca-oneca.md](fastca-oneca.md).

## Integration / runtime status

Native App/TokenHelper integration, catalog-based cert/key resolution, normal
approval/PIN, signature verification and certificate-serial → token-serial routing
are complete. Both menu signing and a local SignHash test passed. Current software
suite: 38 tests passed. No vendor binary, ATR or card response was patched.

OpenSC runtime 0.27.1 is a required installed dependency; missing/wrong versions
produce a visible error. Future distribution/runtime bundling, more card profiles,
physical multi-token/hotplug tests and portal acceptance remain outside this test.
Windows ARM results remain in [Windows report](windows-signing-test.md).

## Code verification (2026-10-22)

**Current host environment:** the parent agent ran `scripts/test-env.sh all`
outside the restricted shell; it returned exit 0. Core build completed in
22.54 seconds, test build in 14.23 seconds, and all 31 Core/shim/bridge tests
passed (3 shim, 17 Core, 11 Bridges). The same invocation passed all 81 M-Invoice
software tests in its existing worktree. The provisioned FastCA module's hash
and signature checks passed; App and TokenHelper were not running and the
module was not loaded. This establishes software-test environment readiness for
both projects at that earlier checkpoint. Later hardware results are recorded in
the native and Windows reports linked above.

Host logs are under `.local/test-env/logs/`: `core-build.log`, `core-tests.log`
and `minvoice/`. The transcribed combined result is retained with
[FCA-ENV-01](evidence/fastca-environment-20261022.txt).

**Earlier restricted-shell validation:**

Build passed; all 31 tests passed (3 shim, 17 Core, 11 Bridges). The added Core
test feeds mixed FastCA/other/unknown readers into the generic candidate scope
and verifies that only the exact FastCA reader is retained, including rejection
of a single unrelated token. These are software checks, not a token test.
The concise transcribed result log is
[fastca-validation-20261022.txt](evidence/fastca-validation-20261022.txt).

The restricted shell required writable temporary module caches and disabling
SwiftPM's nested sandbox, which otherwise failed with `sandbox_apply: Operation
not permitted`:

```sh
CLANG_MODULE_CACHE_PATH=/private/tmp/tokensigner-fastca-clang-cache \
SWIFTPM_MODULECACHE_OVERRIDE=/private/tmp/tokensigner-fastca-swift-cache \
swift build --disable-sandbox --cache-path /private/tmp/tokensigner-fastca-spm-cache

CLANG_MODULE_CACHE_PATH=/private/tmp/tokensigner-fastca-clang-cache \
SWIFTPM_MODULECACHE_OVERRIDE=/private/tmp/tokensigner-fastca-swift-cache \
swift test --disable-sandbox --cache-path /private/tmp/tokensigner-fastca-spm-cache \
  -Xswiftc -plugin-path \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
```
