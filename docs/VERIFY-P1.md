# P1 hardware verification (run by the user, token plugged in)

Build first (one builder at a time):

    swift build

## 1. token-helper reads a token (shim applied)

    HELPER=$(swift build --show-bin-path)/TokenHelper
    SHIM=$(find .build -name libTSShim.dylib | head -1)
    echo '{"listTokens":{}}' | DYLD_INSERT_LIBRARIES=$SHIM "$HELPER" --module /usr/local/lib/libvnptca_p11_v8.dylib

Expect one JSON line with the VNPT token serial and label, and zero 0x80100016 errors.
List certs (no PIN):

    echo '{"listCerts":{"serial":"<serial from above>"}}' | DYLD_INSERT_LIBRARIES=$SHIM "$HELPER" --module /usr/local/lib/libvnptca_p11_v8.dylib

## 2. Menu bar app serves the bridge

    swift run App            # a key icon appears in the menu bar; token list fills in
    # another terminal:
    curl -s http://127.0.0.1:32001/api/SignHash/Version
    curl -s http://127.0.0.1:32001/api/HubClient/GetCert | python3 -m json.tool

GetCert must list the plugged VNPT/NC-CA certs. SignHash is wired through
host-side SHA-256 DigestInfo + CKM_RSA_PKCS (commit `caa25ba`).

## Signing prompts with the menu bar closed

1. Start the app, leave the menu bar popover closed, and send a valid SignHash
   request from an allowed origin using a serial returned by GetCert.
2. A separate approval window must appear in front of the browser. Close it:
   the request must return a refusal, without asking for a PIN.
3. Repeat and choose “Chỉ lần này”. The PIN window must appear. Close it:
   the request must return cancellation and clear the PIN draft.
4. Repeat with “Cho phép 10 phút”. Later requests within that session skip
   approval but must still show the PIN window and its retry warning.
5. Send a second request while the first awaits approval/PIN. It must return
   a busy error without replacing the first prompt.

The reader loop polls every 175 ms and only refreshes helpers when the reader/ATR
set changes. A read-only PC/SC probe on this host returned `dwEventState=0x6`
(`SCARD_STATE_UNKNOWN | SCARD_STATE_CHANGED`) for `\\?PnP?\Notification`, so
blocking PnP notifications are unavailable here.

The window presenter can also be checked without a token or a PIN:

    swiftc -parse-as-library Sources/App/SigningPromptWindow.swift scripts/check-prompt-window.swift -o /tmp/tokensigner-window-check
    /tmp/tokensigner-window-check

Run in a logged-in macOS desktop session with WindowServer access. The harness
starts a complete AppKit event loop, asserts window visibility/key focus/app
activation, close cancellation, the next prompt, and programmatic dismissal.
It exits automatically without opening the menu bar popover or a token helper.

## 3. Confirm signing on hardware

Use “Ký thử” in the app or the existing `scripts/sign-test.sh` harness, approve
the request, and enter the PIN yourself. The app signs a host-computed SHA-256
DigestInfo with CKM_RSA_PKCS. Verify the returned signature with the certificate's
public key. Do not switch real document signing back to on-card hashing:
CKM_SHA256_RSA_PKCS fails for messages of 240 bytes or more on these tokens.

## Verified 2026-10-21 (by Claude, read-only, no PIN)
- Step 1 token-helper: listTokens → VNPT token serial 271C52B10035A10F, label "VNPT-CA PKI Token".
  listCerts → 2 certs (exp 2025-07-28 and 2029-08-30), subject/issuer/serial/dates parsed. Zero 0x80100016.
- (verify) subjectDN renders the UID as its raw OID `0.9.2342.19200300.100.1.1=MST:...` rather than `UID=MST:...`.
  CTSigningHub's real subjectDN string may differ; confirm against a Parallels capture before relying on the exact string.
- Binary name is `TokenHelper` (SwiftPM names it after the target), not `token-helper`.

## Verified 2026-10-21 end-to-end through the app (read path, no PIN)
- `swift run App` → bridge up on 127.0.0.1:32001.
- GET /api/SignHash/Version → "1.2.0.0". GET /api/Info/GetInfoCert → "1".
- GET /api/HubClient/GetCert → status 200 SUCCESS, 2 real VNPT certs (serinumber,
  subjectDN, issuedDN, validFrom/validTo, pemCert base64 DER). Full chain works:
  ReaderScanner → ModuleRegistry → TokenBroker → vendor dylib + shim → X509 parse → bridge.
- Open: subjectDN UID renders as the raw OID 0.9.2342.19200300.100.1.1=MST:... (cosmetic, verify vs portal).

## Sign-mechanism finding (2026-10-21, hardware, VNPT/NC-CA/I-CA)

Historical findings below are superseded by the transport/Le fix and the
host-hash signing path documented in [PROGRESS.md](PROGRESS.md).
- CKM_RSA_PKCS (sign a precomputed SHA-256 DigestInfo) → C_Sign rv=48 CKR_DEVICE_ERROR on all.
- CKM_SHA256_RSA_PKCS (token hashes the raw message on-card) → works, 256-byte sig, openssl verified.
- CMC was not tested (wrong PIN entered).
Implication: CTSigningHub's SignHash sends a precomputed hash, which CKM_RSA_PKCS cannot sign here.
Testing CKM_RSA_X_509 (raw RSA over a host-padded PKCS#1 block) next to serve the precomputed-hash path.

## Sign-mechanism finding, round 2 (NC-CA, I-CA)
- CKM_RSA_X_509 (raw RSA over host-padded PKCS#1 block) → also C_Sign rv=48 CKR_DEVICE_ERROR.
- Only CKM_SHA256_RSA_PKCS (raw message, on-card hash) verifies.
- VNPT, CMC: wrong PIN entered, not measured.
Conclusion: these Feitian macOS dylibs sign only the raw message (on-card hash); no precomputed-hash
mechanism works. So CTSigningHub signxml/signpdf (raw document) is feasible, but bare SignHash is not,
via the vendor dylibs. scripts/trace-sign.sh traces the failing sign to tell card-reject from a macOS 27
transport drop (0x80100016) the shim misses.
