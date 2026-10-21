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

GetCert must list the plugged VNPT/NC-CA certs. SignHash is NOT wired yet (needs login, the
rest of Task 11).

## 3. (Task 11 Step 1) CKM_RSA_PKCS spike — settles the spec's top risk

This needs the login/sign path added to token-helper (next work). Once added, the user signs a
SHA-256 DigestInfo via CKM_RSA_PKCS and verifies with openssl. If the lib rejects CKM_RSA_PKCS,
fall back to CKM_SHA256_RSA_PKCS and report.

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
- CKM_RSA_PKCS (sign a precomputed SHA-256 DigestInfo) → C_Sign rv=48 CKR_DEVICE_ERROR on all.
- CKM_SHA256_RSA_PKCS (token hashes the raw message on-card) → works, 256-byte sig, openssl verified.
- CMC was not tested (wrong PIN entered).
Implication: CTSigningHub's SignHash sends a precomputed hash, which CKM_RSA_PKCS cannot sign here.
Testing CKM_RSA_X_509 (raw RSA over a host-padded PKCS#1 block) next to serve the precomputed-hash path.
