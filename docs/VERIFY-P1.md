# P1 hardware verification (run by the user, token plugged in)

Build first (one builder at a time):

    swift build

## 1. token-helper reads a token (shim applied)

    HELPER=$(swift build --show-bin-path)/token-helper
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
