#!/bin/zsh
# Sign-path spike across every CA whose PKCS#11 dylib is available. For each token
# it logs in, then tries BOTH mechanisms and reports which the token accepts:
#   A) CKM_RSA_PKCS over a SHA-256 DigestInfo (what CTSigningHub's precomputed-hash
#      path needs), verified with openssl pkeyutl.
#   B) CKM_SHA256_RSA_PKCS over the raw message (token hashes on-card), verified
#      with openssl dgst.
# The PIN is read hidden and only piped to the helper; it never appears in output.
#
# Stop the running app first (Ctrl-C the `swift run App` terminal) so it does not
# contend for the tokens over PC/SC. Wrong PIN burns one retry.
set -u
ROOT=${0:A:h:h}
HELPER=$(cd "$ROOT" && swift build --show-bin-path)/TokenHelper
SHIM=$(find "$ROOT/.build" -name libTSShim.dylib | head -1)
APPMOD="$HOME/Library/Application Support/TokenSigner/modules"

typeset -A MODULES
MODULES[VNPT]="/usr/local/lib/libvnptca_p11_v8.dylib"
MODULES[NC-CA]="$APPMOD/ncca_csp11_v1.dylib"
MODULES[CMC]="$APPMOD/cmcca_csp11_v1.dylib"
MODULES[I-CA]="$APPMOD/ica_csp11_v1.dylib"

sign_one() {
    local ca="$1" module="$2"
    [[ -f "$module" ]] || { echo "== $ca: no dylib, skip"; return; }
    local WORK; WORK=$(mktemp -d)
    run() { DYLD_INSERT_LIBRARIES=$SHIM "$HELPER" --module "$module"; }

    local SERIAL
    SERIAL=$(printf '%s\n' '{"listTokens":{}}' | run | SIN=1 python3 -I -c 'import sys,json
try:
    t=json.load(sys.stdin)["tokens"]["_0"]; print(t[0]["serial"] if t else "")
except Exception: print("")')
    if [[ -z "$SERIAL" ]]; then echo "== $ca: no token, skip"; rm -rf "$WORK"; return; fi
    echo "== $ca  (serial $SERIAL)"

    # Parse certs: script from heredoc, JSON via env var (no stdin clash).
    local CERTJSON; CERTJSON=$(printf '%s\n' "{\"listCerts\":{\"serial\":\"$SERIAL\"}}" | run)
    eval "$(CJ="$CERTJSON" WORK="$WORK" python3 -I <<'PY'
import os, json, base64
d = json.loads(os.environ["CJ"])["certs"]["_0"]
c = max(d, key=lambda x: x["notAfter"])
open(os.path.join(os.environ["WORK"], "cert.der"), "wb").write(base64.b64decode(c["derB64"]))
print(f'CERTID={c["id"]}'); print(f'EXP="{c["notAfter"]}"')
PY
)"
    echo "   cert id $CERTID (exp $EXP)"

    local MSG="macos-linhsayshii-token sign-test"
    printf '%s' "$MSG" > "$WORK/msg.txt"
    openssl dgst -sha256 -binary < "$WORK/msg.txt" > "$WORK/digest.bin"
    { printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'; cat "$WORK/digest.bin"; } > "$WORK/di.bin"
    local DIB64 MSGB64
    DIB64=$(base64 < "$WORK/di.bin" | tr -d '\n')
    MSGB64=$(base64 < "$WORK/msg.txt" | tr -d '\n')

    local PIN
    if ! read -s "PIN?   $ca user PIN (hidden, Ctrl-C to skip): "; then echo; rm -rf "$WORK"; return; fi
    echo
    # login, then sign A (RSA_PKCS/DigestInfo) and sign B (SHA256_RSA_PKCS/raw) in one session.
    local OUT
    OUT=$(printf '%s\n%s\n%s\n' \
      "{\"login\":{\"serial\":\"$SERIAL\",\"pin\":\"$PIN\"}}" \
      "{\"sign\":{\"serial\":\"$SERIAL\",\"certId\":\"$CERTID\",\"mech\":\"RSA_PKCS\",\"dataB64\":\"$DIB64\"}}" \
      "{\"sign\":{\"serial\":\"$SERIAL\",\"certId\":\"$CERTID\",\"mech\":\"SHA256_RSA_PKCS\",\"dataB64\":\"$MSGB64\"}}" \
      | run)
    PIN=""
    # line 1 = login, line 2 = sign A, line 3 = sign B. Parse via env + heredoc.
    OUT="$OUT" WORK="$WORK" python3 -I <<'PY'
import json, base64, os
work = os.environ["WORK"]; n = 0
for line in os.environ["OUT"].splitlines():
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if "loginResult" in d:
        print("   login:", d["loginResult"])
    elif "signature" in d:
        n += 1; s = d["signature"]; s = s["_0"] if isinstance(s, dict) else s
        tag = "A" if n == 1 else "B"
        raw = base64.b64decode(s)
        open(os.path.join(work, "sig" + tag + ".bin"), "wb").write(raw)
        print("   sign", tag + ":", len(raw), "bytes")
    elif "error" in d:
        n += 1; tag = "A" if n == 1 else "B"
        print("   sign", tag, "error:", d["error"])
PY

    openssl x509 -inform DER -in "$WORK/cert.der" -noout -pubkey > "$WORK/pub.pem" 2>/dev/null
    if [[ -s "$WORK/sigA.bin" ]] && openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" \
         -sigfile "$WORK/sigA.bin" -in "$WORK/digest.bin" -pkeyopt digest:sha256 >/dev/null 2>&1; then
        echo "   RESULT $ca: CKM_RSA_PKCS (DigestInfo) OK"
    elif [[ -s "$WORK/sigB.bin" ]] && openssl dgst -sha256 -verify "$WORK/pub.pem" \
         -signature "$WORK/sigB.bin" "$WORK/msg.txt" >/dev/null 2>&1; then
        echo "   RESULT $ca: only CKM_SHA256_RSA_PKCS (raw) OK — CKM_RSA_PKCS unusable"
    else
        echo "   RESULT $ca: neither mechanism verified"
    fi
    rm -rf "$WORK"
}

for ca in VNPT NC-CA CMC I-CA; do
    sign_one "$ca" "${MODULES[$ca]}"
done
echo "done"
