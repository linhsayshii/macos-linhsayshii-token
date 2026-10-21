#!/bin/zsh
# Sign-path spike across every CA whose PKCS#11 dylib is available. For each token
# it logs in and signs a SHA-256 DigestInfo via CKM_RSA_PKCS, then verifies the
# signature with openssl against the cert's public key. The PIN is read hidden and
# only piped to the helper; it never appears in output or in a process argument.
#
# Stop the running app first (Ctrl-C the `swift run App` terminal) so it does not
# contend for the tokens over PC/SC. Wrong PIN burns one retry — skip a CA with
# Ctrl-C at its PIN prompt if unsure.
set -u
ROOT=${0:A:h:h}
HELPER=$(cd "$ROOT" && swift build --show-bin-path)/TokenHelper
SHIM=$(find "$ROOT/.build" -name libTSShim.dylib | head -1)
APPMOD="$HOME/Library/Application Support/TokenSigner/modules"

# CA label -> module path. Resolve across /usr/local/lib and the app modules dir.
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
    SERIAL=$(printf '%s\n' '{"listTokens":{}}' | run | python3 -I -c 'import sys,json
try:
    t=json.load(sys.stdin)["tokens"]["_0"]
    print(t[0]["serial"] if t else "")
except Exception: print("")')
    if [[ -z "$SERIAL" ]]; then echo "== $ca: no token, skip"; rm -rf "$WORK"; return; fi
    echo "== $ca  (serial $SERIAL)"

    local CERTJSON CERTID EXP
    CERTJSON=$(printf '%s\n' "{\"listCerts\":{\"serial\":\"$SERIAL\"}}" | run)
    eval "$(printf '%s' "$CERTJSON" | python3 -I - "$WORK" <<'PY'
import sys, json, base64, os
work = sys.argv[1]
certs = json.load(sys.stdin)["certs"]["_0"]
c = max(certs, key=lambda x: x["notAfter"])
open(os.path.join(work, "cert.der"), "wb").write(base64.b64decode(c["derB64"]))
print(f'CERTID={c["id"]}'); print(f'EXP="{c["notAfter"]}"')
PY
)"
    echo "   cert id $CERTID (exp $EXP)"

    local MSG="macos-linhsayshii-token sign-test"
    printf '%s' "$MSG" | openssl dgst -sha256 -binary > "$WORK/digest.bin"
    { printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'; cat "$WORK/digest.bin"; } > "$WORK/di.bin"
    local DIB64; DIB64=$(base64 < "$WORK/di.bin" | tr -d '\n')

    local PIN
    if ! read -s "PIN?   $ca user PIN (hidden, Ctrl-C to skip): "; then echo; rm -rf "$WORK"; return; fi
    echo
    local OUT
    OUT=$(printf '%s\n%s\n' \
      "{\"login\":{\"serial\":\"$SERIAL\",\"pin\":\"$PIN\"}}" \
      "{\"sign\":{\"serial\":\"$SERIAL\",\"certId\":\"$CERTID\",\"mech\":\"RSA_PKCS\",\"dataB64\":\"$DIB64\"}}" \
      | run)
    PIN=""
    printf '%s' "$OUT" | WORK="$WORK" python3 -I -c 'import sys,json,base64,os
work=os.environ["WORK"]
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    d=json.loads(line)
    if "loginResult" in d: print("   login:", d["loginResult"])
    elif "signature" in d:
        s=d["signature"]; s=s["_0"] if isinstance(s,dict) else s
        open(work+"/sig.bin","wb").write(base64.b64decode(s)); print("   signature:", len(open(work+"/sig.bin","rb").read()), "bytes")
    elif "error" in d: print("   error:", d["error"])'

    if [[ -s "$WORK/sig.bin" ]]; then
        openssl x509 -inform DER -in "$WORK/cert.der" -noout -pubkey > "$WORK/pub.pem" 2>/dev/null
        if openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -sigfile "$WORK/sig.bin" \
             -in "$WORK/digest.bin" -pkeyopt digest:sha256 >/dev/null 2>&1; then
            echo "   RESULT: $ca OK (CKM_RSA_PKCS verified)"
        else
            echo "   RESULT: $ca verify FAILED"
        fi
    else
        echo "   RESULT: $ca no signature"
    fi
    rm -rf "$WORK"
}

for ca in VNPT NC-CA CMC I-CA; do
    sign_one "$ca" "${MODULES[$ca]}"
done
echo "done"
