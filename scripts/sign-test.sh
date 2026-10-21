#!/bin/zsh
# Sign-path spike: log in to the VNPT token and sign a SHA-256 DigestInfo via
# CKM_RSA_PKCS, then verify the signature with openssl against the cert's public key.
# The PIN is read hidden and only piped to the helper; it never appears in output.
#
# Stop the running app first (Ctrl-C the `swift run App` terminal) so it does not
# contend for the token over PC/SC.
set -u
ROOT=${0:A:h:h}
HELPER=$(cd "$ROOT" && swift build --show-bin-path)/TokenHelper
SHIM=$(find "$ROOT/.build" -name libTSShim.dylib | head -1)
MODULE=${1:-/usr/local/lib/libvnptca_p11_v8.dylib}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

run() { DYLD_INSERT_LIBRARIES=$SHIM "$HELPER" --module "$MODULE"; }

# 1. token serial
SERIAL=$(printf '%s\n' '{"listTokens":{}}' | run | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["tokens"]["_0"][0]["serial"])')
echo "token serial: $SERIAL"

# 2. pick the cert with the latest notAfter; get its CKA_ID and DER
CERTJSON=$(printf '%s\n' "{\"listCerts\":{\"serial\":\"$SERIAL\"}}" | run)
eval "$(printf '%s' "$CERTJSON" | python3 -I - "$WORK" <<'PY'
import sys, json, base64, os
work = sys.argv[1]
certs = json.load(sys.stdin)["certs"]["_0"]
c = max(certs, key=lambda x: x["notAfter"])
open(os.path.join(work, "cert.der"), "wb").write(base64.b64decode(c["derB64"]))
print(f'CERTID={c["id"]}')
print(f'EXP={c["notAfter"]!r}')
PY
)"
echo "signing cert id: $CERTID (exp $EXP)"

# 3. build SHA-256 DigestInfo of a test message
MSG="macos-linhsayshii-token sign-test"
printf '%s' "$MSG" | openssl dgst -sha256 -binary > "$WORK/digest.bin"
{ printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'; cat "$WORK/digest.bin"; } > "$WORK/di.bin"
DIB64=$(base64 < "$WORK/di.bin" | tr -d '\n')

# 4. login (hidden PIN) + sign, in one helper session
read -s "PIN?VNPT user PIN (hidden): "; echo
SIG_OUT=$(printf '%s\n%s\n' \
  "{\"login\":{\"serial\":\"$SERIAL\",\"pin\":\"$PIN\"}}" \
  "{\"sign\":{\"serial\":\"$SERIAL\",\"certId\":\"$CERTID\",\"mech\":\"RSA_PKCS\",\"dataB64\":\"$DIB64\"}}" \
  | run)
PIN=""
echo "$SIG_OUT" | python3 -I -c 'import sys,json
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    d=json.loads(line)
    if "loginResult" in d: print("login:", d["loginResult"])
    elif "signature" in d: open("'"$WORK"'/sig.bin","wb").write(__import__("base64").b64decode(d["signature"]["_0"] if isinstance(d["signature"],dict) else d["signature"])); print("signature: %d bytes" % len(open("'"$WORK"'/sig.bin","rb").read()))
    elif "error" in d: print("error:", d["error"])'

# 5. verify with openssl
if [[ -s "$WORK/sig.bin" ]]; then
  openssl x509 -inform DER -in "$WORK/cert.der" -noout -pubkey > "$WORK/pub.pem"
  openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -sigfile "$WORK/sig.bin" \
    -in "$WORK/digest.bin" -pkeyopt digest:sha256 && echo "RESULT: CKM_RSA_PKCS works" || echo "RESULT: verify FAILED"
else
  echo "RESULT: no signature produced"
fi
