#!/bin/zsh
# Does CKM_SHA256_RSA_PKCS fail on longer messages? (C_Sign rv=48 = CKR_DEVICE_ERROR on a ~600-byte SignedInfo.)
# One login, then signs messages of growing size and prints ok/error per size. PIN is read hidden and only
# piped to the helper. Quit the TokenSigner app first (PC/SC lock). Wrong PIN burns one retry: Ctrl-C if unsure.
# Usage: scripts/sign-size-test.sh [NC-CA|VNPT]   (default NC-CA)
set -u
ROOT=${0:A:h:h}
CA=${1:-NC-CA}
HELPER=$(cd "$ROOT" && swift build --show-bin-path)/TokenHelper
SHIM=$(find "$ROOT/.build" -name libTSShim.dylib | head -1)
APPMOD="$HOME/Library/Application Support/TokenSigner/modules"
typeset -A MODULES
MODULES[VNPT]="/usr/local/lib/libvnptca_p11_v8.dylib"
MODULES[NC-CA]="$APPMOD/ncca_csp11_v1.dylib"
module=${MODULES[$CA]}
run() { DYLD_INSERT_LIBRARIES=$SHIM "$HELPER" --module "$module"; }

SERIAL=$(printf '%s\n' '{"listTokens":{}}' | run | python3 -I -c 'import sys,json;t=json.load(sys.stdin)["tokens"]["_0"];print(t[0]["serial"] if t else "")')
[[ -n "$SERIAL" ]] || { echo "no token"; exit 1; }
CERTID=$(printf '%s\n' "{\"listCerts\":{\"serial\":\"$SERIAL\"}}" | run | python3 -I -c 'import sys,json;d=json.load(sys.stdin)["certs"]["_0"];print(max(d,key=lambda x:x["notAfter"])["id"])')
echo "$CA token $SERIAL cert id $CERTID"
read -s "PIN?PIN (hidden): "; echo
SIZES=(${=SIZES_OVERRIDE:-32 100 200 240 256 300 400 600 800})
# RSA_PKCS first (DigestInfo of a SHA-256 over 240 bytes, 51 bytes on the wire) so the log shows exactly how the card/CCID reacts.
DIB64=$( { printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'; head -c 240 /dev/zero | tr '\0' 'a' | openssl dgst -sha256 -binary; } | base64 | tr -d '\n')
{
  printf '%s\n' "{\"login\":{\"serial\":\"$SERIAL\",\"pin\":\"$PIN\"}}"
  printf '%s\n' "{\"sign\":{\"serial\":\"$SERIAL\",\"certId\":\"$CERTID\",\"mech\":\"RSA_PKCS\",\"dataB64\":\"$DIB64\"}}"
  for n in $SIZES; do
    B64=$(head -c $n /dev/zero | tr '\0' 'a' | base64 | tr -d '\n')
    printf '%s\n' "{\"sign\":{\"serial\":\"$SERIAL\",\"certId\":\"$CERTID\",\"mech\":\"SHA256_RSA_PKCS\",\"dataB64\":\"$B64\"}}"
  done
} | { if [[ -n "${TSLOG:-}" ]]; then TSSHIM_LOG=1 run 2>/tmp/tsshim.log; else run 2>/dev/null; fi; } | OUT_SIZES="RSA_PKCS-DigestInfo ${SIZES[*]}" python3 -I -c '
import sys, json, os
sizes = os.environ["OUT_SIZES"].split(); i = -1
for line in sys.stdin:
    d = json.loads(line)
    if "loginResult" in d: print("login:", d["loginResult"]); continue
    i += 1
    r = "ok" if "signature" in d else d.get("error")
    print(f"{sizes[i]:>20}: {r}")
'
PIN=""
