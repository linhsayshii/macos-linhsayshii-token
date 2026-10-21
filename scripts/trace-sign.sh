#!/bin/zsh
# Diagnose why CKM_RSA_PKCS fails: trace the PC/SC APDUs during a failing
# precomputed-hash sign on the NC-CA token, so we can see whether the card
# rejects it (a card SW like 6A80/6985) or macOS 27 drops it (0x80100016).
# Inserts the APDU spy + the re-encoding shim. PIN read hidden, piped only.
set -u
ROOT=${0:A:h:h}
HELPER=$(cd "$ROOT" && swift build --show-bin-path)/TokenHelper
SHIM=$(find "$ROOT/.build" -name libTSShim.dylib | head -1)
SPY="/private/tmp/claude-501/-Users-linhsayshii-macos-linhsayshii-token/c7155b36-14ea-4bde-bcd5-4cbdb36c6967/scratchpad/probe/spy.dylib"
MODULE="$HOME/Library/Application Support/TokenSigner/modules/ncca_csp11_v1.dylib"
SERIAL="540E2507021196"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
run() { DYLD_INSERT_LIBRARIES="$SPY:$SHIM" "$HELPER" --module "$MODULE" 2>>"$WORK/apdu.log"; }

CERTID=$(printf '%s\n' "{\"listCerts\":{\"serial\":\"$SERIAL\"}}" | DYLD_INSERT_LIBRARIES="$SHIM" "$HELPER" --module "$MODULE" 2>/dev/null \
  | CJ=1 python3 -I -c 'import sys,json; c=json.load(sys.stdin)["certs"]["_0"]; print(max(c,key=lambda x:x["notAfter"])["id"])')
echo "cert id $CERTID"

printf '%s' "macos sign-test" | openssl dgst -sha256 -binary > "$WORK/digest.bin"
{ printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'; cat "$WORK/digest.bin"; } > "$WORK/di.bin"
DIB64=$(base64 < "$WORK/di.bin" | tr -d '\n')

read -s "PIN?NC-CA user PIN (hidden): "; echo
printf '%s\n%s\n' \
  "{\"login\":{\"serial\":\"$SERIAL\",\"pin\":\"$PIN\"}}" \
  "{\"sign\":{\"serial\":\"$SERIAL\",\"certId\":\"$CERTID\",\"mech\":\"RSA_PKCS\",\"dataB64\":\"$DIB64\"}}" \
  | run
PIN=""
echo "=== last 25 PC/SC APDUs (sign path) ==="
grep -E "^(Tx |SCardConnect|BeginTx)" "$WORK/apdu.log" | tail -25
echo "=== any 0x80100016? ==="
grep -c "0x80100016" "$WORK/apdu.log"
echo "=== non-9000 SW ==="
grep -E "SW=" "$WORK/apdu.log" | grep -vE "SW=9000" | tail -10
