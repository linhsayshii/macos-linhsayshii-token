#!/bin/sh
# Guard smoke test against a running TokenSigner. Dev run next to the installed app:
#   TOKENSIGNER_PORT_OFFSET=100 .build/out/Products/Debug/App &   then   ./scripts/p2-smoke.sh 100
OFF=${1:-0}; P=$((32001+OFF)); B=http://127.0.0.1:$P; O=https://thuedientu.gdt.gov.vn
echo "allowed origin (expect 200 + ACAO + PNA):"; curl -si $B/api/SignHash/Version -H "Origin: $O" | grep -iE "HTTP/|access-control"
echo "bad Host (expect 403):";      curl -si $B/api/SignHash/Version -H "Host: evil.com:$P" | head -1
echo "unknown Origin (expect 403):"; curl -si $B/api/SignHash/Version -H "Origin: https://evil.example" | head -1
echo "signxml (needs a token + approval + PIN; use a real cert serial):"
echo "  curl -s $B/api/HubClient/signxml -H 'Origin: $O' -d '{\"serinumber\":\"<CERT_SERIAL_HEX>\",\"dataFile\":\"'\$(printf '<HDon><DSCKS><NBan/></DSCKS></HDon>' | base64)'\"}'"
