#!/bin/zsh
# Manual launch of the single integrated checkout. No build, install or PIN input.
set -euo pipefail
TASK_ROOT=${0:A:h:h}
TASK_KIND=${1:-all}
case "$TASK_KIND" in
    all|fastca|minvoice|esigner|vnpt) ;;
    *) print -u2 "Usage: $0 [all|fastca|minvoice|esigner|vnpt] [--print]"; exit 2 ;;
esac
if (( $# > 2 )) || [[ -n ${2:-} && ${2:-} != --print ]]; then
    print -u2 "Only --print is accepted after the app name."; exit 2
fi
TASK_BIN=$(cd "$TASK_ROOT" && swift build --show-bin-path)
for TASK_FILE in App TokenHelper libTSShim.dylib; do
    [[ -f "$TASK_BIN/$TASK_FILE" ]] || { print -u2 "Missing $TASK_FILE: run scripts/test-env.sh test-all first."; exit 1; }
done
if [[ ${2:-} == --print ]]; then
    print "$TASK_BIN/App"; exit 0
fi
if pgrep -x App >/dev/null || pgrep -x TokenHelper >/dev/null; then
    print -u2 "Close the running App/TokenHelper before launching another signer."; exit 1
fi
python3 -I - "${TOKENSIGNER_PORT_OFFSET:-0}" <<'PY'
import socket,sys
try: offset=int(sys.argv[1])
except ValueError: raise SystemExit('Invalid TOKENSIGNER_PORT_OFFSET')
if not 0 <= offset <= 65535-32001: raise SystemExit('Invalid TOKENSIGNER_PORT_OFFSET')
for base in (32001,16080,8768,8769,4433,4434):
    port=base+offset
    with socket.socket() as s:
        try: s.bind(('127.0.0.1',port))
        except OSError: raise SystemExit(f'Port {port} is busy; no process was stopped.')
PY
print "Starting the integrated app with all six listeners. Tokens may be enumerated."
print "Signing requires the native certificate picker, consent and PIN."
cd "$TASK_ROOT"
exec "$TASK_BIN/App"
