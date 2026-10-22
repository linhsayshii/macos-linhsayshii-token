#!/bin/zsh
# Explicit manual launch; setup/test-env never invokes this script automatically.
set -euo pipefail
TASK_ROOT=${0:A:h:h}
TASK_KIND=${1:-}
case "$TASK_KIND" in
    fastca) TASK_WORK="$TASK_ROOT"; TASK_BACKEND=swiftbuild; TASK_PORTS=32001 ;;
    minvoice) TASK_WORK="$TASK_ROOT/.claude/worktrees/beautiful-shirley-8acdc0"; TASK_BACKEND=native; TASK_PORTS=32001,16080,8768,8769,4433,4434 ;;
    *) print -u2 "Usage: $0 fastca|minvoice [--print]"; exit 2 ;;
esac
if (( $# > 2 )) || [[ -n ${2:-} && ${2:-} != --print ]]; then
    print -u2 "Only --print is accepted after the app name."; exit 2
fi
TASK_BIN=$(cd "$TASK_WORK" && swift build --build-system "$TASK_BACKEND" --show-bin-path)
for TASK_FILE in App TokenHelper libTSShim.dylib; do
    [[ -f "$TASK_BIN/$TASK_FILE" ]] || { print -u2 "Missing $TASK_FILE: run scripts/test-env.sh test-all first."; exit 1; }
done
if [[ ${2:-} == --print ]]; then
    print "$TASK_BIN/App"
    exit 0
fi
if pgrep -x App >/dev/null || pgrep -x TokenHelper >/dev/null; then
    print -u2 "Close the other App/TokenHelper before launching this worktree."; exit 1
fi
python3 -I - "$TASK_PORTS" <<'PY'
import socket,sys
for port in map(int,sys.argv[1].split(',')):
    with socket.socket() as s:
        try: s.bind(('127.0.0.1',port))
        except OSError: sys.exit(f'Port {port} is busy; no process was stopped.')
PY
print "Starting $TASK_KIND app. Attached tokens may be enumerated."
print "Signing still requires approval and PIN in the local window."
export TOKENSIGNER_PORT_OFFSET=0
cd "$TASK_WORK"
exec "$TASK_BIN/App"
