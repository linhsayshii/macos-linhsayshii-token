#!/bin/zsh
# Prepare/run local FastCA and M-Invoice software tests. No token login/signing.
set -euo pipefail

TASK_ROOT=${0:A:h:h}
TASK_STATE="$TASK_ROOT/.local/test-env"
mkdir -p "$TASK_STATE/tmp" "$TASK_STATE/logs"
export TMPDIR="$TASK_STATE/tmp/"

check_environment() {
    for task_tool in swift swiftc python3 codesign lipo openssl xmlsec1; do
        command -v "$task_tool" >/dev/null || { print -u2 "Missing tool: $task_tool"; return 1; }
    done
    TASK_DEVELOPER=$(xcode-select -p)
    [[ -d "$TASK_DEVELOPER/usr/lib/swift/host/plugins/testing" ]] || {
        print -u2 "Testing macro plugin unavailable in $TASK_DEVELOPER"; return 1;
    }
    python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); s.close(); print("PASS loopback bind")'
    cat > "$TASK_STATE/check-security.swift" <<'SWIFT'
import Foundation
import Security
var error: Unmanaged<CFError>?
let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false]
guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
    if let e = error?.takeRetainedValue() {
        let ns = e as Error as NSError
        fputs("SecKey preflight failed: \(ns.domain) / \(ns.code)\n", stderr)
    }
    exit(1)
}
print("PASS ephemeral RSA fixture (not persisted)")
SWIFT
    swiftc "$TASK_STATE/check-security.swift" -framework Security -o "$TASK_STATE/check-security"
    "$TASK_STATE/check-security"
    codesign --verify --strict /usr/bin/codesign
    print "PASS system code-signature control"
}

setup_fastca() {
    [[ -z ${1:-} ]] || { print -u2 "FastCA native no longer accepts a vendor module path."; return 2; }
    python3 -I - <<'PYTHON'
import ctypes
from pathlib import Path
paths = ['/opt/homebrew/lib/libopensc.13.dylib', '/usr/local/lib/libopensc.13.dylib',
         '/Library/OpenSC/lib/libopensc.13.dylib']
path = next((p for p in paths if Path(p).is_file()), None)
if path is None:
    raise SystemExit('FastCA requires the OpenSC 0.27.1 runtime; none found. No software was installed.')
library = ctypes.CDLL(path)
library.sc_get_version.restype = ctypes.c_char_p
version = library.sc_get_version().decode()
if version != '0.27.1':
    raise SystemExit(f'Unsupported OpenSC ABI {version}; expected 0.27.1. Nothing changed.')
print(f'READY native FastCA: OpenSC {version} at {path}')
print('Runtime check only; no token connection, PIN or signing.')
PYTHON
}

test_core() {
    local task_developer=$(xcode-select -p)
    export CLANG_MODULE_CACHE_PATH="$TASK_STATE/clang-cache"
    export SWIFTPM_MODULECACHE_OVERRIDE="$TASK_STATE/swift-cache"
    cd "$TASK_ROOT"
    swift build --cache-path "$TASK_STATE/spm-cache" 2>&1 | tee "$TASK_STATE/logs/core-build.log"
    swift test --cache-path "$TASK_STATE/spm-cache" \
        -Xswiftc -plugin-path -Xswiftc "$task_developer/usr/lib/swift/host/plugins/testing" \
        2>&1 | tee "$TASK_STATE/logs/core-tests.log"
}

test_minvoice() {
    local task_developer=$(xcode-select -p)
    export CLANG_MODULE_CACHE_PATH="$TASK_STATE/clang-cache"
    export SWIFTPM_MODULECACHE_OVERRIDE="$TASK_STATE/swift-cache"
    cd "$TASK_ROOT"
    swift test --cache-path "$TASK_STATE/spm-cache" \
        -Xswiftc -plugin-path -Xswiftc "$task_developer/usr/lib/swift/host/plugins/testing" \
        --filter 'minvoice|negotiateAndLongPollRoundTrip|rejectsUnknownOriginAndBadHost|webSocketTransport' \
        2>&1 | tee "$TASK_STATE/logs/minvoice-tests.log"
}

case ${1:-check} in
    check) check_environment ;;
    setup-fastca) setup_fastca "${2:-}" ;;
    setup) check_environment; setup_fastca "${2:-}" ;;
    test-core) check_environment; test_core ;;
    test-minvoice) check_environment; test_minvoice ;;
    test-all) check_environment; test_core ;;
    all) check_environment; setup_fastca "${2:-}"; test_core ;;
    *) print -u2 "Usage: $0 check|setup|setup-fastca|test-core|test-minvoice|test-all|all"; exit 2 ;;
esac
