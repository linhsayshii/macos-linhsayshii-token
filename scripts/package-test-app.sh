#!/bin/zsh
# Package existing local build outputs. Does not build, launch or install.
set -euo pipefail
TASK_ROOT=${0:A:h:h}
TASK_BIN=$(cd "$TASK_ROOT" && swift build --show-bin-path)
TASK_APP="$TASK_ROOT/.local/test-env/TokenSigner.app"
if pgrep -x App >/dev/null || pgrep -x TokenHelper >/dev/null; then
    print -u2 "Close App/TokenHelper before replacing the local test bundle."; exit 1
fi
for TASK_FILE in App TokenHelper libTSShim.dylib; do
    [[ -f "$TASK_BIN/$TASK_FILE" ]] || { print -u2 "Build first; missing $TASK_FILE"; exit 1; }
done
"$TASK_ROOT/scripts/test-env.sh" setup-fastca
mkdir -p "$TASK_APP/Contents/MacOS"
for TASK_FILE in App TokenHelper libTSShim.dylib; do
    cp "$TASK_BIN/$TASK_FILE" "$TASK_APP/Contents/MacOS/$TASK_FILE"
    codesign --force --sign - "$TASK_APP/Contents/MacOS/$TASK_FILE"
done
python3 "$TASK_ROOT/scripts/package-native-espk.py" "$TASK_APP"
cat > "$TASK_APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.TokenSigner.AppTest</string>
<key>CFBundleName</key><string>TokenSigner</string>
<key>CFBundleDisplayName</key><string>TokenSigner</string>
<key>CFBundleExecutable</key><string>App</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$TASK_APP"
codesign --verify --strict "$TASK_APP"
python3 "$TASK_ROOT/scripts/check-packaged-shim.py"
print "$TASK_APP"
