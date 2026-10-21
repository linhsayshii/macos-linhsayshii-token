# Build and test

Command Line Tools only (no Xcode). Build:

    swift build

Run tests — this environment needs the Testing macro plugin path passed explicitly,
or `swift test` fails with "plugin for module 'TestingMacros' not found":

    swift test -Xswiftc -plugin-path -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing

Do not run two `swift build`/`swift test` processes against this checkout at once; they
corrupt each other's `.build`.

## SwiftUI without full Xcode

Command Line Tools ship no SwiftUI macro plugin, so `@State` / `@Bindable` / `@Observable`
do not compile here. The App target uses the pre-macro pattern instead: `ObservableObject`
+ `@Published` + `@StateObject` / `@ObservedObject`. Install full Xcode to switch to the
macro style.
