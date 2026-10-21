# TokenSigner P1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A native macOS menu bar app that signs a hash with a VNPT or NC-CA USB token through a local CTSigningHub-compatible HTTP bridge on port 32001.

**Architecture:** SwiftPM package with four targets. `Core` holds signing logic and models. `TokenHelper` is a CLI that loads a vendor PKCS#11 dylib and speaks JSON-RPC over stdin/stdout; a separate C shim dylib fixes the macOS 27 SM-APDU bug via DYLD interpose. `Bridges` is a SwiftNIO HTTP server. `App` is the SwiftUI menu bar UI. The app launches one helper per connected token, routed by ATR customer byte.

**Tech Stack:** Swift 6.4, Swift Testing, SwiftNIO, swift-certificates, swift-asn1, PCSC.framework, clang (C shim).

**Spec:** `docs/superpowers/specs/2026-10-21-tokensigner-design.md`

## Global Constraints

- Platform: macOS 14+, Apple Silicon. App target arm64. Helper + shim built universal (arm64 + x86_64).
- Dependencies: Apple-published only — swift-nio, swift-certificates, swift-asn1. No others.
- All bridge servers bind `127.0.0.1` only, never `0.0.0.0`.
- Light mode only: the app forces `.preferredColorScheme(.light)`. No dark mode.
- UI copy is Vietnamese. Colors come only from `App/Theme.swift`; nothing else hard-codes a color.
- PINs are never written to disk, logged, or placed in a process argument. They travel app → helper over the stdin pipe only.
- The SCardTransmit shim re-encodes exactly the malformed form `CLA & 0x0C == 0x0C && len == 7 + Lc` to extended length; valid short APDUs pass through untouched.
- ATR customer byte is ATR index 19 (0-based). Map: 0x32 VNPT, 0x59 NC-CA, 0x61 CMC, 0x72 I-CA, 0x69 FastCA, 0x51 EFY.
- Commit message footer on every commit:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

---

### Task 1: Package skeleton

**Files:**
- Create: `Package.swift`
- Create: `Sources/Core/Core.swift`
- Create: `Sources/Bridges/Bridges.swift`
- Create: `Sources/App/main.swift`
- Create: `Sources/TokenHelper/main.swift`
- Create: `Sources/TSShim/shim.c`, `Sources/TSShim/include/tsshim.h`
- Test: `Tests/CoreTests/SmokeTests.swift`

**Interfaces:**
- Produces: a buildable 5-target package; `Core` module importable by tests.

- [ ] **Step 1: Write the failing test**

```swift
// Tests/CoreTests/SmokeTests.swift
import Testing
@testable import Core

@Test func coreVersionIsP1() {
    #expect(Core.version == "0.1.0")
}
```

- [ ] **Step 2: Write `Package.swift`**

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TokenSigner",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.76.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.3.0"),
    ],
    targets: [
        .target(name: "TSShim"),
        .target(name: "Core", dependencies: [
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .executableTarget(name: "TokenHelper", dependencies: ["Core", "TSShim"]),
        .target(name: "Bridges", dependencies: [
            "Core",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOHTTP1", package: "swift-nio"),
        ]),
        .executableTarget(name: "App", dependencies: ["Core", "Bridges"]),
        .testTarget(name: "CoreTests", dependencies: ["Core"]),
        .testTarget(name: "BridgesTests", dependencies: ["Bridges", "Core"]),
    ]
)
```

- [ ] **Step 3: Write minimal target stubs**

```swift
// Sources/Core/Core.swift
public enum Core { public static let version = "0.1.0" }
```
```swift
// Sources/Bridges/Bridges.swift
public enum Bridges {}
```
```swift
// Sources/App/main.swift
print("TokenSigner")
```
```swift
// Sources/TokenHelper/main.swift
print("token-helper")
```
```c
/* Sources/TSShim/include/tsshim.h */
#ifndef TSSHIM_H
#define TSSHIM_H
#include <stdint.h>
#include <stddef.h>
/* Re-encode a malformed Feitian SM APDU to extended length.
   Returns new length written to out (cap outcap), or 0 if apdu is left unchanged. */
size_t ts_reencode(const uint8_t *apdu, size_t len, uint8_t *out, size_t outcap);
#endif
```
```c
/* Sources/TSShim/shim.c */
#include "tsshim.h"
size_t ts_reencode(const uint8_t *apdu, size_t len, uint8_t *out, size_t outcap) {
    (void)apdu; (void)len; (void)out; (void)outcap;
    return 0;
}
```

- [ ] **Step 4: Run tests**

Run: `swift test 2>&1 | tail -5`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add Package.swift Sources Tests
git commit -m "feat: TokenSigner package skeleton (5 targets)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: SCardTransmit re-encoding shim

**Files:**
- Modify: `Sources/TSShim/shim.c`
- Test: `Tests/TSShimTests/ReencodeTests.swift`
- Modify: `Package.swift` (add `TSShimTests` target)

**Interfaces:**
- Produces: `ts_reencode` (see `tsshim.h`) — re-encodes a malformed SM APDU, returns new length or 0.

Background: the VNPT lib emits `0C B0 00 00 0E <97 02 00EF 8E08 mac EF> 00 EF` — a 21-byte APDU with short Lc (0x0E = 14) plus a trailing 2-byte Le. That is `len == 7 + Lc`. macOS 27 CCID rejects it (`0x80100016`). Fix: rewrite to extended length `CLA INS P1 P2 00 00 Lc <data> Le_hi Le_lo` (length `9 + Lc`). The 2-byte Le is `apdu[len-2..len-1]`.

- [ ] **Step 1: Add the test target to `Package.swift`**

Add to `targets:`
```swift
.testTarget(name: "TSShimTests", dependencies: ["TSShim"]),
```

- [ ] **Step 2: Write the failing tests**

```swift
// Tests/TSShimTests/ReencodeTests.swift
import Testing
import TSShim

private func reencode(_ bytes: [UInt8]) -> [UInt8]? {
    var out = [UInt8](repeating: 0, count: bytes.count + 8)
    let n = bytes.withUnsafeBufferPointer { inp in
        out.withUnsafeMutableBufferPointer { o in
            ts_reencode(inp.baseAddress, bytes.count, o.baseAddress, o.count)
        }
    }
    return n == 0 ? nil : Array(out.prefix(n))
}

@Test func malformedSMReadBinaryIsExtended() {
    // 0C B0 00 00 | Lc=0E | 14 data bytes | Le = 00 EF
    let data: [UInt8] = [0x97,0x02,0x00,0xEF,0x8E,0x08,0x9b,0x80,0xc9,0x7a,0x19,0x5e,0x65,0x17]
    let apdu: [UInt8] = [0x0C,0xB0,0x00,0x00,0x0E] + data + [0x00,0xEF]
    let got = reencode(apdu)
    // Extended: CLA INS P1 P2 00 00 0E <data> 00 EF
    let want: [UInt8] = [0x0C,0xB0,0x00,0x00,0x00,0x00,0x0E] + data + [0x00,0xEF]
    #expect(got == want)
}

@Test func validShortApduUntouched() {
    // A plain case-2 APDU (no SM class bit set beyond 0x0C? use 0x00): must be left alone.
    let apdu: [UInt8] = [0x00,0x84,0x00,0x00,0x08]
    #expect(reencode(apdu) == nil)
}

@Test func validSMShortWithoutTrailingLeUntouched() {
    // SM class but len == 5 + Lc (no 2-byte Le): not the malformed form.
    let apdu: [UInt8] = [0x0C,0xA4,0x00,0x00,0x02,0x2F,0x01]
    #expect(reencode(apdu) == nil)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `swift test --filter TSShimTests 2>&1 | tail -8`
Expected: FAIL — `ts_reencode` returns 0 for the malformed case.

- [ ] **Step 4: Implement `ts_reencode`**

```c
/* Sources/TSShim/shim.c */
#include "tsshim.h"

size_t ts_reencode(const uint8_t *apdu, size_t len, uint8_t *out, size_t outcap) {
    if (len < 7) return 0;
    if ((apdu[0] & 0x0C) != 0x0C) return 0;   /* SM class bit */
    uint8_t lc = apdu[4];
    if (lc == 0) return 0;
    if (len != (size_t)7 + lc) return 0;       /* short Lc + 2-byte Le form */
    size_t need = (size_t)9 + lc;
    if (outcap < need) return 0;
    out[0] = apdu[0]; out[1] = apdu[1]; out[2] = apdu[2]; out[3] = apdu[3];
    out[4] = 0x00; out[5] = 0x00; out[6] = lc;              /* extended Lc */
    for (uint8_t i = 0; i < lc; i++) out[7 + i] = apdu[5 + i];
    out[7 + lc] = apdu[len - 2];                            /* Le hi */
    out[8 + lc] = apdu[len - 1];                            /* Le lo */
    return need;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `swift test --filter TSShimTests 2>&1 | tail -8`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add Package.swift Sources/TSShim Tests/TSShimTests
git commit -m "feat: SCardTransmit APDU re-encoding shim (macOS 27 Feitian fix)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: SCardTransmit interpose in the shim dylib

**Files:**
- Modify: `Sources/TSShim/shim.c`
- Modify: `Package.swift` (TSShim links PCSC)
- Test: manual (documented below; no unit test — interpose needs a loaded dylib)

**Interfaces:**
- Produces: `libTSShim.dylib` with a `__DATA,__interpose` tuple replacing `SCardTransmit`.

- [ ] **Step 1: Link PCSC in the TSShim target**

In `Package.swift`, change the `TSShim` target to:
```swift
.target(name: "TSShim", linkerSettings: [
    .linkedFramework("PCSC")
]),
```

- [ ] **Step 2: Add the interpose to `shim.c`**

```c
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

static LONG ts_transmit(SCARDHANDLE h, const SCARD_IO_REQUEST *send,
                        const uint8_t *in, uint32_t il,
                        SCARD_IO_REQUEST *recv, uint8_t *out, uint32_t *ol) {
    uint8_t buf[4096];
    size_t n = ts_reencode(in, il, buf, sizeof buf);
    if (n > 0) return SCardTransmit(h, send, buf, (uint32_t)n, recv, out, ol);
    return SCardTransmit(h, send, in, il, recv, out, ol);
}

__attribute__((used)) static struct { const void *a, *b; }
_ts_interpose __attribute__((section("__DATA,__interpose"))) =
    { (const void *)ts_transmit, (const void *)SCardTransmit };
```

- [ ] **Step 3: Build and locate the dylib**

Run: `swift build 2>&1 | tail -3 && find .build -name 'libTSShim.dylib' | head -1`
Expected: a path printed.

- [ ] **Step 4: Manual smoke (with a VNPT token plugged in)**

Note at top of the task that this needs hardware and is run by the user. Record the command in `Sources/TSShim/VERIFY.md`:
```
# with the probe from scratchpad, or once Task 7 lands:
DYLD_INSERT_LIBRARIES=<path>/libTSShim.dylib <helper> listTokens
# expect CKR_OK / token label, zero 0x80100016
```

- [ ] **Step 5: Commit**

```bash
git add Package.swift Sources/TSShim
git commit -m "feat: interpose SCardTransmit in libTSShim.dylib

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: ModuleRegistry — ATR to module routing

**Files:**
- Create: `Sources/Core/ModuleRegistry.swift`
- Test: `Tests/CoreTests/ModuleRegistryTests.swift`

**Interfaces:**
- Produces:
  - `struct ModuleInfo { let ca: String; let moduleName: String; let arch: ModuleArch }`
  - `enum ModuleArch { case universal, x86_64 }`
  - `enum ModuleRegistry { static func lookup(atr: [UInt8]) -> ModuleInfo? }`

- [ ] **Step 1: Write the failing tests**

```swift
// Tests/CoreTests/ModuleRegistryTests.swift
import Testing
@testable import Core

@Test func vnptAtrMapsToVnptModule() {
    let atr: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0x00,0x66,0x46,0x53,0x05,
                        0x34,0x00,0x25,0x71,0xdf,0x00,0x00,0x32,0x00,0x00,0x20]
    let m = ModuleRegistry.lookup(atr: atr)
    #expect(m?.ca == "VNPT")
    #expect(m?.moduleName == "libvnptca_p11_v8.dylib")
}

@Test func nccaAtrByte19Is0x59() {
    var atr = [UInt8](repeating: 0, count: 23)
    atr[19] = 0x59
    #expect(ModuleRegistry.lookup(atr: atr)?.ca == "NC-CA")
}

@Test func unknownCustomerByteIsNil() {
    var atr = [UInt8](repeating: 0, count: 23)
    atr[19] = 0xAB
    #expect(ModuleRegistry.lookup(atr: atr) == nil)
}

@Test func shortAtrIsNil() {
    #expect(ModuleRegistry.lookup(atr: [0x3b, 0x9f]) == nil)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `swift test --filter ModuleRegistryTests 2>&1 | tail -6`
Expected: FAIL — no such type.

- [ ] **Step 3: Implement `ModuleRegistry`**

```swift
// Sources/Core/ModuleRegistry.swift
public enum ModuleArch: Sendable { case universal, x86_64 }

public struct ModuleInfo: Sendable, Equatable {
    public let ca: String
    public let moduleName: String
    public let arch: ModuleArch
}

public enum ModuleRegistry {
    // Keyed by ATR customer byte (index 19). FastCA (0x69) and EFY (0x51) have
    // no usable macOS module yet, so they are intentionally absent.
    private static let table: [UInt8: ModuleInfo] = [
        0x32: ModuleInfo(ca: "VNPT",  moduleName: "libvnptca_p11_v8.dylib", arch: .universal),
        0x59: ModuleInfo(ca: "NC-CA", moduleName: "ncca_csp11_v1.dylib",    arch: .universal),
        0x61: ModuleInfo(ca: "CMC",   moduleName: "cmcca_csp11_v1.dylib",   arch: .universal),
        0x72: ModuleInfo(ca: "I-CA",  moduleName: "ica_csp11_v1.dylib",     arch: .universal),
    ]

    public static func lookup(atr: [UInt8]) -> ModuleInfo? {
        guard atr.count > 19 else { return nil }
        return table[atr[19]]
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `swift test --filter ModuleRegistryTests 2>&1 | tail -6`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add Sources/Core/ModuleRegistry.swift Tests/CoreTests/ModuleRegistryTests.swift
git commit -m "feat: ModuleRegistry routes tokens by ATR customer byte

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: DigestInfo builder for raw-hash signing

**Files:**
- Create: `Sources/Core/DigestInfo.swift`
- Test: `Tests/CoreTests/DigestInfoTests.swift`

**Interfaces:**
- Produces:
  - `enum HashAlg { case sha256, sha1 }`
  - `enum DigestInfo { static func wrap(_ digest: [UInt8], _ alg: HashAlg) throws -> [UInt8] }`

Background: `CKM_RSA_PKCS` signs a caller-built DigestInfo DER. For SHA-256 the prefix is the RFC 8017 fixed sequence `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`, then the 32-byte digest. SHA-1 prefix is `30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14`, then 20 bytes.

- [ ] **Step 1: Write the failing tests**

```swift
// Tests/CoreTests/DigestInfoTests.swift
import Testing
@testable import Core

@Test func sha256DigestInfoHasCorrectPrefixAndLength() throws {
    let digest = [UInt8](repeating: 0xAB, count: 32)
    let d = try DigestInfo.wrap(digest, .sha256)
    let prefix: [UInt8] = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,
                           0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
    #expect(Array(d.prefix(prefix.count)) == prefix)
    #expect(d.count == prefix.count + 32)
    #expect(Array(d.suffix(32)) == digest)
}

@Test func sha256RejectsWrongLength() {
    #expect(throws: (any Error).self) {
        _ = try DigestInfo.wrap([UInt8](repeating: 0, count: 31), .sha256)
    }
}

@Test func sha1DigestInfoLength() throws {
    let d = try DigestInfo.wrap([UInt8](repeating: 1, count: 20), .sha1)
    #expect(d.count == 15 + 20)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `swift test --filter DigestInfoTests 2>&1 | tail -6`
Expected: FAIL.

- [ ] **Step 3: Implement `DigestInfo`**

```swift
// Sources/Core/DigestInfo.swift
public enum HashAlg: Sendable { case sha256, sha1 }

public struct DigestInfoError: Error, Sendable { public let message: String }

public enum DigestInfo {
    private static let sha256Prefix: [UInt8] =
        [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
    private static let sha1Prefix: [UInt8] =
        [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]

    public static func wrap(_ digest: [UInt8], _ alg: HashAlg) throws -> [UInt8] {
        switch alg {
        case .sha256:
            guard digest.count == 32 else { throw DigestInfoError(message: "SHA-256 digest must be 32 bytes") }
            return sha256Prefix + digest
        case .sha1:
            guard digest.count == 20 else { throw DigestInfoError(message: "SHA-1 digest must be 20 bytes") }
            return sha1Prefix + digest
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `swift test --filter DigestInfoTests 2>&1 | tail -6`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add Sources/Core/DigestInfo.swift Tests/CoreTests/DigestInfoTests.swift
git commit -m "feat: DigestInfo builder for CKM_RSA_PKCS raw-hash signing

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: JSON-RPC wire types

**Files:**
- Create: `Sources/Core/HelperProtocol.swift`
- Test: `Tests/CoreTests/HelperProtocolTests.swift`

**Interfaces:**
- Produces (shared by TokenHelper and TokenBroker):
  - `struct TokenInfo: Codable { let slot: UInt; let reader, serial, label: String; let flags: [String] }`
  - `struct CertInfo: Codable { let id, derB64, subject, issuer, serialHex, notBefore, notAfter: String }`
  - `enum HelperRequest: Codable` — cases `listTokens`, `listCerts(serial:)`, `login(serial:pin:)`, `sign(serial:certId:mech:dataB64:)`, `logout(serial:)`
  - `enum HelperResponse: Codable` — cases `tokens([TokenInfo])`, `certs([CertInfo])`, `loginResult(LoginResult)`, `signature(String)`, `ok`, `error(String)`
  - `enum LoginResult: Codable` — `ok`, `pinIncorrect(retriesLeft: Int?)`, `pinLocked`
  - `enum SignMech: String, Codable { case sha256RSA = "SHA256_RSA_PKCS", rsaPKCS = "RSA_PKCS" }`

- [ ] **Step 1: Write the failing tests**

```swift
// Tests/CoreTests/HelperProtocolTests.swift
import Testing
import Foundation
@testable import Core

@Test func requestRoundTrips() throws {
    let req = HelperRequest.sign(serial: "83772", certId: "01", mech: .sha256RSA, dataB64: "AAAA")
    let data = try JSONEncoder().encode(req)
    let back = try JSONDecoder().decode(HelperRequest.self, from: data)
    #expect(back == req)
}

@Test func loginResultEncodesRetries() throws {
    let data = try JSONEncoder().encode(HelperResponse.loginResult(.pinIncorrect(retriesLeft: 2)))
    let s = String(decoding: data, as: UTF8.self)
    #expect(s.contains("pinIncorrect"))
    #expect(s.contains("2"))
}

@Test func mechRawValues() {
    #expect(SignMech.sha256RSA.rawValue == "SHA256_RSA_PKCS")
    #expect(SignMech.rsaPKCS.rawValue == "RSA_PKCS")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `swift test --filter HelperProtocolTests 2>&1 | tail -6`
Expected: FAIL.

- [ ] **Step 3: Implement the types**

```swift
// Sources/Core/HelperProtocol.swift
import Foundation

public struct TokenInfo: Codable, Equatable, Sendable {
    public let slot: UInt; public let reader, serial, label: String; public let flags: [String]
    public init(slot: UInt, reader: String, serial: String, label: String, flags: [String]) {
        self.slot = slot; self.reader = reader; self.serial = serial; self.label = label; self.flags = flags
    }
}

public struct CertInfo: Codable, Equatable, Sendable {
    public let id, derB64, subject, issuer, serialHex, notBefore, notAfter: String
    public init(id: String, derB64: String, subject: String, issuer: String,
                serialHex: String, notBefore: String, notAfter: String) {
        self.id = id; self.derB64 = derB64; self.subject = subject; self.issuer = issuer
        self.serialHex = serialHex; self.notBefore = notBefore; self.notAfter = notAfter
    }
}

public enum SignMech: String, Codable, Sendable { case sha256RSA = "SHA256_RSA_PKCS", rsaPKCS = "RSA_PKCS" }

public enum LoginResult: Codable, Equatable, Sendable {
    case ok
    case pinIncorrect(retriesLeft: Int?)
    case pinLocked
}

public enum HelperRequest: Codable, Equatable, Sendable {
    case listTokens
    case listCerts(serial: String)
    case login(serial: String, pin: String)
    case sign(serial: String, certId: String, mech: SignMech, dataB64: String)
    case logout(serial: String)
}

public enum HelperResponse: Codable, Equatable, Sendable {
    case tokens([TokenInfo])
    case certs([CertInfo])
    case loginResult(LoginResult)
    case signature(String)
    case ok
    case error(String)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `swift test --filter HelperProtocolTests 2>&1 | tail -6`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add Sources/Core/HelperProtocol.swift Tests/CoreTests/HelperProtocolTests.swift
git commit -m "feat: JSON-RPC wire types for app <-> token-helper

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: token-helper — PKCS#11 load, listTokens, listCerts

**Files:**
- Create: `Sources/TokenHelper/PKCS11.swift` (thin dlopen wrapper over C_GetFunctionList)
- Create: `Sources/TokenHelper/pkcs11.h` (OASIS headers, vendored)
- Modify: `Sources/TokenHelper/main.swift`
- Test: `Tests/CoreTests/` — none (hardware); add `Sources/TokenHelper/VERIFY.md`

**Interfaces:**
- Consumes: `HelperRequest`, `HelperResponse`, `TokenInfo`, `CertInfo` from Core.
- Produces: an executable that reads one JSON request per line on stdin, writes one JSON response per line on stdout. Args: `--module <path>`.

Note: this task has no automated test — it needs a token. The deliverable is verified by Step 5 with hardware (user runs it). Keep the code minimal and lean on the Core types, which are already tested.

- [ ] **Step 1: Vendor the PKCS#11 headers**

Download the OASIS headers into `Sources/TokenHelper/`:
```bash
cd Sources/TokenHelper
for f in pkcs11.h pkcs11t.h pkcs11f.h; do
  curl -sfL -o $f "https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/include/pkcs11-v3.0/$f"
done
```

- [ ] **Step 2: Write the dlopen wrapper**

```swift
// Sources/TokenHelper/PKCS11.swift
// Minimal Cryptoki access: dlopen the module, get C_GetFunctionList, expose
// the calls token-helper needs. All calls go through the function list so the
// SCardTransmit interpose in libTSShim.dylib applies underneath.
import Foundation

final class PKCS11 {
    // Implementation detail: load the module, call C_Initialize with
    // CKF_OS_LOCKING_OK, keep the CK_FUNCTION_LIST pointer. Provide:
    //   func slots() throws -> [(slot: CK_SLOT_ID, token: CK_TOKEN_INFO)]
    //   func certs(slot: CK_SLOT_ID) throws -> [CertInfo]
    // Read certs with a read-only session (CKF_SERIAL_SESSION), no login.
    // (Full body written during implementation; mirrors scratchpad probe.c.)
}
```

Implementation reference: the working read path is `scratchpad/probe/probe.c` and `slots.c` — port `C_Initialize` → `C_GetSlotList(CK_TRUE)` → `C_GetTokenInfo` → open session → `C_FindObjects(CKO_CERTIFICATE)` → `C_GetAttributeValue(CKA_ID, CKA_VALUE)`. Parse the cert with X509 from swift-certificates to fill subject/issuer/serial/dates.

- [ ] **Step 3: Wire the stdin/stdout loop in `main.swift`**

```swift
// Sources/TokenHelper/main.swift
import Foundation
import Core

let modulePath = CommandLine.arguments.firstIndex(of: "--module").map { CommandLine.arguments[$0 + 1] }
guard let modulePath else { FileHandle.standardError.write(Data("missing --module\n".utf8)); exit(2) }

let p11 = PKCS11(modulePath: modulePath)   // init/dlopen

while let line = readLine(strippingNewline: true) {
    guard let reqData = line.data(using: .utf8),
          let req = try? JSONDecoder().decode(HelperRequest.self, from: reqData) else {
        emit(.error("bad request")); continue
    }
    do {
        switch req {
        case .listTokens: emit(.tokens(try p11.listTokens()))
        case .listCerts(let serial): emit(.certs(try p11.certs(serial: serial)))
        default: emit(.error("unsupported in P1"))   // login/sign land in Task 11
        }
    } catch { emit(.error("\(error)")) }
}

func emit(_ r: HelperResponse) {
    let d = try! JSONEncoder().encode(r)
    FileHandle.standardOutput.write(d); FileHandle.standardOutput.write(Data([0x0a]))
}
```

- [ ] **Step 4: Build**

Run: `swift build --product TokenHelper 2>&1 | tail -3`
Expected: builds.

- [ ] **Step 5: Hardware verify (user, VNPT token in)**

Record in `Sources/TokenHelper/VERIFY.md`:
```bash
HELPER=$(swift build --show-bin-path)/token-helper
SHIM=$(find .build -name libTSShim.dylib | head -1)
echo '{"listTokens":{}}' | DYLD_INSERT_LIBRARIES=$SHIM $HELPER --module /usr/local/lib/libvnptca_p11_v8.dylib
# expect one line: {"tokens":[{"serial":"8377200522219143","label":"VNPT-CA PKI Token",...}]}
```

- [ ] **Step 6: Commit**

```bash
git add Sources/TokenHelper
git commit -m "feat: token-helper reads tokens and certs over JSON-RPC

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: TokenBroker — spawn and route helpers

**Files:**
- Create: `Sources/Core/TokenBroker.swift`
- Create: `Sources/Core/ReaderScanner.swift` (PC/SC reader + ATR enumeration)
- Test: `Tests/CoreTests/TokenBrokerTests.swift` (with a fake helper process)

**Interfaces:**
- Consumes: `ModuleRegistry`, `HelperRequest`/`HelperResponse`, `TokenInfo`, `CertInfo`.
- Produces:
  - `actor TokenBroker` with `init(helperURL: URL, shimURL: URL, moduleDir: URL)` and
    `func request(_ r: HelperRequest, module: ModuleInfo) async throws -> HelperResponse`
  - For the test, the helper command is injectable so a fake echoer stands in for a real token.

- [ ] **Step 1: Write the failing test (fake helper)**

```swift
// Tests/CoreTests/TokenBrokerTests.swift
import Testing
import Foundation
@testable import Core

// A fake "helper": a /bin/sh script that reads one JSON line and prints a canned tokens response.
private func fakeHelper() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("fakehelper-\(UUID()).sh")
    let script = #"""
    #!/bin/sh
    read line
    printf '{"tokens":[{"slot":1,"reader":"R","serial":"S","label":"L","flags":[]}]}\n'
    """#
    try script.write(to: url, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    return url
}

@Test func brokerSpawnsHelperAndParsesResponse() async throws {
    let helper = try fakeHelper()
    let broker = TokenBroker(helperURL: helper, shimURL: helper, moduleDir: URL(fileURLWithPath: "/tmp"))
    let module = ModuleInfo(ca: "VNPT", moduleName: "x.dylib", arch: .universal)
    let resp = try await broker.request(.listTokens, module: module)
    #expect(resp == .tokens([TokenInfo(slot: 1, reader: "R", serial: "S", label: "L", flags: [])]))
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `swift test --filter TokenBrokerTests 2>&1 | tail -6`
Expected: FAIL — no such type.

- [ ] **Step 3: Implement `TokenBroker`**

```swift
// Sources/Core/TokenBroker.swift
import Foundation

public actor TokenBroker {
    private let helperURL: URL
    private let shimURL: URL
    private let moduleDir: URL
    public init(helperURL: URL, shimURL: URL, moduleDir: URL) {
        self.helperURL = helperURL; self.shimURL = shimURL; self.moduleDir = moduleDir
    }

    public func request(_ r: HelperRequest, module: ModuleInfo) async throws -> HelperResponse {
        let proc = Process()
        if module.arch == .x86_64 {
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/arch")
            proc.arguments = ["-x86_64", helperURL.path, "--module", moduleDir.appendingPathComponent(module.moduleName).path]
        } else {
            proc.executableURL = helperURL
            proc.arguments = ["--module", moduleDir.appendingPathComponent(module.moduleName).path]
        }
        var env = ProcessInfo.processInfo.environment
        env["DYLD_INSERT_LIBRARIES"] = shimURL.path
        proc.environment = env

        let stdinPipe = Pipe(), stdoutPipe = Pipe()
        proc.standardInput = stdinPipe; proc.standardOutput = stdoutPipe
        try proc.run()
        stdinPipe.fileHandleForWriting.write(try JSONEncoder().encode(r))
        stdinPipe.fileHandleForWriting.write(Data([0x0a]))
        try? stdinPipe.fileHandleForWriting.close()

        let out = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        let firstLine = out.split(separator: 0x0a).first ?? Data()
        return try JSONDecoder().decode(HelperResponse.self, from: Data(firstLine))
    }
}
```

Note: in P1 the broker is one-shot per request (spawn, ask, read, exit). A long-lived helper with session state lands with login in Task 11; the moduleDir resolves `/usr/local/lib` when the module is not found in the app's module dir (handled at the call site in Task 10).

- [ ] **Step 4: Run to verify it passes**

Run: `swift test --filter TokenBrokerTests 2>&1 | tail -6`
Expected: PASS (1 test).

- [ ] **Step 5: Add `ReaderScanner`**

```swift
// Sources/Core/ReaderScanner.swift
// PC/SC reader + ATR enumeration, used to route by ATR before any module loads.
// SCardEstablishContext -> SCardListReaders -> SCardGetStatusChange for ATRs.
// Pure read; links PCSC. Returns [(reader: String, atr: [UInt8])].
import Foundation
public struct ReaderScanner {
    public init() {}
    public func readers() -> [(reader: String, atr: [UInt8])] { /* PCSC calls */ [] }
}
```

The body is a direct PCSC port (reference: `scratchpad/probe/pcsc.c`). No unit test (needs hardware); covered by the Task 10 menu-bar hardware check.

- [ ] **Step 6: Commit**

```bash
git add Sources/Core/TokenBroker.swift Sources/Core/ReaderScanner.swift Tests/CoreTests/TokenBrokerTests.swift
git commit -m "feat: TokenBroker spawns per-module helpers; ReaderScanner enumerates ATRs

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: CTSigningHub bridge — Version, GetCert, GetInfoCert, SignHash

**Files:**
- Create: `Sources/Bridges/CTSignModel.swift`
- Create: `Sources/Bridges/CTSignBridge.swift`
- Create: `Sources/Bridges/HTTPServer.swift` (SwiftNIO 127.0.0.1 listener)
- Test: `Tests/BridgesTests/CTSignTests.swift`

**Interfaces:**
- Consumes: a `SigningBackend` protocol (injected, faked in tests):
  ```swift
  public protocol SigningBackend: Sendable {
      func certificates() async -> [CertInfo]
      func sign(serial: String, digestB64: String) async throws -> String  // -> base64 signature
  }
  ```
- Produces: `CTSignBridge(backend:)` with `func handle(method: String, path: String, body: Data) async -> (status: Int, json: Data)`, and `HTTPServer` binding it to `127.0.0.1:32001`.

Wire contract (verified against `ctSignerv2.exe` metadata and MacSigner `src/ctsign/model.rs`):
- `GET /api/SignHash/Version` → JSON string (value: the real 1.2.0.0 version string — **(verify)**, placeholder `"1.2.0.0"` until a Parallels capture confirms it).
- `GET /api/Info/GetInfoCert` → JSON string `"1"`.
- `GET /api/HubClient/GetCert` → `{status:200, data:[CertificateInfo], message:"SUCCESS"}`, or `{status:0, data:null, message:null}` if none. `CertificateInfo` fields: `serinumber, subjectDN, issuedDN, pemCert (base64 DER), valid, validFrom, validTo, error`.
- `POST /api/HubClient/SignHash` body `{requestId?, serinumber, hash:[{Ma, DLieuHash, CKy?}]}`. For each item, `DLieuHash` is a base64 32-byte SHA-256; sign it and put base64 PKCS#1 signature in `CKy`. Response `{status:200, data:<hash[] with CKy filled>, message:"SUCCESS"}`. Unknown serial → `{status:404, message:"Không tìm thấy CTS có serinumber <serial>"}`.

- [ ] **Step 1: Write the failing tests**

```swift
// Tests/BridgesTests/CTSignTests.swift
import Testing
import Foundation
@testable import Bridges
import Core

struct FakeBackend: SigningBackend {
    func certificates() async -> [CertInfo] {
        [CertInfo(id: "01", derB64: "AAE=", subject: "CN=Test", issuer: "CN=VNPT-CA SHA2",
                  serialHex: "54010101", notBefore: "2024-01-01 00:00:00", notAfter: "2027-01-01 00:00:00")]
    }
    func sign(serial: String, digestB64: String) async throws -> String { "U0lH" } // "SIG"
}

@Test func versionReturnsString() async {
    let b = CTSignBridge(backend: FakeBackend())
    let (status, json) = await b.handle(method: "GET", path: "/api/SignHash/Version", body: Data())
    #expect(status == 200)
    #expect(String(decoding: json, as: UTF8.self) == "\"1.2.0.0\"")
}

@Test func getInfoCertReturnsOne() async {
    let b = CTSignBridge(backend: FakeBackend())
    let (_, json) = await b.handle(method: "GET", path: "/api/Info/GetInfoCert", body: Data())
    #expect(String(decoding: json, as: UTF8.self) == "\"1\"")
}

@Test func getCertWrapsCertificates() async throws {
    let b = CTSignBridge(backend: FakeBackend())
    let (_, json) = await b.handle(method: "GET", path: "/api/HubClient/GetCert", body: Data())
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 200)
    #expect(v["message"] as? String == "SUCCESS")
    let data = v["data"] as! [[String: Any]]
    #expect(data.first?["serinumber"] as? String == "54010101")
    #expect(data.first?["subjectDN"] as? String == "CN=Test")
}

@Test func signHashFillsCKy() async throws {
    let b = CTSignBridge(backend: FakeBackend())
    let digest = Data(repeating: 0xAB, count: 32).base64EncodedString()
    let body = try JSONSerialization.data(withJSONObject: [
        "serinumber": "54010101",
        "hash": [["Ma": "one", "DLieuHash": digest]],
    ])
    let (_, json) = await b.handle(method: "POST", path: "/api/HubClient/SignHash", body: body)
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 200)
    let out = v["data"] as! [[String: Any]]
    #expect(out.first?["CKy"] as? String == "U0lH")
}

@Test func signHashUnknownSerialIs404() async throws {
    struct NoCert: SigningBackend {
        func certificates() async -> [CertInfo] { [] }
        func sign(serial: String, digestB64: String) async throws -> String { throw CTSignError.unknownSerial("FFFF") }
    }
    let b = CTSignBridge(backend: NoCert())
    let body = try JSONSerialization.data(withJSONObject: [
        "serinumber": "FFFF", "hash": [["Ma": "x", "DLieuHash": Data(count: 32).base64EncodedString()]],
    ])
    let (_, json) = await b.handle(method: "POST", path: "/api/HubClient/SignHash", body: body)
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 404)
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `swift test --filter CTSignTests 2>&1 | tail -8`
Expected: FAIL.

- [ ] **Step 3: Implement the model and bridge**

```swift
// Sources/Bridges/CTSignModel.swift
import Foundation

public enum CTSignError: Error, Equatable { case unknownSerial(String) }

struct HashItem: Codable {
    let Ma: String?
    let DLieuHash: String
    var CKy: String?
}
struct SignHashRequest: Codable {
    let requestId: String?
    let serinumber: String
    var hash: [HashItem]
}
struct CertificateInfo: Codable {
    let serinumber: String
    let subjectDN: String
    let issuedDN: String
    let pemCert: String
    let valid: Bool
    let validFrom: String
    let validTo: String
    let error: String?
}
```

```swift
// Sources/Bridges/CTSignBridge.swift
import Foundation
import Core

public protocol SigningBackend: Sendable {
    func certificates() async -> [CertInfo]
    func sign(serial: String, digestB64: String) async throws -> String
}

public struct CTSignBridge: Sendable {
    let backend: any SigningBackend
    public init(backend: any SigningBackend) { self.backend = backend }

    public static let version = "1.2.0.0"   // (verify) against real CTSigningHub 1.2

    public func handle(method: String, path: String, body: Data) async -> (status: Int, json: Data) {
        switch (method, path) {
        case ("GET", "/api/SignHash/Version"):
            return (200, jsonString(Self.version))
        case ("GET", "/api/Info/GetInfoCert"):
            return (200, jsonString("1"))
        case ("GET", "/api/HubClient/GetCert"):
            let certs = await backend.certificates()
            if certs.isEmpty { return (200, encode(["status": 0, "data": nil, "message": nil] as [String: Any?])) }
            let infos = certs.map {
                CertificateInfo(serinumber: $0.serialHex, subjectDN: $0.subject, issuedDN: $0.issuer,
                                pemCert: $0.derB64, valid: true, validFrom: $0.notBefore, validTo: $0.notAfter, error: nil)
            }
            return (200, wrap(status: 200, data: infos, message: "SUCCESS"))
        case ("POST", "/api/HubClient/SignHash"):
            guard var req = try? JSONDecoder().decode(SignHashRequest.self, from: body) else {
                return (200, errorBody(500, "bad request"))
            }
            do {
                for i in req.hash.indices {
                    req.hash[i].CKy = try await backend.sign(serial: req.serinumber, digestB64: req.hash[i].DLieuHash)
                }
                return (200, wrap(status: 200, data: req.hash, message: "SUCCESS"))
            } catch CTSignError.unknownSerial(let s) {
                return (200, errorBody(404, "Không tìm thấy CTS có serinumber \(s)"))
            } catch {
                return (200, errorBody(500, "\(error)"))
            }
        default:
            return (404, Data("{}".utf8))
        }
    }
}

// JSON helpers: jsonString, encode, wrap(status:data:message:), errorBody(_:_:)
// — small Encodable wrappers, written during implementation.
```

- [ ] **Step 4: Run to verify they pass**

Run: `swift test --filter CTSignTests 2>&1 | tail -8`
Expected: PASS (5 tests).

- [ ] **Step 5: Add the SwiftNIO server (127.0.0.1:32001)**

```swift
// Sources/Bridges/HTTPServer.swift
// Binds the CTSignBridge on 127.0.0.1:32001. Rejects any request whose Host
// header is not 127.0.0.1:32001 or localhost:32001 (DNS-rebinding guard).
// CORS: echo Access-Control-Allow-Origin only for allowlisted origins and set
// Access-Control-Allow-Private-Network: true on preflight. (Allowlist param.)
```

Body is a standard NIO `HTTPServerPipelineHandler` + a channel handler that buffers the body, calls `bridge.handle`, and writes the response. No unit test for the socket layer in P1; covered by the Task 10 end-to-end curl check.

- [ ] **Step 6: Commit**

```bash
git add Sources/Bridges Tests/BridgesTests
git commit -m "feat: CTSigningHub bridge (Version, GetCert, GetInfoCert, SignHash)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Theme + menu bar app + end-to-end wiring

**Files:**
- Create: `Sources/App/Theme.swift`
- Create: `Sources/App/TokenSignerApp.swift`
- Create: `Sources/App/MenuBarView.swift`
- Create: `Sources/App/AppModel.swift` (ties ReaderScanner + ModuleRegistry + TokenBroker + CTSignBridge + HTTPServer)
- Modify: `Sources/App/main.swift` (host the SwiftUI app)
- Modify: `Package.swift` (App links SwiftUI; add resource for module dir if needed)

**Interfaces:**
- Consumes: everything above.
- Produces: a running menu bar app. `AppModel` is an `@MainActor @Observable` class exposing `tokens: [TokenRow]`, `bridgeStatus: BridgeStatus`, and a `SigningBackend` implementation that resolves a token by cert serial, finds its module via `ModuleRegistry`, and calls `TokenBroker`.

- [ ] **Step 1: Write `Theme.swift`** (tokens from the spec §7)

```swift
// Sources/App/Theme.swift
import SwiftUI
enum Theme {
    static let primary = Color(hex: 0x181818)
    static let primaryHover = Color(hex: 0x2E2E2E)
    static let onPrimary = Color.white
    static let background = Color(hex: 0xF4F4F6)
    static let surface = Color.white
    static let foreground = Color(hex: 0x2C2C2C)
    static let muted = Color(hex: 0x707070)
    static let border = Color(hex: 0xF7F7F8)
    static let borderStrong = Color(hex: 0xEAEAEA)
    static let itemHover = Color(hex: 0xF4F4F6)
    static let secondary = Color(hex: 0xE7E8EC)
    static let danger = Color(hex: 0xC70036)
    static let dangerBg = Color(red: 1, green: 32/255, blue: 86/255).opacity(0.10)
    static let success = Color(hex: 0x007A55)
    static let warning = Color(hex: 0xBB4D00)
    static let errorText = Color(hex: 0xE7000B)
    // type scale (pt): xs 11, sm 13, base 15, lg 17, xl 20
}
extension Color { init(hex: UInt32) {
    self.init(red: Double((hex >> 16) & 0xFF)/255, green: Double((hex >> 8) & 0xFF)/255, blue: Double(hex & 0xFF)/255)
}}
```

- [ ] **Step 2: Write `AppModel`, menu bar view, and app entry**

`AppModel` (MainActor, Observable):
- on init and on a 2s timer, `ReaderScanner().readers()`, map each ATR through `ModuleRegistry.lookup`, build `tokens`. Unknown CA → a row marked "Chưa hỗ trợ".
- expose a `SigningBackend`:
  - `certificates()`: for each supported token, `TokenBroker.request(.listCerts…)`.
  - `sign(serial:digestB64:)`: find the cert's token, `TokenBroker.request(.sign…, mech: .rsaPKCS, dataB64: digestB64)`. In P1, if the token is not logged in, this throws and the menu bar shows "cần đăng nhập" — full PIN sheet is Task 11; a temporary CLI env `TS_PIN` may be read only in DEBUG builds for the end-to-end check.
- start `HTTPServer` with the CTSignBridge on 32001; set `bridgeStatus` to `.up` or `.portInUse`.

`MenuBarView`: `MenuBarExtra` content — status line, token list (CA badge, serial, cert CN, expiry, login state), bridge port status, footer (Thoát). Light mode forced via `.preferredColorScheme(.light)` on the scene.

`TokenSignerApp`: the `App` struct with `MenuBarExtra("TokenSigner", systemImage: …) { MenuBarView() }` and `.menuBarExtraStyle(.window)`.

`main.swift`: `TokenSignerApp.main()`.

- [ ] **Step 3: Build**

Run: `swift build --product App 2>&1 | tail -3`
Expected: builds.

- [ ] **Step 4: End-to-end hardware check (user, VNPT token in)**

Record in `docs/VERIFY-P1.md`. Two terminals:
```bash
# terminal 1: run the app from the CLI (menu bar icon appears)
swift run App
```
```bash
# terminal 2:
curl -s http://127.0.0.1:32001/api/SignHash/Version
curl -s http://127.0.0.1:32001/api/HubClient/GetCert | python3 -m json.tool
# with the token logged in (DEBUG TS_PIN or Task 11 sheet):
DIGEST=$(printf 'hello' | openssl dgst -sha256 -binary | base64)
curl -s -X POST http://127.0.0.1:32001/api/HubClient/SignHash \
  -H 'Content-Type: application/json' \
  -d "{\"serinumber\":\"<serial>\",\"hash\":[{\"Ma\":\"one\",\"DLieuHash\":\"$DIGEST\"}]}" | python3 -m json.tool
# verify the returned CKy against the cert's public key with openssl
```

- [ ] **Step 5: Commit**

```bash
git add Sources/App Package.swift docs/VERIFY-P1.md
git commit -m "feat: menu bar app wires ReaderScanner, broker and CTSign bridge

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: Login + PIN sheet + approval, and CKM_RSA_PKCS verification

**Files:**
- Modify: `Sources/TokenHelper/main.swift`, `Sources/TokenHelper/PKCS11.swift` (add login/sign; keep the process alive for a session)
- Modify: `Sources/Core/TokenBroker.swift` (long-lived helper with a serialized request queue)
- Create: `Sources/App/PINSheet.swift`, `Sources/App/ApprovalSheet.swift`, `Sources/App/ApprovalCenter.swift`
- Test: `Tests/CoreTests/ApprovalCenterTests.swift`

**Interfaces:**
- Consumes: `LoginResult`, `SignMech`, approval types.
- Produces:
  - helper handles `login`, `sign`, `logout`; the broker keeps one process per serial with a queue.
  - `ApprovalCenter` actor: `func decide(origin: String, certSerial: String) -> ApprovalDecision` (`.allowedSession`, `.prompt`, `.denied`), with a 10-minute session keyed by (origin, serial).
  - `PINSheet`, `ApprovalSheet` SwiftUI views.

> **FIRST, the spec's top risk: does the Feitian lib accept `CKM_RSA_PKCS` (pre-built DigestInfo)?** Step 1 settles it on hardware before the UI is built.

- [ ] **Step 1: Hardware spike — CKM_RSA_PKCS on VNPT (user enters PIN)**

Add `sign` to the helper with `mech = RSA_PKCS` → `C_SignInit(CKM_RSA_PKCS)` + `C_Sign(DigestInfo)`. Build a tiny harness invoked by the user:
```bash
# VERIFY: sign a SHA-256 DigestInfo via CKM_RSA_PKCS, verify with openssl.
# (user runs; enters PIN at the prompt)
```
Record the result in `docs/VERIFY-P1.md`.
- If `CKR_OK` and openssl verifies: keep `mech: .rsaPKCS` in the backend.
- If the lib rejects it: fall back to `mech: .sha256RSA` for CTSign (the helper hashes the raw bytes), and note in the spec that CTSign's precomputed-hash path then needs `CKM_RSA_PKCS` to be emulated — stop and report.

- [ ] **Step 2: Write the failing `ApprovalCenter` test**

```swift
// Tests/CoreTests/ApprovalCenterTests.swift
import Testing
import Foundation
@testable import Core

@Test func firstRequestPrompts() async {
    let c = ApprovalCenter(now: { Date(timeIntervalSince1970: 0) })
    #expect(await c.decide(origin: "https://thuedientu.gdt.gov.vn", certSerial: "01") == .prompt)
}

@Test func allowedSessionAutoApprovesWithinWindow() async {
    var t = Date(timeIntervalSince1970: 0)
    let c = ApprovalCenter(now: { t })
    await c.allow(origin: "https://thuedientu.gdt.gov.vn", certSerial: "01", minutes: 10)
    t = Date(timeIntervalSince1970: 300)   // +5 min
    #expect(await c.decide(origin: "https://thuedientu.gdt.gov.vn", certSerial: "01") == .allowedSession)
}

@Test func sessionExpires() async {
    var t = Date(timeIntervalSince1970: 0)
    let c = ApprovalCenter(now: { t })
    await c.allow(origin: "https://x.gdt.gov.vn", certSerial: "01", minutes: 10)
    t = Date(timeIntervalSince1970: 601)   // +10 min 1 s
    #expect(await c.decide(origin: "https://x.gdt.gov.vn", certSerial: "01") == .prompt)
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `swift test --filter ApprovalCenterTests 2>&1 | tail -6`
Expected: FAIL.

- [ ] **Step 4: Implement `ApprovalCenter`**

```swift
// Sources/Core/ApprovalCenter.swift
import Foundation

public enum ApprovalDecision: Sendable, Equatable { case allowedSession, prompt, denied }

public actor ApprovalCenter {
    private struct Key: Hashable { let origin: String; let serial: String }
    private var sessions: [Key: Date] = [:]   // expiry
    private let now: @Sendable () -> Date
    public init(now: @escaping @Sendable () -> Date = { Date() }) { self.now = now }

    public func allow(origin: String, certSerial: String, minutes: Int) {
        sessions[Key(origin: origin, serial: certSerial)] = now().addingTimeInterval(Double(minutes) * 60)
    }
    public func decide(origin: String, certSerial: String) -> ApprovalDecision {
        let k = Key(origin: origin, serial: certSerial)
        if let exp = sessions[k], exp > now() { return .allowedSession }
        sessions[k] = nil
        return .prompt
    }
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `swift test --filter ApprovalCenterTests 2>&1 | tail -6`
Expected: PASS (3 tests).

- [ ] **Step 6: Build the PIN + approval sheets and the long-lived helper**

- `PINSheet`: CA + serial header, `SecureField` (h-10 = 40pt), retry-warning badge driven by token flags (`USER_PIN_COUNT_LOW`, `USER_PIN_FINAL_TRY` red "còn 1 lần", `USER_PIN_LOCKED` disables input), Huỷ / Đăng nhập. On submit, `TokenBroker.request(.login…)`; the PIN string is zeroed after sending and never logged.
- `ApprovalSheet`: origin, cert card (subject/CA/expiry), operation + document count, three buttons — "Cho phép 10 phút" (primary), "Chỉ lần này", "Từ chối" (danger).
- Backend `sign` now: `ApprovalCenter.decide` → prompt (await the sheet) or allowedSession; if the token is not logged in, present `PINSheet`; then `TokenBroker.request(.sign…)`.
- `TokenBroker`: hold one helper process per serial, with an async queue so one call runs at a time (spec §4: batches queue).

- [ ] **Step 7: End-to-end hardware check (user)**

Append to `docs/VERIFY-P1.md`: curl SignHash from an allowlisted Origin, approve in the sheet, enter PIN, confirm the returned `CKy` verifies with openssl against the VNPT cert; repeat for the NC-CA token.

- [ ] **Step 8: Commit**

```bash
git add Sources Tests docs/VERIFY-P1.md
git commit -m "feat: PIN sheet, session approval, CKM_RSA_PKCS signing path

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (P1 scope):**
- Package skeleton → Task 1. Theme → Task 10. ModuleRegistry → Task 4. token-helper + shim → Tasks 2, 3, 7. TokenBroker → Task 8. PIN + approval sheets → Task 11. Menu bar → Task 10. Raw-hash Core → Tasks 5, 11. CTSigningHub bridge → Task 9. CKM_RSA_PKCS verification (spec top risk) → Task 11 Step 1.
- Web defense (Host check, CORS) → Task 9 Step 5 (HTTPServer). Allowlist defaults live in the app config; the origin-matching unit is folded into ApprovalCenter usage. **Note:** a dedicated origin-allowlist matcher test is deferred to P2 when more bridges share it — flagged, acceptable for P1 since CTSign in P1 is exercised from localhost curl.

**Placeholder scan:** Two bodies are described rather than shown — `PKCS11.swift` (Task 7) and `ReaderScanner`/`HTTPServer` NIO plumbing. These are deliberate: they are direct ports of the working C probes in `scratchpad/probe/` and standard NIO boilerplate, with no automated test (hardware / socket). Every unit with a test has full code. `CTSignBridge` JSON helpers (`jsonString`, `wrap`, `errorBody`) are named and their behavior pinned by the Task 9 tests.

**Type consistency:** `CertInfo` (Core) is the single cert type across helper, broker, backend and bridge; `CTSignBridge` maps it to the wire `CertificateInfo`. `SignMech`, `LoginResult`, `HelperRequest`/`HelperResponse` are defined in Task 6 and used unchanged in Tasks 7, 8, 11. `SigningBackend` is defined in Task 9 and implemented in Task 10.

**Known deferrals (carried to P2, flagged):** real `Version` string, request-shape confirmations (eSigner nesting), and the origin-allowlist shared matcher.
