# Feitian ePass2003 PIN → external-auth cryptogram (static RE)

Interop note: static analysis of vendor PKCS#11 modules the user owns, to build an
independent macOS ePass2003 driver that logs in without wasting PIN retries. No binary
was executed; no card/PC-SC touched.

## Targets analysed
- Primary (addresses below): `ncca_csp11_v1.dylib` arm64, sha256 `3bd0a2d9…`.
- Spot-checked identical: `cmcca_csp11_v1.dylib`, `ica_csp11_v1.dylib` (arm64), `fca_v1.dll` (PE32+ x86-64).
- All four embed `ENTERSAFE-ESPK` and `Feitian ePass2003` → one shared Feitian/OpenSC-derived codebase, mbedTLS crypto.
- (REA/Hopper had a 5th sibling `libvnptca_p11_v8.dylib` stuck open from a prior session; logic there is the same. All function addresses below are from the real `ncca` arm64 slice via `otool -arch arm64 -tV`.)

## OpenSC reference (card-epass2003.c, re-read)
`external_key_auth(card, kid, data, datalen)`:
1. GET CHALLENGE 8 bytes.
2. `hash_data`: `key[24] = SHA1(data)[20] || REVERSE_ORDER4(datalen)` — i.e. 20-byte SHA1 **plus the big-endian PIN length**, NOT 4 zero bytes (correction to the brief).
3. `des3_encrypt_cbc(key, 24, iv=0, challenge, 8)` → 8-byte cryptogram. keysize 24 ⇒ 3-key EDE3; keysize 16 ⇒ K1K2K1.
4. APDU `00 82 01 (0x80|kid) Lc=08 <cryptogram>`. User PIN kid=1 ⇒ P2=0x81; SO kid=2 ⇒ P2=0x82.
`data`/`datalen` come from `pin1` with pad_length=16, pad_char=0x00 ⇒ PIN is zero-padded to 16 before SHA1, so datalen=16 and the suffix = `00 00 00 10`.

## Vendor module — OBSERVED (ncca arm64)
`external_key_auth` @ **0x11d568** (sig `(x0=card, w1=kid, x2=key24)`):
```
rnd[8] = card.get_challenge(8)                 ; vtable op[0x48], w2=8        @0x11d5e8
des3_encrypt_cbc(key=x2, keysize=0x18,         ; 24-byte key, EDE3           @0x11d644
                 iv=zero16, in=rnd, len=8,     ; iv buffer zeroed @0x11d620
                 out=tmp8)                      ; helper 0x10cbf0
P2 = 0x80 | kid                                 ;                             @0x11d650
build_apdu(cla=0x00, ins=0x82, p1=0x01,         ; builder 0x116cd8            @0x11d664
           p2=P2, lc=0x08, data=tmp8, le=0)
transmit(apdu)                                  ; 0x116d44
```
Wrapper/op @ **0x11d3f4** rejects any key whose length ≠ 0x18 (24) before calling the above
(`cmp w8,#0x18` @0x11d42c/0x11d438) — hard proof the 3DES key is exactly 24 bytes.

3DES helper @ **0x10cbf0**: `keysize==0x10 → set2key (0x154a50)`, `keysize==0x18 → set3key (0x154d28)`,
then `des3_crypt_cbc(mode=1=encrypt)` (0x15625c). Pure mbedTLS; same expansion rule as OpenSC.
SHA1 present: mbedTLS init state `67452301/efcdab89/98badcfe/10325476` @ **0x15ac94**.

SM channel (separate, matches live trace `84 82 03 00` Lc=16) built by the same `0x116cd8`
with cla=0x84, ins=0x82, p1=3, lc=16 @0x125144 — this is mutual-auth, not the user-PIN path.

## Vendor module — INFERRED
PIN→24-byte key derivation (`SHA1(PIN padded to 16 with 0x00) || BE32(16)`): not directly
captured in the static trace — the 24-byte key is assembled in a higher PKCS#11 layer that
reaches `0x11d3f4` through a function-pointer card-op table, and SHA1 is invoked by name
through the mbedTLS dispatcher. But it is the only construction consistent with every
observed fact (key length forced to exactly 24; 3DES-EDE3-24; mbedTLS SHA1 linked; shared
OpenSC codebase). Treat as strong inference, confirm against one known-good PIN on real HW.

## Vendor module — UNKNOWN
- The exact trailing 4 bytes (`00 00 00 10` vs raw-vs-reversed length vs zeros) — not seen in
  a straight-line static path. Verify on HW: a correct login proves the suffix.
- Whether a DF (DF2003 / ENTERSAFE-ESPK) is MF-selected before auth: not traced here; OpenSC
  selects the key EF path implicitly via the SM channel, no explicit DF select in `external_key_auth`.

## Item-by-item vs OpenSC
1. C_Login→EXTERNAL AUTH builder: **MATCH** (0x11d568, APDU `00 82 01 ..`).
2. P1/P2 + no DF select in the auth fn: **MATCH** (P1=0x01, P2=0x80|kid; kid 1=user, 2=SO).
3. PIN transform (SHA1, pad-16 0x00, +4-byte len → 24): **MATCH inferred** (not byte-observed).
4. Cipher: **MATCH** — 3DES-EDE3, 24-byte key, CBC, IV=0, challenge 8, response 8.
5. Retry/lock: SW mappers @0x11cf14 (user) / 0x11d184 (SO); checks `0x9000`/`0x9403`,
   maps `63Cx`; `CKR_PIN_LOCKED` string present. **MATCH** (reads SW, does not pre-count).
6. NC-CA = CMC = I-CA: external_key_auth structurally identical (ICA @0x118100: `w1=0x18;
   x4=0x8; 3des; P2=0x80|kid; ins=0x82,p1=1,lc=8`). FastCA = same codebase (Windows x86-64,
   `ENTERSAFE-ESPK`), not instruction-diffed. **MATCH**.

## Verdict
OpenSC derivation matches: **YES for the cryptogram, PARTIAL (inferred) for the PIN hash.**
Exact derivation to implement:
```
key24 = SHA1( PIN_ascii padded to 16 bytes with 0x00 )  ||  00 00 00 10
chal8 = GET CHALLENGE (00 84 00 00 08)
cryptogram8 = 3DES-EDE3-CBC_encrypt(key=key24, iv=00*8, data=chal8)   # 3 independent keys
EXTERNAL AUTH: 00 82 01 (0x80|kid) 08 <cryptogram8>   # kid=1 user PIN, kid=2 SO PIN
```
First login against a known PIN confirms the 4-byte length suffix; everything else is observed.
