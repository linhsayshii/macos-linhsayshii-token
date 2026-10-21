# VNPT lib — PIN external-auth + sign derivation (static RE, no card)

Target: `/usr/local/lib/libvnptca_p11_v8.dylib` (arm64 slice). Addresses are arm64 VAs.
Reference: OpenSC `card-epass2003.c` (written by Feitian; this dylib is the same ENTERSAFE/ePass2003
middleware lineage — RTTI `CToken2003`/`CStore2003`/`AuthManager2003`, `ENTERSAFE-ESPK`).
Method: Hopper via REA + cached `objdump` of the arm64 slice. No PIN, no PC/SC.

## APDU call layer (anchors)
- `0x115ac4` = fill APDU struct (cla,ins,p1,p2,lc,data,le) → forwards to `0x125960`.
- `0x115b30` = SM-wrap + transmit; handles SW `6985`→refresh/re-auth, `6988` (SM), stores SW.
- `0x1157c4` = GetRandom/GET CHALLENGE loop: INS `0x84`, 16-byte (0x10) chunks.
- SM session keys live at `0x1bd228` / `0x1bd238` = `01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10`
  — byte-identical to OpenSC `g_init_key_enc` / `g_init_key_mac`. **SM keys = OpenSC defaults.**

## 1–4. Login → EXTERNAL AUTHENTICATE  (Observed)
Worker `0x11c234(self, 0x80|kid, key24ptr)`; dispatcher `0x11c0c0` asserts keylen `== 0x18` (24) at `0x11c0f8`.
```
GET CHALLENGE  -> vtable[+0x48](self, buf, len=8)          @0x11c2b0  (challenge = 8 bytes)
cryptogram8 = DES3_CBC_enc(key=key24, iv=0, in=challenge8) @0x11c310 -> 0x10b9a0
APDU: CLA/INS=0x82 P1=0x01 P2=0x80|kid Lc=8 data=cryptogram @0x11c318-0x11c344 (0x115ac4)
transmit                                                   @0x11c368 (0x115b30)
```
- Cipher `0x10b9a0`: keylen 24 → 3DES key schedule `0x15315c`, then CBC `0x154690` dir=1 (encrypt).
  keylen 16 path (`0x152e84`) also exists but auth uses 24. IV buffer zeroed at `0x11c2f4`.
- P1/P2: **P1=0x01, P2=0x80|kid** (`0x11c31c-0x11c334`). Same code at second site `0x11b818`.
- kid: user=1 (P2 `0x81`), SO=2 (P2 `0x82`); post-steps `0x11bbe0` (user) / `0x11be50` (SO).
- DF: SM SELECT of DF `0x2003` happens in the open path (`0x1221a0`, `mov w1,#0x2003`), before auth.

### PIN transform (Inferred — strong)
The 24-byte `key24` is produced by the caller of `0x11c0c0` (C++ vtable-dispatched, not byte-traced).
Everything downstream (len asserted 24, 3DES-CBC/IV0, 8-byte challenge) matches OpenSC `external_key_auth`,
so the transform is OpenSC `hash_data(SHA1)`:
```
key24 = SHA1(PIN padded with 0x00 to 16 bytes)[20]  ||  BE32(pinlen=0x00000010)
```
SHA1 soft engine present (`8SHA1Soft`), HASH_LEN 24 used throughout. **No salt** (no serial/label mixed in).
→ The one thing to confirm empirically on first login. If it matches OpenSC (expected), it costs 0 retries.
Open question: whether PIN is zero-padded to 16 before SHA1 (OpenSC framework `SC_PIN_CMD_NEED_PADDING`)
or hashed raw at its real length — try padded-to-16 first (len tail `00 00 00 10`).

## 5. Retry counter + lock  (Observed)
`0x11ba00` = get-retries: GET CHALLENGE(8) then `82 01 80|kid` **CASE_1 (no data)**; then
`(SW & 0xFFF0)==0x63C0` → retries = `SW & 0x0F` (`0x11bb28-0x11bb44`). `63C1` special-cased `0x11bf50`.
Lock/blocked via SW `6983`; `CKR_PIN_LOCKED` string present. Exactly OpenSC `get_external_key_retries`.

## 6. Customer check (GET DATA)  (Partial / prior-note)
GET DATA builder: INS `0xca`, **P1=0x01** (`0x1161b8`); token-info path reads P2 `0x81`/`0x84`
(e.g. `0x11b7b0 mov w1,#0x81 → 0x116184`). The compared field/value was **not decoded** statically
(SM-encrypted DO). ATR customer byte [19]==0x32 gate is separate (see runtime-probe.md). The `0x1bd228`
memcmp is the SM key setup, **not** the customer check.

## 7. Signing: MSE + PSO  (Observed structure / Inferred detail)
- MSE: INS `0x22` (`0x11db78`). Data built at `0x11df10`: CRT with tag `0x80` (algo ref) len 01,
  tag `0x81` (key/file ref) — shape `80 01 <alg> 81 02 <FID>` as OpenSC. FID mapping
  (OpenSC `0x2900 + 0x20*keyref`; containers 8000/8020) **not byte-confirmed** here — Inferred.
- PSO COMPUTE: INS `0x2a` P1=`0x9e` P2=`0x9a` (`0x11de8c`). Matches OpenSC EC `2A 9E 9A`.
- PSO HASH: INS `0x2a` P1=`0x90` path exists (`0x1191a4`, `0x11934c`) — card-side hashing.
- **Why 2 PSO/signature:** VNPT lib does on-card **PSO:HASH (2A 90..)** then **PSO:COMPUTE (2A 9E 9A)**,
  i.e. hash on the card. OpenSC instead hashes on the host and sends **one** PSO (EC `2A 9E 9A`,
  RSA `2A 80 86`). → **Divergence** in sign flow; login/SM are identical.
- Padding: host sends DigestInfo/hash; card finalizes. RSA uses `2A 80 86` (decipher) in OpenSC.

## Verdict
See one-line summary in the handback. Login external-auth derivation = OpenSC; sign structure = OpenSC
with an extra on-card PSO:HASH step.
