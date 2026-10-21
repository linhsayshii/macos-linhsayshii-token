# P2 verification

## Verified here (automated, `swift test`)
- CMS detached: `openssl cms -verify` passes for SHA-256 and SHA-1; tampered content fails.
- XMLDSig: placement, SigningTime, independent self-verify (SignatureValue against the key, reference-1 digest recomputed).
  `xmlsec1 1.3.12 --verify` passes for SHA-256 and SHA-1 (root with default namespace), tampered body fails. The xmlsec1 run caught a wrong `rsa-sha1` URI (fixed).
- WebGuard (Host / Origin / CORS / Private-Network), OriginStore persistence, AuditLog (hash only, 0600), WebSocket + WSS handshake guard, local CA (openssl verify, SAN), eSigner / VNPT / CTSigningHub signxml handlers against a fake service.
- Live smoke on a dev instance (`TOKENSIGNER_PORT_OFFSET=100`): CORS + PNA headers, 403 on bad Host and unknown Origin, `filePath` ignored, WS/WSS 101 upgrade for allowlisted origin and 403 otherwise, audit.jsonl written.

## Hardware finding 2026-10-22 (NC-CA, TSSHIM_LOG)
- The macOS 27 CCID passes long extended APDUs fine (no-PIN probe, Lc up to 500). The vendor lib's SM signing commands failed
  only because they had extended Lc + a single Le byte; the shim now widens Le to 2 bytes (`ts_reencode`).
- With that, `CKM_RSA_PKCS` over a 51-byte DigestInfo signs (`0c2a8086` -> SW 9000). This overturns P1's "tokens sign only raw data" conclusion:
  the P1 rv=48 was this CCID malformation.
- On-card hashing (`CKM_SHA256_RSA_PKCS`, `0c2a9080`) is rejected by the CARD (SW 6A80) for messages above ~200 bytes. So all signing
  now hashes in software and signs the DigestInfo with `CKM_RSA_PKCS` (BrokerSigner.signDigest). SignHash / VNPT signHash are live.
- `scripts/sign-size-test.sh` reproduces this.

## Verified on hardware 2026-10-22
- NC-CA token, cert 54010E004EC042B6DCD011ABE8BBAF6A: CTSigningHub `signxml` -> approval sheet -> PIN -> signed XML; `xmlsec1 --verify` = OK.
- GetCert `valid` now reflects expiry.

## NOT verified on hardware (needs the user: PIN + approval click)
- Real-token sign through each bridge: `signxml` (CTSigningHub), eSigner `CER_001`, VNPT `SignXML`/`SignCMS`. Then check with `xmlsec1 --verify` / `openssl cms -verify`.
- `SHA1_RSA_PKCS` on the Feitian libs (only `SHA256_RSA_PKCS` was proven in P1).
- Trusting the local CA: click the menu button once; check `https://localhost:4433` from a browser.

## (verify) items needing Parallels captures
- CTSigningHub `signxml`: meaning of `cks` / `dataBV`; Version string. Adapter: `SignXmlRequestAdapter` (CTSignModel.swift).
- eSigner: nested `INPUT` vs flat (adapter accepts both); `CER_001` prepared-byte (`BASE64_VALUE`, SHA1) vs whole-XML (`VALUE`). `ESignerBridge.sign`.
- VNPT: `args` layouts, option field names, `Connector` extras (`domain`, `payload*callback` framing), attached vs detached CMS (id 4 vs 8). `VNPTArgsAdapter`.
- XMLDSig vendor-structure comparison (transforms, reference order) not done.

## Known limits
- PIN is requested per on-card signature (no PIN session cache).
- Signing time fixed to +07:00.
- No renewal UI for the localhost leaf (reissued automatically at start when <30 days left).
