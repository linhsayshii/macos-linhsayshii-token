# token-helper hardware verification

This task has no automated test — it needs a physical token. Run this with a
VNPT token plugged in (the user's step; not claimed verified by the agent):

```bash
HELPER=$(swift build --show-bin-path)/token-helper
SHIM=$(find .build -name libTSShim.dylib | head -1)
echo '{"listTokens":{}}' | DYLD_INSERT_LIBRARIES=$SHIM $HELPER --module /usr/local/lib/libvnptca_p11_v8.dylib
# expect one line, e.g.:
# {"tokens":[{"serial":"8377200522219143","label":"VNPT-CA PKI Token",...}]}
```

Then list certs for that serial:

```bash
echo '{"listCerts":{"serial":"8377200522219143"}}' | \
  DYLD_INSERT_LIBRARIES=$SHIM $HELPER --module /usr/local/lib/libvnptca_p11_v8.dylib
# expect {"certs":[{"id":"...","subject":"...","serialHex":"...",...}]}
```
