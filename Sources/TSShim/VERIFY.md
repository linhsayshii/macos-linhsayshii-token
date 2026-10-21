# TSShim hardware verify

With a VNPT token plugged in, once token-helper lands (Task 7):

    HELPER=$(swift build --show-bin-path)/token-helper
    SHIM=$(find .build -name libTSShim.dylib | head -1)
    echo '{"listTokens":{}}' | DYLD_INSERT_LIBRARIES=$SHIM $HELPER --module /usr/local/lib/libvnptca_p11_v8.dylib

Expect one JSON line with the token label, and zero 0x80100016 errors.
