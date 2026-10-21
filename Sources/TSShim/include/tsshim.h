#ifndef TSSHIM_H
#define TSSHIM_H
#include <stdint.h>
#include <stddef.h>
/* Re-encode a malformed Feitian SM APDU to extended length.
   Returns new length written to out (cap outcap), or 0 if apdu is left unchanged. */
size_t ts_reencode(const uint8_t *apdu, size_t len, uint8_t *out, size_t outcap);
/* Split an extended-length SM APDU (Lc > 255) into ISO 7816 command-chaining chunks, because the
   macOS CCID stack rejects large extended APDUs with 0x80100016. Chunk 0 starts at offset 0; pass the
   previous `offset + chunk data length` for the next one. Intermediate chunks carry CLA|0x10; the last
   keeps the original CLA and gets a short Le. Returns the chunk length written to out, or 0 if apdu is
   not a chainable extended SM APDU (left unchanged). *dlen = data bytes in this chunk, *last = final chunk. */
size_t ts_chain_chunk(const uint8_t *apdu, size_t len, size_t offset, size_t maxchunk,
                      uint8_t *out, size_t outcap, size_t *dlen, int *last);
#endif
