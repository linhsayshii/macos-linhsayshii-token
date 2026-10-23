#ifndef TSSHIM_H
#define TSSHIM_H
#include <stdint.h>
/* Per-helper policy. Longmai uses valid PC/SC APDUs and must bypass the
   Feitian encoding workaround even when this shim is statically linked. */
void ts_set_reencoding_enabled(int enabled);
#include <stddef.h>
/* Re-encode a malformed Feitian SM APDU to extended length.
   Returns new length written to out (cap outcap), or 0 if apdu is left unchanged. */
size_t ts_reencode(const uint8_t *apdu, size_t len, uint8_t *out, size_t outcap);
#endif
