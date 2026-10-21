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

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

/* Interpose SCardTransmit: re-encode the malformed Feitian SM APDU before it
   reaches the system CCID stack. The MAC covers header+DOs, not Lc/Le, so SM
   stays valid; valid short APDUs pass through untouched. */
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
