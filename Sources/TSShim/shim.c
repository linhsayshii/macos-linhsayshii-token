#include "tsshim.h"
#include <string.h>

size_t ts_reencode(const uint8_t *apdu, size_t len, uint8_t *out, size_t outcap) {
    if (len < 7) return 0;
    if ((apdu[0] & 0x0C) != 0x0C) return 0;   /* SM class bit */
    if (apdu[4] == 0) {
        /* Feitian SM signing can append a short Le after extended Lc.
           Widen only that malformed form; keep the authenticated bytes intact.
           Ported from the hardware-tested P2 fix fd3554f. */
        size_t elc = ((size_t)apdu[5] << 8) | apdu[6];
        if (elc == 0 || len != 8 + elc || outcap < len + 1) return 0;
        memcpy(out, apdu, len - 1);
        out[len - 1] = 0x00; out[len] = apdu[len - 1];
        return len + 1;
    }
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

#include <stdio.h>
#include <stdlib.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

/* Set TSSHIM_LOG=1 to trace each transmitted APDU's length and SW on stderr. */
static int ts_log(void) { static int v = -1; if (v < 0) v = getenv("TSSHIM_LOG") ? 1 : 0; return v; }
static void ts_logsw(const char *tag, uint32_t len, const uint8_t *h, LONG rv,
                     const uint8_t *resp, uint32_t rl) {
    if (!ts_log()) return;
    fprintf(stderr, "[tsshim] %s len=%u hdr=%02x%02x%02x%02x%02x rv=0x%lx",
            tag, len, h[0], h[1], h[2], h[3], len >= 5 ? h[4] : 0, (long)rv);
    if (rv == 0 && rl >= 2) fprintf(stderr, " SW=%02x%02x", resp[rl - 2], resp[rl - 1]);
    fprintf(stderr, "\n");
}

/* Interpose SCardTransmit: re-encode the malformed Feitian SM APDU before it
   reaches the system CCID stack. The MAC covers header+DOs, not Lc/Le, so SM
   stays valid; valid short APDUs pass through untouched. */
static LONG ts_transmit(SCARDHANDLE h, const SCARD_IO_REQUEST *send,
                        const uint8_t *in, uint32_t il,
                        SCARD_IO_REQUEST *recv, uint8_t *out, uint32_t *ol) {
    uint8_t buf[4096];
    size_t n = ts_reencode(in, il, buf, sizeof buf);
    if (n > 0) {
        LONG rv = SCardTransmit(h, send, buf, (uint32_t)n, recv, out, ol);
        ts_logsw("reencode", (uint32_t)n, buf, rv, out, ol ? *ol : 0);
        return rv;
    }
    LONG rv = SCardTransmit(h, send, in, il, recv, out, ol);
    ts_logsw("pass", il, in, rv, out, ol ? *ol : 0);
    return rv;
}

__attribute__((used)) static struct { const void *a, *b; }
_ts_interpose __attribute__((section("__DATA,__interpose"))) =
    { (const void *)ts_transmit, (const void *)SCardTransmit };
