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

size_t ts_chain_chunk(const uint8_t *apdu, size_t len, size_t offset, size_t maxchunk,
                      uint8_t *out, size_t outcap, size_t *dlen, int *last) {
    if (len < 7 || apdu[4] != 0 || (apdu[0] & 0x0C) != 0x0C) return 0;
    size_t lc = ((size_t)apdu[5] << 8) | apdu[6];
    if (lc <= 255) return 0;
    /* Feitian libs append no Le, a 2-byte Le, or (seen on hardware) a single Le byte after the extended Lc. */
    int leBytes;
    if (len == 7 + lc) leBytes = 0; else if (len == 8 + lc) leBytes = 1; else if (len == 9 + lc) leBytes = 2; else return 0;
    if (offset >= lc || maxchunk == 0 || maxchunk > 255) return 0;
    size_t n = lc - offset < maxchunk ? lc - offset : maxchunk;
    int isLast = offset + n == lc;
    size_t need = 5 + n + (isLast && leBytes ? 1 : 0);
    if (outcap < need) return 0;
    out[0] = isLast ? apdu[0] : (uint8_t)(apdu[0] | 0x10);
    out[1] = apdu[1]; out[2] = apdu[2]; out[3] = apdu[3];
    out[4] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) out[5 + i] = apdu[7 + offset + i];
    if (isLast && leBytes) {
        unsigned le = leBytes == 1 ? apdu[len - 1] : ((unsigned)apdu[len - 2] << 8) | apdu[len - 1];
        out[5 + n] = le >= 256 ? 0x00 : (uint8_t)le;
    }
    *dlen = n; *last = isLast;
    return need;
}

#include <string.h>
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
    if (ts_log() && il > 255) {
        fprintf(stderr, "[tsshim] big apdu len=%u first12=", il);
        for (uint32_t i = 0; i < 12 && i < il; i++) fprintf(stderr, "%02x", in[i]);
        fprintf(stderr, " last4=");
        for (uint32_t i = il - 4; i < il; i++) fprintf(stderr, "%02x", in[i]);
        fprintf(stderr, "\n");
    }
    {   /* large extended SM APDU: send as a command chain (see ts_chain_chunk) */
        size_t off = 0, dl = 0; int last = 0;
        size_t cn = ts_chain_chunk(in, il, 0, 200, buf, sizeof buf, &dl, &last);
        while (cn > 0) {
            uint32_t rl = *ol;
            if (!last) {
                uint8_t tmp[300]; uint32_t tl = sizeof tmp;
                LONG rv = SCardTransmit(h, send, buf, (uint32_t)cn, recv, tmp, &tl);
                ts_logsw("chain", (uint32_t)cn, buf, rv, tmp, tl);
                if (rv != 0 || tl < 2 || tmp[tl - 2] != 0x90 || tmp[tl - 1] != 0x00) {
                    memcpy(out, tmp, tl < rl ? tl : rl); *ol = tl < rl ? tl : rl; return rv;  /* abort chain, surface the card's answer */
                }
                off += dl;
                cn = ts_chain_chunk(in, il, off, 200, buf, sizeof buf, &dl, &last);
                continue;
            }
            LONG rv = SCardTransmit(h, send, buf, (uint32_t)cn, recv, out, ol);
            ts_logsw("chain-last", (uint32_t)cn, buf, rv, out, ol ? *ol : 0);
            return rv;
        }
    }
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
