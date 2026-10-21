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
