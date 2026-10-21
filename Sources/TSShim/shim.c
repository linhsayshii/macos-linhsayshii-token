#include "tsshim.h"
size_t ts_reencode(const uint8_t *apdu, size_t len, uint8_t *out, size_t outcap) {
    (void)apdu; (void)len; (void)out; (void)outcap;
    return 0;
}
