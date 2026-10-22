#include "minvoice_zip.h"
#include <zlib.h>
#include <string.h>
int mvzip_inflate(const uint8_t *input, size_t size, uint8_t *output, size_t length) {
    if (!input || !output || !size || size > (2u << 20) || !length || length > (8u << 20)) return -1;
    z_stream s; memset(&s, 0, sizeof s);
    s.next_in = (Bytef *)input; s.avail_in = (uInt)size;
    s.next_out = output; s.avail_out = (uInt)length;
    if (inflateInit2(&s, -MAX_WBITS) != Z_OK) return -1;
    int rv = inflate(&s, Z_FINISH);
    int ok = rv == Z_STREAM_END && s.total_in == size && s.total_out == length;
    inflateEnd(&s);
    return ok ? 0 : -1;
}
uint32_t mvzip_crc(const uint8_t *input, size_t length) { return (uint32_t)crc32(0, input, (uInt)length); }
