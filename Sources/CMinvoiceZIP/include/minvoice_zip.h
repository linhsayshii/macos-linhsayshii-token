#include <stdint.h>
#include <stddef.h>
int mvzip_inflate(const uint8_t *input, size_t size, uint8_t *output, size_t length);
uint32_t mvzip_crc(const uint8_t *input, size_t length);
