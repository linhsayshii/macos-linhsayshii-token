#ifndef CPCSC_H
#define CPCSC_H
#include <stdint.h>

/* Plain-C reader record. No PCSC types cross into Swift (the PCSC clang module
   is marked incompatible with Swift), so all winscard calls stay in shim.c. */
typedef struct {
    char name[128];
    uint8_t atr[33];
    int atr_len;
} cpcsc_reader;

/* Enumerate readers and their current ATRs. Writes up to `max` records to `out`,
   returns the count, or -1 on a PC/SC error. */
int cpcsc_list_readers(cpcsc_reader *out, int max);

#endif
