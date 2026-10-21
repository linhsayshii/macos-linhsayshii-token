#include "cpcsc.h"
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <string.h>
#include <stdlib.h>

int cpcsc_list_readers(cpcsc_reader *out, int max) {
    SCARDCONTEXT ctx;
    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx) != SCARD_S_SUCCESS)
        return -1;

    DWORD namesLen = 0;
    if (SCardListReaders(ctx, NULL, NULL, &namesLen) != SCARD_S_SUCCESS || namesLen == 0) {
        SCardReleaseContext(ctx);
        return 0;
    }
    char *buf = (char *)malloc(namesLen);
    if (!buf) { SCardReleaseContext(ctx); return -1; }
    if (SCardListReaders(ctx, NULL, buf, &namesLen) != SCARD_S_SUCCESS) {
        free(buf); SCardReleaseContext(ctx); return -1;
    }

    int count = 0;
    for (char *p = buf; *p != '\0' && count < max; p += strlen(p) + 1) {
        SCARD_READERSTATE st;
        memset(&st, 0, sizeof st);
        st.szReader = p;
        st.dwCurrentState = SCARD_STATE_UNAWARE;
        if (SCardGetStatusChange(ctx, 0, &st, 1) == SCARD_S_SUCCESS) {
            cpcsc_reader *r = &out[count];
            memset(r, 0, sizeof *r);
            strncpy(r->name, p, sizeof r->name - 1);
            int n = (int)st.cbAtr;
            if (n > 33) n = 33;
            memcpy(r->atr, st.rgbAtr, (size_t)n);
            r->atr_len = n;
            count++;
        }
    }
    free(buf);
    SCardReleaseContext(ctx);
    return count;
}
