#include "cfastca.h"
#include "libopensc/opensc.h"
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

struct fca_runtime {
    void *library;
    sc_context_t *context;
    __typeof__(&sc_context_create) context_create;
    __typeof__(&sc_release_context) release_context;
    __typeof__(&sc_ctx_get_reader_by_name) get_reader;
    __typeof__(&sc_connect_card) connect;
    __typeof__(&sc_disconnect_card) disconnect;
    __typeof__(&sc_lock) lock;
    __typeof__(&sc_unlock) unlock;
    __typeof__(&sc_reset) reset;
    __typeof__(&sc_format_path) format_path;
    __typeof__(&sc_select_file) select_file;
    __typeof__(&sc_file_free) file_free;
    __typeof__(&sc_read_binary) read_binary;
    __typeof__(&sc_get_challenge) challenge;
    __typeof__(&sc_format_apdu) format_apdu;
    __typeof__(&sc_transmit_apdu) transmit;
};

struct fca_card {
    fca_runtime *runtime;
    sc_card_t *card;
    int locked, attempted, authenticated, signed_once;
};

void fca_wipe(void *bytes, size_t length) {
    volatile uint8_t *p = bytes;
    while (length--) *p++ = 0;
}

int fca_runtime_open(const char *path, fca_runtime **out, char *error, size_t capacity) {
    if (!path || !out || !error || capacity == 0) return FCA_INVALID;
    *out = NULL;
    fca_runtime *r = calloc(1, sizeof(*r));
    if (!r) return FCA_RUNTIME;
    r->library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!r->library) {
        snprintf(error, capacity, "Không nạp được OpenSC tại %s", path);
        goto fail;
    }
    const char *(*version)(void) = dlsym(r->library, "sc_get_version");
    // The public structures used below are pinned to these upstream headers.
    if (!version || strcmp(version(), "0.27.1") != 0) {
        snprintf(error, capacity, "ESPK cần OpenSC 0.27.1 (ABI chưa hỗ trợ phiên bản khác)");
        goto fail;
    }
#define LOAD(field, symbol) do { \
    r->field = dlsym(r->library, #symbol); \
    if (!r->field) { snprintf(error, capacity, "OpenSC thiếu %s", #symbol); goto fail; } \
} while (0)
    LOAD(context_create, sc_context_create); LOAD(release_context, sc_release_context);
    LOAD(get_reader, sc_ctx_get_reader_by_name); LOAD(connect, sc_connect_card);
    LOAD(disconnect, sc_disconnect_card); LOAD(lock, sc_lock); LOAD(unlock, sc_unlock);
    LOAD(reset, sc_reset); LOAD(format_path, sc_format_path); LOAD(select_file, sc_select_file);
    LOAD(file_free, sc_file_free); LOAD(read_binary, sc_read_binary);
    LOAD(challenge, sc_get_challenge); LOAD(format_apdu, sc_format_apdu);
    LOAD(transmit, sc_transmit_apdu);
#undef LOAD
    setenv("OPENSC_DEBUG", "0", 1);
    unsetenv("OPENSC_DEBUG_FILE");
    sc_context_param_t parameters = {0};
    parameters.app_name = "TokenSignerESPK";
    parameters.flags = SC_CTX_FLAG_DISABLE_POPUPS;
    int rv = r->context_create(&r->context, &parameters);
    if (rv < 0) {
        snprintf(error, capacity, "Không tạo được OpenSC context: %d", rv);
        goto fail;
    }
    // Configuration can enable debug even when parameters.debug == 0.
    // Disable it before connecting or handling any credential/APDU.
    r->context->debug = 0;
    *out = r;
    return 0;
fail:
    fca_runtime_close(r);
    return FCA_RUNTIME;
}

void fca_runtime_close(fca_runtime *r) {
    if (!r) return;
    if (r->context && r->release_context) r->release_context(r->context);
    if (r->library) dlclose(r->library);
    free(r);
}

int fca_card_open(fca_runtime *r, const char *reader, fca_card **out) {
    return fca_card_open_profile(r, reader, FCA_PROFILE_FASTCA, out);
}

int fca_card_open_profile(fca_runtime *r, const char *reader, fca_profile profile, fca_card **out) {
    if (!out) return FCA_INVALID;
    *out = NULL;
    if (!r || !reader || (profile != FCA_PROFILE_FASTCA && profile != FCA_PROFILE_EFY)) return FCA_INVALID;
    sc_reader_t *device = r->get_reader(r->context, reader);
    if (!device) return SC_ERROR_READER;
    fca_card *c = calloc(1, sizeof(*c));
    if (!c) return FCA_RUNTIME;
    c->runtime = r;
    int rv = r->connect(device, &c->card);
    if (rv < 0) goto fail;
    const uint8_t fastca_atr[] = {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
                          0x05,0x10,0x52,0x39,0x71,0xdf,0,0,0x69,0,0,0x11};
    const uint8_t fastca_atr0631[] = {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
                          0x05,0x10,0x06,0x31,0x71,0xdf,0,0,0x69,0,0,0x4d};
    const uint8_t efy_atr[] = {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
                          0x05,0x10,0x11,0x39,0x71,0xdf,0,0,0x51,0,0,0x6a};
    int matches = c->card->atr.len == sizeof(fastca_atr) &&
        (profile == FCA_PROFILE_EFY ? !memcmp(c->card->atr.value, efy_atr, sizeof(efy_atr)) :
         (!memcmp(c->card->atr.value, fastca_atr, sizeof(fastca_atr)) ||
          !memcmp(c->card->atr.value, fastca_atr0631, sizeof(fastca_atr0631))));
    if (!matches ||
        !c->card->driver || !c->card->driver->short_name || strcmp(c->card->driver->short_name, "epass2003")) {
        rv = FCA_INVALID;
        goto fail;
    }
    rv = r->lock(c->card);
    if (rv < 0) goto fail;
    c->locked = 1;
    // A prior helper may have crashed while authenticated. Clear that state
    // before metadata/PIN handling on every EFY connection, including reads.
    if (profile == FCA_PROFILE_EFY) {
        rv = r->reset(c->card, 0);
        if (rv < 0) goto fail;
        // sc_reset resets only the reader, leaving OpenSC's old SM keys in
        // memory. Re-establish epass2003 SM before any metadata or PIN APDU.
        if (!c->card->sm_ctx.ops.open) { rv = FCA_INVALID; goto fail; }
        rv = c->card->sm_ctx.ops.open(c->card);
        if (rv < 0) goto fail;
    }
    *out = c;
    return 0;
fail:
    fca_card_close(c);
    return rv;
}

void fca_card_close(fca_card *c) {
    if (!c) return;
    if (c->card) {
        // Also reset after an uncertain transport result; authentication may
        // have reached the card even if its response did not reach the caller.
        if (c->attempted) c->runtime->reset(c->card, 0);
        if (c->locked) c->runtime->unlock(c->card);
        c->runtime->disconnect(c->card);
    }
    fca_wipe(c, sizeof(*c));
    free(c);
}

static int select_df(fca_card *c) {
    sc_path_t path;
    c->runtime->format_path("3f002003", &path);
    return c->runtime->select_file(c->card, &path, NULL);
}

int fca_read_file(fca_card *c, uint16_t fid, uint8_t *output, size_t capacity, size_t *length) {
    // ESPK logical file contents are metadata; private key EFs (Axxx/8xxx) are
    // never exposed through this API. Catalog has the separate known FID 6F01.
    if (!c || !output || !length || capacity > 65536 ||
        !((fid >= 0x2000 && fid < 0x4000) || fid == 0x6f01)) return FCA_INVALID;
    *length = 0;
    char name[16];
    snprintf(name, sizeof(name), "3f002003%04x", fid);
    sc_path_t path;
    c->runtime->format_path(name, &path);
    sc_file_t *file = NULL;
    int rv = c->runtime->select_file(c->card, &path, &file);
    if (rv < 0 || !file) { if (file) c->runtime->file_free(file); return rv < 0 ? rv : FCA_INVALID; }
    size_t size = file->size;
    c->runtime->file_free(file);
    if (!size || size > capacity) return FCA_INVALID;
    unsigned long flags = 0;
    rv = c->runtime->read_binary(c->card, 0, output, size, &flags);
    if (rv < 0) return rv;
    if ((size_t)rv != size) return FCA_INVALID;
    *length = size;
    return 0;
}

int fca_login(fca_card *c, const uint8_t *pin, size_t length, uint16_t *status) {
    if (!c || !pin || !status || !length || length > 64 || c->attempted) return FCA_INVALID;
    *status = 0;
    for (size_t i = 0; i < length; i++) if (pin[i] < 0x20 || pin[i] > 0x7e) return FCA_INVALID;
    int rv = select_df(c);
    if (rv < 0) return rv;
    uint8_t key[24] = {0}, challenge[8] = {0}, cryptogram[8] = {0}, iv[8] = {0};
    CC_SHA1(pin, (CC_LONG)length, key);
    key[20] = (length >> 24) & 255; key[21] = (length >> 16) & 255;
    key[22] = (length >> 8) & 255; key[23] = length & 255;
    rv = c->runtime->challenge(c->card, challenge, sizeof(challenge));
    if (rv < 0) goto done;
    size_t produced = 0;
    if (CCCrypt(kCCEncrypt, kCCAlgorithm3DES, 0, key, sizeof(key), iv,
                challenge, sizeof(challenge), cryptogram, sizeof(cryptogram), &produced) != kCCSuccess || produced != 8) {
        rv = FCA_INVALID; goto done;
    }
    sc_apdu_t apdu;
    c->runtime->format_apdu(c->card, &apdu, SC_APDU_CASE_3_SHORT, 0x82, 1, 0x81);
    apdu.data = cryptogram; apdu.datalen = apdu.lc = sizeof(cryptogram);
    apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP;
    c->attempted = 1;
    rv = c->runtime->transmit(c->card, &apdu);
    if (rv < 0) goto done;
    *status = (uint16_t)(apdu.sw1 << 8 | apdu.sw2);
    if (*status == 0x9000) c->authenticated = 1;
    else if (*status == 0x6983 || *status == 0x63c0) rv = FCA_PIN_LOCKED;
    else if ((*status & 0xfff0) == 0x63c0) rv = FCA_PIN_INCORRECT;
    else rv = FCA_STATUS;
done:
    fca_wipe(key, sizeof(key)); fca_wipe(challenge, sizeof(challenge));
    fca_wipe(cryptogram, sizeof(cryptogram));
    return rv;
}

int fca_sign(fca_card *c, uint16_t key, const uint8_t *block, size_t length,
             uint8_t *signature, size_t capacity, size_t *written, uint16_t *status) {
    if (!c || !c->authenticated || c->signed_once || !block || length != 256 ||
        !signature || capacity < 256 || !written || !status || key < 0xa000 || key > 0xafff) return FCA_INVALID;
    *written = 0; *status = 0;
    c->signed_once = 1;
    uint8_t mse[] = {0x80,1,0x84,0x81,2,(uint8_t)(key >> 8),(uint8_t)key};
    sc_apdu_t apdu;
    c->runtime->format_apdu(c->card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xb8);
    apdu.data = mse; apdu.datalen = apdu.lc = sizeof(mse);
    apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP;
    int rv = c->runtime->transmit(c->card, &apdu);
    if (rv < 0) return rv;
    *status = (uint16_t)(apdu.sw1 << 8 | apdu.sw2);
    if (*status != 0x9000) return FCA_STATUS;
    c->runtime->format_apdu(c->card, &apdu, SC_APDU_CASE_4_EXT, 0x2a, 0x80, 0x86);
    apdu.data = block; apdu.datalen = apdu.lc = length;
    apdu.resp = signature; apdu.resplen = capacity; apdu.le = 256;
    apdu.flags |= SC_APDU_FLAGS_NO_RETRY_WL | SC_APDU_FLAGS_NO_GET_RESP;
    rv = c->runtime->transmit(c->card, &apdu);
    if (rv < 0) return rv;
    *status = (uint16_t)(apdu.sw1 << 8 | apdu.sw2);
    if (*status != 0x9000) return FCA_STATUS;
    if (apdu.resplen != 256) return FCA_INVALID;
    *written = apdu.resplen;
    return 0;
}
