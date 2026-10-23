// Compile the production implementation against injected OpenSC operations.
// Never loads a runtime or connects to PC/SC; every APDU ends in mock_transmit.
#include "../../Sources/CFastCA/fastca.c"
#include <assert.h>

static sc_card_t device;
static sc_reader_t reader;
static struct sc_card_driver driver;
static int locks, resets, refreshes, unlocks, disconnects, auths, mses, psos;
static int reset_result, refresh_result, transport_result, auth_status, mse_status, pso_status;
static uint16_t expected_key = 0xa0e0;
static const uint8_t efy_atr[] = {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
    0x05,0x10,0x11,0x39,0x71,0xdf,0,0,0x51,0,0,0x6a};
static const uint8_t fastca_atr[] = {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
    0x05,0x10,0x52,0x39,0x71,0xdf,0,0,0x69,0,0,0x11};
static const uint8_t fastca_atr0631[] = {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,
    0x05,0x10,0x06,0x31,0x71,0xdf,0,0,0x69,0,0,0x4d};

static sc_reader_t *mock_reader(sc_context_t *ctx, const char *name) { return &reader; }
static int mock_connect(sc_reader_t *r, sc_card_t **out) { *out = &device; return 0; }
static int mock_lock(sc_card_t *c) { locks++; return 0; }
static int mock_reset(sc_card_t *c, int cold) { resets++; return reset_result; }
static int mock_refresh(sc_card_t *c) { refreshes++; return refresh_result; }
static int mock_unlock(sc_card_t *c) { unlocks++; return 0; }
static int mock_disconnect(sc_card_t *c) { disconnects++; return 0; }
static void mock_path(const char *s, sc_path_t *p) { memset(p, 0, sizeof(*p)); }
static int mock_select(sc_card_t *c, const sc_path_t *p, sc_file_t **out) { return 0; }
static int mock_challenge(sc_card_t *c, uint8_t *output, size_t length) {
    assert(length == 8); memset(output, 0x31, length); return 0;
}
static void mock_format(sc_card_t *c, sc_apdu_t *a, int type, int ins, int p1, int p2) {
    memset(a, 0, sizeof(*a)); a->cse = type; a->ins = ins; a->p1 = p1; a->p2 = p2;
}
static int mock_transmit(sc_card_t *c, sc_apdu_t *a) {
    assert((a->flags & SC_APDU_FLAGS_NO_RETRY_WL) && (a->flags & SC_APDU_FLAGS_NO_GET_RESP));
    int status;
    if (a->ins == 0x82) {
        auths++;
        assert(a->p1 == 1 && a->p2 == 0x81 && a->datalen == 8 && a->lc == 8);
        // Independent known raw-PIN formula (fixture string only).
        uint8_t key[24] = {0}, iv[8] = {0}, challenge[8], expected[8]; size_t length = 0;
        CC_SHA1("fixture", 7, key); key[23] = 7; memset(challenge, 0x31, 8);
        assert(CCCrypt(kCCEncrypt,kCCAlgorithm3DES,0,key,24,iv,challenge,8,expected,8,&length) == kCCSuccess);
        assert(length == 8 && !memcmp(a->data, expected, 8));
        status = auth_status;
    } else if (a->ins == 0x22) {
        mses++;
        uint8_t expected[] = {0x80,1,0x84,0x81,2,expected_key >> 8,expected_key & 255};
        assert(a->p1 == 0x41 && a->p2 == 0xb8 && a->datalen == 7 && !memcmp(a->data,expected,7));
        status = mse_status;
    } else {
        assert(a->ins == 0x2a); psos++;
        assert(a->p1 == 0x80 && a->p2 == 0x86 && a->cse == (SC_APDU_CASE_4_EXT));
        assert(a->lc == 256 && a->datalen == 256 && a->le == 256 && a->resplen >= 256);
        memset(a->resp, 0x5a, 256); a->resplen = 256; status = pso_status;
    }
    a->sw1 = status >> 8; a->sw2 = status & 255;
    return transport_result;
}

static fca_runtime runtime = {.get_reader=mock_reader, .connect=mock_connect,
    .lock=mock_lock, .reset=mock_reset, .unlock=mock_unlock, .disconnect=mock_disconnect,
    .format_path=mock_path, .select_file=mock_select, .challenge=mock_challenge,
    .format_apdu=mock_format, .transmit=mock_transmit};
static void fixture(const uint8_t *atr) {
    memset(&device,0,sizeof(device)); memset(&driver,0,sizeof(driver));
    driver.short_name="epass2003"; device.driver=&driver;
    device.sm_ctx.ops.open=mock_refresh;
    device.atr.len=sizeof(efy_atr); memcpy(device.atr.value,atr,sizeof(efy_atr));
    locks=resets=refreshes=unlocks=disconnects=auths=mses=psos=0;
    transport_result=reset_result=refresh_result=0; auth_status=mse_status=pso_status=0x9000;
}
static fca_card *open_efy(void) {
    fca_card *card=NULL;
    assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_EFY,&card)==0 && card);
    assert(resets==1 && locks==1 && refreshes==1);
    return card;
}
static int login(fca_card *c, uint16_t *sw) { return fca_login(c,(const uint8_t *)"fixture",7,sw); }
static int sign(fca_card *c, uint16_t *sw) {
    uint8_t block[256]={0,1}, signature[256]; size_t written=0;
    int rv=fca_sign(c,expected_key,block,256,signature,256,&written,sw);
    if (!rv) assert(written==256 && signature[0]==0x5a);
    return rv;
}
int main(void) {
    fca_card *card=NULL; uint16_t sw=0;
    fixture(efy_atr);
    assert(fca_card_open(&runtime,"fixture",&card)==FCA_INVALID && !card && !locks);
    fixture(fastca_atr);
    assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_EFY,&card)==FCA_INVALID && !card && !locks);
    assert(fca_card_open(&runtime,"fixture",&card)==0 && !resets); fca_card_close(card);
    for (size_t i=0;i<sizeof(efy_atr);i++) {
        fixture(efy_atr); device.atr.value[i]^=1;
        assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_EFY,&card)==FCA_INVALID && !card && !locks);
    }
    fixture(efy_atr); driver.short_name="other";
    assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_EFY,&card)==FCA_INVALID && !card);
    fixture(efy_atr); reset_result=-77;
    assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_EFY,&card)==-77 && !card);
    assert(resets==1 && unlocks==1 && disconnects==1 && !auths);
    fixture(efy_atr); refresh_result=-78;
    assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_EFY,&card)==-78 && !card);
    assert(resets==1 && refreshes==1 && unlocks==1 && disconnects==1 && !auths);

    const int statuses[]={0x63c2,0x6983,0x63c0,0x6985,0x9000};
    const int results[]={FCA_PIN_INCORRECT,FCA_PIN_LOCKED,FCA_PIN_LOCKED,FCA_STATUS,-88};
    for (size_t i=0;i<5;i++) {
        fixture(efy_atr); card=open_efy(); auth_status=statuses[i]; if (i==4) transport_result=-88;
        assert(login(card,&sw)==results[i]);
        assert(login(card,&sw)==FCA_INVALID && auths==1);
        assert(sign(card,&sw)==FCA_INVALID && !mses && !psos);
        fca_card_close(card); assert(resets==2 && unlocks==1 && disconnects==1);
    }
    fixture(efy_atr); card=open_efy();
    assert(sign(card,&sw)==FCA_INVALID && !mses);
    assert(fca_login(card,(const uint8_t *)"\x01",1,&sw)==FCA_INVALID && !auths);
    assert(login(card,&sw)==0 && sw==0x9000);
    uint8_t output[8]; size_t length=0;
    assert(fca_read_file(card,0xa020,output,8,&length)==FCA_INVALID);
    assert(sign(card,&sw)==0 && auths==1 && mses==1 && psos==1);
    assert(sign(card,&sw)==FCA_INVALID && psos==1);
    fca_card_close(card); assert(resets==2 && unlocks==1 && disconnects==1);
    for (int fail=0;fail<3;fail++) {
        fixture(efy_atr); card=open_efy(); assert(login(card,&sw)==0);
        if (fail==0) mse_status=0x6a80; else if (fail==1) pso_status=0x6985; else transport_result=-99;
        assert(sign(card,&sw)<0); assert(sign(card,&sw)==FCA_INVALID);
        assert(mses==1 && psos==(fail==1 ? 1 : 0));
        fca_card_close(card); assert(resets==2 && disconnects==1);
    }
    const uint8_t *fastca_profiles[] = {fastca_atr, fastca_atr0631};
    for (size_t p=0;p<2;p++) {
        fixture(fastca_profiles[p]); card=NULL;
        assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_FASTCA,&card)==0 && card);
        fca_card_close(card); assert(!auths && !mses && !psos);
        for (size_t i=0;i<sizeof(fastca_atr);i++) {
            fixture(fastca_profiles[p]); device.atr.value[i]^=1; card=NULL;
            assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_FASTCA,&card)==FCA_INVALID && !card);
            assert(!auths && !mses && !psos && !locks);
        }
    }
    for (size_t i=12;i<=14;i++) {
        for (unsigned value=0;value<256;value++) {
            fixture(fastca_atr); device.atr.value[i]=(uint8_t)value;
            device.atr.value[22]=0;
            for (size_t n=1;n<22;n++) device.atr.value[22]^=device.atr.value[n];
            assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_FASTCA,&card)==0 && card);
            if (memcmp(device.atr.value,fastca_atr,23) && memcmp(device.atr.value,fastca_atr0631,23)) {
                assert(login(card,&sw)==FCA_DISCOVERY_ONLY && !auths && !card->attempted);
            }
            fca_card_close(card);
        }
    }
    fixture(fastca_atr);
    assert(fca_card_open_profile(&runtime,"fixture",FCA_PROFILE_DISCOVERY,&card)==0 && card);
    assert(login(card,&sw)==FCA_DISCOVERY_ONLY && !auths && !card->attempted);
    fca_card_close(card);
    puts("PASS native ESPK mock transport: family discovery, independent PIN guard, reset, no retries, MSE/PSO framing, cleanup");
    return 0;
}
