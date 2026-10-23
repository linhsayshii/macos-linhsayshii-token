#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct fca_runtime fca_runtime;
typedef struct fca_card fca_card;
typedef enum { FCA_PROFILE_FASTCA = 0, FCA_PROFILE_EFY = 1, FCA_PROFILE_DISCOVERY = 2 } fca_profile;
enum { FCA_INVALID = -20001, FCA_RUNTIME = -20002, FCA_STATUS = -20003,
       FCA_PIN_INCORRECT = -20004, FCA_PIN_LOCKED = -20005, FCA_DISCOVERY_ONLY = -20006 };

int fca_runtime_open(const char *path, fca_runtime **out, char *error, size_t capacity);
void fca_runtime_close(fca_runtime *runtime);
int fca_card_open(fca_runtime *runtime, const char *reader, fca_card **out);
int fca_card_open_profile(fca_runtime *runtime, const char *reader, fca_profile profile, fca_card **out);
void fca_card_close(fca_card *card);
int fca_read_file(fca_card *card, uint16_t fid, uint8_t *output, size_t capacity, size_t *length);
int fca_login(fca_card *card, const uint8_t *pin, size_t length, uint16_t *status);
int fca_sign(fca_card *card, uint16_t key, const uint8_t *block, size_t length,
             uint8_t *signature, size_t capacity, size_t *written, uint16_t *status);
void fca_wipe(void *bytes, size_t length);
