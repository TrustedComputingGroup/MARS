#include <stdint.h> // for uint32_t, etc.
#include <stdlib.h> // for size_t
#include <stdbool.h> // for bool, true, false
#include "../ascon/inc/ascon.h"

// From TCG Algorithm Registry
#define TPM_ALG_ERROR 0

// note: mars.c contains defs for PROFILE_COUNT_REG and PROFILE_LEN_XKDF

#define PROFILE_COUNT_PCR  4
#define PROFILE_COUNT_TSR  0
#define PROFILE_LEN_DIGEST ASCON_HASH_DIGEST_LEN
#define PROFILE_LEN_SIGN   ASCON_AEAD_TAG_MIN_SECURE_LEN
#define PROFILE_LEN_KSYM   ASCON_AEAD128_KEY_LEN
#define PROFILE_LEN_KPUB   0
#define PROFILE_LEN_KPRV   0
#define PROFILE_ALG_HASH   0x81
#define PROFILE_ALG_SIGN   0x82 // TODO - not in registry
#define PROFILE_ALG_SKDF   0x83
#define PROFILE_ALG_AKDF   TPM_ALG_ERROR

typedef ascon_hash_ctx_t profile_shc_t;
