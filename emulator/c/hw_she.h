#include <stdint.h> // for uint32_t, etc.
#include <stdlib.h> // for size_t
#include <stdbool.h> // for bool, true, false

// From TCG Algorithm Registry
#define TPM_ALG_ERROR 0
#define TPM_ALG_CMAC  0x3F

// note: mars.c contains defs for PROFILE_COUNT_REG and PROFILE_LEN_XKDF

#define PROFILE_COUNT_PCR 4
#define PROFILE_COUNT_TSR 0
#define PROFILE_LEN_DIGEST 16
#define PROFILE_LEN_SIGN 16
#define PROFILE_LEN_KSYM 16
#define PROFILE_LEN_KPUB 0
#define PROFILE_LEN_KPRV 0
#define PROFILE_ALG_HASH 0x84 // TODO - not approved
#define PROFILE_ALG_SIGN TPM_ALG_CMAC
#define PROFILE_ALG_SKDF 0x86 // TODO - not approved
#define PROFILE_ALG_AKDF TPM_ALG_ERROR

// hctx is Hash ConTeXt
typedef struct {
    size_t   total;          // total # of source bytes hashed
    uint16_t len;            // number of bytes in partial block
    uint8_t  blk[PROFILE_LEN_DIGEST];   // partial block
    uint8_t  H[PROFILE_LEN_DIGEST];     // running digest
} she_hctx_t;

typedef she_hctx_t profile_shc_t;   // for MARS' Sequenced Hash Context
