#include <openssl/evp.h>
#include <stdbool.h>

typedef struct {
    EVP_MD_CTX *mdctx;
} profile_shc_t;

// From TCG Algorithm Registry
#define TPM_ALG_ERROR 0
#define TPM_ALG_HMAC 5
#define TPM_ALG_SHA256 0xb
#define TPM_ALG_KDF1_SP800_108 0x22
#define TPM_ALG_SHA3_256 0x27

#define PROFILE_COUNT_PCR  4
#define PROFILE_COUNT_TSR  0
#define PROFILE_LEN_DIGEST 32 // EVP_MD_size(EVP_sha3_256())
#define PROFILE_LEN_SIGN   PROFILE_LEN_DIGEST
#define PROFILE_LEN_KSYM   PROFILE_LEN_DIGEST
#define PROFILE_LEN_KPUB   0
#define PROFILE_LEN_KPRV   0
#define PROFILE_ALG_HASH   TPM_ALG_SHA3_256
#define PROFILE_ALG_SIGN   0x8a // ?? for KMAC
#define PROFILE_ALG_SKDF   0x8b // ?? for new 800-108 w/ KMAC
#define PROFILE_ALG_AKDF   TPM_ALG_ERROR

