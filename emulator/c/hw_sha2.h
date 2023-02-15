#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// From TCG Algorithm Registry
#define TPM_ALG_ERROR 0
#define TPM_ALG_HMAC 5
#define TPM_ALG_SHA256 0xb
#define TPM_ALG_KDF1_SP800_108 0x22

#define PROFILE_COUNT_PCR  4
#define PROFILE_COUNT_TSR  0
#define PROFILE_LEN_DIGEST SHA256_DIGEST_LENGTH
#define PROFILE_LEN_SIGN   PROFILE_LEN_DIGEST
#define PROFILE_LEN_KSYM   PROFILE_LEN_DIGEST
#define PROFILE_LEN_KPUB   0
#define PROFILE_LEN_KPRV   0
#define PROFILE_ALG_HASH   TPM_ALG_SHA256
#define PROFILE_ALG_SIGN   TPM_ALG_HMAC
#define PROFILE_ALG_SKDF   TPM_ALG_KDF1_SP800_108
#define PROFILE_ALG_AKDF   TPM_ALG_ERROR

typedef SHA256_CTX profile_shc_t;
