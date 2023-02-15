#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "hw_sha2.h"
#include "mars_internal.h"

static void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}


bool CryptVerify(const void *key, const void *dig, const void *sig)
{
uint8_t mac[PROFILE_LEN_SIGN];
    CryptSign(mac, key, dig);
    return memcmp(mac, sig, PROFILE_LEN_SIGN) == 0;
}

// TPM version of 800-108 is in CryptHash.c, CryptKDFa()
// according to part 1 of the TPM Specification.
// Both counter "i" and bit length "L" are encoded in 4 big endian bytes.
// TPM uses 8192 (0x2000) for L.
// Here, i is only 1.

// from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-draft.pdf

// OpenSSL's KBKDF supports 800-108 Counter mode.
// However, the value for L is taken from the parent key size.
// No way to specify a different L (8192).

void CryptSkdf(void * child, const void * parent, char label, const void * ctx, uint16_t ctxlen)
{
#warning "using deprecated HMAC functions"
    HMAC_CTX *hctx = HMAC_CTX_new();
    //  HMAC (key, [i]2 || Label || 0x00 || Context || [L]2)
    HMAC_Init_ex(hctx, parent, PROFILE_LEN_KSYM, EVP_sha256(), NULL);
    HMAC_Update(hctx, "\x00\x00\x00\x01", 4);  // i = 1
    HMAC_Update(hctx, &label, 1);              // Label
    HMAC_Update(hctx, "", 1);                  // 0x00
    HMAC_Update(hctx, ctx, ctxlen);            // Context
    HMAC_Update(hctx, "\x00\x00\x20\x00", 4);  // L = 0x2000 = 8192
    HMAC_Final(hctx, child, 0);
    HMAC_CTX_free(hctx);
    hexout("Skdf", child, PROFILE_LEN_KSYM);
}

void CryptXkdf(void *key, const void *parent, char label, const void *ctx, uint16_t ctxlen)
{
    CryptSkdf(key, parent, label, ctx, ctxlen);
}

void CryptHashInit(profile_shc_t *hctx)
{
    SHA256_Init(hctx);
}

void CryptHashUpdate(profile_shc_t *hctx, const void *msg, size_t n)
{
    SHA256_Update(hctx, msg, n);
}

void CryptHashFinal(profile_shc_t *hctx, void *dig)
{
    SHA256_Final(dig, hctx);
}

void CryptSign(void *out, const void *key, const void *digest)
{
    HMAC(EVP_sha256(), key, PROFILE_LEN_KSYM, digest, PROFILE_LEN_DIGEST, out, 0);
}

bool CryptSelfTest(bool fullTest)
{
profile_shc_t hctx;
uint8_t dig[PROFILE_LEN_DIGEST];
uint8_t exp[PROFILE_LEN_DIGEST] = "\x32\x9b\x3d\xcf\x79\x8a\x73\xe8\xb8\x7f\x48\x6b\xcd\xaa\x8e\x20\x70\xf6\x43\x7f\x1d\x47\x0f\xec\x6e\x17\x4e\xf8\xec\x7b\x15\x54";
    CryptHashInit(&hctx);
    CryptHashUpdate(&hctx, "PYTHON", 6);
    CryptHashFinal(&hctx, dig);
    return memcmp(dig, exp, PROFILE_LEN_DIGEST) == 0;
}
