#include <string.h> // for memset()
#include "mars.h"
#include "hw_ascon.h"
#include "mars_internal.h"

#include <stdio.h>
static void hexout(const char *msg, const void *buf, size_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

void CryptSign(void * out, const void * key, const void * digest)
{
    // Could change to use first part of digest as cipher's nonce ??
    // This use of nonce is probably wrong, due to need for some randomness?
    char label = 'Z';
    uint8_t nonce[ASCON_AEAD_NONCE_LEN];
    memset(nonce, 0, sizeof(nonce)); // pad for label
    nonce[0] = label;

    ascon_aead128_encrypt(
	/*CT output buffer*/ 0,
        /*tag*/ out,
	key, nonce,
        /*AD*/ digest,
        /*PT*/ 0,
        /*AD-len*/ PROFILE_LEN_DIGEST,
        /*PT-LEN*/ 0,
        /*tag-len*/ PROFILE_LEN_SIGN);
}

bool CryptVerify(const void *key, const void *dig, const void *sig)
{
char label = 'Z';
uint8_t nonce[ASCON_AEAD_NONCE_LEN];

    // This use of nonce is probably wrong, due to need for some randomness?
    memset(nonce, 0, sizeof(nonce)); // pad for label
    nonce[0] = label;

    // Verify sig via decrypt
    return ascon_aead128_decrypt(
        /* PT, key, nonce */         0, key, (uint8_t *)&nonce,
        /* AD, CT, expected tag */   dig, 0, sig,
        /* lengths of AD, CT, tag */ PROFILE_LEN_DIGEST, 0, PROFILE_LEN_SIGN);
}

// There is no standard KDF using Ascon
// so, fake it
// Create a tag using label as nonce
void CryptSkdf(void * key, const void * parent, char label, const void * ctx, uint16_t ctxlen)
{
// This use of nonce is probably wrong, due to need for some randomness?
uint8_t nonce[ASCON_AEAD_NONCE_LEN];

    memset(nonce, 0, sizeof(nonce)); // pad for label
    nonce[0] = label;

    ascon_aead128_encrypt(
	/*CT output buffer*/ 0,
        /*tag*/ key,
	parent, nonce,
        /*AD*/ ctx,
        /*PT*/ 0,
        /*AD-len*/ ctxlen,
        /*PT-LEN*/ 0,
        /*tag-len*/ PROFILE_LEN_KSYM);
}

void CryptXkdf(void *key, const void *parent, char label, const void *ctx, uint16_t ctxlen)
{
    CryptSkdf(key, parent, label, ctx, ctxlen);
}

// Test vector from ../ascon/tst/vectors/hash.txt
bool CryptSelfTest(bool fullTest)
{
ascon_hash_ctx_t shc;
uint8_t dig[32];
uint8_t exp[32] = { 0x80, 0x13, 0xEA, 0xAA, 0x19, 0x51, 0x58, 0x0A,
                    0x7B, 0xEF, 0x7D, 0x29, 0xBA, 0xC3, 0x23, 0x37,
                    0x7E, 0x64, 0xF2, 0x79, 0xEA, 0x73, 0xE6, 0x88,
                    0x1B, 0x8A, 0xED, 0x69, 0x85, 0x5E, 0xF7, 0x64 };
    CryptHashInit(&shc);
    CryptHashUpdate(&shc, "\x00\x01\x02\x03", 4);
    CryptHashFinal(&shc, dig);
    return memcmp(dig, exp, sizeof(dig)) == 0;
}

void CryptHashInit(profile_shc_t *hctx)
{
    ascon_hash_init(hctx);
}

void CryptHashUpdate(profile_shc_t *hctx, const void *msg, size_t n)
{
    ascon_hash_update(hctx, msg, n);
}

void CryptHashFinal(profile_shc_t *hctx, void *dig)
{
    ascon_hash_final(hctx, dig);
}
