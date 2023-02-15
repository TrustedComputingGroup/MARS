// Requires openssl 3.0

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>   // for memset, memcpy
#include <stdbool.h>

#include "hw_sha3.h"
#include "mars_internal.h"

void CryptHashInit(profile_shc_t *hctx)
{
    hctx->mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hctx->mdctx, EVP_sha3_256(), NULL);
}

void CryptHashUpdate(profile_shc_t *hctx, const void *in, size_t inlen)
{
    EVP_DigestUpdate(hctx->mdctx, in, inlen);
}

void CryptHashFinal(profile_shc_t *hctx, void *out)
{
unsigned int outlen;

    EVP_DigestFinal_ex(hctx->mdctx, out, &outlen);
    EVP_MD_CTX_free(hctx->mdctx);
    hctx->mdctx = 0;
}

static int do_kmac(const void *in, size_t in_len,
                     const void *key, size_t key_len,
                     void *custom, size_t custom_len,
                     int xof_enabled, void *out, int out_len)
{
EVP_MAC_CTX *ctx = NULL;
EVP_MAC *mac = NULL;
OSSL_PARAM params[4], *p = params;
int ret = 0;
size_t l = 0;

  mac = EVP_MAC_fetch(NULL, "KMAC-256", NULL);
  if (mac && (ctx = EVP_MAC_CTX_new(mac), EVP_MAC_free(mac), ctx))
  {
    if (custom && custom_len)
      *p++ = OSSL_PARAM_construct_octet_string(
                          OSSL_MAC_PARAM_CUSTOM, custom, custom_len);

    *p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &xof_enabled);
    *p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_SIZE, &out_len);
    *p = OSSL_PARAM_construct_end();

    ret = EVP_MAC_init(ctx, key, key_len, params)
       && EVP_MAC_update(ctx, in, in_len)
       && EVP_MAC_final(ctx, out, &l, out_len);
  }
  EVP_MAC_CTX_free(ctx);
  return ret;
}

void CryptSign(void *sig, const void *key, const void *dig)
{
    do_kmac(dig, PROFILE_LEN_DIGEST, // in, in_len
                key, PROFILE_LEN_KSYM,    // key, keylen
                0, 0,                     // custom/label, len
                0,                        // xof_enabled
                sig, PROFILE_LEN_SIGN);   // out, outlen
}

bool CryptVerify(const void *key, const void *dig, const void *sig)
{
uint8_t sig2[PROFILE_LEN_SIGN];
    CryptSign(sig2, key, dig);
    return memcmp(sig2, sig, PROFILE_LEN_SIGN) == 0;
}

void CryptSkdf(void * child, const void * parent, char label, const void * ctx, uint16_t ctxlen)
{
    // return KMAC256.new(key=K, data=context, mac_len=L, custom=label).digest()
    do_kmac(ctx, ctxlen,              // in, in_len
            parent, PROFILE_LEN_KSYM, // key, keylen
            &label, 1,                // custom/label, len
            0,                        // xof_enabled
            child, PROFILE_LEN_KSYM); // out, outlen
}

void CryptXkdf(void *key, const void *parent, char label, const void *ctx, uint16_t ctxlen)
{
    CryptSkdf(key, parent, label, ctx, ctxlen);
}

bool CryptSelfTest(bool fullTest)
{
    return true; // TODO
}
