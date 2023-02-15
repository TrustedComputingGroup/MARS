#include <stdint.h> // for uint32_t, etc.
#include <stdlib.h> // for size_t
#include <stdbool.h> // for bool, true, false

// Prototypes for algorithm-specific cryptographic functions.
void CryptSign(void *out, const void *key, const void *digest);
bool CryptVerify(const void *key, const void *dig, const void *sig);
void CryptSkdf(void *key, const void *parent, char label, const void *ctx, uint16_t ctxlen);
void CryptXkdf(void *key, const void *parent, char label, const void *ctx, uint16_t ctxlen);
bool CryptSelfTest(bool fullTest);

// Prior include HW definition should provide defintion of `profile_shc_t`
void CryptHashInit(profile_shc_t *hctx);
void CryptHashUpdate(profile_shc_t *hctx, const void *msg, size_t n);
void CryptHashFinal(profile_shc_t *hctx, void *dig);
