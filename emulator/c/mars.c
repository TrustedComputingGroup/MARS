#ifndef PROFILE_LEN_DIGEST
#  error preinclude profile header using: gcc -include profile.h
#endif

// should be defined in the Profile hw_xxxx.h
#define CryptDpInit() CryptSkdf(DP, PS, MARS_LD, MARS_debug ? "dbg" : "prd", 3)

#include <arpa/inet.h> // for htonl()
#include <string.h> // for memset()
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "mars.h"
#include "mars_internal.h"

#define PROFILE_COUNT_REG (PROFILE_COUNT_PCR + PROFILE_COUNT_TSR)

#if defined(PROFILE_LEN_KPRV) && PROFILE_LEN_KPRV
#  if PROFILE_LEN_KPRV <= PROFILE_LEN_KPUB
#     error KPRV too small for KPUB
#  endif
#  define PROFILE_LEN_XKDF PROFILE_LEN_KPRV
#else
#  define PROFILE_LEN_KPUB 0
#  define PROFILE_LEN_KPRV 0
#  define PROFILE_LEN_XKDF PROFILE_LEN_KSYM
#endif

#define MARS_LX 'X'
#define MARS_LD 'D'
#define MARS_LU 'U'
#define MARS_LR 'R'

// MARS Device state ------------------------------------------

static uint8_t PS[PROFILE_LEN_KSYM] =
#if PROFILE_LEN_KSYM == 16
    "A 16-byte secret";
#elif PROFILE_LEN_KSYM == 32
    "Here are thirty two secret bytes";
#else
#   error need another key
#endif

static uint8_t DP[PROFILE_LEN_KSYM];
static uint8_t REG[PROFILE_COUNT_REG][PROFILE_LEN_DIGEST];

bool failure = false;
bool MARS_debug = true;
static profile_shc_t shc;   // Sequenced Hash Context
// ---------------------------------------------------------

#define CHECKRC if (rc) { printf("rc=%d, line=%d\n", rc, __LINE__); exit(rc); }

static void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

void MARS_dump(void)
{
uint16_t i;
    printf("--------------------------\n");
    printf("MARS PRIVATE CONFIGURATION\n");
    hexout(" PS", PS, sizeof(PS));
    hexout(" DP", DP, sizeof(DP));
    for (i=0; i<PROFILE_COUNT_REG; i++)
        hexout("REG", REG[i], PROFILE_LEN_DIGEST);
    printf("--------------------------\n");
}

void CryptSnapshot(void * out, uint32_t regSelect, const void * ctx, uint16_t ctxlen)
{
profile_shc_t shc;
uint16_t i = 0;

    uint32_t be_regsel = htonl(regSelect);

    // any TSRs in regSelect should be updated here
    // TSRs are in REG[PROFILE_COUNT_PCR ... PROFILE_COUNT_REG-1]

    CryptHashInit(&shc);
    CryptHashUpdate(&shc, (void *)&be_regsel, 4);

    do if (regSelect & 1)
        CryptHashUpdate(&shc, REG[i], PROFILE_LEN_DIGEST);
    while (++i<PROFILE_COUNT_REG && (regSelect>>=1));

    CryptHashUpdate(&shc, ctx, ctxlen);
    CryptHashFinal(&shc, out);
}

MARS_RC MARS_SelfTest (
    bool fullTest)
{
    failure = failure || !CryptSelfTest(fullTest);
    return failure ? MARS_RC_FAILURE : MARS_RC_SUCCESS;
}

MARS_RC MARS_CapabilityGet (
    uint16_t pt,
    void * cap,
    uint16_t caplen)
{
    if (failure)   return MARS_RC_FAILURE;
    if (!cap || caplen != sizeof(uint16_t))
        return MARS_RC_BUFFER;
    switch (pt)
        {
        case MARS_PT_PCR:
        *(uint16_t *)cap = PROFILE_COUNT_PCR;
        break;

        case MARS_PT_TSR:
        *(uint16_t *)cap = PROFILE_COUNT_TSR;
        break;

        case MARS_PT_LEN_DIGEST:
        *(uint16_t *)cap = PROFILE_LEN_DIGEST;
        break;

        case MARS_PT_LEN_SIGN:
        *(uint16_t *)cap = PROFILE_LEN_SIGN;
        break;

        case MARS_PT_LEN_KSYM:
        *(uint16_t *)cap = PROFILE_LEN_KSYM;
        break;

        case MARS_PT_LEN_KPUB:
        *(uint16_t *)cap = PROFILE_LEN_KPUB;
        break;

        case MARS_PT_LEN_KPRV:
        *(uint16_t *)cap = PROFILE_LEN_KPRV;
        break;

        case MARS_PT_ALG_HASH:
        *(uint16_t *)cap = PROFILE_ALG_HASH;
        break;

        case MARS_PT_ALG_SIGN:
        *(uint16_t *)cap = PROFILE_ALG_SIGN;
        break;

        case MARS_PT_ALG_SKDF:
        *(uint16_t *)cap = PROFILE_ALG_SKDF;
        break;

        case MARS_PT_ALG_AKDF:
        *(uint16_t *)cap = PROFILE_ALG_AKDF;
        break;

        default:
        return MARS_RC_VALUE;
        }
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_SequenceHash ()
{
    if (failure) return MARS_RC_FAILURE;
    CryptHashInit(&shc);
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_SequenceUpdate(
    const void * in,
    size_t inlen,
    void * out,
    size_t * outlen)
{
    if (failure) return MARS_RC_FAILURE;
    if ((inlen && !in) || !outlen)
        return MARS_RC_BUFFER;
    // assumes sequence is hash
    // need to check *outlen long enough for other sequences
//  if (!hash_sequence_in_progress)
//      return MARS_RC_SEQ;
    CryptHashUpdate(&shc, in, inlen);
    *outlen = 0;
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_SequenceComplete(
    void * out,
    size_t * outlen)
{
    if (failure) return MARS_RC_FAILURE;
    // assumes sequence is hash
    if (!out || !outlen || *outlen < PROFILE_LEN_DIGEST)
        return MARS_RC_BUFFER;
//  if (!hash_sequence_in_progress)
//      return MARS_RC_SEQ;
    CryptHashFinal(&shc, out);
    *outlen = PROFILE_LEN_DIGEST;
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_PcrExtend (
    uint16_t pcrIndex,
    const void * dig)
{
    if (failure) return MARS_RC_FAILURE;
    if (pcrIndex >= PROFILE_COUNT_PCR)
        return MARS_RC_REG;
    if (!dig)
        return MARS_RC_BUFFER;

    CryptHashInit(&shc);
    CryptHashUpdate(&shc, REG[pcrIndex], PROFILE_LEN_DIGEST);
    CryptHashUpdate(&shc, dig, PROFILE_LEN_DIGEST);
    CryptHashFinal(&shc, REG[pcrIndex]);
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_RegRead (
    uint16_t regIndex,
    void * dig)
{
    if (failure) return MARS_RC_FAILURE;
    if (regIndex >= PROFILE_COUNT_REG)
        return MARS_RC_REG;
    if (!dig)
        return MARS_RC_BUFFER;

    memcpy(dig, REG[regIndex], PROFILE_LEN_DIGEST);
    return MARS_RC_SUCCESS;
}

// KEY MANAGEMENT

MARS_RC MARS_Derive (
    uint32_t regSelect,
    const void * ctx,
    uint16_t ctxlen,
    void * out)
{
    if (failure) return MARS_RC_FAILURE;
    if (regSelect >> PROFILE_COUNT_REG)
        return MARS_RC_REG;
    if (!out || (ctxlen && !ctx))
        return MARS_RC_BUFFER;

    uint8_t snapshot[PROFILE_LEN_DIGEST];
    CryptSnapshot(snapshot, regSelect, ctx, ctxlen);
    CryptSkdf(out, DP, MARS_LX, snapshot, sizeof(snapshot));
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_DpDerive (
    uint32_t regSelect,
    const void * ctx,
    uint16_t ctxlen)
{
    if (failure) return MARS_RC_FAILURE;
    if (regSelect >> PROFILE_COUNT_REG)
        return MARS_RC_REG;
    if (ctxlen && !ctx)
        return MARS_RC_BUFFER;

    if (ctx)
        {
        uint8_t snapshot[PROFILE_LEN_DIGEST];
        CryptSnapshot(snapshot, regSelect, ctx, ctxlen);
        CryptSkdf(DP, DP, MARS_LD, snapshot, sizeof(snapshot));
        }
    else
        CryptDpInit();

    return MARS_RC_SUCCESS;
}

MARS_RC MARS_PublicRead (
    bool restricted,
    const void * ctx,
    uint16_t ctxlen,
    void * pub)
{
#if defined(PROFILE_LEN_KPRV) && PROFILE_LEN_KPRV > PROFILE_LEN_KPUB
    if (ctxlen && !ctx)
        return MARS_RC_BUFFER;
    uint8_t key[PROFILE_LEN_KPRV];
    uint8_t label = restricted ? MARS_LR : MARS_LU;
    CryptAkdf(key, DP, label, ctx, ctxlen);
    profile_copy_pub(pub, key);  // implementation dependent
    return MARS_RC_SUCCESS;
#else
    return MARS_RC_COMMAND;
#endif
}

MARS_RC MARS_Quote (
    uint32_t regSelect,
    const void * nonce,
    uint16_t nlen,
    const void * ctx,
    uint16_t ctxlen,
    void * sig)
{
    if (failure) return MARS_RC_FAILURE;
    if (regSelect >> PROFILE_COUNT_REG)
        return MARS_RC_REG;
    if ((nlen && !nonce) || (ctxlen && !ctx) || !sig)
        return MARS_RC_BUFFER;

    uint8_t AK[PROFILE_LEN_XKDF];
    uint8_t snapshot[PROFILE_LEN_DIGEST];
    CryptSnapshot(snapshot, regSelect, nonce, nlen);
    CryptXkdf(AK, DP, MARS_LR, ctx, ctxlen);
    CryptSign(sig, AK, snapshot);

    return MARS_RC_SUCCESS;
}

MARS_RC MARS_Sign (
    const void * ctx,
    uint16_t ctxlen,
    const void * dig,
    void * sig)
{
    if (failure) return MARS_RC_FAILURE;
    if (!(dig && sig) || (ctxlen && !ctx))
        return MARS_RC_BUFFER;

    uint8_t key[PROFILE_LEN_XKDF];
    // MARS_LU forces CryptXkdf to derive an unrestricted key
    CryptXkdf(key, DP, MARS_LU, ctx, ctxlen);
    CryptSign(sig, key, dig);
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_SignatureVerify (
    bool restricted,
    const void * ctx,
    uint16_t ctxlen,
    const void * dig,
    const void * sig,
    bool * result)
{
    if (failure) return MARS_RC_FAILURE;
    if (!(dig && sig && result) || (ctxlen && !ctx))
        return MARS_RC_BUFFER;

    uint8_t key[PROFILE_LEN_XKDF];
    uint8_t label = restricted ? MARS_LR : MARS_LU;
    CryptXkdf(key, DP, label, ctx, ctxlen);
    *result = CryptVerify(key, dig, sig);
    return MARS_RC_SUCCESS;
}

// _MARS_Init is supposed to be a signal to hardware.
// It is not part of the API, but is emulated here.
// Invoked by dlopen()
void __attribute__((constructor)) _MARS_Init()
{
    hexout("PS", PS, sizeof(PS));
    memset(REG, 0, sizeof(REG));
    // Init TSR to profile-specified values
    failure = false;

    CryptSelfTest(false);
    CryptDpInit();
    hexout("DP", DP, sizeof(DP));
}
