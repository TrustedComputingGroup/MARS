#include <string.h> // for memset()
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>

#include "api.h"
#include "../tinycbor/src/cbor.h"

extern CborError cbor_vget(CborValue *it, const char *ptype, ...);
// MARS state ------------------------------------------------
// Initialized by _MARS_Init()

static struct {
    pthread_mutex_t mx; // mutex for Lock and Unlock
    pthread_t tid;      // thread ID of mx lock owner; 0 if unlocked
    uint16_t diglen, siglen, keylen;
    void * txrx_ctx;
} mz;

// ---------------------------------------------------------

static void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

// determine if already locked by the caller
static bool mz_locked()
{
    return mz.tid == pthread_self();
}

MARS_RC MARS_Lock()
{
    if (mz_locked() || pthread_mutex_lock(&mz.mx))
        return MARS_RC_LOCK;
    mz.tid = pthread_self();
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_Unlock()
{
    if (!mz_locked()) return MARS_RC_LOCK;
    mz.tid = 0;
    return pthread_mutex_unlock(&mz.mx) ? MARS_RC_LOCK : MARS_RC_SUCCESS;
}

// mz_xqt - Execute a MARS Command and write the reply
// Writes command parameters to CBOR cmdblob,
// sends cmdblob to dispatcher,
// receives response in rspblob,
// parses rspblob to pass results to caller.
// ptype characters indicate the type of parameter to process
// 'b' is boolean
// 'w' is word (32-bit) integer
// 'h' is half word (16-bit) integer
// 'x' is byte string taking 2 parameters, buffer pointer and length pointer
// 1st ptype char is return type, or '-' for no returned data
//      can use captial 'X' for buffer pointer and mandatory length
//      1st char is processed by cbor_vget()
// 2nd ptype char must be 'h' for the Command Code
// remaining chars specify parameter types for the MARS Command
// After the ptype are the matching parameters
// The last parameter is the address(es) to hold the return value(s).
MARS_RC mz_xqt(const char *ptype, ...)
{
    MARS_RC rc;
    char rettype = *ptype++;
    va_list ap;
    uint32_t i;
    uint8_t *xp; // byte string pointer
    CborError err = CborNoError;
    uint8_t cmdblob[1024];
#define rspblob cmdblob
    size_t cmdlen, rsplen;

#define va_get(Z) Z = va_arg(ap, typeof(Z))

    if (!mz_locked()) return MARS_RC_LOCK;

    CborEncoder in, out, array;

    cbor_encoder_init(&out, cmdblob, sizeof(cmdblob), 0);
    for (i=0; ptype[i]; ++i) ;
    cbor_encoder_create_array(&out, &array, i); // CborIndefiniteLength);

    va_start(ap, ptype);
    while (!err && *ptype)      // walk through parameter types
        switch (*ptype++) {

        case 'b':               // boolean parameter
            va_get(i);          // "..." passes boolean as int
            err = cbor_encode_boolean(&array, i);
            break;

        case 'h':               // half-word int parameter
            va_get(i);
            err = cbor_encode_uint(&array, (uint16_t)i);
            break;

        case 'w':               // word int parameter
            va_get(i);
            err = cbor_encode_uint(&array, (uint32_t)i);
            break;

        case 'x':               // byte string parameter
            va_get(xp);
            va_get(i);
            err = xp
                ? cbor_encode_byte_string(&array, xp, i)
                : cbor_encode_null(&array);
            break;

        default:
            err = CborUnknownError;
        }
    if (err) {
        printf("VPUT err %d\n", err);
        cmdlen = 0;
        rc = MARS_RC_IO;
    } else {
        cbor_encoder_close_container(&out, &array);
        cmdlen = cbor_encoder_get_buffer_size(&out, cmdblob);

        // pretty print the command
        CborParser parser;
        CborValue it;
        cbor_parser_init(cmdblob, cmdlen, 0, &parser, &it);
        printf(" Command: ");
        cbor_value_to_pretty_advance(stdout, &it);
        printf("\n");

        rsplen = sizeof(rspblob);
        // dispatcher(cmdblob, cmdlen, rspblob, &rsplen);
        rsplen = MARS_Transport(mz.txrx_ctx, cmdblob, cmdlen, rspblob, rsplen);

        // pretty print the response
        cbor_parser_init(rspblob, rsplen, 0, &parser, &it);
        printf("Response: ");
        cbor_value_to_pretty_advance(stdout, &it);
        printf("\n");

        // get the Response Code and result, if any
        if (cbor_parser_init(rspblob, rsplen, 0, &parser, &it)
                || cbor_value_enter_container(&it, &it)
                || cbor_vget(&it, "h", &rc))
            rc = MARS_RC_IO;
        else if (!rc && (rettype != '-')) {
            void *p1, *p2;
            char f[] = "-";
            f[0] = rettype;
            va_get(p1);
            va_get(p2); // in case retype is 'x'
            if (cbor_vget(&it, f, p1, p2))
                rc = MARS_RC_IO;
        }
        if (!cbor_value_at_end(&it))
            rc = MARS_RC_IO;
    }

    va_end(ap);
    return rc;
}

MARS_RC MARS_SelfTest (bool fullTest)
    { return mz_xqt("-hb", MARS_CC_SelfTest, fullTest); }

MARS_RC MARS_CapabilityGet ( uint16_t pt, void * cap, uint16_t caplen)
    { return mz_xqt("hhh", MARS_CC_CapabilityGet, pt, cap); }

MARS_RC MARS_SequenceHash ()
{ return mz_xqt("-h", MARS_CC_SequenceHash); }

MARS_RC MARS_SequenceUpdate( const void * in, size_t inlen, void * out, size_t * outlen_p)
{ return mz_xqt("xhx", MARS_CC_SequenceUpdate, in, inlen, out, outlen_p); }

MARS_RC MARS_SequenceComplete( void * out, size_t * outlen_p)
{ return mz_xqt("xh", MARS_CC_SequenceComplete, out, outlen_p); }

MARS_RC MARS_PcrExtend ( uint16_t pcrIndex, const void * dig)
{ return mz_xqt("-hhx", MARS_CC_PcrExtend, pcrIndex, dig, mz.diglen); }

MARS_RC MARS_RegRead ( uint16_t regIndex, void * dig)
{ return mz_xqt("Xhh", MARS_CC_RegRead, regIndex, dig, mz.diglen); }

MARS_RC MARS_Derive ( uint32_t regSelect, const void * ctx, uint16_t ctxlen, void * out)
{ return mz_xqt("Xhwx", MARS_CC_Derive, regSelect, ctx, ctxlen, out, mz.keylen); }

MARS_RC MARS_DpDerive ( uint32_t regSelect, const void * ctx, uint16_t ctxlen)
{ return mz_xqt("-hwx", MARS_CC_DpDerive, regSelect, ctx, ctxlen); }

MARS_RC MARS_PublicRead ( bool restricted, const void * ctx, uint16_t ctxlen, void * pub)
{
    // return mz_xqt("xhbx", MARS_CC_PublicRead,
    return MARS_RC_COMMAND;
}

MARS_RC MARS_Quote (
    uint32_t regSelect,
    const void * nonce,
    uint16_t nlen,
    const void * ctx,
    uint16_t ctxlen,
    void * sig)
{
    return mz_xqt("Xhwxx", MARS_CC_Quote, regSelect, nonce, nlen, ctx, ctxlen, sig, mz.siglen);
}

MARS_RC MARS_Sign ( const void * ctx, uint16_t ctxlen, const void * dig, void * sig)
{ return mz_xqt("Xhxx", MARS_CC_Sign, ctx, ctxlen, dig, mz.diglen, sig, mz.siglen); }

MARS_RC MARS_SignatureVerify (
    bool restricted,
    const void * ctx,
    uint16_t ctxlen,
    const void * dig,
    const void * sig,
    bool * result)
{
    return mz_xqt("bhbxxx", MARS_CC_SignatureVerify,
        restricted, ctx, ctxlen, dig, mz.diglen, sig, mz.siglen, result);
}


MARS_RC MARS_ApiInit(void *txrx_ctx)
{
bool err;
    printf("MARS_ApiInit\n");
    pthread_mutex_init(&mz.mx, NULL);
    mz.tid = 0;   // thread ID of mx lock owner; 0 if unlocked
    MARS_Lock();
    mz.txrx_ctx = txrx_ctx;
    err =  MARS_CapabilityGet(MARS_PT_LEN_DIGEST, &mz.diglen, sizeof(mz.diglen))
        || MARS_CapabilityGet(MARS_PT_LEN_SIGN, &mz.siglen, sizeof(mz.siglen))
        || MARS_CapabilityGet(MARS_PT_LEN_KSYM, &mz.keylen, sizeof(mz.keylen));
    if (err) {
        mz.tid = -1; // nothing can unlock
        return MARS_RC_IO;
    }
    MARS_Unlock();
    return MARS_RC_SUCCESS;
}

