#include <stdarg.h>
#include "../tinycbor/src/cbor.h"

// cbor_vget() pulls multiple parameters from CBOR iterator
// 'b' is boolean
// 'w' is word (32-bit) integer
// 'h' is half word (16-bit) integer
// 'x' is byte string taking 2 parameters, buffer pointer and length pointer
// 'X' is byte string taking 2 parameters, buffer pointer and mandatory length
CborError cbor_vget(CborValue *it, const char *ptype, ...)
{
    CborError err = CborNoError;
    va_list ap;
    size_t *zp, z2;
    unsigned int z;
    uint64_t i64;
    void *p;
#define va_get(Z) Z = va_arg(ap, typeof(Z))

    va_start(ap, ptype);
    while (!err && *ptype)      // walk through parameter types
        switch (*ptype++) {

        case 'b':               // boolean parameter
            va_get(p);
            err = cbor_value_is_boolean(it)
                ? cbor_value_get_boolean(it, p), cbor_value_advance_fixed(it)
                : CborUnknownError;
            break;

        case 'w':               // Word = uint32_t
            va_get(p);
            err = cbor_value_is_unsigned_integer(it)
                ? cbor_value_get_uint64(it, &i64),
                  cbor_value_advance_fixed(it)
                : CborUnknownError;
            if (!err)
                *(uint32_t *)p = i64; // truncate to 32 bits, TODO check if (i64>>32)
            break;

        case 'h':               // Half word = uint16_t
            va_get(p);
            err = cbor_value_is_unsigned_integer(it)
                ? cbor_value_get_uint64(it, &i64),
                  cbor_value_advance_fixed(it)
                : CborUnknownError;
            if (!err)
                *(uint16_t *)p = i64; // truncate to 16 bits, TODO check if (i64>>16)
            break;

        case 'x':               // byte string parameter
            va_get(p);          // pointer to buffer
            va_get(zp);         // pointer to length, in/out
            err = cbor_value_is_byte_string(it)
                ? cbor_value_copy_byte_string (it, p, zp, it)
                : CborUnknownError;
            if (err)
                *zp = 0;
            break;

        case 'X':               // byte string parameter
            va_get(p);          // pointer to buffer
            va_get(z);          // mandatory length
            err = (cbor_value_is_byte_string(it)
                    && (cbor_value_calculate_string_length (it, &z2), z==z2))
                ? cbor_value_copy_byte_string (it, p, &z2, it)
                : CborUnknownError;
            if (err)
                *zp = 0;
            break;

        default:
            err = CborUnknownError;
        }
    va_end(ap);
    if (err) printf("VGET err %d on '%c'\n", err, ptype[-1]);
    return err;
}

