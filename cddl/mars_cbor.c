#include <stdint.h>
#include <stdlib.h>
#include "mars_encoder_types.h"
#include "mars_decoder_types.h"
#include "mars_encoder.h"
#include "mars_decoder.h"

#include "mars.h"

// Extract MARS command and parameters from CBOR blob,
// call the selected MARS_ command, and marshall the results
// back over blob.
void dispatcher(void *inblob, size_t inlen, void *outblob, size_t *outlen_p)
{
    struct mars_command command;
    size_t len_out;
    struct mars_response response;
#define RSP(a, b) response._mars_response_rc__##a##_Rsp._##a##_Rsp_##b
#define DATA(a, b) command._mars_command_union__##a._##a##_##b
#define CHOICE(a) response._mars_response_rc_choice = _mars_response_rc__##a##_Rsp

    uint8_t dig[PROFILE_LEN_DIGEST];
    uint8_t key[PROFILE_LEN_KSYM];
    uint8_t sig[PROFILE_LEN_SIGN];
    uint8_t ctx[PROFILE_LEN_DIGEST];

    if (cbor_decode_mars_command(inblob, inlen, &command, &len_out) != ZCBOR_SUCCESS)
        return;

    // Set default response to MARS_RC_FAILURE.
    response._mars_response_rc_choice = _mars_response_rc_union;
    response._mars_response_rc_union_choice = MARS_RC_FAILURE;

    switch (command._mars_command_union_choice)
    {
    case MARS_CC_SelfTest:
        response._mars_response_rc_union_choice = MARS_SelfTest(DATA(SelfTest, full_test));
        break;
    case MARS_CC_CapabilityGet:
    {
        uint16_t cap;
        response._mars_response_rc_union_choice =
            MARS_CapabilityGet(DATA(CapabilityGet, capability_choice),
                               &cap, sizeof(cap));
        if (response._mars_response_rc_union_choice == MARS_RC_SUCCESS)
        {
            RSP(CapabilityGet, capability_data) = cap;
            CHOICE(CapabilityGet);
        }
        break;
    }
    case MARS_CC_SequenceHash:
        response._mars_response_rc_union_choice = MARS_SequenceHash();
        break;
    case MARS_CC_SequenceUpdate:
    {
        size_t outlen = 0;
        response._mars_response_rc_union_choice = MARS_SequenceUpdate(
            DATA(SequenceUpdate, _binary_data.value),
            DATA(SequenceUpdate, _binary_data.len), 0, &outlen);
        if (response._mars_response_rc_union_choice == MARS_RC_SUCCESS)
        {
            CHOICE(SequenceUpdate);
            /* no data is present */
            RSP(SequenceUpdate, _binary_data_present) = 0;
        }
        break;
    }
    case MARS_CC_SequenceComplete:
        break;

    case MARS_CC_PcrExtend:
        break;

    case MARS_CC_RegRead:
        // zcbor_bstr_encode_ptr
        break;
    case MARS_CC_Derive:
        break;
    case MARS_CC_DpDerive:
        break;
    case MARS_CC_PublicRead:
        break;
    case MARS_CC_Quote:
        break;

    case MARS_CC_Sign:
        break;
    case MARS_CC_SignatureVerify:
        break;
    }

    cbor_encode_mars_response(outblob, *outlen_p, &response, outlen_p);
}