#ifndef PROFILE_LEN_DIGEST
#  error preinclude profile header using: gcc -include profile.h
#endif

#include <string.h> // for memset()
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "mars.h"
#include "../tinycbor/src/cbor.h"

static void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

extern bool failure;
extern CborError cbor_vget(CborValue *it, const char *ptype, ...);

// Extract MARS command and parameters from CBOR blob,
// call the selected MARS_ command, and marshall the results
// back over blob.
void dispatcher(void *inblob, size_t inlen, void *outblob, size_t *outlen_p)
{
MARS_RC rc = 99;// Response Code
uint8_t rt = 0; // Response Type: 'b'=boolen, 'h'=int, 'x'=bytes, 0=rc only
bool rb;        // Response for rt 'b'
uint16_t rh;    // Response for rt 'h', or length for rt 'x'
uint8_t (*rx)[];// pointer to output bytes for rt 'x'

CborParser parser;
CborValue it;
CborEncoder enc, array;
uint8_t dig[PROFILE_LEN_DIGEST];    // TODO: consolidate the variables to reuse "hw" registers
uint8_t key[PROFILE_LEN_KSYM];
uint8_t sig[PROFILE_LEN_SIGN];
uint8_t ctx[PROFILE_LEN_DIGEST];
uint16_t cmdcode, pt, index;
uint32_t regsel;
size_t xlen1, xlen2;     // general-purpose byte string lengths
bool fullTest;
uint16_t cap;

    // start parsing the input request, and get the cmdcode
    if (cbor_parser_init(inblob, inlen, 0, &parser, &it)
            || cbor_value_enter_container(&it, &it)
            || cbor_vget(&it, "h", &cmdcode))
        rc = MARS_RC_IO;
    else if (failure && (cmdcode != MARS_CC_CapabilityGet))
        rc = MARS_RC_FAILURE;
    else switch (cmdcode) {

        case MARS_CC_SelfTest:
        rc = cbor_vget (&it, "b.", &fullTest)
            ? MARS_RC_IO
            : MARS_SelfTest(fullTest);
        break;

        case MARS_CC_CapabilityGet: // assumes cap is uint16_t or int
        rc = cbor_vget (&it, "h.", &pt)
            ? MARS_RC_IO
            : MARS_CapabilityGet (pt, &rh, sizeof(rh));
        rt = 'h';
        break;

        case MARS_CC_SequenceHash:
        rc = cbor_value_at_end(&it) ? MARS_SequenceHash() : MARS_RC_IO;
        break;

        case MARS_CC_SequenceUpdate:
        // it'd be more efficient to use the bytes from it in-place,
        // instead of copying to buf first
        if ( !cbor_value_is_byte_string(&it)
                || cbor_value_calculate_string_length (&it, &xlen1)
                || (xlen1 > 2048))
            rc = MARS_RC_IO;
        else {
            uint8_t buf[xlen1];
            size_t outlen = 0;
            cbor_value_copy_byte_string (&it, buf, &xlen1, &it);
            rc = cbor_value_at_end(&it)
                ? MARS_SequenceUpdate(buf, xlen1, 0, &outlen)
                : MARS_RC_IO;
            rh = outlen;
        }
        // hash has no output here, but other seqs might
        rt = 'x'; rx = 0;
        break;

        case MARS_CC_SequenceComplete: // TODO: assumes seq is hash
        xlen1 = sizeof(dig);
        rc = cbor_value_at_end(&it)
            ? MARS_SequenceComplete(dig, &xlen1)
            : MARS_RC_IO;
        rt = 'x'; rx = &dig; rh = xlen1;
        break;

        case MARS_CC_PcrExtend: // ( index, dig )
        rc = cbor_vget(&it, "hX.", &index, &dig, PROFILE_LEN_DIGEST)
            ? MARS_RC_IO
            : MARS_PcrExtend(index, dig);
        break;

        case MARS_CC_RegRead: // ( index )
        rc = cbor_vget(&it, "h.", &index)
            ? MARS_RC_IO
            : MARS_RegRead(index, dig);
        rt = 'x'; rx = &dig; rh = PROFILE_LEN_DIGEST;
        break;

        case MARS_CC_Derive: // (regSelect, ctx, ctxlen)
        xlen1 = sizeof(ctx);
        rc = cbor_vget(&it, "wx.", &regsel, &ctx, &xlen1)
            ? MARS_RC_IO
            : MARS_Derive(regsel, ctx, xlen1, key);
        rt = 'x'; rx = &key; rh = PROFILE_LEN_KSYM;
        break;

        case MARS_CC_DpDerive:
        xlen1 = sizeof(ctx);
        rc = cbor_vget(&it, "w", &regsel)
            ? MARS_RC_IO
            : cbor_value_is_null(&it)
                ? cbor_value_advance_fixed(&it) || !cbor_value_at_end(&it)
                    ? MARS_RC_IO
                    : MARS_DpDerive(0, 0, 0)
                : cbor_vget(&it, "x.", &ctx, &xlen1)
                    ? MARS_RC_IO
                    : MARS_DpDerive(regsel, ctx, xlen1);
        break;

        case MARS_CC_PublicRead: // TODO
        rc = MARS_RC_COMMAND;
        break;

        case MARS_CC_Quote: // ( regSelect, nonce, nlen, ctx, ctxlen, sig )
        xlen1 = sizeof(ctx);
        xlen2 = sizeof(dig);  // reuse dig to hold a nonce
        rc = cbor_vget(&it, "wxx.", &regsel, &dig, &xlen2, &ctx, &xlen1)
            ? MARS_RC_IO
            : MARS_Quote(regsel, dig, xlen2, ctx, xlen1, sig);
        rt = 'x'; rx = &sig; rh = PROFILE_LEN_SIGN;
        break;

        case MARS_CC_Sign: // ( ctx, ctxlen, dig, sig )
        xlen1 = sizeof(ctx);
        rc = cbor_vget(&it, "xX.", &ctx, &xlen1, &dig, PROFILE_LEN_DIGEST)
            ? MARS_RC_IO
            : MARS_Sign(ctx, xlen1, dig, sig);
        rt = 'x'; rx = &sig; rh = PROFILE_LEN_SIGN;
        break;

        bool restricted;
        case MARS_CC_SignatureVerify: // ( restricted, ctx, ctxlen, dig, sig )
        xlen1 = sizeof(ctx);
        rc = cbor_vget(&it, "bxXX.", &restricted, &ctx, &xlen1,
                        &dig, PROFILE_LEN_DIGEST, &sig, PROFILE_LEN_SIGN)
            ? MARS_RC_IO
            : MARS_SignatureVerify(restricted, ctx, xlen1, dig, sig, &rb);
        rt = 'b';
        break;

        default:
        rc = MARS_RC_COMMAND;
    }

    if (failure && (cmdcode != MARS_CC_CapabilityGet))
        rc = MARS_RC_FAILURE;

    cbor_encoder_init(&enc, outblob, *outlen_p, 0);
    // if rc is MARS_RC_SUCCESS, and rt is not 0, then there are 2 values to return
    cbor_encoder_create_array(&enc, &array, (!rc && rt) ? 2 : 1); // CborIndefiniteLength);
    cbor_encode_int(&array, rc);
    if (!rc) {
        if (rt == 'x')
            cbor_encode_byte_string(&array, (void *)rx, rh);
        else if (rt == 'h')
            cbor_encode_int(&array, rh);
        else if (rt == 'b')
            cbor_encode_boolean(&array, rb);
    }

    cbor_encoder_close_container(&enc, &array);
    *outlen_p = cbor_encoder_get_buffer_size(&enc, outblob);
}

// Overly simplified server that puts a datagram send/receive
// in front of dispatcher().
// TODO need an exclusive open to prevent interleaving
int main(void)
{
    int sd;
    struct sockaddr_in server_addr, client_addr;
    char blob[2048];
    socklen_t client_struct_length = sizeof(client_addr);
    ssize_t inlen;
    size_t outlen;

    // Create UDP socket:
    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if(sd < 0){
        printf("Error while creating socket\n");
        return -1;
    }

 // Set port and IP:
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0x4d5a); // MZ
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Bind to the set port and IP:
    if(bind(sd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        printf("Couldn't bind to the port\n");
        return -1;
    }
    printf("Listening on port %d...\n", server_addr.sin_port);

    // Receive client's message:
    while ((inlen = recvfrom(sd, blob, sizeof(blob), 0,
         (struct sockaddr*)&client_addr, &client_struct_length)) >= 0) {

//        printf("\nReceived %ld from IP: %s, port: %i\n", inlen,
//               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        hexout("CMD", blob, inlen);
        outlen = sizeof(blob);
        dispatcher(blob, inlen, blob, &outlen);
        hexout("RSP", blob, outlen);

        sendto(sd, blob, outlen, 0,
                (struct sockaddr*)&client_addr, client_struct_length);
    }

    // Close the socket:
    close(sd);

    return 0;
}

