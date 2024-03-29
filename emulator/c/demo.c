// creates values used for Serialization Spec

#include <string.h> // for memset()
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>

#include "api.h"
void MARS_dump(); // for debugging

static void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

#include <sys/socket.h>
#include <arpa/inet.h>

// send blob to MARS server, wait for reply
size_t MARS_Transport(void *ctx, void *txbuf, size_t txlen, void *rxbuf, size_t rxlen)
{
    int sd;
    struct sockaddr_in server_addr;
    char server_message[100], client_message[100];
    int server_struct_length = sizeof(server_addr);
    ssize_t n;

    // Create socket:
    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sd < 0)
        return 0;

    // Set port and IP:
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0x4d5a); // MARS
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Send the message to server:
    if (txlen != sendto(sd, txbuf, txlen, 0,
            (struct sockaddr*)&server_addr, server_struct_length))
        return 0;

    // Receive the server's response:
    if ((n = recvfrom(sd, rxbuf, rxlen, 0,
            (struct sockaddr*)&server_addr, &server_struct_length)) < 0)
        return 0;

    close(sd);
    return n;
}


int main()
{
uint16_t cap;
uint16_t halg;
size_t outlen;
uint16_t diglen, siglen, keylen;
bool flag;

    MARS_ApiInit(0);

    MARS_Lock();
    MARS_SelfTest(true);
    MARS_CapabilityGet(MARS_PT_LEN_DIGEST, &diglen, sizeof(diglen));
    MARS_CapabilityGet(MARS_PT_LEN_SIGN, &siglen, sizeof(siglen));
    MARS_CapabilityGet(MARS_PT_LEN_KSYM, &keylen, sizeof(keylen));
    MARS_CapabilityGet(MARS_PT_ALG_HASH, &halg, sizeof(halg));

    printf("diglen = %d\n", diglen);
    printf("siglen = %d\n", siglen);
    printf("keylen = %d\n", keylen);
    printf("Hash alg = 0x%x\n", halg);

uint8_t dig[diglen];
uint8_t sig[siglen];
uint8_t ssk[keylen];
uint8_t nonce[] = { // should be generated randomly, but this is for repeatable demo
        0x48, 0x98, 0x4c, 0xe5, 0xd3, 0x9b, 0x6e, 0x27, 0x1e, 0x91, 0xbf, 0xaa, 0xda, 0xa1, 0x5b, 0xaf,
        0xcc, 0xfd, 0x32, 0xd8, 0xe1, 0x92, 0xb9, 0xea, 0x5d, 0xfc, 0x6f, 0x0a, 0xa3, 0x99, 0x72, 0x01 };

    char msg1[] = "TCG MARS demo";
    MARS_SequenceHash();
    outlen = 0;
    MARS_SequenceUpdate(msg1, sizeof(msg1)-1, 0, &outlen);
    outlen = sizeof(dig);
    MARS_SequenceComplete(dig, &outlen);

    hexout("dig", dig, outlen);

    MARS_PcrExtend(0, dig);
    MARS_RegRead(0, dig);
    hexout("PCR0", dig, sizeof(dig));

    MARS_Derive(1, "SealedStorageKey", 16, ssk);
    hexout("SSK", ssk, sizeof(ssk));

    MARS_DpDerive(1, "child", 5);
    // MARS_DpDerive(0, 0, 0);

    MARS_PublicRead(true, "AK1", 3, ""); // MARS_RC_COMMAND - not implemented

    MARS_Quote(/*regsel*/1<<0, nonce, sizeof(nonce), /*AK ctx*/"AK1", /*ctxlen*/3, sig);
    hexout("SIG", sig, sizeof(sig));

    // To verify a quote, the snapshot has to be reproduced
    // CryptSnapshot(snapshot, 1<<0, nonce, sizeof(nonce));
    MARS_SequenceHash();
    outlen = 0;
    MARS_SequenceUpdate("\x00\x00\x00\x01", 4, 0, &outlen);
    MARS_SequenceUpdate(dig, sizeof(dig), 0, &outlen);
    MARS_SequenceUpdate(nonce, sizeof(nonce), 0, &outlen);
    outlen = sizeof(dig);
    MARS_SequenceComplete(dig, &outlen);
    hexout("SS", dig, outlen);

    MARS_SignatureVerify(true, /*ctx*/"AK1", /*ctxlen*/3,
        dig, sig, &flag);
    printf("Verify %s\n", flag ? "True" : "False");

    // demo signing the nonce with an unrestricted key
    MARS_Sign("ukey", 4, nonce, sig);
    hexout("Sign", sig, sizeof(sig));

    MARS_Unlock();
}
