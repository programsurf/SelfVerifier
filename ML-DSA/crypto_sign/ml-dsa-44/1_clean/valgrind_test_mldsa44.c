#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "api.h"

#define MLEN 32

int test_keygen() {
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

    printf("Starting keygen...\n");
    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    printf("Keygen completed with return code: %d\n", ret);

    return ret;
}

int test_sign() {
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t msg[MLEN];
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES + MLEN];
    size_t siglen;

    // Generate keypair first
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);

    // Create test message
    for(int i = 0; i < MLEN; i++) {
        msg[i] = i;
    }

    printf("Starting sign...\n");
    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign(sig, &siglen, msg, MLEN, sk);
    printf("Sign completed with return code: %d, signature length: %zu\n", ret, siglen);

    return ret;
}

int test_verify() {
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t msg[MLEN];
    uint8_t msg_verify[MLEN];
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES + MLEN];
    size_t siglen;
    size_t msglen_verify;

    // Generate keypair
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);

    // Create and sign message
    for(int i = 0; i < MLEN; i++) {
        msg[i] = i;
    }
    PQCLEAN_MLDSA44_CLEAN_crypto_sign(sig, &siglen, msg, MLEN, sk);

    printf("Starting verify...\n");
    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(msg_verify, &msglen_verify, sig, siglen, pk);
    printf("Verify completed with return code: %d\n", ret);

    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <keygen|sign|verify>\n", argv[0]);
        return 1;
    }

    int result = 0;

    if (strcmp(argv[1], "keygen") == 0) {
        result = test_keygen();
    } else if (strcmp(argv[1], "sign") == 0) {
        result = test_sign();
    } else if (strcmp(argv[1], "verify") == 0) {
        result = test_verify();
    } else {
        printf("Unknown operation: %s\n", argv[1]);
        printf("Usage: %s <keygen|sign|verify>\n", argv[0]);
        return 1;
    }

    return result;
}