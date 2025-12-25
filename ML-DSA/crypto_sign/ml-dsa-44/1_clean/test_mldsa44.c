#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"

// Fixed seed for deterministic testing matching our debug tests
static uint32_t rng_seed = 12345;

// Override randombytes for deterministic testing (no prototype needed)
int randombytes(unsigned char *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        rng_seed = rng_seed * 1103515245 + 12345;
        out[i] = (rng_seed >> 16) & 0xff;
    }
    return 0;
}

// Also provide PQCLEAN_randombytes
int PQCLEAN_randombytes(unsigned char *out, size_t outlen) {
    return randombytes(out, outlen);
}

int main() {
    unsigned char pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    unsigned char msg[100] = "test";
    size_t siglen;
    int ret;

    printf("ML-DSA-44 Clean Implementation Test\n");
    printf("====================================\n");

    // Test keygen
    printf("1. Testing keygen...\n");
    ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        printf("   FAILED: keygen returned %d\n", ret);
        return 1;
    }
    printf("   SUCCESS: keypair generated\n");
    printf("   Public key size: %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("   Secret key size: %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);

    // Print first 32 bytes of keys in hex
    printf("   Public key (first 32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", pk[i]);
    }
    printf("\n");

    printf("   Secret key (first 32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sk[i]);
    }
    printf("\n");

    // Test sign
    printf("\n2. Testing sign...\n");
    rng_seed = 54321;  // Reset seed for signing to match our debug tests
    ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign(sig, &siglen, msg, strlen((char*)msg), sk);
    if (ret != 0) {
        printf("   FAILED: sign returned %d\n", ret);
        return 1;
    }
    printf("   SUCCESS: message signed\n");
    printf("   Message: %s\n", msg);
    printf("   Signature length: %zu bytes\n", siglen);

    // Print first 32 bytes of signature in hex
    printf("   Signature (first 32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");

    // Test verify
    printf("\n3. Testing verify...\n");
    // Extract signature from signed message for verification
    unsigned char signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    memcpy(signature, sig, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES);

    // Print first few bytes of signature for debugging
    printf("   Signature bytes (first 100): ");
    for(int i = 0; i < 100; i++) {
        printf("%02x", signature[i]);
        if((i+1) % 16 == 0) printf("\n                                  ");
    }
    printf("\n");

    // Save signature to file for debugging
    FILE *f = fopen("mldsa44_signature.bin", "wb");
    if (f) {
        fwrite(signature, 1, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES, f);
        fclose(f);
        printf("   Signature saved to mldsa44_signature.bin\n");
    }

    ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(signature, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES, msg, strlen((char*)msg), pk);
    if (ret != 0) {
        printf("   FAILED: verify returned %d\n", ret);
        return 1;
    }
    printf("   SUCCESS: signature verified\n");

    // Test with different message to ensure verification fails correctly
    printf("\n4. Testing verify with wrong message...\n");
    unsigned char wrong_msg[] = "wrong message";
    ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(signature, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES, wrong_msg, strlen((char*)wrong_msg), pk);
    if (ret == 0) {
        printf("   FAILED: verification should have failed with wrong message\n");
        return 1;
    }
    printf("   SUCCESS: verification correctly failed with wrong message\n");

    // Test signature-only functions
    printf("\n5. Testing signature-only functions...\n");
    unsigned char sig_only[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t sig_only_len;

    rng_seed = 54321;  // Reset seed again
    ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig_only, &sig_only_len, msg, strlen((char*)msg), sk);
    if (ret != 0) {
        printf("   FAILED: signature-only sign returned %d\n", ret);
        return 1;
    }
    printf("   SUCCESS: signature-only created, length: %zu bytes\n", sig_only_len);

    ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig_only, sig_only_len, msg, strlen((char*)msg), pk);
    if (ret != 0) {
        printf("   FAILED: signature-only verify returned %d\n", ret);
        return 1;
    }
    printf("   SUCCESS: signature-only verified\n");

    printf("\nAll tests passed!\n");
    printf("\nML-DSA-44 Parameter Information:\n");
    printf("================================\n");
    printf("Public key size:  %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("Secret key size:  %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("Signature size:   %d bytes\n", PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES);

    return 0;
}