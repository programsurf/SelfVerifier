/*
 * ML-DSA-44 Command Line Interface for PyTorch Model Signing
 * ===========================================================
 * Simple CLI tool to sign and verify files using ML-DSA-44
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES 1312
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES 2560
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES 2420

// ML-DSA-44 API functions (from libml-dsa-44_clean.a)
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);

extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *pk);

extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);


int read_file(const char *filename, uint8_t **data, size_t *len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file: %s\n", filename);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);

    *data = malloc(*len);
    if (!*data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(f);
        return -1;
    }

    if (fread(*data, 1, *len, f) != *len) {
        fprintf(stderr, "Error: Failed to read file\n");
        free(*data);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

int write_file(const char *filename, const uint8_t *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file for writing: %s\n", filename);
        return -1;
    }

    if (fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "Error: Failed to write file\n");
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

void print_usage(const char *prog) {
    fprintf(stderr, "ML-DSA-44 CLI Tool\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s sign <secret_key> <message_file> <signature_file>\n", prog);
    fprintf(stderr, "  %s verify <public_key> <message_file> <signature_file>\n", prog);
    fprintf(stderr, "  %s keygen <public_key> <secret_key>\n", prog);
}

int cmd_keygen(const char *pk_file, const char *sk_file) {
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

    printf("Generating ML-DSA-44 keypair...\n");

    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Error: Key generation failed\n");
        return 1;
    }

    if (write_file(pk_file, pk, sizeof(pk)) != 0) {
        return 1;
    }

    if (write_file(sk_file, sk, sizeof(sk)) != 0) {
        return 1;
    }

    printf("Public key saved to: %s\n", pk_file);
    printf("Secret key saved to: %s\n", sk_file);

    return 0;
}

int cmd_sign(const char *sk_file, const char *msg_file, const char *sig_file) {
    uint8_t *sk = NULL;
    uint8_t *msg = NULL;
    size_t sk_len, msg_len;
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t sig_len;

    // Read secret key
    if (read_file(sk_file, &sk, &sk_len) != 0) {
        return 1;
    }

    if (sk_len != PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES) {
        fprintf(stderr, "Error: Invalid secret key size (expected %d, got %zu)\n",
                PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES, sk_len);
        free(sk);
        return 1;
    }

    // Read message
    if (read_file(msg_file, &msg, &msg_len) != 0) {
        free(sk);
        return 1;
    }

    // Sign
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &sig_len, msg, msg_len, sk) != 0) {
        fprintf(stderr, "Error: Signing failed\n");
        free(sk);
        free(msg);
        return 1;
    }

    // Write signature
    if (write_file(sig_file, sig, sig_len) != 0) {
        free(sk);
        free(msg);
        return 1;
    }

    printf("Signature saved to: %s (%zu bytes)\n", sig_file, sig_len);

    free(sk);
    free(msg);
    return 0;
}

int cmd_verify(const char *pk_file, const char *msg_file, const char *sig_file) {
    uint8_t *pk = NULL;
    uint8_t *msg = NULL;
    uint8_t *sig = NULL;
    size_t pk_len, msg_len, sig_len;

    // Read public key
    if (read_file(pk_file, &pk, &pk_len) != 0) {
        return 1;
    }

    if (pk_len != PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        fprintf(stderr, "Error: Invalid public key size (expected %d, got %zu)\n",
                PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, pk_len);
        free(pk);
        return 1;
    }

    // Read message
    if (read_file(msg_file, &msg, &msg_len) != 0) {
        free(pk);
        return 1;
    }

    // Read signature
    if (read_file(sig_file, &sig, &sig_len) != 0) {
        free(pk);
        free(msg);
        return 1;
    }

    // Verify
    int result = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk);

    if (result == 0) {
        printf("VALID\n");
    } else {
        printf("INVALID\n");
    }

    free(pk);
    free(msg);
    free(sig);

    return (result == 0) ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (argc != 4) {
            print_usage(argv[0]);
            return 1;
        }
        return cmd_keygen(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "sign") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            return 1;
        }
        return cmd_sign(argv[2], argv[3], argv[4]);
    }
    else if (strcmp(argv[1], "verify") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            return 1;
        }
        return cmd_verify(argv[2], argv[3], argv[4]);
    }
    else {
        fprintf(stderr, "Error: Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }
}
