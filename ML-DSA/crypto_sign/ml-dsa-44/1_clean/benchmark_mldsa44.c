/*
ML-DSA-44 Performance Benchmark
Measures keygen, sign, verify performance using rdtsc
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "api.h"

#define ITERATIONS 1000
#define WARMUP_ITERATIONS 10

// CPU cycle measurement with serialization
static inline uint64_t rdtsc_start(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ (
        "cpuid\n\t"          // Serialize before rdtsc
        "rdtsc\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        : "=r" (hi), "=r" (lo)
        :
        : "%rax", "%rbx", "%rcx", "%rdx"
    );
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_end(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ (
        "rdtscp\n\t"         // Serialize after execution
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "cpuid\n\t"          // Additional serialization
        : "=r" (hi), "=r" (lo)
        :
        : "%rax", "%rbx", "%rcx", "%rdx"
    );
    return ((uint64_t)hi << 32) | lo;
}

// Statistics calculation
void calculate_stats(uint64_t *cycles, int n, uint64_t *avg) {
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) {
        sum += cycles[i];
    }
    *avg = sum / n;
}

// Benchmark keygen
uint64_t benchmark_keygen(int iterations) {
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint64_t cycles[iterations];

    printf("🔑 Benchmarking KEYGEN (%d iterations)...\n", iterations);

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    }

    // Actual measurement
    for (int i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
        uint64_t end = rdtsc_end();
        cycles[i] = end - start;

        if (i % 20 == 0) {
            printf("  Progress: %d/%d\n", i, iterations);
        }
    }

    uint64_t avg_cycles;
    calculate_stats(cycles, iterations, &avg_cycles);

    printf("  Avg:    %10lu cycles\n", avg_cycles);

    return avg_cycles;
}

// Benchmark sign
uint64_t benchmark_sign(int iterations) {
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t siglen;
    const uint8_t msg[] = "Performance benchmark message for ML-DSA-44";
    const size_t msglen = sizeof(msg) - 1;
    uint64_t cycles[iterations];

    printf("\n✍️  Benchmarking SIGN (%d iterations)...\n", iterations);

    // Generate keypair once
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, msglen, sk);
    }

    // Actual measurement
    for (int i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, msglen, sk);
        uint64_t end = rdtsc_end();
        cycles[i] = end - start;

        if (i % 20 == 0) {
            printf("  Progress: %d/%d\n", i, iterations);
        }
    }

    uint64_t avg_cycles;
    calculate_stats(cycles, iterations, &avg_cycles);

    printf("  Avg:    %10lu cycles\n", avg_cycles);

    return avg_cycles;
}

// Benchmark verify
uint64_t benchmark_verify(int iterations) {
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t siglen;
    const uint8_t msg[] = "Performance benchmark message for ML-DSA-44";
    const size_t msglen = sizeof(msg) - 1;
    uint64_t cycles[iterations];

    printf("\n✅ Benchmarking VERIFY (%d iterations)...\n", iterations);

    // Generate keypair and signature once
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, msglen, sk);

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk);
    }

    // Actual measurement
    for (int i = 0; i < iterations; i++) {
        uint64_t start = rdtsc_start();
        int result = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk);
        uint64_t end = rdtsc_end();
        cycles[i] = end - start;

        if (result != 0) {
            printf("ERROR: Verification failed at iteration %d\n", i);
            return 0;
        }

        if (i % 20 == 0) {
            printf("  Progress: %d/%d\n", i, iterations);
        }
    }

    uint64_t avg_cycles;
    calculate_stats(cycles, iterations, &avg_cycles);

    printf("  Avg:    %10lu cycles\n", avg_cycles);

    return avg_cycles;
}

// Get CPU frequency estimate
double get_cpu_freq_ghz() {
    uint64_t start = rdtsc_start();
    sleep(1);  // Sleep for 1 second
    uint64_t end = rdtsc_end();
    return (double)(end - start) / 1e9;  // Convert to GHz
}

int main() {
    printf("🎯 ML-DSA-44 Performance Benchmark\n");
    printf("===================================\n");
    printf("Implementation: ML-DSA-44 Clean\n");
    printf("Iterations: %d (+ %d warmup)\n", ITERATIONS, WARMUP_ITERATIONS);

    // Estimate CPU frequency
    printf("\n📊 System Information:\n");
    printf("Estimating CPU frequency... ");
    fflush(stdout);
    double cpu_freq = get_cpu_freq_ghz();
    printf("~%.2f GHz\n", cpu_freq);

    printf("\n🚀 Starting benchmarks...\n");
    printf("==========================================\n");

    // Run benchmarks
    uint64_t keygen_cycles = benchmark_keygen(ITERATIONS);
    uint64_t sign_cycles = benchmark_sign(ITERATIONS);
    uint64_t verify_cycles = benchmark_verify(ITERATIONS);

    // Summary
    printf("\n📋 PERFORMANCE SUMMARY\n");
    printf("======================\n");
    printf("Operation       | Average Cycles | Time (ms @ %.2f GHz)\n", cpu_freq);
    printf("----------------|----------------|-------------------\n");
    printf("KEYGEN          | %10lu     | %8.3f\n", keygen_cycles, (double)keygen_cycles / (cpu_freq * 1e6));
    printf("SIGN            | %10lu     | %8.3f\n", sign_cycles, (double)sign_cycles / (cpu_freq * 1e6));
    printf("VERIFY          | %10lu     | %8.3f\n", verify_cycles, (double)verify_cycles / (cpu_freq * 1e6));

    // Calculate operations per second
    printf("\n⚡ THROUGHPUT (ops/sec @ %.2f GHz)\n", cpu_freq);
    printf("===================================\n");
    printf("KEYGEN:  %8.1f ops/sec\n", (cpu_freq * 1e9) / keygen_cycles);
    printf("SIGN:    %8.1f ops/sec\n", (cpu_freq * 1e9) / sign_cycles);
    printf("VERIFY:  %8.1f ops/sec\n", (cpu_freq * 1e9) / verify_cycles);

    // Save results to file
    FILE *fp = fopen("benchmark_results_mldsa44.txt", "w");
    if (fp) {
        fprintf(fp, "ML-DSA-44 Clean Implementation Benchmark Results\n");
        fprintf(fp, "=================================================\n");
        fprintf(fp, "CPU Frequency: %.2f GHz\n", cpu_freq);
        fprintf(fp, "Iterations: %d\n\n", ITERATIONS);
        fprintf(fp, "KEYGEN:  %lu cycles (%.3f ms, %.1f ops/sec)\n",
                keygen_cycles, (double)keygen_cycles / (cpu_freq * 1e6), (cpu_freq * 1e9) / keygen_cycles);
        fprintf(fp, "SIGN:    %lu cycles (%.3f ms, %.1f ops/sec)\n",
                sign_cycles, (double)sign_cycles / (cpu_freq * 1e6), (cpu_freq * 1e9) / sign_cycles);
        fprintf(fp, "VERIFY:  %lu cycles (%.3f ms, %.1f ops/sec)\n",
                verify_cycles, (double)verify_cycles / (cpu_freq * 1e6), (cpu_freq * 1e9) / verify_cycles);
        fclose(fp);
        printf("\n💾 Results saved to: benchmark_results_mldsa44.txt\n");
    }

    return 0;
}