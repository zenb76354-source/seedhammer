// engine/main.cu — GPU generation + verification integrated
// Weds seedhammer (hypothesis_gpu.cu) with vaultwatch (ec_jacobian.h, math256.h)
// and scan_kernel.cu (SHA256 + RIPEMD160 + bloom + exact match)

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cuda_runtime.h>

#define CUDA_ERR(x) do { \
    cudaError_t e = (x); \
    if (e != cudaSuccess) { \
        fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(e)); \
        exit(1); \
    } \
} while(0)

// Paths relative to -I includes
#include "hypothesis_gpu.cu" 
#include "math256.h"
#include "ec_jacobian.h"
#include "targets.h"
#include "scan_kernel.cu"

// bloom_build now imported from scan_kernel.cu — IDENTICAL to vaultwatch-cuda.cu's bloom_add
#define build_bloom bloom_build

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mode> [--ts-start N] [--ts-end N] [--seed-start N] [--seed-end N] [--progress]\n", argv[0]);
        return 1;
    }

    char mode_char = argv[1][0];
    uint64_t ts_start = 0, ts_end = 0;
    uint32_t seed_start = 0, seed_end = 0;
    int has_seed_range = 0;
    int show_progress = 0;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--ts-start") && i+1 < argc) ts_start = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--ts-end") && i+1 < argc) ts_end = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--seed-start") && i+1 < argc) { seed_start = (uint32_t)strtoul(argv[++i], NULL, 10); has_seed_range = 1; }
        else if (!strcmp(argv[i], "--seed-end") && i+1 < argc) { seed_end = (uint32_t)strtoul(argv[++i], NULL, 10); has_seed_range = 1; }
        else if (!strcmp(argv[i], "--progress")) show_progress = 1;
    }

    if (ts_start == 0 && ts_end == 0) {
        fprintf(stderr, "ERROR: specify --ts-start and --ts-end\n");
        return 1;
    }

    // Load Targets from targets.h (51 targets, embedded at compile time)
    uint32_t n_targets = NUM_TARGETS;
    const uint8_t *targets = (const uint8_t*)TARGET_H160;
    fprintf(stderr, "Loaded %u targets from targets.h\n", n_targets);
    for (uint32_t ti = 0; ti < n_targets; ti++) {
        const char *addr = TARGET_ADDRS[ti];
        const char *lab = TARGET_LABELS[ti];
        double bal = TARGET_BALANCE[ti];
        fprintf(stderr, "  [%2u] %s %-6s %8.2f BTC\n", ti, lab, addr, bal);
    }

    // Build Bloom - Corrected to 1 << 21 to match DEV_BLOOM_DATA[262144] in scan_kernel.cu
    uint32_t bloom_bits = 1 << 21; // 2,097,152 bits = 262,144 bytes
    uint8_t *bloom_data = (uint8_t*)calloc(1, bloom_bits / 8);
    build_bloom(bloom_data, bloom_bits, targets, n_targets);

    // GPU Init
    CUDA_ERR(cudaSetDevice(0));
    
    // Copy to Constant Memory (Correct DEV_ prefix names)
    CUDA_ERR(cudaMemcpyToSymbol(DEV_BLOOM_BITS, &bloom_bits, sizeof(uint32_t)));
    CUDA_ERR(cudaMemcpyToSymbol(DEV_BLOOM_DATA, bloom_data, bloom_bits / 8));
    CUDA_ERR(cudaMemcpyToSymbol(DEV_N_TARGETS, &n_targets, sizeof(uint32_t)));
    CUDA_ERR(cudaMemcpyToSymbol(DEV_TARGETS, targets, n_targets * 20));

    // Result buffers
    uint8_t *d_found_key;
    unsigned long long *d_found_count;
    CUDA_ERR(cudaMalloc(&d_found_key, 256 * 52));
    CUDA_ERR(cudaMalloc(&d_found_count, sizeof(unsigned long long)));
    CUDA_ERR(cudaMemset(d_found_count, 0, sizeof(unsigned long long)));

    uint64_t seed_range = has_seed_range ? (uint64_t)(seed_end - seed_start) + 1 : 1;
    uint64_t ts_range = ts_end - ts_start + 1;
    uint64_t total_keys = ts_range * seed_range;

    fprintf(stderr, "Engine: mode=%c ts=%lu..%lu seed_range=%lu total=%lu\n", mode_char, ts_start, ts_end, seed_range, total_keys);

    uint32_t threads = 256;
    uint32_t batch_size = 1 << 20; // 1M keys per batch
    uint64_t processed = 0;
    time_t start_time = time(NULL);

    while (processed < total_keys) {
        uint64_t remaining = total_keys - processed;
        uint32_t current_batch = (remaining < batch_size) ? (uint32_t)remaining : batch_size;
        uint32_t blocks = (current_batch + threads - 1) / threads;

        // super_scan_kernel now correctly uses mode for generation
        super_scan_kernel<<<blocks, threads>>>(mode_char, ts_start + (processed / seed_range), 
                                               seed_start + (uint32_t)(processed % seed_range), 
                                               seed_range, current_batch, d_found_count, d_found_key);
        CUDA_ERR(cudaDeviceSynchronize());

        unsigned long long h_found_count;
        CUDA_ERR(cudaMemcpy(&h_found_count, d_found_count, sizeof(unsigned long long), cudaMemcpyDeviceToHost));

        if (h_found_count > 0) {
            uint8_t found_data[52];
            CUDA_ERR(cudaMemcpy(found_data, d_found_key, 52, cudaMemcpyDeviceToHost));
            
            printf("\n*** FOUND! ***\n");
            printf("Priv: "); for(int i=0; i<32; i++) printf("%02x", found_data[i]); printf("\n");
            printf("H160: "); for(int i=0; i<20; i++) printf("%02x", found_data[32+i]); printf("\n");
            
            FILE *f = fopen("found.txt", "a");
            if (f) {
                for(int i=0; i<32; i++) fprintf(f, "%02x", found_data[i]);
                fprintf(f, " | ");
                for(int i=0; i<20; i++) fprintf(f, "%02x", found_data[32+i]);
                fprintf(f, "\n");
                fclose(f);
            }
            break;
        }

        processed += current_batch;
        if (show_progress) {
            time_t now = time(NULL);
            double elapsed = difftime(now, start_time);
            double rate = elapsed > 0 ? (double)processed / elapsed : 0;
            double progress = (double)processed / total_keys * 100.0;
            double eta = rate > 0 ? (total_keys - processed) / rate : 0;
            fprintf(stderr, "\rProgress: %.2f%% | Rate: %.2f M/s | ETA: %.0fs", progress, rate / 1e6, eta);
            fflush(stderr);
        }
    }

    printf("\nScan complete. Processed %lu keys.\n", processed);
    cudaFree(d_found_key);
    cudaFree(d_found_count);
    free(bloom_data);
    return 0;
}
