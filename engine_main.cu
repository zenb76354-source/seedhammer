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
#include "hypothesis_gpu.cu"     // SHA256 + seed generation kernels
#include "ripemd160.cuh"         // RIPEMD-160 standalone header (no SHA256 conflict)
#include "math256.h"
#include "ec_jacobian.h"
#include "targets.h"

// scan_kernel.cu uses sha256() from hypothesis_gpu.cu and ripemd160() from ripemd160.cuh
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
    // Host-side copies for display (avoid __constant__ reads from CPU)
    static const char *TARGET_LABELS_HOST[NUM_TARGETS] = {
        "N1","H1","H2","H3","H4","H5","H6","H7","H8","H9","H10",
        "H11","H12","H13","H14","H15","H16","H17","H18","H19","H20",
        "H21","H22","H23","H24","H25","H26","H27","H28","H29","H30",
        "H31","H32","H33","H34","H35","H36","H37","H38","H39","H40",
        "H41","H42","H43","H44","H45","H46","H47","H48","H49","H50"
    };
    static const double TARGET_BALANCE_HOST[NUM_TARGETS] = {
        1400.98, 1260.0, 820.30, 693.7, 650.45, 500.0, 460.40, 430.9,
        430.31, 408.0, 403.25, 300.01, 290.0, 273.08, 256.32, 253.93,
        250.0, 249.14, 235.49, 228.61, 224.40, 224.00, 212.31, 212.0,
        200.05, 200.03, 200.0, 200.0, 200.0, 200.0, 200.0, 199.41,
        197.47, 195.47, 186.87, 186.32, 186.19, 184.67, 176.0, 172.26,
        168.70, 165.92, 165.2, 163.0, 161.97, 161.47, 161.0, 160.29,
        159.31, 155.91, 1400.98
    };
    for (uint32_t ti = 0; ti < n_targets; ti++) {
        const char *addr = TARGET_ADDRS[ti];
        const char *lab = TARGET_LABELS_HOST[ti];
        double bal = TARGET_BALANCE_HOST[ti];
        fprintf(stderr, "  [%2u] %s %-6s %8.2f BTC\n", ti, lab, addr, bal);
    }

    // Build Bloom - Corrected to 1 << 21 to match DEV_BLOOM_DATA[262144] in scan_kernel.cu
    uint32_t bloom_bits = 1 << 21; // 2,097,152 bits = 262,144 bytes
    uint8_t *bloom_data = (uint8_t*)calloc(1, bloom_bits / 8);
    build_bloom(bloom_data, bloom_bits, targets, n_targets);

    // GPU Init
    CUDA_ERR(cudaSetDevice(0));
    
    // Copy small constants via cudaMemcpyToSymbol; large arrays via global memory
    CUDA_ERR(cudaMemcpyToSymbol(DEV_BLOOM_BITS, &bloom_bits, sizeof(uint32_t)));
    CUDA_ERR(cudaMemcpyToSymbol(DEV_N_TARGETS, &n_targets, sizeof(uint32_t)));

    // Bloom data (256KB) and targets (5KB) exceed 64KB constant memory limit
    // Allocate global memory and pass pointers to kernel
    uint8_t *d_bloom_data;
    uint8_t *d_targets;
    CUDA_ERR(cudaMalloc(&d_bloom_data, bloom_bits / 8));
    CUDA_ERR(cudaMemcpy(d_bloom_data, bloom_data, bloom_bits / 8, cudaMemcpyHostToDevice));
    CUDA_ERR(cudaMalloc(&d_targets, n_targets * 20));
    CUDA_ERR(cudaMemcpy(d_targets, targets, n_targets * 20, cudaMemcpyHostToDevice));

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
                                               seed_range, current_batch, d_found_count, d_found_key,
                                               d_bloom_data, d_targets);
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
    cudaFree(d_bloom_data);
    cudaFree(d_targets);
    free(bloom_data);
    return 0;
}
