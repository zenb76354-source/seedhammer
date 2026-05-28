// engine/main.cu — GPU generation + verification integrated
// seedhammer (hypothesis_gpu.cu) × vaultwatch (ec_jacobian.h, math256.h, targets.h)
// × scan_kernel.cu (warp-parallel SHA+RIPEMD+bloom+differential addition)
// No pipes, no files, no host copy of keys — everything on GPU.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <cuda_runtime.h>

#define THREADS 256

#include "hypothesis_gpu.cu"
#include "math256.h"
#include "ec_jacobian.h"

#include "targets.h"
#include "scan_kernel.cu"

// ==================== HOST-SIDE BLOOM (7 XOR hashes) ====================
static void build_bloom(uint8_t *bloom_data, uint32_t bloom_bits,
                         const uint8_t *targets, uint32_t n_targets) {
    uint32_t mask = bloom_bits - 1;
    for (uint32_t i = 0; i < n_targets; i++) {
        const uint8_t *h = targets + i * 20;
        uint32_t h7[7] = {
            ((uint32_t)h[0]<<24|h[1]<<16|h[2]<<8|h[3]) & mask,
            ((uint32_t)h[4]<<24|h[5]<<16|h[6]<<8|h[7]) & mask,
            ((uint32_t)h[8]<<24|h[9]<<16|h[10]<<8|h[11]) & mask,
            ((uint32_t)h[12]<<24|h[13]<<16|h[14]<<8|h[15]) & mask,
            ((uint32_t)h[16]<<24|h[17]<<16|h[18]<<8|h[19]) & mask,
            ((uint32_t)(h[0]^h[10])<<24|(h[1]^h[11])<<16|(h[2]^h[12])<<8|(h[3]^h[13])) & mask,
            ((uint32_t)(h[4]^h[14])<<24|(h[5]^h[15])<<16|(h[6]^h[16])<<8|(h[7]^h[17])) & mask
        };
        for (int j = 0; j < 7; j++)
            bloom_data[h7[j] >> 3] |= (1 << (h7[j] & 7));
    }
}

// ==================== CUDA ERROR CHECK ====================
#define CUDA_ERR(x) do { \
    cudaError_t e = (x); \
    if (e != cudaSuccess) { \
        fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(e)); \
        exit(1); \
    } \
} while(0)

// ==================== MAIN ====================
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mode> [--ts-start N] [--ts-end N] [--seed-start N] [--seed-end N] [--progress]\n", argv[0]);
        return 1;
    }

    char mode_char = argv[1][0];
    uint64_t ts_start = 0, ts_end = 0;
    uint32_t seed_start = 0, seed_end = UINT32_MAX;
    int show_progress = 0;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--ts-start") && i+1 < argc) ts_start = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--ts-end") && i+1 < argc) ts_end = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--seed-start") && i+1 < argc) seed_start = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--seed-end") && i+1 < argc) seed_end = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--progress")) show_progress = 1;
    }

    if (ts_start == 0 && ts_end == 0 && seed_start == 0 && seed_end == UINT32_MAX) {
        fprintf(stderr, "ERROR: specify --ts-start/--ts-end or --seed range\n");
        return 1;
    }

    fprintf(stderr, "Engine: mode=%c ts=%lu..%lu seed=%u..%u\n",
            mode_char, ts_start, ts_end, seed_start, seed_end);

    // ==================== LOAD TARGETS from targets.h ====================
    uint32_t n_targets = NUM_TARGETS;  // 51 (from targets.h)
    const uint8_t *targets = (const uint8_t*)TARGET_H160;  // [51][20] hardcoded array
    fprintf(stderr, "Loaded %u targets from targets.h\n", n_targets);

    // ==================== BUILD BLOOM FILTER ====================
    uint32_t bloom_bits = 1 << 21;  // 2,097,152 bits = 262144 bytes
    uint8_t *bloom_data = (uint8_t*)calloc(1, bloom_bits / 8);
    if (!bloom_data) { fprintf(stderr, "ERROR: calloc(%u) failed\n", bloom_bits/8); return 1; }
    build_bloom(bloom_data, bloom_bits, targets, n_targets);

    // ==================== GPU INIT ====================
    int gpu_id = 0;
    CUDA_ERR(cudaSetDevice(gpu_id));
    cudaDeviceProp prop;
    CUDA_ERR(cudaGetDeviceProperties(&prop, gpu_id));
    fprintf(stderr, "GPU: %s (SMs=%d, VRAM=%zu MB)\n",
            prop.name, prop.multiProcessorCount, prop.totalGlobalMem >> 20);

    // ==================== UPLOAD TO GPU ====================
    uint32_t h_bloom_bits = bloom_bits;
    CUDA_ERR(cudaMemcpyToSymbol(DEV_BLOOM_BITS, &h_bloom_bits, sizeof(uint32_t)));
    CUDA_ERR(cudaMemcpyToSymbol(DEV_BLOOM_DATA, bloom_data, bloom_bits / 8));
    CUDA_ERR(cudaMemcpyToSymbol(DEV_N_TARGETS, &n_targets, sizeof(uint32_t)));
    CUDA_ERR(cudaMemcpyToSymbol(DEV_TARGETS, targets, n_targets * 20));
    CUDA_ERR(cudaDeviceSynchronize());
    fprintf(stderr, "Uploaded %u targets + %u KB bloom to __constant__ memory\n",
            n_targets, bloom_bits / 8 / 1024);

    // ==================== GPU OUTPUT BUFFERS ====================
    uint8_t *d_found_key;
    uint64_t *d_found_count;
    CUDA_ERR(cudaMalloc(&d_found_key, 256 * 52));
    CUDA_ERR(cudaMalloc(&d_found_count, sizeof(uint64_t)));

    // ==================== LOOP PARAMS ====================
    uint64_t seed_range = (uint64_t)(seed_end - seed_start) + 1;
    uint64_t ts_range = (ts_start > 0 && ts_end > 0) ? (ts_end - ts_start + 1) : 1;
    uint64_t total_keys = ts_range * seed_range;
    uint64_t processed = 0;
    time_t start_time = time(NULL);
    uint32_t keys_per_kernel = THREADS * 1024;  // 256K keys per batch
    // Note: super_scan_kernel generates 16 keys per thread via differential addition
    // So actual keys checked per launch = keys_per_kernel * 16

    fprintf(stderr, "Total keys: %lu | batch: %u keys/kernel\n", total_keys, keys_per_kernel);

    // ==================== MAIN LOOP ====================
    while (processed < total_keys) {
        uint64_t remaining = total_keys - processed;
        uint64_t this_batch = (remaining < keys_per_kernel) ? remaining : keys_per_kernel;

        uint64_t base_ts = ts_start + (processed / seed_range);
        uint32_t base_seed = seed_start + (uint32_t)(processed % seed_range);

        // Reset found counter
        CUDA_ERR(cudaMemset(d_found_count, 0, sizeof(uint64_t)));

        // Launch kernel (16 keys per thread via differential addition)
        uint32_t grid = (uint32_t)((this_batch + THREADS - 1) / THREADS);
        super_scan_kernel<<<grid, THREADS>>>(
            mode_char, base_ts, base_seed, seed_range,
            this_batch, d_found_count, d_found_key
        );

        CUDA_ERR(cudaDeviceSynchronize());

        // Check for found keys
        uint64_t found_this = 0;
        CUDA_ERR(cudaMemcpy(&found_this, d_found_count, sizeof(uint64_t), cudaMemcpyDeviceToHost));
        if (found_this > 0) {
            uint64_t to_read = (found_this < 256) ? found_this : 256;
            uint8_t found_data[256 * 52];
            CUDA_ERR(cudaMemcpy(found_data, d_found_key, to_read * 52, cudaMemcpyDeviceToHost));

            for (uint64_t fi = 0; fi < to_read; fi++) {
                uint8_t *key = found_data + fi * 52;
                printf("FOUND\t");
                for (int i = 0; i < 32; i++) printf("%02x", key[i]);
                printf("\t");
                for (int i = 32; i < 52; i++) printf("%02x", key[i]);
                printf("\n");

                FILE *ff = fopen("found.txt", "a");
                if (ff) {
                    fprintf(ff, "FOUND priv=");
                    for (int i = 0; i < 32; i++) fprintf(ff, "%02x", key[i]);
                    fprintf(ff, " h160=");
                    for (int i = 32; i < 52; i++) fprintf(ff, "%02x", key[i]);
                    fprintf(ff, "\n");
                    fclose(ff);
                }
            }
            fprintf(stderr, "\n[!] FOUND %lu key(s) — check found.txt\n", found_this);
        }

        processed += this_batch;

        // Progress
        if (show_progress) {
            double pct = 100.0 * (double)processed / (double)total_keys;
            double elapsed = (double)(time(NULL) - start_time);
            double kps = (double)processed / (elapsed > 0 ? elapsed : 1.0);
            fprintf(stderr, "\r%c: %.4f%% | %lu Mkeys | %.1f M/s",
                    mode_char, pct, (unsigned long)(processed / 1000000), kps / 1000000.0);
        }
    }

    fprintf(stderr, "\nDone. Processed %lu keys in %ld seconds.\n",
            processed, time(NULL) - start_time);
    return 0;
}
