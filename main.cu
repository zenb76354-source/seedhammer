// ================================================================
// SeedHammer — Pure GPU key generator
// No ECC, no RIPEMD160, no verification.
// Just: seed → SHA256 → 32 bytes → output.
// ================================================================

#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

// -----------------------------------------------------------------
// SHA256 — device-only, single-block, RFC 6234 compliant
// -----------------------------------------------------------------

__device__ static void sha256_block(const uint8_t *msg, uint32_t len, uint8_t out[32]) {
    const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    // Build padded block
    uint8_t block[64];
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (uint32_t i = 0; i < len && i < 64; i++) block[i] = msg[i];

    if (len < 55) {
        block[len] = 0x80;
        uint64_t bits = (uint64_t)len * 8;
        for (int i = 0; i < 8; i++) block[63 - i] = (uint8_t)(bits >> (i * 8));
    } else {
        // Multi-block — for simplicity, assume len <= 55 for now
        // (all our seeds (8 bytes or less) fit in single block)
        block[len] = 0x80;
    }

    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];

    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ((W[i - 15] >> 7) | (W[i - 15] << 25)) ^
                      ((W[i - 15] >> 18) | (W[i - 15] << 14)) ^ (W[i - 15] >> 3);
        uint32_t s1 = ((W[i - 2] >> 17) | (W[i - 2] << 15)) ^
                      ((W[i - 2] >> 19) | (W[i - 2] << 13)) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint32_t H[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;

    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(H[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(H[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(H[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(H[i]);
    }
}

// -----------------------------------------------------------------
// Generation kernels
// -----------------------------------------------------------------

// H36: Unix epoch milliseconds → 8 bytes BE → SHA256
__global__ void gen_h36(uint64_t start_ms, uint64_t count, uint8_t *out_keys) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint64_t ms = start_ms + idx;
    uint8_t seed[8];
    for (int i = 0; i < 8; i++)
        seed[7 - i] = (uint8_t)(ms >> (i * 8));

    sha256_block(seed, 8, out_keys + idx * 32);
}

// H28: uint32 → 4 bytes BE → SHA256
__global__ void gen_h28(uint64_t start, uint64_t count, uint8_t *out_keys) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint32_t val = (uint32_t)(start + idx);
    uint8_t seed[4];
    seed[0] = (uint8_t)(val >> 24);
    seed[1] = (uint8_t)(val >> 16);
    seed[2] = (uint8_t)(val >> 8);
    seed[3] = (uint8_t)(val);

    sha256_block(seed, 4, out_keys + idx * 32);
}

// H20: srand(time(NULL)) — timestamp as 4-byte uint32 LE → SHA256
__global__ void gen_h20(uint64_t start, uint64_t count, uint8_t *out_keys) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint32_t val = (uint32_t)(start + idx);
    uint8_t seed[4];
    seed[0] = (uint8_t)(val);
    seed[1] = (uint8_t)(val >> 8);
    seed[2] = (uint8_t)(val >> 16);
    seed[3] = (uint8_t)(val >> 24);

    sha256_block(seed, 4, out_keys + idx * 32);
}

// H03: timestamp 4 bytes BE + PID 4 bytes BE → SHA256
// Each thread gets a unique (timestamp_idx, pid) pair
__global__ void gen_h03(uint32_t ts, uint32_t pid_start, uint32_t pid_count, uint8_t *out_keys) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (idx >= pid_count) return;

    uint32_t pid = pid_start + (uint32_t)idx;
    uint8_t seed[8];
    seed[0] = (uint8_t)(ts >> 24);
    seed[1] = (uint8_t)(ts >> 16);
    seed[2] = (uint8_t)(ts >> 8);
    seed[3] = (uint8_t)(ts);
    seed[4] = (uint8_t)(pid >> 24);
    seed[5] = (uint8_t)(pid >> 16);
    seed[6] = (uint8_t)(pid >> 8);
    seed[7] = (uint8_t)(pid);

    sha256_block(seed, 8, out_keys + idx * 32);
}

// -----------------------------------------------------------------
// Host
// -----------------------------------------------------------------

static uint64_t parse_u64(const char *s) {
    uint64_t v = 0;
    while (*s) { v = v * 10 + (*s - '0'); s++; }
    return v;
}

static void write_out(const char *path, uint8_t *data, uint64_t bytes) {
    if (strcmp(path, "-") == 0) {
        fwrite(data, 1, bytes, stdout);
        fflush(stdout);
    } else {
        FILE *f = fopen(path, "wb");
        if (!f) { fprintf(stderr, "seedhammer: cannot open %s\n", path); exit(1); }
        fwrite(data, 1, bytes, f);
        fclose(f);
    }
}

static void run_h36(uint64_t start_ms, uint64_t count, const char *outpath) {
    const int THREADS = 256;
    uint64_t batch = 50000000; // 50M keys per batch

    uint8_t *gpu_buf;
    cudaMalloc(&gpu_buf, batch * 32);

    fprintf(stderr, "[h36] Generating %llu keys from ms=%llu...\n",
            (unsigned long long)count, (unsigned long long)start_ms);

    for (uint64_t offset = 0; offset < count; offset += batch) {
        uint64_t b = (offset + batch > count) ? (count - offset) : batch;
        uint64_t blocks = (b + THREADS - 1) / THREADS;

        gen_h36<<<(int)blocks, THREADS>>>(start_ms + offset, b, gpu_buf);
        cudaDeviceSynchronize();

        uint8_t *host_buf = (uint8_t *)malloc(b * 32);
        cudaMemcpy(host_buf, gpu_buf, b * 32, cudaMemcpyDeviceToHost);

        write_out(outpath, host_buf, b * 32);
        free(host_buf);

        fprintf(stderr, "[h36] %llu / %llu (%.1f%%)\n",
                (unsigned long long)(offset + b), (unsigned long long)count,
                100.0 * (offset + b) / count);
    }

    cudaFree(gpu_buf);
}

static void run_h28(uint64_t start, uint64_t count, const char *outpath) {
    const int THREADS = 256;
    uint64_t batch = 100000000; // 100M per batch

    uint8_t *gpu_buf;
    cudaMalloc(&gpu_buf, batch * 32);

    fprintf(stderr, "[h28] Generating %llu keys from %llu...\n",
            (unsigned long long)count, (unsigned long long)start);

    for (uint64_t offset = 0; offset < count; offset += batch) {
        uint64_t b = (offset + batch > count) ? (count - offset) : batch;
        uint64_t blocks = (b + THREADS - 1) / THREADS;

        gen_h28<<<(int)blocks, THREADS>>>(start + offset, b, gpu_buf);
        cudaDeviceSynchronize();

        uint8_t *host_buf = (uint8_t *)malloc(b * 32);
        cudaMemcpy(host_buf, gpu_buf, b * 32, cudaMemcpyDeviceToHost);

        write_out(outpath, host_buf, b * 32);
        free(host_buf);

        fprintf(stderr, "[h28] %llu / %llu (%.1f%%)\n",
                (unsigned long long)(offset + b), (unsigned long long)count,
                100.0 * (offset + b) / count);
    }

    cudaFree(gpu_buf);
}

static void run_h20(uint64_t start, uint64_t count, const char *outpath) {
    // Same as h28 but with LE bytes (for srand())
    const int THREADS = 256;
    uint64_t batch = 100000000;

    uint8_t *gpu_buf;
    cudaMalloc(&gpu_buf, batch * 32);

    fprintf(stderr, "[h20] Generating %llu keys from %llu...\n",
            (unsigned long long)count, (unsigned long long)start);

    for (uint64_t offset = 0; offset < count; offset += batch) {
        uint64_t b = (offset + batch > count) ? (count - offset) : batch;
        uint64_t blocks = (b + THREADS - 1) / THREADS;

        gen_h20<<<(int)blocks, THREADS>>>(start + offset, b, gpu_buf);
        cudaDeviceSynchronize();

        uint8_t *host_buf = (uint8_t *)malloc(b * 32);
        cudaMemcpy(host_buf, gpu_buf, b * 32, cudaMemcpyDeviceToHost);

        write_out(outpath, host_buf, b * 32);
        free(host_buf);

        fprintf(stderr, "[h20] %llu / %llu (%.1f%%)\n",
                (unsigned long long)(offset + b), (unsigned long long)count,
                100.0 * (offset + b) / count);
    }

    cudaFree(gpu_buf);
}

static void run_h03(uint32_t ts, uint32_t pid_start, uint32_t pid_count, const char *outpath) {
    const int THREADS = 256;
    uint64_t blocks = (pid_count + THREADS - 1) / THREADS;

    uint8_t *gpu_buf;
    cudaMalloc(&gpu_buf, (uint64_t)pid_count * 32);

    fprintf(stderr, "[h03] Generating %u keys (ts=%u, pid=%u..%u)...\n",
            pid_count, ts, pid_start, pid_start + pid_count - 1);

    gen_h03<<<(int)blocks, THREADS>>>(ts, pid_start, pid_count, gpu_buf);
    cudaDeviceSynchronize();

    uint8_t *host_buf = (uint8_t *)malloc((uint64_t)pid_count * 32);
    cudaMemcpy(host_buf, gpu_buf, (uint64_t)pid_count * 32, cudaMemcpyDeviceToHost);

    write_out(outpath, host_buf, (uint64_t)pid_count * 32);
    free(host_buf);

    cudaFree(gpu_buf);
    fprintf(stderr, "[h03] Done.\n");
}

static void print_usage() {
    fprintf(stderr,
        "SeedHammer — GPU Bitcoin private key generator\n"
        "Usage:\n"
        "  --mode MODE   Generation mode: h28, h36, h48, h03, h20\n"
        "  --start N     Start value (ms for h36, int for h28/h48)\n"
        "  --count N     Number of keys to generate\n"
        "  --ts N        Timestamp (for h03)\n"
        "  --pid-start N PID start (for h03, default 0)\n"
        "  --pid-count N PID count (for h03, default 32768)\n"
        "  --out FILE    Output file (use - for stdout)\n"
        "\n"
        "Examples:\n"
        "  ./seedhammer --mode h36 --start 1223424000000 --count 50000000 --out keys.bin\n"
        "  ./seedhammer --mode h28 --start 0 --count 1000000000 --out -\n"
        "  ./seedhammer --mode h03 --ts 1268728843 --pid-count 32768 --out keys_h03.bin\n"
    );
}

int main(int argc, char **argv) {
    // Check CUDA device
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    fprintf(stderr, "SeedHammer on %s (SM%d.%d, %d SMs)\n",
            prop.name, prop.major, prop.minor, prop.multiProcessorCount);

    const char *mode = NULL;
    const char *outpath = NULL;
    uint64_t start_val = 0;
    uint64_t count_val = 0;
    uint32_t ts_val = 0;
    uint32_t pid_start = 0;
    uint32_t pid_count = 32768;

    // Simple arg parsing
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
        else if (strcmp(argv[i], "--start") == 0 && i + 1 < argc) start_val = parse_u64(argv[++i]);
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count_val = parse_u64(argv[++i]);
        else if (strcmp(argv[i], "--ts") == 0 && i + 1 < argc) ts_val = (uint32_t)parse_u64(argv[++i]);
        else if (strcmp(argv[i], "--pid-start") == 0 && i + 1 < argc) pid_start = (uint32_t)parse_u64(argv[++i]);
        else if (strcmp(argv[i], "--pid-count") == 0 && i + 1 < argc) pid_count = (uint32_t)parse_u64(argv[++i]);
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) outpath = argv[++i];
        else { print_usage(); return 1; }
    }

    if (!mode || !outpath) { print_usage(); return 1; }

    if (strcmp(mode, "h36") == 0) {
        if (count_val == 0) { fprintf(stderr, "seedhammer: --count required for h36\n"); return 1; }
        run_h36(start_val, count_val, outpath);
    } else if (strcmp(mode, "h28") == 0) {
        if (count_val == 0) { fprintf(stderr, "seedhammer: --count required for h28\n"); return 1; }
        run_h28(start_val, count_val, outpath);
    } else if (strcmp(mode, "h48") == 0) {
        // Same as h28 (uint48 fits in uint64 range)
        if (count_val == 0) { fprintf(stderr, "seedhammer: --count required for h48\n"); return 1; }
        run_h28(start_val, count_val, outpath);
    } else if (strcmp(mode, "h20") == 0) {
        if (count_val == 0) { fprintf(stderr, "seedhammer: --count required for h20\n"); return 1; }
        run_h20(start_val, count_val, outpath);
    } else if (strcmp(mode, "h03") == 0) {
        if (ts_val == 0) { fprintf(stderr, "seedhammer: --ts required for h03\n"); return 1; }
        run_h03(ts_val, pid_start, pid_count, outpath);
    } else {
        fprintf(stderr, "seedhammer: unknown mode '%s'\n", mode);
        return 1;
    }

    fprintf(stderr, "SeedHammer done.\n");
    return 0;
}
