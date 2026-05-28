// SeedHammer main.cu — Auto-pipeline orchestrator
// Compile: make (uses hypothesis_gpu.cu for all mode functions)
// --scan : INTEGRATED generate + verify on GPU, no pipe, no disk
//          Embeds EC+HASH160 in the generation kernel

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cuda_runtime.h>
#include <sys/stat.h>

// Hypotheses generator functions
#include "hypothesis_gpu.cu"

// EC + HASH160 (for --scan integrated mode)
// Includes ec_jacobian.h and math256.h from the vaultwatch directory
// These are included via -I/vaultwatch in the Makefile
#include "ec_jacobian.h"
#include "math256.h"

// Integrated scan kernel (EC multiply + SHA256 + RIPEMD160 + bloom check)
#include "scan_kernel.cu"

static const char *MODES[] = {
    "H","M","R","C","J","W","B","A","D","E",
    "L","S","T","F","G","Q","Y","M2","R2","CQ",
    "LC","RS","Z","K","X","P"
};
#define NUM_MODES (sizeof(MODES)/sizeof(MODES[0]))
#define KEYS_PER_BATCH (1024ULL * 1024 * 8) // 8M keys per batch
#define CHECKPOINT_FILE "autocycle_checkpoint.txt"
#define STOP_FLAG_FILE "STOP"
#define THREADS 2048
#define BLOCKS 16384
#define KEYS_PER_KERNEL ((uint64_t)THREADS * (uint64_t)BLOCKS)

time_t run_start_time = 0;

int check_stop_signal(void){
    FILE *f = fopen(STOP_FLAG_FILE, "r");
    if(f){ fclose(f); return 1; }
    return 0;
}

void save_checkpoint(int mode_idx, uint64_t offset){
    FILE *f = fopen(CHECKPOINT_FILE, "w");
    if(!f) return;
    fprintf(f, "%s %lu\n", MODES[mode_idx], (unsigned long)offset);
    fclose(f);
}

int load_checkpoint(char *mode_str, uint64_t *offset){
    FILE *f = fopen(CHECKPOINT_FILE, "r");
    if(!f) return 0;
    int r = fscanf(f, "%s %lu", mode_str, (unsigned long *)offset);
    fclose(f);
    return r == 2;
}

// GPU kernel: generate keys for one mode
__global__ void gen_keys_kernel(char mode_char,
    uint64_t base_ts, uint32_t base_seed,
    uint64_t seed_range,
    uint8_t *d_out, uint64_t batch_keys)
{
    uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if(idx >= batch_keys) return;

    uint64_t t = base_ts + (idx / (uint64_t)seed_range);
    uint32_t s = base_seed + (uint32_t)(idx % seed_range);
    uint8_t priv[32];

    switch(mode_char){
        case 'H':{
            uint64_t variant = idx % 8;
            if(variant == 0) mode_h36(t, priv);
            else if(variant == 1) mode_h36_drift(t, idx & 0xFF, priv);
            else if(variant == 2) mode_h36_le(t, priv);
            else if(variant == 3) mode_h36_sec((uint32_t)t, priv);
            else if(variant == 4) mode_h36_pid(t, (uint32_t)(s ^ t), priv);
            else if(variant == 5) mode_multisource(t, (uint32_t)s, t & 0xFFFFFFFF, 0, priv);
            else if(variant == 6) mode_jitter(t, (uint8_t)(s & 0xFF), priv);
            else mode_h36_usec(t, s, priv);
            break;
        }
        case 'M':{
            uint64_t variant = idx % 4;
            if(variant == 0) mode_mwc_v8(t, s, priv);
            else if(variant == 1) mode_mwc_little(t, s, priv);
            else if(variant == 2) mode_v8_3_0(t, s, priv);
            else mode_v8_3_4(t, s, priv);
            break;
        }
        case 'R':
            if(idx % 2 == 0) mode_randstorm(t, idx, priv);
            else mode_randstorm_little(t, idx, priv);
            break;
        case 'C':
            mode_bitcoincore_v3(t, (uint32_t)idx, (uint8_t)(idx & 0xFF), priv);
            break;
        case 'J':
            mode_android_rng(s, priv);
            break;
        case 'W':
            mode_instawallet(t, s, priv);
            break;
        case 'B':{
            const uint8_t user[] = "user_test";
            const uint8_t pass[] = "pass_test";
            mode_mybitcoin(user, pass, priv);
            break;
        }
        case 'A':
            mode_bitaddress(t, s, priv);
            break;
        case 'D':
            mode_core_v3_stack(t, (uint32_t)idx, (int)(idx % 256), priv);
            break;
        case 'E':
            mode_mywallet(t, s, priv);
            break;
        case 'L':
            mode_bitbills(t, priv);
            break;
        case 'S':
            mode_electrum(t, s, priv);
            break;
        case 'T':
            mode_h36_pid(t, (uint32_t)(t ^ idx), priv);
            break;
        case 'G':
            mode_spidermonkey(t, (uint32_t)idx, priv);
            break;
        case 'Q':
            mode_jsc_webkit(t, s, priv);
            break;
        case 'Y':
            mode_linux_libc_rand(s, priv);
            break;
        case 'M2':
            mode_mwc_v8(t, s ^ 0xCAFE4242, priv);
            break;
        case 'R2':
            mode_randstorm(t, idx ^ 0xDEADBEEF, priv);
            break;
        case 'CQ':{
            uint32_t year = 2008 + (idx % 20);
            uint32_t qq = (s & 0xFFFFFFF);
            mode_cn_brainwallet((uint32_t)(t % 16), year, qq, priv);
            break;
        }
        case 'LC':
            mode_linux_libc_rand((uint32_t)(t & 0x7FFFFFFF), priv);
            break;
        case 'RS':{
            uint8_t r[32];
            mode_short_r_brute(r, priv);
            break;
        }
        case 'Z': case 'K': case 'X': case 'P':
            // Reserved - fall through to default
        default:
            mode_h36(t, priv);
            break;
    }

    // Write 32 bytes to output
    for(int b = 0; b < 32; b++){
        d_out[idx * 32 + b] = priv[b];
    }
}

void run_mode(char mode_char,
    uint64_t ts_start, uint64_t ts_end,
    uint32_t seed_start, uint32_t seed_end,
    const char *output_path, int show_progress)
{
    uint64_t seed_range = (uint64_t)(seed_end - seed_start) + 1;
    uint64_t ts_range = ts_end - ts_start + 1;
    uint64_t total_keys = ts_range * (uint64_t)seed_range;
    uint64_t processed = 0;
    if(run_start_time == 0) run_start_time = time(NULL);
    int gpu_id = 0;
    cudaSetDevice(gpu_id);
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, gpu_id);
    printf("GPU: %s, total keys: %llu (ts_range=%llu, seed_range=%llu)\n",
           prop.name, (unsigned long long)total_keys,
           (unsigned long long)ts_range, (unsigned long long)seed_range);

    // Allocate device buffer
    size_t buf_size = (size_t)KEYS_PER_BATCH * 32;
    uint8_t *d_priv = NULL;
    cudaError_t err = cudaMalloc(&d_priv, buf_size);
    if(err != cudaSuccess){
        printf("cudaMalloc(%zu bytes) failed: %s\n", buf_size, cudaGetErrorString(err));
        // Fallback: smaller buffer
        buf_size = KEYS_PER_KERNEL * 32;
        err = cudaMalloc(&d_priv, buf_size);
        if(err != cudaSuccess){
            printf("Even small alloc failed: %s\n", cudaGetErrorString(err));
            return;
        }
    }
    uint8_t *h_priv = (uint8_t*)malloc(buf_size);
    if(!h_priv){ printf("host malloc failed\n"); cudaFree(d_priv); return; }

    while(processed < total_keys){
        // Inner loop: launch kernels until all keys in this batch are done
        uint64_t left = total_keys - processed;
        uint64_t sub_batch = left < KEYS_PER_KERNEL ? left : KEYS_PER_KERNEL;

        uint64_t base_ts = ts_start + (processed / seed_range);
        uint32_t base_seed = seed_start + (uint32_t)(processed % seed_range);

        // Launch GPU kernel
        unsigned int blocks = (unsigned int)((sub_batch + THREADS - 1) / THREADS);
        if(blocks > 65535u) blocks = 65535u;

        gen_keys_kernel<<<blocks, THREADS>>>(
            mode_char, base_ts, base_seed, seed_range, d_priv, sub_batch);

        cudaDeviceSynchronize();

        // Write sub_batch to file
        cudaMemcpy(h_priv, d_priv, sub_batch * 32, cudaMemcpyDeviceToHost);
        FILE *f = fopen(output_path, "ab");
        if(!f) f = fopen(output_path, "wb");
        if(f){ fwrite(h_priv, 1, sub_batch * 32, f); fclose(f); }

        processed += sub_batch;

        if(show_progress || (processed & 0xFFFFFFF) == 0){
            double pct = 100.0 * (double)processed / (double)total_keys;
            uint64_t sec_elapsed = time(NULL) - run_start_time;
            double keys_per_sec = sec_elapsed > 0 ? (double)processed / sec_elapsed : 0;
            time_t now = time(NULL);
            int elapsed = (int)(now - run_start_time);
            int eta = (int)((total_keys - processed) / (keys_per_sec > 0 ? keys_per_sec : 1));
            int eta_h = eta / 3600, eta_m = (eta / 60) % 60, eta_s = eta % 60;
            fprintf(stderr, "\r%c: %.4f%% | %llu/Mkeys | %3d:%02d elapsed | ETA %3d:%02d:%02d | %.1f M/s",
                mode_char, pct,
                (unsigned long long)(processed / 1000000),
                elapsed/60, elapsed%60,
                eta_h, eta_m, eta_s,
                keys_per_sec / 1e6);
            fflush(stderr);
        }

        if(check_stop_signal()){
            printf("\nSTOP signal received.\n");
            break;
        }
    }

    printf("\nMode %c complete: %llu keys -> %s\n",
           mode_char, (unsigned long long)processed, output_path);

    cudaFree(d_priv);
    free(h_priv);
}

void run_autocycle(void){
    printf("SeedHammer auto-cycle: %zu modes over full 2009-2012 range\n",
           NUM_MODES);
    printf("Each mode runs L1-L4 via the kernel variant logic.\n");
    printf("Expected keys per mode: %llu (4 years * seeds)\n",
           (unsigned long long)((uint64_t)0x100000000ULL * 1461ULL));

    int start_mode = 0;
    uint64_t dummy_offset = 0;
    char saved_mode[8] = {0};

    if(load_checkpoint(saved_mode, &dummy_offset)){
        for(size_t i = 0; i < NUM_MODES; i++){
            if(strcmp(saved_mode, MODES[i]) == 0){
                start_mode = (int)i;
                printf("Resuming from mode %s\n", MODES[i]);
                break;
            }
        }
    }

    uint64_t ts_start = 1230768000; // Jan 1, 2009
    uint64_t ts_end   = 1356998400; // Dec 31, 2012

    for(int m = start_mode; m < (int)NUM_MODES; m++){
        if(check_stop_signal()){
            printf("\nSTOP signal received. Halting.\n");
            return;
        }

        printf("\n[%d/%zu] Mode %s (ts=%llu..%llu, seeds=0..0xFFFFFFFF)...\n",
               m+1, NUM_MODES, MODES[m],
               (unsigned long long)ts_start, (unsigned long long)ts_end);
        fflush(stdout);

        char output_path[64];
        snprintf(output_path, sizeof(output_path), "keys_%s.bin", MODES[m]);

        run_mode(MODES[m][0],
                 ts_start, ts_end,
                 0, 0xFFFFFFFF,
                 output_path, 0);

        save_checkpoint(m, 0);
    }

    printf("\n=== All %zu modes complete ===\n", NUM_MODES);
    printf("Total keys generated: ~%llu\n",
           (unsigned long long)(NUM_MODES * ((uint64_t)0x100000000ULL * 1461ULL)));
}

int main(int argc, char *argv[]){
    if(argc > 1 && (strcmp(argv[1],"AUTO")==0 || strcmp(argv[1],"ALL")==0)){
        run_autocycle();
        return 0;
    }

    if(argc < 2){
        fprintf(stderr, "Usage: %s <mode> [options]\n", argv[0]);
        fprintf(stderr, "Modes: H M R C J W B A D E L S T F G Q Y M2 R2 CQ LC RS Z K X P\n");
        fprintf(stderr, "       ALL or AUTO = autonomous cycle through all modes\n");
        return 1;
    }

    int scan_mode = 0;
    char mode_char = argv[1][0];
    uint64_t ts_start = 1288834970;
    uint64_t ts_end   = 1356998400;
    uint32_t seed_start = 0;
    uint32_t seed_end   = 0xFFFFFFFF;
    const char *output_path = "keys.bin";
    int show_progress = 0;
    const char *targets_path = "/vaultwatch/patoshi_h160.bin";

    for(int i = 2; i < argc; i++){
        if(!strcmp(argv[i],"--ts-start") && i+1 < argc) ts_start = strtoull(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--ts-end") && i+1 < argc) ts_end = strtoull(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--seed-start") && i+1 < argc) seed_start = (uint32_t)strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--seed-end") && i+1 < argc) seed_end = (uint32_t)strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--output") && i+1 < argc) output_path = argv[++i];
        else if(!strcmp(argv[i],"--progress")) show_progress = 1;
        else if(!strcmp(argv[i],"--scan")) scan_mode = 1;
        else if(!strcmp(argv[i],"--targets") && i+1 < argc) targets_path = argv[++i];
    }

    if(scan_mode) {
        // ========================================================
        // --scan MODE: FULLY INTEGRATED generate + verify on GPU
        // Single process, single GPU kernel that does both.
        // No fork, no pipe, no intermediate files.
        // ========================================================
        printf("SeedHammer-Scan (GPU integrated) mode %c: ts=%lu..%lu\n",
               mode_char, ts_start, ts_end);
        fflush(stdout);

        // Load patoshi H160 targets and build bloom filter
        FILE *pf = fopen(targets_path, "rb");
        if (!pf) { fprintf(stderr, "ERROR: %s not found\n", targets_path); return 1; }
        fseek(pf, 0, SEEK_END);
        long pf_size = ftell(pf);
        rewind(pf);
        uint32_t n_patoshi = pf_size / 20;
        uint8_t *patoshi_h160s = (uint8_t*)malloc(pf_size);
        if (!patoshi_h160s) { fprintf(stderr, "OOM\n"); return 1; }
        fread(patoshi_h160s, 1, pf_size, pf);
        fclose(pf);
        printf("Loaded %u Patoshi H160 targets\n", n_patoshi);

        // Build bloom filter bits
        uint32_t bloom_bits = 1 << 18; // 262144 bits = 32KB
        uint8_t *bloom_data = (uint8_t*)calloc(1, bloom_bits/8);
        if (!bloom_data) { fprintf(stderr, "OOM bloom\n"); free(patoshi_h160s); return 1; }
        uint32_t mask = bloom_bits - 1;
        for(uint32_t i=0; i<n_patoshi; i++){
            const uint8_t *h = patoshi_h160s + i*20;
            uint32_t h7[7] = {
                ((uint32_t)h[0]<<24|h[1]<<16|h[2]<<8|h[3]) & mask,
                ((uint32_t)h[4]<<24|h[5]<<16|h[6]<<8|h[7]) & mask,
                ((uint32_t)h[8]<<24|h[9]<<16|h[10]<<8|h[11]) & mask,
                ((uint32_t)h[12]<<24|h[13]<<16|h[14]<<8|h[15]) & mask,
                ((uint32_t)h[16]<<24|h[17]<<16|h[18]<<8|h[19]) & mask,
                ((uint32_t)(h[0]^h[10])<<24|(h[1]^h[11])<<16|(h[2]^h[12])<<8|(h[3]^h[13])) & mask,
                ((uint32_t)(h[4]^h[14])<<24|(h[5]^h[15])<<16|(h[6]^h[16])<<8|(h[7]^h[17])) & mask
            };
            for(int j=0;j<7;j++){uint32_t b=h7[j];bloom_data[b>>3]|=(1<<(b&7));}
        }
        printf("Bloom filter: %u bits\n", bloom_bits);

        cudaSetDevice(0);
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, 0);
        int sm_count = prop.multiProcessorCount;
        printf("GPU: %s (%d SMs)\n", prop.name, sm_count);

        uint64_t seed_range;
        if(seed_end == UINT32_MAX) seed_range = (uint64_t)UINT32_MAX + 1;
        else seed_range = (uint64_t)(seed_end - seed_start) + 1;
        uint64_t ts_range = ts_end - ts_start + 1;
        uint64_t total_keys = ts_range * seed_range;

        // Allocate device memory
        const uint64_t BATCH = 16 * 1024 * 1024; // 16M keys per batch
        uint8_t *d_keys, *d_found_key;
        uint64_t *d_found_count;
        cudaMalloc(&d_keys, BATCH * 32);
        cudaMalloc(&d_found_key, 256 * 52); // first 256 found
        cudaMalloc(&d_found_count, 8);

        // Upload bloom & patoshi to __constant__ or global memory on device
        // We use cudaMemcpyToSymbol for device variables
        uint32_t h_bloom_bits = bloom_bits;
        cudaMemcpyToSymbol(BLOOM_BITS, &h_bloom_bits, sizeof(uint32_t));
        cudaMemcpyToSymbol(BLOOM_DATA, bloom_data, bloom_bits/8);
        cudaMemcpyToSymbol(N_PATOSHI, &n_patoshi, sizeof(uint32_t));
        cudaMemcpyToSymbol(PATOSHI_H160S, patoshi_h160s, pf_size);

        printf("Total keys to scan: %llu\n", (unsigned long long)total_keys);
        printf("Batch size: %llu keys\n", (unsigned long long)BATCH);
        printf("Memory per batch: %llu MB\n", (unsigned long long)(BATCH * 32 / 1024 / 1024));
        fflush(stdout);

        uint64_t processed = 0;
        uint64_t total_found = 0;
        if(run_start_time == 0) run_start_time = time(NULL);

        while(processed < total_keys) {
            uint64_t left = total_keys - processed;
            uint64_t this_batch = left < BATCH ? left : BATCH;

            uint64_t base_ts = ts_start + (processed / seed_range);
            uint32_t base_seed = seed_start + (uint32_t)(processed % seed_range);

            // Launch generation kernel
            unsigned int blk = (unsigned int)((this_batch + THREADS - 1) / THREADS);
            if(blk > 65535u) blk = 65535u;

            gen_keys_kernel<<<blk, THREADS>>>(
                mode_char, base_ts, base_seed, seed_range, d_keys, this_batch);
            cudaDeviceSynchronize();

            // Reset found counter
            uint64_t zero = 0;
            cudaMemcpy(d_found_count, &zero, 8, cudaMemcpyHostToDevice);

            // Launch scan kernel (EC + SHA + RIPEMD + bloom + exact check)
            scan_kernel<<<blk, 256>>>(
                d_keys, this_batch, d_found_count, d_found_key);
            cudaDeviceSynchronize();

            // Check results
            uint64_t found_this;
            cudaMemcpy(&found_this, d_found_count, 8, cudaMemcpyDeviceToHost);

            if(found_this > 0) {
                uint8_t found_data[256 * 52];
                size_t copy_size = found_this * 52;
                if(copy_size > sizeof(found_data)) copy_size = sizeof(found_data);
                cudaMemcpy(found_data, d_found_key, copy_size, cudaMemcpyDeviceToHost);

                for(uint64_t f = 0; f < found_this && f < 256; f++) {
                    uint8_t *pk = found_data + f * 52;
                    uint8_t *h160 = found_data + f * 52 + 32;
                    time_t t = time(NULL);
                    fprintf(stdout, "\n*** FOUND! ***\nprivkey: ");
                    for(int b=0;b<32;b++) fprintf(stdout, "%02x", pk[b]);
                    fprintf(stdout, "\nh160: ");
                    for(int b=0;b<20;b++) fprintf(stdout, "%02x", h160[b]);
                    fprintf(stdout, "\ntime=%s", ctime(&t));
                    fflush(stdout);

                    // Also write to found.txt
                    FILE *fl = fopen("found.txt", "a");
                    if(fl) {
                        fprintf(fl, "[SCAN] key=");
                        for(int b=0;b<32;b++) fprintf(fl, "%02x", pk[b]);
                        fprintf(fl, " h160=");
                        for(int b=0;b<20;b++) fprintf(fl, "%02x", h160[b]);
                        fprintf(fl, "\n");
                        fclose(fl);
                    }
                }
                total_found += found_this;
                fprintf(stderr, "\n*** FOUND %llu KEYS! ***\n", (unsigned long long)found_this);
            }

            processed += this_batch;

            if(show_progress || (processed & 0xFFFFFFF) == 0) {
                double pct = 100.0 * (double)processed / (double)total_keys;
                uint64_t sec_elapsed = time(NULL) - run_start_time;
                double keys_per_sec = sec_elapsed > 0 ? (double)processed / sec_elapsed : 0;
                int elapsed = (int)(time(NULL) - run_start_time);
                int eta_s = (int)((total_keys - processed) / (keys_per_sec > 0 ? keys_per_sec : 1));
                int eta_h = eta_s / 3600, eta_m = (eta_s / 60) % 60, ss = eta_s % 60;
                fprintf(stderr, "\r%c: %.2f%% | %llu/Mkeys | %d:%02d el | ETA %d:%02d:%02d | %.1f M/s | found=%llu",
                    mode_char, pct,
                    (unsigned long long)(processed / 1000000),
                    elapsed/60, elapsed%60,
                    eta_h, eta_m, ss,
                    keys_per_sec / 1e6,
                    (unsigned long long)total_found);
                fflush(stderr);
            }

            if(total_found > 0) {
                fprintf(stderr, "\n[scan] FOUND %llu keys. Stopping generation.\n",
                        (unsigned long long)total_found);
                break;
            }
        }

        printf("\n[scan] Scan complete. %llu keys checked, %llu found.\n",
               (unsigned long long)processed, (unsigned long long)total_found);

        cudaFree(d_keys);
        cudaFree(d_found_key);
        cudaFree(d_found_count);
        free(patoshi_h160s);
        free(bloom_data);
        return 0;
    }

    printf("SeedHammer mode %c: ts=%lu..%lu seed=%u..%u -> %s\n",
           mode_char, ts_start, ts_end, seed_start, seed_end, output_path);

    run_mode(mode_char, ts_start, ts_end, seed_start, seed_end, output_path, show_progress);
    return 0;
}
