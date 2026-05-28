// SeedHammer main.cu — FUSED Standalone Mode
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <cuda_runtime.h>

#define THREADS 512

#include "hypothesis_gpu.cu"
#include "ec_jacobian.h"
#include "math256.h"
#include "scan_kernel.cu"

time_t run_start_time = 0;
uint64_t batch_size = 0;

int main(int argc, char **argv) {
    if(argc < 2) return 1;
    char mode_char = argv[1][0];
    uint64_t ts_start = 0, ts_end = 0;
    uint32_t seed_start = 0, seed_end = UINT32_MAX;
    int show_progress = 0, scan_mode = 0;

    for(int i=2; i<argc; i++) {
        if(!strcmp(argv[i],"--ts-start") && i+1 < argc) ts_start = strtoull(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--ts-end") && i+1 < argc) ts_end = strtoull(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--seed-start") && i+1 < argc) seed_start = (uint32_t)strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--seed-end") && i+1 < argc) seed_end = (uint32_t)strtoul(argv[++i],NULL,10);
        else if(!strcmp(argv[i],"--progress")) show_progress = 1;
        else if(!strcmp(argv[i],"--scan")) scan_mode = 1;
        else if(!strcmp(argv[i],"--batch") && i+1 < argc) batch_size = strtoull(argv[++i],NULL,10);
    }

    if(scan_mode) {
        printf("SeedHammer-Scan (FUSED) mode %c: ts=%lu..%lu\n", mode_char, ts_start, ts_end);
        
        uint32_t n_patoshi = 8;
        uint8_t *patoshi_h160s = (uint8_t*)malloc(8*20);
        uint8_t internal_targets[8*20] = {
            0x14,0x4d,0xe4,0x97,0x1a,0x30,0x9f,0x65,0x6a,0x25,0x98,0xf9,0x74,0x63,0xe2,0x1f,0xc4,0xe6,0x0f,0xe1,
            0xb3,0x46,0xa3,0xbc,0xe0,0xe6,0xf5,0xe8,0xd0,0x1b,0x6a,0x73,0x9c,0x05,0x01,0x49,0x2d,0xd5,0xf5,0xeb,
            0xbc,0x30,0xaf,0x9c,0xfb,0xa5,0x5e,0xa6,0x13,0x74,0xf9,0x8b,0x3e,0xf3,0x18,0x55,0x70,0xb7,0x98,0x18,
            0x18,0xf2,0xdf,0x2f,0x55,0xe0,0xdd,0x03,0x98,0x2b,0x35,0x8b,0x5f,0xb7,0x49,0x1d,0x98,0xae,0x94,0xaf,
            0x88,0xbb,0x33,0x3d,0x5d,0xff,0xea,0x68,0x28,0xbd,0x86,0x8e,0x3a,0xe5,0x70,0x09,0x75,0xc8,0xfa,0x4c,
            0xe0,0xbe,0x57,0x0f,0x09,0x09,0xa4,0xee,0xdc,0x8e,0x82,0x65,0x2c,0x7f,0x39,0x10,0x38,0xf0,0x0c,0xcc,
            0x30,0x59,0xc8,0x38,0x4e,0x7e,0xbf,0x41,0xe0,0x3c,0x0d,0xa3,0xfa,0x7e,0x69,0xfa,0xb4,0x07,0x64,0x9d,
            0x59,0x2f,0xc3,0x99,0x00,0x26,0x33,0x4c,0x8c,0x6f,0xb2,0xb9,0xda,0x45,0x71,0x79,0xcd,0xb5,0xc6,0x88
        };
        memcpy(patoshi_h160s, internal_targets, 8*20);

        uint32_t bloom_bits = 1 << 18;
        uint8_t *bloom_data = (uint8_t*)calloc(1, bloom_bits/8);
        uint32_t mask = bloom_bits - 1;
        for(uint32_t i=0; i<n_patoshi; i++){
            const uint8_t *h = patoshi_h160s + i*20;
            uint32_t h7[7] = { ((uint32_t)h[0]<<24|h[1]<<16|h[2]<<8|h[3])&mask, ((uint32_t)h[4]<<24|h[5]<<16|h[6]<<8|h[7])&mask, ((uint32_t)h[8]<<24|h[9]<<16|h[10]<<8|h[11])&mask, ((uint32_t)h[12]<<24|h[13]<<16|h[14]<<8|h[15])&mask, ((uint32_t)h[16]<<24|h[17]<<16|h[18]<<8|h[19])&mask, (h[0]*2654435761u+h[1]*2246822519u+h[2])&mask, (h[3]*3266489917u+h[4]*668265263u+h[5])&mask };
            for(int j=0;j<7;j++) bloom_data[h7[j]>>3] |= (1<<(h7[j]&7));
        }

        cudaSetDevice(0);
        uint64_t seed_range = (uint64_t)(seed_end - seed_start) + 1;
        uint64_t ts_range = ts_end - ts_start + 1;
        uint64_t total_keys = ts_range * seed_range;

        if(batch_size == 0) batch_size = 8 * 1024 * 1024; // Balanced for fused kernel
        const uint64_t BATCH = batch_size;
        uint8_t *d_found_key;
        unsigned long long *d_found_count;
        cudaMalloc(&d_found_key, 256 * 52);
        cudaMalloc(&d_found_count, 8);

        uint32_t h_bloom_bits = bloom_bits;
        cudaMemcpyToSymbol(BLOOM_BITS, &h_bloom_bits, sizeof(uint32_t));
        cudaMemcpyToSymbol(BLOOM_DATA, bloom_data, bloom_bits/8);
        cudaMemcpyToSymbol(N_PATOSHI, &n_patoshi, sizeof(uint32_t));
        cudaMemcpyToSymbol(PATOSHI_H160S, patoshi_h160s, n_patoshi * 20);

        uint64_t processed = 0;
        run_start_time = time(NULL);

        while(processed < total_keys) {
            uint64_t this_batch = (total_keys - processed) < BATCH ? (total_keys - processed) : BATCH;
            uint64_t base_ts = ts_start + (processed / seed_range);
            uint32_t base_seed = seed_start + (uint32_t)(processed % seed_range);

            unsigned int blk = (unsigned int)((this_batch + THREADS - 1) / THREADS);
            unsigned long long zero = 0;
            cudaMemcpy(d_found_count, &zero, 8, cudaMemcpyHostToDevice);
            
            fused_scan_kernel<<<blk, THREADS>>>(mode_char, base_ts, base_seed, seed_range, this_batch, d_found_count, d_found_key);
            cudaDeviceSynchronize();

            unsigned long long found_this;
            cudaMemcpy(&found_this, d_found_count, 8, cudaMemcpyDeviceToHost);

            if(found_this > 0) {
                uint8_t found_data[52];
                cudaMemcpy(found_data, d_found_key, 52, cudaMemcpyDeviceToHost);
                printf("\n*** FOUND! ***\nPrivkey: "); for(int i=0;i<32;i++) printf("%02x", found_data[i]);
                printf("\nH160: "); for(int i=0;i<20;i++) printf("%02x", found_data[32+i]);
                printf("\n"); exit(0);
            }

            processed += this_batch;
            if(show_progress || (processed & 0xFFFFFF) == 0) {
                double pct = 100.0 * (double)processed / (double)total_keys;
                double kps = (double)processed / (time(NULL) - run_start_time + 1);
                fprintf(stderr, "\r%c: %.2f%% | %llu Mkeys | %.1f M/s", mode_char, pct, (unsigned long long)(processed/1000000), kps/1000000.0);
            }
        }
    }
    return 0;
}
