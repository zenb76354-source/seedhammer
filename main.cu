// SeedHammer main.cu — Auto-pipeline orchestrator
// Compile: make (uses hypothesis_gpu.cu for all mode functions)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cuda_runtime.h>

// Hypotheses generator functions
#include "hypothesis_gpu.cu"
// SECP256K1_N defined in hypothesis_gpu.cu


static const char *MODES[] = {
    "H","M","R","C","J","W","B","A","D","E",
    "L","S","T","F","G","Q","Y","M2","R2","CQ",
    "LC","RS","Z","K","X","P"
};
#define NUM_MODES (sizeof(MODES)/sizeof(MODES[0]))
#define KEYS_PER_BATCH (1024ULL * 1024 * 8) // 8M keys per batch
#define CHECKPOINT_FILE "autocycle_checkpoint.txt"
#define STOP_FLAG_FILE "STOP"

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

// Forward declaration
void run_mode(char mode_char,
    uint64_t ts_start, uint64_t ts_end,
    uint32_t seed_start, uint32_t seed_end,
    const char *output_path, int show_progress);

void run_autocycle(void){
    printf("SeedHammer auto-cycle: %zu modes, %llu keys/batch\n",
           NUM_MODES, (unsigned long long)KEYS_PER_BATCH);

    int start_mode = 0;
    uint64_t start_offset = 0;
    char saved_mode[8] = {0};

    if(load_checkpoint(saved_mode, &start_offset)){
        for(size_t i = 0; i < NUM_MODES; i++){
            if(strcmp(saved_mode, MODES[i]) == 0){
                start_mode = (int)i;
                printf("Resuming from mode %s at offset %lu\n",
                       MODES[i], (unsigned long)start_offset);
                break;
            }
        }
    }

    uint64_t ts_start = 1230768000; // Jan 1, 2009
    uint64_t ts_end   = 1356998400; // Dec 31, 2012

    for(int cycle = 0; ; cycle++){
        for(int m = start_mode; m < (int)NUM_MODES; m++){
            if(check_stop_signal()){
                printf("\nSTOP signal received. Halting.\n");
                return;
            }

            printf("\n[Cycle %d] Mode %s starting...\n", cycle+1, MODES[m]);
            fflush(stdout);

            char output_path[64];
            snprintf(output_path, sizeof(output_path), "keys_%s.bin", MODES[m]);

            run_mode(MODES[m][0],
                     ts_start + (uint64_t)cycle * 86400,
                     ts_end,
                     0, 0xFFFFFFFF,
                     output_path, 1);

            save_checkpoint(m, 0);
        }
        start_mode = 0;
        printf("\n[Cycle %d complete] Restarting...\n", cycle+1);
    }
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
