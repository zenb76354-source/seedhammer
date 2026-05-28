// ================================================================
// HIGH-PERFORMANCE FUSED Scan Kernel for SeedHammer
// Optimized for B200: Sequential Addition + PTX Assembly
// ================================================================

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

__device__ __constant__ uint32_t SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// --- Optimized PTX Math for 256-bit Addition ---
__device__ __forceinline__ void add256_ptx(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    asm("add.cc.u64 %0, %4, %8;\n\t"
        "addc.cc.u64 %1, %5, %9;\n\t"
        "addc.cc.u64 %2, %6, %10;\n\t"
        "addc.u64 %3, %7, %11;"
        : "=l"(r[0]), "=l"(r[1]), "=l"(r[2]), "=l"(r[3])
        : "l"(a[0]), "l"(a[1]), "l"(a[2]), "l"(a[3]),
          "l"(b[0]), "l"(b[1]), "l"(b[2]), "l"(b[3]));
}

// --- Optimized SHA256 (Minimal Registers) ---
__device__ void sha256_fast(const uint8_t *data, uint32_t len, uint8_t hash[32]) {
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint32_t w[64];
    // Inline compression for speed
    for(int i=0;i<16;i++) w[i]=(data[i*4]<<24)|(data[i*4+1]<<16)|(data[i*4+2]<<8)|data[i*4+3];
    // ... Simplified for brevitiy in this step, full implementation needed for 2B/s
    sha256_opt(data, len, hash); 
}

__device__ uint32_t BLOOM_BITS;
__device__ uint8_t BLOOM_DATA[262144]; 
__device__ uint8_t PATOSHI_H160S[21953*20];
__device__ uint32_t N_PATOSHI;

__device__ static int bloom_test_d(const uint8_t h160[20]) {
    uint32_t m = BLOOM_BITS - 1;
    uint32_t h0 = ((uint32_t)h160[0]<<24|h160[1]<<16|h160[2]<<8|h160[3]) & m;
    if(!(BLOOM_DATA[h0>>3]&(1<<(h0&7)))) return 0;
    uint32_t h1 = ((uint32_t)h160[4]<<24|h160[5]<<16|h160[6]<<8|h160[7]) & m;
    if(!(BLOOM_DATA[h1>>3]&(1<<(h1&7)))) return 0;
    return 1; // Simplified bloom for speed
}

// --- FUSED KERNEL WITH DIFFERENTIAL ADDITION ---
__global__ void super_scan_kernel(char mode, uint64_t base_ts, uint32_t base_seed, uint64_t seed_range, uint64_t n, unsigned long long *found_count, uint8_t *found_key_out) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if(idx >= n) return;
    
    // 1. Initial Point Calculation (Once per thread)
    uint64_t ts = base_ts + (idx / seed_range);
    uint32_t seed = base_seed + (uint32_t)(idx % seed_range);
    uint8_t pk[32];
    mode_h36(ts, pk);

    JacobianPoint P;
    uint64_t k[4];
    privkey_bytes_to_scalar(pk, k);
    point_mul_g(&P, k);

    // 2. Sequential Scan (Differential Addition)
    // For mode 'H', keys are ts, ts+1, ts+2...
    // We can use P = P + G instead of full multiplication
    JacobianPoint G;
    point_set_g(&G);

    for(int step=0; step<1; step++) { // Start with 1 step to verify, then increase
        uint64_t aff_x[4], aff_y[4];
        point_to_affine(&P, aff_x, aff_y);
        
        uint8_t pub_comp[33], sha32[32], h160[20];
        pub_comp[0] = (aff_y[0] & 1) ? 0x03 : 0x02;
        for(int i=0;i<32;i++) pub_comp[1+i] = (aff_x[3-(i/8)] >> ((i%8)*8)) & 0xFF;

        sha256_opt(pub_comp, 33, sha32);
        ripemd160_opt(sha32, 32, h160);

        if(bloom_test_d(h160)) {
            for(uint32_t i=0;i<N_PATOSHI;i++){
                int eq=1; for(int j=0;j<20;j++)if(h160[j]!=PATOSHI_H160S[i*20+j]){eq=0;break;}
                if(eq){
                    unsigned long long pos = atomicAdd(found_count, 1ULL);
                    if(pos < 256) {
                        uint8_t *dst = found_key_out + pos * 52;
                        for(int b=0;b<32;b++) dst[b]=pk[b]; // Note: need to adjust pk for steps
                        for(int b=0;b<20;b++) dst[32+b]=h160[b];
                    }
                }
            }
        }
        // point_add(&P, &P, &G); // Next key: ts + 1
    }
}
