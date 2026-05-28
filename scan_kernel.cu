// ================================================================
// WARP-PARALLEL ULTRA KERNEL for engine
// Strategy: PTX Assembly + 7-hash bloom + differential addition (16x)
// Target: 2.0+ Billion Keys/Second on B200
// ================================================================

#include <cuda_runtime.h>
#include <stdint.h>

// ==================== CONSTANT MEMORY ====================
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

__device__ __constant__ uint32_t DEV_BLOOM_BITS;
__device__ __constant__ uint8_t  DEV_BLOOM_DATA[262144];
__device__ __constant__ uint8_t  DEV_TARGETS[51*20];
__device__ __constant__ uint32_t DEV_N_TARGETS;

// ==================== UTILITY ====================
#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

// ==================== PTX: 256-bit ADD ====================
__device__ __forceinline__ void add256_ptx(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    asm("add.cc.u32 %0, %8, %16;\n\t"
        "addc.cc.u32 %1, %9, %17;\n\t"
        "addc.cc.u32 %2, %10, %18;\n\t"
        "addc.cc.u32 %3, %11, %19;\n\t"
        "addc.cc.u32 %4, %12, %20;\n\t"
        "addc.cc.u32 %5, %13, %21;\n\t"
        "addc.cc.u32 %6, %14, %22;\n\t"
        "addc.u32 %7, %15, %23;"
        : "=r"(r[0]),"=r"(r[1]),"=r"(r[2]),"=r"(r[3]),"=r"(r[4]),"=r"(r[5]),"=r"(r[6]),"=r"(r[7])
        : "r"(a[0]),"r"(a[1]),"r"(a[2]),"r"(a[3]),"r"(a[4]),"r"(a[5]),"r"(a[6]),"r"(a[7]),
          "r"(b[0]),"r"(b[1]),"r"(b[2]),"r"(b[3]),"r"(b[4]),"r"(b[5]),"r"(b[6]),"r"(b[7]));
}

// ==================== SHA256 ====================
__device__ void sha256_compress_fast(uint32_t state[8], const uint32_t block[16]) {
    uint32_t W[64], a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7],t1,t2;
    for(int i=0;i<16;i++)W[i]=block[i];
    for(int i=16;i<64;i++){
        uint32_t s0=ROTL(W[i-15],7)^ROTL(W[i-15],18)^(W[i-15]>>3);
        uint32_t s1=ROTL(W[i-2],17)^ROTL(W[i-2],19)^(W[i-2]>>10);
        W[i]=W[i-16]+s0+W[i-7]+s1;
    }
    for(int i=0;i<64;i++){
        uint32_t S1=ROTL(e,6)^ROTL(e,11)^ROTL(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        t1=h+S1+ch+SHA_K[i]+W[i];
        uint32_t S0=ROTL(a,2)^ROTL(a,13)^ROTL(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        t2=S0+maj; h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

__device__ void sha256_fast(const uint8_t *data, uint32_t len, uint8_t hash[32]) {
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint32_t blk[16]; uint32_t pos=0;
    for(;pos+64<=len;pos+=64){
        for(int i=0;i<16;i++)blk[i]=(data[pos+i*4]<<24)|(data[pos+i*4+1]<<16)|(data[pos+i*4+2]<<8)|data[pos+i*4+3];
        sha256_compress_fast(s,blk);
    }
    uint8_t last[128]; uint32_t rem=len-pos; for(uint32_t i=0;i<rem;i++)last[i]=data[pos+i]; last[rem]=0x80;
    uint32_t last_len=rem+1;
    if(last_len>56){while(last_len<128)last[last_len++]=0; for(int i=0;i<16;i++)blk[i]=(last[i*4]<<24)|(last[i*4+1]<<16)|(last[i*4+2]<<8)|last[i*4+3]; sha256_compress_fast(s,blk); last_len=0;}
    while(last_len<56)last[last_len++]=0;
    uint64_t bitlen=(uint64_t)len*8; for(int i=0;i<8;i++)last[63-i]=(uint8_t)(bitlen>>(i*8));
    for(int i=0;i<16;i++)blk[i]=(last[i*4]<<24)|(last[i*4+1]<<16)|(last[i*4+2]<<8)|last[i*4+3];
    sha256_compress_fast(s,blk);
    for(int i=0;i<8;i++){hash[i*4]=(uint8_t)(s[i]>>24);hash[i*4+1]=(uint8_t)(s[i]>>16);hash[i*4+2]=(uint8_t)(s[i]>>8);hash[i*4+3]=(uint8_t)(s[i]);}
}

// ==================== RIPEMD160 ====================
__device__ void ripemd160_fast(const uint8_t *data, uint32_t len, uint8_t hash[20]) {
    uint32_t st[5]={0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0},blk[16];
    const uint32_t rk[5]={0,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
    const uint32_t rkp[5]={0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0};
    for(uint32_t p=0;p+64<=len;p+=64){
        for(int i=0;i<16;i++)blk[i]=((uint32_t)data[p+i*4+3]<<24)|((uint32_t)data[p+i*4+2]<<16)|((uint32_t)data[p+i*4+1]<<8)|data[p+i*4];
        uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],ap=a,bp=b,cp=c,dp=d,ep=e;
        for(int r=0;r<5;r++)for(int s=0;s<16;s++){
            uint32_t f,fp;
            if(r==0){f=(b&c)|(~b&d);fp=bp^(cp|~dp);}else if(r==1){f=b^c^d;fp=(bp&dp)|(cp&~dp);}else if(r==2){f=(c&~d)|(b&d);fp=bp^cp^dp;}else if(r==3){f=(b&c)|(~b&d);fp=(cp&~dp)|(bp&dp);}else{f=b^(c|~d);fp=bp^(cp|~dp);}
            uint32_t T=ROTL(a+f+blk[s]+rk[r],10)+e;e=d;d=ROTL(c,10);c=b;b=a;a=T;
            T=ROTL(ap+fp+blk[s]+rkp[r],10)+ep;ep=dp;dp=ROTL(cp,10);cp=bp;bp=ap;ap=T;
        }
        st[0]+=a;st[1]+=b;st[2]+=c;st[3]+=d;st[4]+=e;
    }
    for(int i=0;i<5;i++){hash[i*4]=st[i]&0xFF;hash[i*4+1]=(st[i]>>8)&0xFF;hash[i*4+2]=(st[i]>>16)&0xFF;hash[i*4+3]=(st[i]>>24)&0xFF;}
}

// ==================== BLOOM TEST (7 XOR hashes) ====================
__device__ static int bloom_test_fast(const uint8_t h160[20]) {
    uint32_t m = DEV_BLOOM_BITS - 1;
    uint32_t h7[7] = {
        ((uint32_t)h160[0]<<24|h160[1]<<16|h160[2]<<8|h160[3]) & m,
        ((uint32_t)h160[4]<<24|h160[5]<<16|h160[6]<<8|h160[7]) & m,
        ((uint32_t)h160[8]<<24|h160[9]<<16|h160[10]<<8|h160[11]) & m,
        ((uint32_t)h160[12]<<24|h160[13]<<16|h160[14]<<8|h160[15]) & m,
        ((uint32_t)h160[16]<<24|h160[17]<<16|h160[18]<<8|h160[19]) & m,
        ((uint32_t)(h160[0]^h160[10])<<24|(h160[1]^h160[11])<<16|(h160[2]^h160[12])<<8|(h160[3]^h160[13])) & m,
        ((uint32_t)(h160[4]^h160[14])<<24|(h160[5]^h160[15])<<16|(h160[6]^h160[16])<<8|(h160[7]^h160[17])) & m
    };
    for(int i=0;i<7;i++){
        uint32_t b=h7[i];
        if(!(DEV_BLOOM_DATA[b>>3]&(1<<(b&7)))) return 0;
    }
    return 1;
}

// ==================== EXACT MATCH ====================
__device__ static int exact_match_fast(const uint8_t h160[20]) {
    for(uint32_t i=0;i<DEV_N_TARGETS;i++){
        int eq=1;
        for(int j=0;j<20;j++)if(h160[j]!=DEV_TARGETS[i*20+j]){eq=0;break;}
        if(eq) return 1;
    }
    return 0;
}

// ==================== MAIN KERNEL ====================
__global__ void super_scan_kernel(
    char        mode,
    uint64_t    base_ts,
    uint32_t    base_seed,
    uint64_t    seed_range,
    uint64_t    n,
    uint64_t   *found_count,
    uint8_t    *found_key_out
) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if(idx >= n) return;

    // === STEP 1: Generate private key ===
    uint64_t ts = base_ts + (idx / seed_range);
    uint32_t seed_off = base_seed + (uint32_t)(idx % seed_range);
    uint8_t pk[32];
    switch (mode) {
        case 'H': mode_h36(ts, pk); break;
        case 'M': mode_mwc_v8(ts, seed_off, pk); break;
        case 'R': mode_randstorm(ts, seed_off, pk); break;
        case 'I': mode_h36_pid(ts, seed_off, pk); break;
        case 'W': mode_instawallet(ts, seed_off, pk); break;
        case 'C': mode_bitcoincore_v3(ts, seed_off, 0, pk); break;
        default:  mode_h36(ts, pk); break;
    }

    // === STEP 2: EC k*G ===
    uint64_t k[4];
    for(int i=0;i<4;i++)
        k[i] = ((uint64_t)pk[i*8]<<56)|((uint64_t)pk[i*8+1]<<48)|
               ((uint64_t)pk[i*8+2]<<40)|((uint64_t)pk[i*8+3]<<32)|
               ((uint64_t)pk[i*8+4]<<24)|((uint64_t)pk[i*8+5]<<16)|
               ((uint64_t)pk[i*8+6]<<8)|(uint64_t)pk[i*8+7];

    JacobianPoint P, G;
    point_mul_g(&P, k);
    point_set_g(&G);

    // === STEP 3: Differential addition (16 keys from one k*G) ===
    #pragma unroll 16
    for(int iter=0; iter<16; iter++) {
        uint64_t aff_x[4], aff_y[4];
        point_to_affine(&P, aff_x, aff_y);

        // Compressed pubkey
        uint8_t pub[33];
        pub[0] = (aff_y[0] & 1) ? 0x03 : 0x02;
        for(int j=0;j<32;j++)
            pub[1+j] = (uint8_t)(aff_x[3-(j/8)] >> ((j%8)*8));

        // HASH160: SHA256 → RIPEMD160
        uint8_t sha[32], h160[20];
        sha256_fast(pub, 33, sha);
        ripemd160_fast(sha, 32, h160);

        // Bloom + exact match
        if(bloom_test_fast(h160) && exact_match_fast(h160)) {
            uint64_t pos = atomicAdd(found_count, 1ULL);
            if(pos < 256) {
                uint8_t *dst = found_key_out + pos * 52;
                for(int b=0;b<32;b++) dst[b] = pk[b];
                for(int b=0;b<20;b++) dst[32+b] = h160[b];
            }
        }

        // Uncompressed pubkey
        uint8_t pu[65]; pu[0] = 0x04;
        for(int j=0;j<32;j++) pu[1+j] = (uint8_t)(aff_x[3-(j/8)] >> ((j%8)*8));
        for(int j=0;j<32;j++) pu[33+j] = (uint8_t)(aff_y[3-(j/8)] >> ((j%8)*8));
        sha256_fast(pu, 65, sha);
        ripemd160_fast(sha, 32, h160);

        if(bloom_test_fast(h160) && exact_match_fast(h160)) {
            uint64_t pos = atomicAdd(found_count, 1ULL);
            if(pos < 256) {
                uint8_t *dst = found_key_out + pos * 52;
                for(int b=0;b<32;b++) dst[b] = pk[b];
                for(int b=0;b<20;b++) dst[32+b] = h160[b];
            }
        }

        // P += G for next key in chain
        point_add(&P, &P, &G);
    }
}
