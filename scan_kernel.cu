// ================================================================
// Optimized Scan Kernel for SeedHammer --scan mode
// Uses VaultWatch's optimized SHA256 and RIPEMD160 implementations
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

__device__ void sha256_compress_opt(uint32_t state[8], const uint32_t block[16]) {
    uint32_t W[64];
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3];
    uint32_t e=state[4],f=state[5],g=state[6],h=state[7],t1,t2;
    for (int i=0;i<16;i++) W[i]=block[i];
    for (int i=16;i<64;i++) {
        uint32_t s0=ROTL(W[i-15],7)^ROTL(W[i-15],18)^(W[i-15]>>3);
        uint32_t s1=ROTL(W[i-2],17)^ROTL(W[i-2],19)^(W[i-2]>>10);
        W[i]=W[i-16]+s0+W[i-7]+s1;
    }
    for (int i=0;i<64;i++) {
        uint32_t S1=ROTL(e,6)^ROTL(e,11)^ROTL(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        t1=h+S1+ch+SHA_K[i]+W[i];
        uint32_t S0=ROTL(a,2)^ROTL(a,13)^ROTL(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}

__device__ void sha256_opt(const uint8_t *data, uint32_t len, uint8_t hash[32]) {
    uint32_t state[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint32_t block[16];
    uint32_t pos=0;
    for (;pos+64<=len;pos+=64){
        for(int i=0;i<16;i++) block[i]=(data[pos+i*4]<<24)|(data[pos+i*4+1]<<16)|(data[pos+i*4+2]<<8)|data[pos+i*4+3];
        sha256_compress_opt(state,block);
    }
    uint8_t last[128];
    uint32_t rem=len-pos;
    for(uint32_t i=0;i<rem;i++)last[i]=data[pos+i];
    last[rem]=0x80;
    uint32_t last_len=rem+1;
    if(last_len>56){
        while(last_len<128)last[last_len++]=0;
        for(int i=0;i<16;i++)block[i]=(last[i*4]<<24)|(last[i*4+1]<<16)|(last[i*4+2]<<8)|last[i*4+3];
        sha256_compress_opt(state,block);last_len=0;
    }
    while(last_len<56)last[last_len++]=0;
    uint64_t bitlen=(uint64_t)len*8;
    last[56]=(uint8_t)(bitlen>>56);last[57]=(uint8_t)(bitlen>>48);last[58]=(uint8_t)(bitlen>>40);
    last[59]=(uint8_t)(bitlen>>32);last[60]=(uint8_t)(bitlen>>24);last[61]=(uint8_t)(bitlen>>16);
    last[62]=(uint8_t)(bitlen>>8);last[63]=(uint8_t)(bitlen);
    for(int i=0;i<16;i++)block[i]=(last[i*4]<<24)|(last[i*4+1]<<16)|(last[i*4+2]<<8)|last[i*4+3];
    sha256_compress_opt(state,block);
    for(int i=0;i<8;i++){hash[i*4]=(uint8_t)(state[i]>>24);hash[i*4+1]=(uint8_t)(state[i]>>16);
                          hash[i*4+2]=(uint8_t)(state[i]>>8);hash[i*4+3]=(uint8_t)(state[i]);}
}

__device__ void ripemd160_opt(const uint8_t *data, uint32_t len, uint8_t hash[20]) {
    uint32_t state[5]={0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
    uint32_t block[16];
    uint32_t pos=0;
    const uint32_t rk[5] = {0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
    const uint32_t rkp[5]= {0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000};
    const int ro[5][16] = {{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8},{3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12},{1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2},{4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13}};
    const int rop[5][16] = {{5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12},{6,11,3,7,14,9,1,4,12,0,15,5,10,2,13,8},{15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13},{8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14},{12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11}};
    const int rs[5][16] = {{11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8},{7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12},{11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5},{11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12},{9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6}};
    const int rsp[5][16] = {{8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6},{9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11},{9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5},{15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8},{8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11}};

    for(;pos+64<=len;pos+=64){
        for(int i=0;i<16;i++) block[i]=((uint32_t)data[pos+i*4+3]<<24)|((uint32_t)data[pos+i*4+2]<<16)|((uint32_t)data[pos+i*4+1]<<8)|(uint32_t)data[pos+i*4];
        uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],ap=a,bp=b,cp=c,dp=d,ep=e;
        for(int r=0;r<5;r++){
            for(int s=0;s<16;s++){
                uint32_t f, fp;
                if(r==0){f=(b&c)|(~b&d); fp=bp^(cp|~dp);}
                else if(r==1){f=b^c^d; fp=(bp&dp)|(cp&~dp);}
                else if(r==2){f=(c&~d)|(b&d); fp=bp^cp^dp;}
                else if(r==3){f=(b&c)|(~b&d); fp=(cp&~dp)|(bp&dp);}
                else {f=b^(c|~d); fp=bp^(cp|~dp);}
                uint32_t T = ROTL(a + f + block[ro[r][s]] + rk[r], rs[r][s]) + e;
                e=d;d=ROTL(c,10);c=b;b=a;a=T;
                T = ROTL(ap + fp + block[rop[r][s]] + rkp[r], rsp[r][s]) + ep;
                ep=dp;dp=ROTL(cp,10);cp=bp;bp=ap;ap=T;
            }
        }
        uint32_t tmp=state[1]+c+dp;state[1]=state[2]+d+ep;state[2]=state[3]+e+ap;state[3]=state[4]+a+bp;state[4]=state[0]+b+cp;state[0]=tmp;
    }
    uint8_t last[128]; uint32_t rem=len-pos; for(uint32_t i=0;i<rem;i++)last[i]=data[pos+i]; last[rem]=0x80;
    uint32_t last_len=rem+1;
    if(last_len>56){
        while(last_len<128)last[last_len++]=0;
        for(int i=0;i<16;i++) block[i]=((uint32_t)last[i*4+3]<<24)|((uint32_t)last[i*4+2]<<16)|((uint32_t)last[i*4+1]<<8)|(uint32_t)last[i*4];
        uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],ap=a,bp=b,cp=c,dp=d,ep=e;
        for(int r=0;r<5;r++){for(int s=0;s<16;s++){
            uint32_t f, fp; if(r==0){f=(b&c)|(~b&d); fp=bp^(cp|~dp);}else if(r==1){f=b^c^d; fp=(bp&dp)|(cp&~dp);}else if(r==2){f=(c&~d)|(b&d); fp=bp^cp^dp;}else if(r==3){f=(b&c)|(~b&d); fp=(cp&~dp)|(bp&dp);}else{f=b^(c|~d); fp=bp^(cp|~dp);}
            uint32_t T=ROTL(a+f+block[ro[r][s]]+rk[r],rs[r][s])+e;e=d;d=ROTL(c,10);c=b;b=a;a=T;
            T=ROTL(ap+fp+block[rop[r][s]]+rkp[r],rsp[r][s])+ep;ep=dp;dp=ROTL(cp,10);cp=bp;bp=ap;ap=T;
        }}
        uint32_t tmp=state[1]+c+dp;state[1]=state[2]+d+ep;state[2]=state[3]+e+ap;state[3]=state[4]+a+bp;state[4]=state[0]+b+cp;state[0]=tmp; last_len=0;
    }
    while(last_len<56)last[last_len++]=0;
    uint64_t bitlen=(uint64_t)len*8;
    for(int i=0;i<8;i++)last[56+i]=(uint8_t)(bitlen>>(i*8));
    for(int i=0;i<16;i++) block[i]=((uint32_t)last[i*4+3]<<24)|((uint32_t)last[i*4+2]<<16)|((uint32_t)last[i*4+1]<<8)|(uint32_t)last[i*4];
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],ap=a,bp=b,cp=c,dp=d,ep=e;
    for(int r=0;r<5;r++){for(int s=0;s<16;s++){
        uint32_t f, fp; if(r==0){f=(b&c)|(~b&d); fp=bp^(cp|~dp);}else if(r==1){f=b^c^d; fp=(bp&dp)|(cp&~dp);}else if(r==2){f=(c&~d)|(b&d); fp=bp^cp^dp;}else if(r==3){f=(b&c)|(~b&d); fp=(cp&~dp)|(bp&dp);}else{f=b^(c|~d); fp=bp^(cp|~dp);}
        uint32_t T=ROTL(a+f+block[ro[r][s]]+rk[r],rs[r][s])+e;e=d;d=ROTL(c,10);c=b;b=a;a=T;
        T=ROTL(ap+fp+block[rop[r][s]]+rkp[r],rsp[r][s])+ep;ep=dp;dp=ROTL(cp,10);cp=bp;bp=ap;ap=T;
    }}
    uint32_t tmp=state[1]+c+dp;state[1]=state[2]+d+ep;state[2]=state[3]+e+ap;state[3]=state[4]+a+bp;state[4]=state[0]+b+cp;state[0]=tmp;
    for(int i=0;i<5;i++){hash[i*4]=state[i]&0xFF;hash[i*4+1]=(state[i]>>8)&0xFF;hash[i*4+2]=(state[i]>>16)&0xFF;hash[i*4+3]=(state[i]>>24)&0xFF;}
}

__device__ uint32_t BLOOM_BITS;
__device__ uint8_t BLOOM_DATA[262144]; 
__device__ uint8_t PATOSHI_H160S[21953*20];
__device__ uint32_t N_PATOSHI;

__device__ static int bloom_test_d(const uint8_t h160[20]) {
    uint32_t m = BLOOM_BITS - 1;
    uint32_t h[7] = {
        ((uint32_t)h160[0]<<24|h160[1]<<16|h160[2]<<8|h160[3]) & m,
        ((uint32_t)h160[4]<<24|h160[5]<<16|h160[6]<<8|h160[7]) & m,
        ((uint32_t)h160[8]<<24|h160[9]<<16|h160[10]<<8|h160[11]) & m,
        ((uint32_t)h160[12]<<24|h160[13]<<16|h160[14]<<8|h160[15]) & m,
        ((uint32_t)h160[16]<<24|h160[17]<<16|h160[18]<<8|h160[19]) & m,
        ((h160[0]*2654435761u + h160[1]*2246822519u + h160[2]) & m),
        ((h160[3]*3266489917u + h160[4]*668265263u + h160[5]) & m)
    };
    for(int i=0;i<7;i++){uint32_t b=h[i];if(!(BLOOM_DATA[b>>3]&(1<<(b&7))))return 0;}
    return 1;
}

__device__ static int exact_match_d(const uint8_t h160[20]) {
    for(uint32_t i=0;i<N_PATOSHI;i++){
        int eq=1;
        for(int j=0;j<20;j++)if(h160[j]!=PATOSHI_H160S[i*20+j]){eq=0;break;}
        if(eq)return 1;
    }
    return 0;
}

__global__ void scan_kernel(const uint8_t *keys, uint64_t n_keys, unsigned long long *found_count, uint8_t *found_key_out) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if(idx >= n_keys) return;
    const uint8_t *pk = keys + idx * 32;
    uint8_t pub_comp[33], pub_uncomp[65], h160_comp[20], h160_uncomp[20], sha32[32];
    
    privkey_to_pubkey_both(pk, pub_comp, pub_uncomp);
    
    sha256_opt(pub_comp, 33, sha32);
    ripemd160_opt(sha32, 32, h160_comp);
    if(bloom_test_d(h160_comp) && exact_match_d(h160_comp)){
        unsigned long long pos = atomicAdd(found_count, 1ULL);
        if(pos < 256) {
            uint8_t *dst = found_key_out + pos * 52;
            for(int b=0;b<32;b++) dst[b]=pk[b];
            for(int b=0;b<20;b++) dst[32+b]=h160_comp[b];
        }
    }
    
    sha256_opt(pub_uncomp, 65, sha32);
    ripemd160_opt(sha32, 32, h160_uncomp);
    if(bloom_test_d(h160_uncomp) && exact_match_d(h160_uncomp)){
        unsigned long long pos = atomicAdd(found_count, 1ULL);
        if(pos < 256) {
            uint8_t *dst = found_key_out + pos * 52;
            for(int b=0;b<32;b++) dst[b]=pk[b];
            for(int b=0;b<20;b++) dst[32+b]=h160_uncomp[b];
        }
    }
}
