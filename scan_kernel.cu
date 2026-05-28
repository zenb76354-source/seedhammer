// ================================================================
// VaultWatch kernel for SeedHammer --scan mode
// Embedded EC + SHA256 + RIPEMD160 on GPU
// Each thread: read privkey from device memory → EC * G → HASH160
// → compare vs bloom-filtered patoshi targets
// ================================================================

// -----------------------------------------------------------------
// SHA256 device functions (RFC 6234 compliant)
// -----------------------------------------------------------------
__device__ static void sh_compress(uint32_t H[8], const uint8_t blk[64]) {
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
    uint32_t W[64], a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7],t1,t2;
    for(int i=0;i<16;i++)W[i]=((uint32_t)blk[i*4]<<24)|(blk[i*4+1]<<16)|(blk[i*4+2]<<8)|blk[i*4+3];
    for(int i=16;i<64;i++){
        uint32_t s0=((W[i-15]>>7)|(W[i-15]<<25))^((W[i-15]>>18)|(W[i-15]<<14))^(W[i-15]>>3);
        uint32_t s1=((W[i-2]>>17)|(W[i-2]<<15))^((W[i-2]>>19)|(W[i-2]<<13))^(W[i-2]>>10);
        W[i]=W[i-16]+s0+W[i-7]+s1;
    }
    #define RR(x,r)(((x)>>(r))|((x)<<(32-(r))))
    for(int i=0;i<64;i++){
        t1=h+(RR(e,6)^RR(e,11)^RR(e,25))+((e&f)^((~e)&g))+K[i]+W[i];
        t2=(RR(a,2)^RR(a,13)^RR(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}

__device__ static void sha256d(const uint8_t *msg, uint32_t len, uint8_t out[32]) {
    uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[64]; uint32_t pos=0;
    while(pos+64<=len){for(int i=0;i<64;i++)blk[i]=msg[pos+i];sh_compress(H,blk);pos+=64;}
    uint32_t rem=len-pos; for(uint32_t i=0;i<64;i++)blk[i]=0;
    for(uint32_t i=0;i<rem;i++)blk[i]=msg[pos+i]; blk[rem]=0x80;
    uint64_t bits=(uint64_t)len*8;
    if(rem<55){for(int i=0;i<8;i++)blk[63-i]=(uint8_t)(bits>>(i*8));sh_compress(H,blk);}
    else{sh_compress(H,blk);for(int i=0;i<64;i++)blk[i]=0;for(int i=0;i<8;i++)blk[63-i]=(uint8_t)(bits>>(i*8));sh_compress(H,blk);}
    for(int i=0;i<8;i++){out[i*4]=(uint8_t)(H[i]>>24);out[i*4+1]=(uint8_t)(H[i]>>16);out[i*4+2]=(uint8_t)(H[i]>>8);out[i*4+3]=(uint8_t)(H[i]);}
}

// -----------------------------------------------------------------
// RIPEMD160 device function
// -----------------------------------------------------------------
__device__ static void ripemd160d(const uint8_t in[64], uint8_t out[20]) {
    uint32_t h[5]={0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0},x[16];
    for(int i=0;i<16;i++)x[i]=(uint32_t)in[i*4]|(uint32_t)in[i*4+1]<<8|(uint32_t)in[i*4+2]<<16|(uint32_t)in[i*4+3]<<24;
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],ap=a,bp=b,cp=c,dp=d,ep=e;
    for(int r=0;r<5;r++){
        int ro[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},rp[16]={5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12};
        int rs[16]={11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8},rsp[16]={8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6};
        if(r==1){int t[16]={7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8};memcpy(ro,t,64);int tp[16]={6,11,3,7,14,9,1,4,12,0,15,5,10,2,13,8};memcpy(rp,tp,64);int ts[16]={7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12};memcpy(rs,ts,64);int tsp[16]={9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11};memcpy(rsp,tsp,64);}
        else if(r==2){int t[16]={3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12};memcpy(ro,t,64);int tp[16]={15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13};memcpy(rp,tp,64);int ts[16]={11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5};memcpy(rs,ts,64);int tsp[16]={9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5};memcpy(rsp,tsp,64);}
        else if(r==3){int t[16]={1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2};memcpy(ro,t,64);int tp[16]={8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14};memcpy(rp,tp,64);int ts[16]={11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12};memcpy(rs,ts,64);int tsp[16]={15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8};memcpy(rsp,tsp,64);}
        else if(r==4){int t[16]={4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};memcpy(ro,t,64);int tp[16]={12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};memcpy(rp,tp,64);int ts[16]={9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};memcpy(rs,ts,64);int tsp[16]={8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};memcpy(rsp,tsp,64);}
        uint32_t rk=(r==0)?0x00000000:(r==1)?0x5a827999:(r==2)?0x6ed9eba1:(r==3)?0x8f1bbcdc:0xa953fd4e;
        uint32_t rkp=(r==0)?0x50a28be6:(r==1)?0x5c4dd124:(r==2)?0x6d703ef3:(r==3)?0x7a6d76e9:0x00000000;
        for(int s=0;s<16;s++){
            uint32_t f=(r==0||r==3)?((b&c)|(~b&d)):(r==1||r==2)?(b^c^d):(b^(c|~d));
            uint32_t T=((a+f+x[ro[s]]+rk)<<rs[s])|((a+f+x[ro[s]]+rk)>>(32-rs[s]));T+=e;
            e=d;d=(c<<10)|(c>>22);c=b;b=a;a=T;
            uint32_t fp=(r==0||r==3)?(bp^(cp|~dp)):(r==1||r==2)?((bp&cp)|(~bp&dp)):(bp^(cp|~dp));
            T=((ap+fp+x[rp[s]]+rkp)<<rsp[s])|((ap+fp+x[rp[s]]+rkp)>>(32-rsp[s]));T+=ep;
            ep=dp;dp=(cp<<10)|(cp>>22);cp=bp;bp=ap;ap=T;
        }
    }
    uint32_t tmp=h[1]+c+dp;h[1]=h[2]+d+ep;h[2]=h[3]+e+ap;h[3]=h[4]+a+bp;h[4]=h[0]+b+cp;h[0]=tmp;
    for(int i=0;i<5;i++){out[i*4]=h[i]&0xFF;out[i*4+1]=(h[i]>>8)&0xFF;out[i*4+2]=(h[i]>>16)&0xFF;out[i*4+3]=(h[i]>>24)&0xFF;}
}

// -----------------------------------------------------------------
// Full verification: compress + uncompress HASH160
// -----------------------------------------------------------------
// Device-side globals for bloom filter and patoshi targets
// Initialized via cudaMemcpyToSymbol from host
__device__ __constant__ uint32_t BLOOM_BITS;
__device__ __constant__ uint8_t BLOOM_DATA[262144]; // 2M bits for 21953 targets
__device__ __constant__ uint8_t PATOSHI_H160S[21953*20];
__device__ __constant__ uint32_t N_PATOSHI;

__device__ static int bloom_test_d(const uint8_t h160[20]) {
    uint32_t m = BLOOM_BITS - 1;
    uint32_t h7[7] = {
        ((uint32_t)h160[0]<<24|h160[1]<<16|h160[2]<<8|h160[3]) & m,
        ((uint32_t)h160[4]<<24|h160[5]<<16|h160[6]<<8|h160[7]) & m,
        ((uint32_t)h160[8]<<24|h160[9]<<16|h160[10]<<8|h160[11]) & m,
        ((uint32_t)h160[12]<<24|h160[13]<<16|h160[14]<<8|h160[15]) & m,
        ((uint32_t)h160[16]<<24|h160[17]<<16|h160[18]<<8|h160[19]) & m,
        ((uint32_t)(h160[0]^h160[10])<<24|(h160[1]^h160[11])<<16|(h160[2]^h160[12])<<8|(h160[3]^h160[13])) & m,
        ((uint32_t)(h160[4]^h160[14])<<24|(h160[5]^h160[15])<<16|(h160[6]^h160[16])<<8|(h160[7]^h160[17])) & m
    };
    for(int i=0;i<7;i++){uint32_t b=h7[i];if(!(BLOOM_DATA[b>>3]&(1<<(b&7))))return 0;}
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

__global__ void scan_kernel(
    const uint8_t *keys,
    uint64_t       n_keys,
    uint64_t      *found_count,
    uint8_t       *found_key_out  // 32 bytes per found key
) {
    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if(idx >= n_keys) return;

    const uint8_t *pk = keys + idx * 32;

    // --- EC multiplication (secp256k1 generator) ---
    // Convert 32-byte BE to 4x uint64
    uint64_t k[4];
    for(int i=0;i<4;i++)
        k[3-i]=(uint64_t)pk[i*8]<<56|(uint64_t)pk[i*8+1]<<48|(uint64_t)pk[i*8+2]<<40|(uint64_t)pk[i*8+3]<<32|
               (uint64_t)pk[i*8+4]<<24|(uint64_t)pk[i*8+5]<<16|(uint64_t)pk[i*8+6]<<8|pk[i*8+7];

    // Simplified: use point_mul_g from ec_jacobian.h (included via main.cu)
    JacobianPoint jp; point_mul_g(&jp, k);
    uint64_t ax[4], ay[4]; point_to_affine(&jp, ax, ay);

    // compressed HASH160
    uint8_t pc[33]; pc[0]=(ay[0]&1)?0x03:0x02;
    for(int i=0;i<32;i++){int w=i/8,b=i%8;pc[1+i]=(uint8_t)(ax[3-w]>>(b*8));}
    uint8_t sc[32]; sha256d(pc,33,sc);
    uint8_t rmd[64]; for(int i=0;i<32;i++)rmd[i]=sc[i]; rmd[32]=0x80;
    for(int i=33;i<56;i++)rmd[i]=0; rmd[56]=0;rmd[57]=1;for(int i=58;i<64;i++)rmd[i]=0;
    uint8_t hc[20]; ripemd160d(rmd,hc);

    // check compressed
    if(bloom_test_d(hc) && exact_match_d(hc)){
        uint64_t pos = atomicAdd(found_count, 1);
        if(pos < 256) { // store first 256 found keys
            uint8_t *dst = found_key_out + pos * 52; // 32 priv + 20 h160
            for(int b=0;b<32;b++) dst[b]=pk[b];
            for(int b=0;b<20;b++) dst[32+b]=hc[b];
        }
    }

    // uncompressed HASH160
    uint8_t pu[65]; pu[0]=0x04;
    for(int i=0;i<32;i++){int w=i/8,b=i%8;pu[1+i]=(uint8_t)(ax[3-w]>>(b*8));}
    for(int i=0;i<32;i++){int w=i/8,b=i%8;pu[33+i]=(uint8_t)(ay[3-w]>>(b*8));}
    uint8_t su[32]; sha256d(pu,65,su);
    for(int i=0;i<32;i++)rmd[i]=su[i]; rmd[32]=0x80;
    for(int i=33;i<56;i++)rmd[i]=0; rmd[56]=2;rmd[57]=0;for(int i=58;i<64;i++)rmd[i]=0;
    uint8_t hu[20]; ripemd160d(rmd,hu);

    // check uncompressed
    if(bloom_test_d(hu) && exact_match_d(hu)){
        uint64_t pos = atomicAdd(found_count, 1);
        if(pos < 256) {
            uint8_t *dst = found_key_out + pos * 52;
            for(int b=0;b<32;b++) dst[b]=pk[b];
            for(int b=0;b<20;b++) dst[32+b]=hu[b];
        }
    }
}
