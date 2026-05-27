// SeedHammer GPU Private Key Generator
// Modes (added for vulnerability coverage):
//   M: MWC1616 (Chrome/Node.js RNG 2010-2015)
//   R: Randstorm/JSBN (browser entropy)
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

static const uint32_t K256[64]={
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
// Mode R: Randstorm/JSBN (browser entropy)
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
// Timestamp-based (existing H36 mode wrapper)
// ================================================================
D_FUNC void seedhammer_h36(uint64_t ts, uint8_t priv[32]){
    for(int i=0;i<8;i++)priv[24+i]=(ts>>(i*8))&0xFF;
    for(int i=0;i<24;i++)priv[i]=0;
}
