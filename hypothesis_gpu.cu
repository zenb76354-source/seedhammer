// SeedHammer hypothesis_gpu.cu — Clean CUDA device functions
// NO D_FUNC, NO __attribute__, NO #define __device__

#ifdef __CUDA_ARCH__
__constant__ uint32_t K256[64]={
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

#define RR2(n) (((n)>>2)|(((n)&3)<<(30)))
#define RR6(n) (((n)>>6)|(((n)&0x3F)<<(26)))
#define RR11(n) (((n)>>11)|(((n)&0x7FF)<<(21)))
#define RR13(n) (((n)>>13)|(((n)&0x1FFF)<<(19)))
#define RR22(n) (((n)>>22)|(((n)&0x3FFFFF)<<(10)))
#define RR25(n) (((n)>>25)|(((n)&0x1FFFFFF)<<(7)))
#define RR3(n) (((n)>>3)|(((n)&7)<<(29)))
#define RR10(n) (((n)>>10)|(((n)&0x3FF)<<(22)))
#define RR7(n) (((n)>>7)|(((n)&0x7F)<<(25)))
#define RR18(n) (((n)>>18)|(((n)&0x3FFFF)<<(14)))
#define RR17(n) (((n)>>17)|(((n)&0x1FFFF)<<(15)))
#define RR19(n) (((n)>>19)|(((n)&0x7FFFF)<<(13)))

#define SIG0(n) (RR2(n)^RR13(n)^RR22(n))
#define SIG1(n) (RR6(n)^RR11(n)^RR25(n))
#define sig0(n) (RR7(n)^RR18(n)^RR3(n))
#define sig1(n) (RR17(n)^RR19(n)^RR10(n))
#define CH(x,y,z) ((x&y)^(~x&z))
#define MAJ(x,y,z) ((x&y)^(x&z)^(y&z))

__device__ void sha256c(uint32_t s[8],const uint32_t b[16]){
    uint32_t a=s[0],b2=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7],w[64];
    for(int i=0;i<16;i++)w[i]=b[i];
    for(int i=16;i<64;i++)w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    for(int i=0;i<64;i++){uint32_t t1=h+SIG1(e)+CH(e,f,g)+K256[i]+w[i],t2=SIG0(a)+MAJ(a,b2,c);h=g;g=f;f=e;e=d+t1;d=c;c=b2;b2=a;a=t1+t2;}
    s[0]+=a;s[1]+=b2;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

__device__ void sha256(const uint8_t *m,uint32_t len,uint8_t *h){
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint32_t blk[16];uint64_t bits=(uint64_t)len*8;uint32_t idx=0;
    while(len>=64){for(int i=0;i<16;i++){blk[i]=((uint32_t)m[idx]<<24)|((uint32_t)m[idx+1]<<16)|((uint32_t)m[idx+2]<<8)|m[idx+3];idx+=4;}sha256c(s,blk);len-=64;}
    uint8_t pad[144];int pl=0;
    for(uint32_t i=0;i<len;i++)pad[pl++]=m[idx++];pad[pl++]=0x80;
    while((pl%64)!=56)pad[pl++]=0;
    for(int i=7;i>=0;i--)pad[pl++]=(bits>>(i*8))&0xFF;
    for(uint32_t i=0;i<pl;i+=64){for(int j=0;j<16;j++){uint32_t o=i+j*4;blk[j]=((uint32_t)pad[o]<<24)|((uint32_t)pad[o+1]<<16)|((uint32_t)pad[o+2]<<8)|pad[o+3];}sha256c(s,blk);}
    for(int i=0;i<8;i++){h[i*4]=(s[i]>>24)&0xFF;h[i*4+1]=(s[i]>>16)&0xFF;h[i*4+2]=(s[i]>>8)&0xFF;h[i*4+3]=s[i]&0xFF;}
}

static const uint8_t SECP256K1_N[32]={
0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static const char B58[]="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int B58_REV[128]={-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,-1,-1,-1,-1,-1,-1,-1,9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,-1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1};

__device__ uint32_t mwc_v8(uint32_t *z1,uint32_t *z2){*z1=((*z1)&0xFFFF)*0xDEAD+((*z1)>>16);*z2=((*z2)&0xFFFF)*0xBEEF+((*z2)>>16);return ((*z1)<<16)+(*z2);}
__device__ uint32_t glibc_rand(uint32_t *st){*st=(*st*1103515245u+12345u)&0x7FFFFFFFu;return *st;}

__device__ void mode_core_v3_stack(uint64_t ts,uint32_t pid,int pattern_id,uint8_t priv[32]){
    uint8_t stack[32];
    for(int i=0;i<8;i++){stack[i*4]=(uint8_t)(pattern_id+i);stack[i*4+1]=(uint8_t)((ts>>(i*8))&0xFF);stack[i*4+2]=(uint8_t)((pid>>(i*2))&0xFF);stack[i*4+3]=(uint8_t)(ts&0xFF);}
    sha256(stack,32,priv);
}

__device__ void mode_h36(uint64_t ts,uint8_t priv[32]){for(int i=0;i<8;i++)priv[24+i]=(ts>>(i*8))&0xFF;for(int i=0;i<24;i++)priv[i]=0;}
__device__ void mode_h36_drift(uint64_t bt,int32_t dr,uint8_t p[32]){mode_h36(bt+(uint64_t)(dr*1000),p);}
__device__ void mode_h36_usec(uint64_t s,uint64_t u,uint8_t p[32]){for(int i=0;i<8;i++)p[i]=(s>>(i*8))&0xFF;for(int i=0;i<8;i++)p[8+i]=(u>>(i*8))&0xFF;for(int i=16;i<24;i++)p[i]=0;for(int i=0;i<8;i++)p[24+i]=(u>>(i*8))&0xFF;}
__device__ void mode_h36_le(uint64_t ts,uint8_t p[32]){for(int i=0;i<8;i++)p[24+i]=(ts>>(i*8))&0xFF;uint64_t tl=0;for(int i=0;i<8;i++)tl|=((ts>>(i*8))&0xFF)<<((7-i)*8);for(int i=0;i<8;i++)p[24+i]=(tl>>(i*8))&0xFF;}
__device__ void mode_h36_sec(uint32_t us,uint8_t p[32]){for(int i=28;i<32;i++)p[i]=0;p[28]=(us>>24)&0xFF;p[29]=(us>>16)&0xFF;p[30]=(us>>8)&0xFF;p[31]=us&0xFF;}
__device__ void mode_h36_pid(uint64_t ts,uint32_t pid,uint8_t p[32]){for(int i=0;i<8;i++)p[i]=(ts>>(i*8))&0xFF;p[8]=(pid>>24)&0xFF;p[9]=(pid>>16)&0xFF;p[10]=(pid>>8)&0xFF;p[11]=pid&0xFF;for(int i=12;i<32;i++)p[i]=0;}
__device__ void mode_multisource(uint64_t ts,uint32_t pid,uint32_t up,uint32_t fm,uint8_t p[32]){uint8_t b[16];b[0]=ts&0xFF;b[1]=(ts>>8)&0xFF;b[2]=(ts>>16)&0xFF;b[3]=(ts>>24)&0xFF;b[4]=up&0xFF;b[5]=(up>>8)&0xFF;b[6]=(up>>16)&0xFF;b[7]=(up>>24)&0xFF;b[8]=fm&0xFF;b[9]=(fm>>8)&0xFF;b[10]=(fm>>16)&0xFF;b[11]=(fm>>24)&0xFF;b[12]=pid&0xFF;b[13]=(pid>>8)&0xFF;b[14]=0;b[15]=0;sha256(b,16,p);}
__device__ void mode_jitter(uint64_t bt,uint8_t j,uint8_t p[32]){mode_h36(bt+(uint64_t)j,p);}

__device__ void mode_mwc_v8(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint32_t ent=(uint32_t)(ts&0xFFFFFFFFu);uint32_t z1r=(ent^seed)*0xDEADu+0xDEADu;uint32_t z2r=(ent^seed)*0xBEEFu+0xBEEFu;
    uint32_t z1=z1r^(z1r>>30u);uint32_t z2=z2r^(z2r>>30u);uint8_t b[20];
    for(int i=0;i<4;i++){uint32_t r=mwc_v8(&z1,&z2);b[i*4]=(r>>24)&0xFF;b[i*4+1]=(r>>16)&0xFF;b[i*4+2]=(r>>8)&0xFF;b[i*4+3]=r&0xFF;}
    for(int i=0;i<4;i++)b[16+i]=(uint8_t)((ts>>(i*8))&0xFF);sha256(b,20,priv);
}

__device__ void mode_mwc_little(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint32_t ent=(uint32_t)(ts&0xFFFFFFFFu);uint32_t z1r=(ent^seed)*0xDEADu+0xDEADu;uint32_t z2r=(ent^seed)*0xBEEFu+0xBEEFu;
    uint32_t z1=z1r^(z1r>>30u);uint32_t z2=z2r^(z2r>>30u);uint8_t b[20];
    for(int i=0;i<4;i++){uint32_t r=mwc_v8(&z1,&z2);b[i*4]=r&0xFF;b[i*4+1]=(r>>8)&0xFF;b[i*4+2]=(r>>16)&0xFF;b[i*4+3]=(r>>24)&0xFF;}
    for(int i=0;i<4;i++)b[16+i]=(uint8_t)((ts>>(i*8))&0xFF);sha256(b,20,priv);
}

__device__ void mode_v8_3_0(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint32_t z1=(uint32_t)(ts^seed)*0xDEADu+0xDEADu;z1^=z1>>30u;uint32_t z2=(uint32_t)(ts^seed)*0xBEEFu+0xBEEFu;uint8_t b[20];
    for(int i=0;i<4;i++){uint32_t r=mwc_v8(&z1,&z2);b[i*4]=(r>>24)&0xFF;b[i*4+1]=(r>>16)&0xFF;b[i*4+2]=(r>>8)&0xFF;b[i*4+3]=r&0xFF;}
    for(int i=0;i<4;i++)b[16+i]=(uint8_t)((ts>>(i*8))&0xFF);sha256(b,20,priv);
}
__device__ void mode_v8_3_4(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint32_t z1r=((uint32_t)(ts&0xFFFFFFFFu)^seed)*0xDEADu+0xDEADu;uint32_t z2r=((uint32_t)(ts&0xFFFFFFFFu)^seed)*0xBEEFu+0xBEEFu;
    uint32_t z1=z1r^(z1r>>30u);uint32_t z2=z2r^(z2r>>30u);z1^=0xCAFE;z2^=0xCAFE;uint8_t b[20];
    for(int i=0;i<4;i++){uint32_t r=mwc_v8(&z1,&z2);b[i*4]=(r>>24)&0xFF;b[i*4+1]=(r>>16)&0xFF;b[i*4+2]=(r>>8)&0xFF;b[i*4+3]=r&0xFF;}
    for(int i=0;i<4;i++)b[16+i]=(uint8_t)((ts>>(i*8))&0xFF);sha256(b,20,priv);
}

__device__ void mode_randstorm(uint64_t ts,uint64_t idx,uint8_t priv[32]){
    uint8_t pool[256];uint32_t seed=(uint32_t)(ts&0xFFFFFFFFu)+(uint32_t)(idx&0xFFFFFFFFu);
    uint32_t z1=(seed)*0xDEADu+0xDEADu;uint32_t z2=(seed^0x1234u)*0xBEEFu+0xBEEFu;
    for(int i=0;i<64;i++){uint32_t r=mwc_v8(&z1,&z2);pool[i*4]=(r>>24)&0xFF;pool[i*4+1]=(r>>16)&0xFF;pool[i*4+2]=(r>>8)&0xFF;pool[i*4+3]=r&0xFF;if((i%4)==0){pool[i*4]^=((uint32_t)(ts>>(i%8)*8))&0xFF;}}
    uint8_t h1[32];sha256(pool,256,h1);sha256(h1,32,priv);
}
__device__ void mode_randstorm_little(uint64_t ts,uint64_t idx,uint8_t priv[32]){
    uint8_t pool[256];uint32_t seed=(uint32_t)(ts&0xFFFFFFFFu)+(uint32_t)(idx&0xFFFFFFFFu);
    uint32_t z1=(seed)*0xDEADu+0xDEADu;uint32_t z2=(seed^0x1234u)*0xBEEFu+0xBEEFu;
    for(int i=0;i<64;i++){uint32_t r=mwc_v8(&z1,&z2);pool[i*4]=r&0xFF;pool[i*4+1]=(r>>8)&0xFF;pool[i*4+2]=(r>>16)&0xFF;pool[i*4+3]=(r>>24)&0xFF;if((i%4)==0){pool[i*4]^=((uint32_t)(ts>>(i%8)*8))&0xFF;}}
    uint8_t h1[32];sha256(pool,256,h1);sha256(h1,32,priv);
}

__device__ void mode_bitcoincore_v3(uint64_t ts,uint32_t pid,uint8_t pat_id,uint8_t priv[32]){
    mode_core_v3_stack(ts,pid,pat_id,priv);uint8_t b[16];
    for(int i=0;i<8;i++)b[i]=(ts>>(i*8))&0xFF;for(int i=0;i<4;i++)b[8+i]=(pid>>(i*8))&0xFF;for(int i=12;i<16;i++)b[i]=0;sha256(b,16,priv);
}

__device__ void mode_android_rng(uint32_t seed,uint8_t priv[32]){
    uint32_t st=seed;for(int i=0;i<8;i++){uint32_t r=glibc_rand(&st);priv[i*4]=(r>>24)&0xFF;priv[i*4+1]=(r>>16)&0xFF;priv[i*4+2]=(r>>8)&0xFF;priv[i*4+3]=r&0xFF;}
}

__device__ void mode_instawallet(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint32_t z1=(uint32_t)((ts^seed)&0xFFFFFFFFu)*0xDEAD+0xDEAD;uint32_t z2=(uint32_t)(((ts^seed)>>16)&0xFFFFFFFFu)*0xBEEF+0xBEEF;z1^=z1>>30;z2^=z2>>30;
    uint8_t b[60];for(int i=0;i<15;i++){uint32_t r=mwc_v8(&z1,&z2);b[i*4]=(r>>24)&0xFF;b[i*4+1]=(r>>16)&0xFF;b[i*4+2]=(r>>8)&0xFF;b[i*4+3]=r&0xFF;}sha256(b,60,priv);
}

__device__ void mode_mybitcoin(const uint8_t *un,const uint8_t *pw,uint8_t priv[32]){uint8_t b[128];int p=0;for(int i=0;un[i]&&p<64;i++)b[p++]=un[i];for(int i=0;pw[i]&&p<124;i++)b[p++]=pw[i];b[p++]=0;sha256(b,p,priv);}

__device__ void mode_bitaddress(uint64_t ts,uint32_t extra,uint8_t priv[32]){
    uint32_t z1=((uint32_t)(ts&0xFFFFFFFFu)^extra)*0xDEADu+0xDEADu;uint32_t z2=((uint32_t)((ts>>16)&0xFFFFFFFFu)^extra)*0xBEEFu+0xBEEFu;z1^=z1>>30u;z2^=z2>>30u;uint8_t b[20];
    for(int i=0;i<4;i++){uint32_t r=mwc_v8(&z1,&z2);b[i*4]=(r>>24)&0xFF;b[i*4+1]=(r>>16)&0xFF;b[i*4+2]=(r>>8)&0xFF;b[i*4+3]=r&0xFF;}
    for(int i=0;i<4;i++)b[16+i]=(uint8_t)((ts>>(i*8))&0xFF);sha256(b,20,priv);
}

__device__ void mode_mywallet(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint32_t z1=(uint32_t)(ts^seed)*0xDEADu+0xDEADu;uint32_t z2=(uint32_t)((ts>>16)^seed)*0xBEEFu+0xBEEFu;uint8_t pool[128];
    for(int i=0;i<32;i++){uint32_t r=mwc_v8(&z1,&z2);pool[i*4]=(r>>24)&0xFF;pool[i*4+1]=(r>>16)&0xFF;pool[i*4+2]=(r>>8)&0xFF;pool[i*4+3]=r&0xFF;}
    sha256(pool,128,priv);
}

__device__ void mode_bitbills(uint64_t ts,uint8_t priv[32]){uint8_t b[8];for(int i=0;i<8;i++)b[i]=(ts>>(i*8))&0xFF;sha256(b,8,priv);uint8_t h2[32];for(int i=0;i<32;i++)h2[i]=priv[i];sha256(h2,32,priv);}

__device__ void mode_electrum(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint32_t mt[624];mt[0]=seed&0x7FFFFFFFu;for(int i=1;i<624;i++){mt[i]=1812433253u*(mt[i-1]^(mt[i-1]>>30))+i;}
    uint8_t b[32];int bp=0;
    for(int t=0;t<8;t++){int idx2=397;uint32_t y=(mt[0]&0x80000000u)|(mt[1]&0x7FFFFFFFu);uint32_t x=mt[idx2]^(y>>1);if(y&1)x^=0x9908B0DFu;b[bp++]=(x>>24)&0xFF;b[bp++]=(x>>16)&0xFF;b[bp++]=(x>>8)&0xFF;b[bp++]=x&0xFF;for(int i=0;i<623;i++)mt[i]=mt[i+1];mt[623]=x;}
    sha256(b,32,priv);
}

__device__ void mode_spidermonkey(uint64_t ts,uint32_t pid,uint8_t priv[32]){
    uint64_t s0=(ts^(uint64_t)pid)*0x5851F42D+0x12345678;uint64_t s1=s0*0x9E3779B9+ts;uint8_t b[32];
    for(int i=0;i<8;i++){uint64_t x=s0;s0=s1;s1=x^(x<<12)^(s1>>19)^(s1<<28);uint64_t r=s0+s1;b[i*4]=r&0xFF;b[i*4+1]=(r>>8)&0xFF;b[i*4+2]=(r>>16)&0xFF;b[i*4+3]=(r>>24)&0xFF;}
    sha256(b,32,priv);
}

__device__ void mode_jsc_webkit(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    uint8_t sb[256];for(int i=0;i<256;i++)sb[i]=(uint8_t)i;
    uint8_t k[8];for(int i=0;i<8;i++)k[i]=(uint8_t)((ts>>(i*8))&0xFF);
    int j=0;for(int i=0;i<256;i++){j=(j+sb[i]+k[i%8])&0xFF;uint8_t t=sb[i];sb[i]=sb[j];sb[j]=t;}
    int x=0,y=0;uint8_t b[32];for(int n=0;n<32;n++){x=(x+1)&0xFF;y=(y+sb[x])&0xFF;uint8_t t=sb[x];sb[x]=sb[y];sb[y]=t;b[n]=sb[(sb[x]+sb[y])&0xFF];}
    sha256(b,32,priv);
}

__device__ void mode_linux_libc_rand(uint32_t seed,uint8_t priv[32]){uint32_t st=seed;for(int i=0;i<8;i++){uint32_t r=glibc_rand(&st);priv[i*4]=(r>>24)&0xFF;priv[i*4+1]=(r>>16)&0xFF;priv[i*4+2]=(r>>8)&0xFF;priv[i*4+3]=r&0xFF;}}

__device__ void mode_cn_brainwallet(uint32_t base_idx,uint32_t year,uint32_t qq,uint8_t priv[32]){
    uint32_t phrases[16]={0x61766F,0x657969,0x626974,0x71696E,0x7A686F,0x736865,0x626569,0x736861,0x68616F,0x6A6961,0x6D616F,0x776F61,0x6A696E,0x626161,0x666131,0x6C6F76};
    uint32_t ph=phrases[base_idx%16];uint8_t b[32];
    for(int i=0;i<8;i++)b[i]=(ph>>(i*4))&0xFF;for(int i=0;i<8;i++)b[8+i]=(year>>(i*4))&0xFF;for(int i=0;i<8;i++)b[16+i]=(qq>>(i*4))&0xFF;for(int i=0;i<8;i++)b[24+i]=0;
    sha256(b,32,priv);
}

__device__ uint32_t mode_short_r_brute(const uint8_t r[32],uint8_t priv_out[32]){
    uint32_t rl=0;for(uint32_t i=0;i<32;i++){uint8_t b=r[i];if(b==0)rl+=8;else{uint8_t m=0x80;while(m&b){rl++;m>>=1;}break;}}
    priv_out[0]=(uint8_t)(rl&0xFF);priv_out[1]=(uint8_t)((rl>>8)&0xFF);return rl;
}

