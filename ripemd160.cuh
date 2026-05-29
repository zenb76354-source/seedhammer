// ripemd160.cuh — GPU RIPEMD-160 (standalone header)
// Extracted from vaultwatch-integrated.cu to avoid SHA256 name conflict
// License: same as vaultwatch

#ifndef RIPEMD160_CUH
#define RIPEMD160_CUH

#define ROL32_RM(x,n) (((x)<<(n))|((x)>>(32-(n))))

static const uint32_t RMD_K_RM[5]={0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
static const uint32_t RMD_KP_RM[5]={0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000};

D_FUNC void ripemd160(const uint8_t in[64],uint8_t out[20]){
    uint32_t h[5]={0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0},x[16];
    for(int i=0;i<16;i++)x[i]=(uint32_t)in[i*4]|(uint32_t)in[i*4+1]<<8|(uint32_t)in[i*4+2]<<16|(uint32_t)in[i*4+3]<<24;
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],ap=a,bp=b,cp=c,dp=d,ep=e;
    static const uint8_t R[5][4]={{11,14,15,12},{13,14,11,15},{14,13,11,12},{11,13,15,14},{15,12,14,11}};
    static const uint8_t RP[5][4]={{8,9,9,11},{14,15,14,15},{9,8,8,12},{12,12,13,12},{15,12,13,13}};
    for(int r=0;r<5;r++){int r24=r;
        for(int s=0;s<16;s++){
            int j=(r==0)?s:(r==1)?(s*5+1)%16:(r==2)?(s*3+5)%16:(r==3)?(s*7)%16:(s*3+1)%16;
            int f=(r24==0)?(b^c^d):(r24==1)?((b&c)|(~b&d)):(r24==2)?((b|~c)^d):(r24==3)?((b&d)|(c&~d)):(b^(c|~d));
            uint32_t t=ROL32_RM(a+f+x[j]+RMD_K_RM[r24],R[r][s%4])+e;
            a=e;e=d;d=ROL32_RM(c,10);c=b;b=t;
            int jp=(r==0)?s:(r==1)?(s*3+5)%16:(r==2)?(s*7)%16:(r==3)?(s*5+1)%16:(s*3+1)%16;
            int fp=(r24==0)?(bp^(cp|~dp)):(r24==1)?((bp&dp)|(cp&~dp)):(r24==2)?(bp^cp^dp):(r24==3)?((bp&cp)|(~bp&dp)):((bp|~cp)^dp);
            uint32_t tp=ROL32_RM(ap+fp+x[jp]+RMD_KP_RM[r24],RP[r][s%4])+ep;
            ap=ep;ep=dp;dp=ROL32_RM(cp,10);cp=bp;bp=tp;
        }
    }
    uint32_t t=h[1]+c+dp;h[1]=h[2]+d+ep;h[2]=h[3]+e+ap;h[3]=h[4]+a+bp;h[4]=h[0]+b+cp;h[0]=t;
    for(int i=0;i<5;i++){out[i*4]=h[i]&0xFF;out[i*4+1]=(h[i]>>8)&0xFF;out[i*4+2]=(h[i]>>16)&0xFF;out[i*4+3]=(h[i]>>24)&0xFF;}
}

#endif // RIPEMD160_CUH
