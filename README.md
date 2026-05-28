# SeedHammer 🔨

GPU-based Bitcoin private key generator.
Generates candidate private keys via SHA256 of seeds (timestamps, words, integers, etc).
Outputs raw 32-byte keys to a binary file — zero verification, pure generation.

## Philosophy

> "Hammer the seeds. Let someone else watch the vault."

SeedHammer **only generates**. It does not:
- Compute public keys (no ECC)
- Compute RIPEMD160 hashes
- Compare against target addresses
- Verify anything

All it does: seed → SHA256 → 32 bytes → file.

This makes it:
- **Fast** — minimal GPU kernel, maximum throughput
- **Testable** — known SHA256 test vectors, easy to verify
- **Auditable** — any generated keys.bin can be verified by any tool

## Build

Requires: CUDA toolkit (12.x+), `nvcc`

```bash
git clone https://github.com/you/seedhammer
cd seedhammer
make
```

## Usage

```bash
./seedhammer --mode h36  --start 1223424000000 --count 1000000000 --out keys.bin

./seedhammer --mode h28  --start 0 --count 2000000000 --out keys.bin

./seedhammer --mode h03  --ts 1268728843 --pid-start 0 --pid-count 32768 --out keys.bin
```

## Modes

| Mode | Generation Rule | Key Count |
|:----:|----------------|:---------:|
| h28 | SHA256(uint32_be(i)) for i in [start, start+count) | unlimited |
| h36 | SHA256(uint64_be(ms)) for ms in [start, start+count) | unlimited |
| h48 | SHA256(uint48_be(i)) for i in [start, start+count) | up to 2^48 |
| h03 | SHA256(ts_be(4) ++ pid_be(4)) for pid in [0, pid_count) | 32768 per batch |
| h01 | SHA256(word) for each word in dict.txt + variants | depends on dict |
| h20 | SHA256(uint32_be(i)) for i in [0, count) | unlimited |
| h08 | SHA256(block_hash[i]) for i in [0, count) | depends on block data |

## Output Format

Raw binary: each key is **32 bytes** (big-endian uint256).
Concatenated sequentially. Total size = count × 32.

To pipe directly to VaultWatch:

```bash
./seedhammer --mode h36 --start 1223424000000 --count 1000000000 --out - | ../vaultwatch/vaultwatch --pipe
```

## License

MIT

---
*Last updated on May 28, 2026, by Manus AI Assistant.*

