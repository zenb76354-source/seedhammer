#!/usr/bin/env python3
"""
R-value indexer: Find ECDSA nonce reuse in Bitcoin blockchain
Output: sorted triples file for Mode N (nonce_search)

Usage:
  python3 rvalue_indexer.py --blocks 0,230000 --output r_triples.bin

Input: requires bitcoind with txindex=1
Output: 96 bytes per triple: r(32) + s(32) + z(32), sorted by r

How nonce reuse works:
  Two signatures (r1,s1,z1) and (r2,s2,z2) with r1 == r2
  -> k = (z1 - z2) * (s1 - s2)^-1 mod n
  -> privkey = (k * s1 - z1) * r^-1 mod n
  
  The z value = hash of the transaction (sighash)
"""

import sys
import struct
import hashlib
import json
from collections import defaultdict

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def parse_der_sig(der):
    """Extract r, s from DER-encoded signature"""
    if not der or der[0] != 0x30:
        return None, None
    pos = 3  # Skip 0x30, length, 0x02
    if pos >= len(der):
        return None, None
    r_len = der[pos]
    pos += 1
    r_bytes = der[pos:pos+r_len]
    pos += r_len
    if pos >= len(der) or der[pos] != 0x02:
        return None, None
    pos += 1
    s_len = der[pos]
    pos += 1
    s_bytes = der[pos:pos+s_len]
    return r_bytes, s_bytes

def serialize_to_32(val_bytes):
    """Pad or truncate to exactly 32 bytes"""
    if len(val_bytes) > 32:
        return val_bytes[-32:]
    return b'\x00' * (32 - len(val_bytes)) + val_bytes

def process_transaction(tx_hex, txid):
    """Extract (r,s,z) triples from a transaction"""
    results = []
    try:
        tx_bytes = bytes.fromhex(tx_hex)
    except:
        return results
    
    # Simple TX parser (not full - needs python-bitcointx for real use)
    # This is a placeholder for the actual parser
    # For production: use bitcoin.core or python-bitcointxlib
    
    return results

def scan_blockchain(start_block, end_block, output_file):
    """Scan a range of blocks for R-value collisions"""
    print(f"Scanning blocks {start_block}-{end_block}")
    print("This requires bitcoind with txindex=1")
    print("Run: bitcoin-cli getblock <hash> 2 | python3 extract_tx.py")
    
    # For production, this connects to bitcoind RPC
    # For now: writes the structure
    output = {
        "version": 1,
        "block_range": [start_block, end_block],
        "description": "R-value triples for nonce reuse detection",
        "format": "Each triple: r(32 bytes) + s(32 bytes) + z(32 bytes) = 96 bytes",
        "num_triples": 0,
        "data_file": output_file
    }
    print(json.dumps(output, indent=2))
    
    # Create empty output file (production code fills this)
    with open(output_file, "wb") as f:
        f.write(b"")
    
    print(f"\nCreated {output_file} (empty ? run with bitcoind for real data)")
    print(f"\nTo use with seedhammer:")
    print(f"  seedhammer nonce {output_file}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="R-value indexer for nonce reuse detection")
    parser.add_argument("--blocks", default="0,230000", help="Block range (start,end)")
    parser.add_argument("--output", default="r_triples.bin", help="Output file")
    args = parser.parse_args()
    
    start, end = args.blocks.split(",")
    scan_blockchain(int(start), int(end), args.output)
