#!/usr/bin/env python3
"""
QQ number brainwallet generator
QQ was the dominant IM in China in 2011 (700M users)
Common QQ IDs used as bitcoin brainwallet passwords
"""
import sys

def generate_qq_passwords(start=10000, count=100000):
    """Generate common QQ number patterns used as brainwallets"""
    # Real QQ numbers in 2011 were typically 5-9 digits
    # Most common: 10000->99999 (early adopters), 100000->999999
    for qq in range(start, start + count):
        yield str(qq)
        yield f"qq{qq}"
        yield f"{qq}qq"
        yield f"QQ{qq}"

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    for pwd in generate_qq_passwords(start, count):
        print(pwd)
