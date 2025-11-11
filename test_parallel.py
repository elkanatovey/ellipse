#!/usr/bin/env python3
"""
Test script for parallel ELLIPSE (ELLIPtic curve Scalable Encoding and Retrieval) construction.

Usage:
    python test_parallel.py <n> <m> <k> <num_cores>

Example:
    python test_parallel.py 40 100 10 8
    # Encodes 40 items into 100 slots using 10 hash functions on 8 cores
"""

import sys
from ellipse import test_ec_parallel, cpu_count

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_parallel.py <n> <m> <k> <num_cores>")
        print()
        print("Arguments:")
        print("  n: Number of items to encode")
        print("  m: Table size (number of slots)")
        print("  k: Number of hash functions")
        print("  num_cores: Number of CPU cores to use")
        print()
        print(f"Available CPU cores: {cpu_count()}")
        print()
        print("Examples:")
        print("  python test_parallel.py 40 100 10 4")
        print("  python test_parallel.py 90 100 10 8")
        print("  python test_parallel.py 400 500 10 16")
        sys.exit(1)
    
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    m = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    k = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    num_cores = int(sys.argv[4]) if len(sys.argv) > 4 else cpu_count()
    
    print(f"Testing with:")
    print(f"  Items (n): {n}")
    print(f"  Slots (m): {m}")
    print(f"  Hash functions (k): {k}")
    print(f"  CPU cores: {num_cores}")
    print()
    
    test_ec_parallel(n=n, m=m, k=k, num_cores=num_cores)
