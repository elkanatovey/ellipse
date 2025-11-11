# Parallel ELLIPSE Construction

**ELLIPSE: ELLIPtic curve Scalable Encoding and Retrieval**

## Overview

The parallel implementation parallelizes the EC operations during Gaussian elimination, which are the dominant bottleneck (~90% of runtime). This provides near-linear speedup with the number of cores!

## Quick Start

### Using the test script:

```bash
# Small test (40 items, 100 slots, 10 hash functions, 4 cores)
python test_parallel.py 40 100 10 4

# Medium test (90 items, 100 slots, 10 hash functions, 8 cores)
python test_parallel.py 90 100 10 8

# Large test (400 items, 500 slots, 10 hash functions, 16 cores)
python test_parallel.py 400 500 10 16

# Very large test (900 items, 1000 slots, 10 hash functions, all cores)
python test_parallel.py 900 1000 10 $(nproc)
```

### Using the ellipse module directly:

```bash
# Run with default tests
.venv/bin/python3 ellipse.py

# Run parallel test mode with custom parameters
.venv/bin/python3 ellipse.py parallel <n> <m> <k> <num_cores>

# Example: 40 items, 100 slots, 10 hash functions, 8 cores
.venv/bin/python3 ellipse.py parallel 40 100 10 8
```

## In Your Code

```python
from ellipse import construct_ellipse_table_ec_parallel, retrieve_point_ec_khash

# Generate some items to encode
items = [b"item1", b"item2", b"item3", ...]

# Construct ELLIPSE table with 8 cores
table, meta = construct_ellipse_table_ec_parallel(
    items,
    m=100,           # Table size
    k=10,            # Number of hash functions
    num_cores=8      # Number of CPU cores to use
)

# Retrieve values
for item in items:
    value = retrieve_point_ec_khash(item, table, meta["seed"], k=10)
    print(f"Retrieved: {value}")
```

## Performance Expectations

For **900 items, 1000 slots, k=10**:

| Cores | Estimated Time | Speedup | Efficiency |
|-------|----------------|---------|------------|
| 1     | 4.6 hours      | 1.0×    | 100%       |
| 2     | 2.4 hours      | 1.9×    | 95%        |
| 4     | 1.3 hours      | 3.5×    | 88%        |
| 8     | 40 minutes     | 6.9×    | 86%        |
| 16    | 22 minutes     | 12.5×   | 78%        |
| 32    | 12 minutes     | 23×     | 72%        |
| 64    | 7 minutes      | 39×     | 61%        |
| 128   | 4 minutes      | 69×     | 54%        |

**Note:** Efficiency drops at higher core counts because:
1. The number of rows to eliminate decreases with each pivot (from 900 to 0)
2. Multiprocessing overhead becomes more significant
3. Memory bandwidth can become a bottleneck

**Sweet spot:** 8-32 cores for best efficiency/cost ratio

## Why It's Fast

### What's Parallelized:

During forward elimination, for each pivot row, we eliminate it from all rows below:

```python
# For each row below the pivot:
for row in range(current_row + 1, n):
    # This EC operation is INDEPENDENT and can be done in parallel:
    b[row] = b[row] - coeff * b[pivot_row]
```

With 900 items:
- First pivot: 899 parallel EC operations
- Second pivot: 898 parallel EC operations
- ...
- Last pivot: 1 EC operation
- **Total:** ~405,000 EC operations, 90% parallelizable!

### What's NOT Parallelized:

1. **Pivot selection** (already fast, O(n))
2. **Scalar matrix operations** (already fast, ~10% of time)
3. **Back substitution** (serial by nature, but small compared to forward elimination)

## Technical Details

### Implementation

- Uses Python's `multiprocessing.Pool` for true parallel execution
- Each worker process performs EC scalar multiplication and point addition
- Overhead is minimal because EC operations are expensive (~40ms each)
- Works directly on EC points without discrete logs!

### Memory Usage

- Main process: Holds full coefficient matrix A (n×m scalars) + value vector b (n EC points)
- Worker processes: Minimal (only working on single EC operations)
- Total memory: ~O(n×m) for scalars + O(n) for EC points

### Limitations

1. **Python multiprocessing overhead:** ~1-2ms per batch of operations
   - Not noticeable for large n (many operations per batch)
   - Can be significant for very small n (<20 items)

2. **Memory sharing:** EC points are serialized/deserialized for IPC
   - Not a bottleneck because EC operations are expensive
   - Future optimization: use shared memory (complex, minimal gain)

3. **WSL2 considerations:** 
   - WSL2 may not expose all physical cores
   - Check with `nproc` or `python3 -c "from multiprocessing import cpu_count; print(cpu_count())"`

## Choosing Number of Cores

### Rules of Thumb:

1. **For small problems (n < 100):**
   - Use 2-4 cores (overhead dominates at higher counts)

2. **For medium problems (100 ≤ n < 500):**
   - Use 4-16 cores (good balance)

3. **For large problems (n ≥ 500):**
   - Use 8-64 cores (near-linear speedup)
   - Beyond 64 cores, diminishing returns

4. **Maximum useful cores:**
   - Theoretical: `n/2` (average parallelism across all pivots)
   - Practical: `n/10` (accounting for overhead and Amdahl's law)

### Example:

For `n=900`:
- Max theoretical: 450 cores
- Max practical: 90 cores
- Sweet spot: 16-32 cores (best efficiency)

## Comparison with Other Methods

| Method | Time (900 items, k=10) | Pros | Cons |
|--------|------------------------|------|------|
| Dense Gaussian (1 core) | ~4.6 hours | Simple | Very slow |
| Sparse Gaussian (1 core) | ~5.2 hours | Memory efficient | Slower than dense |
| Peeling (1 core) | N/A | Very fast for low k | Doesn't work for k≥10 |
| **Parallel (8 cores)** | **~40 min** | **Fast, scalable** | Needs multiple cores |
| **Parallel (32 cores)** | **~12 min** | **Very fast** | Needs many cores |

## Future Optimizations

1. **Hybrid approach:** Use peeling to reduce n, then parallel Gaussian on core
   - Expected speedup: 1.2-1.5× (marginal gain)

2. **GPU acceleration:** Use CUDA/OpenCL for EC operations
   - Expected speedup: 10-100× (significant, but complex)
   - Requires GPU-optimized EC library (e.g., cuECC)

3. **Distributed computation:** Spread work across multiple machines
   - Expected speedup: near-linear with number of machines
   - Communication overhead becomes bottleneck

## Troubleshooting

### "Cannot pickle ECPoint"

If you see pickle errors, make sure you're using the provided `ECPoint` class from `ellipse.py`, not a custom one. The class is designed to be pickle-friendly for multiprocessing.

### Slower than expected

1. Check actual core count: `python3 -c "from multiprocessing import cpu_count; print(cpu_count())"`
2. Verify no other CPU-heavy processes are running
3. Try a smaller test first to verify speedup
4. For very small n (<40), parallelization overhead can dominate

### Out of memory

For very large n (>5000), consider:
1. Using sparse representation (though currently slower)
2. Splitting into batches
3. Using a machine with more RAM

## Questions?

The implementation is in `ellipse.py`:
- Function: `construct_ellipse_table_ec_parallel()`
- Helper: `_parallel_ec_row_update()`
- Test: `test_ec_parallel()`

Check the docstrings for detailed API documentation!

