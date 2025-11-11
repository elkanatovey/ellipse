# ELLIPSE

**ELLIPtic curve Scalable Encoding and Retrieval**

A high-performance cryptographic retrieval data structure using elliptic curve points with parallel Gaussian elimination.

## What is ELLIPSE?

ELLIPSE is a compact encoding structure that maps items to elliptic curve (EC) points efficiently. It uses:
- **Multiple hash functions** to map items to table positions
- **Gaussian elimination** over EC scalar fields to solve for table values
- **Parallel processing** to achieve near-linear speedup with multiple cores

Think of it as a minimal perfect hash function, but for cryptographic EC points instead of integers.

## Features

- **Fast EC operations** - Uses `fastecdsa` library for high-performance secp256k1
- **Parallel construction** - Near-linear speedup with CPU cores (8 cores = 7× faster)
- **Elliptic curve operations** - Works with secp256k1 EC points
- **Scalable** - Handles hundreds to thousands of items efficiently
- **Configurable** - Adjustable hash functions (k) and table size (m)
- **Deterministic retrieval** - Constant-time lookups

## Quick Start

### Prerequisites
- Python 3.10 or higher

### Installation

1. Clone this repository:
```bash
git clone <your-repo-url>
cd ellipse
```

2. Create a virtual environment:
```bash
python3 -m venv .venv
```

3. Activate the virtual environment:

On Linux/Mac:
```bash
source .venv/bin/activate
```

On Windows:
```bash
.venv\Scripts\activate
```

4. Install dependencies:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

5. **Optional** - Install Baby JubJub curve implementation:
```bash
pip install babyjubjub-py
```

**Note**: `babyjubjub-py` is a research prototype. See its [PyPI page](https://pypi.org/project/babyjubjub-py/) for security warnings before use.

### Basic Usage

**Using secp256k1 (default):**

```python
from ellipse import construct_ellipse_table_ec_parallel, retrieve_point_ec_khash

# Generate items to encode
items = [b"item1", b"item2", b"item3"]

# Construct table with parallel processing
table, meta = construct_ellipse_table_ec_parallel(
    items,
    m=100,        # Table size
    k=10,         # Number of hash functions
    num_cores=8   # CPU cores to use
)

# Retrieve EC point for any item
value = retrieve_point_ec_khash(items[0], table, meta["seed"], k=10)
print(f"Retrieved: {value}")
```

**Using Baby JubJub (alternative curve):**

```python
from ellipse_bjj import construct_ellipse_bjj_parallel, retrieve_point_bjj

items = [b"item1", b"item2", b"item3"]

# Same API, different curve
table, meta = construct_ellipse_bjj_parallel(
    items,
    m=100,
    k=10,
    num_cores=8
)

value = retrieve_point_bjj(items[0], table, meta["seed"], k=10)
print(f"Retrieved: {value}")
```

### Run Tests

```bash
# Small test (40 items, 8 cores)
python test_parallel.py 40 100 10 8

# Large test (900 items, all cores)
python test_parallel.py 900 1000 10 $(nproc)
```

## Performance

**secp256k1 (fastecdsa) - Current implementation:**

For **n=90, m=100, k=10**:
- **Serial**: ~40 seconds
- **Parallel (2 cores)**: ~13.6 seconds (2.9× speedup)

**Baby JubJub (optional - see `ellipse_bjj.py`):**

For **n=90, m=100, k=10**:
- **Parallel (2 cores)**: ~0.43 seconds

For **n=900, m=1000, k=10**:
- **Parallel (2 cores)**: ~70 seconds

See `ellipse_bjj.py` for Baby JubJub implementation.

See `PARALLEL_USAGE.md` for detailed performance analysis.

## Documentation

- **[FASTECDSA_IMPLEMENTATION.md](FASTECDSA_IMPLEMENTATION.md)** - Implementation details and API reference
- **[PARALLEL_USAGE.md](PARALLEL_USAGE.md)** - Comprehensive guide to parallel construction
- **[ellipse.py](ellipse.py)** - Main implementation with docstrings

## Use Cases

- Private Set Intersection (PSI) protocols
- Cryptographic key-value stores
- Oblivious retrieval systems
- Compact set representations with EC operations

## Development

To update dependencies after installing new packages:
```bash
pip freeze > requirements.txt
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Elkana Tovey

