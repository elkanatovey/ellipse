# Ellipse: fastecdsa Implementation

## Overview

`ellipse.py` uses the `fastecdsa` library for high-performance secp256k1 elliptic curve operations. This provides significant performance benefits for the Ellipse construction.

## Performance

| Implementation | Time (n=40, m=100, k=10) | Notes |
|----------------|--------------------------|-------|
| **fastecdsa (secp256k1)** | **0.9s** | **Current default** |
| Baby JubJub (Rust) | 0.4s | See `ellipse_bjj.py` |

## Dependencies

```bash
pip install fastecdsa
```

Or install from requirements:
```bash
pip install -r requirements.txt
```

## Implementation Details

### ECPoint Class

The `ECPoint` class wraps `fastecdsa.point.Point` for secp256k1 operations:

```python
from fastecdsa import curve
from fastecdsa.point import Point as FastPoint

class ECPoint:
    """Wrapper for elliptic curve points using fastecdsa library."""
    __slots__ = ("_point",)
    
    def __init__(self, point: Optional[FastPoint] = None):
        self._point = point
    
    @classmethod
    def from_affine(cls, x: int, y: int) -> 'ECPoint':
        """Create a point from affine coordinates."""
        point = FastPoint(x, y, curve=curve.secp256k1)
        return cls(point)
    
    @classmethod
    def generator(cls) -> 'ECPoint':
        """Return the generator point G."""
        return cls(curve.secp256k1.G)
    
    @classmethod
    def from_scalar(cls, k: int) -> 'ECPoint':
        """Create a point by scalar multiplication: k * G."""
        k = k % _EC_N
        if k == 0:
            return cls(None)
        point = k * curve.secp256k1.G
        return cls(point)
```

### EC Operations

**Point Addition:**
```python
def _ec_point_add(p1: ECPoint, p2: ECPoint) -> ECPoint:
    """Add two elliptic curve points using fastecdsa."""
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    result = p1._point + p2._point
    return ECPoint(result)
```

**Scalar Multiplication:**
```python
def _ec_scalar_mult(k: int, point: ECPoint) -> ECPoint:
    """Multiply an elliptic curve point by a scalar using fastecdsa."""
    if point.is_infinity or k % _EC_N == 0:
        return EC_INFINITY
    k = k % _EC_N
    result = k * point._point
    return ECPoint(result)
```

**Point Negation:**
```python
def _ec_point_neg(p: ECPoint) -> ECPoint:
    """Negate an elliptic curve point."""
    if p.is_infinity:
        return EC_INFINITY
    x, y = p.to_affine()
    return ECPoint.from_affine(x, (-y) % _EC_P)
```

### Serialization (for multiprocessing)

For parallel construction, EC points are serialized as uncompressed format (x || y):

```python
def _ec_point_to_bytes(point: ECPoint) -> bytes:
    """Serialize an EC point to bytes for pickling."""
    if point.is_infinity:
        return b'\x00'
    x, y = point.to_affine()
    return x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def _ec_point_from_bytes(data: bytes) -> ECPoint:
    """Deserialize an EC point from bytes."""
    if data == b'\x00':
        return ECPoint(None)
    x = int.from_bytes(data[:32], 'big')
    y = int.from_bytes(data[32:64], 'big')
    return ECPoint.from_affine(x, y)
```

## Usage

### Basic Construction

```python
import ellipse

# Generate items to encode
items = [b'item1', b'item2', b'item3', ...]

# Construct Ellipse table
table, metadata = ellipse.construct_ellipse_table_ec_gaussian(
    items,
    m=100,      # table size
    k=10,       # number of hash functions
    seed=42     # optional seed for reproducibility
)

# Retrieve values
for item in items:
    retrieved = ellipse.retrieve_point_ec_khash(
        item, 
        table, 
        metadata['seed'], 
        k=10
    )
    expected = ellipse._hash_to_point_ec(item)
    assert retrieved == expected
```

### Parallel Construction

For large workloads, use parallel Gaussian elimination:

```python
import ellipse

table, metadata = ellipse.construct_ellipse_table_ec_parallel(
    items,
    m=100,
    k=10,
    num_cores=4  # specify number of cores
)
```

## Performance Characteristics

### Time Complexity

- **Gaussian Elimination:** O(n² × m) scalar operations + O(n²) EC operations
- **Peeling Algorithm:** O(n × k) when successful (best for k≥5, load≤0.9)
- **Sparse Gaussian:** O(n × k²) for sparse systems

### Space Complexity

- **Table:** O(m) EC points (32 bytes/coordinate × 2 = 64 bytes/point)
- **Working memory:** O(n × m) scalars during construction

### Recommended Configurations

| Load (n/m) | k  | Method           | Expected Time (n=100) |
|------------|----|-----------------|-----------------------|
| 0.4        | 3  | Gaussian/Tree   | ~0.2s                 |
| 0.4        | 10 | Sparse Gaussian | ~0.5s                 |
| 0.9        | 10 | Sparse Gaussian | ~2.0s                 |

## Why fastecdsa?

### Advantages

1. **Performance:** Native C implementation for EC operations
2. **Simplicity:** Direct point arithmetic (`+`, `*` operators)
3. **Compatibility:** Standard secp256k1 curve (Bitcoin/Ethereum)
4. **Battle-tested:** Widely used in production systems

### API Benefits

fastecdsa provides cleaner APIs compared to other libraries:

- Direct point addition: `point1 + point2`
- Direct scalar multiplication: `k * point`
- Simple coordinate access: `point.x`, `point.y`
- Built-in curve parameters: `curve.secp256k1.G`

## Alternative: Baby JubJub

For maximum performance (2× faster than fastecdsa), consider using Baby JubJub with Rust bindings:

```python
import ellipse_bjj

table, metadata = ellipse_bjj.construct_ellipse_bjj_serial(
    items, m=100, k=10, seed=42
)
```

See `ellipse_bjj.py` for details.

## Testing

### Basic Functionality Test

```bash
python3 -c "
import random, os, time, ellipse

random.seed(12345)
items = [os.urandom(16) for _ in range(40)]

start = time.time()
table, meta = ellipse.construct_ellipse_table_ec_gaussian(items, m=100, k=10, seed=999)
elapsed = time.time() - start

correct = sum(
    1 for item in items 
    if ellipse.retrieve_point_ec_khash(item, table, meta['seed'], 10) == 
       ellipse._hash_to_point_ec(item)
)

print(f'Time: {elapsed:.3f}s')
print(f'Correct: {correct}/40')
"
```

Expected output:
```
Time: ~1.0s
Correct: 40/40
```

### Parallel Test

```bash
python3 test_parallel.py 40 100 10 4  # 40 items, 100 slots, 10 hashes, 4 cores
```

## Curve Parameters

secp256k1 parameters used:
- **Field prime (p):** `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`
- **Curve order (n):** `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
- **Equation:** y² = x³ + 7
- **Generator:** Standard secp256k1 G point

## Troubleshooting

### Installation Issues

If `pip install fastecdsa` fails, ensure you have build tools:

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libgmp-dev

# macOS
brew install gmp

# Then retry
pip install fastecdsa
```

### Import Errors

Ensure fastecdsa is installed in the correct environment:

```bash
source .venv/bin/activate  # activate venv first
pip install fastecdsa
```

### Performance Issues

If construction is slow:
1. Use parallel version for n≥100
2. Consider Baby JubJub for maximum speed
3. Use peeling algorithm for high k (k≥5)
4. Reduce load factor (n/m) if possible

## References

- fastecdsa GitHub: https://github.com/AntonKueltz/fastecdsa
- secp256k1 specification: https://www.secg.org/sec2-v2.pdf
- Ellipse paper: https://eprint.iacr.org/2020/193.pdf (PaXoS/PSI)

---

**Current version:** fastecdsa 3.0.1  
**Performance:** ~1s for n=40, m=100, k=10  
**Status:** Production-ready

