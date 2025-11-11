"""
ELLIPSE with Baby JubJub: Fast EC-based PSI using Rust bindings
"""

import hashlib
import os
import random
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from multiprocessing import Pool, cpu_count

import babyjubjub_py as bjj

# Baby JubJub subgroup order (prime order subgroup, cofactor = 8)
# This is the order of the prime-order subgroup for scalar field arithmetic
_EC_N = 2736030358979909402780800718157159386076813972158567259200215660948447373041


def _hash_to_scalar_ec(data: bytes) -> int:
    """Hash data to a scalar in the curve's field."""
    h = hashlib.blake2b(data, digest_size=32).digest()
    scalar = int.from_bytes(h, "big") % _EC_N
    if scalar == 0:
        return 1
    return scalar


def _hash_to_point_ec(data: bytes) -> bjj.ECPoint:
    """Hash data to an elliptic curve point."""
    return bjj.ECPoint.hash_to_point(data)


def _make_hashes_k(m: int, seed: int, k: int) -> List[Callable[[bytes], int]]:
    """Generate k independent hash functions mapping bytes -> [0, m)."""
    def h_i(i: int) -> Callable[[bytes], int]:
        def h(x: bytes) -> int:
            hh = hashlib.blake2b(digest_size=8)
            hh.update(seed.to_bytes(8, "little"))
            hh.update(i.to_bytes(1, "little"))  # Use 1 byte like ellipse.py
            hh.update(x)
            return int.from_bytes(hh.digest(), "little") % m
        return h
    return [h_i(i) for i in range(k)]


def construct_ellipse_bjj_serial(
    items: Sequence[bytes],
    m: int,
    k: int,
    seed: Optional[int] = None,
    max_attempts: int = 10,
) -> Tuple[List[bjj.ECPoint], Dict]:
    """
    Construct Ellipse table using Baby JubJub with Gaussian elimination (serial).
    This version properly performs Gaussian elimination on EC points WITHOUT
    needing to know their discrete logs!
    
    The coefficient matrix comes from hash structure (known scalars),
    while the RHS contains EC points (discrete logs unknown but not needed).
    
    Args:
        items: List of items to encode
        m: Number of table slots
        k: Number of hash functions
        seed: Random seed for hash functions
        max_attempts: Maximum attempts to avoid position collisions
    
    Returns:
        (table, metadata)
    """
    if len(items) == 0:
        return [bjj.ECPoint.infinity() for _ in range(m)], {"seed": 0}
    
    for attempt in range(max_attempts):
        if seed is None:
            seed = random.randrange(1 << 61)
        
        # Generate hash functions
        hashes = _make_hashes_k(m, seed, k)
        
        # Check for position collisions
        position_sets = {}
        has_collision = False
        for x in items:
            positions = tuple(sorted(h(x) for h in hashes))
            if positions in position_sets:
                has_collision = True
                break
            position_sets[positions] = x
        
        if has_collision:
            seed = random.randrange(1 << 61)
            continue
        
        # Build constraint matrix (scalars) and RHS vector (EC points)
        n = len(items)
        rows: List[List[int]] = []
        b_points: List[bjj.ECPoint] = []
        
        for x in items:
            positions = [h(x) for h in hashes]
            row = [0] * m
            for pos in positions:
                row[pos] = (row[pos] + 1) % _EC_N
            rows.append(row)
            
            # Store EC point directly
            value_point = _hash_to_point_ec(x)
            b_points.append(value_point)
        
        # Gaussian elimination with EC points on RHS
        row = 0
        col = 0
        pivot_cols: Dict[int, int] = {}
        
        # Forward elimination
        while row < n and col < m:
            # Find pivot
            pivot_row = None
            for r in range(row, n):
                if rows[r][col] % _EC_N != 0:
                    pivot_row = r
                    break
            
            if pivot_row is None:
                col += 1
                continue
            
            # Swap rows (both matrix and EC points)
            if pivot_row != row:
                rows[row], rows[pivot_row] = rows[pivot_row], rows[row]
                b_points[row], b_points[pivot_row] = b_points[pivot_row], b_points[row]
            
            pivot_cols[row] = col
            
            # Normalize pivot row
            pivot_val = rows[row][col] % _EC_N
            if pivot_val == 0:
                col += 1
                continue
            
            try:
                inv = pow(pivot_val, -1, _EC_N)
            except ValueError:
                # Not invertible (shouldn't happen with prime field, but handle it)
                col += 1
                continue
            
            for c in range(col, m):
                rows[row][c] = (rows[row][c] * inv) % _EC_N
            b_points[row] = b_points[row].scalar_mult(str(inv))
            
            # Eliminate below pivot (row echelon form, not RREF)
            for r in range(row + 1, n):
                factor = rows[r][col]
                if factor == 0:
                    continue
                
                # Update EC point: b_points[r] -= factor * b_points[row]
                scaled = b_points[row].scalar_mult(str(factor))
                b_points[r] = b_points[r].add(scaled.neg())
                
                # Update scalar matrix
                for c in range(col, m):
                    rows[r][c] = (rows[r][c] - factor * rows[row][c]) % _EC_N
            
            row += 1
            col += 1
        
        # Back substitution to get table values
        table_points = [bjj.ECPoint.infinity() for _ in range(m)]
        
        for r in sorted(pivot_cols.keys(), reverse=True):
            c = pivot_cols[r]
            
            # Start with b_points[r]
            result = b_points[r]
            
            # Subtract contributions from already-solved variables (only to the right)
            for j in range(c + 1, m):
                coeff = rows[r][j] % _EC_N
                if coeff != 0 and not table_points[j].is_infinity():
                    contrib = table_points[j].scalar_mult(str(coeff))
                    result = result.add(contrib.neg())
            
            table_points[c] = result
        
        return table_points, {"seed": seed}
    
    # If we get here, all attempts failed
    raise RuntimeError(f"Failed to construct Ellipse table after {max_attempts} attempts due to position collisions")


def _parallel_row_update(args):
    """Helper for parallel EC point operations during Gaussian elimination.
    
    Uses UNCOMPRESSED serialization (64 bytes) for speed - avoids expensive
    point compression/decompression that was causing 5x slowdown.
    """
    row_idx, factor, pivot_bytes, current_bytes = args
    
    # Deserialize EC points (UNCOMPRESSED - fast!)
    pivot_row_point = bjj.ECPoint.from_bytes_uncompressed(pivot_bytes)
    current_row_point = bjj.ECPoint.from_bytes_uncompressed(current_bytes)
    
    # Compute: current_row_point - factor * pivot_row_point
    if factor == 0:
        return row_idx, current_row_point.to_bytes_uncompressed()
    
    # factor * pivot_row_point
    scaled = pivot_row_point.scalar_mult(str(factor))
    # Subtract (add negation)
    result = current_row_point.add(scaled.neg())
    
    return row_idx, result.to_bytes_uncompressed()


def construct_ellipse_bjj_parallel(
    items: Sequence[bytes],
    m: int,
    k: int,
    num_cores: int = None,
    seed: Optional[int] = None,
    max_attempts: int = 10,
) -> Tuple[List[bjj.ECPoint], Dict]:
    """
    Construct Ellipse table using Baby JubJub with parallel Gaussian elimination.
    
    This version parallelizes the EC point operations during forward elimination.
    Matches the secp256k1 parallel implementation structure.
    
    Args:
        items: List of items to encode
        m: Number of table slots
        k: Number of hash functions
        num_cores: Number of CPU cores to use (default: all available)
        seed: Random seed for hash functions
        max_attempts: Maximum attempts to find solvable system (default: 10)
    
    Returns:
        (table, metadata)
    
    Raises:
        RuntimeError: If unable to construct after max_attempts
    """
    if num_cores is None:
        num_cores = cpu_count()
    
    if len(items) == 0:
        return [bjj.ECPoint.infinity() for _ in range(m)], {"seed": 0}
    
    # Retry loop with max_attempts
    for attempt in range(max_attempts):
        if seed is None:
            seed = random.randint(0, 2**32 - 1)
        
        # Generate hash functions
        hashes = _make_hashes_k(m, seed, k)
        
        # Check for position collisions
        position_sets = {}
        has_collision = False
        for x in items:
            positions = tuple(sorted(h(x) for h in hashes))
            if positions in position_sets:
                has_collision = True
                break
            position_sets[positions] = x
        
        if has_collision:
            seed = random.randint(0, 2**32 - 1)
            continue
        
        # Build constraint matrix
        n = len(items)
        rows: List[List[int]] = []
        b_points: List[bjj.ECPoint] = []
        
        for x in items:
            positions = [h(x) for h in hashes]
            row = [0] * m
            for pos in positions:
                row[pos] = (row[pos] + 1) % _EC_N
            rows.append(row)
            
            # Store EC point directly
            value_point = _hash_to_point_ec(x)
            b_points.append(value_point)
        
        # Gaussian elimination with Pool context manager OUTSIDE loop
        current_row = 0
        pivot_cols: Dict[int, int] = {}
        
        with Pool(num_cores) as pool:
            for col in range(m):
                # Find pivot
                pivot_row = None
                for r in range(current_row, n):
                    if rows[r][col] % _EC_N != 0:
                        pivot_row = r
                        break
                
                if pivot_row is None:
                    continue
                
                # Swap rows
                if pivot_row != current_row:
                    rows[current_row], rows[pivot_row] = rows[pivot_row], rows[current_row]
                    b_points[current_row], b_points[pivot_row] = b_points[pivot_row], b_points[current_row]
                
                pivot_cols[current_row] = col
                
                # Normalize pivot row
                pivot_val = rows[current_row][col] % _EC_N
                inv = pow(pivot_val, -1, _EC_N)
                
                for c in range(col, m):
                    rows[current_row][c] = (rows[current_row][c] * inv) % _EC_N
                b_points[current_row] = b_points[current_row].scalar_mult(str(inv))
                
                # Eliminate below pivot (PARALLEL!)
                tasks = []
                for r in range(current_row + 1, n):
                    factor = rows[r][col]
                    if factor == 0:
                        continue
                    tasks.append((r, factor, b_points[current_row].to_bytes_uncompressed(), b_points[r].to_bytes_uncompressed()))
                    
                    # Update scalar matrix
                    for c in range(col, m):
                        rows[r][c] = (rows[r][c] - factor * rows[current_row][c]) % _EC_N
                
                # Execute EC operations in parallel (GIL released in Rust!)
                if tasks:
                    results = pool.map(_parallel_row_update, tasks)
                    for r_idx, new_point_bytes in results:
                        b_points[r_idx] = bjj.ECPoint.from_bytes_uncompressed(new_point_bytes)
                
                current_row += 1
                if current_row >= n:
                    break
        
        # Back substitution
        table_points = [bjj.ECPoint.infinity() for _ in range(m)]
        
        pivot_list = []
        for row in range(min(n, m)):
            for col in range(m):
                if rows[row][col] % _EC_N != 0:
                    pivot_list.append((row, col))
                    break
        
        for row, col in reversed(pivot_list):
            result = b_points[row]
            for j in range(col + 1, m):
                coeff = rows[row][j] % _EC_N
                if coeff != 0 and not table_points[j].is_infinity():
                    contrib = table_points[j].scalar_mult(str(coeff))
                    result = result.add(contrib.neg())
            table_points[col] = result
        
        # Verify
        all_good = True
        for x in items:
            positions = [h(x) for h in hashes]
            result = bjj.ECPoint.infinity()
            for pos in positions:
                result = result.add(table_points[pos])
            if not (result == _hash_to_point_ec(x)):
                all_good = False
                break
        
        if all_good:
            return table_points, {
                "seed": seed,
                "k": k,
                "m": m,
                "n": n,
                "num_cores": num_cores,
                "method": "parallel_gaussian"
            }
        
        seed = random.randint(0, 2**32 - 1)
    
    raise RuntimeError(f"Failed to construct Ellipse table after {max_attempts} attempts")


def retrieve_point_bjj(
    x: bytes,
    table: Sequence[bjj.ECPoint],
    seed: int,
    k: int
) -> bjj.ECPoint:
    """
    Retrieve the stored EC point for item x.
    
    Returns: sum of table[h_i(x)] for all hash functions h_i
    """
    m = len(table)
    hashes = _make_hashes_k(m, seed, k)
    
    result = bjj.ECPoint.infinity()
    for h in hashes:
        pos = h(x)
        result = result.add(table[pos])
    
    return result


def test_ellipse_bjj(n: int = 40, m: int = 100, k: int = 10, num_cores: int = 1, trials: int = 1):
    """
    Test Ellipse with Baby JubJub bindings.
    
    Args:
        n: Number of items
        m: Number of table slots
        k: Number of hash functions
        num_cores: Number of CPU cores (1 = serial, >1 = parallel)
        trials: Number of test trials
    """
    print("="*70)
    print(f"Ellipse with Baby JubJub: n={n}, m={m}, k={k}, cores={num_cores}")
    print("="*70)
    print()
    
    successes = 0
    total_construct_time = 0.0
    total_retrieve_time = 0.0
    
    for trial in range(trials):
        # Generate random items
        random.seed(12345 + trial)
        items = []
        while len(items) < n:
            item = os.urandom(16)
            if item not in items:
                items.append(item)
        
        # Construction
        start = time.time()
        if num_cores == 1:
            table, meta = construct_ellipse_bjj_serial(items, m=m, k=k)
        else:
            table, meta = construct_ellipse_bjj_parallel(items, m=m, k=k, num_cores=num_cores)
        construct_time = time.time() - start
        total_construct_time += construct_time
        
        # Retrieval and verification
        start = time.time()
        all_correct = True
        for x in items:
            retrieved = retrieve_point_bjj(x, table, meta['seed'], k)
            expected = _hash_to_point_ec(x)
            
            if retrieved != expected:
                all_correct = False
                break
        retrieve_time = time.time() - start
        total_retrieve_time += retrieve_time
        
        if all_correct:
            successes += 1
        
        if trials == 1:
            print(f"Construction time: {construct_time:.3f}s")
            print(f"Retrieval time ({n} items): {retrieve_time:.3f}s")
            print(f"Avg retrieval: {retrieve_time*1000/n:.3f}ms")
            print(f"Verification: {'PASSED' if all_correct else 'FAILED'}")
    
    if trials > 1:
        avg_construct = total_construct_time / trials
        avg_retrieve = total_retrieve_time / trials
        print(f"Trials: {trials}")
        print(f"Success rate: {successes}/{trials} ({100*successes/trials:.1f}%)")
        print(f"Avg construction time: {avg_construct:.3f}s")
        print(f"Avg retrieval time: {avg_retrieve:.3f}s")
    
    print()


if __name__ == "__main__":
    import sys
    
    # Parse command line arguments
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    m = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    k = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    num_cores = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    
    test_ellipse_bjj(n=n, m=m, k=k, num_cores=num_cores)

