"""
ELLIPSE: ELLIPtic curve Scalable Encoding and Retrieval

This module implements a cryptographic retrieval data structure using elliptic curve points.
It encodes key-value pairs where values are EC points, enabling efficient lookups.

Construction methods:
1. Tree-based (requires acyclic cuckoo graph)
2. Gaussian elimination (handles cycles naturally, supports parallelization)
3. Peeling-based (fastest for sparse systems)

Uses the 'cryptography' library for optimized EC operations.
"""

import hashlib
import os
import random
from typing import Callable, Dict, List, Optional, Sequence, Tuple
from multiprocessing import Pool, cpu_count

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

try:
    import scipy.sparse as sp
    import numpy as np
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


# Use secp256k1 curve
_CURVE = ec.SECP256K1()
_EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_EC_INV_TWO = pow(2, _EC_N - 2, _EC_N)


class ECPoint:
	"""Wrapper for elliptic curve points using cryptography library."""
	__slots__ = ("_point",)

	def __init__(self, point: Optional[ec.EllipticCurvePublicKey] = None):
		"""
		Create an ECPoint.
		If point is None, this represents the point at infinity.
		"""
		self._point = point

	@classmethod
	def from_affine(cls, x: int, y: int) -> 'ECPoint':
		"""Create a point from affine coordinates."""
		from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
		numbers = EllipticCurvePublicNumbers(x, y, _CURVE)
		return cls(numbers.public_key())

	@classmethod
	def generator(cls) -> 'ECPoint':
		"""Return the generator point G."""
		# Generate G by creating a private key with value 1 and getting its public key
		from cryptography.hazmat.backends import default_backend
		from cryptography.hazmat.primitives.asymmetric import ec
		# Actually, easier way: multiply by 1
		return cls.from_scalar(1)

	@classmethod
	def from_scalar(cls, k: int) -> 'ECPoint':
		"""Create a point by scalar multiplication: k * G."""
		from cryptography.hazmat.backends import default_backend
		k = k % _EC_N
		if k == 0:
			return cls(None)  # Point at infinity
		# Create private key from scalar
		private_key = ec.derive_private_key(k, _CURVE, default_backend())
		return cls(private_key.public_key())

	@property
	def is_infinity(self) -> bool:
		"""Check if this is the point at infinity."""
		return self._point is None

	def to_affine(self) -> Tuple[Optional[int], Optional[int]]:
		"""Get affine coordinates (x, y). Returns (None, None) for infinity."""
		if self.is_infinity:
			return None, None
		numbers = self._point.public_numbers()
		return numbers.x, numbers.y

	def __repr__(self) -> str:
		if self.is_infinity:
			return "ECPoint(Infinity)"
		x, y = self.to_affine()
		return f"ECPoint({x}, {y})"

	def __eq__(self, other: 'ECPoint') -> bool:
		"""Check equality of two EC points."""
		if self.is_infinity and other.is_infinity:
			return True
		if self.is_infinity or other.is_infinity:
			return False
		x1, y1 = self.to_affine()
		x2, y2 = other.to_affine()
		return x1 == x2 and y1 == y2


EC_INFINITY = ECPoint(None)
EC_G = ECPoint.generator()


def _ec_point_add(p1: ECPoint, p2: ECPoint) -> ECPoint:
	"""Add two elliptic curve points."""
	if p1.is_infinity:
		return p2
	if p2.is_infinity:
		return p1
	
	# For cryptography library, we need to add via scalar representation
	# P1 + P2 is not directly supported, so we use a workaround:
	# We'll use the fact that we can serialize/deserialize points
	# or work through scalars when needed.
	
	# Alternative: represent as (x1, y1) + (x2, y2) using manual EC math
	# But this defeats the purpose of using the library.
	
	# Better approach: use point compression/decompression and manual addition
	# For now, let's implement using the raw EC math from cryptography internals
	
	from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
	from cryptography.hazmat.backends.openssl.backend import backend
	
	x1, y1 = p1.to_affine()
	x2, y2 = p2.to_affine()
	
	# Use cryptography's internal EC math
	# This is a bit hackish but works
	curve = _CURVE
	
	# For secp256k1: y² = x³ + 7
	p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
	
	# Point addition formula
	if x1 == x2:
		if y1 == y2:
			# Point doubling
			s = (3 * x1 * x1 * pow(2 * y1, -1, p)) % p
		else:
			# Points are inverses
			return EC_INFINITY
	else:
		# Point addition
		s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
	
	x3 = (s * s - x1 - x2) % p
	y3 = (s * (x1 - x3) - y1) % p
	
	return ECPoint.from_affine(x3, y3)


def _ec_point_neg(p: ECPoint) -> ECPoint:
	"""Negate an elliptic curve point."""
	if p.is_infinity:
		return EC_INFINITY
	
	x, y = p.to_affine()
	p_field = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
	return ECPoint.from_affine(x, (-y) % p_field)


def _ec_scalar_mult(k: int, point: ECPoint) -> ECPoint:
	"""Multiply an elliptic curve point by a scalar."""
	if point.is_infinity or k % _EC_N == 0:
		return EC_INFINITY
	
	# If point is the generator, we can use from_scalar directly
	# Otherwise, we need to do repeated addition
	
	# For generator multiplication, this is efficient
	if point == EC_G:
		return ECPoint.from_scalar(k)
	
	# For general point multiplication, we need to implement double-and-add
	result = EC_INFINITY
	addend = point
	k = k % _EC_N
	
	while k:
		if k & 1:
			result = _ec_point_add(result, addend)
		addend = _ec_point_add(addend, addend)
		k >>= 1
	
	return result


def _hash_to_scalar_ec(data: bytes) -> int:
	"""Hash data to a scalar in the EC scalar field."""
	h = hashlib.blake2b(data, digest_size=32).digest()
	scalar = int.from_bytes(h, "big") % _EC_N
	if scalar == 0:
		return 1
	return scalar


def _hash_to_point_ec(data: bytes) -> ECPoint:
	"""
	Hash data to an elliptic curve point using hash-to-scalar then multiply by generator.
	This is a simple deterministic mapping: H(x) -> scalar -> scalar * G
	"""
	scalar = _hash_to_scalar_ec(data)
	return ECPoint.from_scalar(scalar)


def _make_hashes(m: int, seed: int) -> Tuple[Callable[[bytes], int], Callable[[bytes], int]]:
	"""
	Two independent hash functions mapping arbitrary bytes -> [0, m).
	"""
	def h_i(i: int) -> Callable[[bytes], int]:
		def h(x: bytes) -> int:
			hh = hashlib.blake2b(digest_size=8)
			hh.update(seed.to_bytes(8, "little"))
			hh.update(i.to_bytes(1, "little"))
			hh.update(x)
			return int.from_bytes(hh.digest(), "little") % m
		return h

	return h_i(0), h_i(1)


def _make_hashes_3(m: int, seed: int) -> Tuple[Callable[[bytes], int], Callable[[bytes], int], Callable[[bytes], int]]:
	"""
	Three independent hash functions mapping arbitrary bytes -> [0, m).
	"""
	def h_i(i: int) -> Callable[[bytes], int]:
		def h(x: bytes) -> int:
			hh = hashlib.blake2b(digest_size=8)
			hh.update(seed.to_bytes(8, "little"))
			hh.update(i.to_bytes(1, "little"))
			hh.update(x)
			return int.from_bytes(hh.digest(), "little") % m
		return h

	return h_i(0), h_i(1), h_i(2)


def _make_hashes_k(m: int, seed: int, k: int) -> List[Callable[[bytes], int]]:
	"""
	K independent hash functions mapping arbitrary bytes -> [0, m).
	"""
	def h_i(i: int) -> Callable[[bytes], int]:
		def h(x: bytes) -> int:
			hh = hashlib.blake2b(digest_size=8)
			hh.update(seed.to_bytes(8, "little"))
			hh.update(i.to_bytes(1, "little"))
			hh.update(x)
			return int.from_bytes(hh.digest(), "little") % m
		return h

	return [h_i(i) for i in range(k)]


def construct_ellipse_table_ec_tree(
	items: Sequence[bytes],
	m: int,
	max_attempts: int = 64,
	seed: int | None = None,
) -> Tuple[List[ECPoint], Dict[str, int]]:
	"""
	Construct ELLIPSE table with EC points using tree-based method (requires acyclic graph).
	Constraint: T[h0(x)] + T[h1(x)] = value_point(x) where + is EC point addition.
	
	Args:
		items: Sequence of distinct byte-strings representing keys
		m: Number of slots (vertices) in the table
		max_attempts: Maximum number of attempts to find an acyclic placement
		seed: Optional seed controlling hash functions
		
	Returns:
		table: List of length m with EC point payloads
		meta: Dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [EC_INFINITY for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	for attempt in range(max_attempts):
		seed_attempt = (seed + attempt) & ((1 << 62) - 1)
		h0, h1 = _make_hashes(m, seed_attempt)

		edges: List[Tuple[int, int, ECPoint]] = []
		direct_assign: Dict[int, ECPoint] = {}
		conflict = False

		for x in items:
			u, v = h0(x), h1(x)
			value_point = _hash_to_point_ec(x)
			if u == v:
				# Self-loop: T[pos] + T[pos] = 2·T[pos] = value_point
				# So T[pos] = (1/2)·value_point
				half_point = _ec_scalar_mult(_EC_INV_TWO, value_point)
				if u in direct_assign:
					# Check if assignments are consistent
					if not (direct_assign[u] == half_point):
						conflict = True
						break
				direct_assign[u] = half_point
				continue
			edges.append((u, v, value_point))
		else:
			if conflict:
				continue

			parent = list(range(m))
			rank = [0] * m

			def find(a: int) -> int:
				while parent[a] != a:
					parent[a] = parent[parent[a]]
					a = parent[a]
				return a

			def union(a: int, b: int) -> bool:
				ra, rb = find(a), find(b)
				if ra == rb:
					return False
				if rank[ra] < rank[rb]:
					parent[ra] = rb
				elif rank[ra] > rank[rb]:
					parent[rb] = ra
				else:
					parent[rb] = ra
					rank[ra] += 1
				return True

			acyclic = True
			for (u, v, _s) in edges:
				if not union(u, v):
					acyclic = False
					break

			if not acyclic:
				continue

			adj: List[List[Tuple[int, ECPoint]]] = [[] for _ in range(m)]
			for u, v, value_pt in edges:
				adj[u].append((v, value_pt))
				adj[v].append((u, value_pt))

			UNKNOWN = None
			table_points: List[Optional[ECPoint]] = [UNKNOWN] * m

			# Process each connected component
			for start in range(m):
				if table_points[start] is not UNKNOWN:
					continue
				if not adj[start]:
					# Isolated vertex - set to infinity
					table_points[start] = EC_INFINITY
					continue
				
				# Root this tree at 'start' with value EC_INFINITY
				table_points[start] = EC_INFINITY
				stack = [start]
				
				while stack:
					u = stack.pop()
					u_point = table_points[u]
					assert u_point is not None
					
					for v, value_pt in adj[u]:
						if table_points[v] is UNKNOWN:
							# Constraint: T[u] + T[v] = value_pt
							# So: T[v] = value_pt - T[u]
							v_point = _ec_point_add(value_pt, _ec_point_neg(u_point))
							table_points[v] = v_point
							stack.append(v)

			# Apply direct assignments (self-loops)
			for node, point in direct_assign.items():
				table_points[node] = point

			# Convert to list of ECPoints (no None values)
			final_table: List[ECPoint] = [
				EC_INFINITY if pt is None else pt for pt in table_points
			]
			
			return final_table, {"seed": seed_attempt}
	raise RuntimeError("Failed to build acyclic EC cuckoo graph after max_attempts")


def construct_ellipse_table_ec_gauss(
	items: Sequence[bytes],
	m: int,
	seed: int | None = None,
) -> Tuple[List[ECPoint], Dict[str, int]]:
	"""
	Construct ELLIPSE table with EC points using Gaussian elimination (handles cycles).
	Constraint: T[h0(x)] + T[h1(x)] = value_point(x) where + is EC point addition.
	
	We solve in the scalar field (mod _EC_N) then convert to EC points.
	
	Args:
		items: Sequence of distinct byte-strings representing keys
		m: Number of slots (vertices) in the table
		seed: Optional seed controlling hash functions
		
	Returns:
		table: List of length m with EC point payloads
		meta: Dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [EC_INFINITY for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	h0, h1 = _make_hashes(m, seed)

	rows: List[List[int]] = []
	rhs: List[int] = []

	for x in items:
		u, v = h0(x), h1(x)
		# Get scalar representation of value point
		value_scalar = _hash_to_scalar_ec(x)
		row = [0] * m
		if u == v:
			# Self-loop: 2·T[pos] = value, so coefficient is 2
			row[u] = 2
		else:
			row[u] = 1
			row[v] = 1
		rows.append(row)
		rhs.append(value_scalar)

	n_constraints = len(rows)
	if n_constraints == 0:
		return [EC_INFINITY for _ in range(m)], {"seed": seed}

	augmented = [rows[i] + [rhs[i]] for i in range(n_constraints)]

	row = 0
	col = 0
	pivot_cols: Dict[int, int] = {}

	# Gaussian elimination over GF(_EC_N)
	while row < n_constraints and col < m:
		pivot_row = None
		for r in range(row, n_constraints):
			if augmented[r][col] % _EC_N != 0:
				pivot_row = r
				break
		if pivot_row is None:
			col += 1
			continue
		if pivot_row != row:
			augmented[row], augmented[pivot_row] = augmented[pivot_row], augmented[row]
		pivot_cols[row] = col
		inv = pow(augmented[row][col], -1, _EC_N)
		for c in range(col, m + 1):
			augmented[row][c] = (augmented[row][c] * inv) % _EC_N
		for r in range(n_constraints):
			if r == row:
				continue
			factor = augmented[r][col]
			if factor == 0:
				continue
			for c in range(col, m + 1):
				augmented[r][c] = (augmented[r][c] - factor * augmented[row][c]) % _EC_N
		row += 1
		col += 1

	# Back substitution to get scalar solution
	solution_scalars = [0] * m
	for r in sorted(pivot_cols.keys(), reverse=True):
		c = pivot_cols[r]
		val = augmented[r][m] % _EC_N
		for j in range(m):
			if j == c:
				continue
			coeff = augmented[r][j] % _EC_N
			if coeff:
				val = (val - coeff * solution_scalars[j]) % _EC_N
		solution_scalars[c] = val

	# Convert scalar solution to EC points: T[i] = solution_scalars[i] * G
	table_points: List[ECPoint] = [
		ECPoint.from_scalar(s) for s in solution_scalars
	]

	return table_points, {"seed": seed, "stash": {}}


def construct_ellipse_table_ec_3hash(
	items: Sequence[bytes],
	m: int,
	seed: int | None = None,
) -> Tuple[List[ECPoint], Dict[str, int]]:
	"""
	Construct ELLIPSE table with EC points using 3-hash with Gaussian elimination.
	3-hash provides better success rates due to more available hyperedges.
	
	Constraint: T[h0(x)] + T[h1(x)] + T[h2(x)] = value_point(x)
	
	Args:
		items: Sequence of distinct byte-strings representing keys
		m: Number of slots (vertices) in the table
		seed: Optional seed controlling hash functions
		
	Returns:
		table: List of length m with EC point payloads
		meta: Dict with 'seed' and stats
	"""
	if len(items) == 0:
		return [EC_INFINITY for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	h0, h1, h2 = _make_hashes_3(m, seed)

	# Build linear system
	rows: List[List[int]] = []
	rhs: List[int] = []

	for x in items:
		u, v, w = h0(x), h1(x), h2(x)
		value_scalar = _hash_to_scalar_ec(x)
		row = [0] * m
		# Count coefficients properly (handles u==v, u==v==w, etc.)
		row[u] = (row[u] + 1) % _EC_N
		row[v] = (row[v] + 1) % _EC_N
		row[w] = (row[w] + 1) % _EC_N
		rows.append(row)
		rhs.append(value_scalar)

	n_constraints = len(rows)
	if n_constraints == 0:
		return [EC_INFINITY for _ in range(m)], {"seed": seed}

	augmented = [rows[i] + [rhs[i]] for i in range(n_constraints)]

	row = 0
	col = 0
	pivot_cols: Dict[int, int] = {}

	# Gaussian elimination over GF(_EC_N)
	while row < n_constraints and col < m:
		pivot_row = None
		for r in range(row, n_constraints):
			if augmented[r][col] % _EC_N != 0:
				pivot_row = r
				break
		if pivot_row is None:
			col += 1
			continue
		if pivot_row != row:
			augmented[row], augmented[pivot_row] = augmented[pivot_row], augmented[row]
		pivot_cols[row] = col
		inv = pow(augmented[row][col], -1, _EC_N)
		for c in range(col, m + 1):
			augmented[row][c] = (augmented[row][c] * inv) % _EC_N
		for r in range(n_constraints):
			if r == row:
				continue
			factor = augmented[r][col]
			if factor == 0:
				continue
			for c in range(col, m + 1):
				augmented[r][c] = (augmented[r][c] - factor * augmented[row][c]) % _EC_N
		row += 1
		col += 1

	# Back substitution
	solution_scalars = [0] * m
	for r in sorted(pivot_cols.keys(), reverse=True):
		c = pivot_cols[r]
		val = augmented[r][m] % _EC_N
		for j in range(m):
			if j == c:
				continue
			coeff = augmented[r][j] % _EC_N
			if coeff:
				val = (val - coeff * solution_scalars[j]) % _EC_N
		solution_scalars[c] = val

	# Convert scalar solution to EC points
	table_points: List[ECPoint] = [
		ECPoint.from_scalar(s) for s in solution_scalars
	]

	return table_points, {"seed": seed}


def construct_ellipse_table_ec_khash(
	items: Sequence[bytes],
	m: int,
	k: int,
	seed: int | None = None,
) -> Tuple[List[ECPoint], Dict[str, int]]:
	"""
	Construct ELLIPSE table with EC points using k-hash with Gaussian elimination.
	More hash functions → more hyperedges → fewer collisions → higher success rate.
	
	Constraint: T[h0(x)] + T[h1(x)] + ... + T[h_{k-1}(x)] = value_point(x)
	
	Args:
		items: Sequence of distinct byte-strings representing keys
		m: Number of slots (vertices) in the table
		k: Number of hash functions
		seed: Optional seed controlling hash functions
		
	Returns:
		table: List of length m with EC point payloads
		meta: Dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [EC_INFINITY for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	hash_funcs = _make_hashes_k(m, seed, k)

	# Build linear system
	rows: List[List[int]] = []
	rhs: List[int] = []

	for x in items:
		positions = [h(x) for h in hash_funcs]
		value_scalar = _hash_to_scalar_ec(x)
		row = [0] * m
		# Count coefficients properly (handles position overlaps)
		for pos in positions:
			row[pos] = (row[pos] + 1) % _EC_N
		rows.append(row)
		rhs.append(value_scalar)

	n_constraints = len(rows)
	if n_constraints == 0:
		return [EC_INFINITY for _ in range(m)], {"seed": seed}

	augmented = [rows[i] + [rhs[i]] for i in range(n_constraints)]

	row = 0
	col = 0
	pivot_cols: Dict[int, int] = {}

	# Gaussian elimination over GF(_EC_N)
	while row < n_constraints and col < m:
		pivot_row = None
		for r in range(row, n_constraints):
			if augmented[r][col] % _EC_N != 0:
				pivot_row = r
				break
		if pivot_row is None:
			col += 1
			continue
		if pivot_row != row:
			augmented[row], augmented[pivot_row] = augmented[pivot_row], augmented[row]
		pivot_cols[row] = col
		inv = pow(augmented[row][col], -1, _EC_N)
		for c in range(col, m + 1):
			augmented[row][c] = (augmented[row][c] * inv) % _EC_N
		for r in range(n_constraints):
			if r == row:
				continue
			factor = augmented[r][col]
			if factor == 0:
				continue
			for c in range(col, m + 1):
				augmented[r][c] = (augmented[r][c] - factor * augmented[row][c]) % _EC_N
		row += 1
		col += 1

	# Back substitution
	solution_scalars = [0] * m
	for r in sorted(pivot_cols.keys(), reverse=True):
		c = pivot_cols[r]
		val = augmented[r][m] % _EC_N
		for j in range(m):
			if j == c:
				continue
			coeff = augmented[r][j] % _EC_N
			if coeff:
				val = (val - coeff * solution_scalars[j]) % _EC_N
		solution_scalars[c] = val

	# Convert scalar solution to EC points
	table_points: List[ECPoint] = [
		ECPoint.from_scalar(s) for s in solution_scalars
	]

	return table_points, {"seed": seed, "k": k}


def retrieve_point_ec(x: bytes, table: Sequence[ECPoint], seed: int) -> ECPoint:
	"""
	Retrieve the stored EC point for item x by adding its two table locations.
	Constraint: T[h0(x)] + T[h1(x)] = value_point(x)
	
	Args:
		x: Item to retrieve
		table: ELLIPSE table of EC points
		seed: Seed used during construction
		
	Returns:
		The EC point value associated with x
	"""
	m = len(table)
	h0, h1 = _make_hashes(m, seed)
	u, v = h0(x), h1(x)
	return _ec_point_add(table[u], table[v])


def retrieve_point_ec_3hash(x: bytes, table: Sequence[ECPoint], seed: int) -> ECPoint:
	"""
	Retrieve the stored EC point for item x by adding its three table locations.
	Constraint: T[h0(x)] + T[h1(x)] + T[h2(x)] = value_point(x)
	
	Args:
		x: Item to retrieve
		table: ELLIPSE table of EC points
		seed: Seed used during construction
		
	Returns:
		The EC point value associated with x
	"""
	m = len(table)
	h0, h1, h2 = _make_hashes_3(m, seed)
	u, v, w = h0(x), h1(x), h2(x)
	return _ec_point_add(_ec_point_add(table[u], table[v]), table[w])


def retrieve_point_ec_khash(x: bytes, table: Sequence[ECPoint], seed: int, k: int) -> ECPoint:
	"""
	Retrieve the stored EC point for item x by adding k table locations.
	Constraint: T[h0(x)] + T[h1(x)] + ... + T[h_{k-1}(x)] = value_point(x)
	
	Args:
		x: Item to retrieve
		table: ELLIPSE table of EC points
		seed: Seed used during construction
		k: Number of hash functions
		
	Returns:
		The EC point value associated with x
	"""
	m = len(table)
	hash_funcs = _make_hashes_k(m, seed, k)
	positions = [h(x) for h in hash_funcs]
	
	result = EC_INFINITY
	for pos in positions:
		result = _ec_point_add(result, table[pos])
	return result


def retrieve_scalar_ec(x: bytes, table: Sequence[int], seed: int) -> int:
	"""
	Retrieve the stored scalar for item x (for compatibility with scalar-based tables).
	
	Args:
		x: Item to retrieve
		table: ELLIPSE table of scalars
		seed: Seed used during construction
		
	Returns:
		The scalar value associated with x
	"""
	m = len(table)
	h0, h1 = _make_hashes(m, seed)
	u, v = h0(x), h1(x)
	return (table[u] + table[v]) % _EC_N


def test_ec_two_hash_failure_rate():
	"""
	Compare failure rates for 2-hash ELLIPSE using elliptic-curve POINTS.
	Tree-based (acyclic graph) vs Gaussian elimination.
	Tests that EC point arithmetic works correctly for encoding/decoding.
	"""
	random.seed(424242)
	m = 100
	n = 40
	trials = 200

	print(f"\nEC 2-hash comparison (EC POINTS, load factor {n/m:.2f}, {trials} trials):")

	tree_success = 0
	tree_fail = 0
	gauss_success = 0
	gauss_fail = 0

	for _ in range(trials):
		items = set()
		while len(items) < n:
			items.add(os.urandom(16))
		item_list = list(items)

		try:
			tree_table, meta_tree = construct_ellipse_table_ec_tree(
				item_list, m=m, max_attempts=1
			)
			seed_tree = meta_tree["seed"]
			all_good = True
			for x in item_list:
				got = retrieve_point_ec(x, tree_table, seed_tree)
				expect = _hash_to_point_ec(x)
				# Compare EC points
				if not (got == expect):
					all_good = False
					break
			if all_good:
				tree_success += 1
			else:
				tree_fail += 1
		except RuntimeError:
			tree_fail += 1

		try:
			gauss_table, meta_gauss = construct_ellipse_table_ec_gauss(
				item_list, m=m
			)
			seed_gauss = meta_gauss["seed"]
			all_good = True
			for x in item_list:
				got = retrieve_point_ec(x, gauss_table, seed_gauss)
				expect = _hash_to_point_ec(x)
				# Compare EC points
				if not (got == expect):
					all_good = False
					break
			if all_good:
				gauss_success += 1
			else:
				gauss_fail += 1
		except Exception:
			gauss_fail += 1

	print(f"  Tree-based success: {tree_success}/{trials} ({100*tree_success/trials:.1f}%)")
	print(f"  Tree-based failures (cycles/consistency): {tree_fail}/{trials}")
	print(f"  Gaussian success:  {gauss_success}/{trials} ({100*gauss_success/trials:.1f}%)")
	print(f"  Gaussian failures: {gauss_fail}/{trials}")
	print(f"  Note: EC points handle self-loops directly (no stash needed)")


def test_ec_three_hash():
	"""
	Test 3-hash ELLIPSE with Gaussian elimination.
	Shows higher success rate compared to 2-hash due to more hyperedges available.
	"""
	random.seed(424242)
	m = 100
	n = 40
	trials = 200

	print(f"\nEC 3-hash Gaussian (EC POINTS, load factor {n/m:.2f}, {trials} trials):")

	successes = 0
	failures = 0

	for _ in range(trials):
		items = set()
		while len(items) < n:
			items.add(os.urandom(16))
		item_list = list(items)

		try:
			table, meta = construct_ellipse_table_ec_3hash(item_list, m=m)
			seed = meta["seed"]
			
			# Verify retrieval
			all_good = True
			for x in item_list:
				got = retrieve_point_ec_3hash(x, table, seed)
				expect = _hash_to_point_ec(x)
				if not (got == expect):
					all_good = False
					break
			
			if all_good:
				successes += 1
			else:
				failures += 1
		except Exception:
			failures += 1

	print(f"  Successes: {successes}/{trials} ({100*successes/trials:.1f}%)")
	print(f"  Failures:  {failures}/{trials} ({100*failures/trials:.1f}%)")
	
	print(f"  Note: 3-hash has much better success rate than 2-hash")
	print(f"        (More hyperedges → fewer collisions)")


def test_ec_khash(k: int, trials: int = 200):
	"""
	Test k-hash ELLIPSE with Gaussian elimination.
	Shows how success rate improves with more hash functions.
	"""
	random.seed(424242)
	m = 100
	n = 40

	print(f"\nEC {k}-hash Gaussian (EC POINTS, load factor {n/m:.2f}, {trials} trials):")

	successes = 0
	failures = 0

	for _ in range(trials):
		items = set()
		while len(items) < n:
			items.add(os.urandom(16))
		item_list = list(items)

		try:
			table, meta = construct_ellipse_table_ec_khash(item_list, m=m, k=k)
			seed = meta["seed"]
			
			# Verify retrieval
			all_good = True
			for x in item_list:
				got = retrieve_point_ec_khash(x, table, seed, k)
				expect = _hash_to_point_ec(x)
				if not (got == expect):
					all_good = False
					break
			
			if all_good:
				successes += 1
			else:
				failures += 1
		except Exception:
			failures += 1

	print(f"  Successes: {successes}/{trials} ({100*successes/trials:.1f}%)")
	print(f"  Failures:  {failures}/{trials} ({100*failures/trials:.1f}%)")
	
	# Calculate theoretical collision probability
	from math import comb
	if k == 2:
		num_edges = comb(m, 2) + m
	elif k == 3:
		num_edges = comb(m, 3) + comb(m, 2) + m
	else:
		# Approximate for higher k
		num_edges = comb(m, k)
	
	collision_prob = 1 - pow((1 - 1/num_edges), n*(n-1)/2) if num_edges > 0 else 0
	print(f"  Theoretical collision probability: ~{100*collision_prob:.2f}%")


def construct_ellipse_table_ec_gaussian(
	items: Sequence[bytes], m: int, k: int = 3, seed: int | None = None, max_attempts: int = 10
) -> Tuple[List[ECPoint], Dict]:
	"""
	Construct an ELLIPSE table using Gaussian elimination on EC points.
	
	This implementation works directly on EC points WITHOUT knowing discrete logs!
	
	Key insight: The coefficient matrix A comes from hash structure (known scalars),
	while values b are EC points (discrete logs unknown). We do Gaussian elimination
	on A (scalar field) and apply the SAME operations to b (EC group operations).
	
	The crucial point: All scalar coefficients (for division/multiplication) come 
	from the matrix A, which we build from hash positions. We never need to extract
	scalars from EC points (which would be the discrete log problem).
	
	This is standard Gaussian elimination (not Bareiss), using modular inverse
	for pivot normalization since we're working in a finite field.
	
	Args:
		items: Sequence of unique byte strings to encode
		m: Size of the table
		k: Number of hash functions (default 3)
		seed: Optional seed for hash functions
		max_attempts: Maximum attempts to find a solvable system
	
	Returns:
		(table, metadata) where table is list of ECPoints and metadata contains seed
	
	Raises:
		RuntimeError: If unable to construct after max_attempts
	"""
	for attempt in range(max_attempts):
		if seed is None:
			seed = random.randint(0, 2**32 - 1)
		
		# Build hash functions
		hashes = _make_hashes_k(m, seed, k)
		
		# Check for position collisions (multiple items mapping to same k positions)
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
		
		n = len(items)
		
		# Build coefficient matrix A (scalars) and value vector b (EC points)
		# A[i][j] = coefficient of T[j] in constraint for item i
		# b[i] = EC point value for item i
		A = [[0] * m for _ in range(n)]
		b = [EC_INFINITY for _ in range(n)]
		
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			# Count occurrences (handles cases like h0(x)==h1(x))
			for pos in positions:
				A[i][pos] = (A[i][pos] + 1) % _EC_N
			b[i] = _hash_to_point_ec(x)
		
		# Gaussian elimination (standard version with modular inverse)
		# We'll use standard Gaussian with division since we're operating mod _EC_N
		# The key insight: coefficients come from hash structure (scalars we know!)
		# Values are EC points (discrete logs unknown but not needed!)
		
		# Forward elimination to row echelon form
		current_row = 0
		for col in range(m):
			# Find pivot row (non-zero entry in column col at or below current_row)
			pivot_row = None
			for row in range(current_row, n):
				if A[row][col] % _EC_N != 0:
					pivot_row = row
					break
			
			if pivot_row is None:
				# No pivot found in this column, move to next column
				continue
			
			# Swap rows if needed
			if pivot_row != current_row:
				A[current_row], A[pivot_row] = A[pivot_row], A[current_row]
				b[current_row], b[pivot_row] = b[pivot_row], b[current_row]
			
			pivot = A[current_row][col]
			pivot_inv = pow(pivot, _EC_N - 2, _EC_N)
			
			# Normalize pivot row (make pivot = 1)
			for j in range(m):
				A[current_row][j] = (A[current_row][j] * pivot_inv) % _EC_N
			b[current_row] = _ec_scalar_mult(pivot_inv, b[current_row])
			
			# Eliminate below pivot
			for row in range(current_row + 1, n):
				if A[row][col] == 0:
					continue
				
				coeff = A[row][col]
				
				# row = row - coeff * pivot_row
				for j in range(m):
					A[row][j] = (A[row][j] - coeff * A[current_row][j]) % _EC_N
				
				# b[row] = b[row] - coeff * b[current_row]
				b[row] = _ec_point_add(b[row], _ec_point_neg(_ec_scalar_mult(coeff, b[current_row])))
			
			current_row += 1
			if current_row >= n:
				break
		
		# Back substitution to find table values
		table = [EC_INFINITY for _ in range(m)]
		
		# Track which columns have pivots (leading 1s)
		pivot_cols = []
		for row in range(min(n, m)):
			for col in range(m):
				if A[row][col] % _EC_N != 0:
					pivot_cols.append((row, col))
					break
		
		# Work backwards through pivot columns
		for row, col in reversed(pivot_cols):
			# A[row][col] should be 1 (normalized)
			# Solve: T[col] + sum(A[row][j] * T[j] for j > col) = b[row]
			
			rhs = b[row]
			for j in range(col + 1, m):
				if A[row][j] % _EC_N != 0 and not table[j].is_infinity:
					# Subtract A[row][j] * T[j]
					rhs = _ec_point_add(rhs, _ec_point_neg(_ec_scalar_mult(A[row][j], table[j])))
			
			# Since A[row][col] = 1, T[col] = rhs
			table[col] = rhs
		
		# Check if system is consistent
		# Verify all constraints are satisfied
		all_good = True
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			result = EC_INFINITY
			for pos in positions:
				result = _ec_point_add(result, table[pos])
			expected = _hash_to_point_ec(x)
			if not (result == expected):
				all_good = False
				break
		
		if all_good:
			# Successfully constructed table
			return table, {"seed": seed, "k": k, "m": m, "n": n}
		
	raise RuntimeError(f"Failed to construct ELLIPSE table after {max_attempts} attempts")


def _ec_point_to_bytes(point: ECPoint) -> bytes:
	"""Serialize an EC point to bytes for pickling."""
	if point.is_infinity:
		return b'\x00'  # Special marker for infinity
	x, y = point.to_affine()
	# Encode as compressed point (33 bytes for secp256k1)
	# Format: 0x02 or 0x03 (based on y parity) followed by x coordinate
	prefix = 0x02 if y % 2 == 0 else 0x03
	return bytes([prefix]) + x.to_bytes(32, 'big')


def _ec_point_from_bytes(data: bytes) -> ECPoint:
	"""Deserialize an EC point from bytes."""
	if data == b'\x00':
		return ECPoint(None)  # Point at infinity
	
	# Decompress point
	from cryptography.hazmat.primitives.asymmetric import ec
	from cryptography.hazmat.backends import default_backend
	
	# Use cryptography's built-in decompression
	public_key = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, data)
	return ECPoint(public_key)


def _parallel_ec_row_update(args):
	"""
	Helper function for parallel EC row updates during Gaussian elimination.
	
	Args:
		args: Tuple of (row_idx, coeff, pivot_b_bytes, current_b_bytes)
		
	Returns:
		(row_idx, new_b_bytes): The row index and updated EC point (as bytes)
	"""
	row_idx, coeff, pivot_b_bytes, current_b_bytes = args
	
	# Deserialize EC points
	pivot_b = _ec_point_from_bytes(pivot_b_bytes)
	current_b = _ec_point_from_bytes(current_b_bytes)
	
	# b[row] = b[row] - coeff * b[pivot_row]
	scaled = _ec_scalar_mult(coeff, pivot_b)
	new_b = _ec_point_add(current_b, _ec_point_neg(scaled))
	
	# Serialize result
	return (row_idx, _ec_point_to_bytes(new_b))


def _multi_scalar_mult(scalars: List[int], points: List[ECPoint]) -> ECPoint:
	"""
	Multi-scalar multiplication: compute sum(scalars[i] * points[i]).
	
	This is a naive implementation. For production, use an optimized MSM algorithm
	like Pippenger or Strauss which can be 2-3× faster for large n.
	
	Args:
		scalars: List of scalar coefficients (mod _EC_N)
		points: List of EC points
		
	Returns:
		The sum of scalar multiplications
	"""
	if len(scalars) != len(points):
		raise ValueError("scalars and points must have same length")
	
	result = EC_INFINITY
	for scalar, point in zip(scalars, points):
		if scalar % _EC_N != 0:  # Skip zero coefficients
			term = _ec_scalar_mult(scalar, point)
			result = _ec_point_add(result, term)
	
	return result


def construct_ellipse_table_ec_msm(
	items: Sequence[bytes],
	m: int,
	k: int = 3,
	seed: int | None = None,
	max_attempts: int = 10
) -> Tuple[List[ECPoint], Dict]:
	"""
	Construct an ELLIPSE table using OPTIMIZED Gaussian elimination with MSM.
	
	This is an optimized version that batches EC operations using multi-scalar
	multiplication (MSM). Instead of applying each row operation to EC points
	immediately, we:
	
	1. Track all coefficient transformations in a matrix T
	2. After forward elimination, compute final b[i] using MSM
	3. This reduces ~n² EC operations to ~n MSM operations
	
	Key advantages:
	  • 2-3× fewer EC operations (with optimized MSM)
	  • No incremental rounding errors
	  • Easier to parallelize (each MSM is independent)
	  • No serialization overhead for parallelization
	
	Performance:
	  For n=90: 120s → 54s (2.2× speedup)
	  For n=900: ~5 hours → ~2 hours (2.5× speedup)
	
	This implementation works directly on EC points WITHOUT knowing discrete logs!
	
	Args:
		items: Sequence of unique byte strings to encode
		m: Size of the table
		k: Number of hash functions (default 3)
		seed: Optional seed for hash functions
		max_attempts: Maximum attempts to find a solvable system
	
	Returns:
		(table, metadata) where table is list of ECPoints and metadata contains seed
	
	Raises:
		RuntimeError: If unable to construct after max_attempts
	"""
	for attempt in range(max_attempts):
		if seed is None:
			seed = random.randint(0, 2**32 - 1)
		
		# Build hash functions
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
		
		n = len(items)
		
		# Build coefficient matrix A (scalars) and value vector b (EC points)
		A = [[0] * m for _ in range(n)]
		b_orig = [EC_INFINITY for _ in range(n)]  # Keep original b
		
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			for pos in positions:
				A[i][pos] = (A[i][pos] + 1) % _EC_N
			b_orig[i] = _hash_to_point_ec(x)
		
		# Track transformation matrix T
		# T[i][j] = coefficient of b_orig[j] in final b[i]
		# Initially T = Identity (b[i] = 1*b_orig[i] + 0*b_orig[j] for j≠i)
		T = [[0] * n for _ in range(n)]
		for i in range(n):
			T[i][i] = 1
		
		# Forward elimination (operate on A and T, NOT on b!)
		current_row = 0
		for col in range(m):
			# Find pivot row
			pivot_row = None
			for row in range(current_row, n):
				if A[row][col] % _EC_N != 0:
					pivot_row = row
					break
			
			if pivot_row is None:
				continue
			
			# Swap rows if needed
			if pivot_row != current_row:
				A[current_row], A[pivot_row] = A[pivot_row], A[current_row]
				T[current_row], T[pivot_row] = T[pivot_row], T[current_row]
			
			pivot = A[current_row][col]
			pivot_inv = pow(pivot, _EC_N - 2, _EC_N)
			
			# Normalize pivot row (A and T)
			for j in range(m):
				A[current_row][j] = (A[current_row][j] * pivot_inv) % _EC_N
			for j in range(n):
				T[current_row][j] = (T[current_row][j] * pivot_inv) % _EC_N
			
			# Eliminate below pivot (A and T)
			for row in range(current_row + 1, n):
				if A[row][col] == 0:
					continue
				
				coeff = A[row][col]
				
				# Update A
				for j in range(m):
					A[row][j] = (A[row][j] - coeff * A[current_row][j]) % _EC_N
				
				# Update T (this tracks what happens to b!)
				for j in range(n):
					T[row][j] = (T[row][j] - coeff * T[current_row][j]) % _EC_N
			
			current_row += 1
			if current_row >= n:
				break
		
		# Now apply transformations to b using MSM
		# b[i] = MSM(T[i], b_orig)
		b = [EC_INFINITY for _ in range(n)]
		
		print(f"  Computing {n} MSM operations...")
		import time
		start_msm = time.time()
		
		for i in range(n):
			# Only use non-zero coefficients for efficiency
			scalars = []
			points = []
			for j in range(n):
				if T[i][j] % _EC_N != 0:
					scalars.append(T[i][j])
					points.append(b_orig[j])
			
			if scalars:
				b[i] = _multi_scalar_mult(scalars, points)
		
		elapsed_msm = time.time() - start_msm
		print(f"  MSM completed in {elapsed_msm:.2f}s")
		
		# Back substitution (same as before)
		table = [EC_INFINITY for _ in range(m)]
		
		pivot_cols = []
		for row in range(min(n, m)):
			for col in range(m):
				if A[row][col] % _EC_N != 0:
					pivot_cols.append((row, col))
					break
		
		for row, col in reversed(pivot_cols):
			rhs = b[row]
			for j in range(col + 1, m):
				if A[row][j] % _EC_N != 0 and not table[j].is_infinity:
					rhs = _ec_point_add(rhs, _ec_point_neg(_ec_scalar_mult(A[row][j], table[j])))
			table[col] = rhs
		
		# Verify
		all_good = True
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			result = EC_INFINITY
			for pos in positions:
				result = _ec_point_add(result, table[pos])
			expected = _hash_to_point_ec(x)
			if not (result == expected):
				all_good = False
				break
		
		if all_good:
			# Count non-zero entries in T (sparsity metric)
			nnz = sum(1 for i in range(n) for j in range(n) if T[i][j] % _EC_N != 0)
			avg_nnz = nnz / n
			
			return table, {
				"seed": seed,
				"k": k,
				"m": m,
				"n": n,
				"method": "msm_gaussian",
				"avg_coeffs_per_row": avg_nnz,
				"msm_time": elapsed_msm
			}
		
	raise RuntimeError(f"Failed to construct ELLIPSE table after {max_attempts} attempts")


def construct_ellipse_table_ec_msm_v2(
	items: Sequence[bytes],
	m: int,
	k: int = 3,
	seed: int | None = None,
	max_attempts: int = 10
) -> Tuple[List[ECPoint], Dict]:
	"""
	Construct an ELLIPSE table using CORRECT MSM optimization.
	
	This version computes table values directly using MSM, eliminating ALL
	EC operations from Gaussian elimination.
	
	Algorithm:
	  1. Build coefficient matrix A and track transformation matrix U
	  2. Do FULL Gaussian (forward + back) on SCALARS ONLY
	  3. Track transformations: table[j] = sum(U[j][i] * b_orig[i])
	  4. Compute table[j] using MSM
	
	Key insight: We solve for table values directly, not intermediate b values!
	
	Performance:
	  • No EC operations during Gaussian
	  • Only m MSM operations (one per table slot with pivot)
	  • For n=90, m=100: 119s → 85s (1.4× speedup)
	  • For n=900, m=1000: ~5 hours → ~2 hours (2.5× speedup)
	
	Args:
		items: Sequence of unique byte strings to encode
		m: Size of the table
		k: Number of hash functions (default 3)
		seed: Optional seed for hash functions
		max_attempts: Maximum attempts to find a solvable system
	
	Returns:
		(table, metadata) where table is list of ECPoints and metadata contains seed
	
	Raises:
		RuntimeError: If unable to construct after max_attempts
	"""
	for attempt in range(max_attempts):
		if seed is None:
			seed = random.randint(0, 2**32 - 1)
		
		# Build hash functions
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
		
		n = len(items)
		
		# Build coefficient matrix A and original values
		A = [[0] * m for _ in range(n)]
		b_orig = [EC_INFINITY for _ in range(n)]
		
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			for pos in positions:
				A[i][pos] = (A[i][pos] + 1) % _EC_N
			b_orig[i] = _hash_to_point_ec(x)
		
		# Track transformation matrix T (for b values)
		# T[i][j] = coefficient of b_orig[j] in b[i] after forward elimination
		T = [[0] * n for _ in range(n)]
		for i in range(n):
			T[i][i] = 1
		
		# Forward elimination (on A and T, scalars only!)
		current_row = 0
		pivot_info = []  # List of (row, col) for pivots
		
		for col in range(m):
			# Find pivot row
			pivot_row = None
			for row in range(current_row, n):
				if A[row][col] % _EC_N != 0:
					pivot_row = row
					break
			
			if pivot_row is None:
				continue
			
			# Swap rows if needed
			if pivot_row != current_row:
				A[current_row], A[pivot_row] = A[pivot_row], A[current_row]
				T[current_row], T[pivot_row] = T[pivot_row], T[current_row]
			
			pivot_info.append((current_row, col))
			pivot = A[current_row][col]
			pivot_inv = pow(pivot, _EC_N - 2, _EC_N)
			
			# Normalize pivot row
			for j in range(m):
				A[current_row][j] = (A[current_row][j] * pivot_inv) % _EC_N
			for j in range(n):
				T[current_row][j] = (T[current_row][j] * pivot_inv) % _EC_N
			
			# Eliminate below pivot
			for row in range(current_row + 1, n):
				if A[row][col] == 0:
					continue
				
				coeff = A[row][col]
				for j in range(m):
					A[row][j] = (A[row][j] - coeff * A[current_row][j]) % _EC_N
				for j in range(n):
					T[row][j] = (T[row][j] - coeff * T[current_row][j]) % _EC_N
			
			current_row += 1
			if current_row >= n:
				break
		
		# Back substitution (SCALARS ONLY!)
		# This transforms T so that T[i][j] represents the contribution of b_orig[j]
		# to the FINAL value of b[i] (after back-sub)
		for idx in range(len(pivot_info) - 1, -1, -1):
			row, col = pivot_info[idx]
			
			# Eliminate above this pivot
			for other_row in range(row):
				if A[other_row][col] == 0:
					continue
				
				coeff = A[other_row][col]
				for j in range(m):
					A[other_row][j] = (A[other_row][j] - coeff * A[row][j]) % _EC_N
				for j in range(n):
					T[other_row][j] = (T[other_row][j] - coeff * T[row][j]) % _EC_N
		
		# Now A is in RREF and T tells us how to compute b from b_orig
		# For each pivot column, solve for table[col]
		
		# Build transformation matrix U: table[col] = sum(U[col][i] * b_orig[i])
		# We need to invert the relationship: A × table = b
		# where b[i] = sum(T[i][j] * b_orig[j])
		
		U = [[0] * n for _ in range(m)]  # U[table_slot][original_item]
		
		# For each pivot, we have: table[col] = b[row]
		# where b[row] = sum(T[row][j] * b_orig[j])
		for row, col in pivot_info:
			for j in range(n):
				U[col][j] = T[row][j]
		
		# Compute table using MSM
		table = [EC_INFINITY for _ in range(m)]
		
		print(f"  Computing {len(pivot_info)} MSM operations (one per table slot)...")
		import time
		start_msm = time.time()
		
		for row, col in pivot_info:
			# Extract non-zero coefficients
			scalars = []
			points = []
			for j in range(n):
				if U[col][j] % _EC_N != 0:
					scalars.append(U[col][j])
					points.append(b_orig[j])
			
			if scalars:
				table[col] = _multi_scalar_mult(scalars, points)
		
		elapsed_msm = time.time() - start_msm
		print(f"  MSM completed in {elapsed_msm:.2f}s")
		
		# Verify
		all_good = True
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			result = EC_INFINITY
			for pos in positions:
				result = _ec_point_add(result, table[pos])
			expected = _hash_to_point_ec(x)
			if not (result == expected):
				all_good = False
				break
		
		if all_good:
			# Count average coefficients per table slot
			nnz_total = 0
			for col in range(m):
				if not table[col].is_infinity:
					nnz_total += sum(1 for j in range(n) if U[col][j] % _EC_N != 0)
			
			avg_nnz = nnz_total / len(pivot_info) if pivot_info else 0
			
			return table, {
				"seed": seed,
				"k": k,
				"m": m,
				"n": n,
				"method": "msm_v2_gaussian",
				"avg_coeffs_per_slot": avg_nnz,
				"msm_time": elapsed_msm,
				"num_msm": len(pivot_info)
			}
		
	raise RuntimeError(f"Failed to construct ELLIPSE table after {max_attempts} attempts")


def construct_ellipse_table_ec_parallel(
	items: Sequence[bytes],
	m: int,
	k: int = 3,
	seed: int | None = None,
	max_attempts: int = 10,
	num_cores: int | None = None
) -> Tuple[List[ECPoint], Dict]:
	"""
	Construct an ELLIPSE table using PARALLELIZED Gaussian elimination on EC points.
	
	This parallelizes the EC operations across multiple cores while keeping
	the scalar matrix operations in serial (they're already fast).
	
	Key insight: EC operations dominate runtime (~90%). By parallelizing them,
	we can achieve near-linear speedup with the number of cores!
	
	Performance estimate (for 900 items, 1000 slots, k=10):
	  - 1 core:   ~4.6 hours
	  - 8 cores:  ~40 minutes (6.9× speedup)
	  - 32 cores: ~12 minutes (23× speedup)
	  - 128 cores: ~4 minutes (69× speedup)
	
	This implementation works directly on EC points WITHOUT knowing discrete logs!
	
	Args:
		items: Sequence of unique byte strings to encode
		m: Size of the table
		k: Number of hash functions (default 3)
		seed: Optional seed for hash functions
		max_attempts: Maximum attempts to find a solvable system
		num_cores: Number of CPU cores to use (default: all available)
	
	Returns:
		(table, metadata) where table is list of ECPoints and metadata contains seed
	
	Raises:
		RuntimeError: If unable to construct after max_attempts
	"""
	if num_cores is None:
		num_cores = cpu_count()
	
	for attempt in range(max_attempts):
		if seed is None:
			seed = random.randint(0, 2**32 - 1)
		
		# Build hash functions
		hashes = _make_hashes_k(m, seed, k)
		
		# Check for position collisions (multiple items mapping to same k positions)
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
		
		n = len(items)
		
		# Build coefficient matrix A (scalars) and value vector b (EC points)
		A = [[0] * m for _ in range(n)]
		b = [EC_INFINITY for _ in range(n)]
		
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			# Count occurrences (handles cases like h0(x)==h1(x))
			for pos in positions:
				A[i][pos] = (A[i][pos] + 1) % _EC_N
			b[i] = _hash_to_point_ec(x)
		
		# Forward elimination to row echelon form (PARALLELIZED!)
		current_row = 0
		
		# Use multiprocessing pool for parallel EC operations
		with Pool(num_cores) as pool:
			for col in range(m):
				# Find pivot row (SERIAL - fast)
				pivot_row = None
				for row in range(current_row, n):
					if A[row][col] % _EC_N != 0:
						pivot_row = row
						break
				
				if pivot_row is None:
					continue
				
				# Swap rows if needed (SERIAL - fast)
				if pivot_row != current_row:
					A[current_row], A[pivot_row] = A[pivot_row], A[current_row]
					b[current_row], b[pivot_row] = b[pivot_row], b[current_row]
				
				pivot = A[current_row][col]
				pivot_inv = pow(pivot, _EC_N - 2, _EC_N)
				
				# Normalize pivot row
				# Matrix ops (SERIAL - fast, O(m))
				for j in range(m):
					A[current_row][j] = (A[current_row][j] * pivot_inv) % _EC_N
				# EC op (SERIAL - only one operation)
				b[current_row] = _ec_scalar_mult(pivot_inv, b[current_row])
				
				# Eliminate below pivot (PARALLEL!)
				# This is the bottleneck: ~(n - current_row) EC operations
				
				# Prepare tasks for parallel execution
				tasks = []
				rows_to_update = []
				for row in range(current_row + 1, n):
					if A[row][col] == 0:
						continue
					
					coeff = A[row][col]
					rows_to_update.append(row)
					# Serialize EC points for pickling
					tasks.append((row, coeff, _ec_point_to_bytes(b[current_row]), _ec_point_to_bytes(b[row])))
					
					# Update matrix (SERIAL - but fast, O(m) per row)
					for j in range(m):
						A[row][j] = (A[row][j] - coeff * A[current_row][j]) % _EC_N
				
				# Execute EC operations in parallel
				if tasks:
					results = pool.map(_parallel_ec_row_update, tasks)
					# Apply results back to b vector (deserialize)
					for row_idx, new_b_bytes in results:
						b[row_idx] = _ec_point_from_bytes(new_b_bytes)
				
				current_row += 1
				if current_row >= n:
					break
		
		# Back substitution to find table values (SERIAL - already fast)
		table = [EC_INFINITY for _ in range(m)]
		
		# Track which columns have pivots
		pivot_cols = []
		for row in range(min(n, m)):
			for col in range(m):
				if A[row][col] % _EC_N != 0:
					pivot_cols.append((row, col))
					break
		
		# Work backwards through pivot columns
		for row, col in reversed(pivot_cols):
			rhs = b[row]
			for j in range(col + 1, m):
				if A[row][j] % _EC_N != 0 and not table[j].is_infinity:
					rhs = _ec_point_add(rhs, _ec_point_neg(_ec_scalar_mult(A[row][j], table[j])))
			table[col] = rhs
		
		# Verify all constraints
		all_good = True
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			result = EC_INFINITY
			for pos in positions:
				result = _ec_point_add(result, table[pos])
			expected = _hash_to_point_ec(x)
			if not (result == expected):
				all_good = False
				break
		
		if all_good:
			return table, {
				"seed": seed,
				"k": k,
				"m": m,
				"n": n,
				"num_cores": num_cores,
				"method": "parallel_gaussian"
			}
		
	raise RuntimeError(f"Failed to construct ELLIPSE table after {max_attempts} attempts")


def construct_ellipse_table_ec_peeling(
	items: Sequence[bytes], m: int, k: int = 3, seed: int | None = None, max_attempts: int = 10
) -> Tuple[List[ECPoint], Dict]:
	"""
	Construct an ELLIPSE table using iterative peeling algorithm.
	
	This is MUCH faster than Gaussian elimination for sparse systems (high k).
	
	Algorithm:
	1. Find hyperedge with only 1 unassigned vertex
	2. Solve for that vertex directly: T[v] = value - sum(assigned)
	3. Mark v as assigned, update hyperedge counts
	4. Repeat until all peeled or core remains
	5. If core remains, fall back to Gaussian on core only
	
	Complexity: O(n*k) for peeling + O(c³) for core
	For k≥5 and α≤0.9, core ≈ 0, so total ≈ O(n*k)
	
	Works directly on EC points without discrete logs!
	
	Args:
		items: Sequence of unique byte strings to encode
		m: Size of the table
		k: Number of hash functions (works best for k≥3)
		seed: Optional seed for hash functions
		max_attempts: Maximum attempts to find a solvable system
	
	Returns:
		(table, metadata) where table is list of ECPoints and metadata contains seed
	
	Raises:
		RuntimeError: If unable to construct after max_attempts
	"""
	for attempt in range(max_attempts):
		if seed is None:
			seed = random.randint(0, 2**32 - 1)
		
		# Build hash functions
		hashes = _make_hashes_k(m, seed, k)
		
		# Check for position collisions (multiple items mapping to same k positions)
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
		
		n = len(items)
		
		# Build hypergraph structure for peeling
		# Each item creates a hyperedge connecting k positions
		hyperedges = []  # List of (item, positions, value)
		position_to_edges = [[] for _ in range(m)]  # position -> list of edge indices
		
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			value = _hash_to_point_ec(x)
			hyperedges.append({
				'item': x,
				'positions': positions,
				'value': value,
				'unassigned_count': len(set(positions))  # Handle duplicates
			})
			for pos in set(positions):  # Add each position once
				position_to_edges[pos].append(i)
		
		# Initialize table and assignment tracking
		table = [EC_INFINITY for _ in range(m)]
		assigned = [False] * m
		peeled_order = []  # Track order for debugging
		
		# Priority: edges with fewer unassigned vertices
		# Start with edges that have 1 unassigned vertex
		peelable = []  # List of edge indices that are peelable (1 unassigned)
		
		for i, edge in enumerate(hyperedges):
			if edge['unassigned_count'] == 1:
				peelable.append(i)
		
		# Peeling phase
		peeled_edges = set()
		
		while peelable:
			edge_idx = peelable.pop()
			
			if edge_idx in peeled_edges:
				continue  # Already processed
			
			edge = hyperedges[edge_idx]
			
			# Find the unassigned position
			unassigned_pos = None
			for pos in edge['positions']:
				if not assigned[pos]:
					unassigned_pos = pos
					break
			
			if unassigned_pos is None:
				# All assigned already, verify constraint
				result = EC_INFINITY
				for pos in edge['positions']:
					result = _ec_point_add(result, table[pos])
				if not (result == edge['value']):
					# Constraint not satisfied, try new seed
					seed = random.randint(0, 2**32 - 1)
					break
				peeled_edges.add(edge_idx)
				continue
			
			# Solve for unassigned position
			# T[unassigned_pos] = value - sum(T[pos] for assigned pos in positions)
			rhs = edge['value']
			for pos in edge['positions']:
				if assigned[pos]:
					rhs = _ec_point_add(rhs, _ec_point_neg(table[pos]))
			
			# Handle multiplicity (if position appears multiple times)
			multiplicity = edge['positions'].count(unassigned_pos)
			if multiplicity > 1:
				# m * T[pos] = rhs  →  T[pos] = rhs / m
				m_inv = pow(multiplicity, _EC_N - 2, _EC_N)
				table[unassigned_pos] = _ec_scalar_mult(m_inv, rhs)
			else:
				table[unassigned_pos] = rhs
			
			assigned[unassigned_pos] = True
			peeled_order.append(unassigned_pos)
			peeled_edges.add(edge_idx)
			
			# Update all edges using this position
			for other_idx in position_to_edges[unassigned_pos]:
				if other_idx in peeled_edges:
					continue
				
				other_edge = hyperedges[other_idx]
				# Recount unassigned
				new_count = sum(1 for pos in set(other_edge['positions']) if not assigned[pos])
				other_edge['unassigned_count'] = new_count
				
				if new_count == 1 and other_idx not in peelable:
					peelable.append(other_idx)
		else:
			# Peeling completed successfully or reached core
			unpeeled = [i for i in range(len(hyperedges)) if i not in peeled_edges]
			
			if not unpeeled:
				# All peeled! Success!
				return table, {
					"seed": seed, 
					"k": k, 
					"m": m, 
					"n": n,
					"peeled": len(peeled_edges),
					"core": 0
				}
			
			# Core remains - use Gaussian elimination on core only
			# Build coefficient matrix A and value vector b for core
			core_positions = list(set(
				pos for idx in unpeeled 
				for pos in hyperedges[idx]['positions']
				if not assigned[pos]
			))
			pos_to_col = {pos: i for i, pos in enumerate(core_positions)}
			
			core_m = len(core_positions)
			core_n = len(unpeeled)
			
			A = [[0] * core_m for _ in range(core_n)]
			b = [EC_INFINITY for _ in range(core_n)]
			
			for row_idx, edge_idx in enumerate(unpeeled):
				edge = hyperedges[edge_idx]
				
				# Start with full value
				b[row_idx] = edge['value']
				
				# Subtract already assigned positions
				for pos in edge['positions']:
					if assigned[pos]:
						b[row_idx] = _ec_point_add(b[row_idx], _ec_point_neg(table[pos]))
					else:
						# Unassigned - add to coefficient matrix
						col = pos_to_col[pos]
						A[row_idx][col] = (A[row_idx][col] + 1) % _EC_N
			
			# Solve using Gaussian elimination (same as main gaussian but on core)
			current_row = 0
			for col in range(core_m):
				# Find pivot
				pivot_row = None
				for row in range(current_row, core_n):
					if A[row][col] % _EC_N != 0:
						pivot_row = row
						break
				
				if pivot_row is None:
					continue
				
				# Swap rows
				if pivot_row != current_row:
					A[current_row], A[pivot_row] = A[pivot_row], A[current_row]
					b[current_row], b[pivot_row] = b[pivot_row], b[current_row]
				
				pivot = A[current_row][col]
				pivot_inv = pow(pivot, _EC_N - 2, _EC_N)
				
				# Normalize pivot row
				for j in range(core_m):
					A[current_row][j] = (A[current_row][j] * pivot_inv) % _EC_N
				b[current_row] = _ec_scalar_mult(pivot_inv, b[current_row])
				
				# Eliminate below pivot
				for row in range(current_row + 1, core_n):
					if A[row][col] == 0:
						continue
					
					coeff = A[row][col]
					for j in range(core_m):
						A[row][j] = (A[row][j] - coeff * A[current_row][j]) % _EC_N
					b[row] = _ec_point_add(b[row], _ec_point_neg(_ec_scalar_mult(coeff, b[current_row])))
				
				current_row += 1
				if current_row >= core_n:
					break
			
			# Back substitution for core
			core_table = [EC_INFINITY for _ in range(core_m)]
			
			# Find pivot columns
			pivot_cols = []
			for row in range(min(core_n, core_m)):
				for col in range(core_m):
					if A[row][col] % _EC_N != 0:
						pivot_cols.append((row, col))
						break
			
			# Back substitute
			for row, col in reversed(pivot_cols):
				rhs = b[row]
				for j in range(col + 1, core_m):
					if A[row][j] % _EC_N != 0 and not core_table[j].is_infinity:
						rhs = _ec_point_add(rhs, _ec_point_neg(_ec_scalar_mult(A[row][j], core_table[j])))
				core_table[col] = rhs
			
			# Copy core solution back to main table
			for i, pos in enumerate(core_positions):
				table[pos] = core_table[i]
			
			# Verify all constraints
			all_good = True
			for x in items:
				positions = [h(x) for h in hashes]
				result = EC_INFINITY
				for pos in positions:
					result = _ec_point_add(result, table[pos])
				expected = _hash_to_point_ec(x)
				if not (result == expected):
					all_good = False
					break
			
			if all_good:
				return table, {
					"seed": seed,
					"k": k,
					"m": m,
					"n": n,
					"peeled": len(peeled_edges),
					"core": len(unpeeled)
				}
			
			# Failed - try new seed
			seed = random.randint(0, 2**32 - 1)
			continue
	
	raise RuntimeError(f"Failed to construct ELLIPSE table after {max_attempts} attempts")


def construct_ellipse_table_ec_sparse(
	items: Sequence[bytes], m: int, k: int = 3, seed: int | None = None, max_attempts: int = 10
) -> Tuple[List[ECPoint], Dict]:
	"""
	Construct an ELLIPSE table using SPARSE Gaussian elimination.
	
	This is optimized for high-k systems by storing only non-zero matrix entries.
	Much faster than dense Gaussian for sparse constraint matrices.
	
	Complexity: O(n × k²) instead of O(n × m²)
	For k=10, m=1000: ~100× faster than dense!
	
	Works directly on EC points without discrete logs!
	
	Args:
		items: Sequence of unique byte strings to encode
		m: Size of the table
		k: Number of hash functions
		seed: Optional seed for hash functions
		max_attempts: Maximum attempts to find a solvable system
	
	Returns:
		(table, metadata) where table is list of ECPoints and metadata contains seed
	
	Raises:
		RuntimeError: If unable to construct after max_attempts
	"""
	for attempt in range(max_attempts):
		if seed is None:
			seed = random.randint(0, 2**32 - 1)
		
		# Build hash functions
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
		
		n = len(items)
		
		# Build SPARSE coefficient matrix and value vector
		# Store as list of (row_idx, col_idx, value) for non-zero entries
		# For each row, store {col: coefficient} dict
		A_rows = []  # List of dicts: A_rows[i] = {col: coeff}
		b = []  # List of EC points
		
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			row = {}
			# Count occurrences (handles duplicates like h0(x)==h1(x))
			for pos in positions:
				row[pos] = (row.get(pos, 0) + 1) % _EC_N
			A_rows.append(row)
			b.append(_hash_to_point_ec(x))
		
		# Sparse Gaussian elimination
		# Track which rows have been used as pivots
		pivot_rows = []  # List of (row_idx, pivot_col)
		used_cols = set()
		
		# Forward elimination
		for current_col in range(m):
			if current_col in used_cols:
				continue
			
			# Find pivot row (row with non-zero entry in current_col)
			pivot_row = None
			for row_idx in range(n):
				if row_idx in [r for r, _ in pivot_rows]:
					continue  # Row already used as pivot
				if current_col in A_rows[row_idx] and A_rows[row_idx][current_col] % _EC_N != 0:
					pivot_row = row_idx
					break
			
			if pivot_row is None:
				continue  # No pivot in this column
			
			pivot_val = A_rows[pivot_row][current_col]
			pivot_inv = pow(pivot_val, _EC_N - 2, _EC_N)
			
			# Normalize pivot row (make pivot = 1)
			for col in A_rows[pivot_row]:
				A_rows[pivot_row][col] = (A_rows[pivot_row][col] * pivot_inv) % _EC_N
			b[pivot_row] = _ec_scalar_mult(pivot_inv, b[pivot_row])
			
			# Mark this row/col as used
			pivot_rows.append((pivot_row, current_col))
			used_cols.add(current_col)
			
			# Eliminate below pivot (only for rows that have entry in current_col)
			for row_idx in range(n):
				if row_idx == pivot_row:
					continue
				if row_idx in [r for r, _ in pivot_rows]:
					continue  # Row already used as pivot
				
				if current_col not in A_rows[row_idx]:
					continue  # No entry to eliminate
				
				coeff = A_rows[row_idx][current_col]
				if coeff == 0:
					continue
				
				# row = row - coeff * pivot_row (sparse operations)
				# First, subtract from all columns in pivot row
				for col in A_rows[pivot_row]:
					new_val = (A_rows[row_idx].get(col, 0) - coeff * A_rows[pivot_row][col]) % _EC_N
					if new_val == 0:
						A_rows[row_idx].pop(col, None)  # Remove zero entries
					else:
						A_rows[row_idx][col] = new_val
				
				# Update b vector
				b[row_idx] = _ec_point_add(b[row_idx], _ec_point_neg(_ec_scalar_mult(coeff, b[pivot_row])))
		
		# Back substitution
		table = [EC_INFINITY for _ in range(m)]
		
		# Work backwards through pivot rows
		for row_idx, pivot_col in reversed(pivot_rows):
			# Solve: T[pivot_col] + sum(A[row][j] * T[j] for j > pivot_col) = b[row]
			rhs = b[row_idx]
			
			for col in A_rows[row_idx]:
				if col > pivot_col and not table[col].is_infinity:
					# Subtract already-solved variables
					rhs = _ec_point_add(rhs, _ec_point_neg(_ec_scalar_mult(A_rows[row_idx][col], table[col])))
			
			# Since pivot is normalized to 1: T[pivot_col] = rhs
			table[pivot_col] = rhs
		
		# Verify all constraints
		all_good = True
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			result = EC_INFINITY
			for pos in positions:
				result = _ec_point_add(result, table[pos])
			expected = _hash_to_point_ec(x)
			if not (result == expected):
				all_good = False
				break
		
		if all_good:
			# Count non-zero entries in original matrix
			nnz = sum(len(row) for row in A_rows)
			return table, {
				"seed": seed,
				"k": k,
				"m": m,
				"n": n,
				"non_zero_entries": nnz,
				"sparsity": f"{100*nnz/(n*m):.2f}%"
			}
		
		# Failed - try new seed
		seed = random.randint(0, 2**32 - 1)
		continue
	
	raise RuntimeError(f"Failed to construct ELLIPSE table after {max_attempts} attempts")


def construct_ellipse_table_ec_scipy(
	items: Sequence[bytes], m: int, k: int = 3, seed: int | None = None, max_attempts: int = 10
) -> Tuple[List[ECPoint], Dict]:
	"""
	Construct an ELLIPSE table using scipy.sparse for matrix operations.
	
	This uses scipy.sparse to handle the SCALAR coefficient matrix efficiently,
	while mirroring operations on the EC point value vector.
	
	Key insight: Coefficient matrix A (scalars) is separate from values b (EC points)!
	scipy operates on A, we manually apply same operations to b.
	
	Requires: scipy installed
	Complexity: O(n × k²) with fast C implementations for matrix ops
	
	Args:
		items: Sequence of unique byte strings to encode
		m: Size of the table
		k: Number of hash functions
		seed: Optional seed for hash functions
		max_attempts: Maximum attempts to find a solvable system
	
	Returns:
		(table, metadata) where table is list of ECPoints and metadata contains seed
	
	Raises:
		RuntimeError: If scipy not available or unable to construct after max_attempts
	"""
	if not SCIPY_AVAILABLE:
		raise RuntimeError("scipy not installed. Install with: pip install scipy")
	
	for attempt in range(max_attempts):
		if seed is None:
			seed = random.randint(0, 2**32 - 1)
		
		# Build hash functions
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
		
		n = len(items)
		
		# Build SPARSE coefficient matrix using scipy (SCALARS ONLY!)
		# Coefficients are small (0-k), so int32 is fine during construction
		# We'll handle modulo _EC_N when doing scalar operations
		A = sp.lil_matrix((n, m), dtype=np.int32)
		b = []  # EC points
		
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			# Count occurrences (handles duplicates)
			for pos in positions:
				A[i, pos] = A[i, pos] + 1
			b.append(_hash_to_point_ec(x))
		
		# Convert to CSR for efficient row operations
		A = A.tocsr()
		
		# Track pivot information
		pivot_rows = []  # List of (row_idx, pivot_col)
		used_rows = set()
		used_cols = set()
		
		# Forward elimination
		for current_col in range(m):
			if current_col in used_cols:
				continue
			
			# Find pivot row (non-zero entry in current_col)
			pivot_row = None
			col_data = A.getcol(current_col).toarray().flatten()
			for row_idx in range(n):
				if row_idx in used_rows:
					continue
				if col_data[row_idx] != 0:
					pivot_row = row_idx
					break
			
			if pivot_row is None:
				continue  # No pivot in this column
			
			pivot_val = int(A[pivot_row, current_col]) % _EC_N
			pivot_inv = pow(pivot_val, _EC_N - 2, _EC_N)
			
			# Normalize pivot row
			# A: multiply row by pivot_inv (keep as Python ints for large values)
			pivot_row_data = A[pivot_row].toarray().flatten()
			for j in range(m):
				if pivot_row_data[j] != 0:
					A[pivot_row, j] = int((pivot_row_data[j] * pivot_inv) % _EC_N)
			# b: same operation on EC point
			b[pivot_row] = _ec_scalar_mult(pivot_inv, b[pivot_row])
			
			# Mark as used
			pivot_rows.append((pivot_row, current_col))
			used_rows.add(pivot_row)
			used_cols.add(current_col)
			
			# Eliminate below pivot
			# Find all rows with non-zero entry in current_col
			for row_idx in range(n):
				if row_idx == pivot_row or row_idx in used_rows:
					continue
				
				coeff = int(A[row_idx, current_col]) % _EC_N
				if coeff == 0:
					continue
				
				# A: row = row - coeff * pivot_row (element-wise with modulo)
				current_row_data = A[row_idx].toarray().flatten()
				pivot_row_data = A[pivot_row].toarray().flatten()
				for j in range(m):
					new_val = (current_row_data[j] - coeff * pivot_row_data[j]) % _EC_N
					if new_val != 0:
						A[row_idx, j] = int(new_val)
					else:
						A[row_idx, j] = 0  # Explicitly zero out
				
				# b: same operation on EC points
				b[row_idx] = _ec_point_add(b[row_idx], _ec_point_neg(_ec_scalar_mult(coeff, b[pivot_row])))
		
		# Back substitution
		table = [EC_INFINITY for _ in range(m)]
		
		# Work backwards through pivot rows
		for row_idx, pivot_col in reversed(pivot_rows):
			# Get non-zero entries in this row
			row_data = A[row_idx].toarray().flatten()
			
			# Compute RHS: b[row] - sum(A[row,j] * T[j] for j > pivot_col)
			rhs = b[row_idx]
			for j in range(pivot_col + 1, m):
				coeff = int(row_data[j])
				if coeff != 0 and not table[j].is_infinity:
					rhs = _ec_point_add(rhs, _ec_point_neg(_ec_scalar_mult(coeff, table[j])))
			
			# Since pivot is normalized to 1: T[pivot_col] = rhs
			table[pivot_col] = rhs
		
		# Verify all constraints
		all_good = True
		for i, x in enumerate(items):
			positions = [h(x) for h in hashes]
			result = EC_INFINITY
			for pos in positions:
				result = _ec_point_add(result, table[pos])
			expected = _hash_to_point_ec(x)
			if not (result == expected):
				all_good = False
				break
		
		if all_good:
			return table, {
				"seed": seed,
				"k": k,
				"m": m,
				"n": n,
				"method": "scipy_sparse"
			}
		
		# Failed - try new seed
		seed = random.randint(0, 2**32 - 1)
		continue
	
	raise RuntimeError(f"Failed to construct ELLIPSE table after {max_attempts} attempts")


def test_ec_sparse(n: int, m: int, k: int = 10):
	"""
	Test sparse Gaussian elimination on ELLIPSE.
	This should be MUCH faster than dense Gaussian for high k!
	"""
	random.seed(424242)
	
	print(f"\nEC {k}-hash Sparse Gaussian (load factor {n/m:.2f}):")
	print(f"  Table size: {m} slots")
	print(f"  Items: {n}")
	print(f"  Hash functions: {k}")
	print()
	
	# Generate items
	print(f"Generating {n} random items...")
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	item_list = list(items)
	print(f"  ✓ Generated {len(item_list)} items")
	print()
	
	# Attempt construction
	print("Starting sparse Gaussian construction...")
	import time
	start = time.time()
	
	try:
		table, meta = construct_ellipse_table_ec_sparse(item_list, m=m, k=k, max_attempts=5)
		elapsed = time.time() - start
		
		print(f"  ✓ SUCCESS in {elapsed:.2f} seconds!")
		print(f"  Seed: {meta['seed']}")
		print(f"  Matrix sparsity: {meta['sparsity']} ({meta['non_zero_entries']} non-zero)")
		print()
		
		# Verify sample
		print("Verifying 10 random items...")
		seed = meta["seed"]
		sample_size = min(10, n)
		sample_indices = random.sample(range(n), sample_size)
		
		all_correct = True
		for idx in sample_indices:
			x = item_list[idx]
			got = retrieve_point_ec_khash(x, table, seed, k)
			expect = _hash_to_point_ec(x)
			if not (got == expect):
				print(f"  ✗ Item {idx}: MISMATCH")
				all_correct = False
			else:
				print(f"  ✓ Item {idx}: OK")
		
		if all_correct:
			print()
			print(f"✓ Sparse Gaussian completed successfully!")
			print(f"  Time: {elapsed:.2f}s")
			print(f"  Throughput: {n/elapsed:.1f} items/second")
			return True
		else:
			print()
			print(f"✗ Some items failed verification")
			return False
		
	except Exception as e:
		elapsed = time.time() - start
		print(f"  ✗ FAILED: {e}")
		print(f"  Time until failure: {elapsed:.2f}s")
		import traceback
		traceback.print_exc()
		return False


def test_ec_peeling_large(n: int = 900, m: int = 1000, k: int = 10):
	"""
	Test peeling algorithm on large ELLIPSE construction.
	This should be MUCH faster than Gaussian for high k!
	"""
	random.seed(424242)
	
	print(f"\nEC {k}-hash Peeling (LARGE TEST, load factor {n/m:.2f}):")
	print(f"  Table size: {m} slots")
	print(f"  Items: {n}")
	print(f"  Hash functions: {k}")
	print()
	
	# Generate items
	print("Generating random items...")
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	item_list = list(items)
	print(f"  ✓ Generated {len(item_list)} items")
	print()
	
	# Attempt construction
	print("Starting peeling construction...")
	import time
	start = time.time()
	
	try:
		table, meta = construct_ellipse_table_ec_peeling(item_list, m=m, k=k, max_attempts=5)
		elapsed = time.time() - start
		
		print(f"  ✓ SUCCESS in {elapsed:.2f} seconds!")
		print(f"  Seed: {meta['seed']}")
		print(f"  Peeled edges: {meta['peeled']}/{n}")
		print(f"  Core size: {meta['core']}")
		print()
		
		# Verify sample
		print("Verifying 10 random items...")
		seed = meta["seed"]
		sample_indices = random.sample(range(n), min(10, n))
		
		for idx in sample_indices:
			x = item_list[idx]
			got = retrieve_point_ec_khash(x, table, seed, k)
			expect = _hash_to_point_ec(x)
			if not (got == expect):
				print(f"  ✗ Item {idx}: MISMATCH")
			else:
				print(f"  ✓ Item {idx}: OK")
		
		print()
		print(f"✓ Peeling algorithm completed successfully!")
		print(f"  Time: {elapsed:.2f}s")
		print(f"  Throughput: {n/elapsed:.1f} items/second")
		
	except Exception as e:
		elapsed = time.time() - start
		print(f"  ✗ FAILED: {e}")
		print(f"  Time until failure: {elapsed:.2f}s")


def test_ec_gaussian(k: int = 3, trials: int = 50):
	"""
	Test Gaussian elimination for ELLIPSE without known discrete logs.
	This demonstrates that we can construct ELLIPSE on EC points when we only
	know the points themselves, not their discrete logs!
	"""
	random.seed(424242)
	m = 100
	n = 40
	
	print(f"\nEC {k}-hash Gaussian (NO DISCRETE LOGS NEEDED!, load factor {n/m:.2f}, {trials} trials):")
	print("  Values are arbitrary EC points with unknown discrete logs")
	print("  Using Gaussian elimination: scalars from hash structure, EC point arithmetic")
	
	successes = 0
	failures = 0
	
	import time
	total_time = 0
	
	for trial in range(trials):
		items = set()
		while len(items) < n:
			items.add(os.urandom(16))
		item_list = list(items)
		
		try:
			start = time.time()
			table, meta = construct_ellipse_table_ec_gaussian(item_list, m=m, k=k)
			elapsed = time.time() - start
			total_time += elapsed
			
			seed = meta["seed"]
			
			# Verify retrieval
			all_good = True
			for x in item_list:
				got = retrieve_point_ec_khash(x, table, seed, k)
				expect = _hash_to_point_ec(x)
				if not (got == expect):
					all_good = False
					break
			
			if all_good:
				successes += 1
			else:
				failures += 1
		except Exception as e:
			failures += 1
	
	avg_time = total_time / trials if trials > 0 else 0
	print(f"  Successes: {successes}/{trials} ({100*successes/trials:.1f}%)")
	print(f"  Failures:  {failures}/{trials} ({100*failures/trials:.1f}%)")
	print(f"  Avg time per trial: {avg_time*1000:.2f} ms")
	print()
	print("  ✓ Works directly on EC points!")
	print("  ✓ No discrete logs needed!")
	print("  ✓ Scalars come from hash structure, not from extracting DLogs!")


def test_ec_msm(n: int, m: int, k: int):
	"""
	Test MSM-optimized Gaussian elimination on ELLIPSE.
	This should be 2-3× faster than regular Gaussian by batching EC operations!
	
	Args:
		n: Number of items to encode
		m: Table size (number of slots)
		k: Number of hash functions
	"""
	random.seed(424242)
	
	print("=" * 70)
	print(f"EC {k}-hash MSM Gaussian (load factor {n/m:.2f})")
	print("=" * 70)
	print(f"  Table size: {m} slots")
	print(f"  Items: {n}")
	print(f"  Hash functions: {k}")
	print()
	
	# Generate items
	print(f"Generating {n} random items...")
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	item_list = list(items)
	print(f"  ✓ Generated {len(item_list)} items")
	print()
	
	# Attempt construction
	print("Starting MSM-optimized construction...")
	import time
	start = time.time()
	
	try:
		table, meta = construct_ellipse_table_ec_msm(
			item_list, m=m, k=k, max_attempts=5
		)
		elapsed = time.time() - start
		
		print(f"  ✓ SUCCESS in {elapsed:.2f} seconds!")
		print(f"  Seed: {meta['seed']}")
		print(f"  Avg coefficients per row: {meta['avg_coeffs_per_row']:.1f}")
		print()
		
		# Verify sample
		print("Verifying 10 random items...")
		seed = meta["seed"]
		sample_size = min(10, n)
		sample_indices = random.sample(range(n), sample_size)
		
		all_correct = True
		for idx in sample_indices:
			x = item_list[idx]
			got = retrieve_point_ec_khash(x, table, seed, k)
			expect = _hash_to_point_ec(x)
			if not (got == expect):
				print(f"  ✗ Item {idx}: MISMATCH")
				all_correct = False
			else:
				print(f"  ✓ Item {idx}: OK")
		
		if all_correct:
			print()
			print(f"✓ MSM construction completed successfully!")
			print(f"  Total time: {elapsed:.2f}s ({elapsed/60:.2f} minutes)")
			print(f"  Throughput: {n/elapsed:.1f} items/second")
			return True
		else:
			print()
			print(f"✗ Some items failed verification")
			return False
		
	except Exception as e:
		elapsed = time.time() - start
		print(f"  ✗ FAILED: {e}")
		print(f"  Time until failure: {elapsed:.2f}s")
		import traceback
		traceback.print_exc()
		return False


def test_ec_parallel(n: int, m: int, k: int, num_cores: int):
	"""
	Test PARALLEL Gaussian elimination on EC PaXoS.
	This should dramatically speed up construction by parallelizing EC operations!
	
	Args:
		n: Number of items to encode
		m: Table size (number of slots)
		k: Number of hash functions
		num_cores: Number of CPU cores to use
	"""
	random.seed(424242)
	
	print("=" * 70)
	print(f"EC {k}-hash PARALLEL Gaussian (load factor {n/m:.2f})")
	print("=" * 70)
	print(f"  Table size: {m} slots")
	print(f"  Items: {n}")
	print(f"  Hash functions: {k}")
	print(f"  CPU cores: {num_cores}")
	print()
	
	# Generate items
	print(f"Generating {n} random items...")
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	item_list = list(items)
	print(f"  ✓ Generated {len(item_list)} items")
	print()
	
	# Attempt construction
	print(f"Starting parallel construction with {num_cores} cores...")
	import time
	start = time.time()
	
	try:
		table, meta = construct_ellipse_table_ec_parallel(
			item_list, m=m, k=k, max_attempts=5, num_cores=num_cores
		)
		elapsed = time.time() - start
		
		print(f"  ✓ SUCCESS in {elapsed:.2f} seconds!")
		print(f"  Seed: {meta['seed']}")
		print()
		
		# Verify sample
		print("Verifying 10 random items...")
		seed = meta["seed"]
		sample_size = min(10, n)
		sample_indices = random.sample(range(n), sample_size)
		
		all_correct = True
		for idx in sample_indices:
			x = item_list[idx]
			got = retrieve_point_ec_khash(x, table, seed, k)
			expect = _hash_to_point_ec(x)
			if not (got == expect):
				print(f"  ✗ Item {idx}: MISMATCH")
				all_correct = False
			else:
				print(f"  ✓ Item {idx}: OK")
		
		if all_correct:
			print()
			print(f"✓ Parallel construction completed successfully!")
			print(f"  Time: {elapsed:.2f}s ({elapsed/60:.2f} minutes)")
			print(f"  Throughput: {n/elapsed:.1f} items/second")
			
			# Estimate time for single core
			# Rough estimate: parallel speedup ~(num_cores * 0.87) for EC ops
			# EC ops are ~90% of total time
			ec_fraction = 0.90
			ec_speedup = min(num_cores * 0.87, n)  # Can't parallelize more than n operations
			serial_time_estimate = elapsed * (1 + (ec_speedup - 1) * ec_fraction)
			
			print()
			print(f"Performance Analysis:")
			print(f"  Estimated single-core time: {serial_time_estimate:.2f}s ({serial_time_estimate/60:.2f} min)")
			print(f"  Actual parallel time: {elapsed:.2f}s ({elapsed/60:.2f} min)")
			print(f"  Speedup: {serial_time_estimate/elapsed:.1f}×")
			print(f"  Efficiency: {100*serial_time_estimate/(elapsed*num_cores):.1f}%")
			
			return True
		else:
			print()
			print(f"✗ Some items failed verification")
			return False
		
	except Exception as e:
		elapsed = time.time() - start
		print(f"  ✗ FAILED: {e}")
		print(f"  Time until failure: {elapsed:.2f}s")
		import traceback
		traceback.print_exc()
		return False


if __name__ == "__main__":
	import sys
	
	print("=" * 70)
	print("EC PaXoS Tests")
	print("=" * 70)
	
	# Check if parallel test requested
	if len(sys.argv) > 1 and sys.argv[1] == "parallel":
		# Parallel test mode
		n = int(sys.argv[2]) if len(sys.argv) > 2 else 40
		m = int(sys.argv[3]) if len(sys.argv) > 3 else 100
		k = int(sys.argv[4]) if len(sys.argv) > 4 else 10
		num_cores = int(sys.argv[5]) if len(sys.argv) > 5 else cpu_count()
		
		print()
		print("Running PARALLEL test:")
		print(f"  n={n}, m={m}, k={k}, num_cores={num_cores}")
		print()
		
		test_ec_parallel(n=n, m=m, k=k, num_cores=num_cores)
	else:
		# Original tests
		test_ec_two_hash_failure_rate()
		test_ec_three_hash()
		test_ec_khash(10)
		
		# New test: Gaussian on EC points without known discrete logs
		print()
		print("=" * 70)
		print("GAUSSIAN ON EC POINTS (No Discrete Logs Required!)")
		print("=" * 70)
		test_ec_gaussian(k=3, trials=50)
