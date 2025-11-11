import hashlib
import os
import random
from typing import Callable, Dict, List, Optional, Sequence, Tuple


ByteString = bytes

# --- Simple elliptic curve utilities (secp256k1) ---
_EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_EC_A = 0
_EC_B = 7
_EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_EC_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
_EC_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
_EC_INV_TWO = pow(2, _EC_N - 2, _EC_N)


class ECPoint:
	__slots__ = ("x", "y", "infinity")

	def __init__(self, x: Optional[int] = None, y: Optional[int] = None, infinity: bool = False):
		self.x = x
		self.y = y
		self.infinity = infinity

	def __repr__(self) -> str:
		if self.infinity:
			return "ECPoint(Infinity)"
		return f"ECPoint({self.x}, {self.y})"


EC_INFINITY = ECPoint(infinity=True)
EC_G = ECPoint(_EC_GX, _EC_GY)


def _ec_mod_inv(a: int, p: int = _EC_P) -> int:
	return pow(a, p - 2, p)


def _ec_point_add(p1: ECPoint, p2: ECPoint) -> ECPoint:
	if p1.infinity:
		return p2
	if p2.infinity:
		return p1
	if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
		return EC_INFINITY

	if p1.x == p2.x:
		lambda_num = (3 * p1.x * p1.x + _EC_A) % _EC_P
		lambda_den = _ec_mod_inv((2 * p1.y) % _EC_P)
	else:
		lambda_num = (p2.y - p1.y) % _EC_P
		lambda_den = _ec_mod_inv((p2.x - p1.x) % _EC_P)

	lmbda = (lambda_num * lambda_den) % _EC_P
	x3 = (lmbda * lmbda - p1.x - p2.x) % _EC_P
	y3 = (lmbda * (p1.x - x3) - p1.y) % _EC_P
	return ECPoint(x3, y3)


def _ec_point_neg(p: ECPoint) -> ECPoint:
	if p.infinity:
		return EC_INFINITY
	return ECPoint(p.x, (-p.y) % _EC_P)


def _ec_scalar_mult(k: int, point: ECPoint) -> ECPoint:
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
	return _ec_scalar_mult(scalar, EC_G)


def _digest_to_bytes(data: bytes, seed: int, length: int = 16) -> bytes:
	"""
	Derive a fixed-length byte string from data and a seed.
	"""
	h = hashlib.blake2b(digest_size=length)
	h.update(seed.to_bytes(8, "little"))
	h.update(data)
	return h.digest()


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


def _make_hashes_4(m: int, seed: int) -> Tuple[Callable[[bytes], int], Callable[[bytes], int], Callable[[bytes], int], Callable[[bytes], int]]:
	"""
	Four independent hash functions mapping arbitrary bytes -> [0, m).
	"""
	def h_i(i: int) -> Callable[[bytes], int]:
		def h(x: bytes) -> int:
			hh = hashlib.blake2b(digest_size=8)
			hh.update(seed.to_bytes(8, "little"))
			hh.update(i.to_bytes(1, "little"))
			hh.update(x)
			return int.from_bytes(hh.digest(), "little") % m
		return h

	return h_i(0), h_i(1), h_i(2), h_i(3)


def _value_of_item(x: bytes, payload_len: int = 16) -> bytes:
	"""
	Define the payload/value associated with an item.
	For demo: value(x) = 16-byte digest of x.
	"""
	return hashlib.blake2b(x, digest_size=payload_len).digest()


def _xor(a: bytes, b: bytes) -> bytes:
	return bytes(x ^ y for x, y in zip(a, b))


# ===== NON-EC PAXOS VERSIONS (DISABLED - NOT CALLED) =====
# These functions are kept for reference but are not used.
# Only EC versions are active.

def construct_paxos_table(
	items: Sequence[bytes],
	m: int,
	payload_len: int = 16,
	max_attempts: int = 64,
	seed: int | None = None,
) -> Tuple[List[bytes], Dict[str, int]]:
	"""
	Construct a PaXoS table with 2-hash (two locations per item) on an acyclic cuckoo graph.
	- items: sequence of distinct byte-strings representing keys
	- m: number of slots (vertices)
	- payload_len: bytes per slot/value
	- max_attempts: tries to find an acyclic placement
	- seed: optional seed controlling hash functions

	Returns:
	- table: list of length m with bytes payloads
	- meta: dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [b"\x00" * payload_len for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	# Ensure unique inputs for well-defined constraints
	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	for attempt in range(max_attempts):
		seed_attempt = (seed + attempt) & ((1 << 62) - 1)
		h0, h1 = _make_hashes(m, seed_attempt)

		# Build edges (u, v, e) where e is the value(x)
		edges: List[Tuple[int, int, bytes]] = []
		for x in items:
			u, v = h0(x), h1(x)
			# If u == v, rehash (self-loop would force e=0 constraint)
			if u == v:
				break
			edges.append((u, v, _value_of_item(x, payload_len)))
		else:
			# No self-loops encountered
			# Check for cycles using union-find
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
					return False  # cycle detected
				if rank[ra] < rank[rb]:
					parent[ra] = rb
				elif rank[ra] > rank[rb]:
					parent[rb] = ra
				else:
					parent[rb] = ra
					rank[ra] += 1
				return True

			acyclic = True
			for (u, v, _e) in edges:
				if not union(u, v):
					acyclic = False
					break

			if not acyclic:
				continue

			# We have an acyclic graph. Solve T[u] xor T[v] = e over the forest.
			adj: List[List[Tuple[int, bytes]]] = [[] for _ in range(m)]
			for u, v, e in edges:
				adj[u].append((v, e))
				adj[v].append((u, e))

			UNKNOWN = None
			table: List[bytes | None] = [UNKNOWN] * m

			visited = [False] * m
			for start in range(m):
				if visited[start]:
					continue
				# Skip isolated vertices
				if not adj[start]:
					visited[start] = True
					continue
				# Root this tree at 'start' with value 0
				table[start] = b"\x00" * payload_len
				stack: List[int] = [start]
				visited[start] = True
				while stack:
					u = stack.pop()
					u_val = table[u]
					assert u_val is not None
					for v, e in adj[u]:
						if table[v] is UNKNOWN:
							table[v] = _xor(u_val, e)
							visited[v] = True
							stack.append(v)

			# Replace None with zeros (for any isolated vertices)
			final_table: List[bytes] = [
				(b"\x00" * payload_len) if t is None else t for t in table
			]

			return final_table, {"seed": seed_attempt}

	raise RuntimeError("Failed to build acyclic cuckoo graph after max_attempts")


def construct_paxos_table_2hash_gauss(
	items: Sequence[bytes],
	m: int,
	payload_len: int = 16,
	seed: int | None = None,
) -> Tuple[List[bytes], Dict[str, int]]:
	"""
	Construct a PaXoS table with 2-hash using Gaussian elimination.
	This version handles cycles naturally, unlike the tree-based method.
	
	Constraint: T[h0(x)] XOR T[h1(x)] = value(x)
	
	Returns:
	- table: list of length m with bytes payloads
	- meta: dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [b"\x00" * payload_len for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	h0, h1 = _make_hashes(m, seed)
	
	# Build constraint system: T[h0(x)] XOR T[h1(x)] = value(x)
	constraints: List[Tuple[set, bytes]] = []
	stash: Dict[bytes, bytes] = {}  # For self-loop items with non-zero values
	
	for x in items:
		pos0, pos1 = h0(x), h1(x)
		value = _value_of_item(x, payload_len)
		
		# If both positions are the same: T[pos] XOR T[pos] = 0 = value(x)
		# This only works if value(x) = 0, otherwise put in stash
		if pos0 == pos1:
			# Check if value is all zeros
			if value != b"\x00" * payload_len:
				# Can't encode in table - put in stash
				stash[x] = value
				continue
			# If value is 0, the constraint is automatically satisfied
			# (any value for T[pos] works), so we can skip this constraint
			continue
		
		positions = {pos0, pos1}
		constraints.append((positions, value))
	
	# Solve using Gaussian elimination over GF(2) per byte position
	table: List[bytes] = [b"\x00" * payload_len for _ in range(m)]
	
	for byte_idx in range(payload_len):
		rows: List[List[int]] = []
		rhs: List[int] = []
		
		for positions, value in constraints:
			row = [0] * m
			for pos in positions:
				row[pos] = 1
			rows.append(row)
			rhs.append(value[byte_idx])
		
		# Gaussian elimination over GF(2) - same approach as 3-hash
		n_constraints = len(rows)
		if n_constraints == 0:
			continue  # No constraints for this byte
		
		augmented = [rows[i] + [rhs[i]] for i in range(n_constraints)]
		
		pivot_cols = {}
		row = 0
		col = 0
		
		while row < n_constraints and col < m:
			pivot_row = None
			for r in range(row, n_constraints):
				if augmented[r][col] == 1:
					pivot_row = r
					break
			
			if pivot_row is None:
				col += 1
				continue
			
			if pivot_row != row:
				augmented[row], augmented[pivot_row] = augmented[pivot_row], augmented[row]
			
			pivot_cols[row] = col
			
			for r in range(row + 1, n_constraints):
				if augmented[r][col] == 1:
					for c in range(m + 1):
						augmented[r][c] ^= augmented[row][c]
			
			row += 1
			col += 1
		
		# Back substitution
		solution = [0] * m
		
		for r in range(n_constraints - 1, -1, -1):
			if r not in pivot_cols:
				continue
			
			pivot_col = pivot_cols[r]
			val = augmented[r][m]
			for c in range(m):
				if c != pivot_col and augmented[r][c] == 1:
					val ^= solution[c]
			
			solution[pivot_col] = val
		
		# Update table
		for i in range(m):
			table_bytes = bytearray(table[i])
			table_bytes[byte_idx] = solution[i]
			table[i] = bytes(table_bytes)
	
	return table, {"seed": seed, "stash": stash}
# ===== END NON-EC PAXOS VERSIONS =====


def construct_paxos_table_ec_tree(
	items: Sequence[bytes],
	m: int,
	max_attempts: int = 64,
	seed: int | None = None,
) -> Tuple[List[ECPoint], Dict[str, int]]:
	"""
	Construct PaXoS table with EC points using tree-based method (requires acyclic graph).
	Constraint: T[h0(x)] + T[h1(x)] = value_point(x) where + is EC point addition.
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
					if direct_assign[u].x != half_point.x or direct_assign[u].y != half_point.y:
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


def construct_paxos_table_ec_gauss(
	items: Sequence[bytes],
	m: int,
	seed: int | None = None,
) -> Tuple[List[ECPoint], Dict[str, int]]:
	"""
	Construct PaXoS table with EC points using Gaussian elimination (handles cycles).
	Constraint: T[h0(x)] + T[h1(x)] = value_point(x) where + is EC point addition.
	
	We solve in the scalar field (mod _EC_N) then convert to EC points.
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
		_ec_scalar_mult(s, EC_G) for s in solution_scalars
	]

	return table_points, {"seed": seed, "stash": {}}


def construct_paxos_table_with_stash(
	items: Sequence[bytes],
	m: int,
	payload_len: int = 16,
	seed: int | None = None,
) -> Tuple[List[bytes], Dict[bytes, bytes], Dict[str, int]]:
	"""
	Construct a PaXoS table that handles cycles by using a stash.
	Items that would create cycles are stored directly in the stash.
	
	Returns:
	- table: list of length m with bytes payloads
	- stash: dict mapping items to their values (for cycle-causing items)
	- meta: dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [b"\x00" * payload_len for _ in range(m)], {}, {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	h0, h1 = _make_hashes(m, seed)
	
	# Union-find for cycle detection
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
			return False  # cycle detected
		if rank[ra] < rank[rb]:
			parent[ra] = rb
		elif rank[ra] > rank[rb]:
			parent[rb] = ra
		else:
			parent[rb] = ra
			rank[ra] += 1
		return True

	# Build edges, putting cycle-causing items in stash
	edges: List[Tuple[int, int, bytes, bytes]] = []  # (u, v, value, item)
	stash: Dict[bytes, bytes] = {}
	
	for x in items:
		u, v = h0(x), h1(x)
		if u == v:
			# Self-loop: put in stash
			stash[x] = _value_of_item(x, payload_len)
			continue
		
		# Check if adding this edge would create a cycle
		if not union(u, v):
			# Cycle detected: put this item in stash
			stash[x] = _value_of_item(x, payload_len)
		else:
			# No cycle: add to edges
			edges.append((u, v, _value_of_item(x, payload_len), x))

	# Solve the acyclic graph (same as before)
	adj: List[List[Tuple[int, bytes]]] = [[] for _ in range(m)]
	for u, v, e, _x in edges:
		adj[u].append((v, e))
		adj[v].append((u, e))

	UNKNOWN = None
	table: List[bytes | None] = [UNKNOWN] * m

	visited = [False] * m
	for start in range(m):
		if visited[start]:
			continue
		if not adj[start]:
			visited[start] = True
			continue
		table[start] = b"\x00" * payload_len
		stack: List[int] = [start]
		visited[start] = True
		while stack:
			u = stack.pop()
			u_val = table[u]
			assert u_val is not None
			for v, e in adj[u]:
				if table[v] is UNKNOWN:
					table[v] = _xor(u_val, e)
					visited[v] = True
					stack.append(v)

	final_table: List[bytes] = [
		(b"\x00" * payload_len) if t is None else t for t in table
	]

	return final_table, stash, {"seed": seed}


def construct_paxos_table_3hash(
	items: Sequence[bytes],
	m: int,
	payload_len: int = 16,
	seed: int | None = None,
) -> Tuple[List[bytes], Dict[str, int]]:
	"""
	Construct a PaXoS table using 3 hash functions.
	Constraint: T[h0(x)] XOR T[h1(x)] XOR T[h2(x)] = value(x)
	
	With 3 hash functions, cycles are extremely rare, so we can solve
	the linear system directly using Gaussian elimination over GF(2).
	
	Returns:
	- table: list of length m with bytes payloads
	- meta: dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [b"\x00" * payload_len for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	h0, h1, h2 = _make_hashes_3(m, seed)
	
	# Build constraint system: for each item x, we have
	# T[h0(x)] XOR T[h1(x)] XOR T[h2(x)] = value(x)
	# This is a linear system over GF(2) with m variables and n constraints
	
	# Represent each constraint as a set of positions and a value
	constraints: List[Tuple[set, bytes]] = []
	direct_assignments: Dict[int, bytes] = {}  # For items where all 3 positions are same
	
	for x in items:
		pos0, pos1, pos2 = h0(x), h1(x), h2(x)
		value = _value_of_item(x, payload_len)
		
		# If all three positions are the same: T[pos] XOR T[pos] XOR T[pos] = T[pos] = value
		if pos0 == pos1 == pos2:
			# Direct assignment: T[pos] = value
			if pos0 in direct_assignments:
				# Conflict: two items map to same position with different values
				# This is extremely rare, but handle by XORing (arbitrary resolution)
				direct_assignments[pos0] = _xor(direct_assignments[pos0], value)
			else:
				direct_assignments[pos0] = value
		else:
			positions = {pos0, pos1, pos2}
			constraints.append((positions, value))
	
	# Add direct assignments as single-variable constraints
	for pos, value in direct_assignments.items():
		constraints.append(({pos}, value))
	
	# Solve using Gaussian elimination over GF(2) per byte position
	# We solve payload_len independent systems (one per byte)
	table: List[bytes] = [b"\x00" * payload_len for _ in range(m)]
	
	for byte_idx in range(payload_len):
		# Build system for this byte: each constraint is a row
		# Row format: [coefficient for pos 0, ..., coefficient for pos m-1, RHS]
		rows: List[List[int]] = []
		rhs: List[int] = []
		
		for positions, value in constraints:
			row = [0] * m
			for pos in positions:
				row[pos] = 1  # XOR coefficient
			rows.append(row)
			rhs.append(value[byte_idx])  # Right-hand side
		
		# Gaussian elimination over GF(2)
		n_constraints = len(rows)
		
		# Create augmented matrix [A|b]
		augmented = [rows[i] + [rhs[i]] for i in range(n_constraints)]
		
		# Forward elimination with pivot tracking
		pivot_cols = {}  # row -> pivot column (tracked during elimination)
		row = 0
		col = 0
		
		while row < n_constraints and col < m:
			# Find pivot (row with 1 in column col)
			pivot_row = None
			for r in range(row, n_constraints):
				if augmented[r][col] == 1:
					pivot_row = r
					break
			
			if pivot_row is None:
				# No pivot in this column, move to next
				col += 1
				continue
			
			# Swap pivot row to current position
			if pivot_row != row:
				augmented[row], augmented[pivot_row] = augmented[pivot_row], augmented[row]
			
			# Record this pivot
			pivot_cols[row] = col
			
			# Eliminate column col in rows below
			for r in range(row + 1, n_constraints):
				if augmented[r][col] == 1:
					# XOR row r with pivot row
					for c in range(m + 1):
						augmented[r][c] ^= augmented[row][c]
			
			row += 1
			col += 1
		
		# Back substitution: solve from bottom up
		solution = [0] * m
		
		# Solve from bottom row to top (only rows with pivots)
		for r in range(n_constraints - 1, -1, -1):
			if r not in pivot_cols:
				continue  # Skip zero rows
			
			pivot_col = pivot_cols[r]
			# This row determines variable at pivot_col
			# Solve: var[pivot_col] = RHS XOR (sum of other vars in row)
			val = augmented[r][m]  # RHS
			for c in range(m):
				if c != pivot_col and augmented[r][c] == 1:
					val ^= solution[c]
			
			solution[pivot_col] = val
		
		# For any undetermined variables, set to 0 (arbitrary choice)
		# This is fine - they don't affect any constraints
		
		# Update table with solution for this byte
		for i in range(m):
			table_bytes = bytearray(table[i])
			table_bytes[byte_idx] = solution[i]
			table[i] = bytes(table_bytes)
	
	return table, {"seed": seed}


def construct_paxos_table_4hash(
	items: Sequence[bytes],
	m: int,
	payload_len: int = 16,
	seed: int | None = None,
) -> Tuple[List[bytes], Dict[str, int]]:
	"""
	Construct a PaXoS table using 4 hash functions.
	Constraint: T[h0(x)] XOR T[h1(x)] XOR T[h2(x)] XOR T[h3(x)] = value(x)
	
	With 4 hash functions, cycles are even rarer than with 3, and the system
	is more robust to collisions.
	
	Returns:
	- table: list of length m with bytes payloads
	- meta: dict with 'seed' for reproduction
	"""
	if len(items) == 0:
		return [b"\x00" * payload_len for _ in range(m)], {"seed": 0}

	if seed is None:
		seed = random.randrange(1 << 61)

	seen = set(items)
	if len(seen) != len(items):
		raise ValueError("Items must be distinct")

	h0, h1, h2, h3 = _make_hashes_4(m, seed)
	
	# Build constraint system: for each item x, we have
	# T[h0(x)] XOR T[h1(x)] XOR T[h2(x)] XOR T[h3(x)] = value(x)
	
	constraints: List[Tuple[set, bytes]] = []
	direct_assignments: Dict[int, bytes] = {}
	
	for x in items:
		pos0, pos1, pos2, pos3 = h0(x), h1(x), h2(x), h3(x)
		value = _value_of_item(x, payload_len)
		
		# Check for problematic collisions (even number of same positions)
		positions_list = [pos0, pos1, pos2, pos3]
		position_counts = {}
		for p in positions_list:
			position_counts[p] = position_counts.get(p, 0) + 1
		
		# If all 4 are the same: T[p] XOR T[p] XOR T[p] XOR T[p] = 0 = value(x)
		# This forces value(x) = 0, which is problematic
		if len(set(positions_list)) == 1:
			# All 4 same - would force value = 0, so skip or handle specially
			# Actually, this is impossible unless value = 0, so we'll skip
			continue
		
		# If 2 pairs are the same (e.g., pos0==pos1 and pos2==pos3, both = p):
		# T[p] XOR T[p] XOR T[p] XOR T[p] = 0 = value(x) - also problematic
		# But this is very rare, so we'll let Gaussian elimination handle it
		
		positions = {pos0, pos1, pos2, pos3}
		constraints.append((positions, value))
	
	# Solve using Gaussian elimination over GF(2) per byte position
	table: List[bytes] = [b"\x00" * payload_len for _ in range(m)]
	
	for byte_idx in range(payload_len):
		rows: List[List[int]] = []
		rhs: List[int] = []
		
		for positions, value in constraints:
			row = [0] * m
			for pos in positions:
				row[pos] = 1
			rows.append(row)
			rhs.append(value[byte_idx])
		
		# Gaussian elimination over GF(2) - same as 3-hash
		n_constraints = len(rows)
		augmented = [rows[i] + [rhs[i]] for i in range(n_constraints)]
		
		pivot_cols = {}
		row = 0
		col = 0
		
		while row < n_constraints and col < m:
			pivot_row = None
			for r in range(row, n_constraints):
				if augmented[r][col] == 1:
					pivot_row = r
					break
			
			if pivot_row is None:
				col += 1
				continue
			
			if pivot_row != row:
				augmented[row], augmented[pivot_row] = augmented[pivot_row], augmented[row]
			
			pivot_cols[row] = col
			
			for r in range(row + 1, n_constraints):
				if augmented[r][col] == 1:
					for c in range(m + 1):
						augmented[r][c] ^= augmented[row][c]
			
			row += 1
			col += 1
		
		# Back substitution
		solution = [0] * m
		
		for r in range(n_constraints - 1, -1, -1):
			if r not in pivot_cols:
				continue
			
			pivot_col = pivot_cols[r]
			val = augmented[r][m]
			for c in range(m):
				if c != pivot_col and augmented[r][c] == 1:
					val ^= solution[c]
			
			solution[pivot_col] = val
		
		# Update table
		for i in range(m):
			table_bytes = bytearray(table[i])
			table_bytes[byte_idx] = solution[i]
			table[i] = bytes(table_bytes)
	
	return table, {"seed": seed}


# ===== NON-EC RETRIEVAL FUNCTIONS (DISABLED - NOT CALLED) =====
# These functions are kept for reference but are not used.

def retrieve_value(x: bytes, table: Sequence[bytes], seed: int) -> bytes:
	"""
	Retrieve the stored value for item x as XOR of its two locations.
	"""
	m = len(table)
	h0, h1 = _make_hashes(m, seed)
	u, v = h0(x), h1(x)
	return _xor(table[u], table[v])


def retrieve_value_3hash(x: bytes, table: Sequence[bytes], seed: int) -> bytes:
	"""
	Retrieve the stored value for item x as XOR of its three locations.
	"""
	m = len(table)
	h0, h1, h2 = _make_hashes_3(m, seed)
	u, v, w = h0(x), h1(x), h2(x)
	return _xor(_xor(table[u], table[v]), table[w])


def retrieve_value_4hash(x: bytes, table: Sequence[bytes], seed: int) -> bytes:
	"""
	Retrieve the stored value for item x as XOR of its four locations.
	"""
	m = len(table)
	h0, h1, h2, h3 = _make_hashes_4(m, seed)
	u, v, w, z = h0(x), h1(x), h2(x), h3(x)
	return _xor(_xor(_xor(table[u], table[v]), table[w]), table[z])


def retrieve_value_with_stash(
	x: bytes, table: Sequence[bytes], stash: Dict[bytes, bytes], seed: int
) -> bytes:
	"""
	Retrieve the stored value for item x, checking stash first.
	"""
	# Check stash first (for cycle-causing items)
	if x in stash:
		return stash[x]
	
	# Otherwise, retrieve from table using XOR
	m = len(table)
	h0, h1 = _make_hashes(m, seed)
	u, v = h0(x), h1(x)
	return _xor(table[u], table[v])
# ===== END NON-EC RETRIEVAL FUNCTIONS =====


def retrieve_scalar_ec(x: bytes, table: Sequence[int], seed: int) -> int:
	m = len(table)
	h0, h1 = _make_hashes(m, seed)
	u, v = h0(x), h1(x)
	return (table[u] + table[v]) % _EC_N


def retrieve_point_ec(x: bytes, table: Sequence[ECPoint], seed: int) -> ECPoint:
	"""
	Retrieve the stored EC point for item x by adding its two table locations.
	Constraint: T[h0(x)] + T[h1(x)] = value_point(x)
	"""
	m = len(table)
	h0, h1 = _make_hashes(m, seed)
	u, v = h0(x), h1(x)
	return _ec_point_add(table[u], table[v])


# ===== NON-EC TEST FUNCTIONS (DISABLED - NOT CALLED) =====
# These functions are kept for reference but are not used.

def _demo_test():
	random.seed(1337)
	m = 100
	n = 40
	# Generate n random distinct items
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	items_list = list(items)

	table, meta = construct_paxos_table(items_list, m=m, payload_len=16, max_attempts=128)
	seed = meta["seed"]

	# Verify retrieval for encoded items
	failures = 0
	for x in items_list:
		got = retrieve_value(x, table, seed)
		expect = _value_of_item(x, 16)
		if got != expect:
			failures += 1
	print(f"Encoded items check: {n - failures}/{n} correct")
	assert failures == 0, "Some encoded items failed retrieval"

	# Quick negative test: random non-member should not match its digest (overwhelming probability)
	non_member_trials = 10
	neg_conflicts = 0
	for _ in range(non_member_trials):
		y = os.urandom(16)
		if y in items:
			continue
		got = retrieve_value(y, table, seed)
		expect = _value_of_item(y, 16)
		if got == expect:
			neg_conflicts += 1
	print(f"Non-member accidental matches: {neg_conflicts}/{non_member_trials}")
	assert neg_conflicts == 0, "Unexpected match for non-member (extremely unlikely)"

	print("Demo passed.")


def _test_single_attempt_failure_rate():
	"""
	Test what happens if we only try one hash seed (max_attempts=1).
	Shows the failure rate when cycles occur.
	"""
	random.seed(42)  # Fixed seed for reproducibility
	m = 100
	n = 40
	trials = 100
	
	successes = 0
	failures = 0
	
	for trial in range(trials):
		# Generate random items
		items = set()
		while len(items) < n:
			items.add(os.urandom(16))
		items_list = list(items)
		
		try:
			table, meta = construct_paxos_table(
				items_list, m=m, payload_len=16, max_attempts=1
			)
			successes += 1
		except RuntimeError:
			failures += 1
	
	print(f"\nSingle attempt (max_attempts=1) results:")
	print(f"  Successes: {successes}/{trials} ({100*successes/trials:.1f}%)")
	print(f"  Failures:  {failures}/{trials} ({100*failures/trials:.1f}%)")
	print(f"\nWith n={n} items and m={m} slots (load factor {n/m:.2f})")
	print(f"Failure occurs when the random hash seed produces a cycle.")


def _test_stash_approach():
	"""
	Test the stash-based approach that handles cycles.
	This should always succeed, even with max_attempts=1.
	"""
	random.seed(999)
	m = 100
	n = 40
	
	# Generate random items
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	items_list = list(items)
	
	# Build table with stash (always succeeds, no retries needed)
	table, stash, meta = construct_paxos_table_with_stash(
		items_list, m=m, payload_len=16
	)
	seed = meta["seed"]
	
	print(f"\nStash-based approach (handles cycles):")
	print(f"  Total items: {n}")
	print(f"  Items in stash: {len(stash)} ({100*len(stash)/n:.1f}%)")
	print(f"  Items in table: {n - len(stash)} ({100*(n-len(stash))/n:.1f}%)")
	
	# Verify all items retrieve correctly
	failures = 0
	for x in items_list:
		got = retrieve_value_with_stash(x, table, stash, seed)
		expect = _value_of_item(x, 16)
		if got != expect:
			failures += 1
			print(f"  FAILED for item: {x.hex()[:16]}...")
	
	print(f"  Retrieval check: {n - failures}/{n} correct")
	assert failures == 0, "Some items failed retrieval"
	
	# Negative test
	non_member_trials = 10
	neg_conflicts = 0
	for _ in range(non_member_trials):
		y = os.urandom(16)
		if y in items:
			continue
		got = retrieve_value_with_stash(y, table, stash, seed)
		expect = _value_of_item(y, 16)
		if got == expect:
			neg_conflicts += 1
	
	print(f"  Non-member matches: {neg_conflicts}/{non_member_trials}")
	assert neg_conflicts == 0, "Unexpected match for non-member"
	
	print("  Stash approach test passed!")


def _test_3hash_approach():
	"""
	Test the 3-hash function approach.
	With 3 hash functions, cycles are extremely rare, so this should
	almost always succeed on the first try.
	"""
	random.seed(12345)
	m = 100
	n = 40
	
	# Generate random items
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	items_list = list(items)
	
	# Build table with 3-hash (should succeed on first try)
	table, meta = construct_paxos_table_3hash(
		items_list, m=m, payload_len=16
	)
	seed = meta["seed"]
	
	print(f"\n3-hash approach (handles cycles naturally):")
	print(f"  Total items: {n}")
	
	# Verify all items retrieve correctly
	failures = 0
	for x in items_list:
		got = retrieve_value_3hash(x, table, seed)
		expect = _value_of_item(x, 16)
		if got != expect:
			failures += 1
			print(f"  FAILED for item: {x.hex()[:16]}...")
			print(f"    Expected: {expect.hex()}")
			print(f"    Got:      {got.hex()}")
	
	print(f"  Retrieval check: {n - failures}/{n} correct")
	assert failures == 0, "Some items failed retrieval"
	
	# Negative test
	non_member_trials = 10
	neg_conflicts = 0
	for _ in range(non_member_trials):
		y = os.urandom(16)
		if y in items:
			continue
		got = retrieve_value_3hash(y, table, seed)
		expect = _value_of_item(y, 16)
		if got == expect:
			neg_conflicts += 1
	
	print(f"  Non-member matches: {neg_conflicts}/{non_member_trials}")
	assert neg_conflicts == 0, "Unexpected match for non-member"
	
	print("  3-hash approach test passed!")
	
	# Test success rate with single attempt
	trials = 100
	successes = 0
	for trial in range(trials):
		items_trial = [os.urandom(16) for _ in range(n)]
		try:
			table_trial, meta_trial = construct_paxos_table_3hash(
				items_trial, m=m, payload_len=16
			)
			# Verify a few items using the correct seed
			seed_trial = meta_trial["seed"]
			all_good = True
			for x in items_trial[:5]:  # Check first 5
				got = retrieve_value_3hash(x, table_trial, seed_trial)
				expect = _value_of_item(x, 16)
				if got != expect:
					all_good = False
					break
			if all_good:
				successes += 1
		except Exception:
			pass
	
	print(f"  3-hash success rate: {successes}/{trials} ({100*successes/trials:.1f}%)")


def _test_4hash_approach():
	"""
	Test the 4-hash function approach.
	With 4 hash functions, cycles are even rarer, and the system is more robust.
	"""
	random.seed(54321)
	m = 100
	n = 40
	
	# Generate random items
	items = set()
	while len(items) < n:
		items.add(os.urandom(16))
	items_list = list(items)
	
	# Build table with 4-hash
	table, meta = construct_paxos_table_4hash(
		items_list, m=m, payload_len=16
	)
	seed = meta["seed"]
	
	print(f"\n4-hash approach (even more robust):")
	print(f"  Total items: {n}")
	
	# Verify all items retrieve correctly
	failures = 0
	for x in items_list:
		got = retrieve_value_4hash(x, table, seed)
		expect = _value_of_item(x, 16)
		if got != expect:
			failures += 1
			print(f"  FAILED for item: {x.hex()[:16]}...")
	
	print(f"  Retrieval check: {n - failures}/{n} correct")
	assert failures == 0, "Some items failed retrieval"
	
	# Negative test
	non_member_trials = 10
	neg_conflicts = 0
	for _ in range(non_member_trials):
		y = os.urandom(16)
		if y in items:
			continue
		got = retrieve_value_4hash(y, table, seed)
		expect = _value_of_item(y, 16)
		if got == expect:
			neg_conflicts += 1
	
	print(f"  Non-member matches: {neg_conflicts}/{non_member_trials}")
	assert neg_conflicts == 0, "Unexpected match for non-member"
	
	print("  4-hash approach test passed!")
	
	# Test success rate with single attempt
	trials = 100
	successes = 0
	for trial in range(trials):
		items_trial = [os.urandom(16) for _ in range(n)]
		try:
			table_trial, meta_trial = construct_paxos_table_4hash(
				items_trial, m=m, payload_len=16
			)
			seed_trial = meta_trial["seed"]
			all_good = True
			for x in items_trial[:5]:
				got = retrieve_value_4hash(x, table_trial, seed_trial)
				expect = _value_of_item(x, 16)
				if got != expect:
					all_good = False
					break
			if all_good:
				successes += 1
		except Exception:
			pass
	
	print(f"  4-hash success rate: {successes}/{trials} ({100*successes/trials:.1f}%)")


def _test_2hash_gauss_vs_tree():
	"""
	Compare 2-hash tree-based method (requires acyclic) vs Gaussian elimination (handles cycles).
	This demonstrates that Gaussian elimination handles dense graphs/cycles better.
	"""
	random.seed(99999)
	m = 100
	n = 40
	trials = 100
	
	print(f"\n2-hash comparison: Tree-based (acyclic only) vs Gaussian elimination (handles cycles):")
	print(f"  Testing with n={n} items, m={m} slots, {trials} trials")
	
	tree_successes = 0
	gauss_successes = 0
	
	for trial in range(trials):
		items_trial = [os.urandom(16) for _ in range(n)]
		
		# Test tree-based method (requires acyclic)
		try:
			table_tree, meta_tree = construct_paxos_table(
				items_trial, m=m, payload_len=16, max_attempts=1
			)
			seed_tree = meta_tree["seed"]
			# Verify a few items
			all_good = True
			for x in items_trial[:5]:
				got = retrieve_value(x, table_tree, seed_tree)
				expect = _value_of_item(x, 16)
				if got != expect:
					all_good = False
					break
			if all_good:
				tree_successes += 1
		except RuntimeError:
			pass  # Failed due to cycles
		except Exception:
			pass
		
		# Test Gaussian elimination method (handles cycles)
		try:
			table_gauss, meta_gauss = construct_paxos_table_2hash_gauss(
				items_trial, m=m, payload_len=16
			)
			seed_gauss = meta_gauss["seed"]
			# Verify a few items
			all_good = True
			for x in items_trial[:5]:
				got = retrieve_value(x, table_gauss, seed_gauss)
				expect = _value_of_item(x, 16)
				if got != expect:
					all_good = False
					break
			if all_good:
				gauss_successes += 1
		except Exception:
			pass
	
	print(f"  Tree-based (acyclic only): {tree_successes}/{trials} ({100*tree_successes/trials:.1f}%)")
	print(f"  Gaussian elimination:      {gauss_successes}/{trials} ({100*gauss_successes/trials:.1f}%)")
	print(f"  Improvement: {100*(gauss_successes - tree_successes)/trials:.1f} percentage points")
	print(f"\n  Key insight: Gaussian elimination handles cycles naturally,")
	print(f"  while tree-based method fails when cycles are present.")


def _test_2hash_gauss_failure_rate():
	"""
	Test the 2-hash Gaussian elimination version to see failure rate at 0.4 load factor.
	"""
	random.seed(88888)
	m = 100
	n = 40  # 0.4 load factor
	trials = 1000
	
	print(f"\n2-hash Gaussian elimination failure rate test:")
	print(f"  Load factor: {n/m:.2f} (n={n} items, m={m} slots)")
	print(f"  Trials: {trials}")
	
	successes = 0
	failures = 0
	failure_reasons = {"self_loop": 0, "inconsistent": 0, "retrieval_error": 0}
	total_stash_items = 0
	
	for trial in range(trials):
		items_trial = [os.urandom(16) for _ in range(n)]
		
		try:
			table, meta = construct_paxos_table_2hash_gauss(
				items_trial, m=m, payload_len=16
			)
			seed = meta["seed"]
			stash = meta.get("stash", {})
			total_stash_items += len(stash)
			
			# Verify all items retrieve correctly
			all_good = True
			for x in items_trial:
				# Check stash first, then table
				if x in stash:
					got = stash[x]
				else:
					got = retrieve_value(x, table, seed)
				expect = _value_of_item(x, 16)
				if got != expect:
					all_good = False
					failure_reasons["retrieval_error"] += 1
					break
			
			if all_good:
				successes += 1
			else:
				failures += 1
		except Exception as e:
			failures += 1
			# Could track specific exception types if needed
	
	print(f"  Successes: {successes}/{trials} ({100*successes/trials:.2f}%)")
	print(f"  Failures:  {failures}/{trials} ({100*failures/trials:.2f}%)")
	avg_stash_size = total_stash_items / trials if trials > 0 else 0
	print(f"  Avg items in stash per trial: {avg_stash_size:.2f} ({100*avg_stash_size/n:.2f}% of items)")
	if failure_reasons["retrieval_error"] > 0:
		print(f"  Retrieval errors: {failure_reasons['retrieval_error']}")
	print(f"\n  Note: Self-loop items (h0(x) == h1(x)) with non-zero values")
	print(f"    are stored in a stash. Failures are now only due to")
	print(f"    inconsistent constraint systems (extremely rare).")
# ===== END NON-EC TEST FUNCTIONS =====


def _test_ec_two_hash_failure_rate():
	"""
	Compare failure rates for 2-hash PaXoS using elliptic-curve POINTS.
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
			tree_table, meta_tree = construct_paxos_table_ec_tree(
				item_list, m=m, max_attempts=1
			)
			seed_tree = meta_tree["seed"]
			all_good = True
			for x in item_list:
				got = retrieve_point_ec(x, tree_table, seed_tree)
				expect = _hash_to_point_ec(x)
				# Compare EC points by comparing coordinates
				if got.infinity != expect.infinity or got.x != expect.x or got.y != expect.y:
					all_good = False
					break
			if all_good:
				tree_success += 1
			else:
				tree_fail += 1
		except RuntimeError:
			tree_fail += 1

		try:
			gauss_table, meta_gauss = construct_paxos_table_ec_gauss(
				item_list, m=m
			)
			seed_gauss = meta_gauss["seed"]
			all_good = True
			for x in item_list:
				got = retrieve_point_ec(x, gauss_table, seed_gauss)
				expect = _hash_to_point_ec(x)
				# Compare EC points
				if got.infinity != expect.infinity or got.x != expect.x or got.y != expect.y:
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


if __name__ == "__main__":
	# Only EC PaXoS tests are active
	_test_ec_two_hash_failure_rate()
	
	# Non-EC tests are commented out:
	# _demo_test()
	# _test_single_attempt_failure_rate()
	# _test_stash_approach()
	# _test_3hash_approach()
	# _test_4hash_approach()
	# _test_2hash_gauss_vs_tree()
	# _test_2hash_gauss_failure_rate()


