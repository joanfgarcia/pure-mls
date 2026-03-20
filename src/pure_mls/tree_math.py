"""
TreeKEM Array-Balanced Binary Tree (LBBT) Math.
Implements the exact tree indexing logic defined in RFC 9420, Section 5.1.1.2.
"""


def level(x: int) -> int:
	"""Returns the level of a node x in the tree (number of trailing 1s)."""
	k = 0
	while ((x >> k) & 1) == 1:
		k += 1
	return k


def root(n: int) -> int:
	"""
	Returns the index of the root node of an LBBT with `n` leaves.
	The root is always the largest power of 2 that is less than n, minus 1.
	"""
	if n == 0:
		return 0
	w = 1
	while w < n:
		w *= 2
	return w - 1


def left(x: int) -> int:
	"""Returns the index of the left child of node x."""
	k = level(x)
	if k == 0:
		return x
	return x ^ (0x01 << (k - 1))


def right(x: int) -> int:
	"""Returns the index of the right child of node x."""
	k = level(x)
	if k == 0:
		return x
	return x ^ (0x03 << (k - 1))


def parent(x: int, n: int) -> int:
	"""Returns the index of the parent of node x in a tree with n leaves."""
	if x == root(n):
		return x
	b = level(x)
	p = (x | (1 << b)) & ~(1 << (b + 1))

	# Sub-tree overflow logic for left-skewed trees
	num_nodes = 2 * n - 1
	while p >= num_nodes:
		p = (p | (1 << (b + 1))) & ~(1 << (b + 2))
		b += 1
	return p


def direct_path(x: int, n: int) -> list[int]:
	"""
	Returns the direct path from node x to the root.
	The direct path is the sequence of nodes starting from x's parent up to the root.
	"""
	d = []
	p = parent(x, n)
	while p != x:
		d.append(p)
		x = p
		p = parent(x, n)
	return d


def copath(x: int, n: int) -> list[int]:
	"""
	Returns the copath of node x to the root.
	The copath contains the siblings of all nodes in the direct path (including x's sibling).
	"""
	path = [x] + direct_path(x, n)
	# The root has no sibling, so we don't calculate a co-node for it
	if path[-1] == root(n):
		path.pop()

	c = []
	for node in path:
		p = parent(node, n)
		if node == left(p):
			c.append(right(p))
		else:
			c.append(left(p))
	return c
