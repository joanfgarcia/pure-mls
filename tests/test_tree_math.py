from pure_mls.tree_math import level, root, left, right, parent, direct_path, copath

def test_tree_level() -> None:
	assert level(0) == 0
	assert level(1) == 1
	assert level(2) == 0
	assert level(3) == 2

def test_tree_root() -> None:
	# n = number of leaves
	assert root(1) == 0  # 1 leaf -> node 0 is root
	assert root(2) == 1  # 2 leaves -> node 1 is root
	assert root(3) == 3  # 3 leaves -> node 3 is root
	assert root(4) == 3  # 4 leaves -> node 3 is root
	assert root(5) == 7 

def test_tree_children() -> None:
	# For root(4) = 3
	assert left(3) == 1
	assert right(3) == 5
	assert left(1) == 0
	assert right(1) == 2
	assert left(5) == 4
	assert right(5) == 6

def test_tree_parent() -> None:
	n = 4 # 4 leaves, 7 nodes (0 to 6)
	assert parent(0, n) == 1
	assert parent(2, n) == 1
	assert parent(1, n) == 3
	assert parent(4, n) == 5
	assert parent(6, n) == 5
	assert parent(5, n) == 3
	assert parent(3, n) == 3 # Root parent is itself

def test_tree_direct_path() -> None:
	n = 4
	# Leaf 0 path to root (3) -> [1, 3]
	assert direct_path(0, n) == [1, 3]
	# Leaf 6 path to root (3) -> [5, 3]
	assert direct_path(6, n) == [5, 3]

def test_tree_copath() -> None:
	n = 4
	# Leaf 0 direct path is [1, 3]. Complete resolved path is 0, 1, 3.
	# Siblings: sibling of 0 is 2. sibling of 1 is 5.
	assert copath(0, n) == [2, 5]
	
	# Leaf 4 direct path is [5, 3]. Complete resolved is 4, 5, 3.
	# Siblings: sibling of 4 is 6. sibling of 5 is 1.
	assert copath(4, n) == [6, 1]
