# P1-C: test_tree_math.py updated to test RatchetTree methods (tree_math.py is deprecated)
# These tests now validate the RFC 9420 Appendix C compliant implementations in RatchetTree.

import pytest

from pure_mls.tree import RatchetTree


def test_tree_level() -> None:
	tree = RatchetTree(num_leaves=4)
	assert tree.level(0) == 0
	assert tree.level(1) == 1
	assert tree.level(2) == 0
	assert tree.level(3) == 2


def test_tree_root() -> None:
	# n = number of leaves
	assert RatchetTree(num_leaves=1)._root() == 0  # 1 leaf -> node 0 is root
	assert RatchetTree(num_leaves=2)._root() == 1  # 2 leaves -> node 1 is root
	assert RatchetTree(num_leaves=3)._root() == 3  # 3 leaves -> node 3 is root
	assert RatchetTree(num_leaves=4)._root() == 3  # 4 leaves -> node 3 is root
	assert RatchetTree(num_leaves=5)._root() == 7


def test_tree_parent() -> None:
	tree = RatchetTree(num_leaves=4)
	assert tree._parent(0) == 1
	assert tree._parent(2) == 1
	assert tree._parent(1) == 3
	assert tree._parent(4) == 5
	assert tree._parent(6) == 5
	assert tree._parent(5) == 3
	assert tree._parent(3) == 3  # Root parent is itself


def test_tree_direct_path() -> None:
	tree = RatchetTree(num_leaves=4)
	# Leaf 0 (index 0) path to root (3) -> [1, 3]
	assert tree.direct_path(0) == [1, 3]
	# Leaf 3 (index 6) path to root (3) -> [5, 3]
	assert tree.direct_path(6) == [5, 3]


def test_tree_copath() -> None:
	tree = RatchetTree(num_leaves=4)
	# Leaf 0 copath: siblings of direct_path [1, 3] -> sibling(0)=2, sibling(1)=5
	assert tree.copath(0) == [2, 5]
	# Leaf 2 (index 4) copath: siblings of direct_path [5, 3] -> sibling(4)=6, sibling(5)=1
	assert tree.copath(4) == [6, 1]


def test_tree_math_deprecated() -> None:
	"""P1-03: tree_math.py eliminated — verify module no longer exists in the package."""
	with pytest.raises(ModuleNotFoundError):
		import pure_mls.tree_math  # noqa: F401
