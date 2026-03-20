import os

import pytest

from pure_mls.tree import KeyPackage, LeafNode, ParentNode, RatchetTree


def test_ratchet_tree_initialization() -> None:
	# A tree with 4 agents has 4 leaves and 3 parents. Array size = 7
	tree = RatchetTree(4)
	assert len(tree.nodes) == 7
	assert all(n is None for n in tree.nodes)


def test_ratchet_tree_insertion() -> None:
	tree = RatchetTree(4)

	kp = KeyPackage(identity_key_pub=os.urandom(32), init_key_pub=os.urandom(32))
	leaf = LeafNode(key_package=kp)
	parent = ParentNode(public_key=os.urandom(32), parent_hash=b"hash")

	# Insert leaf at even index 0
	tree.set_leaf(0, leaf)
	assert tree.get_node(0) == leaf

	# Insert parent at odd index 1
	tree.set_parent(1, parent)
	assert tree.get_node(1) == parent


def test_ratchet_tree_constraints() -> None:
	tree = RatchetTree(2)  # Size 3 [0, 1, 2]

	leaf = LeafNode(key_package=KeyPackage(b"i", b"e"))
	parent = ParentNode(public_key=b"p", parent_hash=b"h")

	with pytest.raises(ValueError):
		tree.set_leaf(1, leaf)  # Needs even

	with pytest.raises(ValueError):
		tree.set_parent(0, parent)  # Needs odd
