import hashlib

from pure_mls.tls import tls_opaque, tls_opaque_varint, tls_u32
from pure_mls.tree import LeafNode, ParentNode, RatchetTree


def _make_hpke_info(label: str, context: bytes) -> bytes:
	"""RFC 9420 §4.5: HPKE info = HPKELabel{label, context} (omitting length per common interop)."""
	full_label = b"MLS 1.0 " + label.encode("ascii")
	return tls_opaque_varint(full_label) + tls_opaque_varint(context)


def _egs_info(egi: bytes) -> bytes:
	"""RFC 9420 §12.4.2: HPKE info for EncryptedGroupSecrets."""
	return _make_hpke_info("Welcome", egi)


def _up_info(group_ctx: bytes) -> bytes:
	"""RFC 9420 §5.1.3: HPKE info for UpdatePathNode."""
	return _make_hpke_info("UpdatePathNode", group_ctx)


def _subtree_hash(tree: "RatchetTree", index: int) -> bytes:
	"""RFC 9420 §7.8: recursive subtree hash for parent_hash computation."""
	if index < 0 or index >= len(tree.nodes):
		return hashlib.sha256(b"").digest()
	node = tree.get_node(index)
	if index % 2 == 0:  # leaf
		# RFC 9420 §7.8 LeafNodeHashInput: node_type + uint32 leaf_index + optional<LeafNode>.
		# Must match tree._node_hash (audit tree_hash): the leaf_index was previously omitted.
		leaf_prefix = b"\x01" + tls_u32(index // 2)
		if node is None:
			return hashlib.sha256(leaf_prefix + b"\x00").digest()
		assert isinstance(node, LeafNode)
		return hashlib.sha256(leaf_prefix + b"\x01" + node.to_bytes()).digest()

	lvl = tree.level(index)
	child_dist = 1 << (lvl - 1)
	left = index - child_dist
	right = index + child_dist
	left_hash = _subtree_hash(tree, left)
	right_hash = _subtree_hash(tree, right)

	if node is None:
		return hashlib.sha256(b"\x02\x00" + tls_opaque_varint(left_hash) + tls_opaque_varint(right_hash)).digest()

	assert isinstance(node, ParentNode)
	return hashlib.sha256(b"\x02\x01" + node.to_bytes() + tls_opaque_varint(left_hash) + tls_opaque_varint(right_hash)).digest()


def _compute_parent_hash(new_public_key: bytes, parent_hash_of_parent: bytes, original_sibling_tree_hash: bytes) -> bytes:
	"""RFC 9420 §7.9: parent_hash = SHA-256(label + ParentHashInput)."""
	label = b"MLS 1.0 parent hash"

	return hashlib.sha256(
		tls_opaque(label) + tls_opaque(new_public_key) + tls_opaque(parent_hash_of_parent) + tls_opaque(original_sibling_tree_hash)
	).digest()
