import hashlib

from pure_mls.tls import tls_opaque, tls_opaque_varint
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
		if node is None:
			return hashlib.sha256(b"").digest()
		assert isinstance(node, LeafNode)
		return hashlib.sha256(node.key_package.to_bytes()).digest()

	lvl = tree.level(index)
	child_dist = 1 << (lvl - 1)
	left = index - child_dist
	right = index + child_dist
	left_hash = _subtree_hash(tree, left)
	right_hash = _subtree_hash(tree, right)

	if node is None:
		return hashlib.sha256(left_hash + right_hash).digest()

	assert isinstance(node, ParentNode)
	assert node.public_key is not None

	parent_node_bytes = tls_opaque(node.public_key) + tls_opaque(node.parent_hash) + tls_opaque(node.unmerged_leaves_bytes())
	return hashlib.sha256(parent_node_bytes + left_hash + right_hash).digest()


def _compute_parent_hash(new_public_key: bytes, parent_hash_of_parent: bytes, original_sibling_tree_hash: bytes) -> bytes:
	"""RFC 9420 §7.9: parent_hash = SHA-256(label + ParentHashInput)."""
	label = b"MLS 1.0 parent hash"

	return hashlib.sha256(
		tls_opaque(label) + tls_opaque(new_public_key) + tls_opaque(parent_hash_of_parent) + tls_opaque(original_sibling_tree_hash)
	).digest()
