import pytest

from pure_mls.group import GroupUpdate, MLSGroup, _make_kp_ref
from pure_mls.group import _transcript_hash as _th
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage, LeafNode, ParentNode, RatchetTree


def test_welcome_info_from_bytes_errors():
	# Test node type ParentNode and Invalid type
	# Construct a valid WelcomeInfo first
	sig = SignatureKey()
	kem = KemKey()
	kp = KeyPackage(identity_key_pub=sig.public_bytes(), init_key_pub=kem.public_bytes())
	group = MLSGroup.create(b"cov-group", sig, kem)
	group2, welcome, update = group.add_member(kp)

	# Manually corrupt the tree_bytes node type to 0x02 to trigger ParentNode logic
	tree = RatchetTree(1)
	tree.nodes = [ParentNode(public_key=b"A" * 32, parent_hash=b"B" * 32)]
	from pure_mls.group import WelcomeInfo

	w_parent = WelcomeInfo(b"g", 1, tree, b"J" * 32, b"H" * 32, 2)
	w_parent_bytes = w_parent.to_bytes()
	parsed = WelcomeInfo.from_bytes(w_parent_bytes)
	assert isinstance(parsed.tree.nodes[0], ParentNode)

	# Trigger ValueError for invalid node type
	bad_tree_bytes = b"\x00\x00\x00\x00\x03" + b"X" * 64
	with pytest.raises(ValueError, match="Invalid node type"):
		RatchetTree.from_bytes(bad_tree_bytes)


def test_add_member_parent_node():
	from pure_mls.tree import RatchetTree

	sig1 = SignatureKey()
	kem1 = KemKey()
	group = MLSGroup.create(b"g1", sig1, kem1)

	# Pre-populate a standalone tree with a ParentNode to exercise the isinstance branch.
	raw_tree = RatchetTree(num_leaves=2)
	raw_tree.set_leaf(0, group.state.tree.get_node(0))
	raw_tree.set_parent(1, ParentNode(public_key=b"A" * 32, parent_hash=b"B" * 32))

	sig2 = SignatureKey()
	kem2 = KemKey()
	kp = KeyPackage(identity_key_pub=sig2.public_bytes(), init_key_pub=kem2.public_bytes())
	group.add_member(kp)  # Should hit elif isinstance(node, ParentNode)


def test_process_update_errors():
	sig = SignatureKey()
	kem = KemKey()
	group = MLSGroup.create(b"g1", sig, kem)

	# Empty secrets — sign with the STATE-02 full GroupInfo hash
	epoch_id = 1
	tree = group.state.tree
	encrypted_commit_secrets: dict[bytes, bytes] = {}
	ciphertexts_bytes = b"".join(k + v for k, v in sorted(encrypted_commit_secrets.items()))
	transcript_hash = _th(
		group.group_id,
		epoch_id,
		tree,
		group.state.key_schedule.confirmation_key,
		ciphertexts_bytes,
		sender_index=0,
	)
	update = GroupUpdate(
		epoch_id=epoch_id,
		tree=tree,
		encrypted_commit_secrets=encrypted_commit_secrets,
		committer_index=0,
		signature=sig.sign(transcript_hash),
	)

	# No KPRef for my leaf -> raises ValueError
	with pytest.raises(ValueError, match="Not invited to this epoch"):
		group.process_update(update)

	update.signature = b"badsig\x00" * 9
	with pytest.raises(ValueError, match="Commit Forgery Detected|Invalid signature format"):
		group.process_update(update)

	sig2 = SignatureKey()
	kem2 = KemKey()
	kp = KeyPackage(identity_key_pub=sig2.public_bytes(), init_key_pub=kem2.public_bytes())
	_, _, real_update = group.add_member(kp)

	# Alter my_index to point to a ParentNode (leaf_node lookup fails)
	group.my_index = 1  # ParentNode
	with pytest.raises(ValueError, match="My leaf node not found"):
		group.process_update(real_update)
	group.my_index = 0

	# Build a bad update: valid KPRef but corrupted ciphertext, properly signed
	my_leaf = group.state.tree.get_node(0)
	assert isinstance(my_leaf, LeafNode)
	my_kp_ref = _make_kp_ref(my_leaf.key_package)
	bad_secrets: dict[bytes, bytes] = {my_kp_ref: b"bad_ciphertext" * 5}
	bad_ciphertexts_bytes = b"".join(k + v for k, v in sorted(bad_secrets.items()))
	bad_transcript_hash = _th(
		group.group_id,
		1,
		real_update.tree,
		group.state.key_schedule.confirmation_key,
		bad_ciphertexts_bytes,
		sender_index=0,
	)
	bad_update = GroupUpdate(
		epoch_id=1,
		tree=real_update.tree,
		encrypted_commit_secrets=bad_secrets,
		committer_index=0,
		signature=sig.sign(bad_transcript_hash),
	)

	from cryptography.exceptions import InvalidTag

	with pytest.raises(InvalidTag):
		group.process_update(bad_update)

	# Test ParentNode inside tree for process_update -> invalid committer index
	tree_with_parent = RatchetTree(2)
	tree_with_parent.nodes = [None, ParentNode(b"A" * 32, b"B" * 32)]
	update_parent = GroupUpdate(
		epoch_id=1,
		tree=tree_with_parent,
		encrypted_commit_secrets={},
		committer_index=1,
		signature=b"",
	)
	with pytest.raises(ValueError, match="Invalid committer index"):
		group.process_update(update_parent)
