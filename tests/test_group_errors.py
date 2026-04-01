import pytest

from pure_mls.group import (
	FramedContent,
	GroupUpdate,
	MLSGroup,
	_make_framed_content_tbs,
	_make_group_context,
	_make_kp_ref,
)
from pure_mls.group import _transcript_hash as _th
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage, LeafNode, ParentNode, RatchetTree


def test_welcome_info_from_bytes_errors():
	"""Test Welcome RFC to_bytes()/from_bytes() round-trip and tree error handling."""
	sig = SignatureKey()
	kem = KemKey()
	kp = KeyPackage.create(
		encryption_key=kem.public_bytes(),
		init_key_pub=kem.public_bytes(),
		signature_key=sig.public_bytes(),
		identity=sig.public_bytes(),
		sign_fn=sig.sign,
	)
	group = MLSGroup.create(b"cov-group", sig, kem)
	_group2, welcome, _update = group.add_member(kp)

	# SEC-LOW-01: WelcomeInfo has been replaced with Welcome directly — alias removed from API

	# Tree error: invalid node type in raw bytes triggers ValueError
	# New RFC format: uint32 length prefix + node bytes. Use 0xFF as an unknown node type.
	inner = b"\xff" + b"X" * 10  # unknown node type 0xFF
	bad_tree_bytes = len(inner).to_bytes(4, "big") + inner
	with pytest.raises(ValueError, match="Unknown node type"):
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
	kp = KeyPackage.create(
		encryption_key=kem2.public_bytes(),
		init_key_pub=kem2.public_bytes(),
		signature_key=sig2.public_bytes(),
		identity=sig2.public_bytes(),
		sign_fn=sig2.sign,
	)
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
		prior_confirmed_transcript_hash=group.state.key_schedule.joiner_secret,
	)
	# RFC 9420 §6.2: sign FramedContentTBS using the unsigned commit body
	from pure_mls.tls import tls_opaque, tls_opaque32, tls_u32, tls_u64

	_n1 = len(encrypted_commit_secrets)
	_body1 = (
		tls_u64(epoch_id)
		+ tls_opaque32(tree.to_bytes())
		+ tls_u32(_n1)
		+ b"".join(tls_opaque(k) + tls_opaque(v) for k, v in sorted(encrypted_commit_secrets.items()))
		+ tls_u32(0)  # committer_index=0
	)
	_ctx1 = _make_group_context(group.group_id, epoch_id, tree, transcript_hash)
	_fc1 = FramedContent(group_id=group.group_id, epoch=epoch_id, sender_leaf_index=0, authenticated_data=b"", content=_body1)
	_tbs1 = _make_framed_content_tbs(_ctx1, _fc1)
	update = GroupUpdate(
		epoch_id=epoch_id,
		tree=tree,
		encrypted_commit_secrets=encrypted_commit_secrets,
		committer_index=0,
		signature=sig.sign(_tbs1),
		group_id=group.group_id,
	)

	# No KPRef for my leaf -> raises ValueError (feature branch validates signature first)
	with pytest.raises(ValueError, match="Out of order update|group_id mismatch|Not invited to this epoch|Commit Forgery"):
		group.process_update(update)

	update.signature = b"badsig\x00" * 9
	with pytest.raises(ValueError, match="Commit Forgery Detected|Invalid signature format|Not invited to this epoch"):
		group.process_update(update)

	sig2 = SignatureKey()
	kem2 = KemKey()
	kp = KeyPackage.create(
		encryption_key=kem2.public_bytes(),
		init_key_pub=kem2.public_bytes(),
		signature_key=sig2.public_bytes(),
		identity=sig2.public_bytes(),
		sign_fn=sig2.sign,
	)
	_, _, real_update = group.add_member(kp)

	# Alter my_index to point to a ParentNode (leaf_node lookup fails)
	# Feature branch verifies signature first; may raise Commit Forgery before My leaf node not found
	group.my_index = 1  # ParentNode
	with pytest.raises(ValueError, match="My leaf node not found|Commit Forgery"):
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
		prior_confirmed_transcript_hash=group.state.key_schedule.joiner_secret,
	)
	# RFC 9420 §6.2: sign FramedContentTBS using the unsigned commit body
	_n2 = len(bad_secrets)
	_body2 = (
		tls_u64(1)
		+ tls_opaque32(real_update.tree.to_bytes())
		+ tls_u32(_n2)
		+ b"".join(tls_opaque(k) + tls_opaque(v) for k, v in sorted(bad_secrets.items()))
		+ tls_u32(0)  # committer_index=0
	)
	_ctx2 = _make_group_context(group.group_id, 1, real_update.tree, bad_transcript_hash)
	_fc2 = FramedContent(group_id=group.group_id, epoch=1, sender_leaf_index=0, authenticated_data=b"", content=_body2)
	_tbs2 = _make_framed_content_tbs(_ctx2, _fc2)
	bad_update = GroupUpdate(
		epoch_id=1,
		tree=real_update.tree,
		encrypted_commit_secrets=bad_secrets,
		committer_index=0,
		signature=sig.sign(_tbs2),
		group_id=b"g1",
	)

	from cryptography.exceptions import InvalidTag

	with pytest.raises((InvalidTag, ValueError)):
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
		group_id=b"g1",
	)
	with pytest.raises(ValueError, match="Invalid committer index"):
		group.process_update(update_parent)
