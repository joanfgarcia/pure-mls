import pytest

from pure_mls.group import GroupUpdate, MLSGroup, WelcomeInfo
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage, ParentNode, RatchetTree


def test_welcome_info_from_bytes_errors():
	# Test node type ParentNode and Invalid type
	# Construct a valid WelcomeInfo first
	sig = SignatureKey()
	kem = KemKey()
	kp = KeyPackage(identity_key_pub=sig.public_bytes(), init_key_pub=kem.public_bytes())
	group = MLSGroup.create(b"cov-group", sig, kem)
	group2, welcome, update = group.add_member(kp)

	# Manually corrupt the tree_bytes node type to 0x02 to trigger ParentNode logic
	# Actually, the RatchetTree in WelcomeInfo only has LeafNode and None right now.
	# Let's just create a custom WelcomeInfo with a ParentNode to hit the serialization path
	# For from_bytes to hit 0x02, we need a to_bytes that generated 0x02.
	tree = RatchetTree(1)
	tree.nodes = [ParentNode(public_key=b"A" * 32, parent_hash=b"B" * 32)]
	w_parent = WelcomeInfo(b"g", 1, tree, b"J" * 32, b"H" * 32, 2)
	w_parent_bytes = w_parent.to_bytes()
	parsed = WelcomeInfo.from_bytes(w_parent_bytes)
	assert isinstance(parsed.tree.nodes[0], ParentNode)

	# Trigger ValueError for invalid node type
	# Directly feed invalid bytes to RatchetTree since WelcomeInfo from_bytes is now MAC-protected
	bad_tree_bytes = b"\x00\x00\x00\x00\x03" + b"X" * 64
	with pytest.raises(ValueError, match="Invalid node type"):
		RatchetTree.from_bytes(bad_tree_bytes)


def test_add_member_parent_node():
	sig1 = SignatureKey()
	kem1 = KemKey()
	group = MLSGroup.create(b"g1", sig1, kem1)
	group.state.tree.nodes.append(ParentNode(public_key=b"A" * 32, parent_hash=b"B" * 32))

	sig2 = SignatureKey()
	kem2 = KemKey()
	kp = KeyPackage(identity_key_pub=sig2.public_bytes(), init_key_pub=kem2.public_bytes())
	group.add_member(kp)  # Should hit elif isinstance(node, ParentNode)


def test_process_update_errors():
	sig = SignatureKey()
	kem = KemKey()
	group = MLSGroup.create(b"g1", sig, kem)

	update = GroupUpdate(epoch_id=1, tree=group.state.tree, encrypted_commit_secrets={}, committer_index=0, signature=b"")

	import hashlib

	epoch_id = 1
	tree = group.state.tree
	encrypted_commit_secrets = {}
	ciphertexts_bytes = b"".join(k + v for k, v in sorted(encrypted_commit_secrets.items()))
	transcript_hash = hashlib.sha256(
		epoch_id.to_bytes(8, "big") + tree.to_bytes() + group.state.key_schedule.confirmation_key + ciphertexts_bytes
	).digest()
	update.signature = sig.sign(transcript_hash)

	# Sender is self but lacking secret -> raises ValueError
	with pytest.raises(ValueError, match="Not invited to this epoch"):
		group.process_update(update)

	update.signature = b"badsig\x00" * 9  # roughly 63 bytes or whatever
	with pytest.raises(ValueError, match="Commit Forgery Detected|Invalid signature format"):
		group.process_update(update)

	sig2 = SignatureKey()
	kem2 = KemKey()
	kp = KeyPackage(identity_key_pub=sig2.public_bytes(), init_key_pub=kem2.public_bytes())
	_, _, real_update = group.add_member(kp)

	# Alter my_index to simulate being the receiver but without encrypted commit secret
	group.my_index = 1
	with pytest.raises(ValueError, match="Not invited to this epoch"):
		group.process_update(real_update)  # Empty encrypted_commit_secrets

	# Alter ciphertext to fail decryption but sign it properly to bypass STATE-04 defenses
	bad_update = GroupUpdate(
		epoch_id=1, tree=real_update.tree, encrypted_commit_secrets={kem.public_bytes(): b"bad_ciphertext" * 5}, committer_index=0, signature=b""
	)

	ciphertexts_bytes = b"".join(k + v for k, v in sorted(bad_update.encrypted_commit_secrets.items()))
	transcript_hash = hashlib.sha256(
		bad_update.epoch_id.to_bytes(8, "big") + bad_update.tree.to_bytes() + group.state.key_schedule.confirmation_key + ciphertexts_bytes
	).digest()
	bad_update.signature = sig.sign(transcript_hash)

	from cryptography.exceptions import InvalidTag

	with pytest.raises(InvalidTag):
		group.process_update(bad_update)

	# Test ParentNode inside tree for process_update
	tree_with_parent = RatchetTree(2)
	tree_with_parent.nodes = [None, ParentNode(b"A" * 32, b"B" * 32)]
	update_parent = GroupUpdate(
		epoch_id=1,
		tree=tree_with_parent,
		encrypted_commit_secrets={kem.public_bytes(): real_update.encrypted_commit_secrets[kem2.public_bytes()]},
		committer_index=0,
		signature=b"",
	)

	# Sender is self check (should be None)
	update_parent.committer_index = 1
	with pytest.raises(ValueError, match="Invalid committer index"):
		group.process_update(update_parent)
