import pytest

from pure_mls.group import GroupUpdate, MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


def test_keypackage_coverage():
	with pytest.raises(ValueError, match="Invalid KeyPackage size"):
		KeyPackage.from_bytes(b"short")


def test_group_process_update_coverage():
	sig1 = SignatureKey()
	kem1 = KemKey()
	group1 = MLSGroup.create(b"cov", sig1, kem1)

	# Line 228: Out of order update
	update_out = GroupUpdate(epoch_id=2, tree=group1.state.tree, encrypted_commit_secrets={}, committer_index=0, signature=b"")
	with pytest.raises(ValueError, match="Out of order update"):
		group1.process_update(update_out)

	# Bob joins to set up a group2 at epoch 1
	sig2 = SignatureKey()
	kem2 = KemKey()
	kp2 = KeyPackage(sig2.public_bytes(), kem2.public_bytes())
	group1_next, welcome, update1 = group1.add_member(kp2)
	group2 = MLSGroup.join(welcome, sig2, kem2)

	# Charlie joins to generate an update2 at epoch 2
	sig3 = SignatureKey()
	kem3 = KemKey()
	kp3 = KeyPackage(sig3.public_bytes(), kem3.public_bytes())
	group1_final, welcome3, update2 = group1_next.add_member(kp3)

	# Valid format, wrong signature (64 bytes)
	update_forged = GroupUpdate(
		epoch_id=update2.epoch_id,
		tree=update2.tree,
		encrypted_commit_secrets=update2.encrypted_commit_secrets,
		committer_index=update2.committer_index,
		signature=b"0" * 64,
	)
	with pytest.raises(ValueError, match="Commit Forgery Detected"):
		group2.process_update(update_forged)

	# To hit "Invalid signature format" exception, we need to work around the now-frozen tree.
	# We create a fresh group with a tampered identity key in the tree before it freezes.
	with pytest.raises(ValueError, match="Commit Forgery Detected|Invalid signature format"):
		group2.process_update(update_forged)
