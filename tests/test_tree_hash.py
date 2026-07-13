"""Audit tree_hash + M1: tree.tree_hash() must match RFC 9420 §7.8 (leaf_index included),
and join() must reject a tree whose hash does not match the signed GroupInfo.tree_hash.

The positive known-answer for tree_hash() is the IETF passive-client-welcome vector
(tests/test_ietf_vectors.py), which now runs with the M1 tree_hash check enabled.
"""

import os

import pytest

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage, RatchetTree


def _make_kp(sig: SignatureKey, kem: KemKey) -> KeyPackage:
	return KeyPackage.create(
		encryption_key=kem.public_bytes(),
		init_key_pub=kem.public_bytes(),
		signature_key=sig.public_bytes(),
		identity=sig.public_bytes(),
		sign_fn=sig.sign,
	)


def test_join_rejects_tree_with_wrong_tree_hash() -> None:
	"""M1: a tree supplied out-of-band that does not reproduce the signed tree_hash is rejected."""
	a_sig, a_kem = SignatureKey(), KemKey()
	group = MLSGroup.create(b"th-" + os.urandom(6), a_sig, a_kem)
	b_sig, b_kem = SignatureKey(), KemKey()
	_creator, welcome, _u = group.add_member(_make_kp(b_sig, b_kem))

	wrong_tree = RatchetTree(num_leaves=2)  # empty leaves -> different tree_hash
	with pytest.raises(ValueError, match="tree_hash"):
		MLSGroup.join(welcome, b_sig, b_kem, ratchet_tree=wrong_tree)


def test_join_accepts_embedded_tree() -> None:
	"""Sanity: the honest path (tree from the signed GroupInfo extension) still joins."""
	a_sig, a_kem = SignatureKey(), KemKey()
	group = MLSGroup.create(b"th-ok", a_sig, a_kem)
	b_sig, b_kem = SignatureKey(), KemKey()
	_creator, welcome, _u = group.add_member(_make_kp(b_sig, b_kem))
	joiner = MLSGroup.join(welcome, b_sig, b_kem)
	assert joiner.epoch_id == 1
