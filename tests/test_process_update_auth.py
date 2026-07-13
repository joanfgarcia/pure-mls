"""Audit M4: process_update must authenticate the LeafNodes of the received tree.

A committer (buggy or malicious) that ships a tree with a forged/unauthenticated
LeafNode signature must be rejected before the new state is adopted.
"""

import dataclasses
import os

import pytest
from cryptography.exceptions import InvalidSignature

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage, LeafNode


def _two_member_groups() -> tuple[MLSGroup, MLSGroup]:
	creator_sig, creator_kem = SignatureKey(), KemKey()
	group = MLSGroup.create(b"m4-" + os.urandom(6), creator_sig, creator_kem)
	joiner_sig, joiner_kem = SignatureKey(), KemKey()
	kp = KeyPackage.create(
		encryption_key=joiner_kem.public_bytes(),
		init_key_pub=joiner_kem.public_bytes(),
		signature_key=joiner_sig.public_bytes(),
		identity=joiner_sig.public_bytes(),
		sign_fn=joiner_sig.sign,
	)
	creator_group, welcome, _update = group.add_member(kp)
	joiner_group = MLSGroup.join(welcome, joiner_sig, joiner_kem)
	return creator_group, joiner_group


def test_process_update_accepts_clean_commit() -> None:
	creator_group, joiner_group = _two_member_groups()
	rotated, commit = creator_group.update_key()
	advanced = joiner_group.process_update(commit)
	assert advanced.epoch_id == rotated.epoch_id


def test_process_update_rejects_forged_leaf_signature() -> None:
	creator_group, joiner_group = _two_member_groups()
	_rotated, commit = creator_group.update_key()

	# Forge the committer's leaf signature in the tree carried by the commit.
	leaf = commit.tree.get_node(0)
	assert isinstance(leaf, LeafNode)
	commit.tree.set_leaf(0, dataclasses.replace(leaf, signature=b"\x00" * 64))

	with pytest.raises((ValueError, InvalidSignature)):
		joiner_group.process_update(commit)
