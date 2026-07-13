"""Audit negative-coverage block: T1 (removed member), T2 (replay), T5 (wrong recipient).

These exercise security properties that module docstrings claimed but did not test.
"""

import os

import pytest
from cryptography.exceptions import InvalidTag

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


def _make_kp(sig: SignatureKey, kem: KemKey) -> KeyPackage:
	return KeyPackage.create(
		encryption_key=kem.public_bytes(),
		init_key_pub=kem.public_bytes(),
		signature_key=sig.public_bytes(),
		identity=sig.public_bytes(),
		sign_fn=sig.sign,
	)


def _two_member() -> tuple[MLSGroup, MLSGroup, int]:
	a_sig, a_kem = SignatureKey(), KemKey()
	group = MLSGroup.create(b"neg-" + os.urandom(6), a_sig, a_kem)
	b_sig, b_kem = SignatureKey(), KemKey()
	creator, welcome, _u = group.add_member(_make_kp(b_sig, b_kem))
	joiner = MLSGroup.join(welcome, b_sig, b_kem)
	return creator, joiner, joiner.state.tree.num_leaves


# T2 -------------------------------------------------------------------------
def test_old_epoch_ciphertext_not_decryptable_in_new_epoch() -> None:
	"""A message encrypted at epoch N must not decrypt after the group advances (replay)."""
	creator, joiner, _ = _two_member()
	ct = creator.encrypt_application_message(b"secret at epoch 1")
	rotated, _commit = creator.update_key()  # advance the committer to epoch 2
	with pytest.raises((ValueError, InvalidTag)):
		rotated.decrypt_application_message(ct)


# T5 -------------------------------------------------------------------------
def test_welcome_rejected_for_wrong_recipient() -> None:
	"""A Welcome sealed to Bob must not be joinable with an unrelated key pair."""
	a_sig, a_kem = SignatureKey(), KemKey()
	group = MLSGroup.create(b"neg-recip", a_sig, a_kem)
	b_sig, b_kem = SignatureKey(), KemKey()
	_creator, welcome, _u = group.add_member(_make_kp(b_sig, b_kem))

	mallory_sig, mallory_kem = SignatureKey(), KemKey()
	with pytest.raises(ValueError):
		MLSGroup.join(welcome, mallory_sig, mallory_kem)


# T1 -------------------------------------------------------------------------
def test_removed_member_cannot_decrypt_new_messages() -> None:
	"""After a member is removed, its stale state must not decrypt the new epoch."""
	creator, joiner, _ = _two_member()
	# creator removes the joiner (leaf index 1)
	creator_after, _commit = creator.remove_member(1)

	ct = creator_after.encrypt_application_message(b"post-removal message")
	with pytest.raises((ValueError, InvalidTag)):
		joiner.decrypt_application_message(ct)
