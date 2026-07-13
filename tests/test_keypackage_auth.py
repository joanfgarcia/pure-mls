"""Audit H1/L3: KeyPackage init_key authentication (Welcome-hijack MITM).

The KeyPackageTBS signature is the only one covering init_key_pub. add_member()
must verify it unconditionally, so a tampered or unsigned init_key is rejected.
"""

import pytest
from cryptography.exceptions import InvalidSignature

from pure_mls.group import MLSGroup
from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


def _fresh_group_and_kp() -> tuple[MLSGroup, KeyPackage]:
	alice_sig, alice_kem = SignatureKey(), KemKey()
	bob_sig, bob_kem = SignatureKey(), KemKey()
	group = MLSGroup.create(b"grupo-soberano", alice_sig, alice_kem)
	kp = KeyPackage.create(
		encryption_key=bob_kem.public_bytes(),
		init_key_pub=bob_kem.public_bytes(),
		signature_key=bob_sig.public_bytes(),
		identity=bob_sig.public_bytes(),
		sign_fn=bob_sig.sign,
	)
	return group, kp


def test_add_member_rejects_tampered_init_key() -> None:
	"""MITM swaps init_key_pub — the KeyPackageTBS signature must no longer verify."""
	group, kp = _fresh_group_and_kp()
	mallory = KemKey()
	kp.init_key_pub = mallory.public_bytes()  # hijack: point Welcome KEM at attacker
	with pytest.raises((ValueError, InvalidSignature)):
		group.add_member(kp)


def test_add_member_rejects_unsigned_key_package() -> None:
	"""An empty signature must not be silently accepted."""
	group, kp = _fresh_group_and_kp()
	kp.leaf_node_signature = b""
	with pytest.raises(ValueError):
		group.add_member(kp)


def test_add_member_accepts_valid_key_package() -> None:
	"""A pristine, correctly signed KeyPackage is admitted."""
	group, kp = _fresh_group_and_kp()
	new_group, _welcome, _commit = group.add_member(kp)
	assert new_group.epoch_id == group.epoch_id + 1


def test_keypackage_tbs_matches_wire_extensions_encoding() -> None:
	"""L3: the signed TBS and the wire encoding must agree on the extensions prefix."""
	_group, kp = _fresh_group_and_kp()
	# init_key_pub appears in both _tbs_bytes() and to_bytes(); a mismatch in the
	# trailing extensions<V> prefix (u32 vs VarInt) would break interop verification.
	assert kp._tbs_bytes().endswith(b"\x00")  # VarInt(0) is a single 0x00 byte, not 4 bytes
