import os

import pytest

from pure_mls.keys import KemKey, SignatureKey
from pure_mls.tree import KeyPackage


def test_signature_key() -> None:
	"""Asserts that Ed25519 signs out raw byte parity and verifies."""
	key = SignatureKey()
	message = os.urandom(64)

	signature = key.sign(message)
	assert len(signature) == 64
	assert len(key.public_bytes()) == 32

	# Verify success
	assert SignatureKey.verify(key.public_bytes(), signature, message) is True

	# Verify failure
	tampered_message = message + b"fail"
	assert SignatureKey.verify(key.public_bytes(), signature, tampered_message) is False


def test_kem_exchange() -> None:
	"""Asserts that X25519 Diffie-Hellman establishes mutual mathematical secrets."""
	alice = KemKey()
	bob = KemKey()

	secret_alice = alice.dh_exchange(bob.public_bytes())
	secret_bob = bob.dh_exchange(alice.public_bytes())

	assert secret_alice == secret_bob
	assert len(secret_alice) == 32


# ---------------------------------------------------------------------------
# v1.3: KeyPackage leaf_signature (RFC 9420 §10.1)
# ---------------------------------------------------------------------------


def test_key_package_create_signed():
	"""KeyPackage.create() self-signs with the identity key."""
	sig = SignatureKey()
	kem = KemKey()
	kp = KeyPackage.create(
		identity_key_pub=sig.public_bytes(),
		init_key_pub=kem.public_bytes(),
		sign_fn=sig.sign,
	)
	assert len(kp.leaf_node_signature) == 64
	kp.verify_signature()  # must not raise


def test_key_package_signature_roundtrip():
	"""Signed KeyPackage survives to_bytes()/from_bytes()."""
	sig = SignatureKey()
	kem = KemKey()
	kp = KeyPackage.create(
		identity_key_pub=sig.public_bytes(),
		init_key_pub=kem.public_bytes(),
		sign_fn=sig.sign,
	)
	raw = kp.to_bytes()
	assert len(raw) == 128  # 32 + 32 + 64
	kp2 = KeyPackage.from_bytes(raw)
	assert kp2.identity_key_pub == kp.identity_key_pub
	assert kp2.init_key_pub == kp.init_key_pub
	assert kp2.leaf_node_signature == kp.leaf_node_signature
	kp2.verify_signature()


def test_key_package_legacy_64_bytes():
	"""Legacy 64-byte KeyPackage (no signature) loads without signature."""
	sig = SignatureKey()
	kem = KemKey()
	legacy = sig.public_bytes() + kem.public_bytes()
	kp = KeyPackage.from_bytes(legacy)
	assert kp.leaf_node_signature == b""


def test_key_package_tampered_signature_raises():
	"""Tampered KeyPackage raises on verify_signature()."""
	from cryptography.exceptions import InvalidSignature

	sig = SignatureKey()
	kem = KemKey()
	kp = KeyPackage.create(
		identity_key_pub=sig.public_bytes(),
		init_key_pub=kem.public_bytes(),
		sign_fn=sig.sign,
	)
	kp.leaf_node_signature = bytes([0xFF]) * 64
	with pytest.raises((InvalidSignature, Exception)):
		kp.verify_signature()
