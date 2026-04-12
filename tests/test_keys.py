"""Tests for RFC 9420 §10.1 KeyPackage and §7.2 LeafNode signatures.

Updated for v2.0: KeyPackage.create() now takes encryption_key, init_key_pub,
signature_key, identity, sign_fn per RFC 9420 §10.1 wire format.
"""

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
# v2.0: KeyPackage RFC 9420 §10.1 TLS wire format
# ---------------------------------------------------------------------------


def _make_kp(sig: SignatureKey | None = None, kem: KemKey | None = None) -> KeyPackage:
	"""Helper: create a fully signed KeyPackage with the new RFC 9420 API."""
	sig = sig or SignatureKey()
	kem = kem or KemKey()
	return KeyPackage.create(
		encryption_key=kem.public_bytes(),
		init_key_pub=kem.public_bytes(),
		signature_key=sig.public_bytes(),
		identity=sig.public_bytes(),
		sign_fn=sig.sign,
	)


def test_key_package_create_signed():
	"""KeyPackage.create() produces a fully signed KeyPackage."""
	sig = SignatureKey()
	kem = KemKey()
	kp = _make_kp(sig, kem)

	# leaf_node carries the signature over LeafNodeTBS
	assert len(kp.leaf_node.signature) == 64
	kp.verify_signature()  # must not raise

	# leaf_node_signature is the KeyPackage-level signature (over KeyPackageTBS) — distinct from LeafNode.signature
	assert len(kp.leaf_node_signature) == 64
	# Both signatures are produced by the same key but over different TBS structures
	# (KeyPackageTBS ≠ LeafNodeTBS), so they are intentionally different values


def test_key_package_signature_roundtrip():
	"""Signed KeyPackage survives to_bytes()/from_bytes() (TLS round-trip)."""
	sig = SignatureKey()
	kem = KemKey()
	kp = _make_kp(sig, kem)
	raw = kp.to_bytes()

	# RFC wire format is variable length (not fixed 128 bytes)
	assert len(raw) > 64

	kp2 = KeyPackage.from_bytes(raw)
	assert kp2.init_key_pub == kp.init_key_pub
	assert kp2.identity_key_pub == kp.identity_key_pub
	assert kp2.leaf_node.signature == kp.leaf_node.signature
	kp2.verify_signature()


def test_key_package_legacy_64_bytes():
	"""Legacy 64-byte KeyPackage loads via from_bytes_legacy without signature."""
	sig = SignatureKey()
	kem = KemKey()
	legacy = sig.public_bytes() + kem.public_bytes()
	kp = KeyPackage.from_bytes_legacy(legacy)
	assert kp.leaf_node.signature == b""


def test_key_package_tampered_signature_raises():
	"""Tampered KeyPackage raises on verify_signature()."""
	from dataclasses import replace

	from cryptography.exceptions import InvalidSignature

	sig = SignatureKey()
	kem = KemKey()
	kp = _make_kp(sig, kem)

	# Tamper the leaf_node signature
	tampered_leaf = replace(kp.leaf_node, signature=bytes([0xFF]) * 64)
	tampered_kp = replace(kp, leaf_node=tampered_leaf)

	with pytest.raises((InvalidSignature, Exception)):
		tampered_kp.verify_signature()
