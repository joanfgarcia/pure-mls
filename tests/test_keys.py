import os

from pure_mls.keys import KemKey, SignatureKey


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
