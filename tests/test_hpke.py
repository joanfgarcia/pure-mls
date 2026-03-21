import pytest
from cryptography.exceptions import InvalidTag

from pure_mls.hpke import HPKE
from pure_mls.keys import KemKey


def test_hpke_seal_open_success() -> None:
	"""Asserts that HPKE properly envelopes and unseals data against the correct Private Key."""
	receiver = KemKey()
	receiver_pub = receiver.public_bytes()

	message = b"Extremely Secret Welcome Payload"
	aad = b"Agent-ID-Header-Metadata"

	# Sender seals
	enc, ciphertext = HPKE.seal(receiver_pub, message, aad=aad, info=b"test-info")

	# Receiver opens
	plaintext = HPKE.open(receiver, enc, ciphertext, aad=aad, info=b"test-info")
	assert plaintext == message


def test_hpke_seal_open_wrong_key() -> None:
	"""Asserts that a malicious or incorrect private key is mathematically locked out."""
	victim = KemKey()
	hacker = KemKey()

	message = b"Secret Payload"

	# Message addressed to the victim
	enc, ciphertext = HPKE.seal(victim.public_bytes(), message, info=b"context-a")

	# Hacker attempts to open it
	with pytest.raises(InvalidTag):
		HPKE.open(hacker, enc, ciphertext, info=b"context-a")


def test_hpke_tampered_ciphertext() -> None:
	"""Asserts that GCM rejects any modification to the bytes in transit."""
	receiver = KemKey()
	message = b"Authenticity check"
	enc, ciphertext = HPKE.seal(receiver.public_bytes(), message, info=b"check")

	# Network tampering (corrupts the last byte)
	corrupted = bytearray(ciphertext)
	corrupted[-1] ^= 0xFF

	with pytest.raises(InvalidTag):
		HPKE.open(receiver, enc, bytes(corrupted), info=b"check")


def test_hpke_tampered_aad() -> None:
	"""Asserts that Associated Data ties to the authentication tag."""
	receiver = KemKey()
	enc, ciphertext = HPKE.seal(receiver.public_bytes(), b"data", aad=b"legion_770", info=b"aad-test")

	with pytest.raises(InvalidTag):
		HPKE.open(receiver, enc, ciphertext, aad=b"global_intercept", info=b"aad-test")


def test_hpke_context_isolation() -> None:
	"""CRIT-01: Asserts that different info strings produce different keys/ciphertexts."""
	receiver = KemKey()
	pub = receiver.public_bytes()
	msg = b"Secret"

	# Seal same message to same receiver but different info contexts
	enc1, ct1 = HPKE.seal(pub, msg, info=b"context-1")
	enc2, ct2 = HPKE.seal(pub, msg, info=b"context-2")

	# Even if enc is same (which it isn't because of ephemeral keys),
	# context isolation means opening with wrong info context must fail.
	with pytest.raises(InvalidTag):
		HPKE.open(receiver, enc1, ct1, info=b"context-2")
