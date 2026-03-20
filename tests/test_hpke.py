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
	enc, ciphertext = HPKE.seal(receiver_pub, message, aad)

	# Receiver opens
	plaintext = HPKE.open(receiver, enc, ciphertext, aad)
	assert plaintext == message


def test_hpke_seal_open_wrong_key() -> None:
	"""Asserts that a malicious or incorrect private key is mathematically locked out."""
	victim = KemKey()
	hacker = KemKey()

	message = b"Secret Payload"

	# Message addressed to the victim
	enc, ciphertext = HPKE.seal(victim.public_bytes(), message)

	# Hacker attempts to open it
	with pytest.raises(InvalidTag):
		HPKE.open(hacker, enc, ciphertext)


def test_hpke_tampered_ciphertext() -> None:
	"""Asserts that GCM rejects any modification to the bytes in transit."""
	receiver = KemKey()
	message = b"Authenticity check"
	enc, ciphertext = HPKE.seal(receiver.public_bytes(), message)

	# Network tampering (corrupts the last byte)
	corrupted = bytearray(ciphertext)
	corrupted[-1] ^= 0xFF

	with pytest.raises(InvalidTag):
		HPKE.open(receiver, enc, bytes(corrupted))


def test_hpke_tampered_aad() -> None:
	"""Asserts that Associated Data ties to the authentication tag."""
	receiver = KemKey()
	enc, ciphertext = HPKE.seal(receiver.public_bytes(), b"data", aad=b"legion_770")

	with pytest.raises(InvalidTag):
		HPKE.open(receiver, enc, ciphertext, aad=b"global_intercept")
