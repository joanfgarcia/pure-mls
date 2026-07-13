"""Audit LOW block: L1 (KEM error type), L8 (private-key length validation)."""

import pytest

from pure_mls.keys import KemKey, SignatureKey


def test_dh_exchange_rejects_malformed_pubkey() -> None:
	# L1: a malformed KEM public key is a ValueError, not a signature error.
	with pytest.raises(ValueError):
		KemKey().dh_exchange(b"\x00" * 5)


def test_signature_key_from_private_bytes_validates_length() -> None:
	with pytest.raises(ValueError):
		SignatureKey.from_private_bytes(b"\x00" * 10)


def test_kem_key_from_private_bytes_validates_length() -> None:
	with pytest.raises(ValueError):
		KemKey.from_private_bytes(b"\x00" * 10)


def test_signature_key_accepts_64_byte_expanded() -> None:
	# The 64-byte expanded form (seed+pub) is still accepted (truncated to seed).
	SignatureKey.from_private_bytes(b"\x01" * 64)
