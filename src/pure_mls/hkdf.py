import hashlib
import hmac
from typing import Any, Callable

HashFunction = Callable[[], Any]

# MLS suite identifier prefix (RFC 9420 §8)
MLS_SUITE_ID = b"MLS 1.0 "


def varint_encode(n: int) -> bytes:
	"""MLS variable-length integer encoding (RFC 9420 §C / mls-rs-codec VarInt).

	Encoding:
	0..63        → 1 byte  (top 2 bits = 00)
	64..16383    → 2 bytes (top 2 bits = 01, i.e. OR 0x4000)
	16384..2^30-1 → 4 bytes (top 2 bits = 10, i.e. OR 0x80000000)

	This is what mls-rs `byte_vec` uses for HkdfLabel field lengths.
	"""
	if n <= 63:
		return bytes([n])
	elif n <= 16383:
		return ((n | 0x4000) & 0xFFFF).to_bytes(2, "big")
	elif n <= (1 << 30) - 1:
		return ((n | 0x80000000) & 0xFFFFFFFF).to_bytes(4, "big")
	else:
		raise ValueError(f"VarInt out of range: {n}")


def expand_with_label(
	secret: bytes,
	label: str,
	context: bytes,
	length: int,
	hash_func: HashFunction = hashlib.sha256,
) -> bytes:
	"""RFC 9420 §8: ExpandWithLabel(Secret, Label, Context, Length).

	HkdfLabel wire format (matching mls-rs VarInt byte_vec encoding):
	length(u16) | varint(len(full_label)) | full_label | varint(len(context)) | context
	where full_label = b"MLS 1.0 " + label.encode()
	"""
	full_label = MLS_SUITE_ID + label.encode()
	hkdf_label = length.to_bytes(2, "big") + varint_encode(len(full_label)) + full_label + varint_encode(len(context)) + context
	return hkdf_expand(secret, hkdf_label, length, hash_func)


def derive_secret(secret: bytes, label: str, hash_func: HashFunction = hashlib.sha256) -> bytes:
	"""RFC 9420 §8: DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, b'', NH)."""
	nh = hash_func().digest_size
	return expand_with_label(secret, label, b"", nh, hash_func)


def hkdf_extract(salt: bytes | None, ikm: bytes, hash_func: HashFunction = hashlib.sha256) -> bytes:
	"""HKDF-Extract (RFC 5869).
	Extracts a pseudorandom key (PRK) from input keying material (IKM) and a salt.
	"""
	if salt is None:
		salt = b"\x00" * hash_func().digest_size
	return hmac.new(salt, ikm, hash_func).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_func: HashFunction = hashlib.sha256) -> bytes:
	"""HKDF-Expand (RFC 5869).
	Expands a pseudorandom key (PRK) and info string into output keying material (OKM).
	"""
	hash_len = hash_func().digest_size
	n = (length + hash_len - 1) // hash_len
	okm = b""
	t_i = b""
	for i in range(1, n + 1):
		t_i = hmac.new(prk, t_i + info + bytes([i]), hash_func).digest()
		okm += t_i
	return okm[:length]
