import hashlib
import hmac
from typing import Any, Callable


def encode_varint(val: int) -> bytes:
	"""
	QUIC-style variable-length integer encoding (RFC 9000).
	Used by MLS (RFC 9420) for encoding the lengths of labels and contexts.
	"""
	if val <= 0x3F:
		return bytes([val])
	if val <= 0x3FFF:
		return (0x4000 | val).to_bytes(2, "big")
	if val <= 0x3FFFFFFF:
		return (0x80000000 | val).to_bytes(4, "big")
	if val <= 0x3FFFFFFFFFFFFFFF:
		return (0xC000000000000000 | val).to_bytes(8, "big")
	raise ValueError(f"Varint value too large: {val}")


HashFunction = Callable[[], Any]


def hkdf_extract(salt: bytes | None, ikm: bytes, hash_func: HashFunction = hashlib.sha256) -> bytes:
	"""
	HKDF-Extract (RFC 5869).
	Extracts a pseudorandom key (PRK) from input keying material (IKM) and a salt.
	"""
	if salt is None:
		salt = b"\x00" * hash_func().digest_size
	return hmac.new(salt, ikm, hash_func).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_func: HashFunction = hashlib.sha256) -> bytes:
	"""
	HKDF-Expand (RFC 5869).
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
