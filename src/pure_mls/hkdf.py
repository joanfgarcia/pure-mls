import hashlib
import hmac
from typing import Any, Callable

HashFunction = Callable[[], Any]


def hkdf_extract(salt: bytes, ikm: bytes, hash_func: HashFunction = hashlib.sha256) -> bytes:
	"""
	HKDF-Extract (RFC 5869).
	Extracts a pseudorandom key (PRK) from input keying material (IKM) and a salt.
	"""
	if not salt:
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
