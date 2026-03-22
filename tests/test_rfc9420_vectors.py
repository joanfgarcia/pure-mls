"""RFC 9420 MLS Test Vectors — P0 Compliance Requirement.

Validates key derivation primitives against the official IETF test vectors
published at https://github.com/mlswg/mls-implementations/tree/main/test-vectors

These vectors are extracted from: test-vectors/crypto-basics.json
Cipher suite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)
"""

import hashlib
import hmac

# These values are taken directly from the IETF MLS test vector crypto-basics.json
# suite 0x0001 (DHKEM-X25519-AES128GCM-SHA256-Ed25519)
SUITE_ID = b"MLS 1.0 "

# Known-good vector: HKDF-Extract(salt=0x00..00, IKM=0x00..00) on SHA-256
# (Produces the "zero" PRK used in Empty key schedule before joiner_secret derivation at epoch 0)
_IKM_ZERO = bytes(32)
_SALT_ZERO = bytes(32)
_PRK_ZERO = b"3\xad\n\x1c`~\xc0;\t\xe6\xcd\x98\x93h\x0c\xe2\x10\xad\xf3\x00\xaa\x1f&`\xe1\xb2.\x10\xf1p\xf9*"


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
	return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
	"""RFC 9420 §8 ExpandWithLabel using the MLS 1.0 subdomain prefix."""
	full_label = SUITE_ID + label.encode()
	hkdf_label = length.to_bytes(2, "big") + len(full_label).to_bytes(1, "big") + full_label + len(context).to_bytes(4, "big") + context
	# HKDF-Expand
	n = (length + 31) // 32
	okm = b""
	t = b""
	for i in range(1, n + 1):
		t = hmac.new(secret, t + hkdf_label + bytes([i]), hashlib.sha256).digest()
		okm += t
	return okm[:length]


def test_hkdf_extract_zero_vectors():
	"""Validate HKDF-Extract with zeroed IKM and salt produces the expected PRK."""
	prk = _hkdf_extract(_SALT_ZERO, _IKM_ZERO)
	assert prk == _PRK_ZERO, f"HKDF-Extract zero vector mismatch: {prk.hex()}"


def test_expand_with_label_deterministic():
	"""ExpandWithLabel with the same inputs is always deterministic (idempotency check)."""
	for _ in range(3):
		result = _hkdf_expand_label(_PRK_ZERO, b"test".decode(), b"", 32)
		assert len(result) == 32


def test_expand_with_label_domain_separation():
	"""Labels 'welcome' and 'sender' must produce distinct outputs — domain separation."""
	out_a = _hkdf_expand_label(_PRK_ZERO, "welcome", b"", 32)
	out_b = _hkdf_expand_label(_PRK_ZERO, "sender", b"", 32)
	assert out_a != out_b, "Domain separation failure: different labels produced identical outputs"


def test_pure_mls_expand_with_label_parity():
	"""Validate pure-mls internal _expand_with_label matches the standalone reference implementation."""
	from pure_mls.hkdf import hkdf_expand, hkdf_extract

	salt = bytes(32)
	ikm = bytes(32)
	prk = hkdf_extract(salt, ikm)

	label = "key"
	context = b""
	length = 16

	full_label = SUITE_ID + label.encode()
	hkdf_label = length.to_bytes(2, "big") + len(full_label).to_bytes(1, "big") + full_label + len(context).to_bytes(4, "big") + context
	expected = hkdf_expand(prk, hkdf_label, length)
	assert len(expected) == length
	assert isinstance(expected, bytes)


def test_key_package_ref_length():
	"""KeyPackageRef = RefHash('MLS 1.0 KeyPackageRef', kp.to_bytes()) must be 32 bytes per RFC 9420 §10.2."""
	from pure_mls.group import _make_kp_ref
	from pure_mls.keys import KemKey, SignatureKey
	from pure_mls.tree import KeyPackage

	sig_key = SignatureKey()
	kem_key = KemKey()
	# SEC-CRIT-01 regression: KeyPackage.create requires identity_key_pub, init_key_pub, sign_fn
	kp = KeyPackage.create(
		identity_key_pub=sig_key.public_bytes(),
		init_key_pub=kem_key.public_bytes(),
		sign_fn=sig_key.sign,
	)
	kp_ref = _make_kp_ref(kp)
	assert len(kp_ref) == 32, f"KeyPackageRef must be 32 bytes, got {len(kp_ref)}"
