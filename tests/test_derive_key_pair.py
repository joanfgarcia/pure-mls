"""Audit H2: node keypairs must come from RFC 9180 DeriveKeyPair, not raw node_secret.

Known-answer test against RFC 9180 Appendix A.1 (DHKEM(X25519, HKDF-SHA256), base mode):
DeriveKeyPair(ikmE) -> (skEm, pkEm). This is an external, spec-anchored vector.
"""

from pure_mls.keys import KemKey

# RFC 9180 §A.1.1
_IKM_E = bytes.fromhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234")
_SK_EM = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"
_PK_EM = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"


def test_derive_key_pair_matches_rfc9180_a1() -> None:
	k = KemKey.from_secret(_IKM_E)
	assert k.private_bytes().hex() == _SK_EM
	assert k.public_bytes().hex() == _PK_EM


def test_from_secret_is_not_identity() -> None:
	"""Regression guard: node_secret must NOT be used directly as the private scalar."""
	seed = b"\x11" * 32
	assert KemKey.from_secret(seed).private_bytes() != seed
