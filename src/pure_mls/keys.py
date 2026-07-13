import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from pure_mls.hkdf import hkdf_expand, hkdf_extract

# RFC 9180 §4.1: suite_id for DHKEM(X25519, HKDF-SHA256) = "KEM" || I2OSP(0x0020, 2)
_KEM_SUITE_ID = b"KEM\x00\x20"


class SignatureKey:
	"""
	Ed25519 Signature Keypair.
	Used strictly for MLS Identity keys and signing Commit/Proposal messages.
	"""

	def __init__(self, private_key: ed25519.Ed25519PrivateKey | None = None) -> None:
		self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
		self._public_key = self._private_key.public_key()

	def sign(self, message: bytes) -> bytes:
		"""Signs an arbitrary payload using Ed25519."""
		return self._private_key.sign(message)

	def public_bytes(self) -> bytes:
		"""Returns the raw 32-byte public key."""
		return self._public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

	def private_bytes(self) -> bytes:
		"""Returns the raw 32-byte private key (DANGER)."""
		return self._private_key.private_bytes(
			encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()
		)

	@classmethod
	def from_private_bytes(cls, data: bytes) -> "SignatureKey":
		# IETF/OpenMLS vectors often provide a 64-byte expanded key (seed + pub).
		# cryptography expects a 32-byte seed.
		if len(data) == 64:
			data = data[:32]
		if len(data) != 32:
			raise ValueError(f"Ed25519 private key must be 32 (or 64 expanded) bytes, got {len(data)}")  # audit L8
		return cls(ed25519.Ed25519PrivateKey.from_private_bytes(data))

	@classmethod
	def verify(cls, public_bytes: bytes, signature: bytes, message: bytes) -> bool:
		"""Verifies a signature given raw public bytes."""
		try:
			pub = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
			pub.verify(signature, message)
			return True
		except (InvalidSignature, ValueError):
			return False


class KemKey:
	"""
	X25519 Key Encapsulation Mechanism Keypair.
	Used strictly for TreeKEM nodes and HPKE encryptions (Welcome messages).
	"""

	def __init__(self, private_key: x25519.X25519PrivateKey | None = None) -> None:
		self._private_key = private_key or x25519.X25519PrivateKey.generate()
		self._public_key = self._private_key.public_key()

	def public_bytes(self) -> bytes:
		"""Returns the raw 32-byte public key."""
		return self._public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

	def private_bytes(self) -> bytes:
		"""Returns the raw 32-byte private key (DANGER)."""
		return self._private_key.private_bytes(
			encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()
		)

	@classmethod
	def from_private_bytes(cls, data: bytes) -> "KemKey":
		if len(data) != 32:
			raise ValueError(f"X25519 private key must be 32 bytes, got {len(data)}")  # audit L8
		return cls(x25519.X25519PrivateKey.from_private_bytes(data))

	@classmethod
	def from_secret(cls, secret: bytes) -> "KemKey":
		"""Derive a KemKey from a node_secret via RFC 9180 §7.1.2 DeriveKeyPair, DHKEM(X25519).

		RFC 9420 §7.4 requires node keypairs to come from KEM.DeriveKeyPair(node_secret),
		NOT from using node_secret directly as the X25519 private scalar (audit H2).
		DeriveKeyPair(X25519): sk = LabeledExpand(LabeledExtract("","dkp_prk",secret),"sk","",32).
		Implemented here at the KEM-primitive layer (via hkdf) to avoid a keys<->hpke cycle.
		"""
		labeled_ikm = b"HPKE-v1" + _KEM_SUITE_ID + b"dkp_prk" + secret
		dkp_prk = hkdf_extract(b"", labeled_ikm, hashlib.sha256)  # type: ignore[arg-type]
		labeled_info = (32).to_bytes(2, "big") + b"HPKE-v1" + _KEM_SUITE_ID + b"sk"
		sk = hkdf_expand(dkp_prk, labeled_info, 32, hashlib.sha256)  # type: ignore[arg-type]
		return cls.from_private_bytes(sk)

	def dh_exchange(self, peer_public_bytes: bytes) -> bytes:
		"""
		Diffie-Hellman Key Exchange.
		Mixes local private key with peer's raw public key to derive the shared secret.
		"""
		try:
			peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
			return self._private_key.exchange(peer_pub)
		except ValueError as e:
			# audit L1: a KEM public-key error is not a signature failure
			raise ValueError("Malformed KemKey public bytes") from e
