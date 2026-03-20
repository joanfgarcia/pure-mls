from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


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

	@classmethod
	def verify(cls, public_bytes: bytes, signature: bytes, message: bytes) -> bool:
		"""Verifies a signature given raw public bytes."""
		pub = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
		try:
			pub.verify(signature, message)
			return True
		except Exception:
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

	def dh_exchange(self, peer_public_bytes: bytes) -> bytes:
		"""
		Diffie-Hellman Key Exchange.
		Mixes local private key with peer's raw public key to derive the shared secret.
		"""
		peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
		return self._private_key.exchange(peer_pub)
