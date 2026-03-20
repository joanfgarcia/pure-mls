import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pure_mls.hkdf import hkdf_expand, hkdf_extract
from pure_mls.keys import KemKey


class HPKE:
	"""
	Hybrid Public Key Encryption (RFC 9180) - Base Mode.
	Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.

	Used for end-to-end encrypting isolated messages like 'Welcome' Envelopes
	or TreeKEM UpdatePaths across the network.
	"""

	SUITE_ID = b"HPKE\x00\x20\x00\x01\x00\x02"  # KEM=X25519, KDF=SHA-256, AEAD=AES-256-GCM
	KEM_SUITE_ID = b"KEM\x00\x20"  # DHKEM(X25519)

	@staticmethod
	def _kem_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
		labeled_ikm = b"HPKE-v1" + HPKE.KEM_SUITE_ID + label + ikm
		return hkdf_extract(salt, labeled_ikm, hashlib.sha256)

	@staticmethod
	def _kem_expand(prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
		labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + HPKE.KEM_SUITE_ID + label + info
		return hkdf_expand(prk, labeled_info, length, hashlib.sha256)

	@staticmethod
	def _labeled_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
		labeled_ikm = b"HPKE-v1" + HPKE.SUITE_ID + label + ikm
		return hkdf_extract(salt, labeled_ikm, hashlib.sha256)

	@staticmethod
	def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
		labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + HPKE.SUITE_ID + label + info
		return hkdf_expand(prk, labeled_info, length, hashlib.sha256)

	@staticmethod
	def seal(receiver_pub: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
		"""
		Single-use encapsulation & encryption per RFC 9180 Base Mode.
		"""
		ephemeral = KemKey()
		enc = ephemeral.public_bytes()
		dh = ephemeral.dh_exchange(receiver_pub)
		kem_context = enc + receiver_pub

		# Phase 1: KEM (ExtractAndExpand with KEM_SUITE_ID)
		prk_kem = HPKE._kem_extract(b"", b"shared_secret", dh)
		shared_secret = HPKE._kem_expand(prk_kem, b"shared_secret", kem_context, 32)

		# Phase 2: KeySchedule (with full HPKE SUITE_ID)
		mode = b"\x00"
		psk_id_hash = HPKE._labeled_extract(b"", b"psk_id_hash", b"")
		info_hash = HPKE._labeled_extract(b"", b"info_hash", b"")
		ks_context = mode + psk_id_hash + info_hash

		prk_key = HPKE._labeled_extract(shared_secret, b"key", b"")
		key = HPKE._labeled_expand(prk_key, b"key", ks_context, 32)
		base_nonce = HPKE._labeled_expand(prk_key, b"base_nonce", ks_context, 12)

		aesgcm = AESGCM(key)
		ciphertext = aesgcm.encrypt(base_nonce, plaintext, aad)
		return enc, ciphertext

	@staticmethod
	def open(receiver_priv: KemKey, enc: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
		"""
		Decapsulation & decryption per RFC 9180 Base Mode.
		"""
		dh = receiver_priv.dh_exchange(enc)
		kem_context = enc + receiver_priv.public_bytes()

		# Phase 1: KEM
		prk_kem = HPKE._kem_extract(b"", b"shared_secret", dh)
		shared_secret = HPKE._kem_expand(prk_kem, b"shared_secret", kem_context, 32)

		# Phase 2: KeySchedule
		mode = b"\x00"
		psk_id_hash = HPKE._labeled_extract(b"", b"psk_id_hash", b"")
		info_hash = HPKE._labeled_extract(b"", b"info_hash", b"")
		ks_context = mode + psk_id_hash + info_hash

		prk_key = HPKE._labeled_extract(shared_secret, b"key", b"")
		key = HPKE._labeled_expand(prk_key, b"key", ks_context, 32)
		base_nonce = HPKE._labeled_expand(prk_key, b"base_nonce", ks_context, 12)

		aesgcm = AESGCM(key)
		return aesgcm.decrypt(base_nonce, ciphertext, aad)
