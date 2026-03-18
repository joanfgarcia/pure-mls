import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pure_mls.keys import KemKey
from pure_mls.hkdf import hkdf_extract, hkdf_expand

class HPKE:
	"""
	Hybrid Public Key Encryption (RFC 9180) - Base Mode.
	Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
	
	Used for end-to-end encrypting isolated messages like 'Welcome' Envelopes 
	or TreeKEM UpdatePaths across the network.
	"""
	
	@staticmethod
	def seal(receiver_pub: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
		"""
		Encapsulates a shared secret for the receiver and AEAD encrypts the plaintext.
		Returns (encapsulated_key, ciphertext).
		"""
		# KEM: Generate ephemeral key pair on the fly
		ephemeral = KemKey()
		enc = ephemeral.public_bytes()
		
		# DH Exchange: zz = DH(skE, pkR)
		zz = ephemeral.dh_exchange(receiver_pub)
		
		# KDF: Derive symmetric encryption key and nonce using standard HKDF
		prk = hkdf_extract(enc + receiver_pub, zz, hashlib.sha256)
		key = hkdf_expand(prk, b"pure_mls_hpke_key", 32, hashlib.sha256)
		nonce = hkdf_expand(prk, b"pure_mls_hpke_nonce", 12, hashlib.sha256)
		
		# AEAD: Seal it using AES-256-GCM
		aesgcm = AESGCM(key)
		ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
		
		return enc, ciphertext
		
	@staticmethod
	def open(receiver_priv: KemKey, enc: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
		"""
		Decapsulates the ephemeral key and decrypts the ciphertext.
		Only the exact receiver private key can logically open this envelope.
		"""
		# DH Exchange: zz = DH(skR, pkE)
		zz = receiver_priv.dh_exchange(enc)
		
		# KDF: Reproduce exact symmetric parameters
		prk = hkdf_extract(enc + receiver_priv.public_bytes(), zz, hashlib.sha256)
		key = hkdf_expand(prk, b"pure_mls_hpke_key", 32, hashlib.sha256)
		nonce = hkdf_expand(prk, b"pure_mls_hpke_nonce", 12, hashlib.sha256)
		
		# AEAD: Open with AES-256-GCM
		aesgcm = AESGCM(key)
		return aesgcm.decrypt(nonce, ciphertext, aad)
