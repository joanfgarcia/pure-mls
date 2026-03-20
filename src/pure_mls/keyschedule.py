import hashlib
from dataclasses import dataclass

from pure_mls.hkdf import hkdf_expand, hkdf_extract


@dataclass
class KeySchedule:
	"""
	Immutable object holding the symmetric cryptographic state for a single Epoch.
	Derived strictly from RFC 9420 Section 8 (Key Schedule).
	"""

	joiner_secret: bytes
	epoch_secret: bytes
	sender_data_secret: bytes
	encryption_secret: bytes
	exporter_secret: bytes
	authentication_secret: bytes
	external_secret: bytes
	confirmation_key: bytes
	next_init_secret: bytes

	@classmethod
	def derive(cls, init_secret: bytes, commit_secret: bytes, transcript_hash: bytes = b"epoch") -> "KeySchedule":
		"""
		Derives all epoch cryptographic materials from a previous init_secret
		mixed with the newly injected commit_secret (TreeKEM root hash).
		"""
		# 1. Extract Joiner Secret
		joiner_secret = hkdf_extract(init_secret, commit_secret, hashlib.sha256)

		# 2. Expand Epoch Secret
		epoch_secret = hkdf_expand(joiner_secret, transcript_hash, 32, hashlib.sha256)

		# 3. Expand application and internal branch secrets
		auth_secret = hkdf_expand(epoch_secret, b"authentication", 32, hashlib.sha256)

		return cls(
			joiner_secret=joiner_secret,
			epoch_secret=epoch_secret,
			sender_data_secret=hkdf_expand(epoch_secret, b"sender data", 32, hashlib.sha256),
			encryption_secret=hkdf_expand(epoch_secret, b"encryption", 32, hashlib.sha256),
			exporter_secret=hkdf_expand(epoch_secret, b"exporter", 32, hashlib.sha256),
			authentication_secret=auth_secret,
			external_secret=hkdf_expand(epoch_secret, b"external", 32, hashlib.sha256),
			confirmation_key=hkdf_expand(auth_secret, b"confirm", 32, hashlib.sha256),
			next_init_secret=hkdf_expand(epoch_secret, b"init", 32, hashlib.sha256),
		)
