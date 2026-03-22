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

	SIZE = 288

	@staticmethod
	def _expand_with_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
		full_label = b"MLS 1.0 " + label
		# HkdfLabel struct per RFC 9420
		hkdf_label = length.to_bytes(2, "big") + len(full_label).to_bytes(1, "big") + full_label + len(context).to_bytes(4, "big") + context
		return hkdf_expand(secret, hkdf_label, length, hashlib.sha256)

	@classmethod
	def derive(cls, init_secret: bytes, commit_secret: bytes, transcript_hash: bytes = b"epoch") -> "KeySchedule":
		"""
		Derives all epoch cryptographic materials from a previous init_secret
		mixed with the newly injected commit_secret (TreeKEM root hash).
		"""
		# 1. Extract Joiner Secret (KDF.Extract(commit_secret, init_secret))
		joiner_secret = hkdf_extract(commit_secret, init_secret, hashlib.sha256)

		# 2. Extract Epoch Secret (epoch_secret = KDF.Extract(0*HashLen, joiner_secret))
		epoch_secret = hkdf_extract(b"\x00" * 32, joiner_secret, hashlib.sha256)

		return cls._from_epoch_secret(epoch_secret, joiner_secret)

	@classmethod
	def _from_epoch_secret(cls, epoch_secret: bytes, joiner_secret: bytes) -> "KeySchedule":
		"""
		Constructs the full schedule from an already derived epoch_secret.
		Used by both the committer (derive) and joiner (MLSGroup.join).
		"""
		auth_secret = cls._expand_with_label(epoch_secret, b"authentication", b"", 32)

		return cls(
			joiner_secret=joiner_secret,
			epoch_secret=epoch_secret,
			sender_data_secret=cls._expand_with_label(epoch_secret, b"sender data", b"", 32),
			encryption_secret=cls._expand_with_label(epoch_secret, b"encryption", b"", 32),
			exporter_secret=cls._expand_with_label(epoch_secret, b"exporter", b"", 32),
			authentication_secret=auth_secret,
			external_secret=cls._expand_with_label(epoch_secret, b"external", b"", 32),
			confirmation_key=cls._expand_with_label(auth_secret, b"confirm", b"", 32),
			next_init_secret=cls._expand_with_label(epoch_secret, b"init", b"", 32),
		)

	@staticmethod
	def derive_welcome_key(joiner_secret: bytes, context: bytes) -> bytes:
		"""RFC 9420 §12.1.2: welcome_key = ExpandWithLabel(joiner_secret, "welcome", context, 16).

		Nk = 16 bytes (AES-128-GCM key length).
		context = SHA-256(GroupInfo plaintext) or b"" for simple derivation.
		"""
		full_label = b"MLS 1.0 welcome"
		hkdf_label = b"\x00\x10" + len(full_label).to_bytes(1, "big") + full_label + len(context).to_bytes(4, "big") + context
		return hkdf_expand(joiner_secret, hkdf_label, 16, hashlib.sha256)

	@staticmethod
	def derive_welcome_nonce(joiner_secret: bytes, context: bytes) -> bytes:
		"""RFC 9420 §12.1.2: welcome_nonce = ExpandWithLabel(joiner_secret, "nonce", context, 12).

		Nn = 12 bytes (AES-128-GCM nonce length).
		"""
		full_label = b"MLS 1.0 nonce"
		hkdf_label = b"\x00\x0c" + len(full_label).to_bytes(1, "big") + full_label + len(context).to_bytes(4, "big") + context
		return hkdf_expand(joiner_secret, hkdf_label, 12, hashlib.sha256)

	@staticmethod
	def derive_membership_key(authentication_secret: bytes) -> bytes:
		"""RFC 9420 §6.2: membership_key = ExpandWithLabel(authentication_secret, "membership", b"", 32)."""
		full_label = b"MLS 1.0 membership"
		hkdf_label = (
			b"\x00\x20"  # 32 as uint16
			+ len(full_label).to_bytes(1, "big")
			+ full_label
			+ b"\x00\x00\x00\x00"  # empty context, uint32 length = 0
		)
		return hkdf_expand(authentication_secret, hkdf_label, 32, hashlib.sha256)

	def to_bytes(self) -> bytes:
		"""Serializes the full 9-secret schedule (288 bytes)."""
		return (
			self.joiner_secret
			+ self.epoch_secret
			+ self.sender_data_secret
			+ self.encryption_secret
			+ self.exporter_secret
			+ self.authentication_secret
			+ self.external_secret
			+ self.confirmation_key
			+ self.next_init_secret
		)

	@classmethod
	def from_bytes(cls, data: bytes) -> "KeySchedule":
		if len(data) != 288:
			raise ValueError(f"Invalid KeySchedule size: {len(data)} (expected 288)")
		return cls(
			joiner_secret=data[0:32],
			epoch_secret=data[32:64],
			sender_data_secret=data[64:96],
			encryption_secret=data[96:128],
			exporter_secret=data[128:160],
			authentication_secret=data[160:192],
			external_secret=data[192:224],
			confirmation_key=data[224:256],
			next_init_secret=data[256:288],
		)
